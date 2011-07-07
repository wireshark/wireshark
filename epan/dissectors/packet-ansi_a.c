/* packet-ansi_a.c
 * Routines for ANSI A Interface (IS-634/IOS) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 * Copyright 2008, Michael Lum <michael.lum [AT] utstar.com>
 * In association with UTStarcom Inc.
 * Copyright 2008, Michael Lum <michael.lum [AT] starsolutions.com>
 * In association with Star Solutions
 *
 * Title                3GPP2                   Other
 *
 *   Inter-operability Specification (IOS) for CDMA
 *   2000 Access Network Interfaces
 *                      3GPP2 A.S0001-1         TIA/EIA-2001
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

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/strutil.h>
#include <epan/emem.h>

#include "packet-rtp.h"
#include "packet-bssap.h"
#include "packet-ansi_a.h"

/*
 * IOS 4, probably most common
 */
static gint global_a_variant = A_VARIANT_IOS401;


/* PROTOTYPES/FORWARDS */

void proto_reg_handoff_ansi_a(void);

static const gchar *
my_match_strval_idx(guint32 val, const ext_value_string_t *vs, gint *idx, gint *dec_idx)
{
    gint i = 0;

    while (vs[i].strptr)
    {
        if (vs[i].value == val)
        {
            *idx = i;
            *dec_idx = vs[i].dec_index;
            return(vs[i].strptr);
        }

        i++;
    }

    *idx = -1;
    *dec_idx = -1;
    return(NULL);
}

const ext_value_string_t ansi_a_ios401_bsmap_strings[] =
{
    { 0x69,     "Additional Service Notification",      0 },
    { 0x65,     "ADDS Page",    1 },
    { 0x66,     "ADDS Page Ack",        2 },
    { 0x67,     "ADDS Transfer",        3 },
    { 0x68,     "ADDS Transfer Ack",    4 },
    { 0x02,     "Assignment Complete",  5 },
    { 0x03,     "Assignment Failure",   6 },
    { 0x01,     "Assignment Request",   7 },
    { 0x45,     "Authentication Request",       8 },
    { 0x46,     "Authentication Response",      9 },
    { 0x48,     "Base Station Challenge",       10 },
    { 0x49,     "Base Station Challenge Response",      11 },
    { 0x40,     "Block",        12 },
    { 0x41,     "Block Acknowledge",    13 },
    { 0x09,     "BS Service Request",   14 },
    { 0x0A,     "BS Service Response",  15 },
    { 0x20,     "Clear Command",        16 },
    { 0x21,     "Clear Complete",       17 },
    { 0x22,     "Clear Request",        18 },
    { 0x57,     "Complete Layer 3 Information", 19 },
    { 0x60,     "Feature Notification", 20 },
    { 0x61,     "Feature Notification Ack",     21 },
    { 0x13,     "Handoff Command",      22 },
    { 0x15,     "Handoff Commenced",    23 },
    { 0x14,     "Handoff Complete",     24 },
    { 0x16,     "Handoff Failure",      25 },
    { 0x17,     "Handoff Performed",    26 },
    { 0x10,     "Handoff Request",      27 },
    { 0x12,     "Handoff Request Acknowledge",  28 },
    { 0x11,     "Handoff Required",     29 },
    { 0x1A,     "Handoff Required Reject",      30 },
    { 0x6C,     "PACA Command", 31 },
    { 0x6D,     "PACA Command Ack",     32 },
    { 0x6E,     "PACA Update",  33 },
    { 0x6F,     "PACA Update Ack",      34 },
    { 0x52,     "Paging Request",       35 },
    { 0x53,     "Privacy Mode Command", 36 },
    { 0x55,     "Privacy Mode Complete",        37 },
    { 0x23,     "Radio Measurements for Position Request",      38 },
    { 0x25,     "Radio Measurements for Position Response",     39 },
    { 0x56,     "Rejection",    40 },
    { 0x05,     "Registration Request", 41 },
    { 0x30,     "Reset",        42 },
    { 0x31,     "Reset Acknowledge",    43 },
    { 0x34,     "Reset Circuit",        44 },
    { 0x35,     "Reset Circuit Acknowledge",    45 },
    { 0x47,     "SSD Update Request",   46 },
    { 0x4A,     "SSD Update Response",  47 },
    { 0x6A,     "Status Request",       48 },
    { 0x6B,     "Status Response",      49 },
    { 0x39,     "Transcoder Control Acknowledge",       50 },
    { 0x38,     "Transcoder Control Request",   51 },
    { 0x42,     "Unblock",      52 },
    { 0x43,     "Unblock Acknowledge",  53 },
    { 0x0B,     "User Zone Reject",     54 },
    { 0x04,     "User Zone Update",     55 },
    { 0, NULL, 0 }
};

const ext_value_string_t ansi_a_ios401_dtap_strings[] =
{
    { 0x62,     "Additional Service Request",   0 },
    { 0x53,     "ADDS Deliver", 1 },
    { 0x54,     "ADDS Deliver Ack",     2 },
    { 0x26,     "Alert With Information",       3 },
    { 0x45,     "Authentication Request",       4 },
    { 0x46,     "Authentication Response",      5 },
    { 0x48,     "Base Station Challenge",       6 },
    { 0x49,     "Base Station Challenge Response",      7 },
    { 0x24,     "CM Service Request",   8 },
    { 0x25,     "CM Service Request Continuation",      9 },
    { 0x07,     "Connect",      10 },
    { 0x10,     "Flash with Information",       11 },
    { 0x50,     "Flash with Information Ack",   12 },
    { 0x02,     "Location Updating Accept",     13 },
    { 0x04,     "Location Updating Reject",     14 },
    { 0x08,     "Location Updating Request",    15 },
    { 0x27,     "Paging Response",      16 },
    { 0x2B,     "Parameter Update Confirm",     17 },
    { 0x2C,     "Parameter Update Request",     18 },
    { 0x56,     "Rejection",    19 },
    { 0x03,     "Progress",     20 },
    { 0x70,     "Service Redirection",  21 },
    { 0x2E,     "Service Release",      22 },
    { 0x2F,     "Service Release Complete",     23 },
    { 0x47,     "SSD Update Request",   24 },
    { 0x4A,     "SSD Update Response",  25 },
    { 0x6A,     "Status Request",       26 },
    { 0x6B,     "Status Response",      27 },
    { 0x0B,     "User Zone Reject",     28 },
    { 0x0C,     "User Zone Update",     29 },
    { 0x0D,     "User Zone Update Request",     30 },
    { 0, NULL, 0 }
};

const ext_value_string_t ansi_a_ios401_elem_1_strings[] =
{
    { 0x20,     "Access Network Identifiers",   0 },
    { 0x3D,     "ADDS User Part",       1 },
    { 0x25,     "AMPS Hard Handoff Parameters", 2 },
    { 0x30,     "Anchor PDSN Address",  3 },
    { 0x7C,     "Anchor P-P Address",   4 },
    { 0x41,     "Authentication Challenge Parameter",   5 },
    { 0x28,     "Authentication Confirmation Parameter (RANDC)",        6 },
    { 0x59,     "Authentication Data",  7 },
    { 0x4A,     "Authentication Event", 8 },
    { 0x40,     "Authentication Parameter COUNT",       9 },
    { 0x42,     "Authentication Response Parameter",    10 },
    { 0x37,     "Band Class",   11 },
    { 0x5B,     "Called Party ASCII Number",    12 },
    { 0x5E,     "Called Party BCD Number",      13 },
    { 0x4B,     "Calling Party ASCII Number",   14 },
    { 0x04,     "Cause",        15 },
    { 0x08,     "Cause Layer 3",        16 },
    { 0x0C,     "CDMA Serving One Way Delay",   17 },
    { 0x05,     "Cell Identifier",      18 },
    { 0x1A,     "Cell Identifier List", 19 },
    { 0x23,     "Channel Number",       20 },
    { 0x0B,     "Channel Type", 21 },
    { 0x19,     "Circuit Group",        22 },
    { 0x01,     "Circuit Identity Code",        23 },
    { 0x24,     "Circuit Identity Code Extension",      24 },
    { 0x12,     "Classmark Information Type 2", 25 },
    { 0x29,     "Downlink Radio Environment",   26 },
    { 0x2B,     "Downlink Radio Environment List",      27 },
    { 0x0A,     "Encryption Information",       28 },
    { 0x10,     "Extended Handoff Direction Parameters",        29 },
    { 0x2C,     "Geographic Location",  30 },
    { 0x5A,     "Special Service Call Indicator",       31 },
    { 0x26,     "Handoff Power Level",  32 },
    { 0x16,     "Hard Handoff Parameters",      33 },
    { 0x2E,     "Information Element Requested",        34 },
    { 0x09,     "IS-2000 Channel Identity",     35 },
    { 0x27,     "IS-2000 Channel Identity 3X",  36 },
    { 0x11,     "IS-2000 Mobile Capabilities",  37 },
    { 0x0F,     "IS-2000 Non-Negotiable Service Configuration Record",  38 },
    { 0x0E,     "IS-2000 Service Configuration Record", 39 },
    { 0x62,     "IS-95/IS-2000 Cause Value",    40 },
    { 0x67,     "IS-2000 Redirection Record",   41 },
    { 0x22,     "IS-95 Channel Identity",       42 },
    { 0x64,     "IS-95 MS Measured Channel Identity",   43 },
    { 0x17,     "Layer 3 Information",  44 },
    { 0x13,     "Location Area Information",    45 },
    { 0x38,     "Message Waiting Indication",   46 },
    { 0x0D,     "Mobile Identity",      47 },
    { 0x15,     "MS Information Records (Forward)",     48 },
    { 0xA0,     "Origination Continuation Indicator",   49 },
    { 0x5F,     "PACA Order",   50 },
    { 0x60,     "PACA Reorigination Indicator", 51 },
    { 0x4E,     "PACA Timestamp",       52 },
    { 0x70,     "Packet Session Parameters",    53 },
    { 0x14,     "PDSN IP Address",      54 },
    { 0xA2,     "Power Down Indicator", 55 },
    { 0x06,     "Priority",     56 },
    { 0x3B,     "Protocol Revision",    57 },
    { 0x18,     "Protocol Type",        58 },
    { 0x2D,     "PSMM Count",   59 },
    { 0x07,     "Quality of Service Parameters",        60 },
    { 0x1D,     "Radio Environment and Resources",      61 },
    { 0x1F,     "Registration Type",    62 },
    { 0x44,     "Reject Cause", 63 },
    { 0x1B,     "Response Request",     64 },
    { 0x68,     "Return Cause", 65 },
    { 0x21,     "RF Channel Identity",  66 },
    { 0x03,     "Service Option",       67 },
    { 0x1E,     "Service Option Connection Identifier (SOCI)",  68 },
    { 0x2A,     "Service Option List",  69 },
    { 0x69,     "Service Redirection Info",     70 },
    { 0x71,     "Service Reference Identifier (SR_ID)", 71 },
    { 0x32,     "SID",  72 },
    { 0x34,     "Signal",       73 },
    { 0x35,     "Slot Cycle Index",     74 },
    { 0x31,     "Software Version",     75 },
    { 0x39,     "Source RNC to Target RNC Transparent Container",       76 },
    { 0x14,     "Source PDSN Address",  77 },
    { 0x33,     "Tag",  78 },
    { 0x3A,     "Target RNC to Source RNC Transparent Container",       79 },
    { 0x36,     "Transcoder Mode",      80 }, /* XXX 0x1C in IOS 4.0.1 */
    { 0x02,     "User Zone ID", 81 },
    { 0xA1,     "Voice Privacy Request",        82 },
    { 0x15,     "MS Information Records (Reverse)",     88 },
    { 0, NULL, 0 }
};

const ext_value_string_t ansi_a_ios501_bsmap_strings[] =
{
    { 0x69,     "Additional Service Notification",      0 },
    { 0x65,     "ADDS Page",    1 },
    { 0x66,     "ADDS Page Ack",        2 },
    { 0x67,     "ADDS Transfer",        3 },
    { 0x68,     "ADDS Transfer Ack",    4 },
    { 0x02,     "Assignment Complete",  5 },
    { 0x03,     "Assignment Failure",   6 },
    { 0x01,     "Assignment Request",   7 },
    { 0x45,     "Authentication Request",       8 },
    { 0x46,     "Authentication Response",      9 },
    { 0x48,     "Base Station Challenge",       10 },
    { 0x49,     "Base Station Challenge Response",      11 },
    { 0x40,     "Block",        12 },
    { 0x41,     "Block Acknowledge",    13 },
    { 0x09,     "BS Service Request",   14 },
    { 0x0A,     "BS Service Response",  15 },
    { 0x20,     "Clear Command",        16 },
    { 0x21,     "Clear Complete",       17 },
    { 0x22,     "Clear Request",        18 },
    { 0x57,     "Complete Layer 3 Information", 19 },
    { 0x60,     "Feature Notification", 20 },
    { 0x61,     "Feature Notification Ack",     21 },
    { 0x13,     "Handoff Command",      22 },
    { 0x15,     "Handoff Commenced",    23 },
    { 0x14,     "Handoff Complete",     24 },
    { 0x16,     "Handoff Failure",      25 },
    { 0x17,     "Handoff Performed",    26 },
    { 0x10,     "Handoff Request",      27 },
    { 0x12,     "Handoff Request Acknowledge",  28 },
    { 0x11,     "Handoff Required",     29 },
    { 0x1A,     "Handoff Required Reject",      30 },
    { 0x6C,     "PACA Command", 31 },
    { 0x6D,     "PACA Command Ack",     32 },
    { 0x6E,     "PACA Update",  33 },
    { 0x6F,     "PACA Update Ack",      34 },
    { 0x52,     "Paging Request",       35 },
    { 0x53,     "Privacy Mode Command", 36 },
    { 0x55,     "Privacy Mode Complete",        37 },
    { 0x23,     "Radio Measurements for Position Request",      38 },
    { 0x25,     "Radio Measurements for Position Response",     39 },
    { 0x56,     "Rejection",    40 },
    { 0x05,     "Registration Request", 41 },
    { 0x30,     "Reset",        42 },
    { 0x31,     "Reset Acknowledge",    43 },
    { 0x34,     "Reset Circuit",        44 },
    { 0x35,     "Reset Circuit Acknowledge",    45 },
    { 0x47,     "SSD Update Request",   46 },
    { 0x4A,     "SSD Update Response",  47 },
    { 0x6A,     "Status Request",       48 },
    { 0x6B,     "Status Response",      49 },
    { 0x39,     "Transcoder Control Acknowledge",       50 },
    { 0x38,     "Transcoder Control Request",   51 },
    { 0x42,     "Unblock",      52 },
    { 0x43,     "Unblock Acknowledge",  53 },
    { 0x0B,     "User Zone Reject",     54 },
    { 0x04,     "User Zone Update",     55 },
    { 0x58,     "Bearer Update Request",        56 },
    { 0x59,     "Bearer Update Response",       58 },
    { 0x5A,     "Bearer Update Required",       57 },
    { 0x71,     "Mobile Station Registered Notification",       59 },
    { 0x07,     "BS Authentication Request",    60 },
    { 0x08,     "BS Authentication Request Ack",        61 },
    { 0, NULL, 0 }
};

const ext_value_string_t ansi_a_ios501_dtap_strings[] =
{
    { 0x62,     "Additional Service Request",   0 },
    { 0x53,     "ADDS Deliver", 1 },
    { 0x54,     "ADDS Deliver Ack",     2 },
    { 0x26,     "Alert With Information",       3 },
    { 0x45,     "Authentication Request",       4 },
    { 0x46,     "Authentication Response",      5 },
    { 0x48,     "Base Station Challenge",       6 },
    { 0x49,     "Base Station Challenge Response",      7 },
    { 0x24,     "CM Service Request",   8 },
    { 0x25,     "CM Service Request Continuation",      9 },
    { 0x07,     "Connect",      10 },
    { 0x10,     "Flash with Information",       11 },
    { 0x50,     "Flash with Information Ack",   12 },
    { 0x02,     "Location Updating Accept",     13 },
    { 0x04,     "Location Updating Reject",     14 },
    { 0x08,     "Location Updating Request",    15 },
    { 0x27,     "Paging Response",      16 },
    { 0x2B,     "Parameter Update Confirm",     17 },
    { 0x2C,     "Parameter Update Request",     18 },
    { 0x56,     "Rejection",    19 },
    { 0x03,     "Progress",     20 },
    { 0x70,     "Service Redirection",  21 },
    { 0x2E,     "Service Release",      22 },
    { 0x2F,     "Service Release Complete",     23 },
    { 0x47,     "SSD Update Request",   24 },
    { 0x4A,     "SSD Update Response",  25 },
    { 0x6A,     "Status Request",       26 },
    { 0x6B,     "Status Response",      27 },
    { 0x0B,     "User Zone Reject",     28 },
    { 0x0C,     "User Zone Update",     29 },
    { 0x0D,     "User Zone Update Request",     30 },
    { 0, NULL, 0 }
};

/*
 * ORDER MUST MATCH
 * ansi_a_ios401_elem_1_strings when the same element
 * is being described.
 */
const ext_value_string_t ansi_a_ios501_elem_1_strings[] =
{
    { 0x20,     "Access Network Identifiers",   0 },
    { 0x3D,     "ADDS User Part",       1 },
    { 0x25,     "AMPS Hard Handoff Parameters", 2 },
    { 0x30,     "Anchor PDSN Address",  3 },
    { 0x7C,     "Anchor P-P Address",   4 },
    { 0x41,     "Authentication Challenge Parameter",   5 },
    { 0x28,     "Authentication Confirmation Parameter (RANDC)",        6 },
    { 0x59,     "Authentication Data",  7 },
    { 0x4A,     "Authentication Event", 8 },
    { 0x40,     "Authentication Parameter COUNT",       9 },
    { 0x42,     "Authentication Response Parameter",    10 },
    { 0x37,     "Band Class",   11 },
    { 0x5B,     "Called Party ASCII Number",    12 },
    { 0x5E,     "Called Party BCD Number",      13 },
    { 0x4B,     "Calling Party ASCII Number",   14 },
    { 0x04,     "Cause",        15 },
    { 0x08,     "Cause Layer 3",        16 },
    { 0x0C,     "CDMA Serving One Way Delay",   17 },
    { 0x05,     "Cell Identifier",      18 },
    { 0x1A,     "Cell Identifier List", 19 },
    { 0x23,     "Channel Number",       20 },
    { 0x0B,     "Channel Type", 21 },
    { 0x19,     "Circuit Group",        22 },
    { 0x01,     "Circuit Identity Code",        23 },
    { 0x24,     "Circuit Identity Code Extension",      24 },
    { 0x12,     "Classmark Information Type 2", 25 },
    { 0x29,     "Downlink Radio Environment",   26 },
    { 0x2B,     "Downlink Radio Environment List",      27 },
    { 0x0A,     "Encryption Information",       28 },
    { 0x10,     "Extended Handoff Direction Parameters",        29 },
    { 0x2C,     "Geographic Location",  30 },
    { 0x5A,     "Special Service Call Indicator",       31 },
    { 0x26,     "Handoff Power Level",  32 },
    { 0x16,     "Hard Handoff Parameters",      33 },
    { 0x2E,     "Information Element Requested",        34 },
    { 0x09,     "IS-2000 Channel Identity",     35 },
    { 0x27,     "IS-2000 Channel Identity 3X",  36 },
    { 0x11,     "IS-2000 Mobile Capabilities",  37 },
    { 0x0F,     "IS-2000 Non-Negotiable Service Configuration Record",  38 },
    { 0x0E,     "IS-2000 Service Configuration Record", 39 },
    { 0x62,     "IS-95/IS-2000 Cause Value",    40 },
    { 0x67,     "IS-2000 Redirection Record",   41 },
    { 0x22,     "IS-95 Channel Identity",       42 },
    { 0x64,     "IS-95 MS Measured Channel Identity",   43 },
    { 0x17,     "Layer 3 Information",  44 },
    { 0x13,     "Location Area Information",    45 },
    { 0x38,     "Message Waiting Indication",   46 },
    { 0x0D,     "Mobile Identity",      47 },
    { 0x15,     "MS Information Records (Forward)",     48 },
    { 0xA0,     "Origination Continuation Indicator",   49 },
    { 0x5F,     "PACA Order",   50 },
    { 0x60,     "PACA Reorigination Indicator", 51 },
    { 0x4E,     "PACA Timestamp",       52 },
    { 0x70,     "Packet Session Parameters",    53 },
    { 0x14,     "PDSN IP Address",      54 },
    { 0xA2,     "Power Down Indicator", 55 },
    { 0x06,     "Priority",     56 },
    { 0x3B,     "Protocol Revision",    57 },
    { 0x18,     "Protocol Type",        58 },
    { 0x2D,     "PSMM Count",   59 },
    { 0x07,     "Quality of Service Parameters",        60 },
    { 0x1D,     "Radio Environment and Resources",      61 },
    { 0x1F,     "Registration Type",    62 },
    { 0x44,     "Reject Cause", 63 },
    { 0x1B,     "Response Request",     64 },
    { 0x68,     "Return Cause", 65 },
    { 0x21,     "RF Channel Identity",  66 },
    { 0x03,     "Service Option",       67 },
    { 0x1E,     "Service Option Connection Identifier (SOCI)",  68 },
    { 0x2A,     "Service Option List",  69 },
    { 0x69,     "Service Redirection Info",     70 },
    { 0x71,     "Service Reference Identifier (SR_ID)", 71 },
    { 0x32,     "SID",  72 },
    { 0x34,     "Signal",       73 },
    { 0x35,     "Slot Cycle Index",     74 },
    { 0x31,     "Software Version",     75 },
    { 0x39,     "Source RNC to Target RNC Transparent Container",       76 },
    { 0x14,     "Source PDSN Address",  77 },
    { 0x33,     "Tag",  78 },
    { 0x3A,     "Target RNC to Source RNC Transparent Container",       79 },
    { 0x36,     "Transcoder Mode",      80 }, /* XXX 0x1C in IOS 4.0.1 */
    { 0x02,     "User Zone ID", 81 },
    { 0xA1,     "Voice Privacy Request",        82 },
    { 0x45,     "A2p Bearer Session-Level Parameters",  83 },
    { 0x46,     "A2p Bearer Format-Specific Parameters",        84 },
    { 0x73,     "MS Designated Frequency",      85 },
    { 0x7D,     "Mobile Subscription Information",      86 },
    { 0x72,     "Public Long Code Mask Identification", 87 },
    { 0x15,     "MS Information Records (Reverse)",     88 },
    { 0, NULL, 0 }
};

/*
 * From Table 3.7.5-1 C.S0005-D v1.0 L3
 */
#define ANSI_FWD_MS_INFO_REC_DISPLAY            0x01
#define ANSI_FWD_MS_INFO_REC_CLD_PN             0x02
#define ANSI_FWD_MS_INFO_REC_CLG_PN             0x03
#define ANSI_FWD_MS_INFO_REC_CONN_N             0x04
#define ANSI_FWD_MS_INFO_REC_SIGNAL             0x05
#define ANSI_FWD_MS_INFO_REC_MW                 0x06
#define ANSI_FWD_MS_INFO_REC_SC                 0x07
#define ANSI_FWD_MS_INFO_REC_CLD_PSA            0x08
#define ANSI_FWD_MS_INFO_REC_CLG_PSA            0x09
#define ANSI_FWD_MS_INFO_REC_CONN_SA            0x0a
#define ANSI_FWD_MS_INFO_REC_RED_N              0x0b
#define ANSI_FWD_MS_INFO_REC_RED_SA             0x0c
#define ANSI_FWD_MS_INFO_REC_MP                 0x0d
#define ANSI_FWD_MS_INFO_REC_PA                 0x0e
#define ANSI_FWD_MS_INFO_REC_LC                 0x0f
#define ANSI_FWD_MS_INFO_REC_EDISPLAY           0x10
#define ANSI_FWD_MS_INFO_REC_NNSC               0x13
#define ANSI_FWD_MS_INFO_REC_MC_EDISPLAY        0x14
#define ANSI_FWD_MS_INFO_REC_CWI                0x15
#define ANSI_FWD_MS_INFO_REC_EMC_EDISPLAY       0x16
#define ANSI_FWD_MS_INFO_REC_ERTI               0xfe

static const value_string ansi_fwd_ms_info_rec_str[] = {
    { ANSI_FWD_MS_INFO_REC_DISPLAY,             "Display" },
    { ANSI_FWD_MS_INFO_REC_CLD_PN,              "Called Party Number" },
    { ANSI_FWD_MS_INFO_REC_CLG_PN,              "Calling Party Number" },
    { ANSI_FWD_MS_INFO_REC_CONN_N,              "Connected Number" },
    { ANSI_FWD_MS_INFO_REC_SIGNAL,              "Signal" },
    { ANSI_FWD_MS_INFO_REC_MW,                  "Message Waiting" },
    { ANSI_FWD_MS_INFO_REC_SC,                  "Service Configuration" },
    { ANSI_FWD_MS_INFO_REC_CLD_PSA,             "Called Party Subaddress" },
    { ANSI_FWD_MS_INFO_REC_CLG_PSA,             "Calling Party Subaddress" },
    { ANSI_FWD_MS_INFO_REC_CONN_SA,             "Connected Subaddress" },
    { ANSI_FWD_MS_INFO_REC_RED_N,               "Redirecting Number" },
    { ANSI_FWD_MS_INFO_REC_RED_SA,              "Redirecting Subaddress" },
    { ANSI_FWD_MS_INFO_REC_MP,                  "Meter Pulses" },
    { ANSI_FWD_MS_INFO_REC_PA,                  "Parametric Alerting" },
    { ANSI_FWD_MS_INFO_REC_LC,                  "Line Control" },
    { ANSI_FWD_MS_INFO_REC_EDISPLAY,            "Extended Display" },
    { ANSI_FWD_MS_INFO_REC_NNSC,                "Non-Negotiable Service Configuration" },
    { ANSI_FWD_MS_INFO_REC_MC_EDISPLAY,         "Multiple Character Extended Display" },
    { ANSI_FWD_MS_INFO_REC_CWI,                 "Call Waiting Indicator" },
    { ANSI_FWD_MS_INFO_REC_EMC_EDISPLAY,        "Enhanced Multiple Character Extended Display" },
    { ANSI_FWD_MS_INFO_REC_ERTI,                "Extended Record Type International" },
    { 0, NULL }
};
#define NUM_FWD_MS_INFO_REC (sizeof(ansi_fwd_ms_info_rec_str)/sizeof(value_string))
static gint ett_ansi_fwd_ms_info_rec[NUM_FWD_MS_INFO_REC];

/*
 * From Table 2.7.4-1 C.S0005-D v1.0 L3
 */
#define ANSI_REV_MS_INFO_REC_KEYPAD_FAC         0x03
#define ANSI_REV_MS_INFO_REC_CLD_PN             0x04
#define ANSI_REV_MS_INFO_REC_CLG_PN             0x05
#define ANSI_REV_MS_INFO_REC_CALL_MODE          0x07
#define ANSI_REV_MS_INFO_REC_TERM_INFO          0x08
#define ANSI_REV_MS_INFO_REC_ROAM_INFO          0x09
#define ANSI_REV_MS_INFO_REC_SECUR_STS          0x0a
#define ANSI_REV_MS_INFO_REC_CONN_N             0x0b
#define ANSI_REV_MS_INFO_REC_IMSI               0x0c
#define ANSI_REV_MS_INFO_REC_ESN                0x0d
#define ANSI_REV_MS_INFO_REC_BAND_INFO          0x0e
#define ANSI_REV_MS_INFO_REC_POWER_INFO         0x0f
#define ANSI_REV_MS_INFO_REC_OP_MODE_INFO       0x10
#define ANSI_REV_MS_INFO_REC_SO_INFO            0x11
#define ANSI_REV_MS_INFO_REC_MO_INFO            0x12
#define ANSI_REV_MS_INFO_REC_SC_INFO            0x13
#define ANSI_REV_MS_INFO_REC_CLD_PSA            0x14
#define ANSI_REV_MS_INFO_REC_CLG_PSA            0x15
#define ANSI_REV_MS_INFO_REC_CONN_SA            0x16
#define ANSI_REV_MS_INFO_REC_PCI                0x17
#define ANSI_REV_MS_INFO_REC_IMSI_M             0x18
#define ANSI_REV_MS_INFO_REC_IMSI_T             0x19
#define ANSI_REV_MS_INFO_REC_CAP_INFO           0x1a
#define ANSI_REV_MS_INFO_REC_CCC_INFO           0x1b
#define ANSI_REV_MS_INFO_REC_EMO_INFO           0x1c
#define ANSI_REV_MS_INFO_REC_GEO_CAP            0x1e
#define ANSI_REV_MS_INFO_REC_BAND_SUB           0x1f
#define ANSI_REV_MS_INFO_REC_GECO               0x20
#define ANSI_REV_MS_INFO_REC_HOOK               0x21
#define ANSI_REV_MS_INFO_REC_QOS_PARAM          0x22
#define ANSI_REV_MS_INFO_REC_ENCRYPT_CAP        0x23
#define ANSI_REV_MS_INFO_REC_SMI_CAP            0x24
#define ANSI_REV_MS_INFO_REC_UIM_ID             0x25
#define ANSI_REV_MS_INFO_REC_ESN_ME             0x26
#define ANSI_REV_MS_INFO_REC_MEID               0x27
#define ANSI_REV_MS_INFO_REC_EKEYPAD_FAC        0x28
#define ANSI_REV_MS_INFO_REC_SYNC_ID            0x29
#define ANSI_REV_MS_INFO_REC_ERTI               0xfe

static const value_string ansi_rev_ms_info_rec_str[] = {
    { ANSI_REV_MS_INFO_REC_KEYPAD_FAC,          "Keypad Facility" },
    { ANSI_REV_MS_INFO_REC_CLD_PN,              "Called Party Number" },
    { ANSI_REV_MS_INFO_REC_CLG_PN,              "Calling Party Number" },
    { ANSI_REV_MS_INFO_REC_CALL_MODE,           "Call Mode" },
    { ANSI_REV_MS_INFO_REC_TERM_INFO,           "Terminal Information" },
    { ANSI_REV_MS_INFO_REC_ROAM_INFO,           "Roaming Information" },
    { ANSI_REV_MS_INFO_REC_SECUR_STS,           "Security Status" },
    { ANSI_REV_MS_INFO_REC_CONN_N,              "Connected Number" },
    { ANSI_REV_MS_INFO_REC_IMSI,                "IMSI" },
    { ANSI_REV_MS_INFO_REC_ESN,                 "ESN" },
    { ANSI_REV_MS_INFO_REC_BAND_INFO,           "Band Class Information" },
    { ANSI_REV_MS_INFO_REC_POWER_INFO,          "Power Class Information" },
    { ANSI_REV_MS_INFO_REC_OP_MODE_INFO,        "Operating Mode Information" },
    { ANSI_REV_MS_INFO_REC_SO_INFO,             "Service Option Information" },
    { ANSI_REV_MS_INFO_REC_MO_INFO,             "Multiplex Option Information" },
    { ANSI_REV_MS_INFO_REC_SC_INFO,             "Service Configuration Information" },
    { ANSI_REV_MS_INFO_REC_CLD_PSA,             "Called Party Subaddress" },
    { ANSI_REV_MS_INFO_REC_CLG_PSA,             "Calling Party Subaddress" },
    { ANSI_REV_MS_INFO_REC_CONN_SA,             "Connected Subaddress" },
    { ANSI_REV_MS_INFO_REC_PCI,                 "Power Control Information" },
    { ANSI_REV_MS_INFO_REC_IMSI_M,              "IMSI_M" },
    { ANSI_REV_MS_INFO_REC_IMSI_T,              "IMSI_T" },
    { ANSI_REV_MS_INFO_REC_CAP_INFO,            "Capability Information" },
    { ANSI_REV_MS_INFO_REC_CCC_INFO,            "Channel Configuration Capability Information" },
    { ANSI_REV_MS_INFO_REC_EMO_INFO,            "Extended Multiplex Option Information" },
    { ANSI_REV_MS_INFO_REC_GEO_CAP,             "Geo-Location Capability" },
    { ANSI_REV_MS_INFO_REC_BAND_SUB,            "Band Subclass Information" },
    { ANSI_REV_MS_INFO_REC_GECO,                "Global Emergency Call" },
    { ANSI_REV_MS_INFO_REC_HOOK,                "Hook Status" },
    { ANSI_REV_MS_INFO_REC_QOS_PARAM,           "QoS Parameters" },
    { ANSI_REV_MS_INFO_REC_ENCRYPT_CAP,         "Encryption Capability" },
    { ANSI_REV_MS_INFO_REC_SMI_CAP,             "Signaling Message Integrity Capability" },
    { ANSI_REV_MS_INFO_REC_UIM_ID,              "UIM_ID" },
    { ANSI_REV_MS_INFO_REC_ESN_ME,              "ESN_ME" },
    { ANSI_REV_MS_INFO_REC_MEID,                "MEID" },
    { ANSI_REV_MS_INFO_REC_EKEYPAD_FAC,         "Extended Keypad Facility" },
    { ANSI_REV_MS_INFO_REC_SYNC_ID,             "SYNC_ID" },
    { ANSI_REV_MS_INFO_REC_ERTI,                "Extended Record Type International" },
    { 0, NULL }
};
#define NUM_REV_MS_INFO_REC (sizeof(ansi_rev_ms_info_rec_str)/sizeof(value_string))
static gint ett_ansi_rev_ms_info_rec[NUM_REV_MS_INFO_REC];

/*
 * C.S0057 Table 1.5-1
 */
static const gchar *band_class_str[] = {
    "800 MHz Cellular System",
    "1.850 to 1.990 GHz Broadband PCS",
    "872 to 960 MHz TACS Band",
    "832 to 925 MHz JTACS Band",
    "1.750 to 1.870 GHz Korean PCS",
    "450 MHz NMT",
    "2 GHz IMT-2000",
    "Upper 700 MHz",
    "1.710 to 1.880 GHz PCS",
    "880 to 960 MHz",
    "Secondary 800 MHz",
    "400 MHz European PAMR",
    "800 MHz European PAMR",
    "2.5 GHz IMT-2000 Extension",
    "US PCS 1.9 GHz",
    "AWS",
    "US 2.5 GHz",
    "US 2.5 GHz Forward Link Only",
    "700 MHz Public Safety",
    "Lower 700 MHz"
};
#define NUM_BAND_CLASS_STR      (sizeof(band_class_str)/sizeof(gchar *))

static const gchar *cell_disc_str[] = {
    "whole Cell Global Identification (CGI)",
    "LAC/CI",
    "Cell Identity (CI)",
    "None",
    "Location Area Identification (LAI)",
    "Location Area Code (LAC)",
    "ALL",
    "IS-41 whole Cell Global Identification (ICGI)",
    "Enhanced whole Cell Global Identification (ECGI)"
};
#define NUM_CELL_DISC_STR       (sizeof(cell_disc_str)/sizeof(gchar *))

/* Initialize the protocol and registered fields */
static int proto_a_bsmap = -1;
static int proto_a_dtap = -1;

const ext_value_string_t *ansi_a_bsmap_strings = NULL;
const ext_value_string_t *ansi_a_dtap_strings = NULL;
const ext_value_string_t *ansi_a_elem_1_strings = NULL;

static int ansi_a_tap = -1;

static int hf_ansi_a_none = -1;
static int hf_ansi_a_bsmap_msgtype = -1;
static int hf_ansi_a_dtap_msgtype = -1;
static int hf_ansi_a_length = -1;
static int hf_ansi_a_elem_id = -1;
static int hf_ansi_a_esn = -1;
static int hf_ansi_a_imsi = -1;
static int hf_ansi_a_min = -1;
static int hf_ansi_a_meid = -1;
static int hf_ansi_a_cld_party_bcd_num = -1;
static int hf_ansi_a_clg_party_bcd_num = -1;
static int hf_ansi_a_cld_party_ascii_num = -1;
static int hf_ansi_a_clg_party_ascii_num = -1;
static int hf_ansi_a_cell_ci = -1;
static int hf_ansi_a_cell_lac = -1;
static int hf_ansi_a_cell_mscid = -1;
static int hf_ansi_a_pdsn_ip_addr = -1;
static int hf_ansi_a_s_pdsn_ip_addr = -1;
static int hf_ansi_a_anchor_ip_addr = -1;
static int hf_ansi_a_anchor_pp_ip_addr = -1;
static int hf_ansi_a_a2p_bearer_ipv4_addr = -1;
static int hf_ansi_a_a2p_bearer_ipv6_addr = -1;
static int hf_ansi_a_a2p_bearer_udp_port = -1;
static int hf_ansi_a_so = -1;
static int hf_ansi_a_cause_1 = -1;      /* 1 octet cause */
static int hf_ansi_a_cause_2 = -1;      /* 2 octet cause */
static int hf_ansi_a_meid_configured = -1;


/* Initialize the subtree pointers */
static gint ett_bsmap = -1;
static gint ett_dtap = -1;
static gint ett_elems = -1;
static gint ett_elem = -1;
static gint ett_dtap_oct_1 = -1;
static gint ett_cm_srvc_type = -1;
static gint ett_ansi_ms_info_rec_reserved = -1;
static gint ett_ansi_enc_info = -1;
static gint ett_scm = -1;
static gint ett_cell_list = -1;
static gint ett_bearer_list = -1;
static gint ett_re_list = -1;
static gint ett_so_list = -1;
static gint ett_adds_user_part = -1;
static gint ett_scr = -1;
static gint ett_srvc_con_rec = -1;
static gint ett_cm2_band_class = -1;
static gint ett_vp_algs = -1;

static char a_bigbuf[1024];
static dissector_handle_t rtp_handle=NULL;
static dissector_handle_t data_handle;
static dissector_handle_t dtap_handle;
static dissector_table_t is637_dissector_table; /* IS-637-A Transport Layer (SMS) */
static dissector_table_t is683_dissector_table; /* IS-683-A (OTA) */
static dissector_table_t is801_dissector_table; /* IS-801 (PLD) */
static packet_info *g_pinfo;
static proto_tree *g_tree;
static address rtp_src_addr;
static guint32 rtp_ipv4_addr;
static struct e_in6_addr rtp_ipv6_addr;
static guint16 rtp_port;
static gboolean a_meid_configured = FALSE;


typedef struct ansi_a_dgt_set_t
{
    /*
     * would typically be 15 but to allow MEID decoding this
     * needs to have room for full hexadecimal representation
     */
    unsigned char out[16];
}
ansi_a_dgt_set_t;

/*
 * As per A.S0001 Called Party BCD Number
 */
static ansi_a_dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '0','1','2','3','4','5','6','7','8','9','*','#','a','b','c', 0
    }
};

static ansi_a_dgt_set_t Dgt_msid = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?', 0
    }
};

static ansi_a_dgt_set_t Dgt_meid = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
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
    char        *out,           /* ASCII pattern out */
    guchar      *in,            /* packed pattern in */
    int         num_octs,       /* Number of octets to unpack */
    ansi_a_dgt_set_t   *dgt            /* Digit definitions */
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

        if ((num_octs == 1) && (i == 0x0f))  /* odd number bytes - hit filler */
            break;

        *out++ = dgt->out[i];
        cnt++;
        num_octs--;
    }

    *out = '\0';

    return(cnt);
}

static const gchar *
ansi_a_so_int_to_str(
    gint32      so)
{
    const gchar *str = NULL;

    switch (so)
    {
    case 1: str = "Basic Variable Rate Voice Service (8 kbps)"; break;
    case 2: str = "Mobile Station Loopback (8 kbps)"; break;
    case 3: str = "(EVRC) Enhanced Variable Rate Voice Service (8 kbps)"; break;
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
    case 32798: /* 0x801e */ str = "Qualcomm Loopback"; break;
    case 32799: /* 0x801f */ str = "Qualcomm Markov 8 kbps Loopback"; break;
    case 32800: /* 0x8020 */ str = "Qualcomm Packet Data"; break;
    case 32801: /* 0x8021 */ str = "Qualcomm Async Data"; break;
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
    case 35: str = "Location Services (PDS), Rate Set 1 (9.6 kbps)"; break;
    case 36: str = "Location Services (PDS), Rate Set 2 (14.4 kbps)"; break;
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
    case 68: str = "(EVRC-B NB) Enhanced Variable Rate Voice Service"; break;
    case 70: str = "(EVRC-B WB) Enhanced Variable Rate Voice Service"; break;
    case 73: str = "(EVRC-NW) Enhanced Variable Rate Voice Service"; break;
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

    return(str);
}


/* ELEMENT FUNCTIONS */

#define EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
        proto_tree_add_text(tree, tvb, \
            curr_offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
        curr_offset += ((edc_len) - (edc_max_len)); \
    }

#define SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
        proto_tree_add_text(tree, tvb, \
            curr_offset, (sdc_len), "Short Data (?)"); \
        curr_offset += (sdc_len); \
        return(curr_offset - offset); \
    }

#define EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
        proto_tree_add_text(tree, tvb, \
            asn1->offset, (edc_len), "Unexpected Data Length"); \
        asn1->offset += (edc_len); \
        return; \
    }

#define NO_MORE_DATA_CHECK(nmdc_len) \
    if ((nmdc_len) == (curr_offset - offset)) return(nmdc_len);


/*
 * IOS 6.2.2.6
 */
static guint8
elem_chan_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        proto_tree_add_text(tree,
            tvb, curr_offset, 2,
            "Channel Number: %u",
            value);

        g_snprintf(add_string, string_len, " - (%u)", value);
        break;

    case A_VARIANT_IOS501:
        other_decode_bitfield_value(a_bigbuf, value >> 8, 0xf8, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, value >> 8, 0x07, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  ARFCN (MSB): %u",
            a_bigbuf,
            value & 0x07ff);

        other_decode_bitfield_value(a_bigbuf, value & 0x00ff, 0xff, 8);
        proto_tree_add_text(tree, tvb, curr_offset + 1, 1,
            "%s :  ARFCN (LSB)",
            a_bigbuf);

        g_snprintf(add_string, string_len, " - (ARFCN: %u)", value & 0x07ff);
        break;
    }

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.7
 */
static guint8
elem_chan_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str = NULL;
    gboolean    data;

    curr_offset = offset;
    data = FALSE;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
    case 0: str = "No Alert"; break;
    case 1: str = "Speech"; break;
    case 2: str = "Data"; data = TRUE; break;
    case 3: str = "Signaling"; break;
    default:
        str = "Unknown";
        break;
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Speech or Data Indicator: %s",
        str);

    g_snprintf(add_string, string_len, " - (%s)", str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
    case 0: str = "Reserved (invalid)"; break;
    case 1: str = "DCCH"; break;
    case 2: str = "Reserved for future use (invalid)"; break;
    case 8: str = "Full rate TCH channel Bm"; break;
    case 9: str = "Half rate TCH channel Lm"; break;
    default:
        str = "Unknown";
        break;
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Channel Rate and Type: %s",
        str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (data)
    {
        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Extension",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  %sTransparent service",
            a_bigbuf,
            (oct & 0x40) ? "Non-" : "");

        other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);
    }
    else
    {
        switch (oct)
        {
        case 0: str = "No Resources Required (invalid)"; break;
        case 1: str = "Reserved"; break;
        case 2: str = "Reserved"; break;
        case 3: str = "TIA/EIA-IS-2000 8 kb/s vocoder"; break;
        case 4: str = "8 kb/s enhanced vocoder (EVRC)"; break;
        case 5: str = "13 kb/s vocoder"; break;
        case 6: str = "ADPCM"; break;
        default:
            str = "Reserved";
            break;
        }

        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "Speech Encoding Algorithm/data rate + Transparency Indicator: %s",
            str);
    }

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.83
 */
static guint8
elem_return_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    const gchar *str;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    switch (oct & 0x0f)
    {
    case 0: str = "Normal access"; break;
    case 1: str = "Service redirection failed as a result of system not found"; break;
    case 2: str = "Service redirection failed as a result of protocol mismatch"; break;
    case 3: str = "Service redirection failed as a result of registration rejection"; break;
    case 4: str = "Service redirection failed as a result of wrong SID"; break;
    case 5: str = "Service redirection failed as a result of wrong NID"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Return Cause: %s",
        a_bigbuf,
        str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.8
 */
static guint8
elem_rf_chan_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Color Code");

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  N-AMPS",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  ANSI/EIA/TIA-553",
        a_bigbuf);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Timeslot Number",
        a_bigbuf);

    curr_offset++;

    value = tvb_get_ntohs(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, value >> 8, 0xf8, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, value >> 8, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  ARFCN (MSB): %u",
        a_bigbuf,
        value & 0x07ff);

    other_decode_bitfield_value(a_bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, tvb, curr_offset + 1, 1,
        "%s :  ARFCN (LSB)",
        a_bigbuf);

    g_snprintf(add_string, string_len, " - (ARFCN: %u)", value & 0x07ff);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.86
 */
static guint8
elem_sr_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  SR_ID: %u",
        a_bigbuf,
        oct & 0x07);

    g_snprintf(add_string, string_len, " - (%u)", oct);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.9
 */
static guint8
elem_sid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, value >> 8, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, value >> 8, 0x7f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  SID (MSB), %u",
        a_bigbuf,
        value & 0x7fff);

    other_decode_bitfield_value(a_bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, tvb, curr_offset + 1, 1,
        "%s :  SID (LSB)",
        a_bigbuf);

    g_snprintf(add_string, string_len, " - (SID: %u)", value & 0x7fff);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.10
 */
static guint8
elem_is95_chan_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Hard Handoff",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Number of Channels to Add: %u",
        a_bigbuf,
        (oct & 0x70) >> 4);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Frame Offset: (%u), %.2f ms",
        a_bigbuf,
        oct & 0x0f,
        (oct & 0x0f) * 1.25);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    SHORT_DATA_CHECK(len - (curr_offset - offset), 4);

    do
    {
        oct = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "Walsh Code Channel Index: %u",
            oct);

        curr_offset++;

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0xff, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Pilot PN Code (LSB)",
            a_bigbuf);

        curr_offset++;

        value = oct;
        oct = tvb_get_guint8(tvb, curr_offset);
        value |= ((guint32) (oct & 0x80)) << 1;

        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Pilot PN Code (MSB): %u",
            a_bigbuf,
            value);

        other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Power Combined",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Frequency Included",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x18, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        value = tvb_get_guint8(tvb, curr_offset + 1) | ((oct & 0x07) << 8);

        other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  ARFCN (MSB): %u",
            a_bigbuf,
            value);

        curr_offset++;

        other_decode_bitfield_value(a_bigbuf, value & 0x00ff, 0xff, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  ARFCN (LSB)",
            a_bigbuf);

        if (add_string[0] == '\0')
        {
            g_snprintf(add_string, string_len, " - (ARFCN: %u)", value);
        }

        curr_offset++;
    }
    while ((len - (curr_offset - offset)) >= 4);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.11
 * UNUSED
 */

/*
 * IOS 6.2.2.12
 */
static guint8
elem_enc_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      oct_len;
    guint32     curr_offset;
    const gchar *str;
    guint8      num_recs;
    proto_tree  *subtree;
    proto_item  *item;

    curr_offset = offset;

    num_recs = 0;

    while ((len - (curr_offset - offset)) >= 2)
    {
        num_recs++;

        oct = tvb_get_guint8(tvb, curr_offset);

        switch ((oct & 0x7c) >> 2)
        {
        case 0: str = "Not Used - Invalid value"; break;
        case 1: str = "SME Key: Signaling Message Encryption Key"; break;
        case 2: str = "Reserved (VPM: Voice Privacy Mask)"; break;
        case 3: str = "Reserved"; break;
        case 4: str = "Private Longcode"; break;
        case 5: str = "Data Key (ORYX)"; break;
        case 6: str = "Initial RAND"; break;
        default:
            str = "Reserved";
            break;
        }

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, 1,
                "Encryption Info [%u]: (%u) %s",
                num_recs,
                (oct & 0x7c) >> 2,
                str);

        subtree = proto_item_add_subtree(item, ett_ansi_enc_info);

        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  Extension",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x7c, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  Encryption Parameter Identifier: (%u) %s",
            a_bigbuf,
            (oct & 0x7c) >> 2,
            str);

        other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  Status: %s",
            a_bigbuf,
            (oct & 0x02) ? "active" : "inactive");

        other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  Available: algorithm is %savailable",
            a_bigbuf,
            (oct & 0x01) ? "" : "not ");

        curr_offset++;

        oct_len = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_uint(subtree, hf_ansi_a_length, tvb,
            curr_offset, 1, oct_len);

        curr_offset++;

        if (oct_len > 0)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

            proto_tree_add_text(subtree, tvb, curr_offset, oct_len,
                "Encryption Parameter value");

            curr_offset += oct_len;
        }
    }

    g_snprintf(add_string, string_len, " - %u record%s",
        num_recs, plurality(num_recs, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.13
 * NO ASSOCIATED DATA
 */

/*
 * IOS 6.2.2.14
 * A3/A7
 */

/*
 * IOS 6.2.2.15
 */
static guint8
elem_cm_info_type_2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct, oct2;
    guint8      num_bands, band_class_count;
    guint32     curr_offset;
    gint        band_class;
    proto_tree  *subtree;
    proto_item  *item;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Mobile P_REV: %u",
        a_bigbuf,
        (oct & 0xe0) >> 5);

    g_snprintf(add_string, string_len, " - P_REV (%u)", (oct & 0xe0) >> 5);

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  See List of Entries",
        a_bigbuf);

    switch (oct & 0x07)
    {
    case 0: str = "Class 1, vehicle and portable"; break;
    case 1: str = "Class 2, portable"; break;
    case 2: str = "Class 3, handheld"; break;
    case 3: str = "Class 4, handheld"; break;
    case 4: str = "Class 5, handheld"; break;
    case 5: str = "Class 6, handheld"; break;
    case 6: str = "Class 7, handheld"; break;
    default:
        str = "Class 8, handheld";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  RF Power Capability: %s",
        a_bigbuf,
        str);

    curr_offset++;

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Reserved");

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  NAR_AN_CAP: N-AMPS %ssupported",
        a_bigbuf,
        (oct & 0x80) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  IS-95: %ssupported",
        a_bigbuf,
        (oct & 0x40) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Slotted: mobile is %sin slotted mode",
        a_bigbuf,
        (oct & 0x20) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x18, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  DTX: mobile is %scapable of DTX",
        a_bigbuf,
        (oct & 0x04) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Mobile Term: mobile is %scapable of receiving incoming calls",
        a_bigbuf,
        (oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Reserved");

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Mobile Term: mobile is %scapable of receiving incoming calls",
        a_bigbuf,
        (oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  PACA Supported Indicator (PSI): mobile station %s PACA",
        a_bigbuf,
        (oct & 0x01) ? "supports" : "does not support");

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "SCM Length: %u",
        oct);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    item =
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "Station Class Mark: %u",
            oct);

    /*
     * following SCM decode is from:
     *  3GPP2 C.S0005-0 section 2.3.3
     *  3GPP2 C.S0072-0 section 2.1.2
     */
    subtree = proto_item_add_subtree(item, ett_scm);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
        "%s :  Extended SCM Indicator: %s",
        a_bigbuf,
        (oct & 0x80) ? "Band Classes 1,4" : "Other bands");

    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
        "%s :  %s",
        a_bigbuf,
        (oct & 0x40) ? "Dual Mode" : "CDMA Only");

    other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
        "%s :  %s",
        a_bigbuf,
        (oct & 0x20) ? "Slotted" : "Non-Slotted");

    if (oct & 0x10)
    {
        str = "";
        g_strlcat(add_string, " (MEID configured)", string_len);
        a_meid_configured = TRUE;
    }
    else
    {
        str = "not ";
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_boolean_format(subtree, hf_ansi_a_meid_configured, tvb,
        curr_offset, 1, a_meid_configured,
        "%s :  MEID %sconfigured",
        a_bigbuf,
        str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
        "%s :  25 MHz Bandwidth",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
        "%s :  %s Transmission",
        a_bigbuf,
        (oct & 0x04) ? "Discontinuous" : "Continuous");

    switch (oct & 0x03)
    {
    case 0x00: str = "Class I"; break;
    case 0x01: str = "Class II"; break;
    case 0x02: str = "Class III"; break;
    case 0x03: str = "Reserved"; break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
        "%s :  Power Class for Band Class 0 Analog Operation: %s",
        a_bigbuf,
        str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    band_class_count = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Count of Band Class Entries: %u",
        band_class_count);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Band Class Entry Length: %u",
        oct);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (oct > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), 3);

        num_bands = 0;
        do
        {
            item =
                proto_tree_add_text(tree, tvb, curr_offset, 3,
                    "Band Class Entry [%u]",
                    num_bands + 1);

            subtree = proto_item_add_subtree(item, ett_cm2_band_class);

            oct = tvb_get_guint8(tvb, curr_offset);

            other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
            proto_tree_add_text(subtree,
                tvb, curr_offset, 1,
                "%s :  Reserved",
                a_bigbuf);

            band_class = oct & 0x1f;
            if ((band_class < 0) || (band_class >= (gint) NUM_BAND_CLASS_STR))
            {
                str = "Reserved";
            }
            else
            {
                str = band_class_str[band_class];
            }

            other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
            proto_tree_add_text(subtree,
                tvb, curr_offset, 1,
                "%s :  Band Class: %s",
                a_bigbuf,
                str);

            curr_offset++;

            oct2 = tvb_get_guint8(tvb, curr_offset);
            oct = tvb_get_guint8(tvb, curr_offset+1);

            if (oct < 4)
            {
                other_decode_bitfield_value(a_bigbuf, oct2, 0x80, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE0 (CDMA mode in Band Class 1 and Band Class 4)",
                    a_bigbuf);

                other_decode_bitfield_value(a_bigbuf, oct2, 0x40, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE1 (CDMA mode in Band Class 0 and Band Class 3)",
                    a_bigbuf);

                other_decode_bitfield_value(a_bigbuf, oct2, 0x20, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE2 (Analog mode)",
                    a_bigbuf);

                other_decode_bitfield_value(a_bigbuf, oct2, 0x10, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE3 (Wide analog mode)",
                    a_bigbuf);

                other_decode_bitfield_value(a_bigbuf, oct2, 0x08, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE4 (Narrow analog mode)",
                    a_bigbuf);
            }
            else
            {
                other_decode_bitfield_value(a_bigbuf, oct2, 0x80, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE0 (CDMA mode)",
                    a_bigbuf);

                other_decode_bitfield_value(a_bigbuf, oct2, 0x40, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE1 (CDMA mode)",
                    a_bigbuf);

                other_decode_bitfield_value(a_bigbuf, oct2, 0x20, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE2 (Analog mode)",
                    a_bigbuf);

                other_decode_bitfield_value(a_bigbuf, oct2, 0x10, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE3 (Wide analog mode)",
                    a_bigbuf);

                other_decode_bitfield_value(a_bigbuf, oct2, 0x08, 8);
                proto_tree_add_text(subtree,
                    tvb, curr_offset, 1,
                    "%s :  Band Class Air Interfaces OP_MODE4 (Narrow analog mode)",
                    a_bigbuf);
            }

            other_decode_bitfield_value(a_bigbuf, oct2, 0x07, 8);
            proto_tree_add_text(subtree,
                tvb, curr_offset, 1,
                "%s :  Reserved",
                a_bigbuf);

            curr_offset++;

            proto_tree_add_text(subtree,
                tvb, curr_offset, 1,
                "Band Class MS Protocol Level: %u",
                oct);

            curr_offset++;

            proto_item_append_text(item, ": (%d)", band_class);

            num_bands++;
        }
        while (((len - (curr_offset - offset)) >= 3) &&
            (num_bands < band_class_count));
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.16
 */
static guint8
elem_mid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      *poctets;
    guint32     value;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct & 0x07)
    {
    case 1:
        other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  MEID Hex Digit 1: %X",
            a_bigbuf,
            (oct & 0xf0) >> 4);

        other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Odd/Even Indicator: %s",
            a_bigbuf,
            (oct & 0x08) ? "ODD" : "EVEN");

        other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Type of Identity: MEID",
            a_bigbuf);

        a_bigbuf[0] = Dgt_meid.out[(oct & 0xf0) >> 4];
        curr_offset++;

        poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

        my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
            &Dgt_meid);

        curr_offset += len - (curr_offset - offset);

        proto_tree_add_string_format(tree,
            hf_ansi_a_meid,
            tvb, offset + 1, len - 1,
            a_bigbuf,
            "MEID: %s",
            a_bigbuf);

        g_snprintf(add_string, string_len, " - %s (%s)",
            "MEID",
            a_bigbuf);
        break;

    case 2:
        other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Type of Identity: Broadcast",
            a_bigbuf);

        curr_offset++;

        oct = tvb_get_guint8(tvb, curr_offset);

        switch ((oct & 0xc0) >> 6)
        {
        case 0: str = "Normal"; break;
        case 1: str = "Interactive"; break;
        case 2: str = "Urgent"; break;
        default:
            str = "Emergency";
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Priority: %s",
            a_bigbuf,
            str);

        other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Message ID: %u",
            a_bigbuf,
            oct & 0x3f);

        curr_offset++;

        oct = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "Zone ID: %u",
            oct);

        g_snprintf(add_string, string_len, " - Broadcast (Zone ID: %u)", oct);

        curr_offset++;

        value = tvb_get_ntohs(tvb, curr_offset);

        switch (value)
        {
        case 0x0000: str = "Unknown or unspecified"; break;
        case 0x0001: str = "Emergency Broadcasts"; break;
        case 0x0002: str = "Administrative"; break;
        case 0x0003: str = "Maintenance"; break;
        case 0x0004: str = "General News - Local"; break;
        case 0x0005: str = "General News - Regional"; break;
        case 0x0006: str = "General News - National"; break;
        case 0x0007: str = "General News - International"; break;
        case 0x0008: str = "Business/Financial News - Local"; break;
        case 0x0009: str = "Business/Financial News - Regional"; break;
        case 0x000A: str = "Business/Financial News - National"; break;
        case 0x000B: str = "Business/Financial News - International"; break;
        case 0x000C: str = "Sports News - Local"; break;
        case 0x000D: str = "Sports News - Regional"; break;
        case 0x000E: str = "Sports News - National"; break;
        case 0x000F: str = "Sports News - International"; break;
        case 0x0010: str = "Entertainment News - Local"; break;
        case 0x0011: str = "Entertainment News - Regional"; break;
        case 0x0012: str = "Entertainment News - National"; break;
        case 0x0013: str = "Entertainment News - International"; break;
        case 0x0014: str = "Local Weather"; break;
        case 0x0015: str = "Area Traffic Reports"; break;
        case 0x0016: str = "Local Airport Flight Schedules"; break;
        case 0x0017: str = "Restaurants"; break;
        case 0x0018: str = "Lodgings"; break;
        case 0x0019: str = "Retail Directory"; break;
        case 0x001A: str = "Advertisements"; break;
        case 0x001B: str = "Stock Quotes"; break;
        case 0x001C: str = "Employment Opportunities"; break;
        case 0x001D: str = "Medical/Health/Hospitals"; break;
        case 0x001E: str = "Technology News"; break;
        case 0x001F: str = "Multi-category"; break;
        default:
            if ((value >= 0x0020) && (value <= 0x8000)) { str = "Reserved for standard service categories"; }
            else { str = "Reserved for proprietary service categories"; }
            break;
        }

        proto_tree_add_text(tree,
            tvb, curr_offset, 2,
            "Service: (%u) %s",
            value,
            str);

        curr_offset += 2;

        oct = tvb_get_guint8(tvb, curr_offset);

        switch (oct)
        {
        case 0: str = "Unknown or unspecified"; break;
        case 1: str = "English"; break;
        case 2: str = "French"; break;
        case 3: str = "Spanish"; break;
        case 4: str = "Japanese"; break;
        case 5: str = "Korean"; break;
        case 6: str = "Chinese"; break;
        case 7: str = "Hebrew"; break;
        default:
            str = "Reserved";
            break;
        }

        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "Language: (%u) %s",
            oct,
            str);

        curr_offset++;
        break;

    case 0:
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

        g_snprintf(add_string, string_len, " - No Identity Code");

        curr_offset++;

        if (len > 1)
        {
            proto_tree_add_text(tree, tvb, curr_offset, len - 1,
                "Format not supported");
        }

        curr_offset += len - 1;
        break;

    case 6:
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
            "%s :  Type of Identity: %s",
            a_bigbuf,
            ((oct & 0x07) == 1) ? "MIN" : "IMSI");

        a_bigbuf[0] = Dgt_msid.out[(oct & 0xf0) >> 4];
        curr_offset++;

        poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

        my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
            &Dgt_msid);

        proto_tree_add_string_format(tree,
            ((oct & 0x07) == 1) ? hf_ansi_a_min : hf_ansi_a_imsi,
            tvb, curr_offset, len - (curr_offset - offset),
            a_bigbuf,
            "BCD Digits: %s",
            a_bigbuf);

        g_snprintf(add_string, string_len, " - %s (%s)",
            ((oct & 0x07) == 1) ? "MIN" : "IMSI",
            a_bigbuf);

        curr_offset += len - (curr_offset - offset);
        break;

    case 3:
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
            "%s :  Type of Identity: Interface Directory Number",
            a_bigbuf);

        g_snprintf(add_string, string_len, " - Interface Directory Number");

        curr_offset++;

        if (len > 1)
        {
            proto_tree_add_text(tree, tvb, curr_offset, len - 1,
                "Format not supported");
        }

        curr_offset += len - 1;
        break;

    case 4:
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
            "%s :  Type of Identity: TMSI",
            a_bigbuf);

        g_snprintf(add_string, string_len, " - TMSI");

        curr_offset++;

        if (len > 1)
        {
            proto_tree_add_text(tree, tvb, curr_offset, len - 1,
                "Format not supported");
        }

        curr_offset += len - 1;
        break;

    case 5:
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
            "%s :  Type of Identity: ESN",
            a_bigbuf);

        curr_offset++;

        value = tvb_get_ntohl(tvb, curr_offset);

        proto_tree_add_uint(tree, hf_ansi_a_esn,
            tvb, curr_offset, 4,
            value);

        g_snprintf(add_string, string_len, " - %sESN (0x%04x)",
            a_meid_configured ? "p" : "",
            value);

        curr_offset += 4;
        break;

    default:
        proto_tree_add_text(tree, tvb, curr_offset, len,
            "Format Unknown");

        g_snprintf(add_string, string_len, " - Format Unknown");

        curr_offset += len;
        break;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.17
 */
static guint8
elem_sci(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Slot Cycle Index: %u",
        a_bigbuf,
        oct & 0x07);

    g_snprintf(add_string, string_len, " - (%u)", oct & 0x07);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.18
 */
static guint8
elem_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x3c, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Call Priority Level: %u",
        a_bigbuf,
        (oct & 0x3c) >> 2);

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Queuing %sallowed",
        a_bigbuf,
        (oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Preemption %sallowed",
        a_bigbuf,
        (oct & 0x01) ? "" : "not ");

    g_snprintf(add_string, string_len, " - (%u)", (oct & 0x3c) >> 2);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.79
 */
static guint8
elem_p_rev(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "MOB_P_REV");

    g_snprintf(add_string, string_len, " - (%u)", oct);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.19
 */
static guint8
elem_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;
    const gchar *str = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Extension",
        a_bigbuf);

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

            value = tvb_get_guint8(tvb, curr_offset);

            proto_tree_add_uint_format(tree, hf_ansi_a_cause_2, tvb,
                curr_offset, 1,
                ((oct & 0x7f) << 8) | value,
                "Cause Value");

            curr_offset++;

            g_snprintf(add_string, string_len, " - (National Cause)");
        }
        else
        {
            value = tvb_get_guint8(tvb, curr_offset + 1);

            other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);

            proto_tree_add_uint_format(tree, hf_ansi_a_cause_2, tvb,
                curr_offset, 1,
                ((oct & 0x7f) << 8) | value,
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
        case 0x02: str = "Uplink Quality"; break;
        case 0x03: str = "Uplink strength"; break;
        case 0x04: str = "Downlink quality"; break;
        case 0x05: str = "Downlink strength"; break;
        case 0x06: str = "Distance"; break;
        case 0x07: str = "OAM&P intervention"; break;
        case 0x08: str = "MS busy"; break;
        case 0x09: str = "Call processing"; break;
        case 0x0A: str = "Reversion to old channel"; break;
        case 0x0B: str = "Handoff successful"; break;
        case 0x0C: str = "No response from MS"; break;
        case 0x0D: str = "Timer expired"; break;
        case 0x0E: str = "Better cell (power budget)"; break;
        case 0x0F: str = "Interference"; break;
        case 0x10: str = "Packet call going dormant"; break;
        case 0x11: str = "Service option not available"; break;

        case 0x12: str = "Invalid Call"; break;
        case 0x13: str = "Successful operation"; break;
        case 0x14: str = "Normal call release"; break;

        /* IOS 5 */
        case 0x15: str = "Short data burst authentication failure"; break;
        case 0x17: str = "Time critical relocation/handoff"; break;
        case 0x18: str = "Network optimization"; break;
        case 0x19: str = "Power down from dormant state"; break;
        case 0x1A: str = "Authentication failure"; break;

        case 0x1B: str = "Inter-BS Soft Handoff Drop Target"; break;
        case 0x1D: str = "Intra-BS Soft Handoff Drop Target"; break;

        /* IOS 5 */
        case 0x1E: str = "Autonomous Registration by the Network"; break;

        case 0x20: str = "Equipment failure"; break;
        case 0x21: str = "No radio resource available"; break;
        case 0x22: str = "Requested terrestrial resource unavailable"; break;

        /* IOS 5 */
        case 0x23: str = "A2p RTP Payload Type not available"; break;
        case 0x24: str = "A2p Bearer Format Address Type not available"; break;

        case 0x25: str = "BS not equipped"; break;
        case 0x26: str = "MS not equipped (or incapable)"; break;

        /* IOS 5 */
        case 0x27: str = "2G only sector"; break;
        case 0x28: str = "3G only sector"; break;

        case 0x29: str = "PACA Call Queued"; break;

        /* IOS 5 */
        case 0x2A: str = "Handoff Blocked"; break;

        case 0x2B: str = "Alternate signaling type reject"; break;

        /* IOS 5 */
        case 0x2C: str = "A2p Resource not available"; break;

        case 0x2D: str = "PACA Queue Overflow"; break;
        case 0x2E: str = "PACA Cancel Request Rejected"; break;
        case 0x30: str = "Requested transcoding/rate adaptation unavailable"; break;
        case 0x31: str = "Lower priority radio resources not available"; break;
        case 0x32: str = "PCF resources not available"; break;  /* IOS 4 */
        case 0x33: str = "TFO Control request Failed"; break;

        /* IOS 5 */
        case 0x34: str = "MS rejected order"; break;

        case 0x40: str = "Ciphering algorithm not supported"; break;
        case 0x41: str = "Private Long Code not available or not supported."; break;
        case 0x42: str = "Requested MUX option or rates not available."; break;
        case 0x43: str = "Requested Privacy Configuration unavailable"; break;

        /* IOS 5 */
        case 0x45: str = "PDS-related capability not available or not supported"; break;

        case 0x50: str = "Terrestrial circuit already allocated"; break;
        case 0x60: str = "Protocol Error between BS and MSC"; break;
        case 0x71: str = "ADDS message too long for delivery on the paging channel"; break;
        case 0x72: str = "MS-to-IWF TCP connection failure"; break;
        case 0x73: str = "ATH0 (Modem hang up) Command"; break;
        case 0x74: str = "+FSH/+FHNG (Fax session ended) Command"; break;
        case 0x75: str = "No carrier"; break;
        case 0x76: str = "PPP protocol failure"; break;
        case 0x77: str = "PPP session closed by the MS"; break;
        case 0x78: str = "Do not notify MS"; break;
        case 0x79: str = "PCF (or PDSN) resources are not available"; break;
        case 0x7A: str = "Data ready to send"; break;

        /* IOS 5 */
        case 0x7B: str = "Concurrent authentication"; break;

        case 0x7F: str = "Handoff procedure time-out"; break;
        default:
            str = "Reserved for future use";
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
        proto_tree_add_uint_format(tree, hf_ansi_a_cause_1, tvb,
            curr_offset, 1, oct,
            "%s :  Cause: (%u) %s",
            a_bigbuf,
            oct & 0x7f,
            str);

        curr_offset++;

        g_snprintf(add_string, string_len, " - (%u) %s", oct & 0x7f, str);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.20
 * Formats everything after the discriminator, shared function.
 */
static guint8
elem_cell_id_aux(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len, guint8 disc)
{
    guint32     value;
    guint32     market_id;
    guint32     switch_num;
    guint32     curr_offset;

    curr_offset = offset;

    switch (disc)
    {
    case 0x02:
        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_uint(tree, hf_ansi_a_cell_ci, tvb,
            curr_offset, 2, value);

        curr_offset += 2;

        g_snprintf(add_string, string_len, " - CI (%u)", value);
        break;

    case 0x05:
        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_uint(tree, hf_ansi_a_cell_lac, tvb,
            curr_offset, 2, value);

        curr_offset += 2;

        g_snprintf(add_string, string_len, " - LAC (%u)", value);
        break;

    case 0x07:
        market_id = tvb_get_ntohs(tvb, curr_offset);
        switch_num = tvb_get_guint8(tvb, curr_offset + 2);

        value = tvb_get_ntoh24(tvb, curr_offset);

        proto_tree_add_uint_format(tree, hf_ansi_a_cell_mscid, tvb,
            curr_offset, 3, value,
            "Market ID %u  Switch Number %u",
            market_id, switch_num);

        curr_offset += 3;

        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_uint(tree, hf_ansi_a_cell_ci, tvb,
            curr_offset, 2, value);

        curr_offset += 2;

        g_snprintf(add_string, string_len, " - Market ID (%u) Switch Number (%u) CI (%u)",
            market_id,
            switch_num,
            value);
        break;

    default:
        proto_tree_add_text(tree, tvb, curr_offset, len,
            "Cell ID - Non IOS format");

        curr_offset += len;
        break;
    }

    return(curr_offset - offset);
}

static guint8
elem_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct >= (gint) NUM_CELL_DISC_STR)
    {
        str = "Unknown";
    }
    else
    {
        str = cell_disc_str[oct];
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Cell Identification Discriminator: (%u) %s",
        oct,
        str);

    curr_offset++;

    curr_offset +=
        elem_cell_id_aux(tvb, tree, curr_offset, len - (curr_offset - offset), add_string, string_len, oct);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.21
 */
static guint8
elem_cell_id_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      consumed;
    guint8      num_cells;
    guint32     curr_offset;
    proto_item  *item = NULL;
    proto_tree  *subtree = NULL;
    const gchar *str = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct >= (gint) NUM_CELL_DISC_STR)
    {
        str = "Unknown";
    }
    else
    {
        str = cell_disc_str[oct];
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Cell Identification Discriminator: (%u) %s",
        oct,
        str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    num_cells = 0;
    do
    {
        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, -1,
                "Cell [%u]",
                num_cells + 1);

        subtree = proto_item_add_subtree(item, ett_cell_list);

        add_string[0] = '\0';
        consumed =
            elem_cell_id_aux(tvb, subtree, curr_offset, len - (curr_offset - offset), add_string, string_len, oct);

        if (add_string[0] != '\0')
        {
            proto_item_append_text(item, "%s", add_string);
        }

        proto_item_set_len(item, consumed);

        curr_offset += consumed;

        num_cells++;
    }
    while ((len - (curr_offset - offset)) > 0);

    g_snprintf(add_string, string_len, " - %u cell%s",
        num_cells, plurality(num_cells, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.22
 */
static guint8
elem_cic(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint32     value;
    guint32     curr_offset;

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

    g_snprintf(add_string, string_len, " - (%u) (0x%04x)", value, value);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.23
 */
static guint8
elem_cic_ext(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;
    const gchar *str;

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

    g_snprintf(add_string, string_len, " - (%u) (0x%04x)", value, value);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    switch (oct & 0x0f)
    {
    case 0x00: str = "Full-rate"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Circuit Mode: %s",
        a_bigbuf,
        str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.21
 */
static guint8
elem_ssci(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Mobile Originated Position Determination",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Global Emergency Call Indication",
        a_bigbuf);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.24
 * UNUSED
 */

#define ANSI_A_CELL_ID_LEN(_disc) ((_disc == 7) ? 5 : 2)

/*
 * IOS 6.2.2.25
 * Formats everything no length check
 */
static guint8
elem_downlink_re_aux(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      disc;
    guint8      consumed;
    guint8      num_cells;
    guint8      curr_cell;
    guint32     value;
    guint32     curr_offset;
    proto_item  *item = NULL;
    proto_tree  *subtree = NULL;
    const gchar *str;

    curr_offset = offset;

    num_cells = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Number of Cells: %u",
        num_cells);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    disc = tvb_get_guint8(tvb, curr_offset);

    if (disc >= (gint) NUM_CELL_DISC_STR)
    {
        str = "Unknown";
    }
    else
    {
        str = cell_disc_str[disc];
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Cell Identification Discriminator: (%u) %s",
        disc,
        str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    SHORT_DATA_CHECK(len - (curr_offset - offset), (guint32) 3 + ANSI_A_CELL_ID_LEN(disc));

    curr_cell = 0;

    do
    {
        curr_cell++;

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, -1,
                "Cell [%u]",
                curr_cell);

        subtree = proto_item_add_subtree(item, ett_cell_list);

        add_string[0] = '\0';
        consumed =
            elem_cell_id_aux(tvb, subtree, curr_offset,
                len - (curr_offset - offset), add_string, string_len, disc);

        if (add_string[0] != '\0')
        {
            proto_item_append_text(item, "%s", add_string);
        }

        proto_item_set_len(item, consumed);

        curr_offset += consumed;

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Downlink Signal Strength Raw: %u",
            a_bigbuf,
            oct & 0x3f);

        curr_offset++;

        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_text(tree,
            tvb, curr_offset, 2,
            "CDMA Target One Way Delay: %u",
            value);

        curr_offset += 2;
    }
    while (curr_cell < num_cells);

    g_snprintf(add_string, string_len, " - %u cell%s",
        num_cells, plurality(num_cells, "", "s"));

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.25
 */
static guint8
elem_downlink_re(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint32     curr_offset;

    curr_offset = offset;

    curr_offset +=
        elem_downlink_re_aux(tvb, tree, offset, len, add_string, string_len);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.140
 */
static guint8
elem_downlink_re_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      consumed;
    guint8      num_envs;
    guint8      oct_len;
    guint32     curr_offset;
    proto_item  *item = NULL;
    proto_tree  *subtree = NULL;

    curr_offset = offset;

    num_envs = 0;

    while ((len - (curr_offset - offset)) > 0)
    {
        num_envs++;

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, -1,
                "Environment [%u]",
                num_envs);

        subtree = proto_item_add_subtree(item, ett_re_list);

        oct_len = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_text(subtree,
            tvb, curr_offset, 1,
            "Environment Length: %u",
            oct_len);

        curr_offset++;

        add_string[0] = '\0';
        consumed =
            elem_downlink_re_aux(tvb, subtree, curr_offset, len - (curr_offset - offset), add_string, string_len);

        if (add_string[0] != '\0')
        {
            proto_item_append_text(item, "%s", add_string);
        }

        /*
         * +1 is for environment length
         */
        proto_item_set_len(item, consumed + 1);

        curr_offset += consumed;
    }

    g_snprintf(add_string, string_len, " - %u environment%s",
        num_envs, plurality(num_envs, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.26
 * UNUSED
 */

/*
 * IOS 6.2.2.27
 * UNUSED
 */

/*
 * IOS 6.2.2.28
 * UNUSED
 */

/*
 * IOS 6.2.2.29
 * UNUSED
 */

/*
 * IOS 6.2.2.30
 */
static guint8
elem_pdsn_ip_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_pdsn_ip_addr, tvb, curr_offset, len, FALSE);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.24
 */
static guint8
elem_s_pdsn_ip_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_s_pdsn_ip_addr, tvb, curr_offset, len, FALSE);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.31
 */
static guint8
elem_ho_pow_lev(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      consumed;
    guint8      num_cells;
    proto_item  *item = NULL;
    proto_tree  *subtree = NULL;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Number of Cells: %u",
        oct);

    curr_offset++;

    SHORT_DATA_CHECK(len - (curr_offset - offset), (guint32) 6);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  ID Type: %u",
        a_bigbuf,
        (oct & 0x60) >> 5);

    other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Handoff Power Level: %u",
        a_bigbuf,
        oct & 0x1f);

    curr_offset++;

    item =
        proto_tree_add_text(tree,
            tvb, curr_offset, -1,
            "Cell [1]");

    subtree = proto_item_add_subtree(item, ett_cell_list);

    add_string[0] = '\0';
    consumed =
        elem_cell_id_aux(tvb, subtree, curr_offset,
            len - (curr_offset - offset), add_string, string_len, 0x7);

    if (add_string[0] != '\0')
    {
        proto_item_append_text(item, "%s", add_string);
    }

    proto_item_set_len(item, consumed);

    curr_offset += consumed;

    num_cells = 1;

    while ((len - (curr_offset - offset)) >= 3)
    {
        num_cells++;

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Handoff Power Level: %u",
            a_bigbuf,
            oct & 0x1f);

        curr_offset++;

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, -1,
                "Cell [%u]",
                num_cells);

        subtree = proto_item_add_subtree(item, ett_cell_list);

        add_string[0] = '\0';
        consumed =
            elem_cell_id_aux(tvb, subtree, curr_offset,
                len - (curr_offset - offset), add_string, string_len, 0x2);

        if (add_string[0] != '\0')
        {
            proto_item_append_text(item, "%s", add_string);
        }

        proto_item_set_len(item, consumed);

        curr_offset += consumed;
    }

    g_snprintf(add_string, string_len, " - %u cell%s",
        num_cells, plurality(num_cells, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.32
 */
static guint8
elem_uz_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 2,
        "UZID: %u",
        value);

    curr_offset += 2;

    g_snprintf(add_string, string_len, " - (%u)", value);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.33
 * UNUSED
 */

/*
 * IOS 5 4.2.77
 */
static guint8
elem_info_rec_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      rec_type;
    guint8      num_recs;
    guint32     curr_offset;
    const gchar *str;
    gint        idx;

    curr_offset = offset;

    num_recs = 0;

    while ((len - (curr_offset - offset)) > 0)
    {
        num_recs++;

        rec_type = tvb_get_guint8(tvb, curr_offset);

        str = match_strval_idx((guint32) rec_type, ansi_rev_ms_info_rec_str, &idx);

        if (str == NULL)
        {
            str = "Reserved";
        }

        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "Information Record Type - %u: (%u) %s",
            num_recs,
            rec_type,
            str);

        curr_offset++;
    }

    g_snprintf(add_string, string_len, " - %u request%s",
        num_recs, plurality(num_recs, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.34
 */
static guint8
elem_is2000_chan_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint8      num_chan;
    guint32     value;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  OTD: Mobile will %sbe using OTD",
        a_bigbuf,
        (oct & 0x80) ? "" : "not ");

    num_chan = (oct & 0x70) >> 4;

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Channel Count: %u",
        a_bigbuf,
        num_chan);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Frame Offset: (%u), %.2f ms",
        a_bigbuf,
        oct & 0x0f,
        (oct & 0x0f) * 1.25);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    SHORT_DATA_CHECK(len - (curr_offset - offset), 6);

    do
    {
        oct = tvb_get_guint8(tvb, curr_offset);

        switch (oct)
        {
        case 0x01: str = "Fundamental Channel (FCH) TIA/EIA/IS-2000"; break;
        case 0x02: str = "Dedicated Control Channel (DCCH) TIA/EIA/IS-2000"; break;
        case 0x03: str = "Supplemental Channel (SCH) TIA/EIA/IS-2000"; break;
        default:
            if ((oct >= 0x80) && (oct <= 0x9f)) { str = "Reserved for UMTS"; }
            else { str = "Reserved"; }
            break;
        }

        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "Physical Channel Type: %s",
            str);

        curr_offset++;

        oct = tvb_get_guint8(tvb, curr_offset);

        switch (global_a_variant)
        {
        case A_VARIANT_IOS401:
            other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
            proto_tree_add_text(tree, tvb, curr_offset, 1,
                "%s :  Reserved",
                a_bigbuf);
            break;

        case A_VARIANT_IOS501:
            other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
            proto_tree_add_text(tree, tvb, curr_offset, 1,
                "%s :  Rev_FCH_Gating",
                a_bigbuf);
            break;
        }

        switch ((oct & 0x60) >> 5)
        {
        case 0: str = "Gating rate 1"; break;
        case 1: str = "Gating rate 1/2"; break;
        case 2: str = "Gating rate 1/4"; break;
        default:
            str = "Reserved";
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Pilot Gating Rate: %s",
            a_bigbuf,
            str);

        other_decode_bitfield_value(a_bigbuf, oct, 0x18, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  QOF Mask",
            a_bigbuf);

        value = tvb_get_guint8(tvb, curr_offset + 1);

        other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Walsh Code Channel Index (MSB): %u",
            a_bigbuf,
            ((guint32) (oct & 0x07) << 8) | value);

        curr_offset++;

        other_decode_bitfield_value(a_bigbuf, value, 0xff, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Walsh Code Channel Index (LSB)",
            a_bigbuf);

        curr_offset++;

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0xff, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Pilot PN Code (LSB)",
            a_bigbuf);

        curr_offset++;

        value = oct;
        oct = tvb_get_guint8(tvb, curr_offset);
        value |= ((guint32) (oct & 0x80)) << 1;

        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Pilot PN Code (MSB): %u",
            a_bigbuf,
            value);

        switch (global_a_variant)
        {
        case A_VARIANT_IOS401:
            other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
            proto_tree_add_text(tree, tvb, curr_offset, 1,
                "%s :  Reserved",
                a_bigbuf);
            break;

        case A_VARIANT_IOS501:
            other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
            proto_tree_add_text(tree, tvb, curr_offset, 1,
                "%s :  Reserved",
                a_bigbuf);

            other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
            proto_tree_add_text(tree, tvb, curr_offset, 1,
                "%s :  Power Combined",
                a_bigbuf);
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Frequency Included",
            a_bigbuf);

        value = tvb_get_guint8(tvb, curr_offset + 1) | ((oct & 0x07) << 8);

        other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  ARFCN (MSB): %u",
            a_bigbuf,
            value);

        curr_offset++;

        other_decode_bitfield_value(a_bigbuf, value & 0x00ff, 0xff, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  ARFCN (LSB)",
            a_bigbuf);

        curr_offset++;
    }
    while ((len - (curr_offset - offset)) >= 6);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.35
 * NO ASSOCIATED DATA
 */

/*
 * IOS 6.2.2.36
 */
static guint8
elem_is95_ms_meas_chan_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    gint        temp_int;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    temp_int = (oct & 0xf8) >> 3;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_BAND_CLASS_STR))
    {
        str = "Reserved";
    }
    else
    {
        str = band_class_str[temp_int];
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Band Class: %s",
        a_bigbuf,
        str);

    value = tvb_get_guint8(tvb, curr_offset + 1) | ((oct & 0x07) << 8);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  ARFCN (MSB): %u",
        a_bigbuf,
        value);

    curr_offset++;

    other_decode_bitfield_value(a_bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  ARFCN (LSB)",
        a_bigbuf);

    g_snprintf(add_string, string_len, " - (ARFCN: %u)", value);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.37
 */
static guint8
elem_clg_party_ascii_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    guint8      *poctets;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Extension: %s",
        a_bigbuf,
        (oct & 0x80) ? "Not extended" : "Extended");

    switch ((oct & 0x70) >> 4)
    {
    case 0: str = "Unknown"; break;
    case 1: str = "International number"; break;
    case 2: str = "National number"; break;
    case 3: str = "Network-specific number"; break;
    case 4: str = "Dedicated PAD access, short code"; break;
    case 5: str = "Reserved"; break;
    case 6: str = "Reserved"; break;
    default:
        str = "Reserved for extension";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Type of Number: %s",
        a_bigbuf,
        str);

    switch (oct & 0x0f)
    {
    case 0x00: str = "Unknown"; break;
    case 0x01: str = "ISDN/Telephony Numbering (ITU recommendation E.164/E.163)"; break;
    case 0x03: str = "Data Numbering (ITU-T Rec. X.121)"; break;
    case 0x04: str = "Telex Numbering (ITU-T Rec. F.69)"; break;
    case 0x07: str = "Reserved for extension"; break;
    case 0x08: str = "National Numbering"; break;
    case 0x09: str = "Private Numbering"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Number Plan Identification: %s",
        a_bigbuf,
        str);

    curr_offset++;

    if (!(oct & 0x80))
    {
        /* octet 3a */

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
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
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Presentation Indicator: %s",
            a_bigbuf,
            str);

        switch (oct & 0x03)
        {
        case 0: str = "User-provided, not screened"; break;
        case 1: str = "User-provided, verified and passed"; break;
        case 2: str = "User-provided, verified and failed"; break;
        default:
            str = "Network-provided";
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x1c, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Screening Indicator: %s",
            a_bigbuf,
            str);

        curr_offset++;
    }

    poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

    proto_tree_add_string_format(tree, hf_ansi_a_clg_party_ascii_num,
        tvb, curr_offset, len - (curr_offset - offset),
        (gchar *) poctets,
        "Digits: %s",
        (gchar *) format_text(poctets, len - (curr_offset - offset)));

    curr_offset += len - (curr_offset - offset);

    g_snprintf(add_string, string_len, " - (%s)", poctets);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.38
 */
static guint8
elem_l3_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    tvbuff_t    *l3_tvb;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len,
        "Layer 3 Information");

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
 * IOS 6.2.2.39
 * Protocol Discriminator
 */

/*
 * IOS 6.2.2.40
 * Reserved Octet
 */

/*
 * IOS 6.2.2.41
 * Location Updating Type
 * UNUSED in SPEC!
 */

/*
 * IOS 6.2.2.42
 * Simple data no decode required
 */

/*
 * IOS 6.2.2.43
 */
static guint8
elem_lai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint16     value;
    guint32     curr_offset;
    gchar       mcc[4];
    gchar       mnc[4];

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    mcc[0] = Dgt_tbcd.out[oct & 0x0f];
    mcc[1] = Dgt_tbcd.out[(oct & 0xf0) >> 4];

    oct = tvb_get_guint8(tvb, curr_offset+1);

    mcc[2] = Dgt_tbcd.out[(oct & 0x0f)];
    mcc[3] = '\0';

    mnc[2] = Dgt_tbcd.out[(oct & 0xf0) >> 4];

    oct = tvb_get_guint8(tvb, curr_offset+2);

    mnc[0] = Dgt_tbcd.out[(oct & 0x0f)];
    mnc[1] = Dgt_tbcd.out[(oct & 0xf0) >> 4];
    mnc[3] = '\0';

    proto_tree_add_text(tree,
        tvb, curr_offset, 3,
        "Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s",
        mcc,
        mnc);

    curr_offset += 3;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 2,
        "Location Area Code (LAC): 0x%04x (%u)",
        value,
        value);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.44
 */
static guint8
elem_rej_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
    case 0x01: str = "Reserved"; break;
    case 0x02: str = "MIN/IMSI unknown in HLR"; break;
    case 0x03: str = "Illegal MS"; break;
    case 0x04: str = "TMSI/IMSI/MIN unknown in VLR"; break;
    case 0x05: str = "Reserved"; break;
    case 0x0b: str = "Roaming not allowed"; break;
    case 0x0c: str = "Location area not allowed"; break;
    case 0x20: str = "Service option not supported"; break;
    case 0x21: str = "Requested service option not subscribed"; break;
    case 0x22: str = "Service option temporarily out of order"; break;
    case 0x26: str = "Call cannot be identified"; break;
    case 0x51: str = "Network failure"; break;
    case 0x56: str = "Congestion"; break;
    case 0x62: str = "Message type non-existent or not implemented"; break;
    case 0x63: str = "Information element non-existent or not implemented"; break;
    case 0x64: str = "Invalid information element contents"; break;
    case 0x65: str = "Message not compatible with the call state"; break;
    case 0x66: str = "Protocol error, unspecified"; break;
    case 0x6e: str = "Invalid message, unspecified"; break;
    case 0x6f: str = "Mandatory information element error"; break;
    default:
        str = "Reserved";
        break;
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Reject Cause Value: (%u) %s",
        oct,
        str);

    curr_offset++;

    g_snprintf(add_string, string_len, " - (%s)", str);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.78
 */
static guint8
elem_anchor_pdsn_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_anchor_ip_addr, tvb, curr_offset, len, FALSE);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.80
 */
static guint8
elem_anchor_pp_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_anchor_pp_ip_addr, tvb, curr_offset, len, FALSE);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.45
 */
static guint8
elem_auth_chlg_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    switch (oct & 0x0f)
    {
    case 1: str = "RAND 32 bits"; break;
    case 2: str = "RANDU 24 bits"; break;
    case 4: str = "RANDSSD 56 bits"; break;
    case 8: str = "RANDBS 32 bits"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Random Number Type: (%u) %s",
        a_bigbuf,
        oct & 0x0f,
        str);

    curr_offset++;

    proto_tree_add_text(tree,
        tvb, curr_offset, len - (curr_offset - offset),
        "RAND/RANDU/RANDBS/RANDSSD Value");

    g_snprintf(add_string, string_len, " - (%s)", str);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.46
 */
static guint8
elem_auth_resp_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    switch (oct & 0x0f)
    {
    case 1: str = "AUTHR"; break;
    case 2: str = "AUTHU"; break;
    case 4: str = "AUTHBS"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Auth Signature Type: (%u) %s",
        a_bigbuf,
        oct & 0x0f,
        str);

    curr_offset++;

    proto_tree_add_text(tree,
        tvb, curr_offset, len - (curr_offset - offset),
        "Auth Signature");

    g_snprintf(add_string, string_len, " - (%s)", str);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.47
 */
static guint8
elem_auth_param_count(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Count: %u",
        a_bigbuf,
        oct & 0x3f);

    curr_offset++;

    g_snprintf(add_string, string_len, " - (%u)", oct & 0x3f);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.48
 */
static guint8
elem_mwi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Number of Messages: %u",
        oct);

    curr_offset++;

    g_snprintf(add_string, string_len, " - (%u)", oct);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.49
 * Progress
 * UNUSED in SPEC and no IEI!
 */

/*
 * IOS 6.2.2.50
 */
static guint8
elem_signal(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
    case 0x00: str = "Dial tone on"; break;
    case 0x01: str = "Ring back tone on"; break;
    case 0x02: str = "Intercept tone on"; break;
    case 0x03: str = "Network congestion (reorder) tone on"; break;
    case 0x04: str = "Busy tone on"; break;
    case 0x05: str = "Confirm tone on"; break;
    case 0x06: str = "Answer tone on"; break;
    case 0x07: str = "Call waiting tone on"; break;
    case 0x08: str = "Off-hook warning tone on"; break;
    case 0x3f: str = "Tones off"; break;
    case 0x40: str = "Normal Alerting"; break;
    case 0x41: str = "Inter-group Alerting"; break;
    case 0x42: str = "Special/Priority Alerting"; break;
    case 0x43: str = "Reserved (ISDN Alerting pattern 3)"; break;
    case 0x44: str = "Ping Ring (abbreviated alert)"; break;
    case 0x45: str = "Reserved (ISDN Alerting pattern 5)"; break;
    case 0x46: str = "Reserved (ISDN Alerting pattern 6)"; break;
    case 0x47: str = "Reserved (ISDN Alerting pattern 7)"; break;
    case 0x63: str = "Abbreviated intercept"; break;
    case 0x65: str = "Abbreviated reorder"; break;
    case 0x4f: str = "Alerting off"; break;
    default:
        str = "Unknown";
        break;
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Signal Value: (%u) %s",
        oct,
        str);

    g_snprintf(add_string, string_len, " - (%s)", str);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    switch (oct & 0x03)
    {
    case 0: str = "Medium pitch (standard alert)"; break;
    case 1: str = "High pitch"; break;
    case 2: str = "Low pitch"; break;
    default:
        str = "Reserved";
        break;
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s : Alert Pitch: %s",
        a_bigbuf,
        str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.51
 * CM Service Type
 */

/*
 * IOS 6.2.2.52
 */
static guint8
elem_cld_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      *poctets;
    guint32     curr_offset;
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
    case 0: str = "Unknown"; break;
    case 1: str = "International number"; break;
    case 2: str = "National number"; break;
    case 3: str = "Network specific number"; break;
    case 4: str = "Dedicated PAD access, short code"; break;
    case 7: str = "Reserved for extension"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Type of Number: %s",
        a_bigbuf,
        str);

    switch (oct & 0x0f)
    {
    case 0x00: str = "Unknown"; break;
    case 0x01: str = "ISDN/telephony number plan (ITU recommendation E.164/E.163)"; break;
    case 0x03: str = "Data number plan (ITU recommendation X.121)"; break;
    case 0x04: str = "Telex numbering plan (ITU recommendation F.69)"; break;
    case 0x07: str = "Reserved for extension"; break;
    case 0x08: str = "National numbering plan"; break;
    case 0x09: str = "Private numbering plan"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Numbering Plan Identification: %s",
        a_bigbuf,
        str);

    curr_offset++;

    poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

    my_dgt_tbcd_unpack(a_bigbuf, poctets, len - (curr_offset - offset),
        &Dgt_tbcd);

    proto_tree_add_string_format(tree, hf_ansi_a_cld_party_bcd_num,
        tvb, curr_offset, len - (curr_offset - offset),
        a_bigbuf,
        "BCD Digits: %s",
        a_bigbuf);

    g_snprintf(add_string, string_len, " - (%s)", a_bigbuf);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.53
 * UNUSED in SPEC and no IEI!
 */
#ifdef MAYBE_USED_FOR_OLDER_CODECS
static guint8
elem_clg_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      *poctets;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Extension: %s",
        a_bigbuf,
        (oct & 0x80) ? "Not extended" : "Extended");

    switch ((oct & 0x70) >> 4)
    {
    case 0: str = "Unknown"; break;
    case 1: str = "International number"; break;
    case 2: str = "National number"; break;
    case 3: str = "Network specific number"; break;
    case 4: str = "Dedicated PAD access, short code"; break;
    case 7: str = "Reserved for extension"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Type of Number: %s",
        a_bigbuf,
        str);

    switch (oct & 0x0f)
    {
    case 0x00: str = "Unknown"; break;
    case 0x01: str = "ISDN/telephony number plan (ITU recommendation E.164/E.163)"; break;
    case 0x03: str = "Data number plan (ITU recommendation X.121)"; break;
    case 0x04: str = "Telex numbering plan (ITU recommendation F.69)"; break;
    case 0x07: str = "Reserved for extension"; break;
    case 0x08: str = "National numbering plan"; break;
    case 0x09: str = "Private numbering plan"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Numbering Plan Identification: %s",
        a_bigbuf,
        str);

    curr_offset++;

    if (!(oct & 0x80))
    {
        /* octet 3a */

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
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
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Presentation Indicator: %s",
            a_bigbuf,
            str);

        switch (oct & 0x03)
        {
        case 0: str = "User-provided, not screened"; break;
        case 1: str = "User-provided, verified and passed"; break;
        case 2: str = "User-provided, verified and failed"; break;
        default:
            str = "Network-provided";
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x1c, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Screening Indicator: %s",
            a_bigbuf,
            str);

        curr_offset++;
    }

    poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

    my_dgt_tbcd_unpack(a_bigbuf, poctets, len - (curr_offset - offset),
        &Dgt_tbcd);

    proto_tree_add_string_format(tree, hf_ansi_a_clg_party_bcd_num,
        tvb, curr_offset, len - (curr_offset - offset),
        a_bigbuf,
        "BCD Digits: %s",
        a_bigbuf);

    g_snprintf(add_string, string_len, " - (%s)", a_bigbuf);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}
#endif

/*
 * IOS 6.2.2.54
 */
static guint8
elem_qos_params(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Packet Priority: %u",
        a_bigbuf,
        oct & 0x0f);

    g_snprintf(add_string, string_len, " - (%u)", oct & 0x0f);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.55
 */
static guint8
elem_cause_l3(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Extension",
        a_bigbuf);

    switch ((oct & 0x60) >> 5)
    {
    case 0: str = "Standard as described in ITU Recommendation Q.931"; break;
    case 1: str = "Reserved for other international standards"; break;
    case 2: str = "National standard"; break;
    default:
        str = "Reserved for other international standards";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Coding Standard: %s",
        a_bigbuf,
        str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
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
        str = "Reserved"; break;
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
        "%s :  Extension",
        a_bigbuf);

    switch ((oct & 0x70) >> 4)
    {
    case 0: str = "normal event"; break;
    case 1: str = "normal event"; break;
    case 2: str = "resource unavailable"; break;
    case 3: str = "service or option not available"; break;
    case 4: str = "service or option not implemented"; break;
    case 5: str = "invalid message (e.g., parameter out of range)"; break;
    case 6: str = "protocol error (e.g., unknown message)"; break;
    default:
        str = "interworking";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Class: (%u) %s",
        a_bigbuf,
        (oct & 0x70) >> 4,
        str);

    switch (oct & 0x7f)
    {
    case 0x01: str = "Unassigned (unallocated) number"; break;
    case 0x03: str = "No route to destination"; break;
    case 0x06: str = "Channel unacceptable"; break;
    case 0x0F: str = "Procedure failed"; break;
    case 0x10: str = "Normal Clearing"; break;
    case 0x11: str = "User busy"; break;
    case 0x12: str = "No user responding"; break;
    case 0x13: str = "User alerting, no answer"; break;
    case 0x15: str = "Call rejected"; break;
    case 0x16: str = "Number changed New destination"; break;
    case 0x1A: str = "Non selected user clearing"; break;
    case 0x1B: str = "Destination out of order"; break;
    case 0x1C: str = "Invalid number format (incomplete number)"; break;
    case 0x1D: str = "Facility rejected"; break;
    case 0x1F: str = "Normal, unspecified"; break;
    case 0x22: str = "No circuit/channel available"; break;
    case 0x26: str = "Network out of order"; break;
    case 0x29: str = "Temporary failure"; break;
    case 0x2A: str = "Switching equipment congestion"; break;
    case 0x2B: str = "Access information discarded information element ids"; break;
    case 0x2C: str = "requested circuit/channel not available"; break;
    case 0x2F: str = "Resources unavailable, unspecified"; break;
    case 0x31: str = "Quality of service unavailable"; break;
    case 0x32: str = "Requested facility not subscribed"; break;
    case 0x33: str = "Request MUX option or rates unavailable"; break;
    case 0x39: str = "Bearer capability not authorized"; break;
    case 0x3A: str = "Bearer capability not presently available"; break;
    case 0x3B: str = "SSD Update Rejected"; break;
    case 0x3F: str = "Service or option not available, unspecified"; break;
    case 0x41: str = "Bearer service not implemented"; break;
    case 0x45: str = "Requested facility not implement"; break;
    case 0x46: str = "Only restricted digital information bearer capability is available"; break;
    case 0x4F: str = "Service or option not implemented, unspecified"; break;
    case 0x51: str = "Reserved"; break;
    case 0x58: str = "Incompatible destination incompatible parameter"; break;
    case 0x5B: str = "Invalid transit network selection"; break;
    case 0x5F: str = "Invalid message, unspecified"; break;
    case 0x60: str = "Mandatory information element error information element identifier(s)"; break;
    case 0x61: str = "Message type nonexistent or not implemented message type"; break;
    case 0x62: str = "Message not compatible with control state message type or message type nonexistent or not implemented"; break;
    case 0x64: str = "Invalid information element contents Information element Identifier(s)"; break;
    case 0x65: str = "Message not compatible with call state message type"; break;
    case 0x6F: str = "Protocol error, unspecified"; break;
    case 0x7F: str = "Interworking, unspecified"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Value: (%u)",
        a_bigbuf,
        oct & 0x0f);

    g_snprintf(add_string, string_len, " - (%u) %s", oct & 0x7f, str);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.56
 * A3/A7
 */

/*
 * IOS 6.2.2.57
 * A3/A7
 */

/*
 * IOS 6.2.2.58
 */
static guint8
elem_xmode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfe, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  TFO Mode: %s",
        a_bigbuf,
        (oct & 0x01) ? "TFO" : "tandem");

    g_snprintf(add_string, string_len, " - (%s)",
        (oct & 0x01) ? "TFO" : "tandem");

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.59
 * UNUSED
 */

/*
 * IOS 6.2.2.60
 * NO ASSOCIATED DATA
 */

/*
 * IOS 6.2.2.61
 */
static guint8
elem_reg_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct)
    {
    case 0x00: str = "Timer-based"; break;
    case 0x01: str = "Power-up"; break;
    case 0x02: str = "Zone-based"; break;
    case 0x03: str = "Power-down"; break;
    case 0x04: str = "Parameter-change"; break;
    case 0x05: str = "Ordered"; break;
    case 0x06: str = "Distance-based"; break;
    case 0x07: str = "User Zone-based"; break;
    case 0x09: str = "BCMC Registration"; break;
    default:
        str = "Reserved";
        break;
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Location Registration Type: %s",
        str);

    g_snprintf(add_string, string_len, " - (%s)", str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.62
 */
static guint8
elem_tag(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    value = tvb_get_ntohl(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 4,
        "Tag Value: %u",
        value);

    g_snprintf(add_string, string_len, " - (%u)", value);

    curr_offset += 4;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.63
 */
static guint8
elem_hho_params(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      oct;
    gint        temp_int;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    temp_int = oct & 0x1f;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_BAND_CLASS_STR))
    {
        str = "Reserved";
    }
    else
    {
        str = band_class_str[temp_int];
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Band Class: %s",
        a_bigbuf,
        str);

    curr_offset++;

    g_snprintf(add_string, string_len, " - (%s)", str);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Number of Preamble Frames: %u",
        a_bigbuf,
        (oct & 0xe0) >> 5);

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reset L2: %s Layer 2 Acknowledgement",
        a_bigbuf,
        (oct & 0x10) ? "Reset" : "Do not reset");

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reset FPC: %s counters",
        a_bigbuf,
        (oct & 0x10) ? "Reset" : "Do not reset");

    switch ((oct & 0x06) >> 1)
    {
    case 0: str = "Encryption disabled"; break;
    case 1: str = "Encryption enabled"; break;
    default:
        str = "Unknown";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x06, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Encryption Mode: %s",
        a_bigbuf,
        str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Private LCM: %s Private Long Code Mask",
        a_bigbuf,
        (oct & 0x01) ? "Use" : "Do not use");

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);
        break;

    case A_VARIANT_IOS501:
        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s :  Rev_Pwr_Cntl_Delay_Incl",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x60, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Rev_Pwr_Cntl_Delay",
            a_bigbuf);
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Nom_Pwr_Ext",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Nom_Pwr: %u",
        a_bigbuf,
        oct & 0x0f);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x3e, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  FPC Subchannel Information: %u",
        a_bigbuf,
        (oct & 0x3e) >> 1);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  FPC Subchannel Information Included",
        a_bigbuf);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0e, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Power Control Step: %u",
        a_bigbuf,
        (oct & 0x0e) >> 1);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Power Control Step Included",
        a_bigbuf);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.64
 * UNUSED
 */

/*
 * IOS 6.2.2.65
 */
static guint8
elem_sw_ver(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      major, minor, point;
    guint32     curr_offset;

    curr_offset = offset;

    major = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "IOS Major Revision Level: %u",
        major);

    curr_offset++;

    minor = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "IOS Minor Revision Level: %u",
        minor);

    curr_offset++;

    point = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "IOS Point Revision Level: %u",
        point);

    curr_offset++;

    g_snprintf(add_string, string_len, " - (IOS %u.%u.%u)", major, minor, point);

    if (len > 3)
    {
        proto_tree_add_text(tree, tvb, curr_offset, len - 3,
            "Manufacturer/Carrier Software Information");

        curr_offset += len - 3;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.66
 */
static guint8
elem_so(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint16     value;
    guint32     curr_offset;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, value, 0x8000, 16);
    proto_tree_add_text(tree,
        tvb, curr_offset, 2,
        "%s :  Proprietary Indicator",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, value, 0x7000, 16);
    proto_tree_add_text(tree,
        tvb, curr_offset, 2,
        "%s :  Service Option Revision",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, value, 0x0fff, 16);
    proto_tree_add_text(tree,
        tvb, curr_offset, 2,
        "%s :  Base Service Option Number",
        a_bigbuf);

    g_snprintf(add_string, string_len, " - (%u) (0x%04x)", value, value);

    proto_tree_add_uint_format(tree, hf_ansi_a_so, tvb,
        curr_offset, 2, value,
        "%s %s",
        &add_string[3],
        ansi_a_so_int_to_str(value));

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.73
 */
static guint8
elem_soci(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  SOCI: %u",
        a_bigbuf,
        oct & 0x07);

    g_snprintf(add_string, string_len, " - (%u)", oct);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.74
 */
static guint8
elem_so_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      num_so;
    guint8      inst;
    guint32     curr_offset;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    num_so = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Number of Service Option instances: %u",
        num_so);

    /*
     * this is in case we leave the function before the
     * loop through the instances
     */
    g_snprintf(add_string, string_len, " - %u service options", num_so);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    SHORT_DATA_CHECK(len - (curr_offset - offset), 3);

    inst = 1;

    do
    {
        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, 1,
                "Service Option Instance [%u]",
                inst);

        subtree = proto_item_add_subtree(item, ett_so_list);

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
        proto_tree_add_text(subtree,
            tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x38, 8);
        proto_tree_add_text(subtree,
            tvb, curr_offset, 1,
            "%s :  SR_ID: %u",
            a_bigbuf,
            (oct & 0x38) >> 3);

        other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
        proto_tree_add_text(subtree,
            tvb, curr_offset, 1,
            "%s :  SOCI: %u",
            a_bigbuf,
            oct & 0x07);

        curr_offset++;

        curr_offset += elem_so(tvb, subtree, curr_offset, len, add_string, string_len);
        add_string[0] = '\0';

        inst++;
    }
    while ((len - (curr_offset - offset)) >= 3);

    /*
     * this is because 'add_string' was used by 'elem_so()'
     */
    g_snprintf(add_string, string_len, " - %u service options", num_so);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.70
 */
static guint8
elem_acc_net_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint32     value;
    guint32     sid, nid, pzid;
    guint32     curr_offset;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);
    sid = value & 0x7fff;

    other_decode_bitfield_value(a_bigbuf, value >> 8, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, value >> 8, 0x7f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  SID (MSB), %u",
        a_bigbuf,
        sid);

    other_decode_bitfield_value(a_bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, tvb, curr_offset + 1, 1,
        "%s :  SID (LSB)",
        a_bigbuf);

    curr_offset += 2;

    nid = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 2,
        "NID: %u",
        nid);

    curr_offset += 2;

    pzid = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 2,
        "PZID: %u",
        pzid);

    curr_offset += 2;

    g_snprintf(add_string, string_len, " - (SID/NID/PZID: %u/%u/%u)", sid, nid, pzid);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}


#define ADDS_APP_UNKNOWN        0x00
#define ADDS_APP_ADS            0x01
#define ADDS_APP_FAX            0x02
#define ADDS_APP_SMS            0x03
#define ADDS_APP_OTA            0x04
#define ADDS_APP_PDS            0x05            /* aka PLD */
#define ADDS_APP_SDB            0x06
#define ADDS_APP_HRPD           0x07
#define ADDS_APP_EXT_INTL       0x3E
#define ADDS_APP_EXT            0x3F

static const value_string ansi_a_adds_strings[] = {
    { ADDS_APP_UNKNOWN,         "UNKNOWN" },
    { ADDS_APP_ADS,             "ADS" },
    { ADDS_APP_FAX,             "FAX" },
    { ADDS_APP_SMS,             "SMS" },
    { ADDS_APP_OTA,             "OTA" },
    { ADDS_APP_PDS,             "PDS" },
    { ADDS_APP_SDB,             "SDB" },
    { ADDS_APP_HRPD,            "HRPD" },
    { ADDS_APP_EXT_INTL,        "EXT_INTL" },
    { ADDS_APP_EXT,             "EXT" },
    { 0,                        NULL}
};

/*
 * IOS 6.2.2.67
 */
static guint8
elem_adds_user_part(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    guint8      adds_app;
    guint32     curr_offset;
    const gchar *str;
    tvbuff_t    *adds_tvb;
    gint        idx;
    proto_tree  *subtree;
    proto_item  *item;

    curr_offset = offset;
    adds_app = 0;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    adds_app = oct & 0x3f;

    str = match_strval_idx((guint32) adds_app, ansi_a_adds_strings, &idx);
    if (str == NULL)
    {
        str = "Reserved";
    }
    g_snprintf(add_string, string_len, " - (%s)", str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Data Burst Type: %s",
        a_bigbuf,
        str);

    curr_offset++;

    item =
        proto_tree_add_text(tree, tvb, curr_offset, len - 1,
            "Application Data Message");

    subtree = proto_item_add_subtree(item, ett_adds_user_part);

    switch (adds_app)
    {
    case ADDS_APP_SMS:
        adds_tvb = tvb_new_subset(tvb, curr_offset, len - 1, len - 1);

        dissector_try_uint(is637_dissector_table,
            0, adds_tvb, g_pinfo, g_tree);

        curr_offset += (len - 1);
        break;

    case ADDS_APP_OTA:
        adds_tvb = tvb_new_subset(tvb, curr_offset, len - 1, len - 1);

        dissector_try_uint(is683_dissector_table,
            (g_pinfo->p2p_dir == P2P_DIR_RECV), adds_tvb, g_pinfo, g_tree);

        curr_offset += (len - 1);
        break;

    case ADDS_APP_PDS:
        adds_tvb = tvb_new_subset(tvb, curr_offset, len - 1, len - 1);

        dissector_try_uint(is801_dissector_table,
            (g_pinfo->p2p_dir == P2P_DIR_RECV), adds_tvb, g_pinfo, g_tree);

        curr_offset += (len - 1);
        break;

    case ADDS_APP_SDB:
        /*
         * no SDB dissector, push to GRE/A11 dissector ?
         */
        curr_offset += (len - 1);
        break;

    case ADDS_APP_EXT_INTL:
        /*
         * no generic External International dissector
         */
        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_text(subtree,
            tvb, curr_offset, 2,
            "Extended Burst Type - International: 0x%04x", value);

        curr_offset += 2;

        proto_tree_add_text(tree, tvb, curr_offset, len - (curr_offset - offset),
            "Data");

        curr_offset += len - (curr_offset - offset);
        break;

    case ADDS_APP_EXT:
        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_text(subtree,
            tvb, curr_offset, 2,
            "Extended Burst Type: 0x%04x", value);

        curr_offset += 2;

        proto_tree_add_text(subtree, tvb, curr_offset, len - (curr_offset - offset),
            "Data");

        curr_offset += len - (curr_offset - offset);
        break;

    default:
        /*
         * no sub-dissectors
         */
        curr_offset += (len - 1);
        break;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.75
 */
static guint8
elem_amps_hho_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Encryption Mode: (%u) %s",
        a_bigbuf,
        oct & 0x03,
        (oct & 0x03) ? "enabled" : "disabled");

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.68
 */
static guint8
elem_is2000_scr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct, num_con_rec, i;
    guint8      bit_mask, bit_offset;
    guint32     curr_offset, saved_offset;
    guint32     value;
    guint       is2000_portion_len;
    proto_tree  *scr_subtree, *subtree;
    proto_item  *item = NULL;
    const gchar *str = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Bit-Exact Length Fill Bits: %u",
        a_bigbuf,
        oct & 0x07);

    curr_offset++;

    is2000_portion_len = len - (curr_offset - offset);

    /*
     * the following decode was modified from the packet-ansi_map.c version
     */

    SHORT_DATA_CHECK(is2000_portion_len, 7);

    saved_offset = curr_offset;

    item =
        proto_tree_add_text(tree, tvb, curr_offset,
            is2000_portion_len,
            "IS-2000 Service Configuration Record Content");

    scr_subtree =
        proto_item_add_subtree(item, ett_scr);

    proto_tree_add_text(scr_subtree, tvb,
        curr_offset, 2,
        "FOR_MUX_OPTION:  Forward Traffic Channel multiplex option");

    curr_offset += 2;

    proto_tree_add_text(scr_subtree, tvb,
        curr_offset, 2,
        "REV_MUX_OPTION:  Reverse Traffic Channel multiplex option");

    curr_offset += 2;

    proto_tree_add_text(scr_subtree, tvb,
        curr_offset, 1,
        "FOR_RATES:  Transmission rates of the Forward Fundamental Channel");

    curr_offset += 1;

    proto_tree_add_text(scr_subtree, tvb,
        curr_offset, 1,
        "REV_RATES:  Transmission rates of the Reverse Fundamental Channel");

    curr_offset += 1;

    num_con_rec = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(scr_subtree, tvb,
        curr_offset, 1,
        "NUM_CON_REC:  Number of service option connection records, %u",
        num_con_rec);

    curr_offset += 1;

    for (i=1; i <= num_con_rec; i++)
    {
        oct = tvb_get_guint8(tvb, curr_offset);

        item =
            proto_tree_add_text(scr_subtree, tvb,
                curr_offset, oct /* oct already includes the length octet itself */,
                "Service option connection record [%u]",
                i);

        subtree =
            proto_item_add_subtree(item, ett_srvc_con_rec);

        curr_offset += 1;

        oct = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_text(subtree, tvb,
            curr_offset, 1,
            "CON_REF:  Service option connection reference, %u",
            oct);

        curr_offset += 1;

        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_text(subtree, tvb,
            curr_offset, 2,
            "SERVICE_OPTION:  %s",
            ansi_a_so_int_to_str(value));

        curr_offset += 2;

        oct = tvb_get_guint8(tvb, curr_offset);

        switch ((oct & 0xf0) >> 4)
        {
        case 0x00: str = "The service option connection does not use Forward Traffic Channel traffic."; break;
        case 0x01: str = "The service option connection uses primary traffic on the Forward Traffic Channel."; break;
        case 0x02: str = "The service option connection uses secondary traffic on the Forward Traffic Channel."; break;
        default: str = "Reserved"; break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
        proto_tree_add_text(subtree, tvb,
            curr_offset, 1,
            "%s :  FOR_TRAFFIC:  Forward Traffic Channel traffic type, %s",
            a_bigbuf,
            str);

        switch (oct & 0x0f)
        {
        case 0x00: str = "The service option connection does not use Reverse Traffic Channel traffic."; break;
        case 0x01: str = "The service option connection uses primary traffic on the Reverse Traffic Channel."; break;
        case 0x02: str = "The service option connection uses secondary traffic on the Reverse Traffic Channel."; break;
        default: str = "Reserved"; break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
        proto_tree_add_text(subtree, tvb,
            curr_offset, 1,
            "%s :  REV_TRAFFIC:  Reverse Traffic Channel traffic type, %s",
            a_bigbuf,
            str);

        curr_offset += 1;

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
        proto_tree_add_text(subtree, tvb,
            curr_offset, 1,
            "%s :  UI_ENCRYPT_MODE:  Encryption mode indicator for user information privacy",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x1c, 8);
        proto_tree_add_text(subtree, tvb,
            curr_offset, 1,
            "%s :  SR_ID:  Service reference identifier",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
        proto_tree_add_text(subtree, tvb,
            curr_offset, 1,
            "%s :  RLP_INFO_INCL:  RLP information included indicator",
            a_bigbuf);

        if (oct & 0x02)
        {
            value = (oct & 0x01) << 3;
            other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);

            curr_offset += 1;

            oct = tvb_get_guint8(tvb, curr_offset);

            value |= (oct & 0xe0) >> 5;

            proto_tree_add_text(subtree, tvb,
                curr_offset - 1, 1,
                "%s :  RLP_BLOB_LEN (MSB), %u",
                a_bigbuf,
                value);

            other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
            proto_tree_add_text(subtree, tvb,
                curr_offset, 1,
                "%s :  RLP_BLOB_LEN (LSB)",
                a_bigbuf);

            other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
            proto_tree_add_text(subtree, tvb,
                curr_offset, 1,
                "%s :  RLP_BLOB (MSB)",
                a_bigbuf);

            curr_offset += 1;

            if (value > 1)
            {
                proto_tree_add_text(subtree, tvb,
                    curr_offset, value - 1,
                    "RLP_BLOB");

                curr_offset += value - 1;
            }

            oct = tvb_get_guint8(tvb, curr_offset);

            other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
            proto_tree_add_text(subtree, tvb,
                curr_offset, 1,
                "%s :  RLP_BLOB (LSB)",
                a_bigbuf);

            other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
            proto_tree_add_text(subtree, tvb,
                curr_offset, 1,
                "%s :  Reserved",
                a_bigbuf);
        }
        else
        {
            other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
            proto_tree_add_text(subtree, tvb,
                curr_offset, 1,
                "%s :  Reserved",
                a_bigbuf);
        }

        curr_offset += 1;
    }

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(scr_subtree, tvb,
        curr_offset, 1,
        "%s :  FCH_CC_INCL:  Channel configuration for the Fundamental Channel included indicator",
        a_bigbuf);

    if (oct & 0x80)
    {
        other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
        proto_tree_add_text(scr_subtree, tvb,
            curr_offset, 1,
            "%s :  FCH_FRAME_SIZE:  Fundamental Channel frame size supported indicator",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x3e, 8);
        proto_tree_add_text(scr_subtree, tvb,
            curr_offset, 1,
            "%s :  FOR_FCH_RC:  Forward Fundamental Channel Radio Configuration, %u",
            a_bigbuf,
            (oct & 0x3e) >> 1);

        other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
        value = (oct & 0x01) << 4;

        curr_offset += 1;

        oct = tvb_get_guint8(tvb, curr_offset);

        value |= (oct & 0xf0) >> 4;

        proto_tree_add_text(scr_subtree, tvb,
            curr_offset - 1, 1,
            "%s :  REV_FCH_RC:  Reverse Fundamental Channel Radio Configuration (MSB), %u",
            a_bigbuf,
            value);

        other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
        proto_tree_add_text(scr_subtree, tvb,
            curr_offset, 1,
            "%s :  REV_FCH_RC:  (LSB)",
            a_bigbuf);

        bit_mask = 0x08;
        bit_offset = 3;
    }
    else
    {
        bit_mask = 0x40;
        bit_offset = 6;
    }

    other_decode_bitfield_value(a_bigbuf, oct, bit_mask, 8);
    proto_tree_add_text(scr_subtree, tvb,
        curr_offset, 1,
        "%s :  DCCH_CC_INCL:  Channel configuration for the Dedicated Control Channel included indicator",
        a_bigbuf);

    if (oct & bit_mask)
    {
        /* can't be bothered to do the rest of the decode */

        proto_tree_add_text(scr_subtree, tvb,
            curr_offset, (is2000_portion_len - (curr_offset - saved_offset)),
            "DCCH + ? + Reserved");

        curr_offset += (is2000_portion_len - (curr_offset - saved_offset));
    }
    else
    {
        bit_mask >>= 1;
        bit_offset--;

        other_decode_bitfield_value(a_bigbuf, oct, bit_mask, 8);
        proto_tree_add_text(scr_subtree, tvb,
            curr_offset, 1,
            "%s :  FOR_SCH_CC_INCL:  Channel configuration for the Dedicated Control Channel included indicator",
            a_bigbuf);

        if (oct & bit_mask)
        {
            /* can't be bothered to do the rest of the decode */

            proto_tree_add_text(scr_subtree, tvb,
                curr_offset, (is2000_portion_len - (curr_offset - saved_offset)),
                "FOR_SCH + ? + Reserved");

            curr_offset += (is2000_portion_len - (curr_offset - saved_offset));
        }
        else
        {
            bit_mask >>= 1;
            bit_offset--;

            other_decode_bitfield_value(a_bigbuf, oct, bit_mask, 8);
            proto_tree_add_text(scr_subtree, tvb,
                curr_offset, 1,
                "%s :  REV_SCH_CC_INCL:  Channel configuration for the Dedicated Control Channel included indicator",
                a_bigbuf);

            if (oct & bit_mask)
            {
                /* can't be bothered to do the rest of the decode */

                proto_tree_add_text(scr_subtree, tvb,
                    curr_offset, (is2000_portion_len - (curr_offset - saved_offset)),
                    "REV_SCH + ? + Reserved");

                curr_offset += (is2000_portion_len - (curr_offset - saved_offset));
            }
            else
            {
                bit_mask = (0xff << (8 - bit_offset));
                bit_mask >>= (8 - bit_offset);

                other_decode_bitfield_value(a_bigbuf, oct, bit_mask, 8);
                proto_tree_add_text(scr_subtree, tvb,
                    curr_offset, 1,
                    "%s :  Reserved",
                    a_bigbuf);

                curr_offset += 1;
            }
        }
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.69
 */
static guint8
elem_is2000_nn_scr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     curr_offset;
    guint       is2000_portion_len;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Bit-Exact Length Fill Bits: %u",
        a_bigbuf,
        oct & 0x07);

    curr_offset++;

    is2000_portion_len = len - (curr_offset - offset);

#ifndef MLUM

    NO_MORE_DATA_CHECK(len);

    if (is2000_portion_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), is2000_portion_len);

        proto_tree_add_text(tree, tvb, curr_offset, is2000_portion_len,
            "IS-2000 Non-Negotiable Service Configuration Record Content");

        curr_offset += is2000_portion_len;
    }

#else


#endif

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.70
 */
static guint8
elem_is2000_mob_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint8      oct_len;
    guint32     curr_offset;
    proto_tree  *subtree;
    proto_item  *item = NULL;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);
        break;

    case A_VARIANT_IOS501:
        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  REV_PDCH Supported: IS-2000 R-PDCH %ssupported",
            a_bigbuf,
            (oct & 0x80) ? "" : "not ");

        other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  FOR_PDCH Supported: IS-2000 F-PDCH %ssupported",
            a_bigbuf,
            (oct & 0x40) ? "" : "not ");

        other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  ERAM Supported: Enhanced Rate Adaptation Mode %ssupported",
            a_bigbuf,
            (oct & 0x20) ? "" : "not ");
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  DCCH Supported: IS-2000 DCCH %ssupported",
        a_bigbuf,
        (oct & 0x10) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  FCH Supported: IS-2000 FCH %ssupported",
        a_bigbuf,
        (oct & 0x08) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  OTD Supported: Orthogonal Transmit Diversity %ssupported",
        a_bigbuf,
        (oct & 0x04) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Enhanced RC CFG Supported: Radio configuration in radio class 2 %ssupported",
        a_bigbuf,
        (oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  QPCH Supported: Quick Paging Channel %ssupported",
        a_bigbuf,
        (oct & 0x01) ? "" : "not ");

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct_len = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "FCH Information: Bit-Exact Length Octet Count: %u",
        oct_len);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    switch ((oct & 0x70) >> 4)
    {
    case 0: str = "No mobile assisted geo-location capabilities"; break;
    case 1: str = "IS801 capable (Advanced Forward Link Triangulation only (AFLT))"; break;
    case 2: str = "IS801 capable (Advanced Forward Link Triangulation and Global Positioning Systems"; break;
    case 3: str = "Global Positioning Systems Only"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Geo Location Type: %s",
        a_bigbuf,
        str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Geo Location Included",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  FCH Information: Bit-Exact Length Fill Bits: %u",
        a_bigbuf,
        oct & 0x07);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (oct_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

        proto_tree_add_text(tree, tvb, curr_offset, oct_len,
            "FCH Information Content");

        curr_offset += oct_len;

        NO_MORE_DATA_CHECK(len);
    }

    /*
     * DCCH
     */
    oct_len = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "DCCH Information: Bit-Exact Length Octet Count: %u",
        oct_len);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  DCCH Information: Bit-Exact Length Fill Bits: %u",
        a_bigbuf,
        oct & 0x07);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (oct_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

        proto_tree_add_text(tree, tvb, curr_offset, oct_len,
            "DCCH Information Content");

        curr_offset += oct_len;

        NO_MORE_DATA_CHECK(len);
    }

    /*
     * FOR_PDCH
     */
    oct_len = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "FOR_PDCH Information: Bit-Exact Length Octet Count: %u",
        oct_len);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  FOR_PDCH Information: Bit-Exact Length Fill Bits: %u",
        a_bigbuf,
        oct & 0x07);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (oct_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

        proto_tree_add_text(tree, tvb, curr_offset, oct_len,
            "FOR_PDCH Information Content");

        curr_offset += oct_len;

        NO_MORE_DATA_CHECK(len);
    }

    /*
     * REV_PDCH
     */
    oct_len = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "REV_PDCH Information: Bit-Exact Length Octet Count: %u",
        oct_len);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  REV_PDCH Information: Bit-Exact Length Fill Bits: %u",
        a_bigbuf,
        oct & 0x07);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (oct_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

        proto_tree_add_text(tree, tvb, curr_offset, oct_len,
            "REV_PDCH Information Content");

        curr_offset += oct_len;

        NO_MORE_DATA_CHECK(len);
    }

    oct = tvb_get_guint8(tvb, curr_offset);

    item =
        proto_tree_add_text(tree, tvb,
            curr_offset, 1,
            "VP Algorithms Supported%s",
            oct ? "" : ":  No voice privacy supported");

    if (oct)
    {
        subtree =
            proto_item_add_subtree(item, ett_vp_algs);

        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  %s",
            a_bigbuf,
            (oct & 0x80) ? "No extension" : "Extended");

        other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  A7:  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x20, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  A6:  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x10, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  A5:  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  A4:  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x04, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  A3:  Reserved",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  A2:  Advanced Encryption Standard (AES)",
            a_bigbuf);

        other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  A1:  Private long code",
            a_bigbuf);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.71
 */
static guint8
elem_ptype(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint32     value;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);

    switch (value)
    {
    case 0x880b: str = "PPP"; break;
    case 0x8881: str = "Unstructured Byte Stream"; break;
    default:
        str = "Unknown";
        break;
    }

    proto_tree_add_text(tree,
        tvb, curr_offset, 2,
        "(%u) %s",
        value,
        str);

    g_snprintf(add_string, string_len, " - (%s)", str);

    curr_offset += 2;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.72
 */
static guint8
elem_fwd_ms_info_recs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      oct_len;
    guint8      rec_type;
    guint8      num_recs;
    guint32     value;
    guint32     curr_offset;
    const gchar *str;
    gint        ett_elem_idx, idx, i;
    proto_tree  *subtree;
    proto_item  *item;

    curr_offset = offset;

    num_recs = 0;

    while ((len - (curr_offset - offset)) >= 2)
    {
        num_recs++;

        rec_type = tvb_get_guint8(tvb, curr_offset);

        str = match_strval_idx((guint32) rec_type, ansi_fwd_ms_info_rec_str, &idx);

        if (str == NULL)
        {
            str = "Reserved";
            ett_elem_idx = ett_ansi_ms_info_rec_reserved;
        }
        else
        {
            ett_elem_idx = ett_ansi_fwd_ms_info_rec[idx];
        }

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, 1,
                "Information Record Type [%u]: (%u) %s",
                num_recs,
                rec_type,
                str);

        subtree = proto_item_add_subtree(item, ett_elem_idx);

        curr_offset++;

        oct_len = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_uint(subtree, hf_ansi_a_length, tvb,
            curr_offset, 1, oct_len);

        curr_offset++;

        if (oct_len > 0)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

            switch (rec_type)
            {
            case ANSI_FWD_MS_INFO_REC_CLD_PN:
                oct = tvb_get_guint8(tvb, curr_offset);

                switch ((oct & 0xe0) >> 5)
                {
                case 0: str = "Unknown"; break;
                case 1: str = "International number"; break;
                case 2: str = "National number"; break;
                case 3: str = "Network-specific number"; break;
                case 4: str = "Subscriber number"; break;
                case 5: str = "Reserved"; break;
                case 6: str = "Abbreviated number"; break;
                default:
                    str = "Reserved for extension";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
                proto_tree_add_text(subtree, tvb, curr_offset, 1,
                    "%s :  Number Type: %s",
                    a_bigbuf,
                    str);

                switch ((oct & 0x1e) >> 1)
                {
                case 0x00: str = "Unknown"; break;
                case 0x01: str = "ISDN/Telephony Numbering"; break;
                case 0x03: str = "Data Numbering (ITU-T Rec. X.121)"; break;
                case 0x04: str = "Telex Numbering (ITU-T Rec. F.69)"; break;
                case 0x09: str = "Private Numbering"; break;
                case 0x0f: str = "Reserved for extension"; break;
                default:
                    str = "Reserved";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, oct, 0x1e, 8);
                proto_tree_add_text(subtree, tvb, curr_offset, 1,
                    "%s :  Number Plan: %s",
                    a_bigbuf,
                    str);

                if (oct_len > 1)
                {
                    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
                    proto_tree_add_text(subtree, tvb, curr_offset, 1,
                        "%s :  MSB of first digit",
                        a_bigbuf);

                    curr_offset++;

                    for (i=0; i < (oct_len - 1); i++)
                    {
                        a_bigbuf[i] = (oct & 0x01) << 7;

                        oct = tvb_get_guint8(tvb, curr_offset + i);

                        a_bigbuf[i] |= (oct & 0xfe) >> 1;
                    }
                    a_bigbuf[i] = '\0';

                    proto_tree_add_text(subtree, tvb, curr_offset, oct_len - 1,
                        "Digits: %s",
                        a_bigbuf);

                    curr_offset += (oct_len - 2);
                }

                other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
                proto_tree_add_text(subtree, tvb, curr_offset, 1,
                    "%s :  Reserved",
                    a_bigbuf);

                curr_offset++;
                break;

            case ANSI_FWD_MS_INFO_REC_CLG_PN:
                value = tvb_get_ntohs(tvb, curr_offset);

                oct = (value & 0xff00) >> 8;

                switch ((oct & 0xe0) >> 5)
                {
                case 0: str = "Unknown"; break;
                case 1: str = "International number"; break;
                case 2: str = "National number"; break;
                case 3: str = "Network-specific number"; break;
                case 4: str = "Subscriber number"; break;
                case 5: str = "Reserved"; break;
                case 6: str = "Abbreviated number"; break;
                default:
                    str = "Reserved for extension";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, value, 0xe000, 16);
                proto_tree_add_text(subtree, tvb, curr_offset, 2,
                    "%s :  Number Type: %s",
                    a_bigbuf,
                    str);

                switch ((oct & 0x1e) >> 1)
                {
                case 0x00: str = "Unknown"; break;
                case 0x01: str = "ISDN/Telephony Numbering"; break;
                case 0x03: str = "Data Numbering (ITU-T Rec. X.121)"; break;
                case 0x04: str = "Telex Numbering (ITU-T Rec. F.69)"; break;
                case 0x09: str = "Private Numbering"; break;
                case 0x0f: str = "Reserved for extension"; break;
                default:
                    str = "Reserved";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, value, 0x1e00, 16);
                proto_tree_add_text(subtree, tvb, curr_offset, 2,
                    "%s :  Number Plan: %s",
                    a_bigbuf,
                    str);

                switch ((value & 0x0180) >> 7)
                {
                case 0: str = "Presentation allowed"; break;
                case 1: str = "Presentation restricted"; break;
                case 2: str = "Number not available"; break;
                default:
                    str = "Reserved";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, value, 0x0180, 16);
                proto_tree_add_text(subtree, tvb, curr_offset, 2,
                    "%s :  Presentation Indicator (PI): %s",
                    a_bigbuf,
                    str);

                switch ((value & 0x0060) >> 5)
                {
                case 0: str = "User-provided, not screened"; break;
                case 1: str = "User-provided, verified and passed"; break;
                case 2: str = "User-provided, verified and failed"; break;
                default:
                    str = "Network-provided";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, value, 0x0060, 16);
                proto_tree_add_text(subtree, tvb, curr_offset, 2,
                    "%s :  Screening Indicator (SI): %s",
                    a_bigbuf,
                    str);

                if (oct_len > 2)
                {
                    oct = (value & 0x00ff);

                    other_decode_bitfield_value(a_bigbuf, value, 0x001f, 16);
                    proto_tree_add_text(subtree, tvb, curr_offset, 2,
                        "%s :  MSB of first digit",
                        a_bigbuf);

                    curr_offset += 2;

                    for (i=0; i < (oct_len - 2); i++)
                    {
                        a_bigbuf[i] = (oct & 0x1f) << 3;

                        oct = tvb_get_guint8(tvb, curr_offset + i);

                        a_bigbuf[i] |= (oct & 0xe0) >> 5;
                    }
                    a_bigbuf[i] = '\0';

                    proto_tree_add_text(subtree, tvb, curr_offset, oct_len - 2,
                        "Digits: %s",
                        a_bigbuf);

                    curr_offset += (oct_len - 3);

                    other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
                    proto_tree_add_text(subtree, tvb, curr_offset, 1,
                        "%s :  Reserved",
                        a_bigbuf);

                    curr_offset++;
                }
                else
                {
                    other_decode_bitfield_value(a_bigbuf, value, 0x001f, 16);
                    proto_tree_add_text(subtree, tvb, curr_offset, 2,
                        "%s :  Reserved",
                        a_bigbuf);

                    curr_offset += 2;
                }
                break;

            case ANSI_FWD_MS_INFO_REC_MW:
                oct = tvb_get_guint8(tvb, curr_offset);

                proto_tree_add_text(subtree, tvb, curr_offset, 1,
                    "Number of messages waiting: %u",
                    oct);

                curr_offset++;
                break;

            default:
                proto_tree_add_text(subtree,
                    tvb, curr_offset, oct_len,
                    "Record Content");

                curr_offset += oct_len;
                break;
            }
        }
    }

    g_snprintf(add_string, string_len, " - %u record%s",
        num_recs, plurality(num_recs, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.72
 */
static guint8
elem_rev_ms_info_recs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint8      oct_len;
    guint8      rec_type;
    guint8      num_recs;
    guint32     value;
    guint32     curr_offset, saved_offset;
    const gchar *str;
    gint        ett_elem_idx, idx, i;
    proto_tree  *subtree, *subtree2;
    proto_item  *item;
    guint8      *poctets;

    curr_offset = offset;

    num_recs = 0;

    while ((len - (curr_offset - offset)) >= 2)
    {
        num_recs++;

        rec_type = tvb_get_guint8(tvb, curr_offset);

        str = match_strval_idx((guint32) rec_type, ansi_rev_ms_info_rec_str, &idx);

        if (str == NULL)
        {
            str = "Reserved";
            ett_elem_idx = ett_ansi_ms_info_rec_reserved;
        }
        else
        {
            ett_elem_idx = ett_ansi_rev_ms_info_rec[idx];
        }

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, 1,
                "Information Record Type [%u]: (%u) %s",
                num_recs,
                rec_type,
                str);

        subtree = proto_item_add_subtree(item, ett_elem_idx);

        curr_offset++;

        oct_len = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_uint(subtree, hf_ansi_a_length, tvb,
            curr_offset, 1, oct_len);

        curr_offset++;

        if (oct_len > 0)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

            switch (rec_type)
            {
            case ANSI_REV_MS_INFO_REC_KEYPAD_FAC:
                poctets = tvb_get_ephemeral_string(tvb, curr_offset, oct_len);

                proto_tree_add_string_format(subtree, hf_ansi_a_cld_party_ascii_num,
                    tvb, curr_offset, oct_len,
                    (gchar *) poctets,
                    "Digits: %s",
                    (gchar *) format_text(poctets, oct_len));

                curr_offset += oct_len;
                break;

            case ANSI_REV_MS_INFO_REC_CLD_PN:
                oct = tvb_get_guint8(tvb, curr_offset);

                switch ((oct & 0xe0) >> 5)
                {
                case 0: str = "Unknown"; break;
                case 1: str = "International number"; break;
                case 2: str = "National number"; break;
                case 3: str = "Network-specific number"; break;
                case 4: str = "Subscriber number"; break;
                case 5: str = "Reserved"; break;
                case 6: str = "Abbreviated number"; break;
                default:
                    str = "Reserved for extension";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
                proto_tree_add_text(subtree, tvb, curr_offset, 1,
                    "%s :  Number Type: %s",
                    a_bigbuf,
                    str);

                switch ((oct & 0x1e) >> 1)
                {
                case 0x00: str = "Unknown"; break;
                case 0x01: str = "ISDN/Telephony Numbering"; break;
                case 0x03: str = "Data Numbering (ITU-T Rec. X.121)"; break;
                case 0x04: str = "Telex Numbering (ITU-T Rec. F.69)"; break;
                case 0x09: str = "Private Numbering"; break;
                case 0x0f: str = "Reserved for extension"; break;
                default:
                    str = "Reserved";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, oct, 0x1e, 8);
                proto_tree_add_text(subtree, tvb, curr_offset, 1,
                    "%s :  Number Plan: %s",
                    a_bigbuf,
                    str);

                if (oct_len > 1)
                {
                    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
                    proto_tree_add_text(subtree, tvb, curr_offset, 1,
                        "%s :  MSB of first digit",
                        a_bigbuf);

                    curr_offset++;

                    for (i=0; i < (oct_len - 1); i++)
                    {
                        a_bigbuf[i] = (oct & 0x01) << 7;

                        oct = tvb_get_guint8(tvb, curr_offset + i);

                        a_bigbuf[i] |= (oct & 0xfe) >> 1;
                    }
                    a_bigbuf[i] = '\0';

                    proto_tree_add_text(subtree, tvb, curr_offset, oct_len - 1,
                        "Digits: %s",
                        a_bigbuf);

                    curr_offset += (oct_len - 2);
                }

                other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
                proto_tree_add_text(subtree, tvb, curr_offset, 1,
                    "%s :  Reserved",
                    a_bigbuf);

                curr_offset++;
                break;

            case ANSI_REV_MS_INFO_REC_CLG_PN:
                value = tvb_get_ntohs(tvb, curr_offset);

                oct = (value & 0xff00) >> 8;

                switch ((oct & 0xe0) >> 5)
                {
                case 0: str = "Unknown"; break;
                case 1: str = "International number"; break;
                case 2: str = "National number"; break;
                case 3: str = "Network-specific number"; break;
                case 4: str = "Subscriber number"; break;
                case 5: str = "Reserved"; break;
                case 6: str = "Abbreviated number"; break;
                default:
                    str = "Reserved for extension";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, value, 0xe000, 16);
                proto_tree_add_text(subtree, tvb, curr_offset, 2,
                    "%s :  Number Type: %s",
                    a_bigbuf,
                    str);

                switch ((oct & 0x1e) >> 1)
                {
                case 0x00: str = "Unknown"; break;
                case 0x01: str = "ISDN/Telephony Numbering"; break;
                case 0x03: str = "Data Numbering (ITU-T Rec. X.121)"; break;
                case 0x04: str = "Telex Numbering (ITU-T Rec. F.69)"; break;
                case 0x09: str = "Private Numbering"; break;
                case 0x0f: str = "Reserved for extension"; break;
                default:
                    str = "Reserved";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, value, 0x1e00, 16);
                proto_tree_add_text(subtree, tvb, curr_offset, 2,
                    "%s :  Number Plan: %s",
                    a_bigbuf,
                    str);

                switch ((value & 0x0180) >> 7)
                {
                case 0: str = "Presentation allowed"; break;
                case 1: str = "Presentation restricted"; break;
                case 2: str = "Number not available"; break;
                default:
                    str = "Reserved";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, value, 0x0180, 16);
                proto_tree_add_text(subtree, tvb, curr_offset, 2,
                    "%s :  Presentation Indicator (PI): %s",
                    a_bigbuf,
                    str);

                switch ((value & 0x0060) >> 5)
                {
                case 0: str = "User-provided, not screened"; break;
                case 1: str = "User-provided, verified and passed"; break;
                case 2: str = "User-provided, verified and failed"; break;
                default:
                    str = "Network-provided";
                    break;
                }

                other_decode_bitfield_value(a_bigbuf, value, 0x0060, 16);
                proto_tree_add_text(subtree, tvb, curr_offset, 2,
                    "%s :  Screening Indicator (SI): %s",
                    a_bigbuf,
                    str);

                if (oct_len > 2)
                {
                    oct = (value & 0x00ff);

                    other_decode_bitfield_value(a_bigbuf, value, 0x001f, 16);
                    proto_tree_add_text(subtree, tvb, curr_offset, 2,
                        "%s :  MSB of first digit",
                        a_bigbuf);

                    curr_offset += 2;

                    for (i=0; i < (oct_len - 2); i++)
                    {
                        a_bigbuf[i] = (oct & 0x1f) << 3;

                        oct = tvb_get_guint8(tvb, curr_offset + i);

                        a_bigbuf[i] |= (oct & 0xe0) >> 5;
                    }
                    a_bigbuf[i] = '\0';

                    proto_tree_add_text(subtree, tvb, curr_offset, oct_len - 2,
                        "Digits: %s",
                        a_bigbuf);

                    curr_offset += (oct_len - 3);

                    other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
                    proto_tree_add_text(subtree, tvb, curr_offset, 1,
                        "%s :  Reserved",
                        a_bigbuf);

                    curr_offset++;
                }
                else
                {
                    other_decode_bitfield_value(a_bigbuf, value, 0x001f, 16);
                    proto_tree_add_text(subtree, tvb, curr_offset, 2,
                        "%s :  Reserved",
                        a_bigbuf);

                    curr_offset += 2;
                }
                break;

            case ANSI_REV_MS_INFO_REC_SO_INFO:
                i = 0;
                saved_offset = curr_offset;

                while ((oct_len - (curr_offset - saved_offset)) > 2)
                {
                    item =
                        proto_tree_add_text(subtree,
                            tvb, curr_offset, 3,
                            "Service Option [%u]",
                            i + 1);

                    subtree2 = proto_item_add_subtree(item, ett_so_list);

                    oct = tvb_get_guint8(tvb, curr_offset);

                    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
                    proto_tree_add_text(subtree2, tvb, curr_offset, 1,
                        "%s :  Reserved",
                        a_bigbuf);

                    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
                    proto_tree_add_text(subtree2, tvb, curr_offset, 1,
                        "%s :  Forward Support: %s",
                        a_bigbuf,
                        (oct & 0x02) ? "TRUE" : "FALSE");

                    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
                    proto_tree_add_text(subtree2, tvb, curr_offset, 1,
                        "%s :  Reverse Support: %s",
                        a_bigbuf,
                        (oct & 0x01) ? "TRUE" : "FALSE");

                    curr_offset++;

                    value = tvb_get_ntohs(tvb, curr_offset);

                    str = ansi_a_so_int_to_str(value);
                    proto_tree_add_text(subtree2, tvb, curr_offset, 2,
                        "Service Option:  %s (%u)",
                        str,
                        value);

                    proto_item_append_text(item, " - (%u) %s", value, str);

                    i++;
                    curr_offset += 2;
                }
                break;

            default:
                proto_tree_add_text(subtree,
                    tvb, curr_offset, oct_len,
                    "Record Content");

                curr_offset += oct_len;
                break;
            }
        }
    }

    g_snprintf(add_string, string_len, " - %u record%s",
        num_recs, plurality(num_recs, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.73
 */
static guint8
elem_ext_ho_dir_params(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Search Window A Size (Srch_Win_A): %u",
        a_bigbuf,
        (oct & 0xf0) >> 4);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Search Window N Size (Srch_Win_N): %u",
        a_bigbuf,
        oct & 0x0f);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Search Window R Size (Srch_Win_R): %u",
        a_bigbuf,
        (oct & 0xf0) >> 4);

    value = tvb_get_guint8(tvb, curr_offset + 1);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Add Pilot Threshold (T_Add) (MSB): %u",
        a_bigbuf,
        (oct & 0x0f) << 2 | (value & 0xc0) >> 6);

    curr_offset++;

    oct = value;

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Add Pilot Threshold (T_Add) (LSB)",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Drop Pilot Threshold (T_Drop): %u",
        a_bigbuf,
        oct & 0x3f);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Compare Threshold (T_Comp): %u",
        a_bigbuf,
        (oct & 0xf0) >> 4);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Drop Timer Value (T_TDrop): %u",
        a_bigbuf,
        oct & 0x0f);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Neighbor Max Age (Nghbor_Max_AGE): %u",
        a_bigbuf,
        (oct & 0xf0) >> 4);

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);
        break;

    case A_VARIANT_IOS501:
        other_decode_bitfield_value(a_bigbuf, oct, 0x0c, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Reserved",
            a_bigbuf);

        switch (oct & 0x03)
        {
        case 0: str = "Only Search Window A Size is valid"; break;
        case 1: str = "Subset is valid"; break;
        case 2: str = "All fields valid"; break;
        default:
            str = "Reserved";
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
        proto_tree_add_text(tree, tvb, curr_offset, 1,
            "%s :  Target BS Values Included: %s",
            a_bigbuf,
            str);
        break;
    }

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  SOFT_SLOPE: %u",
        a_bigbuf,
        oct & 0x3f);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  ADD_INTERCEPT: %u",
        a_bigbuf,
        oct & 0x3f);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  DROP_INTERCEPT: %u",
        a_bigbuf,
        oct & 0x3f);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "Target BS P_REV: %u",
        oct);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.74
 * UNUSED in SPEC and no IEI!
 */

/*
 * IOS 6.2.2.75
 * UNUSED in SPEC and no IEI!
 */

/*
 * IOS 6.2.2.76
 * UNUSED
 */

/*
 * IOS 6.2.2.77
 * UNUSED in SPEC and no IEI!
 */

/*
 * IOS 6.2.2.78
 * UNUSED in SPEC and no IEI!
 */

/*
 * IOS 6.2.2.79
 */
static guint8
elem_cdma_sowd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;
    const gchar *str = NULL;

    curr_offset = offset;

    curr_offset += elem_cell_id(tvb, tree, offset, len, add_string, string_len);
    add_string[0] = '\0';

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 2,
        "CDMA Serving One Way Delay: %u",
        value);

    curr_offset += 2;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    switch (oct & 0x03)
    {
    case 0: str = "100 nsec"; break;
    case 1: str = "50 nsec"; break;
    case 2: str = "1/16 CDMA PN Chip"; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Resolution: %s",
        a_bigbuf,
        str);

    curr_offset++;

    if ((len - (curr_offset - offset)) > 1)
    {
        proto_tree_add_text(tree,
            tvb, curr_offset, 2,
            "Timestamp");

        curr_offset += 2;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.80
 * UNUSED
 */

/*
 * IOS 6.2.2.81
 * UNUSED
 */

/*
 * IOS 6.2.2.82
 */
static guint8
elem_re_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Include Priority: MSC %s include priority in Assignment Request",
        a_bigbuf,
        (oct & 0x40) ? "should" : "does not need to");

    switch ((oct & 0x30) >> 4)
    {
    case 0: str = "Not reported"; break;
    case 1: str = "radio environment is acceptable"; break;
    case 2: str = "radio environment is marginally acceptable"; break;
    default:
        str = "radio environment is poor";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x30, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Forward: %s",
        a_bigbuf,
        str);

    switch ((oct & 0x0c) >> 2)
    {
    case 0: str = "Not reported"; break;
    case 1: str = "radio environment is acceptable"; break;
    case 2: str = "radio environment is marginally acceptable"; break;
    default:
        str = "radio environment is poor";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0c, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reverse: %s",
        a_bigbuf,
        str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Alloc: resources are %sallocated",
        a_bigbuf,
        (oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Avail: resources are %savailable",
        a_bigbuf,
        (oct & 0x01) ? "" : "not ");

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.83
 * UNUSED in SPEC and no IEI!
 */

/*
 * IOS 6.2.2.84
 * UNUSED
 */

/*
 * IOS 6.2.2.85
 * UNUSED
 */

/*
 * IOS 6.2.2.86
 * UNUSED
 */

/*
 * IOS 6.2.2.87
 * UNUSED
 */

/*
 * IOS 6.2.2.88
 * UNUSED
 */

/*
 * IOS 6.2.2.89
 * A3/A7
 */

/*
 * IOS 6.2.2.90
 * UNUSED in SPEC and no IEI!
 */

/*
 * IOS 6.2.2.91
 * A3/A7
 */

/*
 * IOS 6.2.2.92
 * UNUSED
 */

/*
 * IOS 6.2.2.93
 * UNUSED
 */

/*
 * IOS 6.2.2.94
 * UNUSED
 */

/*
 * IOS 6.2.2.95
 * UNUSED
 */

/*
 * IOS 6.2.2.96
 * A3/A7
 */

/*
 * IOS 6.2.2.97
 * A3/A7
 */

/*
 * IOS 6.2.2.98
 * A3/A7
 */

/*
 * IOS 6.2.2.99
 * A3/A7
 */

/*
 * IOS 6.2.2.100
 * UNUSED
 */

/*
 * IOS 6.2.2.101
 * UNUSED
 */

/*
 * IOS 6.2.2.102
 * UNUSED
 */

/*
 * IOS 6.2.2.103
 * UNUSED
 */

/*
 * IOS 6.2.2.104
 * UNUSED
 */

/*
 * IOS 6.2.2.105
 */
static guint8
elem_cld_party_ascii_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    guint8      *poctets;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  Extension",
        a_bigbuf);

    switch ((oct & 0x70) >> 4)
    {
    case 0: str = "Unknown"; break;
    case 1: str = "International number"; break;
    case 2: str = "National number"; break;
    case 3: str = "Network specific number"; break;
    case 4: str = "Dedicated PAD access, short code"; break;
    case 7: str = "Reserved for extension"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Type of Number: %s",
        a_bigbuf,
        str);

    switch (oct & 0x0f)
    {
    case 0x00: str = "Unknown"; break;
    case 0x01: str = "ISDN/telephony number plan (ITU recommendation E.164/E.163)"; break;
    case 0x03: str = "Data number plan (ITU recommendation X.121)"; break;
    case 0x04: str = "Telex numbering plan (ITU recommendation F.69)"; break;
    case 0x07: str = "Reserved for extension"; break;
    case 0x08: str = "National numbering plan"; break;
    case 0x09: str = "Private numbering plan"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Numbering Plan Identification: %s",
        a_bigbuf,
        str);

    curr_offset++;

    poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

    proto_tree_add_string_format(tree, hf_ansi_a_cld_party_ascii_num,
        tvb, curr_offset, len - (curr_offset - offset),
        (gchar *) poctets,
        "Digits: %s",
        (gchar *) format_text(poctets, len - (curr_offset - offset)));

    curr_offset += len - (curr_offset - offset);

    g_snprintf(add_string, string_len, " - (%s)", poctets);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.106
 */
static guint8
elem_band_class(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    gint        temp_int;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xe0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    temp_int = oct & 0x1f;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_BAND_CLASS_STR))
    {
        str = "Reserved";
    }
    else
    {
        str = band_class_str[temp_int];
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x1f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Band Class: %s",
        a_bigbuf,
        str);

    curr_offset++;

    g_snprintf(add_string, string_len, " - (%s)", str);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.107
 * UNUSED
 */

/*
 * IOS 6.2.2.108
 * A3/A7
 */

/*
 * IOS 6.2.2.109
 * A3/A7
 */

/*
 * IOS 6.2.2.110
 */
static guint8
elem_is2000_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len, "IS-95/IS-2000 Cause Information");

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.111
 * UNUSED
 */

/*
 * IOS 6.2.2.112
 * UNUSED
 */

/*
 * IOS 6.2.2.113
 * UNUSED
 */

/*
 * IOS 6.2.2.114
 */
static guint8
elem_auth_event(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    if (len == 1)
    {
        oct = tvb_get_guint8(tvb, curr_offset);

        switch (oct)
        {
        case 0x01: str = "Event: Authentication parameters were NOT received from mobile"; break;
        case 0x02: str = "Event: RANDC mis-match"; break;
        case 0x03: str = "Event: Recently requested"; break;
        case 0x04: str = "Event: Direct channel assignment"; break;
        default:
            str = "Event";
            break;
        }

        proto_tree_add_text(tree, tvb, curr_offset, len,
            "%s", str);
    }
    else
    {
        proto_tree_add_text(tree, tvb, curr_offset, len, "Event");
    }

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.115
 * UNUSED
 */

/*
 * IOS 6.2.2.116
 * UNUSED
 */

/*
 * IOS 6.2.2.117
 * UNUSED
 */

/*
 * IOS 6.2.2.118
 * UNUSED
 */

/*
 * IOS 6.2.2.119
 * A3/A7
 */

/*
 * IOS 6.2.2.120
 * A3/A7
 */

/*
 * IOS 6.2.2.121
 * A3/A7
 */

/*
 * IOS 6.2.2.122
 * UNUSED
 */

/*
 * IOS 6.2.2.123
 * UNUSED
 */

/*
 * IOS 6.2.2.124
 * UNUSED
 */

/*
 * IOS 6.2.2.125
 * A3/A7
 */

/*
 * IOS 6.2.2.126
 * UNUSED
 */

/*
 * IOS 6.2.2.127
 * UNUSED
 */

/*
 * IOS 6.2.2.128
 * A3/A7
 */

/*
 * IOS 6.2.2.129
 * UNUSED
 */

/*
 * IOS 6.2.2.130
 * UNUSED
 */

/*
 * IOS 6.2.2.131
 * UNUSED
 */

/*
 * IOS 6.2.2.132
 * A3/A7
 */

/*
 * IOS 6.2.2.133
 * UNUSED
 */

/*
 * IOS 6.2.2.134
 * A3/A7
 */

/*
 * IOS 6.2.2.135
 * UNUSED
 */

/*
 * IOS 6.2.2.136
 * UNUSED
 */

/*
 * IOS 6.2.2.137
 * Generic decode is good enough
 */

/*
 * IOS 6.2.2.138
 */
static guint8
elem_psmm_count(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  PSMM Count: %u",
        a_bigbuf,
        oct & 0x0f);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.139
 */
static guint8
elem_geo_loc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len, "Calling Geodetic Location");

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.140
 * UNUSED
 */

/*
 * IOS 6.2.2.141
 * A3/A7
 */

/*
 * IOS 6.2.2.142
 * A3/A7
 */

/*
 * IOS 6.2.2.143
 * A3/A7
 */

/*
 * IOS 6.2.2.144
 * A3/A7
 */

/*
 * IOS 6.2.2.145
 * A3/A7
 */

/*
 * IOS 6.2.2.146
 * A3/A7
 */

/*
 * IOS 6.2.2.147
 * A3/A7
 */

/*
 * IOS 6.2.2.148
 */
static guint8
elem_cct_group(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x02, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  All Circuits",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Inclusive",
        a_bigbuf);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "Count: %u circuit%s",
        oct, plurality(oct, "", "s"));

    g_snprintf(add_string, string_len, " - %u circuit%s",
        oct, plurality(oct, "", "s"));

    curr_offset++;

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

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_text(tree,
        tvb, curr_offset, len - (curr_offset - offset),
        "Circuit Bitmap");

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.149
 */
static guint8
elem_paca_ts(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_text(tree, tvb, curr_offset, len, "PACA Queuing Time");

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.150
 */
static guint8
elem_paca_order(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    switch (oct & 0x07)
    {
    case 0: str = "Reserved"; break;
    case 1: str = "Update Queue Position and notify MS"; break;
    case 2: str = "Remove MS from the queue and release MS"; break;
    case 3: str = "Remove MS from the queue"; break;
    case 4: str = "MS Requested PACA Cancel"; break;
    case 5: str = "BS Requested PACA Cancel"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  PACA Action Required: %s",
        a_bigbuf,
        str);

    curr_offset++;

    g_snprintf(add_string, string_len, " - (%s)", str);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.151
 */
static guint8
elem_paca_reoi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfe, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  PACA Reorigination Indicator (PRI)",
        a_bigbuf);

    curr_offset++;

    g_snprintf(add_string, string_len, " - (%sReorigination)", (oct & 0x01) ? "" : "Not ");

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.89
 */
static guint8
elem_a2p_bearer_session(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x38, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Max Frames: %u",
        a_bigbuf,
        (oct & 0x38) >> 3);

    other_decode_bitfield_value(a_bigbuf, oct, 0x06, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Session IP Address Type: Internet Protocol IPv%s",
        a_bigbuf,
        ((oct & 0x06) >> 1) ? "6" : "4");

    other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Session Address Flag",
        a_bigbuf);

    curr_offset++;

    if (oct & 0x01)
    {
        /* session address included */

        if ((oct & 0x06) >> 1)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), 18);

            proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_ipv6_addr,
                tvb, curr_offset, 16, FALSE);

            rtp_src_addr.type = AT_IPv6;
            rtp_src_addr.len = 16;
            rtp_src_addr.data = (guint8 *) &rtp_ipv6_addr;

            tvb_get_ipv6(tvb, curr_offset, &rtp_ipv6_addr);

            curr_offset += 16;
        }
        else
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), 6);

            proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_ipv4_addr,
                tvb, curr_offset, 4, FALSE);

            rtp_src_addr.type = AT_IPv4;
            rtp_src_addr.len = 4;
            rtp_src_addr.data = (guint8 *) &rtp_ipv4_addr;

            rtp_ipv4_addr = tvb_get_ipv4(tvb, curr_offset);

            curr_offset += 4;
        }

        proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_udp_port,
            tvb, curr_offset, 2, FALSE);

        rtp_port = tvb_get_ntohs(tvb, curr_offset);

        curr_offset += 2;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

static void
free_encoding_name_str(void *ptr)
{
    encoding_name_and_rate_t    *encoding_name_and_rate = (encoding_name_and_rate_t *) ptr;

    if (encoding_name_and_rate->encoding_name)
    {
        g_free(encoding_name_and_rate->encoding_name);
    }
}

/*
 * IOS 5 4.2.90
 */
static guint8
elem_a2p_bearer_format(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8                              oct;
    proto_item                          *item;
    proto_tree                          *subtree;
    guint8                              num_bearers;
    guint32                             curr_offset, orig_offset;
    guint8                              ip_addr_type;
    gboolean                            ext;
    guint8                              ext_len;
    const gchar                         *str;
    const gchar                         *mime_type;
    int                                 sample_rate;
    gboolean                            format_assigned;
    gboolean                            in_band_format_assigned;
    gboolean                            first_assigned_found;
    gboolean                            rtp_dyn_payload_used;
    guint8                              rtp_payload_type;
    GHashTable                          *rtp_dyn_payload;
    gint                                *key;
    encoding_name_and_rate_t            *encoding_name_and_rate;

    rtp_dyn_payload = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, free_encoding_name_str);
    rtp_dyn_payload_used = FALSE;

    first_assigned_found = FALSE;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Number of Bearer Formats: %u",
        a_bigbuf,
        (oct & 0xfc) >> 2);

    other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Session IP Address Type: Internet Protocol IPv%s",
        a_bigbuf,
        (oct & 0x03) ? "6" : "4");

    ip_addr_type = (oct & 0x03);

    curr_offset++;

    num_bearers = 0;

    while ((len - (curr_offset - offset)) > 0)
    {
        orig_offset = curr_offset;

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, -1,
                "Bearer Format [%u]",
                num_bearers + 1);

        subtree = proto_item_add_subtree(item, ett_bearer_list);

        oct = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "Bearer Format Length: %u",
            oct);

        curr_offset++;

        NO_MORE_DATA_CHECK(len);

        oct = tvb_get_guint8(tvb, curr_offset);

        other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  Extension",
            a_bigbuf);

        ext = (oct & 0x80) ? TRUE : FALSE;

        format_assigned = FALSE;
        in_band_format_assigned = FALSE;

        switch ((oct & 0x70) >> 4)
        {
        case 0: str = "Unknown"; break;
        case 1:
            str = "In-band signaling";
            in_band_format_assigned = TRUE;
            break;
        case 2:
            str = "Assigned";
            format_assigned = TRUE;
            break;
        case 3: str = "Unassigned"; break;
        case 4: str = "Transcoded"; break;
        default:
            str = "Reserved";
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  Bearer Format Tag Type: %s",
            a_bigbuf,
            str);

        /*
         * assuming default sampling rate of 8000Hz
         */
        sample_rate = 8000;

        switch (oct & 0x0f)
        {
        case 0: mime_type = str = "PCMU"; break;
        case 1: mime_type = str = "PCMA"; break;
        case 2:
            str = "13K Vocoder";
            mime_type = "QCELP";
            break;
        case 3: mime_type = str = "EVRC"; break;
        case 4: mime_type = str = "EVRC0"; break;
        case 5: mime_type = str = "SMV"; break;
        case 6: mime_type = str = "SMV0"; break;
        case 7: mime_type = str = "telephone-event"; break;
        case 8: mime_type = str = "EVRCB"; break;
        case 9: mime_type = str = "EVRCB0"; break;
        case 10: mime_type = str = "EVRCWB"; sample_rate = 16000; break;
        case 11: mime_type = str = "EVRCWB0"; sample_rate = 16000; break;
        case 12: mime_type = str = "EVRCNW"; sample_rate = 16000; break;
        case 13: mime_type = str = "EVRCNW0"; sample_rate = 16000; break;
        default:
            mime_type = str = "Reserved";
            break;
        }

        other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  Bearer Format ID: %s",
            a_bigbuf,
            str);

        proto_item_append_text(item, " - (%s)", str);

        curr_offset++;

        NO_MORE_DATA_CHECK(len);

        oct = tvb_get_guint8(tvb, curr_offset);

        rtp_payload_type = (oct & 0xfe) >> 1;

        other_decode_bitfield_value(a_bigbuf, oct, 0xfe, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  RTP Payload Type: %u",
            a_bigbuf,
            rtp_payload_type);

        other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
        proto_tree_add_text(subtree, tvb, curr_offset, 1,
            "%s :  Bearer Address Flag",
            a_bigbuf);

        curr_offset++;

        if (oct & 0x01)
        {
            /* bearer address included */

            if (ip_addr_type != 0)
            {
                SHORT_DATA_CHECK(len - (curr_offset - offset), 18);

                proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_ipv6_addr,
                    tvb, curr_offset, 16, FALSE);

                if (format_assigned)
                {
                    rtp_src_addr.type = AT_IPv6;
                    rtp_src_addr.len = 16;
                    rtp_src_addr.data = (guint8 *) &rtp_ipv6_addr;

                    tvb_get_ipv6(tvb, curr_offset, &rtp_ipv6_addr);
                }

                curr_offset += 16;
            }
            else
            {
                SHORT_DATA_CHECK(len - (curr_offset - offset), 6);

                proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_ipv4_addr,
                    tvb, curr_offset, 4, FALSE);

                if (format_assigned)
                {
                    rtp_src_addr.type = AT_IPv4;
                    rtp_src_addr.len = 4;
                    rtp_src_addr.data = (guint8 *) &rtp_ipv4_addr;

                    rtp_ipv4_addr = tvb_get_ipv4(tvb, curr_offset);
                }

                curr_offset += 4;
            }

            proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_udp_port,
                tvb, curr_offset, 2, FALSE);

            if (format_assigned)
            {
                rtp_port = tvb_get_ntohs(tvb, curr_offset);
            }

            curr_offset += 2;
        }

        if (ext)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), 1);

            oct = tvb_get_guint8(tvb, curr_offset);

            ext_len = (oct & 0xf0) >> 4;

            other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
            proto_tree_add_text(subtree, tvb, curr_offset, 1,
                "%s :  Extension Length: %u",
                a_bigbuf,
                ext_len);

            other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
            proto_tree_add_text(subtree, tvb, curr_offset, 1,
                "%s :  Extension ID: %u",
                a_bigbuf,
                (oct & 0x0f));

            curr_offset++;

            if (ext_len > 0)
            {
                SHORT_DATA_CHECK(len - (curr_offset - offset), ext_len);

                proto_tree_add_text(subtree, tvb, curr_offset, ext_len,
                    "Extension Parameter value");

                curr_offset += ext_len;
            }
        }

        proto_item_set_len(item, curr_offset - orig_offset);

        if (rtp_handle &&
            format_assigned &&
            (first_assigned_found == FALSE))
        {
            key = (gint *) g_malloc(sizeof(gint));
            *key = rtp_payload_type;

            encoding_name_and_rate = g_malloc(sizeof(encoding_name_and_rate_t));
            encoding_name_and_rate->encoding_name = g_strdup(mime_type);
            encoding_name_and_rate->sample_rate = sample_rate;

            g_hash_table_insert(rtp_dyn_payload, key, encoding_name_and_rate);
            rtp_dyn_payload_used = TRUE;

            first_assigned_found = TRUE;
            rtp_add_address(g_pinfo, &rtp_src_addr, rtp_port, 0, "IOS5",
                g_pinfo->fd->num, FALSE, rtp_dyn_payload);
        }

        if (in_band_format_assigned)
        {
            key = (gint *) g_malloc(sizeof(gint));
            *key = rtp_payload_type;

            encoding_name_and_rate = g_malloc(sizeof(encoding_name_and_rate_t));
            encoding_name_and_rate->encoding_name = g_strdup("telephone-event");
            encoding_name_and_rate->sample_rate = sample_rate;

            g_hash_table_insert(rtp_dyn_payload, key, encoding_name_and_rate);
            rtp_dyn_payload_used = TRUE;
        }

        num_bearers++;
    }

    if (rtp_dyn_payload_used == FALSE)
    {
        rtp_free_hash_dyn_payload(rtp_dyn_payload);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.88
 */
static guint8
elem_ms_des_freq(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8      oct;
    guint32     value;
    gint        temp_int;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    temp_int = (oct & 0xf8) >> 3;
    if ((temp_int < 0) || (temp_int >= (gint) NUM_BAND_CLASS_STR))
    {
        str = "Reserved";
    }
    else
    {
        str = band_class_str[temp_int];
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Band Class: %s",
        a_bigbuf,
        str);

    value = tvb_get_guint8(tvb, curr_offset + 1) | ((oct & 0x07) << 8);

    other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  CDMA Channel (MSB): %u",
        a_bigbuf,
        value);

    curr_offset++;

    other_decode_bitfield_value(a_bigbuf, value & 0x00ff, 0xff, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  CDMA Channel (LSB)",
        a_bigbuf);

    g_snprintf(add_string, string_len, " - (CDMA Channel: %u)", value);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.87
 */
static guint8
elem_plcm_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    /*
     * from C.S0005-D v1.0 L3 Table 3.7.2.3.2.21-5
     */
    switch ((oct & 0xf0) >> 4)
    {
    case 0x00: str = "PLCM derived from ESN or MEID"; break;
    case 0x01: str = "PLCM specified by the base station"; break;
    case 0x02: str = "PLCM derived from IMSI_O_S when IMSI_O is derived from IMSI_M"; break;
    case 0x03: str = "PLCM derived from IMSI_O_S when IMSI_O is derived from IMSI_T"; break;
    default:
        str = "Reserved";
        break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  PLCM_TYPE: %s",
        a_bigbuf,
        str);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0c, 8);
    proto_tree_add_text(tree,
        tvb, curr_offset, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x03, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s :  PLCM_42 (MSB)",
        a_bigbuf);

    curr_offset++;

    proto_tree_add_text(tree, tvb, curr_offset, 5, "PLCM_42");

    curr_offset += 5;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.152
 * A3/A7
 */

/*
 * IOS 6.2.2.153
 * A3/A7
 */

/*
 * ORDER MUST BE MAINTAINED
 *
 * The value of this enum is used as an index into
 * elem_1_fcn[]
 *
 */
typedef enum
{
    ANSI_A_E_ACC_NET_ID,            /* Access Network Identifiers */
    ANSI_A_E_ADDS_USER_PART,        /* ADDS User Part */
    ANSI_A_E_AMPS_HHO_PARAM,        /* AMPS Hard Handoff Parameters */
    ANSI_A_E_ANCH_PDSN_ADDR,        /* Anchor PDSN Address */
    ANSI_A_E_ANCH_PP_ADDR,          /* Anchor P-P Address */
    ANSI_A_E_AUTH_CHLG_PARAM,       /* Authentication Challenge Parameter */
    ANSI_A_E_AUTH_CNF_PARAM,        /* Authentication Confirmation Parameter (RANDC) */
    ANSI_A_E_AUTH_DATA,             /* Authentication Data */
    ANSI_A_E_AUTH_EVENT,            /* Authentication Event */
    ANSI_A_E_AUTH_PARAM_COUNT,      /* Authentication Parameter COUNT */
    ANSI_A_E_AUTH_RESP_PARAM,       /* Authentication Response Parameter */
    ANSI_A_E_BAND_CLASS,            /* Band Class */
    ANSI_A_E_CLD_PARTY_ASCII_NUM,   /* Called Party ASCII Number */
    ANSI_A_E_CLD_PARTY_BCD_NUM,     /* Called Party BCD Number */
    ANSI_A_E_CLG_PARTY_ASCII_NUM,   /* Calling Party ASCII Number */
    ANSI_A_E_CAUSE,                 /* Cause */
    ANSI_A_E_CAUSE_L3,              /* Cause Layer 3 */
    ANSI_A_E_CDMA_SOWD,             /* CDMA Serving One Way Delay */
    ANSI_A_E_CELL_ID,               /* Cell Identifier */
    ANSI_A_E_CELL_ID_LIST,          /* Cell Identifier List */
    ANSI_A_E_CHAN_NUM,              /* Channel Number */
    ANSI_A_E_CHAN_TYPE,             /* Channel Type */
    ANSI_A_E_CCT_GROUP,             /* Circuit Group */
    ANSI_A_E_CIC,                   /* Circuit Identity Code */
    ANSI_A_E_CIC_EXT,               /* Circuit Identity Code Extension */
    ANSI_A_E_CM_INFO_TYPE_2,        /* Classmark Information Type 2 */
    ANSI_A_E_DOWNLINK_RE,           /* Downlink Radio Environment */
    ANSI_A_E_DOWNLINK_RE_LIST,      /* Downlink Radio Environment List */
    ANSI_A_E_ENC_INFO,              /* Encryption Information */
    ANSI_A_E_EXT_HO_DIR_PARAMS,     /* Extended Handoff Direction Parameters */
    ANSI_A_E_GEO_LOC,               /* Geographic Location */
    ANSI_A_E_SSCI,                  /* Special Service Call Indicator */
    ANSI_A_E_HO_POW_LEV,            /* Handoff Power Level */
    ANSI_A_E_HHO_PARAMS,            /* Hard Handoff Parameters */
    ANSI_A_E_IE_REQD,               /* Information Element Requested */
    ANSI_A_E_IS2000_CHAN_ID,        /* IS-2000 Channel Identity */
    ANSI_A_E_IS2000_CHAN_ID_3X,     /* IS-2000 Channel Identity 3X */
    ANSI_A_E_IS2000_MOB_CAP,        /* IS-2000 Mobile Capabilities */
    ANSI_A_E_IS2000_NN_SCR,         /* IS-2000 Non-Negotiable Service Configuration Record */
    ANSI_A_E_IS2000_SCR,            /* IS-2000 Service Configuration Record */
    ANSI_A_E_IS2000_CAUSE,          /* IS-95/IS-2000 Cause Value */
    ANSI_A_E_IS2000_RED_RECORD,     /* IS-2000 Redirection Record */
    ANSI_A_E_IS95_CHAN_ID,          /* IS-95 Channel Identity */
    ANSI_A_E_IS95_MS_MEAS_CHAN_ID,  /* IS-95 MS Measured Channel Identity */
    ANSI_A_E_L3_INFO,               /* Layer 3 Information */
    ANSI_A_E_LAI,                   /* Location Area Information */
    ANSI_A_E_MWI,                   /* Message Waiting Indication */
    ANSI_A_E_MID,                   /* Mobile Identity */
    ANSI_A_E_FWD_MS_INFO_RECS,      /* (Forward) MS Information Records */
    ANSI_A_E_ORIG_CI,               /* Origination Continuation Indicator */
    ANSI_A_E_PACA_ORDER,            /* PACA Order */
    ANSI_A_E_PACA_REOI,             /* PACA Reorigination Indicator */
    ANSI_A_E_PACA_TS,               /* PACA Timestamp */
    ANSI_A_E_PSP,                   /* Packet Session Parameters */
    ANSI_A_E_PDSN_IP_ADDR,          /* PDSN IP Address */
    ANSI_A_E_PDI,                   /* Power Down Indicator */
    ANSI_A_E_PRIO,                  /* Priority */
    ANSI_A_E_P_REV,                 /* Protocol Revision */
    ANSI_A_E_PTYPE,                 /* Protocol Type */
    ANSI_A_E_PSMM_COUNT,            /* PSMM Count */
    ANSI_A_E_QOS_PARAMS,            /* Quality of Service Parameters */
    ANSI_A_E_RE_RES,                /* Radio Environment and Resources */
    ANSI_A_E_REG_TYPE,              /* Registration Type */
    ANSI_A_E_REJ_CAUSE,             /* Reject Cause */
    ANSI_A_E_RESP_REQ,              /* Response Request */
    ANSI_A_E_RETURN_CAUSE,          /* Return Cause */
    ANSI_A_E_RF_CHAN_ID,            /* RF Channel Identity */
    ANSI_A_E_SO,                    /* Service Option */
    ANSI_A_E_SOCI,                  /* Service Option Connection Identifier (SOCI) */
    ANSI_A_E_SO_LIST,               /* Service Option List */
    ANSI_A_E_S_RED_INFO,            /* Service Redirection Info */
    ANSI_A_E_SR_ID,                 /* Service Reference Identifier (SR_ID) */
    ANSI_A_E_SID,                   /* SID */
    ANSI_A_E_SIGNAL,                /* Signal */
    ANSI_A_E_SCI,                   /* Slot Cycle Index */
    ANSI_A_E_SW_VER,                /* Software Version */
    ANSI_A_E_SRNC_TRNC_TC,          /* Source RNC to Target RNC Transparent Container */
    ANSI_A_E_S_PDSN_ADDR,           /* Source PDSN Address */
    ANSI_A_E_TAG,                   /* Tag */
    ANSI_A_E_TRNC_SRNC_TC,          /* Target RNC to Source RNC Transparent Container */
    ANSI_A_E_XMODE,                 /* Transcoder Mode */
    ANSI_A_E_UZ_ID,                 /* User Zone ID */
    ANSI_A_E_VP_REQ,                /* Voice Privacy Request */
    ANSI_A_E_A2P_BEARER_SESSION,    /* A2p Bearer Session-Level Parameters */
    ANSI_A_E_A2P_BEARER_FORMAT,     /* A2p Bearer Format-Specific Parameters */
    ANSI_A_E_MS_DES_FREQ,           /* MS Designated Frequency */
    ANSI_A_E_MOB_SUB_INFO,          /* Mobile Subscription Information */
    ANSI_A_E_PLCM_ID,               /* Public Long Code Mask Identifier */
    ANSI_A_E_REV_MS_INFO_RECS,      /* (Reverse) MS Information Records */
    ANSI_A_E_NONE        /* NONE */
}
elem_idx_t;
static elem_idx_t ansi_a_elem_1_max = 0;

#define MAX_IOS401_NUM_ELEM_1 (sizeof(ansi_a_ios401_elem_1_strings)/sizeof(ext_value_string_t))
#define MAX_IOS501_NUM_ELEM_1 (sizeof(ansi_a_ios501_elem_1_strings)/sizeof(ext_value_string_t))
static gint ett_ansi_elem_1[MAX(MAX_IOS401_NUM_ELEM_1, MAX_IOS501_NUM_ELEM_1)];
static guint8 (*elem_1_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) =
{
    elem_acc_net_id,                /* Access Network Identifiers */
    elem_adds_user_part,            /* ADDS User Part */
    elem_amps_hho_param,            /* AMPS Hard Handoff Parameters */
    elem_anchor_pdsn_addr,          /* Anchor PDSN Address */
    elem_anchor_pp_addr,            /* Anchor P-P Address */
    elem_auth_chlg_param,           /* Authentication Challenge Parameter */
    NULL /* no decode required */,  /* Authentication Confirmation Parameter (RANDC) */
    NULL /* no decode required */,  /* Authentication Data */
    elem_auth_event,                /* Authentication Event */
    elem_auth_param_count,          /* Authentication Parameter COUNT */
    elem_auth_resp_param,           /* Authentication Response Parameter */
    elem_band_class,                /* Band Class */
    elem_cld_party_ascii_num,       /* Called Party ASCII Number */
    elem_cld_party_bcd_num,         /* Called Party BCD Number */
    elem_clg_party_ascii_num,       /* Calling Party ASCII Number */
    elem_cause,                     /* Cause */
    elem_cause_l3,                  /* Cause Layer 3 */
    elem_cdma_sowd,                 /* CDMA Serving One Way Delay */
    elem_cell_id,                   /* Cell Identifier */
    elem_cell_id_list,              /* Cell Identifier List */
    elem_chan_num,                  /* Channel Number */
    elem_chan_type,                 /* Channel Type */
    elem_cct_group,                 /* Circuit Group */
    elem_cic,                       /* Circuit Identity Code */
    elem_cic_ext,                   /* Circuit Identity Code Extension */
    elem_cm_info_type_2,            /* Classmark Information Type 2 */
    elem_downlink_re,               /* Downlink Radio Environment */
    elem_downlink_re_list,          /* Downlink Radio Environment List */
    elem_enc_info,                  /* Encryption Information */
    elem_ext_ho_dir_params,         /* Extended Handoff Direction Parameters */
    elem_geo_loc,                   /* Geographic Location */
    elem_ssci,                      /* Special Service Call Indicator */
    elem_ho_pow_lev,                /* Handoff Power Level */
    elem_hho_params,                /* Hard Handoff Parameters */
    elem_info_rec_req,              /* Information Element Requested */
    elem_is2000_chan_id,            /* IS-2000 Channel Identity */
    NULL,                           /* IS-2000 Channel Identity 3X */
    elem_is2000_mob_cap,            /* IS-2000 Mobile Capabilities */
    elem_is2000_nn_scr,             /* IS-2000 Non-Negotiable Service Configuration Record */
    elem_is2000_scr,                /* IS-2000 Service Configuration Record */
    elem_is2000_cause,              /* IS-95/IS-2000 Cause Value */
    NULL,                           /* IS-2000 Redirection Record */
    elem_is95_chan_id,              /* IS-95 Channel Identity */
    elem_is95_ms_meas_chan_id,      /* IS-95 MS Measured Channel Identity */
    elem_l3_info,                   /* Layer 3 Information */
    elem_lai,                       /* Location Area Information */
    elem_mwi,                       /* Message Waiting Indication */
    elem_mid,                       /* Mobile Identity */
    elem_fwd_ms_info_recs,          /* (Forward) MS Information Records */
    NULL /* no associated data */,  /* Origination Continuation Indicator */
    elem_paca_order,                /* PACA Order */
    elem_paca_reoi,                 /* PACA Reorigination Indicator */
    elem_paca_ts,                   /* PACA Timestamp */
    NULL,                           /* Packet Session Parameters */
    elem_pdsn_ip_addr,              /* PDSN IP Address */
    NULL /* no associated data */,  /* Power Down Indicator */
    elem_prio,                      /* Priority */
    elem_p_rev,                     /* Protocol Revision */
    elem_ptype,                     /* Protocol Type */
    elem_psmm_count,                /* PSMM Count */
    elem_qos_params,                /* Quality of Service Parameters */
    elem_re_res,                    /* Radio Environment and Resources */
    elem_reg_type,                  /* Registration Type */
    elem_rej_cause,                 /* Reject Cause */
    NULL /* no associated data */,  /* Response Request */
    elem_return_cause,              /* Return Cause */
    elem_rf_chan_id,                /* RF Channel Identity */
    elem_so,                        /* Service Option */
    elem_soci,                      /* Service Option Connection Identifier (SOCI) */
    elem_so_list,                   /* Service Option List */
    NULL,                           /* Service Redirection Info */
    elem_sr_id,                     /* Service Reference Identifier (SR_ID) */
    elem_sid,                       /* SID */
    elem_signal,                    /* Signal */
    elem_sci,                       /* Slot Cycle Index */
    elem_sw_ver,                    /* Software Version */
    NULL /* transparent */,         /* Source RNC to Target RNC Transparent Container */
    elem_s_pdsn_ip_addr,            /* Source PDSN Address */
    elem_tag,                       /* Tag */
    NULL /* transparent */,         /* Target RNC to Source RNC Transparent Container */
    elem_xmode,                     /* Transcoder Mode */
    elem_uz_id,                     /* User Zone ID */
    NULL /* no associated data */,  /* Voice Privacy Request */
    elem_a2p_bearer_session,        /* A2p Bearer Session-Level Parameters */
    elem_a2p_bearer_format,         /* A2p Bearer Format-Specific Parameters */
    elem_ms_des_freq,               /* MS Designated Frequency */
    NULL,                           /* Mobile Subscription Information */
    elem_plcm_id,                   /* Public Long Code Mask Identification */
    elem_rev_ms_info_recs,          /* (Reverse) MS Information Records */
    NULL,        /* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * Type Length Value (TLV) element dissector
 */
static guint8
elem_tlv(tvbuff_t *tvb, proto_tree *tree, elem_idx_t idx, guint32 offset, guint len _U_, const gchar *name_add)
{
    guint8      oct, parm_len;
    guint8      consumed;
    guint32     curr_offset;
    proto_tree  *subtree;
    proto_item  *item;
    gint        dec_idx;

    curr_offset = offset;
    consumed = 0;

    if ((int)idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_length_remaining(tvb, offset) ;
    }

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == (guint8) ansi_a_elem_1_strings[idx].value)
    {
        dec_idx = ansi_a_elem_1_strings[idx].dec_index;

        parm_len = tvb_get_guint8(tvb, curr_offset + 1);

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, parm_len + 2,
                "%s%s",
                ansi_a_elem_1_strings[idx].strptr,
                (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, ett_ansi_elem_1[idx]);

        proto_tree_add_uint_format(subtree, hf_ansi_a_elem_id, tvb,
            curr_offset, 1, oct,
            "Element ID");

        proto_tree_add_uint(subtree, hf_ansi_a_length, tvb,
            curr_offset + 1, 1, parm_len);

        if (parm_len > 0)
        {
            if (elem_1_fcn[dec_idx] == NULL)
            {
                proto_tree_add_text(subtree,
                    tvb, curr_offset + 2, parm_len,
                    "Element Value");

                consumed = parm_len;
            }
            else
            {
                gchar *a_add_string;

                a_add_string = (gchar *) ep_alloc(1024);
                a_add_string[0] = '\0';
                consumed =
                    (*elem_1_fcn[dec_idx])(tvb, subtree, curr_offset + 2,
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
elem_tv(tvbuff_t *tvb, proto_tree *tree, elem_idx_t idx, guint32 offset, const gchar *name_add)
{
    guint8      oct;
    guint8      consumed;
    guint32     curr_offset;
    proto_tree  *subtree;
    proto_item  *item;
    gint        dec_idx;


    curr_offset = offset;
    consumed = 0;

    if ((int)idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_length_remaining(tvb, offset) ;
    }

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == (guint8) ansi_a_elem_1_strings[idx].value)
    {
        dec_idx = ansi_a_elem_1_strings[idx].dec_index;

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, -1,
                "%s%s",
                ansi_a_elem_1_strings[idx].strptr,
                (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, ett_ansi_elem_1[idx]);

        proto_tree_add_uint_format(subtree, hf_ansi_a_elem_id, tvb,
            curr_offset, 1, oct,
            "Element ID");

        if (elem_1_fcn[dec_idx] == NULL)
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

            a_add_string = (gchar *) ep_alloc(1024);
            a_add_string[0] = '\0';
            consumed = (*elem_1_fcn[dec_idx])(tvb, subtree, curr_offset + 1, -1, a_add_string, 1024);

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
 * Type (T) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
static guint8
elem_t(tvbuff_t *tvb, proto_tree *tree, elem_idx_t idx, guint32 offset, const gchar *name_add)
{
    guint8      oct;
    guint32     curr_offset;
    guint8      consumed;


    curr_offset = offset;
    consumed = 0;

    if ((int)idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_length_remaining(tvb, offset) ;
    }

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == (guint8) ansi_a_elem_1_strings[idx].value)
    {
        proto_tree_add_uint_format(tree, hf_ansi_a_elem_id, tvb, curr_offset, 1, oct,
            "%s%s",
            ansi_a_elem_1_strings[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        consumed = 1;
    }

    return(consumed);
}

/*
 * Length Value (LV) element dissector
 */
static guint8
elem_lv(tvbuff_t *tvb, proto_tree *tree, elem_idx_t idx, guint32 offset, guint len _U_, const gchar *name_add)
{
    guint8      parm_len;
    guint8      consumed;
    guint32     curr_offset;
    proto_tree  *subtree;
    proto_item  *item;
    gint        dec_idx;


    curr_offset = offset;
    consumed = 0;

    if ((int)idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_length_remaining(tvb, offset) ;
    }

    dec_idx = ansi_a_elem_1_strings[idx].dec_index;

    parm_len = tvb_get_guint8(tvb, curr_offset);

    item =
        proto_tree_add_text(tree,
            tvb, curr_offset, parm_len + 1,
            "%s%s",
            ansi_a_elem_1_strings[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

    subtree = proto_item_add_subtree(item, ett_ansi_elem_1[idx]);

    proto_tree_add_uint(subtree, hf_ansi_a_length, tvb,
        curr_offset, 1, parm_len);

    if (parm_len > 0)
    {
        if (elem_1_fcn[dec_idx] == NULL)
        {
            proto_tree_add_text(subtree,
                tvb, curr_offset + 1, parm_len,
                "Element Value");

            consumed = parm_len;
        }
        else
        {
            gchar *a_add_string;

            a_add_string = (gchar *) ep_alloc(1024);
            a_add_string[0] = '\0';
            consumed =
                (*elem_1_fcn[dec_idx])(tvb, subtree, curr_offset + 1,
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
elem_v(tvbuff_t *tvb, proto_tree *tree, elem_idx_t idx, guint32 offset)
{
    guint8      consumed;
    guint32     curr_offset;
    gint        dec_idx;

    curr_offset = offset;
    consumed = 0;

    if ((int)idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_length_remaining(tvb, offset) ;
    }

    dec_idx = ansi_a_elem_1_strings[idx].dec_index;

    if (elem_1_fcn[dec_idx] == NULL)
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

        a_add_string = (gchar *) ep_alloc(1024);
        a_add_string[0] = '\0';
        consumed = (*elem_1_fcn[dec_idx])(tvb, tree, curr_offset, -1, a_add_string, 1024);
    }

    return(consumed);
}


#define ELEM_MAND_TLV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_tlv(tvb, tree, elem_idx, curr_offset, curr_len, elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_text(tree, \
            tvb, curr_offset, 0, \
            "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
                ansi_a_elem_1_strings[elem_idx].value, \
                ansi_a_elem_1_strings[elem_idx].strptr, \
                (elem_name_addition == NULL) || (elem_name_addition[0] == '\0') ? "" : elem_name_addition \
            ); \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_TLV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_tlv(tvb, tree, elem_idx, curr_offset, curr_len, elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_MAND_TV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_tv(tvb, tree, elem_idx, curr_offset, elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_text(tree, \
            tvb, curr_offset, 0, \
            "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
                ansi_a_elem_1_strings[elem_idx].value, \
                ansi_a_elem_1_strings[elem_idx].strptr, \
                (elem_name_addition == NULL) || (elem_name_addition[0] == '\0') ? "" : elem_name_addition \
            ); \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_TV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_tv(tvb, tree, elem_idx, curr_offset, elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_T(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_t(tvb, tree, elem_idx, curr_offset, elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_MAND_LV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_lv(tvb, tree, elem_idx, curr_offset, curr_len, elem_name_addition)) > 0) \
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

#define ELEM_MAND_V(elem_idx) \
{\
    if ((consumed = elem_v(tvb, tree, elem_idx, curr_offset)) > 0) \
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


/*
 * IOS 6.1.2.1
 */
static void
bsmap_cl3_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8      consumed;
    guint32     curr_offset;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CELL_ID, "");

    ELEM_MAND_TLV(ANSI_A_E_L3_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.2
 */
static void
dtap_cm_srvc_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;
    guint8      oct;
    proto_tree  *subtree;
    proto_item  *item;
    const gchar *str;

    curr_offset = offset;
    curr_len = len;

    /*
     * special dissection for CM Service Type
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct & 0x0f)
    {
    case 0x01: str = "Mobile Originating Call"; break;
    default:
        str = "Unknown";
        break;
    }

    item =
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "CM Service Type: %s",
            str);

    subtree = proto_item_add_subtree(item, ett_cm_srvc_type);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(subtree,
        tvb, curr_offset, 1,
        "%s :  Element ID",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(subtree,
        tvb, curr_offset, 1,
        "%s :  Service Type: (%u) %s",
        a_bigbuf,
        oct & 0x0f,
        str);

    curr_offset++;
    curr_len--;

    ELEM_MAND_LV(ANSI_A_E_CM_INFO_TYPE_2, "");

    ELEM_MAND_LV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_CLD_PARTY_BCD_NUM, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_RESP_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_CNF_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_PARAM_COUNT, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    ELEM_OPT_T(ANSI_A_E_VP_REQ, "");

    ELEM_OPT_TV(ANSI_A_E_RE_RES, "");

    ELEM_OPT_TLV(ANSI_A_E_CLD_PARTY_ASCII_NUM, "");

    ELEM_OPT_TV(ANSI_A_E_CIC, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_EVENT, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_DATA, "");

    ELEM_OPT_TLV(ANSI_A_E_PACA_REOI, "");

    ELEM_OPT_TLV(ANSI_A_E_UZ_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_CDMA_SOWD, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_SSCI, "");

        ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

        ELEM_OPT_T(ANSI_A_E_ORIG_CI, "");

        ELEM_OPT_TV(ANSI_A_E_RETURN_CAUSE, "");

        ELEM_OPT_TLV(ANSI_A_E_MID, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

        ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.1.3
 */
static void
dtap_cm_srvc_req_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_CLD_PARTY_BCD_NUM, "");

    ELEM_OPT_TLV(ANSI_A_E_CLD_PARTY_ASCII_NUM, "");

    ELEM_OPT_TLV(ANSI_A_E_REV_MS_INFO_RECS, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.3
 */
static void
bsmap_page_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

        ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

        ELEM_OPT_TLV(ANSI_A_E_MID, "");

        ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.4
 */
static void
dtap_page_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_CM_INFO_TYPE_2, "");

    ELEM_MAND_LV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_RESP_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_CNF_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_PARAM_COUNT, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    ELEM_OPT_T(ANSI_A_E_VP_REQ, "");

    ELEM_OPT_TV(ANSI_A_E_CIC, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_EVENT, "");

    ELEM_OPT_TV(ANSI_A_E_RE_RES, "");

    ELEM_OPT_TLV(ANSI_A_E_UZ_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_CDMA_SOWD, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

        ELEM_OPT_TLV(ANSI_A_E_MID, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.12
 */
static void
dtap_progress(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TV(ANSI_A_E_SIGNAL, "");

    ELEM_OPT_TLV(ANSI_A_E_FWD_MS_INFO_RECS, "");

    ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.8.1
 */
static void
dtap_srvc_redirection(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_IS2000_RED_RECORD, "");

    ELEM_MAND_TLV(ANSI_A_E_S_RED_INFO, "");

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.1.11
 */
static void
dtap_srvc_release(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_SOCI, "");

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE_L3, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.1.12
 */
static void
dtap_srvc_release_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_SOCI, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.15
 */
static void
bsmap_ass_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8      consumed;
    guint32     curr_offset;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CHAN_TYPE, "");

    ELEM_OPT_TV(ANSI_A_E_CIC, "");

    ELEM_OPT_TLV(ANSI_A_E_ENC_INFO, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    ELEM_OPT_TV(ANSI_A_E_SIGNAL, "");

    ELEM_OPT_TLV(ANSI_A_E_CLG_PARTY_ASCII_NUM, "");

    ELEM_OPT_TLV(ANSI_A_E_FWD_MS_INFO_RECS, "");

    ELEM_OPT_TLV(ANSI_A_E_PRIO, "");

    ELEM_OPT_TLV(ANSI_A_E_PACA_TS, "");

    ELEM_OPT_TLV(ANSI_A_E_QOS_PARAMS, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

        ELEM_OPT_TLV(ANSI_A_E_SR_ID, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

        ELEM_OPT_TLV(ANSI_A_E_MID, "");

        ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.16
 */
static void
bsmap_ass_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8      consumed;
    guint32     curr_offset;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TV(ANSI_A_E_CHAN_NUM, "");

    ELEM_OPT_TLV(ANSI_A_E_ENC_INFO, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

        ELEM_OPT_TLV(ANSI_A_E_MID, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.17
 */
static void
bsmap_ass_failure(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8      consumed;
    guint32     curr_offset;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.20
 */
static void
bsmap_clr_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8      consumed;
    guint32     curr_offset;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE_L3, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.21
 */
static void
bsmap_clr_command(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8      consumed;
    guint32     curr_offset;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE_L3, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.22
 */
static void
bsmap_clr_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint8      consumed;
    guint32     curr_offset;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_T(ANSI_A_E_PDI, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.24
 */
static void
dtap_alert_with_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_FWD_MS_INFO_RECS, "");

    ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.28
 */
static void
bsmap_bs_srvc_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_ADDS_USER_PART, "");

    ELEM_OPT_TLV(ANSI_A_E_SR_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.29
 */
static void
bsmap_bs_srvc_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.1.19
 */
static void
bsmap_add_srvc_noti(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_MAND_TV(ANSI_A_E_SO, "");

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.1.20
 */
static void
dtap_add_srvc_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_SOCI, "");

    ELEM_OPT_TLV(ANSI_A_E_CLD_PARTY_BCD_NUM, "");

    ELEM_MAND_TV(ANSI_A_E_SO, "");

    ELEM_OPT_T(ANSI_A_E_VP_REQ, "");

    ELEM_OPT_TLV(ANSI_A_E_CLD_PARTY_ASCII_NUM, "");

    ELEM_OPT_TV(ANSI_A_E_CIC, "");

    ELEM_OPT_TLV(ANSI_A_E_SSCI, "");

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.1.10
 */
static void
dtap_connect(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.3.7
 */
static void
dtap_flash_with_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_CLD_PARTY_BCD_NUM, "");

    ELEM_OPT_TV(ANSI_A_E_SIGNAL, "");

    ELEM_OPT_TV(ANSI_A_E_MWI, "");

    ELEM_OPT_TLV(ANSI_A_E_CLG_PARTY_ASCII_NUM, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    if (g_pinfo->p2p_dir == P2P_DIR_RECV)
    {
        ELEM_OPT_TLV(ANSI_A_E_REV_MS_INFO_RECS, "");
    }
    else
    {
        ELEM_OPT_TLV(ANSI_A_E_FWD_MS_INFO_RECS, "");
    }

    ELEM_OPT_TLV(ANSI_A_E_SSCI, "");

    ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.3.8
 */
static void
dtap_flash_with_info_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.3.9
 */
static void
bsmap_feat_noti(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TV(ANSI_A_E_SIGNAL, "");

    ELEM_OPT_TV(ANSI_A_E_MWI, "");

    ELEM_OPT_TLV(ANSI_A_E_CLG_PARTY_ASCII_NUM, "");

    ELEM_OPT_TLV(ANSI_A_E_FWD_MS_INFO_RECS, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

    ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.3.10
 */
static void
bsmap_feat_noti_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.3.11
 */
static void
bsmap_paca_command(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_PRIO, "");

    ELEM_OPT_TLV(ANSI_A_E_PACA_TS, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.3.12
 */
static void
bsmap_paca_command_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.3.13
 */
static void
bsmap_paca_update(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_PACA_ORDER, "");

    ELEM_OPT_TLV(ANSI_A_E_PRIO, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_RESP_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_CNF_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_PARAM_COUNT, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_EVENT, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.3.14
 */
static void
bsmap_paca_update_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_PRIO, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.2.9
 */
static void
bsmap_rm_pos_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_PSMM_COUNT, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.2.10
 */
static void
bsmap_rm_pos_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_CDMA_SOWD, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_DOWNLINK_RE_LIST, "");

    ELEM_OPT_TLV(ANSI_A_E_GEO_LOC, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.1
 */
static void
bsmap_auth_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

    ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_auth_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.2
 */
static void
bsmap_auth_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_AUTH_RESP_PARAM, "");

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_MAND_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5
 * Section 3.1.21
 */
static void
bsmap_bearer_upd_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5
 * Section 3.1.22
 */
static void
bsmap_bearer_upd_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5
 * Section 3.1.23
 */
static void
bsmap_bearer_upd_reqd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

    ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_auth_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_AUTH_RESP_PARAM, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.3
 */
static void
bsmap_user_zone_update(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_UZ_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.16
 */
static void
dtap_user_zone_update_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_UZ_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.17
 */
static void
dtap_user_zone_update(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_UZ_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.18
 */
static void
bsmap_user_zone_reject(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_UZ_ID, "");

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

    ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.18
 */
static void
dtap_user_zone_reject(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_UZ_ID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.19
 */
static void
bsmap_reg_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.20
 */
static void
bsmap_ms_reg_noti(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.21
 */
static void
bsmap_bs_auth_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.22
 */
static void
bsmap_bs_auth_req_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.4
 */
static void
dtap_ssd_update_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.5
 */
static void
dtap_bs_challenge(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.6
 */
static void
dtap_bs_challenge_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_AUTH_RESP_PARAM, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.7
 */
static void
dtap_ssd_update_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_CAUSE_L3, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.8
 */
static void
dtap_lu_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_LAI, "");

    ELEM_OPT_TLV(ANSI_A_E_CM_INFO_TYPE_2, "");

    ELEM_OPT_TV(ANSI_A_E_REG_TYPE, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_RESP_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_CNF_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_PARAM_COUNT, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_EVENT, "");

    ELEM_OPT_TLV(ANSI_A_E_UZ_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TV(ANSI_A_E_RETURN_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.9
 */
static void
dtap_lu_accept(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        ELEM_OPT_TV(ANSI_A_E_LAI, "");
        break;

    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

        ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

        ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.10
 */
static void
dtap_lu_reject(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(ANSI_A_E_REJ_CAUSE);

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

        ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.18
 */
static void
bsmap_priv_mode_command(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_ENC_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.4.19
 */
static void
bsmap_priv_mode_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_ENC_INFO, "");

    ELEM_OPT_T(ANSI_A_E_VP_REQ, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.14
 */
static void
bsmap_status_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_IE_REQD, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

    ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.14
 */
static void
dtap_status_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_IE_REQD, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}


/*
 * IOS 5 3.3.15
 */
static void
bsmap_status_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_REV_MS_INFO_RECS, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.3.15
 */
static void
dtap_status_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_REV_MS_INFO_RECS, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.5.4
 */
static void
bsmap_ho_reqd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_MAND_TLV(ANSI_A_E_CELL_ID_LIST, " (Target)");

    ELEM_OPT_TLV(ANSI_A_E_CM_INFO_TYPE_2, "");

    ELEM_OPT_T(ANSI_A_E_RESP_REQ, "");

    ELEM_OPT_TLV(ANSI_A_E_ENC_INFO, "");

    ELEM_OPT_TLV(ANSI_A_E_IS95_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_DOWNLINK_RE, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    ELEM_OPT_TLV(ANSI_A_E_CDMA_SOWD, "");

    ELEM_OPT_TLV(ANSI_A_E_IS95_MS_MEAS_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_QOS_PARAMS, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_SCR, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        ELEM_OPT_TLV(ANSI_A_E_PDSN_IP_ADDR, "");
        break;

    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_S_PDSN_ADDR, "");
        break;
    }

    ELEM_OPT_TLV(ANSI_A_E_PTYPE, "");

    ELEM_OPT_TLV(ANSI_A_E_SRNC_TRNC_TC, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TV(ANSI_A_E_ACC_NET_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_SO_LIST, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_CHAN_ID_3X, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_NN_SCR, "");

    ELEM_OPT_TLV(ANSI_A_E_ANCH_PDSN_ADDR, "");

    ELEM_OPT_TLV(ANSI_A_E_ANCH_PP_ADDR, "");

    ELEM_OPT_TLV(ANSI_A_E_PSP, "");

    ELEM_OPT_TLV(ANSI_A_E_PLCM_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.5.5
 */
static void
bsmap_ho_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CHAN_TYPE, "");

    ELEM_MAND_TLV(ANSI_A_E_ENC_INFO, "");

    ELEM_MAND_TLV(ANSI_A_E_CM_INFO_TYPE_2, "");

    ELEM_MAND_TLV(ANSI_A_E_CELL_ID_LIST, "(Target)");

    ELEM_OPT_TLV(ANSI_A_E_CIC_EXT, "");

    ELEM_OPT_TLV(ANSI_A_E_IS95_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_DOWNLINK_RE, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    ELEM_OPT_TLV(ANSI_A_E_CDMA_SOWD, "");

    ELEM_OPT_TLV(ANSI_A_E_IS95_MS_MEAS_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_QOS_PARAMS, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_SCR, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        ELEM_OPT_TLV(ANSI_A_E_PDSN_IP_ADDR, "");
        break;

    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_S_PDSN_ADDR, "");
        break;
    }

    ELEM_OPT_TLV(ANSI_A_E_PTYPE, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_SRNC_TRNC_TC, "");

        ELEM_OPT_TV(ANSI_A_E_SCI, "");

        ELEM_OPT_TV(ANSI_A_E_ACC_NET_ID, "");

        ELEM_OPT_TLV(ANSI_A_E_SO_LIST, "");

        ELEM_OPT_TLV(ANSI_A_E_IS2000_CHAN_ID_3X, "");

        ELEM_OPT_TLV(ANSI_A_E_IS2000_NN_SCR, "");

        ELEM_OPT_TLV(ANSI_A_E_ANCH_PDSN_ADDR, "");

        ELEM_OPT_TLV(ANSI_A_E_ANCH_PP_ADDR, "");

        ELEM_OPT_TLV(ANSI_A_E_PSP, "");

        ELEM_OPT_TLV(ANSI_A_E_PLCM_ID, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");

        ELEM_OPT_TLV(ANSI_A_E_MID, "");

        ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.5.6
 */
static void
bsmap_ho_req_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_IS95_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TLV(ANSI_A_E_EXT_HO_DIR_PARAMS, "");

    ELEM_OPT_TV(ANSI_A_E_HHO_PARAMS, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_SCR, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_NN_SCR, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_TRNC_SRNC_TC, "");

        ELEM_OPT_TLV(ANSI_A_E_SO_LIST, "");

        ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

        ELEM_OPT_TLV(ANSI_A_E_IS2000_CHAN_ID_3X, "");

        ELEM_OPT_TLV(ANSI_A_E_PLCM_ID, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_SESSION, "");

        ELEM_OPT_TLV(ANSI_A_E_A2P_BEARER_FORMAT, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.5.7
 */
static void
bsmap_ho_failure(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.5.8
 */
static void
bsmap_ho_command(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TV(ANSI_A_E_RF_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS95_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TLV(ANSI_A_E_HO_POW_LEV, "");

    ELEM_OPT_TV(ANSI_A_E_SID, "");

    ELEM_OPT_TLV(ANSI_A_E_EXT_HO_DIR_PARAMS, "");

    ELEM_OPT_TV(ANSI_A_E_HHO_PARAMS, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_CHAN_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_SCR, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_NN_SCR, "");

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ELEM_OPT_TLV(ANSI_A_E_TRNC_SRNC_TC, "");

        ELEM_OPT_TLV(ANSI_A_E_SO_LIST, "");

        ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

        ELEM_OPT_TLV(ANSI_A_E_AMPS_HHO_PARAM, "");

        ELEM_OPT_TLV(ANSI_A_E_IS2000_CHAN_ID_3X, "");

        ELEM_OPT_TLV(ANSI_A_E_PLCM_ID, "");
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.4.6
 */
static void
bsmap_ho_complete(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.5.9
 */
static void
bsmap_ho_reqd_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.5.12
 */
static void
bsmap_ho_performed(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TV(ANSI_A_E_CHAN_NUM, "");

    ELEM_OPT_TLV(ANSI_A_E_BAND_CLASS, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.2
 */
static void
bsmap_block(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TV(ANSI_A_E_CIC, "");

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_CCT_GROUP, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.3
 */
static void
bsmap_block_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TV(ANSI_A_E_CIC, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.4
 */
static void
bsmap_unblock(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TV(ANSI_A_E_CIC, "");

    ELEM_OPT_TLV(ANSI_A_E_CCT_GROUP, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.5
 */
static void
bsmap_unblock_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TV(ANSI_A_E_CIC, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.6
 */
static void
bsmap_reset(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_SW_VER, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.7
 */
static void
bsmap_reset_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_SW_VER, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.8
 */
static void
bsmap_reset_cct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TV(ANSI_A_E_CIC, "");

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_CCT_GROUP, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.9
 */
static void
bsmap_reset_cct_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TV(ANSI_A_E_CIC, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.10
 */
static void
bsmap_xmode_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_XMODE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.6.11
 */
static void
bsmap_xmode_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.7.1
 */
static void
bsmap_adds_page(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_MAND_TLV(ANSI_A_E_ADDS_USER_PART, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID_LIST, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_P_REV, "");

    ELEM_OPT_TLV(ANSI_A_E_MS_DES_FREQ, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.7.2
 */
static void
bsmap_adds_transfer(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_MAND_TLV(ANSI_A_E_ADDS_USER_PART, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_RESP_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_CNF_PARAM, "");

    ELEM_OPT_TV(ANSI_A_E_AUTH_PARAM_COUNT, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_CHLG_PARAM, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_EVENT, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_CDMA_SOWD, "");

    ELEM_OPT_TLV(ANSI_A_E_AUTH_DATA, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CM_INFO_TYPE_2, "");

    ELEM_OPT_TV(ANSI_A_E_SCI, "");

    ELEM_OPT_TV(ANSI_A_E_SO, "");

    ELEM_OPT_TLV(ANSI_A_E_UZ_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_MOB_CAP, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MOB_SUB_INFO, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 5 3.6.4
 */
static void
bsmap_adds_transfer_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.7.3
 */
static void
dtap_adds_deliver(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_ADDS_USER_PART, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CDMA_SOWD, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.7.4
 */
static void
bsmap_adds_page_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_CELL_ID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.7.5
 */
static void
dtap_adds_deliver_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TV(ANSI_A_E_TAG, "");

    ELEM_OPT_TLV(ANSI_A_E_CAUSE, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.8.1
 */
static void
bsmap_rejection(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void
dtap_rejection(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    ELEM_OPT_TLV(ANSI_A_E_IS2000_CAUSE, "");

    ELEM_OPT_TLV(ANSI_A_E_SOCI, "");

    ELEM_OPT_TLV(ANSI_A_E_MID, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

#define ANSI_A_IOS401_BSMAP_NUM_MSG (sizeof(ansi_a_ios401_bsmap_strings)/sizeof(ext_value_string_t))
#define ANSI_A_IOS501_BSMAP_NUM_MSG (sizeof(ansi_a_ios501_bsmap_strings)/sizeof(ext_value_string_t))
static gint ett_bsmap_msg[MAX(ANSI_A_IOS401_BSMAP_NUM_MSG, ANSI_A_IOS501_BSMAP_NUM_MSG)];
static void (*bsmap_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) =
{
    bsmap_add_srvc_noti,            /* Additional Service Notification */
    bsmap_adds_page,                /* ADDS Page */
    bsmap_adds_page_ack,            /* ADDS Page Ack */
    bsmap_adds_transfer,            /* ADDS Transfer */
    bsmap_adds_transfer_ack,        /* ADDS Transfer Ack */
    bsmap_ass_complete,             /* Assignment Complete */
    bsmap_ass_failure,              /* Assignment Failure */
    bsmap_ass_req,                  /* Assignment Request */
    bsmap_auth_req,                 /* Authentication Request */
    bsmap_auth_resp,                /* Authentication Response */
    NULL /* no BSMAP definition */, /* Base Station Challenge */
    NULL /* no BSMAP definition */, /* Base Station Challenge Response */
    bsmap_block,                    /* Block */
    bsmap_block_ack,                /* Block Acknowledge */
    bsmap_bs_srvc_req,              /* BS Service Request */
    bsmap_bs_srvc_resp,             /* BS Service Response */
    bsmap_clr_command,              /* Clear Command */
    bsmap_clr_complete,             /* Clear Complete */
    bsmap_clr_req,                  /* Clear Request */
    bsmap_cl3_info,                 /* Complete Layer 3 Information */
    bsmap_feat_noti,                /* Feature Notification */
    bsmap_feat_noti_ack,            /* Feature Notification Ack */
    bsmap_ho_command,               /* Handoff Command */
    NULL /* no associated data */,  /* Handoff Commenced */
    bsmap_ho_complete,              /* Handoff Complete */
    bsmap_ho_failure,               /* Handoff Failure */
    bsmap_ho_performed,             /* Handoff Performed */
    bsmap_ho_req,                   /* Handoff Request */
    bsmap_ho_req_ack,               /* Handoff Request Acknowledge */
    bsmap_ho_reqd,                  /* Handoff Required */
    bsmap_ho_reqd_rej,              /* Handoff Required Reject */
    bsmap_paca_command,             /* PACA Command */
    bsmap_paca_command_ack,         /* PACA Command Ack */
    bsmap_paca_update,              /* PACA Update */
    bsmap_paca_update_ack,          /* PACA Update Ack */
    bsmap_page_req,                 /* Paging Request */
    bsmap_priv_mode_command,        /* Privacy Mode Command */
    bsmap_priv_mode_complete,       /* Privacy Mode Complete */
    bsmap_rm_pos_req,               /* Radio Measurements for Position Request */
    bsmap_rm_pos_resp,              /* Radio Measurements for Position Response */
    bsmap_rejection,                /* Rejection */
    bsmap_reg_req,                  /* Registration Request */
    bsmap_reset,                    /* Reset */
    bsmap_reset_ack,                /* Reset Acknowledge */
    bsmap_reset_cct,                /* Reset Circuit */
    bsmap_reset_cct_ack,            /* Reset Circuit Acknowledge */
    NULL /* no BSMAP definition */, /* SSD Update Request */
    NULL /* no BSMAP definition */, /* SSD Update Response */
    bsmap_status_req,               /* Status Request */
    bsmap_status_resp,              /* Status Response */
    bsmap_xmode_ack,                /* Transcoder Control Acknowledge */
    bsmap_xmode_req,                /* Transcoder Control Request */
    bsmap_unblock,                  /* Unblock */
    bsmap_unblock_ack,              /* Unblock Acknowledge */
    bsmap_user_zone_reject,         /* User Zone Reject */
    bsmap_user_zone_update,         /* User Zone Update */
    bsmap_bearer_upd_req,           /* Bearer Update Request *//* IOS 5.0.1 */
    bsmap_bearer_upd_resp,          /* Bearer Update Response *//* IOS 5.0.1 */
    bsmap_bearer_upd_reqd,          /* Bearer Update Required *//* IOS 5.0.1 */
    bsmap_ms_reg_noti,              /* Mobile Station Registered Notification *//* IOS 5.0.1 */
    bsmap_bs_auth_req,              /* BS Authentication Request *//* IOS 5.0.1 */
    bsmap_bs_auth_req_ack,          /* BS Authentication Request Ack *//* IOS 5.0.1 */
    NULL,        /* NONE */
};

#define ANSI_A_IOS401_DTAP_NUM_MSG (sizeof(ansi_a_ios401_dtap_strings)/sizeof(ext_value_string_t))
#define ANSI_A_IOS501_DTAP_NUM_MSG (sizeof(ansi_a_ios501_dtap_strings)/sizeof(ext_value_string_t))
static gint ett_dtap_msg[MAX(ANSI_A_IOS401_DTAP_NUM_MSG, ANSI_A_IOS501_DTAP_NUM_MSG)];
static void (*dtap_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) =
{
    dtap_add_srvc_req,              /* Additional Service Request */
    dtap_adds_deliver,              /* ADDS Deliver */
    dtap_adds_deliver_ack,          /* ADDS Deliver Ack */
    dtap_alert_with_info,           /* Alert With Information */
    dtap_auth_req,                  /* Authentication Request */
    dtap_auth_resp,                 /* Authentication Response */
    dtap_bs_challenge,              /* Base Station Challenge */
    dtap_bs_challenge_resp,         /* Base Station Challenge Response */
    dtap_cm_srvc_req,               /* CM Service Request */
    dtap_cm_srvc_req_cont,          /* CM Service Request Continuation */
    dtap_connect,                   /* Connect */
    dtap_flash_with_info,           /* Flash with Information */
    dtap_flash_with_info_ack,       /* Flash with Information Ack */
    dtap_lu_accept,                 /* Location Updating Accept */
    dtap_lu_reject,                 /* Location Updating Reject */
    dtap_lu_req,                    /* Location Updating Request */
    dtap_page_resp,                 /* Paging Response */
    NULL /* no associated data */,  /* Parameter Update Confirm */
    NULL /* no associated data */,  /* Parameter Update Request */
    dtap_rejection,                 /* Rejection */
    dtap_progress,                  /* Progress */
    dtap_srvc_redirection,          /* Service Redirection */
    dtap_srvc_release,              /* Service Release */
    dtap_srvc_release_complete,     /* Service Release Complete */
    dtap_ssd_update_req,            /* SSD Update Request */
    dtap_ssd_update_resp,           /* SSD Update Response */
    dtap_status_req,                /* Status Request */
    dtap_status_resp,               /* Status Response */
    dtap_user_zone_reject,          /* User Zone Reject */
    dtap_user_zone_update,          /* User Zone Update */
    dtap_user_zone_update_req,      /* User Zone Update Request */
    NULL,       /* NONE */
};

/* Utillity function to dissect CDMA200 A1 elements in ANSI MAP messages */
void
dissect_cdma2000_a1_elements(tvbuff_t *tvb, _U_ packet_info *pinfo, proto_tree *tree, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;
    elem_idx_t  idx;
    guint8      oct;

    curr_offset = offset;
    curr_len = len;

    /*
     * require at least 2 octets for T(ype) and L(ength)
     */
    while (curr_len > 1)
    {
        /*
         * peeking at T(ype)
         */
        oct = tvb_get_guint8(tvb, curr_offset);

        for (idx=0; idx < ansi_a_elem_1_max; idx++)
        {
            if (oct == (guint8) ansi_a_elem_1_strings[idx].value)
            {
                ELEM_OPT_TLV(idx, "");
                break;
            }
        }

        if (idx == ansi_a_elem_1_max)
        {
            /*
             * didn't recognize the T(ype)
             * assuming it is in TLV form, step over
             */
            consumed = 2 + tvb_get_guint8(tvb, curr_offset + 1);
            curr_offset += consumed;
            curr_len -= consumed;
        }
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/* GENERIC DISSECTOR FUNCTIONS */

static void
dissect_bsmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    static ansi_a_tap_rec_t     tap_rec[16];
    static ansi_a_tap_rec_t     *tap_p;
    static int                  tap_current=0;
    guint8                      oct;
    guint32                     offset, saved_offset;
    guint32                     len;
    gint                        idx, dec_idx;
    proto_item                  *bsmap_item = NULL;
    proto_tree                  *bsmap_tree = NULL;
    const gchar                 *msg_str;


    col_append_str(pinfo->cinfo, COL_INFO, "(BSMAP) ");

    /*
     * set tap record pointer
     */
    tap_current++;
    if (tap_current == array_length(tap_rec))
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
     * add BSMAP message name
     */
    oct = tvb_get_guint8(tvb, offset++);

    msg_str = my_match_strval_idx((guint32) oct, ansi_a_bsmap_strings, &idx, &dec_idx);

    /*
     * create the a protocol tree
     */
    if (msg_str == NULL)
    {
        bsmap_item =
            proto_tree_add_protocol_format(tree, proto_a_bsmap, tvb, 0, len,
                "ANSI A-I/F BSMAP - Unknown BSMAP Message Type (%u)",
                oct);

        bsmap_tree = proto_item_add_subtree(bsmap_item, ett_bsmap);
    }
    else
    {
        bsmap_item =
            proto_tree_add_protocol_format(tree, proto_a_bsmap, tvb, 0, -1,
                "ANSI A-I/F BSMAP - %s",
                msg_str);

        bsmap_tree = proto_item_add_subtree(bsmap_item, ett_bsmap_msg[dec_idx]);

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
    }

    /*
     * add BSMAP message name
     */
    proto_tree_add_uint_format(bsmap_tree, hf_ansi_a_bsmap_msgtype,
        tvb, saved_offset, 1, oct, "Message Type");

    tap_p->pdu_type = BSSAP_PDU_TYPE_BSMAP;
    tap_p->message_type = oct;

    tap_queue_packet(ansi_a_tap, pinfo, tap_p);

    if (msg_str == NULL) return;

    if ((len - offset) <= 0) return;

    a_meid_configured = FALSE;

    /*
     * decode elements
     */
    if (bsmap_msg_fcn[dec_idx] == NULL)
    {
        proto_tree_add_text(bsmap_tree,
            tvb, offset, len - offset,
            "Message Elements");
    }
    else
    {
        (*bsmap_msg_fcn[dec_idx])(tvb, bsmap_tree, offset, len - offset);
    }
}

static void
dissect_dtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    static ansi_a_tap_rec_t     tap_rec[16];
    static ansi_a_tap_rec_t     *tap_p;
    static int                  tap_current=0;
    guint8                      oct;
    guint32                     offset, saved_offset;
    guint32                     len;
    guint32                     oct_1, oct_2;
    gint                        idx, dec_idx;
    proto_item                  *dtap_item = NULL;
    proto_tree                  *dtap_tree = NULL;
    proto_item                  *oct_1_item = NULL;
    proto_tree                  *oct_1_tree = NULL;
    const gchar                 *msg_str;
    const gchar                 *str;


    len = tvb_length(tvb);

    if (len < 3)
    {
        /*
         * too short to be DTAP
         */
        call_dissector(data_handle, tvb, pinfo, tree);
        return;
    }

    col_append_str(pinfo->cinfo, COL_INFO, "(DTAP) ");

    /*
     * set tap record pointer
     */
    tap_current++;
    if (tap_current == array_length(tap_rec))
    {
        tap_current = 0;
    }
    tap_p = &tap_rec[tap_current];


    offset = 0;
    saved_offset = offset;

    g_pinfo = pinfo;
    g_tree = tree;

    /*
     * get protocol discriminator
     */
    oct_1 = tvb_get_guint8(tvb, offset++);
    oct_2 = tvb_get_guint8(tvb, offset++);

    /*
     * add DTAP message name
     */
    saved_offset = offset;
    oct = tvb_get_guint8(tvb, offset++);

    msg_str = my_match_strval_idx((guint32) oct, ansi_a_dtap_strings, &idx, &dec_idx);

    /*
     * create the a protocol tree
     */
    if (msg_str == NULL)
    {
        dtap_item =
            proto_tree_add_protocol_format(tree, proto_a_dtap, tvb, 0, len,
                "ANSI A-I/F DTAP - Unknown DTAP Message Type (%u)",
                oct);

        dtap_tree = proto_item_add_subtree(dtap_item, ett_dtap);
    }
    else
    {
        dtap_item =
            proto_tree_add_protocol_format(tree, proto_a_dtap, tvb, 0, -1,
                "ANSI A-I/F DTAP - %s",
                msg_str);

        dtap_tree = proto_item_add_subtree(dtap_item, ett_dtap_msg[dec_idx]);

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
    }

    /*
     * octet 1
     */
    switch (oct_1 & 0x0f)
    {
    case 3: str = "Call Control, call related SS"; break;
    case 5: str = "Mobility Management"; break;
    case 6: str = "Radio Resource Management"; break;
    case 9: str = "Facility Management"; break;
    case 11: str = "Other Signaling Procedures"; break;
    case 15: str = "Reserved for tests"; break;
    default:
        str = "Unknown";
        break;
    }

    oct_1_item =
        proto_tree_add_text(dtap_tree,
            tvb, 0, 1,
            "Protocol Discriminator: %s",
            str);

    oct_1_tree = proto_item_add_subtree(oct_1_item, ett_dtap_oct_1);

    other_decode_bitfield_value(a_bigbuf, oct_1, 0xf0, 8);
    proto_tree_add_text(oct_1_tree,
        tvb, 0, 1,
        "%s :  Reserved",
        a_bigbuf);

    other_decode_bitfield_value(a_bigbuf, oct_1, 0x0f, 8);
    proto_tree_add_text(oct_1_tree,
        tvb, 0, 1,
        "%s :  Protocol Discriminator: %u",
        a_bigbuf,
        oct_1 & 0x0f);

    /*
     * octet 2
     */
    switch (global_a_variant)
    {
    case A_VARIANT_IS634:
        other_decode_bitfield_value(a_bigbuf, oct_2, 0x80, 8);
        proto_tree_add_text(dtap_tree,
            tvb, 1, 1,
            "%s :  Transaction Identifier (TI) Flag: %s",
            a_bigbuf,
            ((oct_2 & 0x80) ?  "allocated by receiver" : "allocated by sender"));

        other_decode_bitfield_value(a_bigbuf, oct_2, 0x70, 8);
        proto_tree_add_text(dtap_tree,
            tvb, 1, 1,
            "%s :  Transaction Identifier (TI): %u",
            a_bigbuf,
            (oct_2 & 0x70) >> 4);

        other_decode_bitfield_value(a_bigbuf, oct_2, 0x0f, 8);
        proto_tree_add_text(dtap_tree,
            tvb, 1, 1,
            "%s :  Reserved",
            a_bigbuf);
        break;

    default:
        proto_tree_add_text(dtap_tree,
            tvb, 1, 1,
            "Reserved Octet");
        break;
    }

    /*
     * add DTAP message name
     */
    proto_tree_add_uint_format(dtap_tree, hf_ansi_a_dtap_msgtype,
        tvb, saved_offset, 1, oct,
        "Message Type");

    tap_p->pdu_type = BSSAP_PDU_TYPE_DTAP;
    tap_p->message_type = oct;

    tap_queue_packet(ansi_a_tap, pinfo, tap_p);

    if (msg_str == NULL) return;

    if ((len - offset) <= 0) return;

    a_meid_configured = FALSE;

    /*
     * decode elements
     */
    if (dtap_msg_fcn[dec_idx] == NULL)
    {
        proto_tree_add_text(dtap_tree,
            tvb, offset, len - offset,
            "Message Elements");
    }
    else
    {
        (*dtap_msg_fcn[dec_idx])(tvb, dtap_tree, offset, len - offset);
    }
}


/* Register the protocol with Wireshark */
void
proto_register_ansi_a(void)
{
    module_t            *ansi_a_module;
    guint               i;
    gint                last_offset;

    /* Setup list of header fields */

    static hf_register_info hf[] =
    {
        { &hf_ansi_a_bsmap_msgtype,
            { "BSMAP Message Type",     "ansi_a_bsmap.msgtype",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_dtap_msgtype,
            { "DTAP Message Type",      "ansi_a_bsmap.dtap_msgtype",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_elem_id,
            { "Element ID",     "ansi_a_bsmap.elem_id",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_length,
            { "Length",         "ansi_a_bsmap.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_none,
            { "Sub tree",       "ansi_a_bsmap.none",
            FT_NONE, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_esn,
            { "ESN",    "ansi_a_bsmap.esn",
            FT_UINT32, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_imsi,
            { "IMSI",   "ansi_a_bsmap.imsi",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_min,
            { "MIN",    "ansi_a_bsmap.min",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_meid,
            { "MEID",   "ansi_a_bsmap.meid",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cld_party_bcd_num,
            { "Called Party BCD Number",        "ansi_a_bsmap.cld_party_bcd_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_bcd_num,
            { "Calling Party BCD Number",       "ansi_a_bsmap.clg_party_bcd_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cld_party_ascii_num,
            { "Called Party ASCII Number",      "ansi_a_bsmap.cld_party_ascii_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_ascii_num,
            { "Calling Party ASCII Number",     "ansi_a_bsmap.clg_party_ascii_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cell_ci,
            { "Cell CI",        "ansi_a_bsmap.cell_ci",
            FT_UINT16, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cell_lac,
            { "Cell LAC",       "ansi_a_bsmap.cell_lac",
            FT_UINT16, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cell_mscid,
            { "Cell MSCID",     "ansi_a_bsmap.cell_mscid",
            FT_UINT24, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_pdsn_ip_addr,
            { "PDSN IP Address", "ansi_a_bsmap.pdsn_ip_addr",
            FT_IPv4, BASE_NONE, NULL, 0,
            "IP Address", HFILL }
        },
        { &hf_ansi_a_s_pdsn_ip_addr,
            { "Source PDSN Address", "ansi_a_bsmap.s_pdsn_ip_addr",
            FT_IPv4, BASE_NONE, NULL, 0,
            "IP Address", HFILL }
        },
        { &hf_ansi_a_anchor_ip_addr,
            { "Anchor PDSN Address", "ansi_a_bsmap.anchor_pdsn_ip_addr",
            FT_IPv4, BASE_NONE, NULL, 0,
            "IP Address", HFILL }
        },
        { &hf_ansi_a_anchor_pp_ip_addr,
            { "Anchor P-P Address", "ansi_a_bsmap.anchor_pp_ip_addr",
            FT_IPv4, BASE_NONE, NULL, 0,
            "IP Address", HFILL }
        },
        { &hf_ansi_a_a2p_bearer_ipv4_addr,
            { "A2p Bearer IP Address", "ansi_a_bsmap.a2p_bearer_ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_ipv6_addr,
            { "A2p Bearer IP Address", "ansi_a_bsmap.a2p_bearer_ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_udp_port,
            { "A2p Bearer UDP Port", "ansi_a_bsmap.a2p_bearer_udp_port",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_so,
            { "Service Option", "ansi_a_bsmap.so",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_1,
            { "Cause",  "ansi_a_bsmap.cause_1",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_2,
            { "Cause",  "ansi_a_bsmap.cause_2",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_meid_configured,
            { "Is MEID configured",  "ansi_a_bsmap.meid_configured",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static enum_val_t a_variant_options[] = {
            { "is-634-rev0",    "IS-634 rev. 0",        A_VARIANT_IS634 },
            { "tsb-80",         "TSB-80",               A_VARIANT_TSB80 },
            { "is-634-a",       "IS-634-A",             A_VARIANT_IS634A },
            { "ios-2.x",        "IOS 2.x",              A_VARIANT_IOS2 },
            { "ios-3.x",        "IOS 3.x",              A_VARIANT_IOS3 },
            { "ios-4.0.1",      "IOS 4.0.1",            A_VARIANT_IOS401 },
            { "ios-5.0.1",      "IOS 5.0.1",            A_VARIANT_IOS501 },
            { NULL,             NULL,                   0 }

    };

    /* Setup protocol subtree array */
#define MAX_NUM_DTAP_MSG        MAX(ANSI_A_IOS401_DTAP_NUM_MSG, ANSI_A_IOS501_DTAP_NUM_MSG)
#define MAX_NUM_BSMAP_MSG       MAX(ANSI_A_IOS401_BSMAP_NUM_MSG, ANSI_A_IOS501_BSMAP_NUM_MSG)
#define MAX_NUM_ELEM_1          MAX(MAX_IOS401_NUM_ELEM_1, MAX_IOS501_NUM_ELEM_1)
#define NUM_INDIVIDUAL_ELEMS    18
    gint **ett;
    gint ett_len = (NUM_INDIVIDUAL_ELEMS+MAX_NUM_DTAP_MSG+MAX_NUM_BSMAP_MSG+MAX_NUM_ELEM_1+NUM_FWD_MS_INFO_REC+NUM_REV_MS_INFO_REC) * sizeof(gint *);

    /*
     * XXX - at least one version of the HP C compiler apparently doesn't
     * recognize constant expressions using the "?" operator as being
     * constant expressions, so you can't use the expression that
     * initializes "ett_let" as an array size.  Therefore, we dynamically
     * allocate the array instead.
     */
    ett = (gint **) g_malloc(ett_len);

    memset((void *) ett_dtap_msg, -1, sizeof(ett_dtap_msg));
    memset((void *) ett_bsmap_msg, -1, sizeof(ett_bsmap_msg));
    memset((void *) ett_ansi_elem_1, -1, sizeof(ett_ansi_elem_1));
    memset((void *) ett_ansi_fwd_ms_info_rec, -1, sizeof(gint) * NUM_FWD_MS_INFO_REC);
    memset((void *) ett_ansi_rev_ms_info_rec, -1, sizeof(gint) * NUM_REV_MS_INFO_REC);

    ett[0] = &ett_bsmap;
    ett[1] = &ett_dtap;
    ett[2] = &ett_elems;
    ett[3] = &ett_elem;
    ett[4] = &ett_dtap_oct_1;
    ett[5] = &ett_cm_srvc_type;
    ett[6] = &ett_ansi_ms_info_rec_reserved;
    ett[7] = &ett_ansi_enc_info;
    ett[8] = &ett_cell_list;
    ett[9] = &ett_bearer_list;
    ett[10] = &ett_re_list;
    ett[11] = &ett_so_list;
    ett[12] = &ett_scm;
    ett[13] = &ett_adds_user_part;
    ett[14] = &ett_scr;
    ett[15] = &ett_srvc_con_rec;
    ett[16] = &ett_cm2_band_class;
    ett[17] = &ett_vp_algs;

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < MAX_NUM_DTAP_MSG; i++, last_offset++)
    {
        ett[last_offset] = &ett_dtap_msg[i];
    }

    for (i=0; i < MAX_NUM_BSMAP_MSG; i++, last_offset++)
    {
        ett[last_offset] = &ett_bsmap_msg[i];
    }

    for (i=0; i < MAX_NUM_ELEM_1; i++, last_offset++)
    {
        ett[last_offset] = &ett_ansi_elem_1[i];
    }

    for (i=0; i < NUM_FWD_MS_INFO_REC; i++, last_offset++)
    {
        ett[last_offset] = &ett_ansi_fwd_ms_info_rec[i];
    }

    for (i=0; i < NUM_REV_MS_INFO_REC; i++, last_offset++)
    {
        ett[last_offset] = &ett_ansi_rev_ms_info_rec[i];
    }

    /* Register the protocol name and description */

    proto_a_bsmap =
        proto_register_protocol("ANSI A-I/F BSMAP", "ANSI BSMAP", "ansi_a_bsmap");

    proto_register_field_array(proto_a_bsmap, hf, array_length(hf));

    proto_a_dtap =
        proto_register_protocol("ANSI A-I/F DTAP", "ANSI DTAP", "ansi_a_dtap");

    is637_dissector_table =
        register_dissector_table("ansi_a.sms", "IS-637-A (SMS)",
        FT_UINT8, BASE_DEC);

    is683_dissector_table =
        register_dissector_table("ansi_a.ota", "IS-683-A (OTA)",
        FT_UINT8, BASE_DEC);

    is801_dissector_table =
        register_dissector_table("ansi_a.pld", "IS-801 (PLD)",
        FT_UINT8, BASE_DEC);

    proto_register_subtree_array(ett, ett_len / (int)sizeof(gint *));

    ansi_a_tap = register_tap("ansi_a");

    /*
     * setup for preferences
     */
    ansi_a_module = prefs_register_protocol(proto_a_bsmap, proto_reg_handoff_ansi_a);

    prefs_register_enum_preference(ansi_a_module,
        "global_variant",
        "Dissect PDU as",
        "(if other than the default of IOS 4.0.1)",
        &global_a_variant,
        a_variant_options,
        FALSE);

    g_free(ett);
}


void
proto_reg_handoff_ansi_a(void)
{
    static gboolean ansi_a_prefs_initialized = FALSE;

    if (!ansi_a_prefs_initialized)
    {
        dissector_handle_t bsmap_handle;
        bsmap_handle = create_dissector_handle(dissect_bsmap, proto_a_bsmap);
        dtap_handle = create_dissector_handle(dissect_dtap, proto_a_dtap);
        data_handle = find_dissector("data");
        rtp_handle = find_dissector("rtp");

        dissector_add_uint("bsap.pdu_type",  BSSAP_PDU_TYPE_BSMAP, bsmap_handle);
        dissector_add_uint("bsap.pdu_type",  BSSAP_PDU_TYPE_DTAP, dtap_handle);

        ansi_a_prefs_initialized = TRUE;
    }

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ansi_a_bsmap_strings = ansi_a_ios501_bsmap_strings;
        ansi_a_dtap_strings = ansi_a_ios501_dtap_strings;
        ansi_a_elem_1_strings = ansi_a_ios501_elem_1_strings;
        ansi_a_elem_1_max = MAX_IOS501_NUM_ELEM_1;
        break;

    default:
        ansi_a_bsmap_strings = ansi_a_ios401_bsmap_strings;
        ansi_a_dtap_strings = ansi_a_ios401_dtap_strings;
        ansi_a_elem_1_strings = ansi_a_ios401_elem_1_strings;
        ansi_a_elem_1_max = MAX_IOS401_NUM_ELEM_1;
        break;
    }
}
