/* packet-ansi_a.c
 * Routines for ANSI A Interface (IS-634/IOS) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 * Copyright 2008, Michael Lum <michael.lum [AT] starsolutions.com>
 * In association with Star Solutions
 *
 * Title                3GPP2                   Other
 *
 *   Inter-operability Specification (IOS) for CDMA
 *   2000 Access Network Interfaces
 *                      3GPP2 A.S0001-1         TIA/EIA-2001
 *
 *                      3GPP2 C.R1001-H v1.0    TSB-58-I (or J?)
 *
 *   RFC 5188
 *   RTP Payload Format for the Enhanced Variable Rate Wideband Codec (EVRC-WB)
 *   and the Media Subtype Updates for EVRC-B Codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include <epan/to_str.h>

#include <wsutil/str_util.h>

#include "packet-rtp.h"
#include "packet-bssap.h"
#include "packet-ansi_a.h"

/*
 * IOS 4, probably most common
 */
static gint global_a_variant = A_VARIANT_IOS401;
static gboolean global_a_info_display = TRUE;

/* PROTOTYPES/FORWARDS */

void proto_register_ansi_a(void);
void proto_reg_handoff_ansi_a(void);

static const gchar *
my_try_val_to_str_idx(guint32 val, const ext_value_string_t *vs, gint *dec_idx)
{
    gint i = 0;

    while (vs[i].strptr)
    {
        if (vs[i].value == val)
        {
            *dec_idx = vs[i].dec_index;
            return(vs[i].strptr);
        }

        i++;
    }

    *dec_idx = -1;
    return(NULL);
}

static const true_false_string tfs_l2_reset_dont_reset =
{
    "Reset Layer 2 Ack",
    "Do not reset Layer 2 Ack"
};

static const true_false_string tfs_fpc_reset_dont_reset =
{
    "Reset counters",
    "Do not reset counters"
};

static const true_false_string tfs_use_dont_use =
{
    "Use",
    "Do not use"
};

static const true_false_string tfs_prio_incl_yes_no =
{
    "MSC should include priority in Assignment Request",
    "MSC does not need to include priority in Assignment Request"
};

static const true_false_string tfs_alloc_yes_no =
{
    "Resources are allocated",
    "Resources are not allocated"
};

static const true_false_string tfs_avail_yes_no =
{
    "Resources are available",
    "Resources are not available"
};

static const true_false_string tfs_reoi_pri_reorig_no_reorig =
{
    "Reorigination",
    "Not reorigination"
};

static const true_false_string tfs_ansi_a_xmode_tfo_mode =
{
    "TFO",
    "tandem"
};

static const true_false_string tfs_reserved_no_voice_privacy =
{
    "Reserved",
    "No voice privacy supported"
};

static const true_false_string tfs_reserved_aes =
{
    "Reserved",
    "Advanced Encryption Standard (AES)"
};

static const true_false_string tfs_reserved_private_long_code =
{
    "Reserved",
    "Private long code"
};

static const true_false_string tfs_a2p_bearer_form_format_bearer_addr_flag =
{
    "Override Bearer Session IP Address",
    "Use Bearer Session IP Address"
};

static const true_false_string tfs_a2p_bearer_sess_addr_flag =
{
    "Session IP Address is present",
    "Session IP Address is not present"
};

const ext_value_string_t ansi_a_ios401_bsmap_strings[] =
{
    { 0x69,     "Additional Service Notification",              0 },
    { 0x65,     "ADDS Page",                                    1 },
    { 0x66,     "ADDS Page Ack",                                2 },
    { 0x67,     "ADDS Transfer",                                3 },
    { 0x68,     "ADDS Transfer Ack",                            4 },
    { 0x02,     "Assignment Complete",                          5 },
    { 0x03,     "Assignment Failure",                           6 },
    { 0x01,     "Assignment Request",                           7 },
    { 0x45,     "Authentication Request",                       8 },
    { 0x46,     "Authentication Response",                      9 },
    { 0x48,     "Base Station Challenge",                       10 },
    { 0x49,     "Base Station Challenge Response",              11 },
    { 0x40,     "Block",                                        12 },
    { 0x41,     "Block Acknowledge",                            13 },
    { 0x09,     "BS Service Request",                           14 },
    { 0x0A,     "BS Service Response",                          15 },
    { 0x20,     "Clear Command",                                16 },
    { 0x21,     "Clear Complete",                               17 },
    { 0x22,     "Clear Request",                                18 },
    { 0x57,     "Complete Layer 3 Information",                 19 },
    { 0x60,     "Feature Notification",                         20 },
    { 0x61,     "Feature Notification Ack",                     21 },
    { 0x13,     "Handoff Command",                              22 },
    { 0x15,     "Handoff Commenced",                            23 },
    { 0x14,     "Handoff Complete",                             24 },
    { 0x16,     "Handoff Failure",                              25 },
    { 0x17,     "Handoff Performed",                            26 },
    { 0x10,     "Handoff Request",                              27 },
    { 0x12,     "Handoff Request Acknowledge",                  28 },
    { 0x11,     "Handoff Required",                             29 },
    { 0x1A,     "Handoff Required Reject",                      30 },
    { 0x6C,     "PACA Command",                                 31 },
    { 0x6D,     "PACA Command Ack",                             32 },
    { 0x6E,     "PACA Update",                                  33 },
    { 0x6F,     "PACA Update Ack",                              34 },
    { 0x52,     "Paging Request",                               35 },
    { 0x53,     "Privacy Mode Command",                         36 },
    { 0x55,     "Privacy Mode Complete",                        37 },
    { 0x23,     "Radio Measurements for Position Request",      38 },
    { 0x25,     "Radio Measurements for Position Response",     39 },
    { 0x56,     "Rejection",                                    40 },
    { 0x05,     "Registration Request",                         41 },
    { 0x30,     "Reset",                                        42 },
    { 0x31,     "Reset Acknowledge",                            43 },
    { 0x34,     "Reset Circuit",                                44 },
    { 0x35,     "Reset Circuit Acknowledge",                    45 },
    { 0x47,     "SSD Update Request",                           46 },
    { 0x4A,     "SSD Update Response",                          47 },
    { 0x6A,     "Status Request",                               48 },
    { 0x6B,     "Status Response",                              49 },
    { 0x39,     "Transcoder Control Acknowledge",               50 },
    { 0x38,     "Transcoder Control Request",                   51 },
    { 0x42,     "Unblock",                                      52 },
    { 0x43,     "Unblock Acknowledge",                          53 },
    { 0x0B,     "User Zone Reject",                             54 },
    { 0x04,     "User Zone Update",                             55 },
    { 0, NULL, 0 }
};

const ext_value_string_t ansi_a_ios401_dtap_strings[] =
{
    { 0x62,     "Additional Service Request",           0 },
    { 0x53,     "ADDS Deliver",                         1 },
    { 0x54,     "ADDS Deliver Ack",                     2 },
    { 0x26,     "Alert With Information",               3 },
    { 0x45,     "Authentication Request",               4 },
    { 0x46,     "Authentication Response",              5 },
    { 0x48,     "Base Station Challenge",               6 },
    { 0x49,     "Base Station Challenge Response",      7 },
    { 0x24,     "CM Service Request",                   8 },
    { 0x25,     "CM Service Request Continuation",      9 },
    { 0x07,     "Connect",                              10 },
    { 0x10,     "Flash with Information",               11 },
    { 0x50,     "Flash with Information Ack",           12 },
    { 0x02,     "Location Updating Accept",             13 },
    { 0x04,     "Location Updating Reject",             14 },
    { 0x08,     "Location Updating Request",            15 },
    { 0x27,     "Paging Response",                      16 },
    { 0x2B,     "Parameter Update Confirm",             17 },
    { 0x2C,     "Parameter Update Request",             18 },
    { 0x56,     "Rejection",                            19 },
    { 0x03,     "Progress",                             20 },
    { 0x70,     "Service Redirection",                  21 },
    { 0x2E,     "Service Release",                      22 },
    { 0x2F,     "Service Release Complete",             23 },
    { 0x47,     "SSD Update Request",                   24 },
    { 0x4A,     "SSD Update Response",                  25 },
    { 0x6A,     "Status Request",                       26 },
    { 0x6B,     "Status Response",                      27 },
    { 0x0B,     "User Zone Reject",                     28 },
    { 0x0C,     "User Zone Update",                     29 },
    { 0x0D,     "User Zone Update Request",             30 },
    { 0x33,     "Send Burst DTMF",                      31 },           /* IS-634.400A 6.1.3.1 */
    { 0x34,     "Send Burst DTMF Ack",                  32 },           /* IS-634.400A 6.1.3.2 */
    { 0x35,     "Start DTMF",                           33 },           /* IS-634.400A 6.1.3.3 */
    { 0x36,     "Start DTMF Ack",                       34 },           /* IS-634.400A 6.1.3.4 */
    { 0x31,     "Stop DTMF",                            35 },           /* IS-634.400A 6.1.3.5 */
    { 0x32,     "Stop DTMF Ack",                        36 },           /* IS-634.400A 6.1.3.6 */
    { 0, NULL, 0 }
};

const ext_value_string_t ansi_a_ios401_elem_1_strings[] =
{
    { 0x20,     "Access Network Identifiers",                                   0 },
    { 0x3D,     "ADDS User Part",                                               1 },
    { 0x25,     "AMPS Hard Handoff Parameters",                                 2 },
    { 0x30,     "Anchor PDSN Address",                                          3 },
    { 0x7C,     "Anchor P-P Address",                                           4 },
    { 0x41,     "Authentication Challenge Parameter",                           5 },
    { 0x28,     "Authentication Confirmation Parameter (RANDC)",                6 },
    { 0x59,     "Authentication Data",                                          7 },
    { 0x4A,     "Authentication Event",                                         8 },
    { 0x40,     "Authentication Parameter COUNT",                               9 },
    { 0x42,     "Authentication Response Parameter",                            10 },
    { 0x37,     "Band Class",                                                   11 },
    { 0x5B,     "Called Party ASCII Number",                                    12 },
    { 0x5E,     "Called Party BCD Number",                                      13 },
    { 0x4B,     "Calling Party ASCII Number",                                   14 },
    { 0x04,     "Cause",                                                        15 },
    { 0x08,     "Cause Layer 3",                                                16 },
    { 0x0C,     "CDMA Serving One Way Delay",                                   17 },
    { 0x05,     "Cell Identifier",                                              18 },
    { 0x1A,     "Cell Identifier List",                                         19 },
    { 0x23,     "Channel Number",                                               20 },
    { 0x0B,     "Channel Type",                                                 21 },
    { 0x19,     "Circuit Group",                                                22 },
    { 0x01,     "Circuit Identity Code",                                        23 },
    { 0x24,     "Circuit Identity Code Extension",                              24 },
    { 0x12,     "Classmark Information Type 2",                                 25 },
    { 0x29,     "Downlink Radio Environment",                                   26 },
    { 0x2B,     "Downlink Radio Environment List",                              27 },
    { 0x0A,     "Encryption Information",                                       28 },
    { 0x10,     "Extended Handoff Direction Parameters",                        29 },
    { 0x2C,     "Geographic Location",                                          30 },
    { 0x5A,     "Special Service Call Indicator",                               31 },
    { 0x26,     "Handoff Power Level",                                          32 },
    { 0x16,     "Hard Handoff Parameters",                                      33 },
    { 0x2E,     "Information Element Requested",                                34 },
    { 0x09,     "IS-2000 Channel Identity",                                     35 },
    { 0x27,     "IS-2000 Channel Identity 3X",                                  36 },
    { 0x11,     "IS-2000 Mobile Capabilities",                                  37 },
    { 0x0F,     "IS-2000 Non-Negotiable Service Configuration Record",          38 },
    { 0x0E,     "IS-2000 Service Configuration Record",                         39 },
    { 0x62,     "IS-95/IS-2000 Cause Value",                                    40 },
    { 0x67,     "IS-2000 Redirection Record",                                   41 },
    { 0x22,     "IS-95 Channel Identity",                                       42 },
    { 0x64,     "IS-95 MS Measured Channel Identity",                           43 },
    { 0x17,     "Layer 3 Information",                                          44 },
    { 0x13,     "Location Area Information",                                    45 },
    { 0x38,     "Message Waiting Indication",                                   46 },
    { 0x0D,     "Mobile Identity",                                              47 },
    { 0x15,     "MS Information Records (Forward)",                             48 },
    { 0xA0,     "Origination Continuation Indicator",                           49 },
    { 0x5F,     "PACA Order",                                                   50 },
    { 0x60,     "PACA Reorigination Indicator",                                 51 },
    { 0x4E,     "PACA Timestamp",                                               52 },
    { 0x70,     "Packet Session Parameters",                                    53 },
    { 0x14,     "PDSN IP Address",                                              54 },
    { 0xA2,     "Power Down Indicator",                                         55 },
    { 0x06,     "Priority",                                                     56 },
    { 0x3B,     "Protocol Revision",                                            57 },
    { 0x18,     "Protocol Type",                                                58 },
    { 0x2D,     "PSMM Count",                                                   59 },
    { 0x07,     "Quality of Service Parameters",                                60 },
    { 0x1D,     "Radio Environment and Resources",                              61 },
    { 0x1F,     "Registration Type",                                            62 },
    { 0x44,     "Reject Cause",                                                 63 },
    { 0x1B,     "Response Request",                                             64 },
    { 0x68,     "Return Cause",                                                 65 },
    { 0x21,     "RF Channel Identity",                                          66 },
    { 0x03,     "Service Option",                                               67 },
    { 0x1E,     "Service Option Connection Identifier (SOCI)",                  68 },
    { 0x2A,     "Service Option List",                                          69 },
    { 0x69,     "Service Redirection Info",                                     70 },
    { 0x71,     "Service Reference Identifier (SR_ID)",                         71 },
    { 0x32,     "SID",                                                          72 },
    { 0x34,     "Signal",                                                       73 },
    { 0x35,     "Slot Cycle Index",                                             74 },
    { 0x31,     "Software Version",                                             75 },
    { 0x39,     "Source RNC to Target RNC Transparent Container",               76 },
    { 0x14,     "Source PDSN Address",                                          77 },
    { 0x33,     "Tag",                                                          78 },
    { 0x3A,     "Target RNC to Source RNC Transparent Container",               79 },
    { 0x36,     "Transcoder Mode",                                              80 },   /* XXX 0x1C in IOS 4.0.1 */
    { 0x02,     "User Zone ID",                                                 81 },
    { 0xA1,     "Voice Privacy Request",                                        82 },
    { 0x15,     "MS Information Records (Reverse)",                             83 },
    { 0x2C,     "Burst DTMF Transmission Information",                          84 },   /* duplicate but never used because this elem is always MANDATORY in DTAP */
    { 0x2D,     "DTMF Characters",                                              85 },   /* duplicate but never used because this elem is always MANDATORY in DTAP */
    { 0, NULL, 0 }
};

const ext_value_string_t ansi_a_ios501_bsmap_strings[] =
{
    { 0x69,     "Additional Service Notification",              0 },
    { 0x65,     "ADDS Page",                                    1 },
    { 0x66,     "ADDS Page Ack",                                2 },
    { 0x67,     "ADDS Transfer",                                3 },
    { 0x68,     "ADDS Transfer Ack",                            4 },
    { 0x02,     "Assignment Complete",                          5 },
    { 0x03,     "Assignment Failure",                           6 },
    { 0x01,     "Assignment Request",                           7 },
    { 0x45,     "Authentication Request",                       8 },
    { 0x46,     "Authentication Response",                      9 },
    { 0x48,     "Base Station Challenge",                       10 },
    { 0x49,     "Base Station Challenge Response",              11 },
    { 0x40,     "Block",                                        12 },
    { 0x41,     "Block Acknowledge",                            13 },
    { 0x09,     "BS Service Request",                           14 },
    { 0x0A,     "BS Service Response",                          15 },
    { 0x20,     "Clear Command",                                16 },
    { 0x21,     "Clear Complete",                               17 },
    { 0x22,     "Clear Request",                                18 },
    { 0x57,     "Complete Layer 3 Information",                 19 },
    { 0x60,     "Feature Notification",                         20 },
    { 0x61,     "Feature Notification Ack",                     21 },
    { 0x13,     "Handoff Command",                              22 },
    { 0x15,     "Handoff Commenced",                            23 },
    { 0x14,     "Handoff Complete",                             24 },
    { 0x16,     "Handoff Failure",                              25 },
    { 0x17,     "Handoff Performed",                            26 },
    { 0x10,     "Handoff Request",                              27 },
    { 0x12,     "Handoff Request Acknowledge",                  28 },
    { 0x11,     "Handoff Required",                             29 },
    { 0x1A,     "Handoff Required Reject",                      30 },
    { 0x6C,     "PACA Command",                                 31 },
    { 0x6D,     "PACA Command Ack",                             32 },
    { 0x6E,     "PACA Update",                                  33 },
    { 0x6F,     "PACA Update Ack",                              34 },
    { 0x52,     "Paging Request",                               35 },
    { 0x53,     "Privacy Mode Command",                         36 },
    { 0x55,     "Privacy Mode Complete",                        37 },
    { 0x23,     "Radio Measurements for Position Request",      38 },
    { 0x25,     "Radio Measurements for Position Response",     39 },
    { 0x56,     "Rejection",                                    40 },
    { 0x05,     "Registration Request",                         41 },
    { 0x30,     "Reset",                                        42 },
    { 0x31,     "Reset Acknowledge",                            43 },
    { 0x34,     "Reset Circuit",                                44 },
    { 0x35,     "Reset Circuit Acknowledge",                    45 },
    { 0x47,     "SSD Update Request",                           46 },
    { 0x4A,     "SSD Update Response",                          47 },
    { 0x6A,     "Status Request",                               48 },
    { 0x6B,     "Status Response",                              49 },
    { 0x39,     "Transcoder Control Acknowledge",               50 },
    { 0x38,     "Transcoder Control Request",                   51 },
    { 0x42,     "Unblock",                                      52 },
    { 0x43,     "Unblock Acknowledge",                          53 },
    { 0x0B,     "User Zone Reject",                             54 },
    { 0x04,     "User Zone Update",                             55 },
    { 0x58,     "Bearer Update Request",                        56 },
    { 0x5A,     "Bearer Update Required",                       57 },
    { 0x59,     "Bearer Update Response",                       58 },
    { 0x71,     "Mobile Station Registered Notification",       59 },
    { 0x07,     "BS Authentication Request",                    60 },
    { 0x08,     "BS Authentication Request Ack",                61 },
    { 0, NULL, 0 }
};

const ext_value_string_t ansi_a_ios501_dtap_strings[] =
{
    { 0x62,     "Additional Service Request",                   0 },
    { 0x53,     "ADDS Deliver",                                 1 },
    { 0x54,     "ADDS Deliver Ack",                             2 },
    { 0x26,     "Alert With Information",                       3 },
    { 0x45,     "Authentication Request",                       4 },
    { 0x46,     "Authentication Response",                      5 },
    { 0x48,     "Base Station Challenge",                       6 },
    { 0x49,     "Base Station Challenge Response",              7 },
    { 0x24,     "CM Service Request",                           8 },
    { 0x25,     "CM Service Request Continuation",              9 },
    { 0x07,     "Connect",                                      10 },
    { 0x10,     "Flash with Information",                       11 },
    { 0x50,     "Flash with Information Ack",                   12 },
    { 0x02,     "Location Updating Accept",                     13 },
    { 0x04,     "Location Updating Reject",                     14 },
    { 0x08,     "Location Updating Request",                    15 },
    { 0x27,     "Paging Response",                              16 },
    { 0x2B,     "Parameter Update Confirm",                     17 },
    { 0x2C,     "Parameter Update Request",                     18 },
    { 0x56,     "Rejection",                                    19 },
    { 0x03,     "Progress",                                     20 },
    { 0x70,     "Service Redirection",                          21 },
    { 0x2E,     "Service Release",                              22 },
    { 0x2F,     "Service Release Complete",                     23 },
    { 0x47,     "SSD Update Request",                           24 },
    { 0x4A,     "SSD Update Response",                          25 },
    { 0x6A,     "Status Request",                               26 },
    { 0x6B,     "Status Response",                              27 },
    { 0x0B,     "User Zone Reject",                             28 },
    { 0x0C,     "User Zone Update",                             29 },
    { 0x0D,     "User Zone Update Request",                     30 },
    { 0x33,     "Send Burst DTMF",                              31 },   /* IS-634.400A 6.1.3.1 */
    { 0x34,     "Send Burst DTMF Ack",                          32 },   /* IS-634.400A 6.1.3.2 */
    { 0x35,     "Start DTMF",                                   33 },   /* IS-634.400A 6.1.3.3 */
    { 0x36,     "Start DTMF Ack",                               34 },   /* IS-634.400A 6.1.3.4 */
    { 0x31,     "Stop DTMF",                                    35 },   /* IS-634.400A 6.1.3.5 */
    { 0x32,     "Stop DTMF Ack",                                36 },   /* IS-634.400A 6.1.3.6 */
    { 0, NULL, 0 }
};

/*
 * ORDER MUST MATCH
 * ansi_a_ios401_elem_1_strings when the same element
 * is being described.
 */
const ext_value_string_t ansi_a_ios501_elem_1_strings[] =
{
    { 0x20,     "Access Network Identifiers",                                   0 },
    { 0x3D,     "ADDS User Part",                                               1 },
    { 0x25,     "AMPS Hard Handoff Parameters",                                 2 },
    { 0x30,     "Anchor PDSN Address",                                          3 },
    { 0x7C,     "Anchor P-P Address",                                           4 },
    { 0x41,     "Authentication Challenge Parameter",                           5 },
    { 0x28,     "Authentication Confirmation Parameter (RANDC)",                6 },
    { 0x59,     "Authentication Data",                                          7 },
    { 0x4A,     "Authentication Event",                                         8 },
    { 0x40,     "Authentication Parameter COUNT",                               9 },
    { 0x42,     "Authentication Response Parameter",                            10 },
    { 0x37,     "Band Class",                                                   11 },
    { 0x5B,     "Called Party ASCII Number",                                    12 },
    { 0x5E,     "Called Party BCD Number",                                      13 },
    { 0x4B,     "Calling Party ASCII Number",                                   14 },
    { 0x04,     "Cause",                                                        15 },
    { 0x08,     "Cause Layer 3",                                                16 },
    { 0x0C,     "CDMA Serving One Way Delay",                                   17 },
    { 0x05,     "Cell Identifier",                                              18 },
    { 0x1A,     "Cell Identifier List",                                         19 },
    { 0x23,     "Channel Number",                                               20 },
    { 0x0B,     "Channel Type",                                                 21 },
    { 0x19,     "Circuit Group",                                                22 },
    { 0x01,     "Circuit Identity Code",                                        23 },
    { 0x24,     "Circuit Identity Code Extension",                              24 },
    { 0x12,     "Classmark Information Type 2",                                 25 },
    { 0x29,     "Downlink Radio Environment",                                   26 },
    { 0x2B,     "Downlink Radio Environment List",                              27 },
    { 0x0A,     "Encryption Information",                                       28 },
    { 0x10,     "Extended Handoff Direction Parameters",                        29 },
    { 0x2C,     "Geographic Location",                                          30 },
    { 0x5A,     "Special Service Call Indicator",                               31 },
    { 0x26,     "Handoff Power Level",                                          32 },
    { 0x16,     "Hard Handoff Parameters",                                      33 },
    { 0x2E,     "Information Element Requested",                                34 },
    { 0x09,     "IS-2000 Channel Identity",                                     35 },
    { 0x27,     "IS-2000 Channel Identity 3X",                                  36 },
    { 0x11,     "IS-2000 Mobile Capabilities",                                  37 },
    { 0x0F,     "IS-2000 Non-Negotiable Service Configuration Record",          38 },
    { 0x0E,     "IS-2000 Service Configuration Record",                         39 },
    { 0x62,     "IS-95/IS-2000 Cause Value",                                    40 },
    { 0x67,     "IS-2000 Redirection Record",                                   41 },
    { 0x22,     "IS-95 Channel Identity",                                       42 },
    { 0x64,     "IS-95 MS Measured Channel Identity",                           43 },
    { 0x17,     "Layer 3 Information",                                          44 },
    { 0x13,     "Location Area Information",                                    45 },
    { 0x38,     "Message Waiting Indication",                                   46 },
    { 0x0D,     "Mobile Identity",                                              47 },
    { 0x15,     "MS Information Records (Forward)",                             48 },
    { 0xA0,     "Origination Continuation Indicator",                           49 },
    { 0x5F,     "PACA Order",                                                   50 },
    { 0x60,     "PACA Reorigination Indicator",                                 51 },
    { 0x4E,     "PACA Timestamp",                                               52 },
    { 0x70,     "Packet Session Parameters",                                    53 },
    { 0x14,     "PDSN IP Address",                                              54 },
    { 0xA2,     "Power Down Indicator",                                         55 },
    { 0x06,     "Priority",                                                     56 },
    { 0x3B,     "Protocol Revision",                                            57 },
    { 0x18,     "Protocol Type",                                                58 },
    { 0x2D,     "PSMM Count",                                                   59 },
    { 0x07,     "Quality of Service Parameters",                                60 },
    { 0x1D,     "Radio Environment and Resources",                              61 },
    { 0x1F,     "Registration Type",                                            62 },
    { 0x44,     "Reject Cause",                                                 63 },
    { 0x1B,     "Response Request",                                             64 },
    { 0x68,     "Return Cause",                                                 65 },
    { 0x21,     "RF Channel Identity",                                          66 },
    { 0x03,     "Service Option",                                               67 },
    { 0x1E,     "Service Option Connection Identifier (SOCI)",                  68 },
    { 0x2A,     "Service Option List",                                          69 },
    { 0x69,     "Service Redirection Info",                                     70 },
    { 0x71,     "Service Reference Identifier (SR_ID)",                         71 },
    { 0x32,     "SID",                                                          72 },
    { 0x34,     "Signal",                                                       73 },
    { 0x35,     "Slot Cycle Index",                                             74 },
    { 0x31,     "Software Version",                                             75 },
    { 0x39,     "Source RNC to Target RNC Transparent Container",               76 },
    { 0x14,     "Source PDSN Address",                                          77 },
    { 0x33,     "Tag",                                                          78 },
    { 0x3A,     "Target RNC to Source RNC Transparent Container",               79 },
    { 0x36,     "Transcoder Mode",                                              80 },   /* XXX 0x1C in IOS 4.0.1 */
    { 0x02,     "User Zone ID",                                                 81 },
    { 0xA1,     "Voice Privacy Request",                                        82 },
    { 0x15,     "MS Information Records (Reverse)",                             83 },
    { 0x2C,     "Burst DTMF Transmission Information",                          84 },   /* duplicate but never used because this elem is always MANDATORY in DTAP */
    { 0x2D,     "DTMF Characters",                                              85 },   /* duplicate but never used because this elem is always MANDATORY in DTAP */
    { 0x45,     "A2p Bearer Session-Level Parameters",                          86 },
    { 0x46,     "A2p Bearer Format-Specific Parameters",                        87 },
    { 0x73,     "MS Designated Frequency",                                      88 },
    { 0x7D,     "Mobile Subscription Information",                              89 },
    { 0x72,     "Public Long Code Mask Identification",                         90 },
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

static const value_string ansi_fwd_ms_info_rec_str[] =
{
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

static const value_string ansi_rev_ms_info_rec_str[] =
{
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
static const value_string ansi_a_band_class_vals[] = {
    { 0x00,     "800 MHz Cellular System" },
    { 0x01,     "1.850 to 1.990 GHz Broadband PCS" },
    { 0x02,     "872 to 960 MHz TACS Band" },
    { 0x03,     "832 to 925 MHz JTACS Band" },
    { 0x04,     "1.750 to 1.870 GHz Korean PCS" },
    { 0x05,     "450 MHz NMT" },
    { 0x06,     "2 GHz IMT-2000" },
    { 0x07,     "Upper 700 MHz" },
    { 0x08,     "1.710 to 1.880 GHz PCS" },
    { 0x09,     "880 to 960 MHz" },
    { 0x0a,     "Secondary 800 MHz" },
    { 0x0b,     "400 MHz European PAMR" },
    { 0x0c,     "800 MHz European PAMR" },
    { 0x0d,     "2.5 GHz IMT-2000 Extension" },
    { 0x0e,     "US PCS 1.9 GHz" },
    { 0x0f,     "AWS" },
    { 0x10,     "US 2.5 GHz" },
    { 0x11,     "US 2.5 GHz Forward Link Only" },
    { 0x12,     "700 MHz Public Safety" },
    { 0x13,     "Lower 700 MHz" },
    { 0, NULL }
};

static const value_string ansi_a_ip_addr_type_vals[] = {
    { 0x00,     "IPv4" },
    { 0x01,     "IPv6" },
    { 0x02,     "Reserved" },
    { 0x03,     "Reserved" },
    { 0, NULL }
};

/*
 * C.S0005-E v2.0 Table 2.6.6.2.1-1
 */
static const value_string ansi_a_srch_win_sizes_vals[] = {
    { 0x00,     "4 PN chips" },
    { 0x01,     "6 PN chips" },
    { 0x02,     "8 PN chips" },
    { 0x03,     "10 PN chips" },
    { 0x04,     "14 PN chips" },
    { 0x05,     "20 PN chips" },
    { 0x06,     "28 PN chips" },
    { 0x07,     "40 PN chips" },
    { 0x08,     "60 PN chips" },
    { 0x09,     "80 PN chips" },
    { 0x0a,     "100 PN chips" },
    { 0x0b,     "130 PN chips" },
    { 0x0c,     "160 PN chips" },
    { 0x0d,     "226 PN chips" },
    { 0x0e,     "320 PN chips" },
    { 0x0f,     "452 PN chips" },
    { 0, NULL }
};

/*
 * C.S0005-E v2.0 Table 2.6.6.2.3-1
 */
static const value_string ansi_a_t_tdrop_vals[] = {
    { 0x00,     "100 milliseconds" },
    { 0x01,     "1 second" },
    { 0x02,     "2 seconds" },
    { 0x03,     "4 seconds" },
    { 0x04,     "6 seconds" },
    { 0x05,     "9 seconds" },
    { 0x06,     "13 seconds" },
    { 0x07,     "19 seconds" },
    { 0x08,     "27 seconds" },
    { 0x09,     "39 seconds" },
    { 0x0a,     "55 seconds" },
    { 0x0b,     "79 seconds" },
    { 0x0c,     "112 seconds" },
    { 0x0d,     "159 seconds" },
    { 0x0e,     "225 seconds" },
    { 0x0f,     "319 seconds" },
    { 0, NULL }
};

static const value_string cell_disc_vals[] = {
    { 0,        "whole Cell Global Identification (CGI)" },
    { 1,        "LAC/CI" },
    { 2,        "Cell Identity (CI)" },
    { 3,        "None" },
    { 4,        "Location Area Identification (LAI)" },
    { 5,        "Location Area Code (LAC)" },
    { 6,        "ALL" },
    { 7,        "IS-41 whole Cell Global Identification (ICGI)" },
    { 8,        "Enhanced whole Cell Global Identification (ECGI)" },
    { 0, NULL }
};

/*
 * Not strictly A-interface info, but put here to avoid file polution
 *
 * Title                3GPP2                   Other
 *
 *   Administration of Parameter Value Assignments for
 *   cdma2000 Spread Spectrum Standards
 *                      3GPP2 C.R1001-H v1.0    TSB-58-I (or J?)
 */

/*
 * 9.1 Data Field Encoding Assignments
 */
const value_string ansi_tsb58_encoding_vals[] = {
    { 0x0000,   "Octet, unspecified" },
    { 0x0001,   "Extended Protocol Message" },
    { 0x0002,   "7-bit ASCII" },
    { 0x0003,   "IA5" },
    { 0x0004,   "UNICODE" },
    { 0x0005,   "Shift-JIS" },
    { 0x0006,   "Korean" },
    { 0x0007,   "Latin/Hebrew" },
    { 0x0008,   "Latin" },
    { 0x0009,   "GSM 7-bit default alphabet" },
    { 0x0010,   "KSC5601 (Korean)" },
    { 0, NULL }
};

/*
 * 9.2 Language Indicator Value Assignments
 */
const value_string ansi_tsb58_language_ind_vals[] = {
    { 0x0000,   "Unknown or unspecified" },
    { 0x0001,   "English" },
    { 0x0002,   "French" },
    { 0x0003,   "Spanish" },
    { 0x0004,   "Japanese" },
    { 0x0005,   "Korean" },
    { 0x0006,   "Chinese" },
    { 0x0007,   "Hebrew" },
    { 0x0008,   "Portuguese" },
    { 0x0009,   "Hindi" },
    { 0x000a,   "Turkish" },
    { 0x000b,   "Hungarian" },
    { 0x000c,   "Polish" },
    { 0x000d,   "Czech" },
    { 0x000e,   "Arabic" },
    { 0x000f,   "Russian" },
    { 0x0010,   "Icelandic" },
    { 0x0011,   "German" },
    { 0x0012,   "Italian" },
    { 0x0013,   "Dutch" },
    { 0x0014,   "Swedish" },
    { 0x0015,   "Danish" },
    { 0x0017,   "Finnish" },
    { 0x0018,   "Norwegian" },
    { 0x0019,   "Greek" },
    { 0x001a,   "Bengali" },
    { 0x001b,   "Gujarati" },
    { 0x001c,   "Kannada" },
    { 0x001d,   "Malayalam" },
    { 0x001e,   "Oriya" },
    { 0x001f,   "Punjabi" },
    { 0x0020,   "Tamil" },
    { 0x0021,   "Telugu" },
    { 0x0022,   "Urdu" },
    { 0x0023,   "Bahasa" },
    { 0x0024,   "Thai" },
    { 0x0025,   "Tagalog" },
    { 0x0026,   "Swahili" },
    { 0x0027,   "Afrikaans" },
    { 0x0028,   "Hausa" },
    { 0x0029,   "Vietnamese" },
    { 0, NULL }
};

value_string_ext ansi_tsb58_language_ind_vals_ext = VALUE_STRING_EXT_INIT(ansi_tsb58_language_ind_vals);

/* NOTE:  Table 160 of 3GPP2 N.S0005 may specify different values */

/*
 * 9.3 Service Category Assignments
 */
const value_string ansi_tsb58_srvc_cat_vals[] = {
    { 0x0000,   "Unknown or unspecified" },
    { 0x0001,   "Emergency Broadcasts" },
    { 0x0002,   "Administrative" },
    { 0x0003,   "Maintenance" },
    { 0x0004,   "General News - Local" },
    { 0x0005,   "General News - Regional" },
    { 0x0006,   "General News - National" },
    { 0x0007,   "General News - International" },
    { 0x0008,   "Business/Financial News - Local" },
    { 0x0009,   "Business/Financial News - Regional" },
    { 0x000A,   "Business/Financial News - National" },
    { 0x000B,   "Business/Financial News - International" },
    { 0x000C,   "Sports News - Local" },
    { 0x000D,   "Sports News - Regional" },
    { 0x000E,   "Sports News - National" },
    { 0x000F,   "Sports News - International" },
    { 0x0010,   "Entertainment News - Local" },
    { 0x0011,   "Entertainment News - Regional" },
    { 0x0012,   "Entertainment News - National" },
    { 0x0013,   "Entertainment News - International" },
    { 0x0014,   "Local Weather" },
    { 0x0015,   "Area Traffic Reports" },
    { 0x0016,   "Local Airport Flight Schedules" },
    { 0x0017,   "Restaurants" },
    { 0x0018,   "Lodgings" },
    { 0x0019,   "Retail Directory" },
    { 0x001A,   "Advertisements" },
    { 0x001B,   "Stock Quotes" },
    { 0x001C,   "Employment Opportunities" },
    { 0x001D,   "Medical/Health/Hospitals" },
    { 0x001E,   "Technology News" },
    { 0x001F,   "Multi-category" },
    { 0x0020,   "Card Application Toolkit Protocol Teleservice (CATPT)" },
    { 0x1000,   "Presidential-Level Alert" },
    { 0x1001,   "Extreme Threat to Life and Property" },
    { 0x1002,   "Severe Threat to Life and Property" },
    { 0x1003,   "AMBER (Child Abduction Emergency)" },
    { 0x1004,   "CMAS Test Message" },
    { 0, NULL }
};

value_string_ext ansi_tsb58_srvc_cat_vals_ext = VALUE_STRING_EXT_INIT(ansi_tsb58_srvc_cat_vals);

/*
 * END Not strictly A-interface info
 */


/* Initialize the protocol and registered fields */
static int proto_a_bsmap = -1;
static int proto_a_dtap = -1;

const ext_value_string_t *ansi_a_bsmap_strings = NULL;
const ext_value_string_t *ansi_a_dtap_strings = NULL;
const ext_value_string_t *ansi_a_elem_1_strings = NULL;

static int ansi_a_tap = -1;

static int hf_ansi_a_bsmap_msgtype = -1;
static int hf_ansi_a_dtap_msgtype = -1;
static int hf_ansi_a_protocol_disc = -1;
static int hf_ansi_a_reserved_octet = -1;
static int hf_ansi_a_ti_flag = -1;
static int hf_ansi_a_ti_ti = -1;
static int hf_ansi_a_cm_svrc_type = -1;
static int hf_ansi_a_elem_id = -1;
static int hf_ansi_a_elem_id_f0 = -1;
static int hf_ansi_a_length = -1;
static int hf_ansi_a_esn = -1;
static int hf_ansi_a_imsi = -1;
static int hf_ansi_a_meid = -1;
static int hf_ansi_a_cld_party_bcd_num = -1;
static int hf_ansi_a_cld_party_ascii_num = -1;
static int hf_ansi_a_clg_party_ascii_num = -1;
static int hf_ansi_a_cell_ci = -1;
static int hf_ansi_a_cell_lac = -1;
static int hf_ansi_a_cell_mscid = -1;
static int hf_ansi_a_pdsn_ip_addr = -1;
static int hf_ansi_a_s_pdsn_ip_addr = -1;
static int hf_ansi_a_anchor_ip_addr = -1;
static int hf_ansi_a_anchor_pp_ip_addr = -1;
static int hf_ansi_a_so = -1;
static int hf_ansi_a_cause_1 = -1;      /* 1 octet cause */
static int hf_ansi_a_cause_2 = -1;      /* 2 octet cause */
static int hf_ansi_a_ms_info_rec_signal_type = -1;
static int hf_ansi_a_ms_info_rec_signal_alert_pitch = -1;
static int hf_ansi_a_ms_info_rec_signal_tone = -1;
static int hf_ansi_a_ms_info_rec_signal_isdn_alert = -1;
static int hf_ansi_a_ms_info_rec_signal_is54b_alert = -1;
static int hf_ansi_a_ms_info_rec_call_waiting_ind = -1;
static int hf_ansi_a_extension_8_80 = -1;
static int hf_ansi_a_reserved_bits_8_generic = -1;
static int hf_ansi_a_reserved_bits_8_01 = -1;
static int hf_ansi_a_reserved_bits_8_07 = -1;
static int hf_ansi_a_reserved_bits_8_0c = -1;
static int hf_ansi_a_reserved_bits_8_0f = -1;
static int hf_ansi_a_reserved_bits_8_10 = -1;
static int hf_ansi_a_reserved_bits_8_18 = -1;
static int hf_ansi_a_reserved_bits_8_1c = -1;
static int hf_ansi_a_reserved_bits_8_1f = -1;
static int hf_ansi_a_reserved_bits_8_3f = -1;
static int hf_ansi_a_reserved_bits_8_7f = -1;
static int hf_ansi_a_reserved_bits_8_80 = -1;
static int hf_ansi_a_reserved_bits_8_c0 = -1;
static int hf_ansi_a_reserved_bits_8_e0 = -1;
static int hf_ansi_a_reserved_bits_8_f0 = -1;
static int hf_ansi_a_reserved_bits_8_f8 = -1;
static int hf_ansi_a_reserved_bits_8_fc = -1;
static int hf_ansi_a_reserved_bits_8_fe = -1;
static int hf_ansi_a_reserved_bits_8_ff = -1;
static int hf_ansi_a_reserved_bits_16_001f = -1;
static int hf_ansi_a_reserved_bits_16_003f = -1;
static int hf_ansi_a_reserved_bits_16_8000 = -1;
static int hf_ansi_a_reserved_bits_16_f800 = -1;
static int hf_ansi_a_reserved_bits_24_001800 = -1;
static int hf_ansi_a_reserved_bits_24_006000 = -1;
static int hf_ansi_a_reserved_bits_24_007000 = -1;
static int hf_ansi_a_speech_or_data_indicator = -1;
static int hf_ansi_a_channel_number = -1;
static int hf_ansi_a_IOS5_channel_number = -1;
static int hf_ansi_a_chan_rate_and_type = -1;
static int hf_ansi_a_speech_enc_or_data_rate = -1;
static int hf_ansi_a_chan_type_data_ext = -1;
static int hf_ansi_a_chan_type_data_transparent = -1;
static int hf_ansi_a_return_cause = -1;
static int hf_ansi_a_rf_chan_id_color_code = -1;
static int hf_ansi_a_rf_chan_id_n_amps_based = -1;
static int hf_ansi_a_rf_chan_id_amps_based = -1;
static int hf_ansi_a_rf_chan_id_timeslot = -1;
static int hf_ansi_a_rf_chan_id_channel_number = -1;
static int hf_ansi_a_sr_id = -1;
static int hf_ansi_a_sid = -1;
static int hf_ansi_a_is95_chan_id_hho = -1;
static int hf_ansi_a_is95_chan_id_num_chans_add = -1;
static int hf_ansi_a_is95_chan_id_frame_offset = -1;
static int hf_ansi_a_is95_chan_id_walsh_code_chan_idx = -1;
static int hf_ansi_a_is95_chan_id_pilot_pn = -1;
static int hf_ansi_a_is95_chan_id_power_combined = -1;
static int hf_ansi_a_is95_chan_id_freq_incl = -1;
static int hf_ansi_a_is95_chan_id_channel_number = -1;
static int hf_ansi_a_enc_info_enc_parm_id = -1;
static int hf_ansi_a_enc_info_status = -1;
static int hf_ansi_a_enc_info_available = -1;
static int hf_ansi_a_cm2_mob_p_rev = -1;
static int hf_ansi_a_cm2_see_list = -1;
static int hf_ansi_a_cm2_rf_power_cap = -1;
static int hf_ansi_a_cm2_nar_an_cap = -1;
static int hf_ansi_a_cm2_is95 = -1;
static int hf_ansi_a_cm2_slotted = -1;
static int hf_ansi_a_cm2_dtx = -1;
static int hf_ansi_a_cm2_mobile_term = -1;
static int hf_ansi_a_cm2_analog_cap = -1;
static int hf_ansi_a_cm2_psi = -1;
static int hf_ansi_a_cm2_scm_len = -1;
static int hf_ansi_a_cm2_scm = -1;
static int hf_ansi_a_cm2_scm_ext_scm_ind = -1;
static int hf_ansi_a_cm2_scm_dual_mode = -1;
static int hf_ansi_a_cm2_scm_slotted = -1;
static int hf_ansi_a_cm2_scm_meid_configured = -1;
static int hf_ansi_a_cm2_scm_25MHz_bandwidth = -1;
static int hf_ansi_a_cm2_scm_transmission = -1;
static int hf_ansi_a_cm2_scm_power_class = -1;
static int hf_ansi_a_cm2_scm_band_class_count = -1;
static int hf_ansi_a_cm2_scm_band_class_entry_len = -1;
static int hf_ansi_a_scm_band_class_entry_band_class = -1;
static int hf_ansi_a_scm_band_class_entry_opmode0_1 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode1_1 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode2_1 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode3_1 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode4_1 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode0_2 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode1_2 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode2_2 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode3_2 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode4_2 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode5_2 = -1;
static int hf_ansi_a_scm_band_class_entry_opmode6_2 = -1;
static int hf_ansi_a_scm_band_class_entry_p_rev = -1;
static int hf_ansi_a_meid_mid_digit_1 = -1;
static int hf_ansi_a_imsi_mid_digit_1 = -1;
static int hf_ansi_a_mid_odd_even_ind = -1;
static int hf_ansi_a_mid_type_of_id = -1;
static int hf_ansi_a_mid_broadcast_priority = -1;
static int hf_ansi_a_mid_broadcast_message_id = -1;
static int hf_ansi_a_mid_broadcast_zone_id = -1;
static int hf_ansi_a_mid_broadcast_srvc_cat = -1;
static int hf_ansi_a_mid_broadcast_language = -1;
static int hf_ansi_a_mid_unused = -1;
static int hf_ansi_a_sci_sign = -1;
static int hf_ansi_a_sci = -1;
static int hf_ansi_a_prio_call_priority = -1;
static int hf_ansi_a_prio_queue_allowed = -1;
static int hf_ansi_a_prio_preempt_allowed = -1;
static int hf_ansi_a_mob_p_rev = -1;
static int hf_ansi_a_cause_1_ext = -1;
static int hf_ansi_a_cause_2_ext = -1;
static int hf_ansi_a_cell_id_disc = -1;
static int hf_ansi_a_cic = -1;
static int hf_ansi_a_cic_pcm_multi = -1;
static int hf_ansi_a_cic_timeslot = -1;
static int hf_ansi_a_cic_ext_cic = -1;
static int hf_ansi_a_cic_ext_pcm_multi = -1;
static int hf_ansi_a_cic_ext_timeslot = -1;
static int hf_ansi_a_cic_ext_circuit_mode = -1;
static int hf_ansi_a_ssci_mopd = -1;
static int hf_ansi_a_ssci_geci = -1;
static int hf_ansi_a_downlink_re_num_cells = -1;
static int hf_ansi_a_downlink_re_sig_str_raw = -1;
static int hf_ansi_a_downlink_re_cdma_towd = -1;
static int hf_ansi_a_downlink_re_entry_env_len = -1;
static int hf_ansi_a_ho_pow_lev_num_cells = -1;
static int hf_ansi_a_ho_pow_lev_id_type = -1;
static int hf_ansi_a_ho_pow_lev_pow_lev = -1;
static int hf_ansi_a_uz_id = -1;
static int hf_ansi_a_info_rec_req = -1;
static int hf_ansi_a_is2000_chan_id_otd = -1;
static int hf_ansi_a_is2000_chan_id_chan_count = -1;
static int hf_ansi_a_is2000_chan_id_frame_offset = -1;
static int hf_ansi_a_is2000_chan_id_chan_chan_type = -1;
static int hf_ansi_a_is2000_chan_id_chan_rev_fch_gating = -1;
static int hf_ansi_a_is2000_chan_id_chan_rev_pilot_gating_rate = -1;
static int hf_ansi_a_is2000_chan_id_chan_qof_mask = -1;
static int hf_ansi_a_is2000_chan_id_chan_walsh_code_chan_idx = -1;
static int hf_ansi_a_is2000_chan_id_chan_pilot_pn_code = -1;
static int hf_ansi_a_is2000_chan_id_chan_power_combined = -1;
static int hf_ansi_a_is2000_chan_id_chan_freq_incl = -1;
static int hf_ansi_a_is2000_chan_id_chan_channel_number = -1;
static int hf_ansi_a_is2000_chan_id_chan_fdc_length = -1;
static int hf_ansi_a_is2000_chan_id_chan_fdc_band_class = -1;
static int hf_ansi_a_is2000_chan_id_chan_fdc_fwd_chan_freq = -1;
static int hf_ansi_a_is2000_chan_id_chan_fdc_rev_chan_freq = -1;
static int hf_ansi_a_is95_ms_meas_chan_id_band_class = -1;
static int hf_ansi_a_is95_ms_meas_chan_id_channel_number = -1;
static int hf_ansi_a_clg_party_ascii_num_ton = -1;
static int hf_ansi_a_clg_party_ascii_num_plan = -1;
static int hf_ansi_a_clg_party_ascii_num_pi = -1;
static int hf_ansi_a_clg_party_ascii_num_si = -1;
static int hf_ansi_a_lai_mcc = -1;
static int hf_ansi_a_lai_mnc = -1;
static int hf_ansi_a_lai_lac = -1;
static int hf_ansi_a_rej_cause = -1;
static int hf_ansi_a_auth_chlg_param_rand_num_type = -1;
static int hf_ansi_a_auth_chlg_param_rand = -1;
static int hf_ansi_a_auth_resp_param_sig_type = -1;
static int hf_ansi_a_auth_resp_param_sig = -1;
static int hf_ansi_a_auth_param_count_count = -1;
static int hf_ansi_a_mwi_num_messages = -1;
static int hf_ansi_a_signal_signal_value = -1;
static int hf_ansi_a_signal_alert_pitch = -1;
static int hf_ansi_a_clg_party_bcd_num_ton = -1;
static int hf_ansi_a_clg_party_bcd_num_plan = -1;
static int hf_ansi_a_qos_params_packet_priority = -1;
static int hf_ansi_a_cause_l3_coding_standard = -1;
static int hf_ansi_a_cause_l3_location = -1;
static int hf_ansi_a_cause_l3_class = -1;
static int hf_ansi_a_cause_l3_value_without_class = -1;
static int hf_ansi_a_cause_l3_value = -1;
static int hf_ansi_a_auth_conf_param_randc = -1;
static int hf_ansi_a_xmode_tfo_mode = -1;
static int hf_ansi_a_reg_type_type = -1;
static int hf_ansi_a_tag_value = -1;
static int hf_ansi_a_hho_params_band_class = -1;
static int hf_ansi_a_hho_params_num_pream_frames = -1;
static int hf_ansi_a_hho_params_reset_l2 = -1;
static int hf_ansi_a_hho_params_reset_fpc = -1;
static int hf_ansi_a_hho_params_enc_mode = -1;
static int hf_ansi_a_hho_params_private_lcm = -1;
static int hf_ansi_a_hho_params_rev_pwr_cntl_delay_incl = -1;
static int hf_ansi_a_hho_params_rev_pwr_cntl_delay = -1;
static int hf_ansi_a_hho_params_nom_pwr_ext = -1;
static int hf_ansi_a_hho_params_nom_pwr = -1;
static int hf_ansi_a_hho_params_fpc_subchan_info = -1;
static int hf_ansi_a_hho_params_fpc_subchan_info_incl = -1;
static int hf_ansi_a_hho_params_pwr_cntl_step = -1;
static int hf_ansi_a_hho_params_pwr_cntl_step_incl = -1;
static int hf_ansi_a_sw_ver_major = -1;
static int hf_ansi_a_sw_ver_minor = -1;
static int hf_ansi_a_sw_ver_point = -1;
static int hf_ansi_a_so_proprietary_ind = -1;
static int hf_ansi_a_so_revision = -1;
static int hf_ansi_a_so_base_so_num = -1;
static int hf_ansi_a_soci = -1;
static int hf_ansi_a_so_list_num = -1;
static int hf_ansi_a_so_list_sr_id = -1;
static int hf_ansi_a_so_list_soci = -1;
static int hf_ansi_a_nid = -1;
static int hf_ansi_a_pzid = -1;
static int hf_ansi_a_adds_user_part_burst_type = -1;
static int hf_ansi_a_adds_user_part_ext_burst_type = -1;
static int hf_ansi_a_adds_user_part_ext_data = -1;
static int hf_ansi_a_adds_user_part_unknown_data = -1;
static int hf_ansi_a_amps_hho_params_enc_mode = -1;
static int hf_ansi_a_is2000_scr_num_fill_bits = -1;
static int hf_ansi_a_is2000_scr_for_mux_option = -1;
static int hf_ansi_a_is2000_scr_rev_mux_option = -1;
static int hf_ansi_a_is2000_scr_for_fch_rate = -1;
static int hf_ansi_a_is2000_scr_rev_fch_rate = -1;
static int hf_ansi_a_is2000_scr_num_socr = -1;
static int hf_ansi_a_is2000_scr_socr_soc_ref = -1;
static int hf_ansi_a_is2000_scr_socr_so = -1;
static int hf_ansi_a_is2000_scr_socr_for_chan_type = -1;
static int hf_ansi_a_is2000_scr_socr_rev_chan_type = -1;
static int hf_ansi_a_is2000_scr_socr_ui_enc_mode = -1;
static int hf_ansi_a_is2000_scr_socr_sr_id = -1;
static int hf_ansi_a_is2000_scr_socr_rlp_info_incl = -1;
static int hf_ansi_a_is2000_scr_socr_rlp_blob_len = -1;
static int hf_ansi_a_is2000_scr_socr_rlp_blob_msb = -1;
static int hf_ansi_a_is2000_scr_socr_rlp_blob = -1;
static int hf_ansi_a_is2000_scr_socr_rlp_blob_lsb = -1;
static int hf_ansi_a_is2000_scr_socr_fch_cc_incl = -1;
static int hf_ansi_a_is2000_scr_socr_fch_frame_size_support_ind = -1;
static int hf_ansi_a_is2000_scr_socr_for_fch_rc = -1;
static int hf_ansi_a_is2000_scr_socr_rev_fch_rc = -1;
static int hf_ansi_a_is2000_nn_scr_num_fill_bits = -1;
static int hf_ansi_a_is2000_nn_scr_content = -1;
static int hf_ansi_a_is2000_nn_scr_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_rev_pdch_support_ind = -1;
static int hf_ansi_a_is2000_mob_cap_for_pdch_support_ind = -1;
static int hf_ansi_a_is2000_mob_cap_eram_support_ind = -1;
static int hf_ansi_a_is2000_mob_cap_dcch_support_ind = -1;
static int hf_ansi_a_is2000_mob_cap_fch_support_ind = -1;
static int hf_ansi_a_is2000_mob_cap_otd_support_ind = -1;
static int hf_ansi_a_is2000_mob_cap_enh_rc_cfg_support_ind = -1;
static int hf_ansi_a_is2000_mob_cap_qpch_support_ind = -1;
static int hf_ansi_a_is2000_mob_cap_fch_info_octet_len = -1;
static int hf_ansi_a_is2000_mob_cap_fch_info_geo_loc_type = -1;
static int hf_ansi_a_is2000_mob_cap_fch_info_geo_loc_incl = -1;
static int hf_ansi_a_is2000_mob_cap_fch_info_num_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_fch_info_content = -1;
static int hf_ansi_a_is2000_mob_cap_fch_info_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_dcch_info_octet_len = -1;
static int hf_ansi_a_is2000_mob_cap_dcch_info_num_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_dcch_info_content = -1;
static int hf_ansi_a_is2000_mob_cap_dcch_info_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_for_pdch_info_octet_len = -1;
static int hf_ansi_a_is2000_mob_cap_for_pdch_info_num_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_for_pdch_info_content = -1;
static int hf_ansi_a_is2000_mob_cap_for_pdch_info_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_rev_pdch_info_octet_len = -1;
static int hf_ansi_a_is2000_mob_cap_rev_pdch_info_num_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_rev_pdch_info_content = -1;
static int hf_ansi_a_is2000_mob_cap_rev_pdch_info_fill_bits = -1;
static int hf_ansi_a_is2000_mob_cap_vp_support = -1;
static int hf_ansi_a_is2000_mob_cap_vp_support_a7 = -1;
static int hf_ansi_a_is2000_mob_cap_vp_support_a6 = -1;
static int hf_ansi_a_is2000_mob_cap_vp_support_a5 = -1;
static int hf_ansi_a_is2000_mob_cap_vp_support_a4 = -1;
static int hf_ansi_a_is2000_mob_cap_vp_support_a3 = -1;
static int hf_ansi_a_is2000_mob_cap_vp_support_a2 = -1;
static int hf_ansi_a_is2000_mob_cap_vp_support_a1 = -1;
static int hf_ansi_a_protocol_type = -1;
static int hf_ansi_a_fwd_ms_info_rec_cld_pn_num_type = -1;
static int hf_ansi_a_fwd_ms_info_rec_cld_pn_num_plan = -1;
static int hf_ansi_a_fwd_ms_info_rec_cld_pn_num = -1;
static int hf_ansi_a_fwd_ms_info_rec_clg_pn_num_type = -1;
static int hf_ansi_a_fwd_ms_info_rec_clg_pn_num_plan = -1;
static int hf_ansi_a_fwd_ms_info_rec_clg_pn_num = -1;
static int hf_ansi_a_fwd_ms_info_rec_clg_pn_pi = -1;
static int hf_ansi_a_fwd_ms_info_rec_clg_pn_si = -1;
static int hf_ansi_a_fwd_ms_info_rec_mw_num = -1;
static int hf_ansi_a_fwd_ms_info_rec_content = -1;
static int hf_ansi_a_rev_ms_info_rec_cld_pn_num_type = -1;
static int hf_ansi_a_rev_ms_info_rec_cld_pn_num_plan = -1;
static int hf_ansi_a_rev_ms_info_rec_cld_pn_num = -1;
static int hf_ansi_a_rev_ms_info_rec_clg_pn_num_type = -1;
static int hf_ansi_a_rev_ms_info_rec_clg_pn_num_plan = -1;
static int hf_ansi_a_rev_ms_info_rec_clg_pn_num = -1;
static int hf_ansi_a_rev_ms_info_rec_clg_pn_pi = -1;
static int hf_ansi_a_rev_ms_info_rec_clg_pn_si = -1;
static int hf_ansi_a_rev_ms_info_rec_so_info_fwd_support = -1;
static int hf_ansi_a_rev_ms_info_rec_so_info_rev_support = -1;
static int hf_ansi_a_rev_ms_info_rec_so_info_so = -1;
static int hf_ansi_a_rev_ms_info_rec_content = -1;
static int hf_ansi_a_ext_ho_dir_params_srch_win_a = -1;
static int hf_ansi_a_ext_ho_dir_params_srch_win_n = -1;
static int hf_ansi_a_ext_ho_dir_params_srch_win_r = -1;
static int hf_ansi_a_ext_ho_dir_params_t_add = -1;
static int hf_ansi_a_ext_ho_dir_params_t_drop = -1;
static int hf_ansi_a_ext_ho_dir_params_t_comp = -1;
static int hf_ansi_a_ext_ho_dir_params_t_tdrop = -1;
static int hf_ansi_a_ext_ho_dir_params_nghbor_max_age = -1;
static int hf_ansi_a_ext_ho_dir_params_target_bs_values_incl = -1;
static int hf_ansi_a_ext_ho_dir_params_soft_slope = -1;
static int hf_ansi_a_ext_ho_dir_params_add_intercept = -1;
static int hf_ansi_a_ext_ho_dir_params_drop_intercept = -1;
static int hf_ansi_a_ext_ho_dir_params_target_bs_p_rev = -1;
static int hf_ansi_a_cdma_sowd_sowd = -1;
static int hf_ansi_a_cdma_sowd_resolution = -1;
static int hf_ansi_a_cdma_sowd_timestamp = -1;
static int hf_ansi_a_re_res_prio_incl = -1;
static int hf_ansi_a_re_res_forward = -1;
static int hf_ansi_a_re_res_reverse = -1;
static int hf_ansi_a_re_res_alloc = -1;
static int hf_ansi_a_re_res_avail = -1;
static int hf_ansi_a_cld_party_ascii_num_ton = -1;
static int hf_ansi_a_cld_party_ascii_num_plan = -1;
static int hf_ansi_a_band_class = -1;
static int hf_ansi_a_is2000_cause = -1;
static int hf_ansi_a_auth_event = -1;
static int hf_ansi_a_psmm_count = -1;
static int hf_ansi_a_geo_loc = -1;
static int hf_ansi_a_cct_group_all_circuits = -1;
static int hf_ansi_a_cct_group_inclusive = -1;
static int hf_ansi_a_cct_group_count = -1;
static int hf_ansi_a_cct_group_first_cic = -1;
static int hf_ansi_a_cct_group_first_cic_pcm_multi = -1;
static int hf_ansi_a_cct_group_first_cic_timeslot = -1;
static int hf_ansi_a_paca_timestamp_queuing_time = -1;
static int hf_ansi_a_paca_order_action_reqd = -1;
static int hf_ansi_a_paca_reoi_pri = -1;
static int hf_ansi_a_a2p_bearer_sess_max_frames = -1;
static int hf_ansi_a_a2p_bearer_sess_ip_addr_type = -1;
static int hf_ansi_a_a2p_bearer_sess_addr_flag = -1;
static int hf_ansi_a_a2p_bearer_sess_ipv4_addr = -1;
static int hf_ansi_a_a2p_bearer_sess_ipv6_addr = -1;
static int hf_ansi_a_a2p_bearer_sess_udp_port = -1;
static int hf_ansi_a_a2p_bearer_form_num_formats = -1;
static int hf_ansi_a_a2p_bearer_form_ip_addr_type = -1;
static int hf_ansi_a_a2p_bearer_form_format_len = -1;
static int hf_ansi_a_a2p_bearer_form_format_tag_type = -1;
static int hf_ansi_a_a2p_bearer_form_format_format_id = -1;
static int hf_ansi_a_a2p_bearer_form_format_rtp_payload_type = -1;
static int hf_ansi_a_a2p_bearer_form_format_bearer_addr_flag = -1;
static int hf_ansi_a_a2p_bearer_form_format_ipv4_addr = -1;
static int hf_ansi_a_a2p_bearer_form_format_ipv6_addr = -1;
static int hf_ansi_a_a2p_bearer_form_format_udp_port = -1;
static int hf_ansi_a_a2p_bearer_form_format_ext_len = -1;
static int hf_ansi_a_a2p_bearer_form_format_ext_id = -1;
static int hf_ansi_a_ms_des_freq_band_class = -1;
static int hf_ansi_a_ms_des_freq_cdma_channel = -1;
static int hf_ansi_a_plcm_id_plcm_type = -1;
static int hf_ansi_a_bdtmf_trans_info_dtmf_off_len = -1;
static int hf_ansi_a_bdtmf_trans_info_dtmf_on_len = -1;
static int hf_ansi_a_bdtmf_chars_num_chars = -1;
static int hf_ansi_a_bdtmf_chars_digits = -1;
static int hf_ansi_a_encryption_parameter_value = -1;
static int hf_ansi_a_layer3_info = -1;
static int hf_ansi_a_manufacturer_software_info = -1;
static int hf_ansi_a_circuit_bitmap = -1;
static int hf_ansi_a_extension_parameter_value = -1;
static int hf_ansi_a_msb_first_digit = -1;
static int hf_ansi_a_dcch_cc_incl = -1;
static int hf_ansi_a_for_sch_cc_incl = -1;
static int hf_ansi_a_rev_sch_cc_incl = -1;
static int hf_ansi_a_plcm42 = -1;


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
static gint ett_scr_socr = -1;
static gint ett_cm2_band_class = -1;
static gint ett_vp_algs = -1;
static gint ett_chan_list = -1;
static gint ett_cic = -1;
static gint ett_is2000_mob_cap_fch_info = -1;
static gint ett_is2000_mob_cap_dcch_info = -1;
static gint ett_is2000_mob_cap_for_pdch_info = -1;
static gint ett_is2000_mob_cap_rev_pdch_info = -1;

static expert_field ei_ansi_a_extraneous_data = EI_INIT;
static expert_field ei_ansi_a_short_data = EI_INIT;
static expert_field ei_ansi_a_missing_mand_elem = EI_INIT;
static expert_field ei_ansi_a_unknown_format = EI_INIT;
static expert_field ei_ansi_a_no_tlv_elem_diss = EI_INIT;
static expert_field ei_ansi_a_no_tv_elem_diss = EI_INIT;
static expert_field ei_ansi_a_no_lv_elem_diss = EI_INIT;
static expert_field ei_ansi_a_no_v_elem_diss = EI_INIT;
static expert_field ei_ansi_a_miss_dtap_msg_diss = EI_INIT;
static expert_field ei_ansi_a_miss_bsmap_msg_diss = EI_INIT;
static expert_field ei_ansi_a_is2000_chan_id_pilot_pn = EI_INIT;
static expert_field ei_ansi_a_unknown_dtap_msg = EI_INIT;
static expert_field ei_ansi_a_unknown_bsmap_msg = EI_INIT;
static expert_field ei_ansi_a_undecoded = EI_INIT;

static dissector_handle_t dtap_handle;
static dissector_table_t is637_dissector_table; /* IS-637-A Transport Layer (SMS) */
static dissector_table_t is683_dissector_table; /* IS-683-A (OTA) */
static dissector_table_t is801_dissector_table; /* IS-801 (PLD) */

typedef struct ansi_a_shared_data_t
{
    /*
     * top level tree
     */
    proto_tree          *g_tree;

    /*
     * item pointer for BSMAP or DTAP message
     * (may be NULL in the case that the IS41 MAP dissector called dissect_cdma2000_a1_elements())
     */
    proto_item          *message_item;
    proto_item          *elem_item;

    /*
     * message direction
     *  TRUE means from the BSC to MSC
     */
    gboolean            is_reverse;

    /*
     * IOS message was carried in SIP
     */
    gboolean            from_sip;

    address             rtp_src_addr;
    guint32             rtp_ipv4_addr;
    ws_in6_addr   rtp_ipv6_addr;
    guint16             rtp_port;

    gboolean            meid_configured;
}
ansi_a_shared_data_t;

/*
 * As per A.S0001 Called Party BCD Number
 */
static dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '0','1','2','3','4','5','6','7','8','9','*','#','a','b','c', 0
    }
};

static dgt_set_t Dgt_msid = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?', 0
    }
};

static dgt_set_t Dgt_meid = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    }
};

/*
 * As per C.S0005 Table 2.7.1.3.2.4-4 and IS-634.400A 6.2.2.57
 */
static dgt_set_t Dgt_dtmf = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '?','1','2','3','4','5','6','7','8','9','0','*','#','?','?', 0
    }
};

/* FUNCTIONS */

static const value_string ansi_a_so_str_vals[] = {
    { 1,        "Basic Variable Rate Voice Service (8 kbps)" },
    { 2,        "Mobile Station Loopback (8 kbps)" },
    { 3,        "(EVRC) Enhanced Variable Rate Voice Service (8 kbps)" },
    { 4,        "Asynchronous Data Service (9.6 kbps)" },
    { 5,        "Group 3 Facsimile (9.6 kbps)" },
    { 6,        "Short Message Services (Rate Set 1)" },
    { 7,        "Packet Data Service: Internet or ISO Protocol Stack (9.6 kbps)" },
    { 8,        "Packet Data Service: CDPD Protocol Stack (9.6 kbps)" },
    { 9,        "Mobile Station Loopback (13 kbps)" },
    { 10,       "STU-III Transparent Service" },
    { 11,       "STU-III Non-Transparent Service" },
    { 12,       "Asynchronous Data Service (14.4 or 9.6 kbps)" },
    { 13,       "Group 3 Facsimile (14.4 or 9.6 kbps)" },
    { 14,       "Short Message Services (Rate Set 2)" },
    { 15,       "Packet Data Service: Internet or ISO Protocol Stack (14.4 kbps)" },
    { 16,       "Packet Data Service: CDPD Protocol Stack (14.4 kbps)" },
    { 17,       "High Rate Voice Service (13 kbps)" },
    { 18,       "Over-the-Air Parameter Administration (Rate Set 1)" },
    { 19,       "Over-the-Air Parameter Administration (Rate Set 2)" },
    { 20,       "Group 3 Analog Facsimile (Rate Set 1)" },
    { 21,       "Group 3 Analog Facsimile (Rate Set 2)" },
    { 22,       "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS1 forward, RS1 reverse)" },
    { 23,       "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS1 forward, RS2 reverse)" },
    { 24,       "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS2 forward, RS1 reverse)" },
    { 25,       "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS2 forward, RS2 reverse)" },
    { 26,       "High Speed Packet Data Service: CDPD Protocol Stack (RS1 forward, RS1 reverse)" },
    { 27,       "High Speed Packet Data Service: CDPD Protocol Stack (RS1 forward, RS2 reverse)" },
    { 28,       "High Speed Packet Data Service: CDPD Protocol Stack (RS2 forward, RS1 reverse)" },
    { 29,       "High Speed Packet Data Service: CDPD Protocol Stack (RS2 forward, RS2 reverse)" },
    { 30,       "Supplemental Channel Loopback Test for Rate Set 1" },
    { 31,       "Supplemental Channel Loopback Test for Rate Set 2" },
    { 32,       "Test Data Service Option (TDSO)" },
    { 33,       "cdma2000 High Speed Packet Data Service, Internet or ISO Protocol Stack" },
    { 34,       "cdma2000 High Speed Packet Data Service, CDPD Protocol Stack" },
    { 35,       "Location Services (PDS), Rate Set 1 (9.6 kbps)" },
    { 36,       "Location Services (PDS), Rate Set 2 (14.4 kbps)" },
    { 37,       "ISDN Interworking Service (64 kbps)" },
    { 38,       "GSM Voice" },
    { 39,       "GSM Circuit Data" },
    { 40,       "GSM Packet Data" },
    { 41,       "GSM Short Message Service" },
    { 42,       "None Reserved for MC-MAP standard service options" },
    { 54,       "Markov Service Option (MSO)" },
    { 55,       "Loopback Service Option (LSO)" },
    { 56,       "Selectable Mode Vocoder" },
    { 57,       "32 kbps Circuit Video Conferencing" },
    { 58,       "64 kbps Circuit Video Conferencing" },
    { 59,       "HRPD Accounting Records Identifier" },
    { 60,       "Link Layer Assisted Robust Header Compression (LLA ROHC) - Header Removal" },
    { 61,       "Link Layer Assisted Robust Header Compression (LLA ROHC) - Header Compression" },
    { 62,       "- 4099 None Reserved for standard service options" },
    { 68,       "(EVRC-B NB) Enhanced Variable Rate Voice Service" },
    { 70,       "(EVRC-B WB) Enhanced Variable Rate Voice Service" },
    { 73,       "(EVRC-NW) Enhanced Variable Rate Voice Service" },
    { 74,       "Flexible Markov Service Option" },
    { 75,       "Enhanced Loopback Service Option" },
    { 76,       "Tunneled forward link SMS based on Application Data Delivery Service trigger support in E-UTRAN - 1x Interworking" },
    { 77,       "(EVRC-NW2k) EVRC-NW including a 2kbps maximum mode" },
    { 78,       "Unstructured Supplementary Service Data, Rate Set 1 (9.6 kbps)" },
    { 79,       "Unstructured Supplementary Service Data, Rate Set 2 (14.4 kbps)" },
    { 4100,     "Asynchronous Data Service, Revision 1 (9.6 or 14.4 kbps)" },
    { 4101,     "Group 3 Facsimile, Revision 1 (9.6 or 14.4 kbps)" },
    { 4102,     "Reserved for standard service option" },
    { 4103,     "Packet Data Service: Internet or ISO Protocol Stack, Revision 1 (9.6 or 14.4 kbps)" },
    { 4104,     "Packet Data Service: CDPD Protocol Stack, Revision 1 (9.6 or 14.4 kbps)" },
    { 4169,     "EVRC-NW with capacity operating point 0 support over the A1 interface" },
    { 32760,    "Identifies service reference identifier 0" },
    { 32761,    "Identifies service reference identifier 1" },
    { 32762,    "Identifies service reference identifier 2" },
    { 32763,    "Identifies service reference identifier 3" },
    { 32764,    "Identifies service reference identifier 4" },
    { 32765,    "Identifies service reference identifier 5" },
    { 32766,    "Identifies service reference identifier 6" },
    { 32767,    "Identifies service reference identifier 7" },
    { 32768,    "QCELP (13 kbps)" },
    { 32769,    "Proprietary QUALCOMM Incorporated" },
    { 32770,    "Proprietary QUALCOMM Incorporated" },
    { 32771,    "Proprietary QUALCOMM Incorporated" },
    { 32772,    "Proprietary OKI Telecom" },
    { 32773,    "Proprietary OKI Telecom" },
    { 32774,    "Proprietary OKI Telecom" },
    { 32775,    "Proprietary OKI Telecom" },
    { 32776,    "Proprietary Lucent Technologies" },
    { 32777,    "Proprietary Lucent Technologies" },
    { 32778,    "Proprietary Lucent Technologies" },
    { 32779,    "Proprietary Lucent Technologies" },
    { 32780,    "Nokia" },
    { 32781,    "Nokia" },
    { 32782,    "Nokia" },
    { 32783,    "Nokia" },
    { 32784,    "NORTEL NETWORKS" },
    { 32785,    "NORTEL NETWORKS" },
    { 32786,    "NORTEL NETWORKS" },
    { 32787,    "NORTEL NETWORKS" },
    { 32788,    "Sony Electronics Inc." },
    { 32789,    "Sony Electronics Inc." },
    { 32790,    "Sony Electronics Inc." },
    { 32791,    "Sony Electronics Inc." },
    { 32792,    "Motorola" },
    { 32793,    "Motorola" },
    { 32794,    "Motorola" },
    { 32795,    "Motorola" },
    { 32796,    "QUALCOMM Incorporated" },
    { 32797,    "QUALCOMM Incorporated" },
    { 32798,    "Qualcomm Loopback" },
    { 32799,    "Qualcomm Markov 8 kbps Loopback" },
    { 32800,    "Qualcomm Packet Data" },
    { 32801,    "Qualcomm Async Data" },
    { 32802,    "QUALCOMM Incorporated" },
    { 32803,    "QUALCOMM Incorporated" },
    { 32804,    "QUALCOMM Incorporated" },
    { 32805,    "QUALCOMM Incorporated" },
    { 32806,    "QUALCOMM Incorporated" },
    { 32807,    "QUALCOMM Incorporated" },
    { 32808,    "QUALCOMM Incorporated" },
    { 32809,    "QUALCOMM Incorporated" },
    { 32810,    "QUALCOMM Incorporated" },
    { 32811,    "QUALCOMM Incorporated" },
    { 32812,    "Lucent Technologies" },
    { 32813,    "Lucent Technologies" },
    { 32814,    "Lucent Technologies" },
    { 32815,    "Lucent Technologies" },
    { 32816,    "Denso International" },
    { 32817,    "Denso International" },
    { 32818,    "Denso International" },
    { 32819,    "Denso International" },
    { 32820,    "Motorola" },
    { 32821,    "Motorola" },
    { 32822,    "Motorola" },
    { 32823,    "Motorola" },
    { 32824,    "Denso International" },
    { 32825,    "Denso International" },
    { 32826,    "Denso International" },
    { 32827,    "Denso International" },
    { 32828,    "Denso International" },
    { 32829,    "Denso International" },
    { 32830,    "Denso International" },
    { 32831,    "Denso International" },
    { 32832,    "Denso International" },
    { 32833,    "Denso International" },
    { 32834,    "Denso International" },
    { 32835,    "Denso International" },
    { 32836,    "NEC America" },
    { 32837,    "NEC America" },
    { 32838,    "NEC America" },
    { 32839,    "NEC America" },
    { 32840,    "Samsung Electronics" },
    { 32841,    "Samsung Electronics" },
    { 32842,    "Samsung Electronics" },
    { 32843,    "Samsung Electronics" },
    { 32844,    "Texas Instruments Incorporated" },
    { 32845,    "Texas Instruments Incorporated" },
    { 32846,    "Texas Instruments Incorporated" },
    { 32847,    "Texas Instruments Incorporated" },
    { 32848,    "Toshiba Corporation" },
    { 32849,    "Toshiba Corporation" },
    { 32850,    "Toshiba Corporation" },
    { 32851,    "Toshiba Corporation" },
    { 32852,    "LG Electronics Inc." },
    { 32853,    "LG Electronics Inc." },
    { 32854,    "LG Electronics Inc." },
    { 32855,    "LG Electronics Inc." },
    { 32856,    "VIA Telecom Inc." },
    { 32857,    "VIA Telecom Inc." },
    { 32858,    "VIA Telecom Inc." },
    { 32859,    "VIA Telecom Inc." },
    { 32860,    "Verizon Wireless" },
    { 32861,    "Verizon Wireless" },
    { 32862,    "Verizon Wireless" },
    { 32863,    "Verizon Wireless" },
    { 32864,    "Huawei Technologies" },
    { 32865,    "Huawei Technologies" },
    { 32866,    "Huawei Technologies" },
    { 32867,    "Huawei Technologies" },
    { 32868,    "QUALCOMM Incorporated" },
    { 32869,    "QUALCOMM Incorporated" },
    { 32870,    "QUALCOMM Incorporated" },
    { 32871,    "QUALCOMM Incorporated" },
    { 32872,    "ZTE Corporation" },
    { 32873,    "ZTE Corporation" },
    { 32874,    "ZTE Corporation" },
    { 32875,    "ZTE Corporation" },
    { 32876,    "China Telecom" },
    { 32877,    "China Telecom" },
    { 32878,    "China Telecom" },
    { 32879,    "China Telecom" },
    { 0, NULL }
};

static value_string_ext ansi_a_so_str_vals_ext = VALUE_STRING_EXT_INIT(ansi_a_so_str_vals);

static const gchar *ansi_a_so_int_to_str(gint32 so)
{
    const gchar *str = try_val_to_str_ext(so, &ansi_a_so_str_vals_ext);

    if (str == NULL)
    {
        if ((so >= 4105) && (so <= 32767))
        {
            str = "Reserved for standard service options";
        }
        else
        {
            str = "Reserved";
        }
    }

    return(str);
}

static void
content_fill_aux(
    tvbuff_t            *tvb,
    proto_tree          *tree,
    guint32             offset,
    guint8              content_len,
    guint8              fill_bits,
    int                 hf_content,
    int                 hf_content_fill_bits)
{
    proto_tree_add_item(tree, hf_content, tvb, offset, content_len, ENC_NA);

    offset += content_len;

    if (fill_bits)
    {
        proto_tree_add_bits_item(tree, hf_content_fill_bits, tvb, (offset - 1)*8, fill_bits-1, ENC_NA);
    }
}


/* ELEMENT FUNCTIONS */

#define EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_ansi_a_extraneous_data, \
            tvb, curr_offset, (edc_len) - (edc_max_len)); \
        curr_offset += ((edc_len) - (edc_max_len)); \
    }

#define SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_ansi_a_short_data, \
            tvb, curr_offset, (sdc_len)); \
        curr_offset += (sdc_len); \
        return(curr_offset - offset); \
    }

#define NO_MORE_DATA_CHECK(nmdc_len) \
    if ((nmdc_len) <= (curr_offset - offset)) return(nmdc_len);


/*
 * IOS 6.2.2.6
 */
static guint8
elem_chan_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        proto_tree_add_item(tree, hf_ansi_a_channel_number, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

        proto_item_append_text(data_p->elem_item, " - (%u)", value);
        break;

    case A_VARIANT_IOS501:
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_16_f800, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_IOS5_channel_number, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

        proto_item_append_text(data_p->elem_item, " - (ARFCN: %u)", value & 0x07ff);
        break;
    }

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.7
 */

static const value_string ansi_a_speech_or_data_indicator_vals[] = {
    { 0x0,      "No Alert" },
    { 0x1,      "Speech" },
    { 0x2,      "Data" },
    { 0x3,      "Signaling" },
    { 0, NULL }
};

static const value_string ansi_a_channel_rate_and_type_vals[] = {
    { 0x00,     "Reserved (invalid)" },
    { 0x01,     "DCCH" },
    { 0x02,     "Reserved for future use (invalid)" },
    { 0x08,     "Full rate TCH channel Bm" },
    { 0x09,     "Half rate TCH channel Lm" },
    { 0, NULL }
};

static const value_string ansi_a_speech_enc_or_data_rate_vals[] = {
    { 0x00,     "No Resources Required (invalid)" },
    { 0x01,     "Reserved" },
    { 0x02,     "Reserved" },
    { 0x03,     "TIA/EIA-IS-2000 8 kb/s vocoder" },
    { 0x04,     "8 kb/s enhanced vocoder (EVRC)" },
    { 0x05,     "13 kb/s vocoder" },
    { 0x06,     "Adaptive Differential PCM" },
    { 0, NULL }
};

static guint8
elem_chan_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_speech_or_data_indicator, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%s)",
        val_to_str_const(oct, ansi_a_speech_or_data_indicator_vals, "Unknown"));

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_chan_rate_and_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (oct == 0x02)
    {
        proto_tree_add_item(tree, hf_ansi_a_chan_type_data_ext, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_chan_type_data_transparent, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_3f, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    }
    else
    {
        proto_tree_add_item(tree, hf_ansi_a_speech_enc_or_data_rate, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    }

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.83
 */

static const value_string ansi_a_return_cause_vals[] = {
    { 0x00,     "Normal access" },
    { 0x01,     "Service redirection failed as a result of system not found" },
    { 0x02,     "Service redirection failed as a result of protocol mismatch" },
    { 0x03,     "Service redirection failed as a result of registration rejection" },
    { 0x04,     "Service redirection failed as a result of wrong SID" },
    { 0x05,     "Service redirection failed as a result of wrong NID" },
    { 0, NULL }
};

static guint8
elem_return_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_return_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.8
 */

static const value_string ansi_a_rf_chan_id_timeslot_number_vals[] = {
    { 0x00,     "Centered on N" },
    { 0x01,     "Channel below N" },
    { 0x02,     "Channel above N" },
    { 0x03,     "Reserved" },
    { 0, NULL }
};

static guint8
elem_rf_chan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_rf_chan_id_color_code, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_rf_chan_id_n_amps_based, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_rf_chan_id_amps_based, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_rf_chan_id_timeslot, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_16_f800, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_rf_chan_id_channel_number, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (ARFCN: %u)", value & 0x07ff);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.86
 */
static guint8
elem_sr_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_sr_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u)", oct);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.9
 */
static guint8
elem_sid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_16_8000, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_sid, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (SID: %u)", value & 0x7fff);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.10
 */
static guint8
elem_is95_chan_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint8      num_chans;
    guint8      chan_num;
    guint32     value;
    guint32     curr_offset;
    proto_tree  *subtree;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_is95_chan_id_hho, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is95_chan_id_num_chans_add, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format_value(tree, hf_ansi_a_is95_chan_id_frame_offset, tvb, curr_offset, 1,
        oct, "%u (%.2f ms)", oct & 0x0f, (oct & 0x0f) * 1.25);

    num_chans = (oct & 0x70) >> 4;

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (num_chans > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), 4);

        chan_num = 0;
        do
        {
            subtree =
                proto_tree_add_subtree_format(tree, tvb, curr_offset, 4,
                    ett_chan_list, NULL, "Channel [%u]", chan_num + 1);

            proto_tree_add_item(subtree, hf_ansi_a_is95_chan_id_walsh_code_chan_idx, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

            curr_offset += 1;

            proto_tree_add_item(subtree, hf_ansi_a_is95_chan_id_pilot_pn, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_ansi_a_is95_chan_id_power_combined, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_ansi_a_is95_chan_id_freq_incl, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_24_001800, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_ansi_a_is95_chan_id_channel_number, tvb, curr_offset, 3, ENC_BIG_ENDIAN);

            /*
             * only use the first channel number
             */
            if (chan_num == 0)
            {
                value = tvb_get_ntohs(tvb, curr_offset + 1);

                proto_item_append_text(data_p->elem_item, " - (ARFCN: %u)", value & 0x07ff);
            }

            curr_offset += 3;

            chan_num++;
        }
        while (((len - (curr_offset - offset)) >= 4) &&
            (chan_num < num_chans));
    }

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

static const value_string ansi_a_enc_info_ident_vals[] = {
    { 0x00,     "Not Used - Invalid value" },
    { 0x01,     "SME Key: Signaling Message Encryption Key" },
    { 0x02,     "Reserved (VPM: Voice Privacy Mask)" },
    { 0x03,     "Reserved" },
    { 0x04,     "Private Longcode" },
    { 0x05,     "Data Key (ORYX)" },
    { 0x06,     "Initial RAND" },
    { 0, NULL }
};

static const value_string ansi_a_enc_info_status_vals[] = {
    { 0x00,     "Active" },
    { 0x01,     "Inactive" },
    { 0, NULL }
};

static const value_string ansi_a_enc_info_available_vals[] = {
    { 0x00,     "Available" },
    { 0x01,     "Not available" },
    { 0, NULL }
};

static guint8
elem_enc_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset, saved_offset;
    guint8      num_recs;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    num_recs = 0;

    while ((len - (curr_offset - offset)) >= 2)
    {
        saved_offset = curr_offset;

        oct = tvb_get_guint8(tvb, curr_offset);

        subtree =
            proto_tree_add_subtree_format(tree,
                tvb, curr_offset, -1, ett_ansi_enc_info, &item,
                "Encryption Info [%u]: %s (%u)",
                num_recs + 1,
                val_to_str_const((oct & 0x7c) >> 2, ansi_a_enc_info_ident_vals, "Reserved"),
                (oct & 0x7c) >> 2);

        proto_tree_add_item(subtree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_enc_info_enc_parm_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_enc_info_status, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_enc_info_available, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;

        if (oct & 0x80)
        {
            oct = tvb_get_guint8(tvb, curr_offset);

            proto_tree_add_uint(subtree, hf_ansi_a_length, tvb,
                curr_offset, 1, oct);

            curr_offset++;

            if (oct > 0)
            {
                SHORT_DATA_CHECK(len - (curr_offset - offset), oct);

                proto_tree_add_item(subtree, hf_ansi_a_encryption_parameter_value, tvb, curr_offset, oct, ENC_NA);

                curr_offset += oct;
            }
        }

        proto_item_set_len(item, curr_offset - saved_offset);

        num_recs++;
    }

    proto_item_append_text(data_p->elem_item, " - %u record%s", num_recs, plurality(num_recs, "", "s"));

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
 *
 * IOS 5 4.2.12
 */

static const value_string ansi_a_cm2_rf_power_cap_vals[] = {
    { 0x00,     "Class 1, vehicle and portable" },
    { 0x01,     "Class 2, portable" },
    { 0x02,     "Class 3, handheld" },
    { 0x03,     "Class 4, handheld" },
    { 0x04,     "Class 5, handheld" },
    { 0x05,     "Class 6, handheld" },
    { 0x06,     "Class 7, handheld" },
    { 0x07,     "Class 8, handheld" },
    { 0, NULL }
};

static const value_string ansi_a_cm2_scm_ext_scm_ind_vals[] = {
    { 0x00,     "Band Classes 1, 4, 14" },
    { 0x01,     "Other bands" },
    { 0, NULL }
};

static const value_string ansi_a_cm2_scm_dual_mode_vals[] = {
    { 0x00,     "CDMA Only (Always)" },
    { 0x01,     "Dual Mode (invalid)" },
    { 0, NULL }
};

static const value_string ansi_a_cm2_scm_slotted_class_vals[] = {
    { 0x00,     "Non-Slotted" },
    { 0x01,     "Slotted" },
    { 0, NULL }
};

static const value_string ansi_a_cm2_scm_meid_configured_vals[] = {
    { 0x00,     "MEID not configured" },
    { 0x01,     "MEID configured" },
    { 0, NULL }
};

static const value_string ansi_a_cm2_scm_transmission_vals[] = {
    { 0x00,     "Continuous" },
    { 0x01,     "Discontinuous" },
    { 0, NULL }
};

static const value_string ansi_a_cm2_scm_power_class_vals[] = {
    { 0x00,     "Class I" },
    { 0x01,     "Class II" },
    { 0x02,     "Class III" },
    { 0x03,     "Reserved" },
    { 0, NULL }
};

static guint8
elem_cm_info_type_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint8      num_bands, band_class_count, band_class_entry_len, p_rev;
    guint32     curr_offset;
    gint        band_class;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_cm2_mob_p_rev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_10, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_see_list, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_rf_power_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - P_REV (%u)", (oct & 0xe0) >> 5);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_ff, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_cm2_nar_an_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_is95, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_slotted, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_18, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_dtx, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_mobile_term, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_analog_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_ff, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_mobile_term, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cm2_psi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_cm2_scm_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    item =
        proto_tree_add_item(tree, hf_ansi_a_cm2_scm, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    /*
     * following SCM decode is from:
     *  3GPP2 C.S0005-0 section 2.3.3
     *  3GPP2 C.S0072-0 section 2.1.2
     */
    subtree = proto_item_add_subtree(item, ett_scm);

    proto_tree_add_item(subtree, hf_ansi_a_cm2_scm_ext_scm_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cm2_scm_dual_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cm2_scm_slotted, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cm2_scm_meid_configured, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cm2_scm_25MHz_bandwidth, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cm2_scm_transmission, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cm2_scm_power_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct & 0x10)
    {
        proto_item_append_text(data_p->elem_item, " (MEID configured)");
        data_p->meid_configured = TRUE;
    }

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_cm2_scm_band_class_count, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    band_class_count = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_cm2_scm_band_class_entry_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    band_class_entry_len = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (band_class_entry_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), band_class_entry_len);

        num_bands = 0;
        do
        {
            subtree =
                proto_tree_add_subtree_format(tree, tvb, curr_offset, band_class_entry_len,
                    ett_cm2_band_class, NULL, "Band Class Entry [%u]", num_bands + 1);

            proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_e0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_band_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

            oct = tvb_get_guint8(tvb, curr_offset);

            band_class = oct & 0x1f;

            curr_offset++;

            p_rev = tvb_get_guint8(tvb, curr_offset + 1);

            if (p_rev < 4)
            {
                /*
                 * As per C.S0005 Table 2.7.4.15-1
                 */
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode0_1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode1_1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode2_1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode3_1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode4_1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_07, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            }
            else
            {
                /*
                 * As per C.S0005 Table 2.7.4.15-2
                 */
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode0_2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode1_2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode2_2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode3_2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode4_2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode5_2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_opmode6_2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_01, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            }

            curr_offset++;

            proto_tree_add_item(subtree, hf_ansi_a_scm_band_class_entry_p_rev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

            curr_offset++;

            proto_item_append_text(item, ": (%d)", band_class);

            num_bands++;
        }
        while (((len - (curr_offset - offset)) >= band_class_entry_len) &&
            (num_bands < band_class_count));
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.16
 *
 * IOS 5 4.2.13
 */

static const value_string ansi_a_mid_odd_even_ind_vals[] = {
    { 0x00,     "Even" },
    { 0x01,     "Odd" },
    { 0, NULL }
};

static const value_string ansi_a_mid_type_vals[] = {
    { 0x01,     "MEID" },
    { 0x02,     "Broadcast Address" },
    { 0x05,     "ESN" },
    { 0x06,     "IMSI" },
    { 0, NULL }
};

static const value_string ansi_a_mid_broadcast_priority_vals[] = {
    { 0x00,     "Normal" },
    { 0x01,     "Interactive" },
    { 0x02,     "Urgent" },
    { 0x03,     "Emergency" },
    { 0, NULL }
};

static guint8
elem_mid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct & 0x07)
    {
    case 1:     /* MEID */
        proto_tree_add_item(tree, hf_ansi_a_meid_mid_digit_1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_mid_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_mid_type_of_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        if (curr_offset - offset >= len) /* Sanity check */
            return (curr_offset - offset);

        str = tvb_bcd_dig_to_str(pinfo->pool, tvb, curr_offset, len - (curr_offset - offset), &Dgt_meid, TRUE);
        proto_tree_add_string(tree, hf_ansi_a_meid, tvb, curr_offset, len - (curr_offset - offset), str);

        proto_item_append_text(data_p->elem_item, " - MEID (%s)", str);
        curr_offset += len - (curr_offset - offset);
        break;

    case 2:     /* Broadcast Address */
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_mid_type_of_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;

        proto_tree_add_item(tree, hf_ansi_a_mid_broadcast_priority, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_mid_broadcast_message_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;

        proto_tree_add_item(tree, hf_ansi_a_mid_broadcast_zone_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        oct = tvb_get_guint8(tvb, curr_offset);

        proto_item_append_text(data_p->elem_item, " - Broadcast (Zone ID: %u)", oct);

        curr_offset++;

        value = tvb_get_ntohs(tvb, curr_offset);

        str = val_to_str_ext_const(value, &ansi_tsb58_srvc_cat_vals_ext, "Reserved");

        proto_tree_add_uint_format_value(tree, hf_ansi_a_mid_broadcast_srvc_cat, tvb, curr_offset, 2,
            value,
            "%s (%u)",
            str,
            value);

        curr_offset += 2;

        oct = tvb_get_guint8(tvb, curr_offset);

        str = val_to_str_ext_const(oct, &ansi_tsb58_language_ind_vals_ext, "Reserved");

        proto_tree_add_uint_format_value(tree, hf_ansi_a_mid_broadcast_language, tvb, curr_offset, 1,
            oct,
            "%s (%u)",
            str,
            oct);

        curr_offset++;
        break;

    case 5:     /* ESN */
        proto_tree_add_item(tree, hf_ansi_a_mid_unused, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_mid_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_mid_type_of_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;

        value = tvb_get_ntohl(tvb, curr_offset);

        proto_tree_add_uint(tree, hf_ansi_a_esn,
            tvb, curr_offset, 4,
            value);

        proto_item_append_text(data_p->elem_item, " - %sESN (0x%04x)",
            data_p->meid_configured ? "p" : "",
            value);

        curr_offset += 4;
        break;

    case 6:     /* IMSI */
        proto_tree_add_uint_format_value(tree, hf_ansi_a_imsi_mid_digit_1, tvb, curr_offset, 1,
            oct, "%c", Dgt_msid.out[(oct & 0xf0) >> 4]);

        proto_tree_add_item(tree, hf_ansi_a_mid_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_mid_type_of_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        if (curr_offset - offset >= len) /* Sanity check */
            return (curr_offset - offset);

        str = tvb_bcd_dig_to_str(pinfo->pool, tvb, curr_offset, len - (curr_offset - offset), &Dgt_msid, TRUE);
        proto_tree_add_string_format(tree, hf_ansi_a_imsi, tvb, curr_offset, len - (curr_offset - offset),
                                     str, "BCD Digits: %s", str);

        proto_item_append_text(data_p->elem_item, " - IMSI (%s)", str);
        if (data_p->message_item)
        {
            proto_item_append_text(data_p->message_item, " MID=%s", str);
        }
        if (global_a_info_display)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "MID=%s ", str);
        }

        curr_offset += len - (curr_offset - offset);
        break;

    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_ansi_a_unknown_format, tvb, curr_offset, len,
            "Mobile Identity ID type, %u, unknown/unsupported",
            (oct & 0x07));

        proto_item_append_text(data_p->elem_item, " - Format Unknown/Unsupported");

        curr_offset += len;
        break;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.17
 *
 * IOS 5 4.2.14
 */
static guint8
elem_sci(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_sci_sign, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format_value(tree, hf_ansi_a_sci, tvb, curr_offset, 1,
        oct, "%s%u", (oct & 0x08) ? "-" : "", oct & 0x07);

    proto_item_append_text(data_p->elem_item, " - (%s%u)",
        (oct & 0x08) ? "-" : "", oct & 0x07);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.18
 *
 * IOS 5 4.2.15
 */
static guint8
elem_prio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format_value(tree, hf_ansi_a_prio_call_priority, tvb, curr_offset, 1,
        oct, "Priority Level %u", (oct & 0x3c) >> 2);

    proto_tree_add_item(tree, hf_ansi_a_prio_queue_allowed, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_prio_preempt_allowed, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_item_append_text(data_p->elem_item, " - (%u)", (oct & 0x3c) >> 2);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.79
 */
static guint8
elem_p_rev(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_mob_p_rev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u)", oct);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.19
 */
static const value_string ansi_a_elem_cause_vals[] = {
    { 0x00,     "Radio interface message failure" },
    { 0x01,     "Radio interface failure" },
    { 0x02,     "Uplink Quality" },
    { 0x03,     "Uplink strength" },
    { 0x04,     "Downlink quality" },
    { 0x05,     "Downlink strength" },
    { 0x06,     "Distance" },
    { 0x07,     "OAM&P intervention" },
    { 0x08,     "MS busy" },
    { 0x09,     "Call processing" },
    { 0x0A,     "Reversion to old channel" },
    { 0x0B,     "Handoff successful" },
    { 0x0C,     "No response from MS" },
    { 0x0D,     "Timer expired" },
    { 0x0E,     "Better cell (power budget)" },
    { 0x0F,     "Interference" },
    { 0x10,     "Packet call going dormant" },
    { 0x11,     "Service option not available" },

    { 0x12,     "Invalid Call" },
    { 0x13,     "Successful operation" },
    { 0x14,     "Normal call release" },

        /* IOS 5 */
    { 0x15,     "Short data burst authentication failure" },
    { 0x17,     "Time critical relocation/handoff" },
    { 0x18,     "Network optimization" },
    { 0x19,     "Power down from dormant state" },
    { 0x1A,     "Authentication failure" },

    { 0x1B,     "Inter-BS Soft Handoff Drop Target" },
    { 0x1D,     "Intra-BS Soft Handoff Drop Target" },

        /* IOS 5 */
    { 0x1E,     "Autonomous Registration by the Network" },

    { 0x20,     "Equipment failure" },
    { 0x21,     "No radio resource available" },
    { 0x22,     "Requested terrestrial resource unavailable" },

        /* IOS 5 */
    { 0x23,     "A2p RTP Payload Type not available" },
    { 0x24,     "A2p Bearer Format Address Type not available" },

    { 0x25,     "BS not equipped" },
    { 0x26,     "MS not equipped (or incapable)" },

        /* IOS 5 */
    { 0x27,     "2G only sector" },
    { 0x28,     "3G only sector" },

    { 0x29,     "PACA Call Queued" },

        /* IOS 5 */
    { 0x2A,     "Handoff Blocked" },

    { 0x2B,     "Alternate signaling type reject" },

        /* IOS 5 */
    { 0x2C,     "A2p Resource not available" },

    { 0x2D,     "PACA Queue Overflow" },
    { 0x2E,     "PACA Cancel Request Rejected" },
    { 0x30,     "Requested transcoding/rate adaptation unavailable" },
    { 0x31,     "Lower priority radio resources not available" },
    { 0x32,     "PCF resources not available" },  /* IOS 4 */
    { 0x33,     "TFO Control request Failed" },

        /* IOS 5 */
    { 0x34,     "MS rejected order" },

    { 0x40,     "Ciphering algorithm not supported" },
    { 0x41,     "Private Long Code not available or not supported." },
    { 0x42,     "Requested MUX option or rates not available." },
    { 0x43,     "Requested Privacy Configuration unavailable" },

        /* IOS 5 */
    { 0x45,     "PDS-related capability not available or not supported" },

    { 0x50,     "Terrestrial circuit already allocated" },
    { 0x60,     "Protocol Error between BS and MSC" },
    { 0x71,     "ADDS message too long for delivery on the paging channel" },
    { 0x72,     "MS-to-IWF TCP connection failure" },
    { 0x73,     "ATH0 (Modem hang up) Command" },
    { 0x74,     "+FSH/+FHNG (Fax session ended) Command" },
    { 0x75,     "No carrier" },
    { 0x76,     "PPP protocol failure" },
    { 0x77,     "PPP session closed by the MS" },
    { 0x78,     "Do not notify MS" },
    { 0x79,     "PCF (or PDSN) resources are not available" },
    { 0x7A,     "Data ready to send" },

        /* IOS 5 */
    { 0x7B,     "Concurrent authentication" },

    { 0x7F,     "Handoff procedure time-out" },
    { 0, NULL }
};

static value_string_ext ansi_a_elem_cause_vals_ext = VALUE_STRING_EXT_INIT(ansi_a_elem_cause_vals);

static guint8
elem_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str = NULL;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct & 0x80)
    {
        /* 2 octet cause */

        proto_tree_add_item(tree, hf_ansi_a_cause_2_ext, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_cause_2, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

        curr_offset += 2;
    }
    else
    {
        proto_tree_add_item(tree, hf_ansi_a_cause_1_ext, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        str = val_to_str_ext_const(oct & 0x7f, &ansi_a_elem_cause_vals_ext, "Reserved for future use");

        proto_tree_add_uint_format_value(tree, hf_ansi_a_cause_1, tvb, curr_offset, 1, oct,
            "%s (%u)", str, oct & 0x7f);

        proto_item_append_text(data_p->elem_item, " - (%u) %s", oct & 0x7f, str);

        curr_offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.20
 * Formats everything after the discriminator, shared function.
 */
static guint8
elem_cell_id_aux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, guint8 disc, proto_item *parent_item_p)
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

        proto_tree_add_uint(tree, hf_ansi_a_cell_ci, tvb, curr_offset, 2, value);

        curr_offset += 2;

        if (parent_item_p)
        {
            proto_item_append_text(parent_item_p, " - CI (%u)", value);
        }
        break;

    case 0x05:
        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_uint(tree, hf_ansi_a_cell_lac, tvb, curr_offset, 2, value);

        curr_offset += 2;

        if (parent_item_p)
        {
            proto_item_append_text(parent_item_p, " - LAC (%u)", value);
        }
        break;

    case 0x07:
        market_id = tvb_get_ntohs(tvb, curr_offset);
        switch_num = tvb_get_guint8(tvb, curr_offset + 2);

        value = tvb_get_ntoh24(tvb, curr_offset);

        proto_tree_add_uint_format(tree, hf_ansi_a_cell_mscid, tvb, curr_offset, 3,
            value,
            "Market ID %u  Switch Number %u",
            market_id, switch_num);

        curr_offset += 3;

        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_uint(tree, hf_ansi_a_cell_ci, tvb, curr_offset, 2, value);

        curr_offset += 2;

        if (parent_item_p)
        {
            proto_item_append_text(parent_item_p, " - Market ID (%u) Switch Number (%u) CI (%u)",
                market_id, switch_num, value);
        }
        break;

    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_ansi_a_unknown_format, tvb, curr_offset, len,
            "Cell ID - Non IOS format");

        curr_offset += len;
        break;
    }

    return(curr_offset - offset);
}

static guint8
elem_cell_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_cell_id_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    curr_offset += 1;

    curr_offset +=
        elem_cell_id_aux(tvb, pinfo, tree, curr_offset, len - (curr_offset - offset), oct, data_p->elem_item);

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.21
 */
static guint8
elem_cell_id_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint16     consumed;
    guint8      num_cells;
    guint32     curr_offset;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_cell_id_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    num_cells = 0;

    do
    {
        subtree =
            proto_tree_add_subtree_format(tree, tvb, curr_offset, -1,
                ett_cell_list, &item, "Cell [%u]", num_cells + 1);

        consumed =
            elem_cell_id_aux(tvb, pinfo, subtree, curr_offset, len - (curr_offset - offset), oct, item);

        proto_item_set_len(item, consumed);

        curr_offset += consumed;

        num_cells++;
    }
    while ((len - (curr_offset - offset)) > 0);

    proto_item_append_text(data_p->elem_item, " - %u cell%s", num_cells, plurality(num_cells, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.22
 */
static guint8
elem_cic(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint32     value;
    guint32     curr_offset;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    item =
        proto_tree_add_item(tree, hf_ansi_a_cic, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    subtree = proto_item_add_subtree(item, ett_cic);

    proto_tree_add_item(subtree, hf_ansi_a_cic_pcm_multi, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cic_timeslot, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u) (0x%04x)", value, value);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.23
 */
static guint8
elem_cic_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     value;
    guint32     curr_offset;
    proto_item  *item;
    proto_tree  *subtree;
    const gchar *str;

    curr_offset = offset;

    item =
        proto_tree_add_item(tree, hf_ansi_a_cic_ext_cic, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    subtree = proto_item_add_subtree(item, ett_cic);

    proto_tree_add_item(subtree, hf_ansi_a_cic_ext_pcm_multi, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cic_ext_timeslot, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u) (0x%04x)", value, value);

    curr_offset += 2;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct & 0x0f)
    {
    case 0x00: str = "Full-rate"; break;
    default:
        str = "Reserved";
        break;
    }

    proto_tree_add_uint_format_value(tree, hf_ansi_a_cic_ext_circuit_mode, tvb, curr_offset, 1,
        oct, "%s (%u)", str, oct);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.21
 */
static guint8
elem_ssci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ssci_mopd, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ssci_geci, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

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
elem_downlink_re_aux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, proto_item *parent_item_p)
{
    guint8      disc;
    guint16     consumed;
    guint8      num_cells;
    guint8      curr_cell;
    guint32     curr_offset;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_downlink_re_num_cells, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    num_cells = tvb_get_guint8(tvb, curr_offset);

    curr_offset += 1;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_cell_id_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    disc = tvb_get_guint8(tvb, curr_offset);

    curr_offset += 1;

    NO_MORE_DATA_CHECK(len);

    curr_cell = 0;

    do
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), (guint32) 3 + ANSI_A_CELL_ID_LEN(disc));

        subtree =
            proto_tree_add_subtree_format(tree, tvb, curr_offset, -1,
                ett_cell_list, &item, "Cell [%u]", curr_cell + 1);

        consumed =
            elem_cell_id_aux(tvb, pinfo, subtree, curr_offset, len - (curr_offset - offset), disc, item);

        proto_item_set_len(item, consumed);

        curr_offset += consumed;

        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_downlink_re_sig_str_raw, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset += 1;

        proto_tree_add_item(tree, hf_ansi_a_downlink_re_cdma_towd, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

        curr_offset += 2;

        curr_cell++;
    }
    while (curr_cell < num_cells);

    proto_item_append_text(parent_item_p, " - %u cell%s", num_cells, plurality(num_cells, "", "s"));

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.25
 */
static guint8
elem_downlink_re(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;

    curr_offset = offset;

    curr_offset +=
        elem_downlink_re_aux(tvb, pinfo, tree, offset, len, data_p->elem_item);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.140
 */
static guint8
elem_downlink_re_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
    guint8      num_envs;
    guint32     curr_offset;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    num_envs = 0;

    while ((len - (curr_offset - offset)) > 0)
    {
        subtree =
            proto_tree_add_subtree_format(tree, tvb, curr_offset, -1,
                ett_re_list, &item, "Environment [%u]",
                num_envs + 1);

        proto_tree_add_item(subtree, hf_ansi_a_downlink_re_entry_env_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;

        consumed =
            elem_downlink_re_aux(tvb, pinfo, subtree, curr_offset, len - (curr_offset - offset), item);

        /*
         * +1 is for environment length
         */
        proto_item_set_len(item, consumed + 1);

        curr_offset += consumed;

        num_envs++;
    }

    proto_item_append_text(data_p->elem_item, " - %u environment%s", num_envs, plurality(num_envs, "", "s"));

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
elem_pdsn_ip_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_pdsn_ip_addr, tvb, curr_offset, len, ENC_BIG_ENDIAN);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.24
 */
static guint8
elem_s_pdsn_ip_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_s_pdsn_ip_addr, tvb, curr_offset, len, ENC_BIG_ENDIAN);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.31
 *
 * IOS 5 4.2.25
 */
static guint8
elem_ho_pow_lev(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
    guint8      num_cells;
    proto_item  *item;
    proto_tree  *subtree;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_ho_pow_lev_num_cells, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    SHORT_DATA_CHECK(len - (curr_offset - offset), (guint32) 6);

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ho_pow_lev_id_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ho_pow_lev_pow_lev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    subtree =
        proto_tree_add_subtree_format(tree, tvb, curr_offset, -1,
            ett_cell_list, &item, "Cell [1]");

    consumed =
        elem_cell_id_aux(tvb, pinfo, subtree, curr_offset, len - (curr_offset - offset), 0x7, item);

    proto_item_set_len(item, consumed);

    curr_offset += consumed;

    num_cells = 0;

    while ((len - (curr_offset - offset)) >= 3)
    {
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_e0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_ho_pow_lev_pow_lev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;

        subtree =
            proto_tree_add_subtree_format(tree, tvb, curr_offset, -1,
                ett_cell_list, &item, "Cell [%u]", num_cells + 1);

        consumed =
            elem_cell_id_aux(tvb, pinfo, subtree, curr_offset, len - (curr_offset - offset), 0x2, item);

        proto_item_set_len(item, consumed);

        curr_offset += consumed;

        num_cells++;
    }

    proto_item_append_text(data_p->elem_item, " - %u cell%s", num_cells, plurality(num_cells, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.32
 */
static guint8
elem_uz_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_uz_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u)", value);

    curr_offset += 2;

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
elem_info_rec_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    guint8      num_recs;
    const gchar *str;

    curr_offset = offset;

    num_recs = 0;

    while ((len - (curr_offset - offset)) > 0)
    {
        oct = tvb_get_guint8(tvb, curr_offset);

        str = val_to_str_const((guint32) oct, ansi_rev_ms_info_rec_str, "Reserved");

        proto_tree_add_uint_format(tree, hf_ansi_a_info_rec_req, tvb, curr_offset, 1,
            oct,
            "Information Record Type - %u: %s (%u)",
            num_recs + 1, str, oct);

        curr_offset++;

        num_recs++;
    }

    proto_item_append_text(data_p->elem_item, " - %u request%s", num_recs, plurality(num_recs, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.34
 */
static const value_string ansi_a_is2000_chan_id_chan_rev_pilot_gating_rate_vals[] = {
    { 0x00,     "Gating rate 1" },
    { 0x01,     "Gating rate 1/2" },
    { 0x02,     "Gating rate 1/4" },
    { 0x03,     "Reserved" },
    { 0, NULL }
};

static guint8
elem_is2000_chan_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint8      oct;
    guint8      num_chans;
    guint8      chan_num;
    guint32     curr_offset;
    proto_tree  *subtree;
    const gchar *str;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_is2000_chan_id_otd, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_chan_id_chan_count, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format_value(tree, hf_ansi_a_is2000_chan_id_frame_offset, tvb, curr_offset, 1,
        oct, "%u (%.2f ms)", oct & 0x0f, (oct & 0x0f) * 1.25);

    num_chans = (oct & 0x70) >> 4;

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    SHORT_DATA_CHECK(len - (curr_offset - offset), 6);

    chan_num = 0;

    do
    {
        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 6,
                ett_chan_list, NULL, "Channel [%u]", chan_num + 1);

        oct = tvb_get_guint8(tvb, curr_offset);

        switch (oct)
        {
        case 0x01: str = "Fundamental Channel (FCH) TIA/EIA/IS-2000"; break;
        case 0x02: str = "Dedicated Control Channel (DCCH) TIA/EIA/IS-2000"; break;
        case 0x03: str = "Supplemental Channel (SCH) TIA/EIA/IS-2000"; break;
        default:
            str = "Reserved";
            break;
        }

        proto_tree_add_uint_format_value(subtree, hf_ansi_a_is2000_chan_id_chan_chan_type, tvb, curr_offset, 1,
            oct, "%s", str);

        curr_offset += 1;

        switch (global_a_variant)
        {
        case A_VARIANT_IOS401:
            proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_16_8000, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            break;

        case A_VARIANT_IOS501:
            proto_tree_add_item(subtree, hf_ansi_a_is2000_chan_id_chan_rev_fch_gating, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            break;
        }

        proto_tree_add_item(subtree, hf_ansi_a_is2000_chan_id_chan_rev_pilot_gating_rate, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_chan_id_chan_qof_mask, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_chan_id_chan_walsh_code_chan_idx, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

        curr_offset += 2;

        /*
         * this field is odd in the IOS specification
         * one place (only as far as I can tell) that the bits are not MSB first
         *
         * SEE THE SPEC BEFORE CHANGING
         */
        proto_tree_add_expert(subtree, pinfo, &ei_ansi_a_is2000_chan_id_pilot_pn, tvb, curr_offset, 2);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_chan_id_chan_pilot_pn_code, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
        /*
         * SEE THE SPEC BEFORE CHANGING
         *
         * the field above has an odd encoding
         */

        switch (global_a_variant)
        {
        case A_VARIANT_IOS401:
            proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_24_007000, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            break;

        case A_VARIANT_IOS501:
            proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_24_006000, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_ansi_a_is2000_chan_id_chan_power_combined, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            break;
        }

        proto_tree_add_item(subtree, hf_ansi_a_is2000_chan_id_chan_freq_incl, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_chan_id_chan_channel_number, tvb, curr_offset, 3, ENC_BIG_ENDIAN);

        curr_offset += 3;

        chan_num++;
    }
    while (((len - (curr_offset - offset)) >= 6) &&
        (chan_num < num_chans));

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        SHORT_DATA_CHECK(len - (curr_offset - offset), 5);

        proto_tree_add_item(tree, hf_ansi_a_is2000_chan_id_chan_fdc_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_is2000_chan_id_chan_fdc_band_class, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_is2000_chan_id_chan_fdc_fwd_chan_freq, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_is2000_chan_id_chan_fdc_rev_chan_freq, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_16_001f, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        break;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.35
 * NO ASSOCIATED DATA
 */

/*
 * IOS 6.2.2.36
 *
 * IOS 5 4.2.29
 */
static guint8
elem_is95_ms_meas_chan_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_is95_ms_meas_chan_id_band_class, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is95_ms_meas_chan_id_channel_number, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    proto_item_append_text(data_p->elem_item, " - (ARFCN: %u)", tvb_get_ntohs(tvb, curr_offset) & 0x07ff);

    curr_offset += 2;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.33
 */
static guint8
elem_auth_conf_param(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_auth_conf_param_randc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.37
 */
static const value_string ansi_a_clg_party_ascii_num_ton_vals[] = {
    { 0,        "Unknown" },
    { 1,        "International number" },
    { 2,        "National number" },
    { 3,        "Network-specific number" },
    { 4,        "Dedicated PAD access, short code" },
    { 5,        "Reserved" },
    { 6,        "Reserved" },
    { 7,        "Reserved for extension" },
    { 0, NULL }
};

static const value_string ansi_a_clg_party_ascii_num_plan_vals[] = {
    { 0,        "Unknown" },
    { 1,        "ISDN/Telephony Numbering (ITU recommendation E.164/E.163)" },
    { 2,        "Reserved" },
    { 3,        "Data Numbering (ITU-T Rec. X.121)" },
    { 4,        "Telex Numbering (ITU-T Rec. F.69)" },
    { 5,        "Reserved" },
    { 6,        "Reserved" },
    { 7,        "Reserved for extension" },
    { 8,        "National Numbering" },
    { 9,        "Private Numbering" },
    { 10,       "Reserved" },
    { 11,       "Reserved" },
    { 12,       "Reserved" },
    { 13,       "Reserved" },
    { 14,       "Reserved" },
    { 15,       "Reserved" },
    { 0, NULL }
};

static guint8
elem_clg_party_ascii_num(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    guint8      *poctets;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_clg_party_ascii_num_ton, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_clg_party_ascii_num_plan, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    if (!(oct & 0x80))
    {
        /* octet 3a */

        proto_tree_add_item(tree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_clg_party_ascii_num_pi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_1c, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_clg_party_ascii_num_si, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;
    }

    poctets = tvb_get_string_enc(pinfo->pool, tvb, curr_offset, len - (curr_offset - offset), ENC_ASCII|ENC_NA);

    proto_tree_add_string_format(tree, hf_ansi_a_clg_party_ascii_num, tvb, curr_offset, len - (curr_offset - offset),
        (gchar *) poctets,
        "Digits: %s",
        (gchar *) format_text(pinfo->pool, poctets, len - (curr_offset - offset)));

    proto_item_append_text(data_p->elem_item, " - (%s)", poctets);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.38
 */
static guint8
elem_l3_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;
    tvbuff_t    *l3_tvb;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_layer3_info, tvb, curr_offset, len, ENC_NA);

    /*
     * dissect the embedded DTAP message
     */
    l3_tvb = tvb_new_subset_length(tvb, curr_offset, len);

    call_dissector(dtap_handle, l3_tvb, pinfo, data_p->g_tree);

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
elem_lai(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p _U_)
{
    guint8      oct;
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

    proto_tree_add_string(tree, hf_ansi_a_lai_mcc, tvb, curr_offset, 2, mcc);

    mnc[2] = Dgt_tbcd.out[(oct & 0xf0) >> 4];

    oct = tvb_get_guint8(tvb, curr_offset+2);

    mnc[0] = Dgt_tbcd.out[(oct & 0x0f)];
    mnc[1] = Dgt_tbcd.out[(oct & 0xf0) >> 4];
    mnc[3] = '\0';

    proto_tree_add_string(tree, hf_ansi_a_lai_mnc, tvb, curr_offset + 1, 2, mnc);

    curr_offset += 3;

    proto_tree_add_item(tree, hf_ansi_a_lai_lac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.44
 */
static const value_string ansi_a_rej_cause_vals[] = {
    { 0x01,     "Reserved" },
    { 0x02,     "MIN/IMSI unknown in HLR" },
    { 0x03,     "Illegal MS" },
    { 0x04,     "TMSI/IMSI/MIN unknown in VLR" },
    { 0x05,     "Reserved" },
    { 0x0b,     "Roaming not allowed" },
    { 0x0c,     "Location area not allowed" },
    { 0x20,     "Service option not supported" },
    { 0x21,     "Requested service option not subscribed" },
    { 0x22,     "Service option temporarily out of order" },
    { 0x26,     "Call cannot be identified" },
    { 0x51,     "Network failure" },
    { 0x56,     "Congestion" },
    { 0x62,     "Message type non-existent or not implemented" },
    { 0x63,     "Information element non-existent or not implemented" },
    { 0x64,     "Invalid information element contents" },
    { 0x65,     "Message not compatible with the call state" },
    { 0x66,     "Protocol error, unspecified" },
    { 0x6e,     "Invalid message, unspecified" },
    { 0x6f,     "Mandatory information element error" },
    { 0, NULL }
};

static guint8
elem_rej_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    str = val_to_str_const(oct, ansi_a_rej_cause_vals, "Reserved");
    proto_tree_add_uint_format_value(tree, hf_ansi_a_rej_cause, tvb, curr_offset, 1,
        oct, "%s (%u)", str, oct);

    if (data_p->message_item)
    {
        proto_item_append_text(data_p->message_item, " - (%s)", str);
    }

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.78
 */
static guint8
elem_anchor_pdsn_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_anchor_ip_addr, tvb, curr_offset, len, ENC_BIG_ENDIAN);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.80
 */
static guint8
elem_anchor_pp_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_anchor_pp_ip_addr, tvb, curr_offset, len, ENC_BIG_ENDIAN);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.45
 */
static const value_string ansi_a_auth_chlg_param_rand_num_type_vals[] = {
    { 1,        "RAND 32 bits" },
    { 2,        "RANDU 24 bits" },
    { 4,        "RANDSSD 56 bits" },
    { 8,        "RANDBS 32 bits" },
    { 0, NULL }
};

static guint8
elem_auth_chlg_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    str = val_to_str_const(oct & 0x0F, ansi_a_auth_chlg_param_rand_num_type_vals, "Reserved");
    proto_tree_add_uint_format_value(tree, hf_ansi_a_auth_chlg_param_rand_num_type, tvb, curr_offset, 1,
        oct, "%s (%u)", str, oct & 0x0f);

    proto_item_append_text(data_p->elem_item, " - (%s)", str);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_auth_chlg_param_rand, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.46
 */
static const value_string ansi_a_auth_resp_param_sig_type_vals[] = {
    { 1,        "AUTHR" },
    { 2,        "AUTHU" },
    { 4,        "AUTHBS" },
    { 0, NULL }
};

static guint8
elem_auth_resp_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    str = val_to_str_const(oct & 0x0F, ansi_a_auth_resp_param_sig_type_vals, "Reserved");
    proto_tree_add_uint_format_value(tree, hf_ansi_a_auth_resp_param_sig_type, tvb, curr_offset, 1,
        oct, "%s (%u)", str, oct & 0x0f);

    proto_item_append_text(data_p->elem_item, " - (%s)", str);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_auth_resp_param_sig, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.47
 */
static guint8
elem_auth_param_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_auth_param_count_count, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u)", oct & 0x3f);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.48
 */
static guint8
elem_mwi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_mwi_num_messages, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u)", oct);

    curr_offset++;

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

/*
 * from the IOS specification and MAY not be the exact same as the ones defined in
 * the cdma2000 specification
 * (and even if they are you shouldn't share the definitions in case one or the other changes)
 */
static const value_string ansi_a_signal_signal_vals[] = {
    { 0x00,     "Dial tone on" },
    { 0x01,     "Ring back tone on" },
    { 0x02,     "Intercept tone on" },
    { 0x03,     "Network congestion (reorder) tone on" },
    { 0x04,     "Busy tone on" },
    { 0x05,     "Confirm tone on" },
    { 0x06,     "Answer tone on" },
    { 0x07,     "Call waiting tone on" },
    { 0x08,     "Off-hook warning tone on" },
    { 0x3f,     "Tones off" },
    { 0x40,     "Normal Alerting" },
    { 0x41,     "Inter-group Alerting" },
    { 0x42,     "Special/Priority Alerting" },
    { 0x43,     "Reserved (ISDN Alerting pattern 3)" },
    { 0x44,     "Ping Ring (abbreviated alert)" },
    { 0x45,     "Reserved (ISDN Alerting pattern 5)" },
    { 0x46,     "Reserved (ISDN Alerting pattern 6)" },
    { 0x47,     "Reserved (ISDN Alerting pattern 7)" },
    { 0x4f,     "Alerting off" },
    { 0x63,     "Abbreviated intercept" },
    { 0x65,     "Abbreviated reorder" },
    { 0, NULL }
};

static const value_string ansi_a_signal_alert_pitch_vals[] = {
    { 0x00,     "Medium pitch (standard alert)" },
    { 0x01,     "High pitch" },
    { 0x02,     "Low pitch" },
    { 0x03,     "Reserved" },
    { 0, NULL }
};

static guint8
elem_signal(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    str = val_to_str_const(oct, ansi_a_signal_signal_vals, "Unknown");
    proto_tree_add_item(tree, hf_ansi_a_signal_signal_value, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_item_append_text(data_p->elem_item, " - (%s)", str);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_signal_alert_pitch, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

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
 *
 * IOS 5 4.2.40
 */
/*
 * IS-634-A Table 6.62
 * IOS 5 Table 4.2.40-1
 */
static const value_string ansi_a_cld_party_bcd_num_ton_vals[] = {
    { 0,        "Unknown" },
    { 1,        "International number" },
    { 2,        "National number" },
    { 3,        "Network specific number" },
    { 4,        "Dedicated PAD access, short code" },
    { 5,        "Reserved" },
    { 6,        "Reserved" },
    { 7,        "Reserved for extension" },
    { 0, NULL }
};

/*
 * IS-634-A Table 6.63
 * IOS 5 Table 4.2.40-2
 */
static const value_string ansi_a_cld_party_bcd_num_plan_vals[] = {
    { 0x00,     "Unknown" },
    { 0x01,     "ISDN/telephony number plan (ITU recommendation E.164/E.163)" },
    { 0x02,     "Reserved" },
    { 0x03,     "Data number plan (ITU recommendation X.121)" },
    { 0x04,     "Telex numbering plan (ITU recommendation F.69)" },
    { 0x05,     "Reserved" },
    { 0x06,     "Reserved" },
    { 0x07,     "Reserved for extension" },
    { 0x08,     "National numbering plan" },
    { 0x09,     "Private numbering plan" },
    { 0x0a,     "Reserved" },
    { 0x0b,     "Reserved" },
    { 0x0c,     "Reserved" },
    { 0x0d,     "Reserved" },
    { 0x0e,     "Reserved" },
    { 0x0f,     "Reserved" },
    { 0, NULL }
};

static guint8
elem_cld_party_bcd_num(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;
    const char *str;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_clg_party_bcd_num_ton, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_clg_party_bcd_num_plan, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    if (curr_offset - offset >= len) /* Sanity check */
        return (curr_offset - offset);

    str = tvb_bcd_dig_to_str(pinfo->pool, tvb, curr_offset, len - (curr_offset - offset), &Dgt_tbcd, FALSE);
    proto_tree_add_string(tree, hf_ansi_a_cld_party_bcd_num, tvb, curr_offset, len - (curr_offset - offset), str);

    proto_item_append_text(data_p->elem_item, " - (%s)", str);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.54
 */
static guint8
elem_qos_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_qos_params_packet_priority, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u)", oct & 0x0f);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.55
 */
static const value_string ansi_a_cause_l3_coding_standard_vals[] = {
    { 0,        "Standard as described in ITU Recommendation Q.931" },
    { 1,        "Reserved for other international standards" },
    { 2,        "National standard" },
    { 3,        "Reserved for other international standards" },
    { 0, NULL }
};

static const value_string ansi_a_cause_l3_location_vals[] = {
    { 0,        "User" },
    { 1,        "Private network serving the local user" },
    { 2,        "Public network serving the local user" },
    { 3,        "Transit network" },
    { 4,        "Public network serving the remote user" },
    { 5,        "Private network serving the remote user" },
    { 6,        "Reserved" },
    { 7,        "International network" },
    { 8,        "Reserved" },
    { 9,        "Reserved" },
    { 10,       "Network beyond interworking point" },
    { 11,       "Reserved" },
    { 12,       "Reserved" },
    { 13,       "Reserved" },
    { 14,       "Reserved" },
    { 15,       "Reserved" },
    { 0, NULL }
};

static const value_string ansi_a_cause_l3_class_vals[] = {
    { 0,        "normal event" },
    { 1,        "normal event" },
    { 2,        "resource unavailable" },
    { 3,        "service or option not available" },
    { 4,        "service or option not implemented" },
    { 5,        "invalid message (e.g., parameter out of range)" },
    { 6,        "protocol error (e.g., unknown message)" },
    { 7,        "interworking" },
    { 0, NULL }
};

static const value_string ansi_a_cause_l3_value_vals[] = {
    { 0x01,     "Unassigned (unallocated) number" },
    { 0x03,     "No route to destination" },
    { 0x06,     "Channel unacceptable" },
    { 0x0F,     "Procedure failed" },
    { 0x10,     "Normal Clearing" },
    { 0x11,     "User busy" },
    { 0x12,     "No user responding" },
    { 0x13,     "User alerting, no answer" },
    { 0x15,     "Call rejected" },
    { 0x16,     "Number changed New destination" },
    { 0x1A,     "Non selected user clearing" },
    { 0x1B,     "Destination out of order" },
    { 0x1C,     "Invalid number format (incomplete number)" },
    { 0x1D,     "Facility rejected" },
    { 0x1F,     "Normal, unspecified" },
    { 0x22,     "No circuit/channel available" },
    { 0x26,     "Network out of order" },
    { 0x29,     "Temporary failure" },
    { 0x2A,     "Switching equipment congestion" },
    { 0x2B,     "Access information discarded information element ids" },
    { 0x2C,     "requested circuit/channel not available" },
    { 0x2F,     "Resources unavailable, unspecified" },
    { 0x31,     "Quality of service unavailable" },
    { 0x32,     "Requested facility not subscribed" },
    { 0x33,     "Request MUX option or rates unavailable" },
    { 0x39,     "Bearer capability not authorized" },
    { 0x3A,     "Bearer capability not presently available" },
    { 0x3B,     "SSD Update Rejected" },
    { 0x3F,     "Service or option not available, unspecified" },
    { 0x41,     "Bearer service not implemented" },
    { 0x45,     "Requested facility not implement" },
    { 0x46,     "Only restricted digital information bearer capability is available" },
    { 0x4F,     "Service or option not implemented, unspecified" },
    { 0x51,     "Reserved" },
    { 0x58,     "Incompatible destination incompatible parameter" },
    { 0x5B,     "Invalid transit network selection" },
    { 0x5F,     "Invalid message, unspecified" },
    { 0x60,     "Mandatory information element error information element identifier(s)" },
    { 0x61,     "Message type nonexistent or not implemented message type" },
    { 0x62,     "Message not compatible with control state message type or message type nonexistent or not implemented" },
    { 0x64,     "Invalid information element contents Information element Identifier(s)" },
    { 0x65,     "Message not compatible with call state message type" },
    { 0x6F,     "Protocol error, unspecified" },
    { 0x7F,     "Interworking, unspecified" },
    { 0, NULL }
};

static value_string_ext ansi_a_cause_l3_value_vals_ext = VALUE_STRING_EXT_INIT(ansi_a_cause_l3_value_vals);

static guint8
elem_cause_l3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str = NULL;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cause_l3_coding_standard, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_10, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cause_l3_location, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_ansi_a_cause_l3_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cause_l3_value_without_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    str = val_to_str_ext_const(oct & 0x7f, &ansi_a_cause_l3_value_vals_ext, "Reserved");
    proto_tree_add_uint_format_value(tree, hf_ansi_a_cause_l3_value, tvb, curr_offset, 1,
        oct & 0x7f, "%s (%u)", str, oct & 0x7f);

    proto_item_append_text(data_p->elem_item, " - (%u) %s", oct & 0x7f, str);

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
elem_xmode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fe, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_item(tree, hf_ansi_a_xmode_tfo_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_item_append_text(data_p->elem_item, " - (%s)",
        tfs_get_string(oct & 0x01, &tfs_ansi_a_xmode_tfo_mode));

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
 *
 * IOS 5 4.2.45
 */
static const value_string ansi_a_reg_type_type_vals[] = {
    { 0,        "Timer-based" },
    { 1,        "Power-up" },
    { 2,        "Zone-based" },
    { 3,        "Power-down" },
    { 4,        "Parameter-change" },
    { 5,        "Ordered" },
    { 6,        "Distance-based" },
    { 7,        "User Zone-based" },
    { 9,        "BCMC Registration" },
    { 0, NULL }
};

static guint8
elem_reg_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    str = val_to_str_const(oct, ansi_a_reg_type_type_vals, "Reserved");
    proto_tree_add_uint_format_value(tree, hf_ansi_a_reg_type_type, tvb, curr_offset, 1,
        oct, "%s", str);

    proto_item_append_text(data_p->elem_item, " - (%s)", str);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.62
 *
 * IOS 5 4.2.46
 */
static guint8
elem_tag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint32     value;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_tag_value, tvb, curr_offset, 4, ENC_BIG_ENDIAN);

    value = tvb_get_ntohl(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u)", value);

    curr_offset += 4;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.63
 *
 * IOS 5 4.2.47
 */
static guint8
elem_hho_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_e0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_band_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    str = val_to_str_const(oct & 0x1f, ansi_a_band_class_vals, "Reserved");

    proto_item_append_text(data_p->elem_item, " - (%s)", str);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_hho_params_num_pream_frames, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_reset_l2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_reset_fpc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_enc_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_private_lcm, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_e0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;

    case A_VARIANT_IOS501:
        proto_tree_add_item(tree, hf_ansi_a_hho_params_rev_pwr_cntl_delay_incl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_hho_params_rev_pwr_cntl_delay, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    proto_tree_add_item(tree, hf_ansi_a_hho_params_nom_pwr_ext, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_nom_pwr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_fpc_subchan_info, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_fpc_subchan_info_incl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_pwr_cntl_step, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_hho_params_pwr_cntl_step_incl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

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
elem_sw_ver(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      major, minor, point;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_sw_ver_major, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    major = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_sw_ver_minor, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    minor = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_sw_ver_point, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    point = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (IOS %u.%u.%u)", major, minor, point);

    curr_offset++;

    if (len > 3)
    {
        proto_tree_add_item(tree, hf_ansi_a_manufacturer_software_info, tvb, curr_offset, len - 3, ENC_NA);

        curr_offset += len - 3;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.66
 */
static guint8
elem_so_aux(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, guint16 *value_p)
{
    proto_tree_add_item(tree, hf_ansi_a_so_proprietary_ind, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_so_revision, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_so_base_so_num, tvb, offset, 2, ENC_BIG_ENDIAN);

    *value_p = tvb_get_ntohs(tvb, offset);

    proto_tree_add_uint_format(tree, hf_ansi_a_so, tvb, offset, 2,
        *value_p,
        "%s",
        ansi_a_so_int_to_str(*value_p));

    /* no length check possible */

    return(2);
}

static guint8
elem_so(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     value;
    guint32     curr_offset;

    curr_offset = offset + elem_so_aux(tvb, pinfo, tree, offset, len, &value);

    proto_item_append_text(data_p->elem_item, " - (%u) %s", value, ansi_a_so_int_to_str(value));
    if (data_p->message_item)
    {
        proto_item_append_text(data_p->message_item, " - SO (%u)", value);
    }
    if (global_a_info_display)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "- SO (%u)", value);
    }

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.73
 */
static guint8
elem_soci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_soci, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%u)", oct);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.74
 */
static guint8
elem_so_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      num_so;
    guint8      inst;
    guint32     curr_offset;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_so_list_num, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    num_so = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - %u service options", num_so);

    curr_offset += 1;

    NO_MORE_DATA_CHECK(len);

    SHORT_DATA_CHECK(len - (curr_offset - offset), 3);

    inst = 0;

    do
    {
        guint16         value;

        subtree =
            proto_tree_add_subtree_format(tree, tvb, curr_offset, 3,
                ett_so_list, &item, "Service Option [%u]",
                inst + 1);

        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_so_list_sr_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_so_list_soci, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset += 1;

        curr_offset += elem_so_aux(tvb, pinfo, subtree, curr_offset, len, &value);

        proto_item_append_text(item, " - (%u) %s", value, ansi_a_so_int_to_str(value));

        inst++;
    }
    while (((len - (curr_offset - offset)) >= 3) &&
        (inst < num_so));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.70
 */
static guint8
elem_acc_net_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     sid, nid, pzid;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_16_8000, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_sid, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_nid, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_pzid, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    sid = tvb_get_ntohs(tvb, curr_offset) & 0x7fff;

    curr_offset += 2;

    nid = tvb_get_ntohs(tvb, curr_offset);

    curr_offset += 2;

    pzid = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (SID/NID/PZID: %u/%u/%u)", sid, nid, pzid);

    curr_offset += 1;

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

static const value_string ansi_a_adds_vals[] = {
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
    { 0, NULL }
};

/*
 * IOS 6.2.2.67
 */
static guint8
elem_adds_user_part(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    tvbuff_t    *adds_tvb;
    proto_tree  *subtree;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_adds_user_part_burst_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%s)",
        val_to_str_const(oct & 0x3f, ansi_a_adds_vals, "Reserved"));

    curr_offset++;

    subtree = proto_tree_add_subtree(tree, tvb, curr_offset, len - 1, ett_adds_user_part, NULL, "Application Data Message");

    switch (oct & 0x3f)
    {
    case ADDS_APP_SMS:
        adds_tvb = tvb_new_subset_length(tvb, curr_offset, len - 1);

        dissector_try_uint(is637_dissector_table, 0, adds_tvb, pinfo, data_p->g_tree);
        curr_offset += (len - 1);
        break;

    case ADDS_APP_OTA:
        adds_tvb = tvb_new_subset_length(tvb, curr_offset, len - 1);

        dissector_try_uint(is683_dissector_table, data_p->is_reverse, adds_tvb, pinfo, data_p->g_tree);

        curr_offset += (len - 1);
        break;

    case ADDS_APP_PDS:
        adds_tvb = tvb_new_subset_length(tvb, curr_offset, len - 1);

        dissector_try_uint(is801_dissector_table, data_p->is_reverse, adds_tvb, pinfo, data_p->g_tree);

        curr_offset += (len - 1);
        break;

    case ADDS_APP_SDB:
        /*
         * no SDB dissector, push to GRE/A11 dissector ?
         */
        curr_offset += (len - 1);
        break;

    case ADDS_APP_EXT_INTL:

        /* FALLTHROUGH */

    case ADDS_APP_EXT:
        /*
         * no generic External International dissector
         * no generic External dissector
         */
        proto_tree_add_item(subtree, hf_ansi_a_adds_user_part_ext_burst_type, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

        curr_offset += 2;

        proto_tree_add_item(subtree, hf_ansi_a_adds_user_part_ext_data, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

        curr_offset += len - (curr_offset - offset);
        break;

    default:
        /*
         * no sub-dissectors
         */
        proto_tree_add_item(subtree, hf_ansi_a_adds_user_part_unknown_data, tvb, curr_offset, len - 1, ENC_NA);

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
elem_amps_hho_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_amps_hho_params_enc_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.68
 */
static const value_string ansi_a_is2000_scr_socr_for_chan_type_vals[] = {
    { 0x00,     "The service option connection does not use Forward Traffic Channel traffic." },
    { 0x01,     "The service option connection uses primary traffic on the Forward Traffic Channel." },
    { 0x02,     "The service option connection uses secondary traffic on the Forward Traffic Channel." },
    { 0, NULL }
};

static const value_string ansi_a_is2000_scr_socr_rev_chan_type_vals[] = {
    { 0x00,     "The service option connection does not use Reverse Traffic Channel traffic." },
    { 0x01,     "The service option connection uses primary traffic on the Reverse Traffic Channel." },
    { 0x02,     "The service option connection uses secondary traffic on the Reverse Traffic Channel." },
    { 0, NULL }
};

static guint8
elem_is2000_scr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint8      oct, num_con_rec, ii;
    guint8      bit_mask, bit_offset;
    guint32     curr_offset, saved_offset;
    guint32     value;
    guint       is2000_portion_len;
    proto_tree  *scr_subtree, *subtree;
    const gchar *str = NULL;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_scr_num_fill_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    is2000_portion_len = len - (curr_offset - offset);

    SHORT_DATA_CHECK(is2000_portion_len, 7);

    saved_offset = curr_offset;

    scr_subtree = proto_tree_add_subtree(tree, tvb, curr_offset, is2000_portion_len,
            ett_scr, NULL, "IS-2000 Service Configuration Record Content");

    proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_for_mux_option, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset += 2;

    proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_rev_mux_option, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset += 2;

    proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_for_fch_rate, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset += 1;

    proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_rev_fch_rate, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset += 1;

    proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_num_socr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    num_con_rec = tvb_get_guint8(tvb, curr_offset);
    curr_offset += 1;

    for (ii=0; ii < num_con_rec; ii++)
    {
        oct = tvb_get_guint8(tvb, curr_offset);

        subtree = proto_tree_add_subtree_format(scr_subtree, tvb,
                curr_offset, oct /* !!! oct already includes the length octet itself */,
                ett_scr_socr, NULL, "Service option connection record [%u]", ii+1);
        curr_offset += 1;

        proto_tree_add_item(subtree, hf_ansi_a_is2000_scr_socr_soc_ref, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset += 1;

        value = tvb_get_ntohs(tvb, curr_offset);

        proto_tree_add_uint_format_value(subtree, hf_ansi_a_is2000_scr_socr_so, tvb, curr_offset, 2,
            value,
            "%s (%u)",
            ansi_a_so_int_to_str(value), value);

        curr_offset += 2;

        oct = tvb_get_guint8(tvb, curr_offset);

        str = val_to_str_const((oct & 0xf0) >> 4, ansi_a_is2000_scr_socr_for_chan_type_vals, "Reserved");
        proto_tree_add_uint_format_value(subtree, hf_ansi_a_is2000_scr_socr_for_chan_type, tvb, curr_offset, 1,
            oct, "Forward Traffic Channel traffic type, %s", str);

        str = val_to_str_const(oct & 0x0f, ansi_a_is2000_scr_socr_rev_chan_type_vals, "Reserved");
        proto_tree_add_uint_format_value(subtree, hf_ansi_a_is2000_scr_socr_rev_chan_type, tvb, curr_offset, 1,
            oct, "Reverse Traffic Channel traffic type, %s", str);
        curr_offset += 1;

        proto_tree_add_item(subtree, hf_ansi_a_is2000_scr_socr_ui_enc_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_scr_socr_sr_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_scr_socr_rlp_info_incl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        oct = tvb_get_guint8(tvb, curr_offset);

        if (oct & 0x02)
        {
            value = (oct & 0x01) << 3;

            curr_offset += 1;

            oct = tvb_get_guint8(tvb, curr_offset);

            value |= (oct & 0xe0) >> 5;

            proto_tree_add_item(subtree, hf_ansi_a_is2000_scr_socr_rlp_blob_len, tvb, curr_offset - 1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_ansi_a_is2000_scr_socr_rlp_blob_msb, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

            curr_offset += 1;

            if (value > 1)
            {
                proto_tree_add_item(subtree, hf_ansi_a_is2000_scr_socr_rlp_blob, tvb, curr_offset, value - 1, ENC_NA);
                curr_offset += value - 1;
            }

            proto_tree_add_item(subtree, hf_ansi_a_is2000_scr_socr_rlp_blob_lsb, tvb, curr_offset, 1, ENC_NA);
            proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_1f, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        }
        else
        {
            proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_01, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        }

        curr_offset += 1;
    }

    proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_socr_fch_cc_incl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct & 0x80)
    {
        proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_socr_fch_frame_size_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_socr_for_fch_rc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset += 1;

        oct = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_item(scr_subtree, hf_ansi_a_is2000_scr_socr_rev_fch_rc, tvb, curr_offset - 1, 2, ENC_BIG_ENDIAN);
        bit_mask = 0x08;
        bit_offset = 3;
    }
    else
    {
        bit_offset = 6;
        bit_mask = 0x40;
    }

    proto_tree_add_bits_item(scr_subtree, hf_ansi_a_dcch_cc_incl, tvb, (curr_offset*8)+(8-bit_offset), 1, ENC_NA);
    if (oct & bit_mask)
    {
        /* can't be bothered to do the rest of the decode */

        proto_tree_add_expert_format(scr_subtree, pinfo, &ei_ansi_a_undecoded, tvb, curr_offset, (is2000_portion_len - (curr_offset - saved_offset)), "DCCH + ? + Reserved");

        curr_offset += (is2000_portion_len - (curr_offset - saved_offset));
    }
    else
    {
        bit_mask >>= 1;
        bit_offset--;

        proto_tree_add_bits_item(scr_subtree, hf_ansi_a_for_sch_cc_incl, tvb, (curr_offset*8)+(8-bit_offset), 1, ENC_NA);
        if (oct & bit_mask)
        {
            /* can't be bothered to do the rest of the decode */

            proto_tree_add_expert_format(scr_subtree, pinfo, &ei_ansi_a_undecoded, tvb, curr_offset, (is2000_portion_len - (curr_offset - saved_offset)), "FOR_SCH + ? + Reserved");

            curr_offset += (is2000_portion_len - (curr_offset - saved_offset));
        }
        else
        {
            bit_mask >>= 1;
            bit_offset--;

            proto_tree_add_bits_item(scr_subtree, hf_ansi_a_rev_sch_cc_incl, tvb, (curr_offset*8)+(8-bit_offset), 1, ENC_NA);

            if (oct & bit_mask)
            {
                /* can't be bothered to do the rest of the decode */

                proto_tree_add_expert_format(scr_subtree, pinfo, &ei_ansi_a_undecoded, tvb, curr_offset, (is2000_portion_len - (curr_offset - saved_offset)), "REV_SCH + ? + Reserved");

                curr_offset += (is2000_portion_len - (curr_offset - saved_offset));
            }
            else
            {
                proto_tree_add_bits_item(scr_subtree, hf_ansi_a_reserved_bits_8_generic, tvb, (curr_offset*8)+(8-bit_offset), bit_offset, ENC_NA);
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
elem_is2000_nn_scr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;
    guint       is2000_portion_len;
    guint8      fill_bits;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_nn_scr_num_fill_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    fill_bits = tvb_get_guint8(tvb, curr_offset) & 0x07;

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    is2000_portion_len = len - (curr_offset - offset);

    if (is2000_portion_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), is2000_portion_len);

        content_fill_aux(tvb, tree, curr_offset, is2000_portion_len, fill_bits,
            hf_ansi_a_is2000_nn_scr_content,
            hf_ansi_a_is2000_nn_scr_fill_bits);

        curr_offset += is2000_portion_len;

        NO_MORE_DATA_CHECK(len);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.70
 *
 * IOS 5 4.2.53
 */
static const value_string ansi_a_is2000_mob_cap_fch_info_geo_loc_type_vals[] = {
    { 0,        "No mobile assisted geo-location capabilities" },
    { 1,        "IS801 capable (Advanced Forward Link Triangulation only (AFLT))" },
    { 2,        "IS801 capable (Advanced Forward Link Triangulation and Global Positioning Systems)" },
    { 3,        "Global Positioning Systems Only" },
    { 4,        "Reserved" },
    { 5,        "Reserved" },
    { 6,        "Reserved" },
    { 7,        "Reserved" },
    { 0, NULL }
};

static guint8
elem_is2000_mob_cap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint8      oct;
    guint8      oct_len;
    guint32     curr_offset;
    guint8      fill_bits;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_e0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;

    case A_VARIANT_IOS501:
        proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_rev_pdch_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_for_pdch_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_eram_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_dcch_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_fch_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_otd_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_enh_rc_cfg_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_qpch_support_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_fch_info_octet_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct_len = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    /*
     * The octet following the FCH/DCCH/... Information Bit-Exact Length - Octet Count
     * field is NOT counted in that length and is required.
     */
    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_fch_info_geo_loc_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_fch_info_geo_loc_incl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_fch_info_num_fill_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    fill_bits = tvb_get_guint8(tvb, curr_offset) & 0x07;

    curr_offset++;

    if (oct_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

        subtree =
            proto_tree_add_subtree(tree, tvb, curr_offset, oct_len,
                ett_is2000_mob_cap_fch_info, NULL, "FCH Information");

        content_fill_aux(tvb, subtree, curr_offset, oct_len, fill_bits,
            hf_ansi_a_is2000_mob_cap_fch_info_content,
            hf_ansi_a_is2000_mob_cap_fch_info_fill_bits);

        curr_offset += oct_len;
    }

    /*
     * DCCH
     */
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_dcch_info_octet_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct_len = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_dcch_info_num_fill_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    fill_bits = tvb_get_guint8(tvb, curr_offset) & 0x07;

    curr_offset++;

    if (oct_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

        subtree = proto_tree_add_subtree(tree, tvb, curr_offset, oct_len,
                     ett_is2000_mob_cap_dcch_info, NULL, "DCCH Information");

        content_fill_aux(tvb, subtree, curr_offset, oct_len, fill_bits,
            hf_ansi_a_is2000_mob_cap_dcch_info_content,
            hf_ansi_a_is2000_mob_cap_dcch_info_fill_bits);

        curr_offset += oct_len;
    }

    NO_MORE_DATA_CHECK(len);

    /*
     * FOR_PDCH
     */
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_for_pdch_info_octet_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct_len = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_for_pdch_info_num_fill_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    fill_bits = tvb_get_guint8(tvb, curr_offset) & 0x07;

    curr_offset++;

    if (oct_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

        subtree = proto_tree_add_subtree(tree, tvb, curr_offset, oct_len,
                    ett_is2000_mob_cap_for_pdch_info, NULL, "FOR_PDCH Information");

        content_fill_aux(tvb, subtree, curr_offset, oct_len, fill_bits,
            hf_ansi_a_is2000_mob_cap_for_pdch_info_content,
            hf_ansi_a_is2000_mob_cap_for_pdch_info_fill_bits);

        curr_offset += oct_len;
    }

    NO_MORE_DATA_CHECK(len);

    /*
     * REV_PDCH
     */
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_rev_pdch_info_octet_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct_len = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_is2000_mob_cap_rev_pdch_info_num_fill_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    fill_bits = tvb_get_guint8(tvb, curr_offset) & 0x07;

    curr_offset++;

    if (oct_len > 0)
    {
        SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

        subtree = proto_tree_add_subtree(tree, tvb, curr_offset, oct_len,
            ett_is2000_mob_cap_rev_pdch_info, NULL, "REV_PDCH Information");

        content_fill_aux(tvb, subtree, curr_offset, oct_len, fill_bits,
            hf_ansi_a_is2000_mob_cap_rev_pdch_info_content,
            hf_ansi_a_is2000_mob_cap_rev_pdch_info_fill_bits);

        curr_offset += oct_len;
    }

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    item = proto_tree_add_uint_format(tree, hf_ansi_a_is2000_mob_cap_vp_support, tvb, curr_offset, 1,
            oct & 0x7f,
            "VP Algorithms Supported%s",
            (oct & 0x7f) ? "" : ":  No voice privacy supported");

    if (oct & 0x7f)
    {
        subtree = proto_item_add_subtree(item, ett_vp_algs);

        proto_tree_add_item(subtree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_mob_cap_vp_support_a7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_mob_cap_vp_support_a6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_mob_cap_vp_support_a5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_mob_cap_vp_support_a4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_mob_cap_vp_support_a3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_mob_cap_vp_support_a2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_is2000_mob_cap_vp_support_a1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.71
 */
static guint8
elem_ptype(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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

    proto_tree_add_uint_format(tree, hf_ansi_a_protocol_type, tvb, curr_offset, 2,
        value,
        "%s (%u)",
        str, value);

    proto_item_append_text(data_p->elem_item, " - (%s)", str);

    curr_offset += 2;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.72
 */
static const value_string ansi_a_ms_info_rec_signal_type_vals[] = {
    { 0x0,      "Tone signal" },
    { 0x1,      "ISDN Alerting" },
    { 0x2,      "IS-54B Alerting" },
    { 0x3,      "Reserved" },
    { 0, NULL }
};

static const value_string ansi_a_ms_info_rec_signal_alert_pitch_vals[] = {
    { 0x0,      "Medium pitch (standard alert)" },
    { 0x1,      "High pitch" },
    { 0x2,      "Low pitch" },
    { 0x3,      "Reserved" },
    { 0, NULL }
};

static const value_string ansi_a_ms_info_rec_signal_tone_vals[] = {
    { 0x00,     "Dial tone on" },
    { 0x01,     "Ring back tone on" },
    { 0x02,     "Intercept tone on" },
    { 0x03,     "Abbreviated intercept" },
    { 0x04,     "Network congestion (reorder) tone on" },
    { 0x05,     "Abbreviated network congestion (reorder)" },
    { 0x06,     "Busy tone on" },
    { 0x07,     "Confirm tone on" },
    { 0x08,     "Answer tone on" },
    { 0x09,     "Call waiting tone on" },
    { 0x0a,     "Pip tone on" },
    { 0x3f,     "Tones off" },
    { 0, NULL }
};

static const value_string ansi_a_ms_info_rec_signal_isdn_alert_vals[] = {
    { 0x0,      "Normal Alerting" },
    { 0x1,      "Intergroup Alerting" },
    { 0x2,      "Special/Priority Alerting" },
    { 0x3,      "Reserved (ISDN Alerting pattern 3)" },
    { 0x4,      "Ping ring" },
    { 0x5,      "Reserved (ISDN Alerting pattern 5)" },
    { 0x6,      "Reserved (ISDN Alerting pattern 6)" },
    { 0x7,      "Reserved (ISDN Alerting pattern 7)" },
    { 0xf,      "Alerting off" },
    { 0, NULL }
};

static const value_string ansi_a_ms_info_rec_signal_is54b_alert_vals[] = {
    { 0x0,      "No Tone" },
    { 0x1,      "Long" },
    { 0x2,      "Short-Short" },
    { 0x3,      "Short-Short-Long" },
    { 0x4,      "Short-Short-2" },
    { 0x5,      "Short-Long-Short" },
    { 0x6,      "Short-Short-Short-Short" },
    { 0x7,      "PBX Long" },
    { 0x8,      "PBX Short-Short" },
    { 0x9,      "PBX Short-Short-Long" },
    { 0xa,      "PBX Short-Long-Short" },
    { 0xb,      "PBX Short-Short-Short-Short" },
    { 0xc,      "Pip-Pip-Pip-Pip" },
    { 0, NULL }
};

/*
 * C.S0005 Table 2.7.1.3.2.4-2 Number Types
 */
const value_string ansi_a_ms_info_rec_num_type_vals[] = {
    { 0,        "Unknown" },
    { 1,        "International number" },
    { 2,        "National number" },
    { 3,        "Network-specific number" },
    { 4,        "Subscriber number" },
    { 5,        "Reserved" },
    { 6,        "Abbreviated number" },
    { 7,        "Reserved for extension" },
    { 0, NULL }
};

/*
 * C.S0005 Table 2.7.1.3.2.4-3 Numbering Plan Identification
 */
const value_string ansi_a_ms_info_rec_num_plan_vals[] = {
    { 0x00,     "Unknown" },
    { 0x01,     "ISDN/Telephony Numbering" },
    { 0x02,     "Reserved" },
    { 0x03,     "Data Numbering (ITU-T Rec. X.121)" },
    { 0x04,     "Telex Numbering (ITU-T Rec. F.69)" },
    { 0x05,     "Reserved" },
    { 0x06,     "Reserved" },
    { 0x07,     "Reserved" },
    { 0x08,     "Reserved" },
    { 0x09,     "Private Numbering" },
    { 0x0a,     "Reserved" },
    { 0x0b,     "Reserved" },
    { 0x0c,     "Reserved" },
    { 0x0d,     "Reserved" },
    { 0x0e,     "Reserved" },
    { 0x0f,     "Reserved for extension" },
    { 0, NULL }
};

/*
 * C.S0005 Table 2.7.4.4-1 Presentation Indicator
 */
static const value_string ansi_a_ms_info_rec_clg_pn_pi_vals[] = {
    { 0,        "Presentation allowed" },
    { 1,        "Presentation restricted" },
    { 2,        "Number not available" },
    { 3,        "Reserved" },
    { 0, NULL }
};

/*
 * C.S0005 Table 2.7.4.4-2 Screening Indicator
 */
static const value_string ansi_a_ms_info_rec_clg_pn_si_vals[] = {
    { 0,        "User-provided, not screened" },
    { 1,        "User-provided, verified and passed" },
    { 2,        "User-provided, verified and failed" },
    { 3,        "Network-provided" },
    { 0, NULL }
};

static guint8
elem_fwd_ms_info_recs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint8      oct_len;
    guint8      rec_type;
    guint8      num_recs;
    guint32     value;
    guint32     curr_offset, saved_offset;
    const gchar *str;
    gchar       *str_num;
    gint        ett_elem_idx, idx, i;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    num_recs = 0;

    while ((len - (curr_offset - offset)) >= 2)
    {
        saved_offset = curr_offset;

        rec_type = tvb_get_guint8(tvb, curr_offset);

        str = try_val_to_str_idx((guint32) rec_type, ansi_fwd_ms_info_rec_str, &idx);

        if (str == NULL)
        {
            str = "Reserved";
            ett_elem_idx = ett_ansi_ms_info_rec_reserved;
        }
        else
        {
            ett_elem_idx = ett_ansi_fwd_ms_info_rec[idx];
        }

        subtree =
            proto_tree_add_subtree_format(tree, tvb, curr_offset, -1,
                ett_elem_idx, &item,
                "Information Record Type [%u]: (%u) %s",
                num_recs + 1,
                rec_type,
                str);

        curr_offset++;

        oct_len = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_uint(subtree, hf_ansi_a_length, tvb, curr_offset, 1, oct_len);

        curr_offset++;

        if (oct_len > 0)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

            switch (rec_type)
            {
            case ANSI_FWD_MS_INFO_REC_CLD_PN:
                proto_tree_add_item(subtree, hf_ansi_a_fwd_ms_info_rec_cld_pn_num_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_fwd_ms_info_rec_cld_pn_num_plan, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

                if (oct_len > 1)
                {
                    oct = tvb_get_guint8(tvb, curr_offset);

                    proto_tree_add_bits_item(subtree, hf_ansi_a_msb_first_digit, tvb, (curr_offset*8)+7, 1, ENC_NA);

                    curr_offset++;

                    str_num = (gchar*)wmem_alloc(pinfo->pool, oct_len);
                    for (i=0; i < (oct_len - 1); i++)
                    {
                        str_num[i] = (oct & 0x01) << 7;

                        oct = tvb_get_guint8(tvb, curr_offset + i);

                        str_num[i] |= (oct & 0xfe) >> 1;
                    }
                    str_num[i] = '\0';

                    proto_tree_add_string_format(subtree, hf_ansi_a_fwd_ms_info_rec_cld_pn_num, tvb,
                                                 curr_offset, oct_len - 1, str_num, "Digits: %s", str_num);

                    curr_offset += (oct_len - 2);
                }

                proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_01, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
                break;

            case ANSI_FWD_MS_INFO_REC_CLG_PN:
                proto_tree_add_item(subtree, hf_ansi_a_fwd_ms_info_rec_clg_pn_num_type, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_fwd_ms_info_rec_clg_pn_num_plan, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_fwd_ms_info_rec_clg_pn_pi, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_fwd_ms_info_rec_clg_pn_si, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

                if (oct_len > 2)
                {
                    value = tvb_get_ntohs(tvb, curr_offset);

                    oct = (value & 0x00ff);

                    proto_tree_add_bits_item(subtree, hf_ansi_a_msb_first_digit, tvb, (curr_offset*8)+11, 5, ENC_NA);

                    curr_offset += 2;

                    str_num = (gchar*)wmem_alloc(pinfo->pool, oct_len - 1);
                    for (i=0; i < (oct_len - 2); i++)
                    {
                        str_num[i] = (oct & 0x1f) << 3;

                        oct = tvb_get_guint8(tvb, curr_offset + i);

                        str_num[i] |= (oct & 0xe0) >> 5;
                    }
                    str_num[i] = '\0';

                    proto_tree_add_string_format(subtree, hf_ansi_a_fwd_ms_info_rec_clg_pn_num, tvb,
                                                 curr_offset, oct_len - 2, str_num, "Digits: %s", str_num);

                    curr_offset += (oct_len - 3);

                    proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_1f, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                    curr_offset++;
                }
                else
                {
                    proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_16_001f, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                    curr_offset += 2;
                }
                break;

            case ANSI_FWD_MS_INFO_REC_MW:
                proto_tree_add_item(subtree, hf_ansi_a_fwd_ms_info_rec_mw_num, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
                break;

            case ANSI_FWD_MS_INFO_REC_SIGNAL:
                proto_tree_add_item(subtree, hf_ansi_a_ms_info_rec_signal_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_ms_info_rec_signal_alert_pitch, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

                oct = tvb_get_guint8(tvb, curr_offset);

                switch (oct & 0xc0)
                {
                case 0x00:
                    proto_tree_add_item(subtree, hf_ansi_a_ms_info_rec_signal_tone, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                    break;

                case 0x40:
                    proto_tree_add_item(subtree, hf_ansi_a_ms_info_rec_signal_isdn_alert, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                    break;

                case 0x80:
                    proto_tree_add_item(subtree, hf_ansi_a_ms_info_rec_signal_is54b_alert, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                    break;

                default:
                    /* DO NOTHING */
                    break;
                }

                proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_16_003f, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

                curr_offset += oct_len;
                break;

            case ANSI_FWD_MS_INFO_REC_CWI:
                proto_tree_add_item(subtree, hf_ansi_a_ms_info_rec_call_waiting_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_7f, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

                curr_offset += oct_len;
                break;

            default:
                proto_tree_add_item(subtree, hf_ansi_a_fwd_ms_info_rec_content, tvb, curr_offset, oct_len, ENC_NA);

                curr_offset += oct_len;
                break;
            }
        }

        proto_item_set_len(item, curr_offset - saved_offset);

        num_recs++;
    }

    proto_item_append_text(data_p->elem_item, " - %u record%s", num_recs, plurality(num_recs, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.72
 */
static guint8
elem_rev_ms_info_recs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint8      oct_len;
    guint8      rec_type;
    guint8      num_recs;
    guint32     value;
    guint32     curr_offset, saved_offset, saved_offset2;
    const gchar *str;
    gchar       *str_num;
    gint        ett_elem_idx, idx, i;
    proto_item  *item, *item2;
    proto_tree  *subtree, *subtree2;
    guint8      *poctets;

    curr_offset = offset;

    num_recs = 0;

    while ((len - (curr_offset - offset)) >= 2)
    {
        saved_offset = curr_offset;

        rec_type = tvb_get_guint8(tvb, curr_offset);

        str = try_val_to_str_idx((guint32) rec_type, ansi_rev_ms_info_rec_str, &idx);

        if (str == NULL)
        {
            str = "Reserved";
            ett_elem_idx = ett_ansi_ms_info_rec_reserved;
        }
        else
        {
            ett_elem_idx = ett_ansi_rev_ms_info_rec[idx];
        }

        subtree =
            proto_tree_add_subtree_format(tree, tvb, curr_offset, -1,
                ett_elem_idx, &item,
                "Information Record Type [%u]: (%u) %s",
                num_recs + 1,
                rec_type,
                str);

        curr_offset++;

        oct_len = tvb_get_guint8(tvb, curr_offset);

        proto_tree_add_uint(subtree, hf_ansi_a_length, tvb, curr_offset, 1, oct_len);

        curr_offset++;

        if (oct_len > 0)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), oct_len);

            switch (rec_type)
            {
            case ANSI_REV_MS_INFO_REC_KEYPAD_FAC:
                poctets = tvb_get_string_enc(pinfo->pool, tvb, curr_offset, oct_len, ENC_ASCII|ENC_NA);

                proto_tree_add_string_format(subtree, hf_ansi_a_cld_party_ascii_num, tvb, curr_offset, oct_len,
                    (gchar *) poctets,
                    "Digits: %s",
                    (gchar *) format_text(pinfo->pool, poctets, oct_len));

                curr_offset += oct_len;
                break;

            case ANSI_REV_MS_INFO_REC_CLD_PN:
                proto_tree_add_item(subtree, hf_ansi_a_rev_ms_info_rec_cld_pn_num_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_rev_ms_info_rec_cld_pn_num_plan, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

                if (oct_len > 1)
                {
                    oct = tvb_get_guint8(tvb, curr_offset);

                    proto_tree_add_bits_item(subtree, hf_ansi_a_msb_first_digit, tvb, (curr_offset*8)+7, 1, ENC_NA);

                    curr_offset++;

                    str_num = (gchar*)wmem_alloc(pinfo->pool, oct_len);
                    for (i=0; i < (oct_len - 1); i++)
                    {
                        str_num[i] = (oct & 0x01) << 7;

                        oct = tvb_get_guint8(tvb, curr_offset + i);

                        str_num[i] |= (oct & 0xfe) >> 1;
                    }
                    str_num[i] = '\0';

                    proto_tree_add_string_format(subtree, hf_ansi_a_rev_ms_info_rec_cld_pn_num, tvb,
                                                 curr_offset, oct_len - 1, str_num, "Digits: %s", str_num);

                    curr_offset += (oct_len - 2);
                }

                proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_01, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

                curr_offset++;
                break;

            case ANSI_REV_MS_INFO_REC_CLG_PN:
                proto_tree_add_item(subtree, hf_ansi_a_rev_ms_info_rec_clg_pn_num_type, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_rev_ms_info_rec_clg_pn_num_plan, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_rev_ms_info_rec_clg_pn_pi, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_ansi_a_rev_ms_info_rec_clg_pn_si, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

                if (oct_len > 2)
                {
                    value = tvb_get_ntohs(tvb, curr_offset);

                    oct = (value & 0x00ff);

                    proto_tree_add_bits_item(subtree, hf_ansi_a_msb_first_digit, tvb, (curr_offset*8)+11, 5, ENC_NA);

                    curr_offset += 2;

                    str_num = (gchar*)wmem_alloc(pinfo->pool, oct_len - 1);
                    for (i=0; i < (oct_len - 2); i++)
                    {
                        str_num[i] = (oct & 0x1f) << 3;

                        oct = tvb_get_guint8(tvb, curr_offset + i);

                        str_num[i] |= (oct & 0xe0) >> 5;
                    }
                    str_num[i] = '\0';

                    proto_tree_add_string_format(subtree, hf_ansi_a_rev_ms_info_rec_clg_pn_num, tvb,
                                                 curr_offset, oct_len - 2, str_num, "Digits: %s", str_num);

                    curr_offset += (oct_len - 3);

                    proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_8_1f, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

                    curr_offset++;
                }
                else
                {
                    proto_tree_add_item(subtree, hf_ansi_a_reserved_bits_16_001f, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

                    curr_offset += 2;
                }
                break;

            case ANSI_REV_MS_INFO_REC_SO_INFO:
                i = 0;
                saved_offset2 = curr_offset;

                while ((oct_len - (curr_offset - saved_offset2)) > 2)
                {
                    subtree2 = proto_tree_add_subtree_format(subtree, tvb, curr_offset, 3,
                            ett_so_list, &item2, "Service Option [%u]", i + 1);

                    proto_tree_add_item(subtree2, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree2, hf_ansi_a_rev_ms_info_rec_so_info_fwd_support, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree2, hf_ansi_a_rev_ms_info_rec_so_info_rev_support, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

                    curr_offset++;

                    value = tvb_get_ntohs(tvb, curr_offset);

                    str = ansi_a_so_int_to_str(value);

                    proto_tree_add_uint_format(subtree2, hf_ansi_a_rev_ms_info_rec_so_info_so, tvb, curr_offset, 2,
                        value,
                        "%s",
                        str);

                    proto_item_append_text(item2, " - (%u) %s", value, str);

                    i++;
                    curr_offset += 2;
                }
                break;

            default:
                proto_tree_add_item(subtree, hf_ansi_a_rev_ms_info_rec_content, tvb, curr_offset, oct_len, ENC_NA);

                curr_offset += oct_len;
                break;
            }
        }

        proto_item_set_len(item, curr_offset - saved_offset);

        num_recs++;
    }

    proto_item_append_text(data_p->elem_item, " - %u record%s", num_recs, plurality(num_recs, "", "s"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.73
 *
 * IOS 5 4.2.56
 */
static const value_string ansi_a_ext_ho_dir_params_target_bs_values_incl_vals[] = {
    { 0,        "Only Search Window A Size is valid" },
    { 1,        "Subset is valid" },
    { 2,        "All fields valid" },
    { 3,        "Reserved" },
    { 0, NULL }
};

static guint8
elem_ext_ho_dir_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_srch_win_a, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_srch_win_n, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_srch_win_r, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_t_add, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset++;

    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_t_drop, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_t_comp, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_t_tdrop, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_nghbor_max_age, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    switch (global_a_variant)
    {
    case A_VARIANT_IOS401:
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_0f, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;

    case A_VARIANT_IOS501:
        proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_0c, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_target_bs_values_incl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_soft_slope, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_add_intercept, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_drop_intercept, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_ext_ho_dir_params_target_bs_p_rev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
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
static const value_string ansi_a_cdma_sowd_resolution_vals[] = {
    { 0,        "100 nsec" },
    { 1,        "50 nsec" },
    { 2,        "1/16 CDMA PN Chip" },
    { 3,        "Reserved" },
    { 0, NULL }
};

static guint8
elem_cdma_sowd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint8      disc;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_cell_id_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    disc = tvb_get_guint8(tvb, curr_offset);

    curr_offset += 1;

    curr_offset +=
        elem_cell_id_aux(tvb, pinfo, tree, curr_offset, len - (curr_offset - offset), disc, NULL);

    proto_tree_add_item(tree, hf_ansi_a_cdma_sowd_sowd, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset += 2;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cdma_sowd_resolution, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((len - (curr_offset - offset)) > 1)
    {
        proto_tree_add_item(tree, hf_ansi_a_cdma_sowd_timestamp, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

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
static const value_string ansi_a_re_res_vals[] = {
    { 0,        "Not reported" },
    { 1,        "Radio environment is acceptable" },
    { 2,        "Radio environment is marginally acceptable" },
    { 3,        "Radio environment is poor" },
    { 0, NULL }
};

static guint8
elem_re_res(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint len _U_, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_re_res_prio_incl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_re_res_forward, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_re_res_reverse, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_re_res_alloc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_re_res_avail, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

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
 *
 * IOS 5 4.2.59
 */
static guint8
elem_cld_party_ascii_num(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;
    guint8      *poctets;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_ansi_a_cld_party_ascii_num_ton, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cld_party_ascii_num_plan, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    poctets = tvb_get_string_enc(pinfo->pool, tvb, curr_offset, len - (curr_offset - offset), ENC_ASCII|ENC_NA);

    proto_tree_add_string_format(tree, hf_ansi_a_cld_party_ascii_num, tvb, curr_offset, len - (curr_offset - offset),
        (gchar *) poctets,
        "Digits: %s",
        (gchar *) format_text(pinfo->pool, poctets, len - (curr_offset - offset)));

    proto_item_append_text(data_p->elem_item, " - (%s)", poctets);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.106
 */
static guint8
elem_band_class(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_e0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_band_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%s)",
        val_to_str_const(oct & 0x1f, ansi_a_band_class_vals, "Reserved"));

    curr_offset++;

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
 *
 * IOS 5 4.2.60
 */
static guint8
elem_is2000_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_is2000_cause, tvb, curr_offset, len, ENC_NA);

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
elem_auth_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint8              oct;
    guint32             curr_offset;
    const gchar         *str;

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

        proto_tree_add_bytes_format(tree, hf_ansi_a_auth_event, tvb, curr_offset, len,
            NULL,
            "%s",
            str);
    }
    else
    {
        proto_tree_add_item(tree, hf_ansi_a_auth_event, tvb, curr_offset, len, ENC_NA);
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
 * IOS 5 4.2.62
 * Generic decode is good enough
 */

/*
 * IOS 6.2.2.138
 */
static guint8
elem_psmm_count(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_psmm_count, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.139
 */
static guint8
elem_geo_loc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_geo_loc, tvb, curr_offset, len, ENC_NA);

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
elem_cct_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    proto_item  *item;
    proto_tree  *subtree;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cct_group_all_circuits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_cct_group_inclusive, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format(tree, hf_ansi_a_cct_group_count, tvb, curr_offset, 1,
        oct,
        "Count: %u circuit%s",
        oct,
        plurality(oct, "", "s"));

    proto_item_append_text(data_p->elem_item, " - %u circuit%s", oct, plurality(oct, "", "s"));

    curr_offset++;

    item = proto_tree_add_item(tree, hf_ansi_a_cct_group_first_cic, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_cic);

    proto_tree_add_item(subtree, hf_ansi_a_cct_group_first_cic_pcm_multi, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cct_group_first_cic_timeslot, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    curr_offset += 2;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_ansi_a_circuit_bitmap, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

    curr_offset += len - (curr_offset - offset);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.149
 */
static guint8
elem_paca_ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_paca_timestamp_queuing_time, tvb, curr_offset, 4, ENC_BIG_ENDIAN);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.150
 */
static const value_string ansi_a_paca_order_action_reqd_vals[] = {
    { 0,        "Reserved" },
    { 1,        "Update Queue Position and notify MS" },
    { 2,        "Remove MS from the queue and release MS" },
    { 3,        "Remove MS from the queue" },
    { 4,        "MS Requested PACA Cancel" },
    { 5,        "BS Requested PACA Cancel" },
    { 6,        "Reserved" },
    { 7,        "Reserved" },
    { 0, NULL }
};

static guint8
elem_paca_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_f8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_paca_order_action_reqd, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%s)",
        val_to_str_const(oct & 0x07, ansi_a_paca_order_action_reqd_vals, "Reserved"));

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 6.2.2.151
 */
static guint8
elem_paca_reoi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_fe, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_paca_reoi_pri, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_item_append_text(data_p->elem_item, " - (%sReorigination)", (oct & 0x01) ? "" : "Not ");

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.89
 */
static guint8
elem_a2p_bearer_session(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_sess_max_frames, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_sess_ip_addr_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_sess_addr_flag, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, curr_offset);

    curr_offset++;

    if (oct & 0x01)
    {
        /* session address included */

        if ((oct & 0x06) >> 1)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), 18);

            proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_sess_ipv6_addr, tvb, curr_offset, 16, ENC_NA);

            data_p->rtp_src_addr.type = AT_IPv6;
            data_p->rtp_src_addr.len = 16;
            data_p->rtp_src_addr.data = (guint8 *) &data_p->rtp_ipv6_addr;

            tvb_get_ipv6(tvb, curr_offset, &data_p->rtp_ipv6_addr);

            curr_offset += 16;
        }
        else
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), 6);

            proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_sess_ipv4_addr, tvb, curr_offset, 4, ENC_BIG_ENDIAN);

            data_p->rtp_src_addr.type = AT_IPv4;
            data_p->rtp_src_addr.len = 4;
            data_p->rtp_src_addr.data = (guint8 *) &data_p->rtp_ipv4_addr;

            data_p->rtp_ipv4_addr = tvb_get_ipv4(tvb, curr_offset);

            curr_offset += 4;
        }

        proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_sess_udp_port, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

        data_p->rtp_port = tvb_get_ntohs(tvb, curr_offset);

        curr_offset += 2;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.90
 */
static const value_string ansi_a_a2p_bearer_form_format_tag_type_vals[] = {
    { 0,        "Unknown" },
    { 1,        "In-band signaling" },
    { 2,        "Assigned" },
    { 3,        "Unassigned" },
    { 4,        "Transcoded" },
    { 5,        "Reserved" },
    { 6,        "Reserved" },
    { 7,        "Reserved" },
    { 0, NULL }
};

/*
 * IOS 5 Table 4.2.90-3
 *  Bearer Format ID, Encoding Name from IANA
 */
static const value_string ansi_a_a2p_bearer_form_format_format_id_vals[] = {
    { 0,        "PCMU" },
    { 1,        "PCMA" },
    { 2,        "13K Vocoder" },        /* aka QCELP */
    { 3,        "EVRC" },
    { 4,        "EVRC0" },
    { 5,        "SMV" },
    { 6,        "SMV0" },
    { 7,        "telephone-event" },
        /*
         * the following Bearer Format IDs have been assumed/used by Star Solutions, however,
         * 3GPP2 has not yet updated the IOS specifications for these vocoders
         * (the MIME types are in IANA)
         */
    { 8,        "EVRCB" },
    { 9,        "EVRCB0" },
    { 10,       "EVRCWB" },
    { 11,       "EVRCWB0" },
    { 12,       "EVRCNW" },
    { 13,       "EVRCNW0" },
    { 14,       "EVRCNW2K" },
    { 15,       "EVRCNW2K0" },
    { 0, NULL }
};

static guint8
elem_a2p_bearer_format(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8                              oct;
    proto_item                          *item;
    proto_tree                          *subtree;
    guint8                              num_bearers;
    guint32                             curr_offset, orig_offset;
    guint8                              ip_addr_type;
    gboolean                            ext;
    guint8                              ext_len;
    const gchar                         *mime_type;
    int                                 sample_rate;
    gboolean                            format_assigned;
    gboolean                            in_band_format_assigned;
    gboolean                            first_assigned_found;
    gboolean                            rtp_dyn_payload_used;
    guint8                              rtp_payload_type;
    rtp_dyn_payload_t                  *rtp_dyn_payload;

    rtp_dyn_payload = rtp_dyn_payload_new();
    rtp_dyn_payload_used = FALSE;

    first_assigned_found = FALSE;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_form_num_formats, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_a2p_bearer_form_ip_addr_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    ip_addr_type = tvb_get_guint8(tvb, curr_offset) & 0x03;

    curr_offset++;

    num_bearers = 0;

    while ((len - (curr_offset - offset)) > 0)
    {
        orig_offset = curr_offset;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1,
                ett_bearer_list, &item, "Bearer Format [%u]", num_bearers + 1);

        proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;

        NO_MORE_DATA_CHECK(len);

        proto_tree_add_item(subtree, hf_ansi_a_extension_8_80, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_tag_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_format_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        oct = tvb_get_guint8(tvb, curr_offset);

        ext = (oct & 0x80) ? TRUE : FALSE;

        format_assigned = FALSE;
        in_band_format_assigned = FALSE;

        switch ((oct & 0x70) >> 4)
        {
        case 1:
            in_band_format_assigned = TRUE;
            break;
        case 2:
            format_assigned = TRUE;
            break;
        }

        /*
         * sampling rates are based on the specific vocoder RFCs
         * (example subset RFC4788, RFC5188, RFC6884)
         */
        if (((oct & 0x0f) >= 10))
        {
            sample_rate = 16000;
        }
        else
        {
            sample_rate = 8000;
        }

        mime_type = val_to_str_const(oct & 0xf, ansi_a_a2p_bearer_form_format_format_id_vals, "Reserved");
        proto_item_append_text(item, " - (%s)", mime_type);
        curr_offset++;

        NO_MORE_DATA_CHECK(len);

        proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_rtp_payload_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_bearer_addr_flag, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        oct = tvb_get_guint8(tvb, curr_offset);

        rtp_payload_type = (oct & 0xfe) >> 1;

        curr_offset++;

        if (oct & 0x01)
        {
            /* bearer address included */

            if (ip_addr_type != 0)
            {
                SHORT_DATA_CHECK(len - (curr_offset - offset), 18);

                proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_ipv6_addr, tvb, curr_offset, 16, ENC_NA);

                if (format_assigned)
                {
                    data_p->rtp_src_addr.type = AT_IPv6;
                    data_p->rtp_src_addr.len = 16;
                    data_p->rtp_src_addr.data = (guint8 *) &data_p->rtp_ipv6_addr;

                    tvb_get_ipv6(tvb, curr_offset, &data_p->rtp_ipv6_addr);
                }

                curr_offset += 16;
            }
            else
            {
                SHORT_DATA_CHECK(len - (curr_offset - offset), 6);

                proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_ipv4_addr, tvb, curr_offset, 4, ENC_BIG_ENDIAN);

                if (format_assigned)
                {
                    data_p->rtp_src_addr.type = AT_IPv4;
                    data_p->rtp_src_addr.len = 4;
                    data_p->rtp_src_addr.data = (guint8 *) &data_p->rtp_ipv4_addr;

                    data_p->rtp_ipv4_addr = tvb_get_ipv4(tvb, curr_offset);
                }

                curr_offset += 4;
            }

            proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_udp_port, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

            if (format_assigned)
            {
                data_p->rtp_port = tvb_get_ntohs(tvb, curr_offset);
            }

            curr_offset += 2;
        }

        if (ext)
        {
            SHORT_DATA_CHECK(len - (curr_offset - offset), 1);

            proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_ext_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_ansi_a_a2p_bearer_form_format_ext_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

            oct = tvb_get_guint8(tvb, curr_offset);

            ext_len = (oct & 0xf0) >> 4;

            curr_offset++;

            if (ext_len > 0)
            {
                SHORT_DATA_CHECK(len - (curr_offset - offset), ext_len);

                proto_tree_add_item(subtree, hf_ansi_a_extension_parameter_value, tvb, curr_offset, ext_len, ENC_NA);

                curr_offset += ext_len;
            }
        }

        proto_item_set_len(item, curr_offset - orig_offset);

        if (format_assigned &&
            (first_assigned_found == FALSE))
        {
            rtp_dyn_payload_insert(rtp_dyn_payload, rtp_payload_type, mime_type, sample_rate);
            rtp_dyn_payload_used = TRUE;

            first_assigned_found = TRUE;
            rtp_add_address(pinfo, PT_UDP, &data_p->rtp_src_addr, data_p->rtp_port, 0, "IOS5",
                pinfo->num, FALSE, rtp_dyn_payload);
        }

        if (in_band_format_assigned)
        {
            rtp_dyn_payload_insert(rtp_dyn_payload, rtp_payload_type, "telephone-event", sample_rate);
            rtp_dyn_payload_used = TRUE;
        }

        num_bearers++;
    }

    if (rtp_dyn_payload_used == FALSE)
    {
        rtp_dyn_payload_free(rtp_dyn_payload);
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.88
 */
static guint8
elem_ms_des_freq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_ms_des_freq_band_class, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_ms_des_freq_cdma_channel, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    proto_item_append_text(data_p->elem_item, " - (CDMA Channel: %u)",
        tvb_get_ntohs(tvb, curr_offset) & 0x07ff);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IOS 5 4.2.87
 */
static const value_string ansi_a_plcm_id_plcm_type_vals[] = {
    { 0,        "PLCM derived from ESN or MEID" },
    { 1,        "PLCM specified by the base station" },
    { 2,        "PLCM derived from IMSI_O_S when IMSI_O is derived from IMSI_M" },
    { 3,        "PLCM derived from IMSI_O_S when IMSI_O is derived from IMSI_T" },
    { 0, NULL }
};

static guint8
elem_plcm_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint8      oct;
    guint32     curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    /*
     * from C.S0005-D v1.0 L3 Table 3.7.2.3.2.21-5
     */
    str = val_to_str_const((oct & 0xf0) >> 4, ansi_a_plcm_id_plcm_type_vals, "Reserved");
    proto_tree_add_uint_format_value(tree, hf_ansi_a_plcm_id_plcm_type, tvb, curr_offset, 1,
        oct, "%s", str);

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_0c, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_plcm42, tvb, curr_offset, 6, ENC_BIG_ENDIAN);

    curr_offset += 6;

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
 * IS-634.400A 6.2.2.56
 */
static const value_string ansi_a_bdtmf_trans_info_dtmf_off_len_vals[] = {
    { 0,        "60ms" },
    { 1,        "100ms" },
    { 2,        "150ms" },
    { 3,        "200ms" },
    { 4,        "Reserved" },
    { 5,        "Reserved" },
    { 6,        "Reserved" },
    { 7,        "Reserved" },
    { 0, NULL }
};

static const value_string ansi_a_bdtmf_trans_info_dtmf_on_len_vals[] = {
    { 0,        "95ms" },
    { 1,        "150ms" },
    { 2,        "200ms" },
    { 3,        "250ms" },
    { 4,        "300ms" },
    { 5,        "350ms" },
    { 6,        "Reserved" },
    { 7,        "Reserved" },
    { 0, NULL }
};

static guint8
elem_bdtmf_trans_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_reserved_bits_8_c0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_bdtmf_trans_info_dtmf_off_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_a_bdtmf_trans_info_dtmf_on_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

/*
 * IS-634.400A 6.2.2.57
 *
 * XXX - is this specified in some document that doesn't cost over
 * USD 500 for either a dead-tree copy or a "Secure PDF" that probably
 * can only be read with the help of a Windows-only plugin for Adobe
 * Acrobat reader?
 */
static guint8
elem_dtmf_chars(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint32     curr_offset;
    guint8      packed_len;
    char       *str;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_ansi_a_bdtmf_chars_num_chars, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    oct = tvb_get_guint8(tvb, curr_offset);
    curr_offset++;

    if (curr_offset - offset >= len) /* Sanity check */
        return (curr_offset - offset);

    packed_len = len - (curr_offset - offset);
    str = (char*)tvb_bcd_dig_to_str(pinfo->pool, tvb, curr_offset, packed_len, &Dgt_dtmf, FALSE);
    /*
     * the packed DTMF digits are not "terminated" with a '0xF' for an odd
     * number of digits but the unpack routine expects it
     *
     * XXX - is "oct" a count of digits?  If so, we could use it, although
     * we'd also need to check whether it claims that there are more
     * digits than are present in the information element based on its
     * length.
     */
    if (oct & 0x01)
    {
        str[(2*packed_len)-1] = '\0';
    }

    proto_tree_add_string(tree, hf_ansi_a_bdtmf_chars_digits, tvb, curr_offset, packed_len, str);
    proto_item_append_text(data_p->elem_item, " - (%s)", str);

    curr_offset += packed_len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset - offset);
}

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
    ANSI_A_E_REV_MS_INFO_RECS,      /* (Reverse) MS Information Records */
    ANSI_A_E_BDTMF_TRANS_INFO,      /* Burst DTMF Transmission Information IS-634.400A 6.2.2.56 */
    ANSI_A_E_DTMF_CHARS,            /* DTMF Characters IS-634.400A 6.2.2.57 */
    ANSI_A_E_A2P_BEARER_SESSION,    /* A2p Bearer Session-Level Parameters */
    ANSI_A_E_A2P_BEARER_FORMAT,     /* A2p Bearer Format-Specific Parameters */
    ANSI_A_E_MS_DES_FREQ,           /* MS Designated Frequency */
    ANSI_A_E_MOB_SUB_INFO,          /* Mobile Subscription Information */
    ANSI_A_E_PLCM_ID,               /* Public Long Code Mask Identifier */
    ANSI_A_E_NONE                   /* NONE */
}
elem_idx_t;
static elem_idx_t ansi_a_elem_1_max = (elem_idx_t) 0;

#define MAX_IOS401_NUM_ELEM_1 (sizeof(ansi_a_ios401_elem_1_strings)/sizeof(ext_value_string_t))
#define MAX_IOS501_NUM_ELEM_1 (sizeof(ansi_a_ios501_elem_1_strings)/sizeof(ext_value_string_t))
static gint ett_ansi_elem_1[MAX(MAX_IOS401_NUM_ELEM_1, MAX_IOS501_NUM_ELEM_1)];
static guint8 (*elem_1_fcn[])(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p) =
{
    elem_acc_net_id,                /* Access Network Identifiers */
    elem_adds_user_part,            /* ADDS User Part */
    elem_amps_hho_params,           /* AMPS Hard Handoff Parameters */
    elem_anchor_pdsn_addr,          /* Anchor PDSN Address */
    elem_anchor_pp_addr,            /* Anchor P-P Address */
    elem_auth_chlg_param,           /* Authentication Challenge Parameter */
    elem_auth_conf_param,           /* Authentication Confirmation Parameter (RANDC) */
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
    elem_rev_ms_info_recs,          /* (Reverse) MS Information Records */
    elem_bdtmf_trans_info,          /* Burst DTMF Transmission Information */
    elem_dtmf_chars,                /* DTMF Characters */
    elem_a2p_bearer_session,        /* A2p Bearer Session-Level Parameters */
    elem_a2p_bearer_format,         /* A2p Bearer Format-Specific Parameters */
    elem_ms_des_freq,               /* MS Designated Frequency */
    NULL,                           /* Mobile Subscription Information */
    elem_plcm_id,                   /* Public Long Code Mask Identification */
    NULL         /* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * Type Length Value (TLV) element dissector
 */
static guint16
elem_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, elem_idx_t idx, guint32 offset, guint len _U_, const gchar *name_add, ansi_a_shared_data_t *data_p)
{
    guint8      oct, parm_len;
    guint16     consumed;
    guint32     curr_offset;
    proto_tree  *subtree;
    gint        dec_idx;

    curr_offset = offset;
    consumed = 0;

    if ((int) idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_reported_length_remaining(tvb, offset);
    }

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == (guint8) ansi_a_elem_1_strings[idx].value)
    {
        dec_idx = ansi_a_elem_1_strings[idx].dec_index;

        parm_len = tvb_get_guint8(tvb, curr_offset + 1);

        subtree =
            proto_tree_add_subtree_format(tree, tvb, curr_offset, parm_len + 2,
                ett_ansi_elem_1[idx], &data_p->elem_item, "%s%s",
                ansi_a_elem_1_strings[idx].strptr,
                (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        proto_tree_add_uint(subtree, hf_ansi_a_elem_id, tvb, curr_offset, 1, oct);

        proto_tree_add_uint(subtree, hf_ansi_a_length, tvb, curr_offset + 1, 1, parm_len);

        if (parm_len > 0)
        {
            if (elem_1_fcn[dec_idx] == NULL)
            {
                proto_tree_add_expert_format(subtree, pinfo, &ei_ansi_a_no_tlv_elem_diss, tvb, curr_offset + 2, parm_len,
                    "Element Value");

                consumed = parm_len;
            }
            else
            {
                consumed = (*elem_1_fcn[dec_idx])(tvb, pinfo, subtree, curr_offset + 2, parm_len, data_p);
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
static guint16
elem_tv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, elem_idx_t idx, guint32 offset, const gchar *name_add, ansi_a_shared_data_t *data_p)
{
    guint8      oct;
    guint16     consumed;
    guint32     curr_offset;
    proto_tree  *subtree;
    gint        dec_idx;


    curr_offset = offset;
    consumed = 0;

    if ((int) idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_reported_length_remaining(tvb, offset);
    }

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == (guint8) ansi_a_elem_1_strings[idx].value)
    {
        dec_idx = ansi_a_elem_1_strings[idx].dec_index;

        subtree =
            proto_tree_add_subtree_format(tree,
                tvb, curr_offset, -1,
                ett_ansi_elem_1[idx], &data_p->elem_item, "%s%s",
                ansi_a_elem_1_strings[idx].strptr,
                (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        proto_tree_add_uint(subtree, hf_ansi_a_elem_id, tvb, curr_offset, 1, oct);

        if (elem_1_fcn[dec_idx] == NULL)
        {
            /* BAD THING, CANNOT DETERMINE LENGTH */

            proto_tree_add_expert_format(subtree, pinfo, &ei_ansi_a_no_tv_elem_diss, tvb, curr_offset + 1, 1,
                "No element dissector, rest of dissection may be incorrect");

            consumed = 1;
        }
        else
        {
            consumed = (*elem_1_fcn[dec_idx])(tvb, pinfo, subtree, curr_offset + 1, -1, data_p);
        }

        consumed++;

        proto_item_set_len(data_p->elem_item, consumed);
    }

    return(consumed);
}

/*
 * Type (T) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
static guint16
elem_t(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, elem_idx_t idx, guint32 offset, const gchar *name_add, ansi_a_shared_data_t *data_p _U_)
{
    guint8      oct;
    guint32     curr_offset;
    guint16     consumed;


    curr_offset = offset;
    consumed = 0;

    if ((int) idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_reported_length_remaining(tvb, offset);
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
static guint16
elem_lv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, elem_idx_t idx, guint32 offset, guint len _U_, const gchar *name_add, ansi_a_shared_data_t *data_p)
{
    guint8      parm_len;
    guint16     consumed;
    guint32     curr_offset;
    proto_tree  *subtree;
    gint        dec_idx;


    curr_offset = offset;
    consumed = 0;

    if ((int) idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_reported_length_remaining(tvb, offset);
    }

    dec_idx = ansi_a_elem_1_strings[idx].dec_index;

    parm_len = tvb_get_guint8(tvb, curr_offset);

    subtree =
        proto_tree_add_subtree_format(tree, tvb, curr_offset, parm_len + 1,
            ett_ansi_elem_1[idx], &data_p->elem_item, "%s%s",
            ansi_a_elem_1_strings[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

    proto_tree_add_uint(subtree, hf_ansi_a_length, tvb,
        curr_offset, 1, parm_len);

    if (parm_len > 0)
    {
        if (elem_1_fcn[dec_idx] == NULL)
        {
            proto_tree_add_expert_format(subtree, pinfo, &ei_ansi_a_no_lv_elem_diss, tvb, curr_offset + 1, parm_len,
                "Element Value");

            consumed = parm_len;
        }
        else
        {
            consumed = (*elem_1_fcn[dec_idx])(tvb, pinfo, subtree, curr_offset + 1, parm_len, data_p);
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
static guint16
elem_v(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, elem_idx_t idx, guint32 offset, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
    guint32     curr_offset;
    gint        dec_idx;

    curr_offset = offset;

    if ((int) idx < 0 || idx >= ansi_a_elem_1_max-1)
    {
        /* Unknown index, skip the element */
        return tvb_reported_length_remaining(tvb, offset) ;
    }

    dec_idx = ansi_a_elem_1_strings[idx].dec_index;

    data_p->elem_item = NULL;

    if (elem_1_fcn[dec_idx] == NULL)
    {
        /* BAD THING, CANNOT DETERMINE LENGTH */

        proto_tree_add_expert_format(tree, pinfo, &ei_ansi_a_no_v_elem_diss, tvb, curr_offset, 1,
            "No element dissector, rest of dissection may be incorrect");

        consumed = 1;
    }
    else
    {
        consumed = (*elem_1_fcn[dec_idx])(tvb, pinfo, tree, curr_offset, -1, data_p);
    }

    return(consumed);
}


#define ELEM_MAND_TLV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_tlv(tvb, pinfo, tree, elem_idx, curr_offset, curr_len, elem_name_addition, data_p)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_ansi_a_missing_mand_elem, \
            tvb, curr_offset, 0, \
            "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
                ansi_a_elem_1_strings[elem_idx].value, \
                ansi_a_elem_1_strings[elem_idx].strptr, \
                elem_name_addition \
            ); \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_TLV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_tlv(tvb, pinfo, tree, elem_idx, curr_offset, curr_len, elem_name_addition, data_p)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_MAND_TV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_tv(tvb, pinfo, tree, elem_idx, curr_offset, elem_name_addition, data_p)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    else \
    { \
        proto_tree_add_expert_format(tree, pinfo, &ei_ansi_a_missing_mand_elem, \
            tvb, curr_offset, 0, \
            "Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
                ansi_a_elem_1_strings[elem_idx].value, \
                ansi_a_elem_1_strings[elem_idx].strptr, \
                elem_name_addition \
            ); \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_TV(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_tv(tvb, pinfo, tree, elem_idx, curr_offset, elem_name_addition, data_p)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_OPT_T(elem_idx, elem_name_addition) \
{\
    if ((consumed = elem_t(tvb, pinfo, tree, elem_idx, curr_offset, elem_name_addition, data_p)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
    if (curr_len <= 0) return; \
}

#define ELEM_MAND_LV(elem_idx, elem_name_addition) \
{\
    if ((consumed = (data_p->from_sip ? \
                         elem_tlv(tvb, pinfo, tree, elem_idx, curr_offset, curr_len, elem_name_addition, data_p) : \
                         elem_lv(tvb, pinfo, tree, elem_idx, curr_offset, curr_len, elem_name_addition, data_p))) > 0) \
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
    if ((consumed = (data_p->from_sip ? \
                         elem_tv(tvb, pinfo, tree, elem_idx, curr_offset, "", data_p) : \
                         elem_v(tvb, pinfo, tree, elem_idx, curr_offset, data_p))) > 0) \
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
bsmap_cl3_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;
    guint16     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    if (!data_p->from_sip)
    {
        /*
         * With femtoInterfaceMsg application, the Information Elements for the
         * Complete Layer 3 Information message shall not be included
         */
        ELEM_MAND_TLV(ANSI_A_E_CELL_ID, "");

        ELEM_MAND_TLV(ANSI_A_E_L3_INFO, "");
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IOS 6.1.2.2
 */
static const value_string dtap_cm_service_type_vals[] = {
    { 1,        "Mobile Originating Call" },
    { 2,        "Emergency call establishment" },
    { 4,        "Short Message transfer" },
    { 8,        "Supplementary Service activation" },
    { 0, NULL }
};

static void
dtap_cm_srvc_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;
    guint8      oct;
    proto_tree  *subtree;

    curr_offset = offset;
    curr_len = len;

    /*
     * special dissection for CM Service Type
     */
    oct = tvb_get_guint8(tvb, curr_offset);
    subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 1, ett_cm_srvc_type, NULL,
            "CM Service Type: %s", val_to_str_const(oct & 0x0f, dtap_cm_service_type_vals, "Unknown"));

    proto_tree_add_item(subtree, hf_ansi_a_elem_id_f0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_a_cm_svrc_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

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
dtap_cm_srvc_req_cont(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_page_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_page_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_progress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_srvc_redirection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_srvc_release(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_srvc_release_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ass_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
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
bsmap_ass_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
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
bsmap_ass_failure(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
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
bsmap_clr_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
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
bsmap_clr_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
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
bsmap_clr_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint16     consumed;
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
dtap_alert_with_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_bs_srvc_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_bs_srvc_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_add_srvc_noti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_add_srvc_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_connect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_flash_with_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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

    if (data_p->is_reverse)
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
dtap_flash_with_info_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_feat_noti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_feat_noti_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_paca_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_paca_command_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_paca_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_paca_update_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_rm_pos_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_rm_pos_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_auth_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_auth_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_auth_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_bearer_upd_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_bearer_upd_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_bearer_upd_reqd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_auth_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_user_zone_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_user_zone_update_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_user_zone_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
 * IS-634.400A 6.1.3.1
 */
static void
dtap_send_burst_dtmf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_BDTMF_TRANS_INFO, "");

    ELEM_MAND_LV(ANSI_A_E_DTMF_CHARS, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IS-634.400A 6.1.3.2
 */
static void
dtap_send_burst_dtmf_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
 * IS-634.400A 6.1.3.3
 */
static void
dtap_start_dtmf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(ANSI_A_E_DTMF_CHARS, "");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * IS-634.400A 6.1.3.4
 */
static void
dtap_start_dtmf_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
 * IS-634.400A 6.1.3.6
 */
static void
dtap_stop_dtmf_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
 * IOS 5 3.3.18
 */
static void
bsmap_user_zone_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_user_zone_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_reg_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ms_reg_noti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_bs_auth_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_bs_auth_req_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_ssd_update_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_bs_challenge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_bs_challenge_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_ssd_update_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_lu_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_lu_accept(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_lu_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_priv_mode_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_priv_mode_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_status_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_status_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_status_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_status_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ho_reqd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ho_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ho_req_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ho_failure(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ho_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ho_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ho_reqd_rej(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_ho_performed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_block_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_unblock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_unblock_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_reset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_reset_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_reset_cct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_reset_cct_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_xmode_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_xmode_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_adds_page(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_adds_transfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_adds_transfer_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_adds_deliver(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_adds_page_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_adds_deliver_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
bsmap_rejection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
dtap_rejection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p)
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
static void (*bsmap_msg_fcn[])(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p) =
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
    NULL        /* NONE */
};

#define ANSI_A_IOS401_DTAP_NUM_MSG (sizeof(ansi_a_ios401_dtap_strings)/sizeof(ext_value_string_t))
#define ANSI_A_IOS501_DTAP_NUM_MSG (sizeof(ansi_a_ios501_dtap_strings)/sizeof(ext_value_string_t))
static gint ett_dtap_msg[MAX(ANSI_A_IOS401_DTAP_NUM_MSG, ANSI_A_IOS501_DTAP_NUM_MSG)];
static void (*dtap_msg_fcn[])(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len, ansi_a_shared_data_t *data_p) =
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
    dtap_send_burst_dtmf,           /* Send Burst DTMF */
    dtap_send_burst_dtmf_ack,       /* Send Burst DTMF Ack */
    dtap_start_dtmf,                /* Start DTMF */
    dtap_start_dtmf_ack,            /* Start DTMF Ack */
    NULL /* no associated data */,  /* Stop DTMF */
    dtap_stop_dtmf_ack,             /* Stop DTMF Ack */
    NULL        /* NONE */
};

/* Utillity function to dissect CDMA200 A1 elements in ANSI MAP messages */
void
dissect_cdma2000_a1_elements(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len)
{
    guint32                     curr_offset;
    guint32                     consumed;
    guint                       curr_len;
    unsigned                    idx;
    guint8                      oct;
    ansi_a_shared_data_t        shared_data;
    ansi_a_shared_data_t        *data_p;

    memset((void *) &shared_data, 0, sizeof(shared_data));
    data_p = &shared_data;

    shared_data.g_tree = tree;

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

        for (idx=0; idx < (unsigned) ansi_a_elem_1_max; idx++)
        {
            if (oct == (guint8) ansi_a_elem_1_strings[idx].value)
            {
                ELEM_OPT_TLV((elem_idx_t) idx, "");
                break;
            }
        }

        if (idx == (elem_idx_t) ansi_a_elem_1_max)
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
dissect_bsmap_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean from_sip)
{
    static ansi_a_tap_rec_t     tap_rec[16];
    static ansi_a_tap_rec_t     *tap_p;
    static int                  tap_current = 0;
    guint8                      oct;
    guint32                     offset;
    guint32                     len;
    gint                        dec_idx;
    proto_item                  *bsmap_item = NULL;
    proto_tree                  *bsmap_tree = NULL;
    const gchar                 *msg_str;
    ansi_a_shared_data_t        shared_data;

    memset((void *) &shared_data, 0, sizeof(shared_data));

    shared_data.g_tree = tree;
    shared_data.from_sip = from_sip;

    /*
     * determine if this is a REVERSE link message (from BSC/mobile)
     */
    shared_data.is_reverse = (pinfo->p2p_dir == P2P_DIR_RECV);

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

    len = tvb_reported_length(tvb);
    offset = 0;

    /*
     * add BSMAP message name
     */
    oct = tvb_get_guint8(tvb, offset);

    msg_str = my_try_val_to_str_idx((guint32) oct, ansi_a_bsmap_strings, &dec_idx);

    /*
     * create the a protocol tree
     */
    if (msg_str == NULL)
    {
        bsmap_item =
            proto_tree_add_expert_format(tree, pinfo, &ei_ansi_a_unknown_bsmap_msg, tvb, 0, len,
                "ANSI A-I/F BSMAP - Unknown BSMAP Message Type (%u)",
                oct);

        bsmap_tree = proto_item_add_subtree(bsmap_item, ett_bsmap);
    }
    else
    {
        bsmap_item =
            proto_tree_add_protocol_format(tree, proto_a_bsmap, tvb, 0, len,
                "ANSI A-I/F BSMAP - %s",
                msg_str);

        bsmap_tree = proto_item_add_subtree(bsmap_item, ett_bsmap_msg[dec_idx]);

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
    }

    shared_data.message_item = bsmap_item;

    proto_tree_add_item(bsmap_tree, hf_ansi_a_bsmap_msgtype, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    tap_p->pdu_type = BSSAP_PDU_TYPE_BSMAP;
    tap_p->message_type = oct;

    tap_queue_packet(ansi_a_tap, pinfo, tap_p);

    if (msg_str == NULL) return;

    if ((len - offset) <= 0) return;

    /*
     * decode elements
     */
    if (bsmap_msg_fcn[dec_idx] == NULL)
    {
        proto_tree_add_expert_format(bsmap_tree, pinfo, &ei_ansi_a_miss_bsmap_msg_diss, tvb, offset, len - offset,
            "Message Elements");
    }
    else
    {
        (*bsmap_msg_fcn[dec_idx])(tvb, pinfo, bsmap_tree, offset, len - offset, &shared_data);
    }
}

static int
dissect_bsmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_bsmap_common(tvb, pinfo, tree, FALSE);
    return tvb_captured_length(tvb);
}

static void
dissect_dtap_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean from_sip)
{
    static ansi_a_tap_rec_t     tap_rec[16];
    static ansi_a_tap_rec_t     *tap_p;
    static int                  tap_current = 0;
    guint8                      oct, oct_1 = 0;
    guint32                     offset;
    guint32                     len;
    gint                        dec_idx;
    proto_item                  *dtap_item = NULL;
    proto_tree                  *dtap_tree = NULL;
    proto_item                  *oct_1_item = NULL;
    proto_tree                  *oct_1_tree = NULL;
    const gchar                 *msg_str;
    const gchar                 *str;
    ansi_a_shared_data_t        shared_data;

    len = tvb_reported_length(tvb);

    if ((len < 3) && !from_sip)
    {
        /*
         * too short to be DTAP
         */
        call_data_dissector(tvb, pinfo, tree);
        return;
    }

    memset((void *) &shared_data, 0, sizeof(shared_data));

    shared_data.g_tree = tree;
    shared_data.from_sip = from_sip;

    /*
     * determine if this is a REVERSE link message (from BSC/mobile)
     */
    shared_data.is_reverse = (pinfo->p2p_dir == P2P_DIR_RECV);

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

    /*
     * get protocol discriminator
     */
    if (!from_sip)
    {
        oct_1 = tvb_get_guint8(tvb, offset);
        offset++;
        offset++;       /* octet '2' */
    }

    /*
     * add DTAP message name
     */
    oct = tvb_get_guint8(tvb, offset);

    msg_str = my_try_val_to_str_idx((guint32) oct, ansi_a_dtap_strings, &dec_idx);

    /*
     * create the a protocol tree
     */
    if (msg_str == NULL)
    {
        dtap_item =
            proto_tree_add_expert_format(tree, pinfo, &ei_ansi_a_unknown_dtap_msg, tvb, 0, len,
                "ANSI A-I/F DTAP - Unknown DTAP Message Type (%u)",
                oct);

        dtap_tree = proto_item_add_subtree(dtap_item, ett_dtap);
    }
    else
    {
        dtap_item =
            proto_tree_add_protocol_format(tree, proto_a_dtap, tvb, 0, len,
                "ANSI A-I/F DTAP - %s",
                msg_str);

        dtap_tree = proto_item_add_subtree(dtap_item, ett_dtap_msg[dec_idx]);

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
    }

    shared_data.message_item = dtap_item;

    if (!from_sip)
    {
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
            proto_tree_add_uint_format(dtap_tree, hf_ansi_a_protocol_disc, tvb, 0, 1,
                (oct_1 & 0x0f),
                "Protocol Discriminator: %s",
                str);

        oct_1_tree = proto_item_add_subtree(oct_1_item, ett_dtap_oct_1);

        proto_tree_add_item(oct_1_tree, hf_ansi_a_reserved_bits_8_f0, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(oct_1_tree, hf_ansi_a_protocol_disc, tvb, 0, 1, ENC_BIG_ENDIAN);

        /*
         * octet 2
         */
        switch (global_a_variant)
        {
        case A_VARIANT_IS634:
            proto_tree_add_item(dtap_tree, hf_ansi_a_ti_flag, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(dtap_tree, hf_ansi_a_ti_ti, tvb, 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(dtap_tree, hf_ansi_a_reserved_bits_8_0f, tvb, 1, 1, ENC_BIG_ENDIAN);
            break;

        default:
            proto_tree_add_item(dtap_tree, hf_ansi_a_reserved_octet, tvb, 1, 1, ENC_BIG_ENDIAN);
            break;
        }
    }

    proto_tree_add_item(dtap_tree, hf_ansi_a_dtap_msgtype, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    tap_p->pdu_type = BSSAP_PDU_TYPE_DTAP;
    tap_p->message_type = oct;

    tap_queue_packet(ansi_a_tap, pinfo, tap_p);

    if (msg_str == NULL) return;

    if ((len - offset) <= 0) return;

    /*
     * decode elements
     */
    if (dtap_msg_fcn[dec_idx] == NULL)
    {
        proto_tree_add_expert_format(dtap_tree, pinfo, &ei_ansi_a_miss_dtap_msg_diss, tvb, offset, len - offset,
            "Message Elements");
    }
    else
    {
        (*dtap_msg_fcn[dec_idx])(tvb, pinfo, dtap_tree, offset, len - offset, &shared_data);
    }
}

static int
dissect_dtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_dtap_common(tvb, pinfo, tree, FALSE);
    return tvb_captured_length(tvb);
}

static int
dissect_sip_dtap_bsmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint        linelen, offset, next_offset, begin;
    guint8      *msg_type;
    tvbuff_t    *ansi_a_tvb;
    gboolean    is_dtap = TRUE;

    offset = 0;

    if ((linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE)) > 0)
    {
        if (linelen >= 2)
        {
            ansi_a_tvb = tvb_new_composite();
            msg_type = (guint8 *) wmem_alloc(pinfo->pool, 1);
            msg_type[0] = (guint8) strtoul(tvb_get_string_enc(pinfo->pool, tvb, offset, 2, ENC_ASCII|ENC_NA), NULL, 16);

            if ((begin = tvb_find_guint8(tvb, offset, linelen, '"')) > 0)
            {
                if (tvb_get_guint8(tvb, begin + 1) == '1')
                {
                    is_dtap = FALSE;
                }
            }
            else
            {
                if (my_try_val_to_str_idx((guint32) msg_type[0], ansi_a_dtap_strings, &linelen) == NULL)
                {
                    is_dtap = FALSE;
                }
            }

            tvb_composite_append(ansi_a_tvb, tvb_new_child_real_data(tvb, msg_type, 1, 1));

            offset = next_offset;

            while ((linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE)) > 0)
            {
                if ((begin = tvb_find_guint8(tvb, offset, linelen, '=')) > 0)
                {
                    begin++;
                    tvb_composite_append(ansi_a_tvb, base64_to_tvb(tvb, tvb_get_string_enc(pinfo->pool, tvb, begin, offset + linelen - begin, ENC_ASCII|ENC_NA)));
                }

                offset = next_offset;
            }

            tvb_composite_finalize(ansi_a_tvb);

            if (is_dtap)
            {
                add_new_data_source(pinfo, ansi_a_tvb, "ANSI DTAP");
                dissect_dtap_common(ansi_a_tvb, pinfo, tree, TRUE);
            }
            else
            {
                add_new_data_source(pinfo, ansi_a_tvb, "ANSI BSMAP");
                dissect_bsmap_common(ansi_a_tvb, pinfo, tree, TRUE);
            }
        }
    }
    return tvb_captured_length(tvb);
}

/* TAP STAT INFO */
typedef enum
{
    IEI_COLUMN = 0,
    MESSAGE_NAME_COLUMN,
    COUNT_COLUMN
} ansi_a_stat_columns;

static stat_tap_table_item dtap_stat_fields[] = {{TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "IEI", "0x%02x  "}, {TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "Message Name", "%-50s"},
    {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Count", "%d"}};

static void ansi_a_dtap_stat_init(stat_tap_table_ui* new_stat)
{
    const char *table_name = "ANSI A-I/F DTAP Statistics";
    int num_fields = sizeof(dtap_stat_fields)/sizeof(stat_tap_table_item);
    stat_tap_table *table;
    int i = 0;
    stat_tap_table_item_type items[sizeof(dtap_stat_fields)/sizeof(stat_tap_table_item)];

    items[IEI_COLUMN].type = TABLE_ITEM_UINT;
    items[MESSAGE_NAME_COLUMN].type = TABLE_ITEM_STRING;
    items[COUNT_COLUMN].type = TABLE_ITEM_UINT;
    items[COUNT_COLUMN].value.uint_value = 0;

    table = stat_tap_find_table(new_stat, table_name);
    if (table) {
        if (new_stat->stat_tap_reset_table_cb) {
            new_stat->stat_tap_reset_table_cb(table);
        }
        return;
    }

    table = stat_tap_init_table(table_name, num_fields, 0, NULL);
    stat_tap_add_table(new_stat, table);

    /* Add a row for each value type */
    while (ansi_a_dtap_strings[i].strptr)
    {
        items[IEI_COLUMN].value.uint_value = ansi_a_dtap_strings[i].value;
        items[MESSAGE_NAME_COLUMN].value.string_value = ansi_a_dtap_strings[i].strptr;

        stat_tap_init_table_row(table, i, num_fields, items);
        i++;
    }
}

static tap_packet_status
ansi_a_dtap_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
    stat_data_t* stat_data = (stat_data_t*)tapdata;
    const ansi_a_tap_rec_t      *data_p = (const ansi_a_tap_rec_t *)data;
    stat_tap_table_item_type* dtap_data;
    stat_tap_table* table;
    guint idx;

    if (data_p->pdu_type == BSSAP_PDU_TYPE_DTAP)
    {
        if (my_try_val_to_str_idx(data_p->message_type, ansi_a_dtap_strings, &idx) == NULL)
            return TAP_PACKET_DONT_REDRAW;

        table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);

        dtap_data = stat_tap_get_field_data(table, idx, COUNT_COLUMN);
        dtap_data->value.uint_value++;
        stat_tap_set_field_data(table, idx, COUNT_COLUMN, dtap_data);

        return TAP_PACKET_REDRAW;
    }

    return TAP_PACKET_DONT_REDRAW;
}

static void
ansi_a_stat_reset(stat_tap_table* table)
{
    guint element;
    stat_tap_table_item_type* item_data;

    for (element = 0; element < table->num_elements; element++)
    {
        item_data = stat_tap_get_field_data(table, element, COUNT_COLUMN);
        item_data->value.uint_value = 0;
        stat_tap_set_field_data(table, element, COUNT_COLUMN, item_data);
    }

}

static stat_tap_table_item bsmap_stat_fields[] = {{TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "IEI", "0x%02x  "}, {TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "Message Name", "%-50s"},
    {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Count", "%d"}};

static void ansi_a_bsmap_stat_init(stat_tap_table_ui* new_stat)
{
    const char *table_name = "ANSI A-I/F BSMAP Statistics";
    int num_fields = sizeof(bsmap_stat_fields)/sizeof(stat_tap_table_item);
    stat_tap_table *table;
    int i = 0;
    stat_tap_table_item_type items[sizeof(bsmap_stat_fields)/sizeof(stat_tap_table_item)];

    items[IEI_COLUMN].type = TABLE_ITEM_UINT;
    items[MESSAGE_NAME_COLUMN].type = TABLE_ITEM_STRING;
    items[COUNT_COLUMN].type = TABLE_ITEM_UINT;
    items[COUNT_COLUMN].value.uint_value = 0;

    table = stat_tap_find_table(new_stat, table_name);
    if (table) {
        if (new_stat->stat_tap_reset_table_cb) {
            new_stat->stat_tap_reset_table_cb(table);
        }
        return;
    }

    table = stat_tap_init_table(table_name, num_fields, 0, NULL);
    stat_tap_add_table(new_stat, table);

    /* Add a row for each value type */
    while (ansi_a_bsmap_strings[i].strptr)
    {
        items[IEI_COLUMN].value.uint_value = ansi_a_bsmap_strings[i].value;
        items[MESSAGE_NAME_COLUMN].value.string_value = ansi_a_bsmap_strings[i].strptr;

        stat_tap_init_table_row(table, i, num_fields, items);
        i++;
    }
}

static tap_packet_status
ansi_a_bsmap_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
    stat_data_t* stat_data = (stat_data_t*)tapdata;
    const ansi_a_tap_rec_t      *data_p = (const ansi_a_tap_rec_t *)data;
    stat_tap_table_item_type* dtap_data;
    stat_tap_table* table;
    guint idx;

    if (data_p->pdu_type == BSSAP_PDU_TYPE_BSMAP)
    {
        if (my_try_val_to_str_idx(data_p->message_type, ansi_a_bsmap_strings, &idx) == NULL)
            return TAP_PACKET_DONT_REDRAW;

        table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);

        dtap_data = stat_tap_get_field_data(table, idx, COUNT_COLUMN);
        dtap_data->value.uint_value++;
        stat_tap_set_field_data(table, idx, COUNT_COLUMN, dtap_data);

        return TAP_PACKET_REDRAW;
    }

    return TAP_PACKET_DONT_REDRAW;
}

/* Register the protocol with Wireshark */
void
proto_register_ansi_a(void)
{
    module_t            *ansi_a_module;
    guint               i;
    gint                last_offset;

    /* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_ansi_a_bsmap_msgtype,
            { "BSMAP Message Type", "ansi_a_bsmap.msgtype",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_dtap_msgtype,
            { "DTAP Message Type", "ansi_a_bsmap.dtap_msgtype",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_protocol_disc,
            { "Protocol Discriminator", "ansi_a_bsmap.protocol_disc",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_octet,
            { "Reserved Octet", "ansi_a_bsmap.reserved_octet",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ti_flag,
            { "Transaction Identifier (TI) Flag", "ansi_a_bsmap.ti.flag",
            FT_BOOLEAN, 8, TFS(&tfs_allocated_by_receiver_sender), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_ti_ti,
            { "Transaction Identifier (TI)", "ansi_a_bsmap.ti.ti",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm_svrc_type,
            { "CM Service Type", "ansi_a_bsmap.cm_srvc_type",
            FT_UINT8, BASE_DEC, VALS(dtap_cm_service_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_elem_id,
            { "Element ID", "ansi_a_bsmap.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_elem_id_f0,
            { "Element ID", "ansi_a_bsmap.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_length,
            { "Length", "ansi_a_bsmap.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_esn,
            { "ESN", "ansi_a_bsmap.esn",
            FT_UINT32, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_imsi,
            { "IMSI", "ansi_a_bsmap.imsi",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_meid,
            { "MEID", "ansi_a_bsmap.meid",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cld_party_bcd_num,
            { "Called Party BCD Number", "ansi_a_bsmap.cld_party_bcd_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cld_party_ascii_num,
            { "Called Party ASCII Number", "ansi_a_bsmap.cld_party_ascii_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_ascii_num,
            { "Calling Party ASCII Number", "ansi_a_bsmap.clg_party_ascii_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cell_ci,
            { "Cell CI", "ansi_a_bsmap.cell_ci",
            FT_UINT16, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cell_lac,
            { "Cell LAC", "ansi_a_bsmap.cell_lac",
            FT_UINT16, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cell_mscid,
            { "Cell MSCID", "ansi_a_bsmap.cell_mscid",
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
        { &hf_ansi_a_so,
            { "Service Option", "ansi_a_bsmap.so",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_1,
            { "Cause", "ansi_a_bsmap.cause_1",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_2,
            { "Cause", "ansi_a_bsmap.cause_2",
            FT_UINT16, BASE_DEC, NULL, 0x7fff,
            NULL, HFILL }
        },
        { &hf_ansi_a_ms_info_rec_signal_type,
            { "Signal Type", "ansi_a_bsmap.ms_info_rec.signal.type",
            FT_UINT8, BASE_HEX, VALS(ansi_a_ms_info_rec_signal_type_vals), 0xc0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ms_info_rec_signal_alert_pitch,
            { "Alert Type", "ansi_a_bsmap.ms_info_rec.signal.alert_pitch",
            FT_UINT8, BASE_HEX, VALS(ansi_a_ms_info_rec_signal_alert_pitch_vals), 0x30,
            NULL, HFILL }
        },
        { &hf_ansi_a_ms_info_rec_signal_tone,
            { "Signal", "ansi_a_bsmap.ms_info_rec.signal.tone",
            FT_UINT16, BASE_HEX, VALS(ansi_a_ms_info_rec_signal_tone_vals), 0x0fc0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ms_info_rec_signal_isdn_alert,
            { "Signal", "ansi_a_bsmap.ms_info_rec.signal.isdn_alert",
            FT_UINT16, BASE_HEX, VALS(ansi_a_ms_info_rec_signal_isdn_alert_vals), 0x0fc0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ms_info_rec_signal_is54b_alert,
            { "Signal", "ansi_a_bsmap.ms_info_rec.signal.is54b_alert",
            FT_UINT16, BASE_HEX, VALS(ansi_a_ms_info_rec_signal_is54b_alert_vals), 0x0fc0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ms_info_rec_call_waiting_ind,
            { "Call Waiting Indicator", "ansi_a_bsmap.ms_info_rec.call_waiting_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_extension_8_80,
            { "Extended", "ansi_a_bsmap.extended",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_generic,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_01,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_07,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_0c,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0c,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_0f,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_10,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_18,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x18,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_1c,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x1c,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_1f,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_3f,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_7f,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_80,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_c0,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xc0,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_e0,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_f0,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_f8,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xf8,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_fc,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xfc,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_fe,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xfe,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_8_ff,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_16_001f,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT16, BASE_DEC, NULL, 0x001f,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_16_003f,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT16, BASE_DEC, NULL, 0x003f,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_16_8000,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_16_f800,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT16, BASE_DEC, NULL, 0xf800,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_24_001800,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT24, BASE_DEC, NULL, 0x001800,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_24_006000,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT24, BASE_DEC, NULL, 0x006000,
            NULL, HFILL }
        },
        { &hf_ansi_a_reserved_bits_24_007000,
            { "Reserved bit(s)", "ansi_a_bsmap.reserved",
            FT_UINT24, BASE_DEC, NULL, 0x007000,
            NULL, HFILL }
        },
        { &hf_ansi_a_channel_number,
            { "Channel Number", "ansi_a_bsmap.channel_number.channel_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_IOS5_channel_number,
            { "Channel Number", "ansi_a_bsmap.channel_number.channel_number",
            FT_UINT16, BASE_DEC, NULL, 0x07ff,
            NULL, HFILL }
        },
        { &hf_ansi_a_speech_or_data_indicator,
            { "Speech or Data Indicator", "ansi_a_bsmap.channel_type.speech_or_data_indicator",
            FT_UINT8, BASE_HEX, VALS(ansi_a_speech_or_data_indicator_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ansi_a_chan_rate_and_type,
            { "Channel Rate and Type", "ansi_a_bsmap.channel_type.rate_and_type",
            FT_UINT8, BASE_HEX, VALS(ansi_a_channel_rate_and_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ansi_a_speech_enc_or_data_rate,
            { "Speech Encoding Algorithm/data rate + Transparency Indicator", "ansi_a_bsmap.channel_type.speech_enc_or_data_rate",
            FT_UINT8, BASE_HEX, VALS(ansi_a_speech_enc_or_data_rate_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ansi_a_chan_type_data_ext,
            { "Extension", "ansi_a_bsmap.channel_type.data_ext",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_chan_type_data_transparent,
            { "Transparent", "ansi_a_bsmap.channel_type.data_transparent",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_return_cause,
            { "Return Cause", "ansi_a_bsmap.return_cause.cause",
            FT_UINT8, BASE_DEC, VALS(ansi_a_return_cause_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_rf_chan_id_color_code,
            { "Color Code", "ansi_a_bsmap.rf_channel_id.color_code",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_rf_chan_id_n_amps_based,
            { "N-AMPS", "ansi_a_bsmap.rf_channel_id.n_amps_based",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_rf_chan_id_amps_based,
            { "ANSI/EIA/TIA-553", "ansi_a_bsmap.rf_channel_id.amps_based",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_rf_chan_id_timeslot,
            { "Timeslot Number", "ansi_a_bsmap.rf_channel_id.timeslot",
            FT_UINT8, BASE_DEC, VALS(ansi_a_rf_chan_id_timeslot_number_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_a_rf_chan_id_channel_number,
            { "Channel Number", "ansi_a_bsmap.rf_channel_id.channel_number",
            FT_UINT16, BASE_DEC, NULL, 0x07ff,
            NULL, HFILL }
        },
        { &hf_ansi_a_sr_id,
            { "SR_ID", "ansi_a_bsmap.sr_id",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_sid,
            { "SID", "ansi_a_bsmap.sid",
            FT_UINT16, BASE_DEC, NULL, 0x7fff,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_chan_id_hho,
            { "Hard Handoff", "ansi_a_bsmap.is95_chan_id.hho",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_chan_id_num_chans_add,
            { "Number of Channels to Add", "ansi_a_bsmap.is95_chan_id.num_chans_add",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_chan_id_frame_offset,
            { "Frame Offset", "ansi_a_bsmap.is95_chan_id.frame_offset",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_chan_id_walsh_code_chan_idx,
            { "Walsh Code Channel Index", "ansi_a_bsmap.is95_chan_id.walsh_code_chan_idx",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_chan_id_pilot_pn,
            { "Pilot PN Code", "ansi_a_bsmap.is95_chan_id.pilot_pn",
            FT_UINT24, BASE_DEC, NULL, 0xff8000,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_chan_id_power_combined,
            { "Power Combined", "ansi_a_bsmap.is95_chan_id.power_combined",
            FT_BOOLEAN, 24, TFS(&tfs_yes_no), 0x004000,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_chan_id_freq_incl,
            { "Frequency Included", "ansi_a_bsmap.is95_chan_id.freq_incl",
            FT_BOOLEAN, 24, TFS(&tfs_yes_no), 0x002000,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_chan_id_channel_number,
            { "Channel Number", "ansi_a_bsmap.is95_chan_id.channel_number",
            FT_UINT24, BASE_DEC, NULL, 0x0007ff,
            NULL, HFILL }
        },
        { &hf_ansi_a_enc_info_enc_parm_id,
            { "Encryption Parameter Identifier", "ansi_a_bsmap.enc_info.parm_id",
            FT_UINT8, BASE_DEC, VALS(ansi_a_enc_info_ident_vals), 0x7c,
            NULL, HFILL }
        },
        { &hf_ansi_a_enc_info_status,
            { "Status", "ansi_a_bsmap.enc_info.status",
            FT_UINT8, BASE_DEC, VALS(ansi_a_enc_info_status_vals), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_enc_info_available,
            { "Available", "ansi_a_bsmap.enc_info.available",
            FT_UINT8, BASE_DEC, VALS(ansi_a_enc_info_available_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_mob_p_rev,
            { "MOB_P_REV", "ansi_a_bsmap.cm2.mob_p_rev",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_see_list,
            { "See List of Entries", "ansi_a_bsmap.cm2.see_list",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_rf_power_cap,
            { "RF Power Capability", "ansi_a_bsmap.cm2.rf_power_cap",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cm2_rf_power_cap_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_nar_an_cap,
            { "NAR_AN_CAP", "ansi_a_bsmap.cm2.nar_an_cap",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_is95,
            { "IS-95 supported", "ansi_a_bsmap.cm2.is95",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_slotted,
            { "Operating in slotted mode", "ansi_a_bsmap.cm2.slotted",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_dtx,
            { "DTX capable", "ansi_a_bsmap.cm2.dtx",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_mobile_term,
            { "Mobile Term; can receive incoming calls", "ansi_a_bsmap.cm2.mobile_term",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_analog_cap,
            { "ANSI/EIA/TIA-553; supports analog capabilities", "ansi_a_bsmap.cm2.ansi_eia_tia_553",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_psi,
            { "PACA Supported Indicator (PSI)", "ansi_a_bsmap.cm2.psi",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_len,
            { "SCM Length", "ansi_a_bsmap.cm2.scm_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm,
            { "Station Class Mark", "ansi_a_bsmap.cm2.scm",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_ext_scm_ind,
            { "Extended SCM Indicator", "ansi_a_bsmap.cm2.scm.ext_scm_ind",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cm2_scm_ext_scm_ind_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_dual_mode,
            { "Dual Mode", "ansi_a_bsmap.cm2.scm.dual_mode",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cm2_scm_dual_mode_vals), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_slotted,
            { "Slotted Class", "ansi_a_bsmap.cm2.scm.slotted_class",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cm2_scm_slotted_class_vals), 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_meid_configured,
            { "MEID support indicator", "ansi_a_bsmap.cm2.scm.meid_configured",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cm2_scm_meid_configured_vals), 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_25MHz_bandwidth,
            { "25 MHz Bandwidth", "ansi_a_bsmap.cm2.scm.25MHz_bandwidth",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_transmission,
            { "Transmission", "ansi_a_bsmap.cm2.scm.transmission",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cm2_scm_transmission_vals), 0x04,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_power_class,
            { "Power Class for Band Class 0 Analog Operation", "ansi_a_bsmap.cm2.scm.power_class",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cm2_scm_power_class_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_band_class_count,
            { "Count of Band Class Entries", "ansi_a_bsmap.cm2.scm.band_class_count",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cm2_scm_band_class_entry_len,
            { "Band Class Entry Length", "ansi_a_bsmap.cm2.scm.band_class_entry_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_band_class,
            { "Band Class", "ansi_a_bsmap.cm2.scm.bc_entry.band_class",
            FT_UINT8, BASE_DEC, VALS(ansi_a_band_class_vals), 0x1f,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode0_1,
            { "Air Interface OP_MODE0:  CDMA mode in Band Class 1 and Band Class 4", "ansi_a_bsmap.cm2.scm.bc_entry.opmode0",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode1_1,
            { "Air Interface OP_MODE1:  CDMA mode in Band Class 0 and Band Class 3", "ansi_a_bsmap.cm2.scm.bc_entry.opmode1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode2_1,
            { "Air Interface OP_MODE2:  Reserved (Previously Analog mode)", "ansi_a_bsmap.cm2.scm.bc_entry.opmode2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode3_1,
            { "Air Interface OP_MODE3:  Reserved (Previously Wide analog mode)", "ansi_a_bsmap.cm2.scm.bc_entry.opmode3",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode4_1,
            { "Air Interface OP_MODE4:  Reserved (Previously Narrow analog mode)", "ansi_a_bsmap.cm2.scm.bc_entry.opmode4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode0_2,
            { "Air Interface OP_MODE0:  CDMA mode", "ansi_a_bsmap.cm2.scm.bc_entry.opmode0",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode1_2,
            { "Air Interface OP_MODE1:  CDMA mode", "ansi_a_bsmap.cm2.scm.bc_entry.opmode1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode2_2,
            { "Air Interface OP_MODE2:  Reserved (Previously Analog mode)", "ansi_a_bsmap.cm2.scm.bc_entry.opmode2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode3_2,
            { "Air Interface OP_MODE3:  Reserved (Previously Wide analog mode)", "ansi_a_bsmap.cm2.scm.bc_entry.opmode3",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode4_2,
            { "Air Interface OP_MODE4:  Reserved (Previously Narrow analog mode)", "ansi_a_bsmap.cm2.scm.bc_entry.opmode4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode5_2,
            { "Air Interface OP_MODE5:  DS-41", "ansi_a_bsmap.cm2.scm.bc_entry.opmode5",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_opmode6_2,
            { "Air Interface OP_MODE6:  MC-MAP", "ansi_a_bsmap.cm2.scm.bc_entry.opmode6",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_scm_band_class_entry_p_rev,
            { "Band Class MS Protocol Level", "ansi_a_bsmap.cm2.scm.bc_entry.p_rev",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_meid_mid_digit_1,
            { "MEID Hex Digit 1", "ansi_a_bsmap.mid.digit_1",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_imsi_mid_digit_1,
            { "Identity Digit 1", "ansi_a_bsmap.mid.digit_1",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_mid_odd_even_ind,
            { "Odd/Even Indicator", "ansi_a_bsmap.mid.odd_even_ind",
            FT_UINT8, BASE_DEC, VALS(ansi_a_mid_odd_even_ind_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_a_mid_type_of_id,
            { "Type of Identity", "ansi_a_bsmap.mid.type_of_identity",
            FT_UINT8, BASE_DEC, VALS(ansi_a_mid_type_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_mid_broadcast_priority,
            { "Priority", "ansi_a_bsmap.mid.broadcast.priority",
            FT_UINT8, BASE_DEC, VALS(ansi_a_mid_broadcast_priority_vals), 0xc0,
            NULL, HFILL }
        },
        { &hf_ansi_a_mid_broadcast_message_id,
            { "Message ID", "ansi_a_bsmap.mid.broadcast.message_id",
            FT_UINT8, BASE_DEC, NULL, 0x2f,
            NULL, HFILL }
        },
        { &hf_ansi_a_mid_broadcast_zone_id,
            { "Zone ID", "ansi_a_bsmap.mid.broadcast.zone_id",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_mid_broadcast_srvc_cat,
            { "Service Category", "ansi_a_bsmap.mid.broadcast.srvc_cat",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_mid_broadcast_language,
            { "Language", "ansi_a_bsmap.mid.broadcast.language",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_mid_unused,
            { "Unused", "ansi_a_bsmap.mid.unused",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_sci_sign,
            { "SCI Sign", "ansi_a_bsmap.slot_cycle_index_sign",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            "1 indicates a negative sign is associated with the SCI", HFILL }
        },
        { &hf_ansi_a_sci,
            { "Slot Cycle Index", "ansi_a_bsmap.slot_cycle_index",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_prio_call_priority,
            { "Call Priority Level", "ansi_a_bsmap.prio.call_priority",
            FT_UINT8, BASE_DEC, NULL, 0x3c,
            NULL, HFILL }
        },
        { &hf_ansi_a_prio_queue_allowed,
            { "Queuing allowed", "ansi_a_bsmap.prio.queuing_allowed",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_prio_preempt_allowed,
            { "Preemption allowed", "ansi_a_bsmap.prio.preempt_allowed",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_mob_p_rev,
            { "MOB_P_REV", "ansi_a_bsmap.mob_p_rev",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_1_ext,
            { "Extension", "ansi_a_bsmap.cause.ext",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_2_ext,
            { "Extension", "ansi_a_bsmap.cause.ext",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_ansi_a_cell_id_disc,
            { "Cell Identification Discriminator", "ansi_a_bsmap.cell_id_discriminator",
            FT_UINT8, BASE_DEC, VALS(cell_disc_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ansi_a_cic,
            { "CIC", "ansi_a_bsmap.cic",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cic_pcm_multi,
            { "PCM Multiplexer", "ansi_a_bsmap.cic.pcm_multi",
            FT_UINT16, BASE_DEC, NULL, 0xffe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cic_timeslot,
            { "Timeslot", "ansi_a_bsmap.cic.timeslot",
            FT_UINT16, BASE_DEC, NULL, 0x001f,
            NULL, HFILL }
        },
        { &hf_ansi_a_cic_ext_cic,
            { "CIC", "ansi_a_bsmap.cic_ext.cic",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cic_ext_pcm_multi,
            { "PCM Multiplexer", "ansi_a_bsmap.cic_ext.pcm_multi",
            FT_UINT16, BASE_DEC, NULL, 0xffe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cic_ext_timeslot,
            { "Timeslot", "ansi_a_bsmap.cic_ext.timeslot",
            FT_UINT16, BASE_DEC, NULL, 0x001f,
            NULL, HFILL }
        },
        { &hf_ansi_a_cic_ext_circuit_mode,
            { "Circuit Mode", "ansi_a_bsmap.cic_ext.circuit_mode",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_ssci_mopd,
            { "Mobile Originated Position Determination", "ansi_a_bsmap.ssci.mopd",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_ssci_geci,
            { "Global Emergency Call Indication", "ansi_a_bsmap.ssci.geci",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_downlink_re_num_cells,
            { "Number of Cells", "ansi_a_bsmap.downlink_re.num_cells",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_downlink_re_sig_str_raw,
            { "Downlink Signal Strength Raw", "ansi_a_bsmap.downlink_re.sig_str_raw",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_a_downlink_re_cdma_towd,
            { "CDMA Target One Way Delay", "ansi_a_bsmap.downlink_re.cdma_towd",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_downlink_re_entry_env_len,
            { "Environment Length", "ansi_a_bsmap.downlink_re.entry.env_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ho_pow_lev_num_cells,
            { "Number of Cells", "ansi_a_bsmap.ho_pow_lev.num_cells",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ho_pow_lev_id_type,
            { "ID Type", "ansi_a_bsmap.ho_pow_lev.id_type",
            FT_UINT8, BASE_DEC, NULL, 0x60,
            NULL, HFILL }
        },
        { &hf_ansi_a_ho_pow_lev_pow_lev,
            { "Handoff Power Level", "ansi_a_bsmap.ho_pow_lev.pow_lev",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_ansi_a_uz_id,
            { "UZID", "ansi_a_bsmap.uzid",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_info_rec_req,
            { "Information Record Type", "ansi_a_bsmap.info_rec.rev_ms",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_otd,
            { "OTD", "ansi_a_bsmap.is2000_chan_id.otd",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            "1 indicates mobile is using OTD", HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_count,
            { "Physical Channel Count", "ansi_a_bsmap.is2000_chan_id.chan_count",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_frame_offset,
            { "Frame Offset", "ansi_a_bsmap.is2000_chan_id.frame_offset",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_chan_type,
            { "Physical Channel Type", "ansi_a_bsmap.is2000_chan_id.chan.chan_type",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_rev_fch_gating,
            { "Rev_FCH_Gating", "ansi_a_bsmap.is2000_chan_id.chan.rev_fch_gating",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_rev_pilot_gating_rate,
            { "Reverse Pilot Gating Rate", "ansi_a_bsmap.is2000_chan_id.chan.rev_pilot_gating_rate",
            FT_UINT16, BASE_DEC, VALS(ansi_a_is2000_chan_id_chan_rev_pilot_gating_rate_vals), 0x6000,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_qof_mask,
            { "QOF Mask", "ansi_a_bsmap.is2000_chan_id.chan.qof_mask",
            FT_UINT16, BASE_DEC, NULL, 0x1800,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_walsh_code_chan_idx,
            { "Walsh Code Channel Index", "ansi_a_bsmap.is2000_chan_id.chan.walsh_code_chan_idx",
            FT_UINT16, BASE_DEC, NULL, 0x7ff,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_pilot_pn_code,
            { "Pilot PN Code", "ansi_a_bsmap.is2000_chan_id.chan.pilot_pn_code",
            FT_UINT24, BASE_DEC, NULL, 0xff8000,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_power_combined,
            { "Power Combined", "ansi_a_bsmap.is2000_chan_id.chan.power_combined",
            FT_BOOLEAN, 24, TFS(&tfs_yes_no), 0x001000,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_freq_incl,
            { "Frequency Included", "ansi_a_bsmap.is2000_chan_id.chan.freq_incl",
            FT_BOOLEAN, 24, TFS(&tfs_yes_no), 0x000800,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_channel_number,
            { "Channel Number (ARFCN)", "ansi_a_bsmap.is2000_chan_id.chan.channel_number",
            FT_UINT24, BASE_DEC, NULL, 0x0007ff,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_fdc_length,
            { "FDC Length", "ansi_a_bsmap.is2000_chan_id.chan.fdc_length",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_fdc_band_class,
            { "FDC Length", "ansi_a_bsmap.is2000_chan_id.chan.fdc_band_class",
            FT_UINT16, BASE_DEC, VALS(ansi_a_band_class_vals), 0xf800,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_fdc_fwd_chan_freq,
            { "FDC Forward Channel Frequency", "ansi_a_bsmap.is2000_chan_id.chan.fdc_fwd_chan_freq",
            FT_UINT16, BASE_DEC, NULL, 0x07ff,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_chan_id_chan_fdc_rev_chan_freq,
            { "FDC Reverse Channel Frequency", "ansi_a_bsmap.is2000_chan_id.chan.fdc_rev_chan_freq",
            FT_UINT16, BASE_DEC, NULL, 0xffe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_ms_meas_chan_id_band_class,   /* IOS 5 (MS Measured Channel Identity) */
            { "Band Class", "ansi_a_bsmap.is95_ms_meas_chan_id.band_class",
            FT_UINT16, BASE_DEC, VALS(ansi_a_band_class_vals), 0xf800,
            NULL, HFILL }
        },
        { &hf_ansi_a_is95_ms_meas_chan_id_channel_number,
            { "Channel Number (ARFCN)", "ansi_a_bsmap.is95_ms_meas_chan_id.channel_number",
            FT_UINT16, BASE_DEC, NULL, 0x07ff,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_ascii_num_ton,
            { "Type of Number", "ansi_a_bsmap.clg_party_ascii_num.ton",
            FT_UINT8, BASE_DEC, VALS(ansi_a_clg_party_ascii_num_ton_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_ascii_num_plan,
            { "Numbering Plan Identification", "ansi_a_bsmap.clg_party_ascii_num.plan",
            FT_UINT8, BASE_DEC, VALS(ansi_a_clg_party_ascii_num_plan_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_ascii_num_pi,
            { "Presentation Indicator", "ansi_a_bsmap.clg_party_ascii_num.pi",
            /* not a typo, MS Info Rec and CLG Party ASCII have the same definition for this field */
            FT_UINT8, BASE_DEC, VALS(ansi_a_ms_info_rec_clg_pn_pi_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_ascii_num_si,
            { "Screening Indicator", "ansi_a_bsmap.clg_party_ascii_num.si",
            /* not a typo, MS Info Rec and CLG Party ASCII have the same definition for this field */
            FT_UINT8, BASE_DEC, VALS(ansi_a_ms_info_rec_clg_pn_si_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_a_lai_mcc,
            { "Mobile Country Code (MCC)", "ansi_a_bsmap.lai.mcc",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_lai_mnc,
            { "Mobile Network Code (MNC)", "ansi_a_bsmap.lai.mnc",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_lai_lac,
            { "Location Area Code", "ansi_a_bsmap.lai.lac",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_rej_cause,
            { "Reject Cause Value", "ansi_a_bsmap.rej_cause",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_auth_chlg_param_rand_num_type,
            { "Random Number Type", "ansi_a_bsmap.auth_chlg_param.rand_num_type",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_auth_chlg_param_rand,
            { "RAND/RANDU/RANDBS/RANDSSD Value", "ansi_a_bsmap.auth_chlg_param.rand",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_auth_resp_param_sig_type,
            { "Auth Signature Type", "ansi_a_bsmap.auth_resp_param.sig_type",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_auth_resp_param_sig,
            { "Auth Signature", "ansi_a_bsmap.auth_resp_param.sig",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_auth_param_count_count,
            { "Count", "ansi_a_bsmap.auth_param_count.count",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_a_mwi_num_messages,
            { "Number of Messages", "ansi_a_bsmap.mwi.num_messages",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_signal_signal_value,
            { "Signal Value", "ansi_a_bsmap.signal.signal_value",
            FT_UINT8, BASE_DEC, VALS(ansi_a_signal_signal_vals), 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_signal_alert_pitch,
            { "Alert Pitch", "ansi_a_bsmap.signal.alert_pitch",
            FT_UINT8, BASE_DEC, VALS(ansi_a_signal_alert_pitch_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_bcd_num_ton,
            { "Type of Number", "ansi_a_bsmap.clg_party_bcd_num.ton",
            /* not a typo, CLG and CLD have the same definition for this field */
            FT_UINT8, BASE_DEC, VALS(ansi_a_cld_party_bcd_num_ton_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_clg_party_bcd_num_plan,
            { "Numbering Plan Identification", "ansi_a_bsmap.clg_party_bcd_num.plan",
            /* not a typo, CLG and CLD have the same definition for this field */
            FT_UINT8, BASE_DEC, VALS(ansi_a_cld_party_bcd_num_plan_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_qos_params_packet_priority,
            { "Packet Priority", "ansi_a_bsmap.qos_params.packet_priority",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_l3_coding_standard,
            { "Coding Standard", "ansi_a_bsmap.cause_l3.coding_standard",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cause_l3_coding_standard_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_l3_location,
            { "Location", "ansi_a_bsmap.cause_l3.location",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cause_l3_location_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_l3_class,
            { "Class", "ansi_a_bsmap.cause_l3.class",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cause_l3_class_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_l3_value_without_class,
            { "Value (Without class)", "ansi_a_bsmap.cause_l3.value_without_class",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_cause_l3_value,
            { "Value", "ansi_a_bsmap.cause_l3.value",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_auth_conf_param_randc,
            { "RANDC", "ansi_a_bsmap.auth_conf_param.randc",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_xmode_tfo_mode,
            { "TFO Mode", "ansi_a_bsmap.xmode.tfo_mode",
            FT_BOOLEAN, 8, TFS(&tfs_ansi_a_xmode_tfo_mode), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_reg_type_type,
            { "Location Registration Type", "ansi_a_bsmap.reg_type.type",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_tag_value,
            { "Tag value", "ansi_a_bsmap.tag.value",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_band_class,
            { "Band Class", "ansi_a_bsmap.hho_params.band_class",
            FT_UINT8, BASE_DEC, VALS(ansi_a_band_class_vals), 0x1f,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_num_pream_frames,
            { "Number of Preamble Frames", "ansi_a_bsmap.hho_params.num_pream_frames",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_reset_l2,
            { "Reset L2", "ansi_a_bsmap.hho_params.reset_l2",
            FT_BOOLEAN, 8, TFS(&tfs_l2_reset_dont_reset), 0x10,
            "1 means reset Layer 2 Ack", HFILL }
        },
        { &hf_ansi_a_hho_params_reset_fpc,
            { "Reset FPC", "ansi_a_bsmap.hho_params.reset_fpc",
            FT_BOOLEAN, 8, TFS(&tfs_fpc_reset_dont_reset), 0x08,
            "1 means reset counters", HFILL }
        },
        { &hf_ansi_a_hho_params_enc_mode,
            { "Encryption Mode", "ansi_a_bsmap.hho_params.enc_mode",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x06,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_private_lcm,
            { "Private LCM", "ansi_a_bsmap.hho_params.private_lcm",
            FT_BOOLEAN, 8, TFS(&tfs_use_dont_use), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_rev_pwr_cntl_delay_incl,
            { "Rev_Pwr_Cntl_Delay_Incl", "ansi_a_bsmap.hho_params.rev_pwr_cntl_delay_incl",
            FT_BOOLEAN, 8, TFS(&tfs_use_dont_use), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_rev_pwr_cntl_delay,
            { "Rev_Pwr_Cntl_Delay", "ansi_a_bsmap.hho_params.rev_pwr_cntl_delay",
            FT_UINT8, BASE_DEC, NULL, 0x60,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_nom_pwr_ext,
            { "Nom_Pwr_Ext", "ansi_a_bsmap.hho_params.nom_pwr_ext",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_nom_pwr,
            { "Nom_Pwr", "ansi_a_bsmap.hho_params.nom_pwr",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_fpc_subchan_info,
            { "FPC Subchannel Information", "ansi_a_bsmap.hho_params.fpc_subchan_info",
            FT_UINT8, BASE_DEC, NULL, 0x3e,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_fpc_subchan_info_incl,
            { "FPC Subchannel Info Included", "ansi_a_bsmap.hho_params.fpc_subchan_info_incl",
            FT_BOOLEAN, 8, TFS(&tfs_use_dont_use), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_pwr_cntl_step,
            { "Power Control Step", "ansi_a_bsmap.hho_params.pwr_cntl_step",
            FT_UINT8, BASE_DEC, NULL, 0x0e,
            NULL, HFILL }
        },
        { &hf_ansi_a_hho_params_pwr_cntl_step_incl,
            { "Power Control Step Included", "ansi_a_bsmap.hho_params.pwr_cntl_step_incl",
            FT_BOOLEAN, 8, TFS(&tfs_use_dont_use), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_sw_ver_major,
            { "IOS Major Revision Level", "ansi_a_bsmap.sw_ver.major",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_sw_ver_minor,
            { "IOS Minor Revision Level", "ansi_a_bsmap.sw_ver.minor",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_sw_ver_point,
            { "IOS Point Release Level", "ansi_a_bsmap.sw_ver.point",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_so_proprietary_ind,
            { "Proprietary Indicator", "ansi_a_bsmap.so.proprietary_ind",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
            NULL, HFILL }
        },
        { &hf_ansi_a_so_revision,
            { "Service Option Revision", "ansi_a_bsmap.so.revision",
            FT_UINT16, BASE_DEC, NULL, 0x7000,
            NULL, HFILL }
        },
        { &hf_ansi_a_so_base_so_num,
            { "Base Service Option Number", "ansi_a_bsmap.so.base_so_num",
            FT_UINT16, BASE_DEC, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_ansi_a_soci,
            { "Service Option Connection Identifier", "ansi_a_bsmap.soci",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_so_list_num,
            { "Number of Service Option instances", "ansi_a_bsmap.so_list.num",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_so_list_sr_id,
            { "SR_ID", "ansi_a_bsmap.so_list.sr_id",
            FT_UINT8, BASE_DEC, NULL, 0x38,
            NULL, HFILL }
        },
        { &hf_ansi_a_so_list_soci,
            { "SOCI", "ansi_a_bsmap.so_list.soci",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_nid,
            { "NID", "ansi_a_bsmap.nid",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_pzid,
            { "PZID", "ansi_a_bsmap.pzid",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_adds_user_part_burst_type,
            { "Data Burst Type", "ansi_a_bsmap.adds_user_part.burst_type",
            FT_UINT8, BASE_DEC, VALS(ansi_a_adds_vals), 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_a_adds_user_part_ext_burst_type,
            { "Extended Burst Type", "ansi_a_bsmap.adds_user_part.ext_burst_type",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_adds_user_part_ext_data,
            { "Data", "ansi_a_bsmap.adds_user_part.ext_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_adds_user_part_unknown_data,
            { "Data", "ansi_a_bsmap.adds_user_part.unknown_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_amps_hho_params_enc_mode,
            { "Encryption Mode", "ansi_a_bsmap.amps_hho_params.enc_mode",
            FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_num_fill_bits,
            { "Bit-Exact Length Fill Bits", "ansi_a_bsmap.is2000_scr.num_fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_for_mux_option,
            { "FOR_MUX_OPTION:  Forward Traffic Channel multiplex option", "ansi_a_bsmap.is2000_scr.for_mux_opt",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_rev_mux_option,
            { "REV_MUX_OPTION:  Reverse Traffic Channel multiplex option", "ansi_a_bsmap.is2000_scr.rev_mux_opt",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_for_fch_rate,
            { "FOR_RATES:  Transmission rates of the Forward Fundamental Channel", "ansi_a_bsmap.is2000_scr.for_fch_rate",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_rev_fch_rate,
            { "REV_RATES:  Transmission rates of the Reverse Fundamental Channel", "ansi_a_bsmap.is2000_scr.rev_fch_rate",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_num_socr,
            { "NUM_CON_REC:  Number of service option connection records", "ansi_a_bsmap.is2000_scr.num_socr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_soc_ref,
            { "CON_REF:  Service option connection reference", "ansi_a_bsmap.is2000_scr.socr.soc_ref",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_so,
            { "SERVICE_OPTION", "ansi_a_bsmap.is2000_scr.socr.so",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_for_chan_type,
            { "FOR_TRAFFIC", "ansi_a_bsmap.is2000_scr.socr.for_chan_type",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_rev_chan_type,
            { "REV_TRAFFIC", "ansi_a_bsmap.is2000_scr.socr.rev_chan_type",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_ui_enc_mode,
            { "UI_ENCRYPT_MODE:  Encryption mode indicator for user information privacy", "ansi_a_bsmap.is2000_scr.socr.ui_enc_mode",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_sr_id,
            { "SR_ID:  Service reference identifier", "ansi_a_bsmap.is2000_scr.socr.sr_id",
            FT_UINT8, BASE_DEC, NULL, 0x1c,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_rlp_info_incl,
            { "RLP_INFO_INCL:  RLP information included indicator", "ansi_a_bsmap.is2000_scr.socr.rlp_info_incl",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_rlp_blob_len,
            { "RLP_BLOB_LEN", "ansi_a_bsmap.is2000_scr.socr.rlp_blob_len",
            FT_UINT16, BASE_DEC, NULL, 0x01E0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_rlp_blob_msb,
            { "RLP_BLOB (MSB)", "ansi_a_bsmap.is2000_scr.socr.rlp_blob_msb",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_rlp_blob,
            { "RLP_BLOB", "ansi_a_bsmap.is2000_scr.socr.rlp_blob",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_rlp_blob_lsb,
            { "RLP_BLOB (LSB)", "ansi_a_bsmap.is2000_scr.socr.rlp_blob_lsb",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_fch_cc_incl,
            { "FCH_CC_INCL:  Channel configuration for the Fundamental Channel included indicator", "ansi_a_bsmap.is2000_scr.socr.fch_cc_incl",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_fch_frame_size_support_ind,
            { "FCH_FRAME_SIZE:  Fundamental Channel frame size supported indicator", "ansi_a_bsmap.is2000_scr.socr.fch_frame_size_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_for_fch_rc,
            { "FOR_FCH_RC:  Forward Fundamental Channel Radio Configuration", "ansi_a_bsmap.is2000_scr.socr.for_fch_rc",
            FT_UINT8, BASE_DEC, NULL, 0x3e,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_scr_socr_rev_fch_rc,
            { "REV_FCH_RC", "ansi_a_bsmap.is2000_scr.socr.rev_fch_rc",
            FT_UINT16, BASE_DEC, NULL, 0x01F0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_nn_scr_num_fill_bits,
            { "Bit-Exact Length Fill Bits", "ansi_a_bsmap.is2000_nn_scr.num_fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_nn_scr_content,
            { "IS-2000 Non-Negotiable Service Configuration Record Content", "ansi_a_bsmap.is2000_nn_scr.content",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_nn_scr_fill_bits,
            { "Fill Bits", "ansi_a_bsmap.is2000_nn_scr.fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_rev_pdch_support_ind,
            { "REV_PDCH:  IS-2000 R-PDCH supported", "ansi_a_bsmap.is2000_mob_cap.rev_pdch_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_for_pdch_support_ind,
            { "FOR_PDCH:  IS-2000 F-PDCH supported", "ansi_a_bsmap.is2000_mob_cap.for_pdch_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_eram_support_ind,
            { "ERAM:  Enhanced Rate Adaptation Mode supported", "ansi_a_bsmap.is2000_mob_cap.eram_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_dcch_support_ind,
            { "DCCH:  IS-2000 DCCH supported", "ansi_a_bsmap.is2000_mob_cap.dcch_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_fch_support_ind,
            { "FCH:  IS-2000 FCH supported", "ansi_a_bsmap.is2000_mob_cap.fch_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_otd_support_ind,
            { "OTD:  Orthogonal Transmit Diversity supported", "ansi_a_bsmap.is2000_mob_cap.otd_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_enh_rc_cfg_support_ind,
            { "Enhanced RC CFG Supported:  Radio configuration in radio class 2 supported", "ansi_a_bsmap.is2000_mob_cap.enh_rc_cfg_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_qpch_support_ind,
            { "QPCH Supported:  Quick Paging Channel supported", "ansi_a_bsmap.is2000_mob_cap.qpch_support_ind",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_fch_info_octet_len,
            { "FCH Information:  Bit-Exact Length Octet Count", "ansi_a_bsmap.is2000_mob_cap.fch_info.octet_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_fch_info_geo_loc_type,
            { "Geo Location Type", "ansi_a_bsmap.is2000_mob_cap.fch_info.geo_loc_type",
            FT_UINT8, BASE_DEC, VALS(ansi_a_is2000_mob_cap_fch_info_geo_loc_type_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_fch_info_geo_loc_incl,
            { "Geo Location Included", "ansi_a_bsmap.is2000_mob_cap.fch_info.geo_loc_incl",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_fch_info_num_fill_bits,
            { "Bit-Exact Length Fill Bits", "ansi_a_bsmap.is2000_mob_cap.fch_info.num_fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_fch_info_content,
            { "FCH Information Content", "ansi_a_bsmap.is2000_mob_cap.fch_info.content",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_fch_info_fill_bits,
            { "Fill Bits", "ansi_a_bsmap.is2000_mob_cap.fch_info.fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_dcch_info_octet_len,
            { "DCCH Information:  Bit-Exact Length Octet Count", "ansi_a_bsmap.is2000_mob_cap.dcch_info.octet_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_dcch_info_num_fill_bits,
            { "Bit-Exact Length Fill Bits", "ansi_a_bsmap.is2000_mob_cap.dcch_info.num_fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_dcch_info_content,
            { "DCCH Information Content", "ansi_a_bsmap.is2000_mob_cap.dcch_info.content",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_dcch_info_fill_bits,
            { "Fill Bits", "ansi_a_bsmap.is2000_mob_cap.dcch_info.fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_for_pdch_info_octet_len,
            { "FOR_PDCH Information:  Bit-Exact Length Octet Count", "ansi_a_bsmap.is2000_mob_cap.for_pdch_info.octet_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_for_pdch_info_num_fill_bits,
            { "Bit-Exact Length Fill Bits", "ansi_a_bsmap.is2000_mob_cap.for_pdch_info.num_fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_for_pdch_info_content,
            { "FOR_PDCH Information Content", "ansi_a_bsmap.is2000_mob_cap.for_pdch_info.content",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_for_pdch_info_fill_bits,
            { "Fill Bits", "ansi_a_bsmap.is2000_mob_cap.for_pdch_info.fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_rev_pdch_info_octet_len,
            { "REV_PDCH Information:  Bit-Exact Length Octet Count", "ansi_a_bsmap.is2000_mob_cap.rev_pdch_info.octet_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_rev_pdch_info_num_fill_bits,
            { "Bit-Exact Length Fill Bits", "ansi_a_bsmap.is2000_mob_cap.rev_pdch_info.num_fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_rev_pdch_info_content,
            { "REV_PDCH Information Content", "ansi_a_bsmap.is2000_mob_cap.rev_pdch_info.content",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_rev_pdch_info_fill_bits,
            { "Fill Bits", "ansi_a_bsmap.is2000_mob_cap.rev_pdch_info.fill_bits",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_vp_support,
            { "VP Algorithms Supported", "ansi_a_bsmap.is2000_mob_cap.vp_support",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_vp_support_a7,
            { "VP Algorithm A7", "ansi_a_bsmap.is2000_mob_cap.vp_support.a7",
            FT_BOOLEAN, 8, TFS(&tfs_reserved_no_voice_privacy), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_vp_support_a6,
            { "VP Algorithm A6", "ansi_a_bsmap.is2000_mob_cap.vp_support.a6",
            FT_BOOLEAN, 8, TFS(&tfs_reserved_no_voice_privacy), 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_vp_support_a5,
            { "VP Algorithm A5", "ansi_a_bsmap.is2000_mob_cap.vp_support.a5",
            FT_BOOLEAN, 8, TFS(&tfs_reserved_no_voice_privacy), 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_vp_support_a4,
            { "VP Algorithm A4", "ansi_a_bsmap.is2000_mob_cap.vp_support.a4",
            FT_BOOLEAN, 8, TFS(&tfs_reserved_no_voice_privacy), 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_vp_support_a3,
            { "VP Algorithm A3", "ansi_a_bsmap.is2000_mob_cap.vp_support.a3",
            FT_BOOLEAN, 8, TFS(&tfs_reserved_no_voice_privacy), 0x04,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_vp_support_a2,
            { "VP Algorithm A2", "ansi_a_bsmap.is2000_mob_cap.vp_support.a2",
            FT_BOOLEAN, 8, TFS(&tfs_reserved_aes), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_mob_cap_vp_support_a1,
            { "VP Algorithm A1", "ansi_a_bsmap.is2000_mob_cap.vp_support.a1",
            FT_BOOLEAN, 8, TFS(&tfs_reserved_private_long_code), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_protocol_type,
            { "Protocol Type", "ansi_a_bsmap.protocol_type",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_cld_pn_num_type,
            { "Forward MS Information Record Called Party Number:  Number Type", "ansi_a_bsmap.fwd_ms_info_rec.cld_pn.num_type",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ms_info_rec_num_type_vals), 0xe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_cld_pn_num_plan,
            { "Forward MS Information Record Called Party Number:  Number Plan", "ansi_a_bsmap.fwd_ms_info_rec.cld_pn.num_plan",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ms_info_rec_num_plan_vals), 0x1e,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_cld_pn_num,
            { "Forward MS Information Record Called Party Number:  Number", "ansi_a_bsmap.fwd_ms_info_rec.cld_pn.num",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_clg_pn_num_type,
            { "Forward MS Information Record Calling Party Number:  Number Type", "ansi_a_bsmap.fwd_ms_info_rec.clg_pn.num_type",
            FT_UINT16, BASE_DEC, VALS(ansi_a_ms_info_rec_num_type_vals), 0xe000,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_clg_pn_num_plan,
            { "Forward MS Information Record Calling Party Number:  Number Plan", "ansi_a_bsmap.fwd_ms_info_rec.clg_pn.num_plan",
            FT_UINT16, BASE_DEC, VALS(ansi_a_ms_info_rec_num_plan_vals), 0x1e00,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_clg_pn_num,
            { "Forward MS Information Record Calling Party Number:  Number", "ansi_a_bsmap.fwd_ms_info_rec.clg_pn.num",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_clg_pn_pi,
            { "Forward MS Information Record Calling Party Number:  PI", "ansi_a_bsmap.fwd_ms_info_rec.clg_pn.pi",
            FT_UINT16, BASE_DEC, VALS(ansi_a_ms_info_rec_clg_pn_pi_vals), 0x0180,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_clg_pn_si,
            { "Forward MS Information Record Calling Party Number:  SI", "ansi_a_bsmap.fwd_ms_info_rec.clg_pn.si",
            FT_UINT16, BASE_DEC, VALS(ansi_a_ms_info_rec_clg_pn_si_vals), 0x0060,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_mw_num,
            { "Number of messages waiting", "ansi_a_bsmap.fwd_ms_info_rec.mw.num",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_fwd_ms_info_rec_content,
            { "Forward MS Information Record Content", "ansi_a_bsmap.fwd_ms_info_rec.content",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_cld_pn_num_type,
            { "Reverse MS Information Record Called Party Number:  Number Type", "ansi_a_bsmap.rev_ms_info_rec.cld_pn.num_type",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ms_info_rec_num_type_vals), 0xe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_cld_pn_num_plan,
            { "Reverse MS Information Record Called Party Number:  Number Plan", "ansi_a_bsmap.rev_ms_info_rec.cld_pn.num_plan",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ms_info_rec_num_plan_vals), 0x1e,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_cld_pn_num,
            { "Reverse MS Information Record Called Party Number:  Number", "ansi_a_bsmap.rev_ms_info_rec.cld_pn.num",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_clg_pn_num_type,
            { "Reverse MS Information Record Calling Party Number:  Number Type", "ansi_a_bsmap.rev_ms_info_rec.clg_pn.num_type",
            FT_UINT16, BASE_DEC, VALS(ansi_a_ms_info_rec_num_type_vals), 0xe000,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_clg_pn_num_plan,
            { "Reverse MS Information Record Calling Party Number:  Number Plan", "ansi_a_bsmap.rev_ms_info_rec.clg_pn.num_plan",
            FT_UINT16, BASE_DEC, VALS(ansi_a_ms_info_rec_num_plan_vals), 0x1e00,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_clg_pn_pi,
            { "Reverse MS Information Record Calling Party Number:  PI", "ansi_a_bsmap.rev_ms_info_rec.clg_pn.pi",
            FT_UINT16, BASE_DEC, VALS(ansi_a_ms_info_rec_clg_pn_pi_vals), 0x0180,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_clg_pn_si,
            { "Reverse MS Information Record Calling Party Number:  SI", "ansi_a_bsmap.rev_ms_info_rec.clg_pn.si",
            FT_UINT16, BASE_DEC, VALS(ansi_a_ms_info_rec_clg_pn_si_vals), 0x0060,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_clg_pn_num,
            { "Reverse MS Information Record Calling Party Number:  Number", "ansi_a_bsmap.rev_ms_info_rec.clg_pn.num",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_so_info_fwd_support,
            { "Forward Support", "ansi_a_bsmap.rev_ms_info_rec.so_info.fwd_support",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_so_info_rev_support,
            { "Reverse Support", "ansi_a_bsmap.rev_ms_info_rec.so_info.rev_support",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_so_info_so,
            { "Service Option", "ansi_a_bsmap.rev_ms_info_rec.so_info.so",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_ms_info_rec_content,
            { "Reverse MS Information Record Content", "ansi_a_bsmap.rev_ms_info_rec.content",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_srch_win_a,
            { "Search Window A Size (Srch_Win_A)", "ansi_a_bsmap.ext_ho_dir_params.srch_win_a",
            FT_UINT8, BASE_DEC, VALS(ansi_a_srch_win_sizes_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_srch_win_n,
            { "Search Window N Size (Srch_Win_N)", "ansi_a_bsmap.ext_ho_dir_params.srch_win_n",
            FT_UINT8, BASE_DEC, VALS(ansi_a_srch_win_sizes_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_srch_win_r,
            { "Search Window R Size (Srch_Win_R)", "ansi_a_bsmap.ext_ho_dir_params.srch_win_r",
            FT_UINT8, BASE_DEC, VALS(ansi_a_srch_win_sizes_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_t_add,
            { "Add Pilot Threshold (T_Add)", "ansi_a_bsmap.ext_ho_dir_params.t_add",
            FT_UINT16, BASE_DEC, NULL, 0x0fc0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_t_drop,
            { "Drop Pilot Threshold (T_Drop)", "ansi_a_bsmap.ext_ho_dir_params.t_drop",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_t_comp,
            { "Compare Threshold (T_Comp)", "ansi_a_bsmap.ext_ho_dir_params.t_comp",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_t_tdrop,
            { "Drop Timer Value (T_TDrop)", "ansi_a_bsmap.ext_ho_dir_params.t_tdrop",
            FT_UINT8, BASE_DEC, VALS(ansi_a_t_tdrop_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_nghbor_max_age,
            { "Neighbor Max Age (Nghbor_Max_AGE)", "ansi_a_bsmap.ext_ho_dir_params.nghbor_max_age",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_target_bs_values_incl,
            { "Target BS Values Included", "ansi_a_bsmap.ext_ho_dir_params.target_bs_values_incl",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ext_ho_dir_params_target_bs_values_incl_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_soft_slope,
            { "SOFT_SLOPE", "ansi_a_bsmap.ext_ho_dir_params.soft_slope",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_add_intercept,
            { "ADD_INTERCEPT", "ansi_a_bsmap.ext_ho_dir_params.add_intercept",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_drop_intercept,
            { "DROP_INTERCEPT", "ansi_a_bsmap.ext_ho_dir_params.drop_intercept",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_ansi_a_ext_ho_dir_params_target_bs_p_rev,
            { "Target BS P_REV", "ansi_a_bsmap.ext_ho_dir_params.target_bs_p_rev",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cdma_sowd_sowd,
            { "CDMA Serving One Way Delay", "ansi_a_bsmap.cdma_sowd.sowd",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cdma_sowd_resolution,
            { "Resolution", "ansi_a_bsmap.cdma_sowd.resolution",
            FT_UINT8, BASE_DEC, VALS(ansi_a_cdma_sowd_resolution_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_a_cdma_sowd_timestamp,
            { "CDMA Serving One Way Delay Time Stamp", "ansi_a_bsmap.cdma_sowd.timestamp",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_re_res_prio_incl,
            { "Include Priority", "ansi_a_bsmap.re_res.prio_incl",
            FT_BOOLEAN, 8, TFS(&tfs_prio_incl_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_a_re_res_forward,
            { "Forward", "ansi_a_bsmap.re_res.forward",
            FT_UINT8, BASE_DEC, VALS(ansi_a_re_res_vals), 0x30,
            NULL, HFILL }
        },
        { &hf_ansi_a_re_res_reverse,
            { "Reverse", "ansi_a_bsmap.re_res.reverse",
            FT_UINT8, BASE_DEC, VALS(ansi_a_re_res_vals), 0x0c,
            NULL, HFILL }
        },
        { &hf_ansi_a_re_res_alloc,
            { "Alloc", "ansi_a_bsmap.re_res.alloc",
            FT_BOOLEAN, 8, TFS(&tfs_alloc_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_re_res_avail,
            { "Avail", "ansi_a_bsmap.re_res.avail",
            FT_BOOLEAN, 8, TFS(&tfs_avail_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_cld_party_ascii_num_ton,
            { "Type of Number", "ansi_a_bsmap.cld_party_ascii_num.ton",
            /* Should actually be as defined by ATIS-1000607.2000 (but I don't have that) */
            FT_UINT8, BASE_DEC, VALS(ansi_a_cld_party_bcd_num_ton_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_cld_party_ascii_num_plan,
            { "Numbering Plan Identification", "ansi_a_bsmap.cld_party_ascii_num.plan",
            /* Should actually be as defined by ATIS-1000607.2000 (but I don't have that) */
            FT_UINT8, BASE_DEC, VALS(ansi_a_cld_party_bcd_num_plan_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_band_class,
            { "Band Class", "ansi_a_bsmap.band_class",
            FT_UINT8, BASE_DEC, VALS(ansi_a_band_class_vals), 0x1f,
            NULL, HFILL }
        },
        { &hf_ansi_a_is2000_cause,
            { "Cause", "ansi_a_bsmap.is2000_cause",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_auth_event,
            { "Event", "ansi_a_bsmap.auth_event",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_psmm_count,
            { "PSMM Count", "ansi_a_bsmap.psmm_count",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_geo_loc,
            { "Calling Geodetic Location (CGL)", "ansi_a_bsmap.geo_loc",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cct_group_all_circuits,
            { "All Circuits", "ansi_a_bsmap.cct_group.all_circuits",
            FT_BOOLEAN, 8, TFS(&tfs_avail_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_a_cct_group_inclusive,
            { "Inclusive", "ansi_a_bsmap.cct_group.inclusive",
            FT_BOOLEAN, 8, TFS(&tfs_avail_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_cct_group_count,
            { "Count", "ansi_a_bsmap.cct_group.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cct_group_first_cic,
            { "First CIC", "ansi_a_bsmap.cct_group.first_cic",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cct_group_first_cic_pcm_multi,
            { "First CIC PCM Multiplexer", "ansi_a_bsmap.cct_group.first_cic.pcm_multi",
            FT_UINT16, BASE_DEC, NULL, 0xffe0,
            NULL, HFILL }
        },
        { &hf_ansi_a_cct_group_first_cic_timeslot,
            { "First CIC Timeslot", "ansi_a_bsmap.cct_group.first_cic.timeslot",
            FT_UINT16, BASE_DEC, NULL, 0x001f,
            NULL, HFILL }
        },
        { &hf_ansi_a_paca_timestamp_queuing_time,
            { "PACA Queuing Time", "ansi_a_bsmap.paca_timestamp.queuing_time",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_paca_order_action_reqd,
            { "PACA Action Required", "ansi_a_bsmap.paca_order.action_reqd",
            FT_UINT8, BASE_DEC, VALS(ansi_a_paca_order_action_reqd_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_paca_reoi_pri,
            { "PACA Reorigination Indicator (PRI)", "ansi_a_bsmap.paca_reoi.pri",
            FT_BOOLEAN, 8, TFS(&tfs_reoi_pri_reorig_no_reorig), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_sess_max_frames,
            { "Max Frames", "ansi_a_bsmap.a2p_bearer_sess.max_frames",
            FT_UINT8, BASE_DEC, NULL, 0x38,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_sess_ip_addr_type,
            { "Session IP Address Type", "ansi_a_bsmap.a2p_bearer_sess.ip_addr_type",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ip_addr_type_vals), 0x06,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_sess_addr_flag,
            { "Session Address Flag", "ansi_a_bsmap.a2p_bearer_sess.addr_flag",
            FT_BOOLEAN, 8, TFS(&tfs_a2p_bearer_sess_addr_flag), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_sess_ipv4_addr,
            { "Session IP Address", "ansi_a_bsmap.a2p_bearer_sess.ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_sess_ipv6_addr,
            { "Session IP Address", "ansi_a_bsmap.a2p_bearer_sess.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_sess_udp_port,
            { "Session UDP Port", "ansi_a_bsmap.a2p_bearer_sess.udp_port",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_num_formats,
            { "Number of Bearer Formats", "ansi_a_bsmap.a2p_bearer_form.num_formats",
            FT_UINT8, BASE_DEC, NULL, 0xfc,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_ip_addr_type,
            { "Bearer IP Address Type", "ansi_a_bsmap.a2p_bearer_form.ip_addr_type",
            FT_UINT8, BASE_DEC, VALS(ansi_a_ip_addr_type_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_len,
            { "Bearer Format Length", "ansi_a_bsmap.a2p_bearer_form.format.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_tag_type,
            { "Bearer Format Tag Type", "ansi_a_bsmap.a2p_bearer_form.format.tag_type",
            FT_UINT8, BASE_DEC, VALS(ansi_a_a2p_bearer_form_format_tag_type_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_format_id,
            { "Bearer Format ID", "ansi_a_bsmap.a2p_bearer_form.format.format_id",
            FT_UINT8, BASE_DEC, VALS(ansi_a_a2p_bearer_form_format_format_id_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_rtp_payload_type,
            { "RTP Payload Type", "ansi_a_bsmap.a2p_bearer_form.format.rtp_payload_type",
            FT_UINT8, BASE_DEC, NULL, 0xfe,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_bearer_addr_flag,
            { "Bearer Address Flag", "ansi_a_bsmap.a2p_bearer_form.format.bearer_addr_flag",
            FT_BOOLEAN, 8, TFS(&tfs_a2p_bearer_form_format_bearer_addr_flag), 0x01,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_ipv4_addr,
            { "Bearer IP Address", "ansi_a_bsmap.a2p_bearer_form.format.ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_ipv6_addr,
            { "Bearer IP Address", "ansi_a_bsmap.a2p_bearer_form.format.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_udp_port,
            { "Bearer UDP Port", "ansi_a_bsmap.a2p_bearer_form.format.udp_port",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_ext_len,
            { "Extension Length", "ansi_a_bsmap.a2p_bearer_form.format.ext_len",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_a2p_bearer_form_format_ext_id,
            { "Extension ID", "ansi_a_bsmap.a2p_bearer_form.format.ext_id",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_ansi_a_ms_des_freq_band_class,
            { "Band Class", "ansi_a_bsmap.ms_des_freq.band_class",
            FT_UINT16, BASE_DEC, VALS(ansi_a_band_class_vals), 0xf800,
            NULL, HFILL }
        },
        { &hf_ansi_a_ms_des_freq_cdma_channel,
            { "CDMA Channel", "ansi_a_bsmap.ms_des_freq.cdma_channel",
            FT_UINT16, BASE_DEC, NULL, 0x07ff,
            NULL, HFILL }
        },
        { &hf_ansi_a_plcm_id_plcm_type,
            { "PLCM_TYPE", "ansi_a_bsmap.plcm_id.plcm_type",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_ansi_a_bdtmf_trans_info_dtmf_off_len,
            { "DTMF Off Length", "ansi_a_bsmap.bdtmf_trans_info.dtmf_off_len",
            FT_UINT8, BASE_DEC, VALS(ansi_a_bdtmf_trans_info_dtmf_off_len_vals), 0x38,
            NULL, HFILL }
        },
        { &hf_ansi_a_bdtmf_trans_info_dtmf_on_len,
            { "DTMF On Length", "ansi_a_bsmap.bdtmf_trans_info.dtmf_on_len",
            FT_UINT8, BASE_DEC, VALS(ansi_a_bdtmf_trans_info_dtmf_on_len_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_a_bdtmf_chars_num_chars,
            { "DTMF Number of Characters", "ansi_a_bsmap.bdtmf_chars.num_chars",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_bdtmf_chars_digits,
            { "DTMF Digits", "ansi_a_bsmap.bdtmf_chars.digits",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_encryption_parameter_value,
            { "Encryption Parameter value", "ansi_a_bsmap.encryption_parameter_value",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_layer3_info,
            { "Layer 3 Information", "ansi_a_bsmap.layer3_info",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_manufacturer_software_info,
            { "Manufacturer/Carrier Software Information", "ansi_a_bsmap.manufacturer_software_info",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_circuit_bitmap,
            { "Circuit Bitmap", "ansi_a_bsmap.circuit_bitmap",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_extension_parameter_value,
            { "Extension Parameter value", "ansi_a_bsmap.extension_parameter_value",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_msb_first_digit,
            { "MSB of first digit", "ansi_a_bsmap.msb_first_digit",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_dcch_cc_incl,
            { "DCCH_CC_INCL (Channel configuration for the Dedicated Control Channel included indicator)", "ansi_a_bsmap.dcch_cc_incl",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_for_sch_cc_incl,
            { "FOR_SCH_CC_INCL (Channel configuration for the Dedicated Control Channel included indicator)", "ansi_a_bsmap.for_sch_cc_incl",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_rev_sch_cc_incl,
            { "REV_SCH_CC_INCL (Channel configuration for the Dedicated Control Channel included indicator)", "ansi_a_bsmap.rev_sch_cc_incl",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_a_plcm42,
            { "PLCM_42", "ansi_a_bsmap.plcm42",
            FT_BOOLEAN, 56, NULL, G_GUINT64_CONSTANT(0x3FFFFFFFFFF),
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_ansi_a_extraneous_data,
            { "ansi_a.extraneous_data", PI_PROTOCOL, PI_NOTE,
            "Extraneous Data - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_short_data,
            { "ansi_a.short_data", PI_PROTOCOL, PI_NOTE,
            "Short Data (?) - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_missing_mand_elem,
            { "ansi_a.missing_mand_elem", PI_PROTOCOL, PI_WARN,
            "Missing Mandatory element, rest of dissection is suspect - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_unknown_format,
            { "ansi_a.unknown_format", PI_PROTOCOL, PI_WARN,
            "Format Unknown/Unsupported - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_no_tlv_elem_diss,
            { "ansi_a.no_tlv_elem_dissector", PI_PROTOCOL, PI_NOTE,
            "No TLV element dissector - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_no_tv_elem_diss,
            { "ansi_a.no_tv_elem_dissector", PI_PROTOCOL, PI_WARN /* because we don't know length */,
            "No TV element dissector, rest of dissection is suspect - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_no_lv_elem_diss,
            { "ansi_a.no_lv_elem_dissector", PI_PROTOCOL, PI_NOTE,
            "No LV element dissector - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_no_v_elem_diss,
            { "ansi_a.no_v_elem_dissector", PI_PROTOCOL, PI_WARN /* because we don't know length */,
            "No V element dissector, rest of dissection is suspect - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_miss_dtap_msg_diss,
            { "ansi_a.miss_dtap_msg_dissector", PI_PROTOCOL, PI_NOTE,
            "Missing DTAP message dissector - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_miss_bsmap_msg_diss,
            { "ansi_a.miss_bsmap_msg_dissector", PI_PROTOCOL, PI_NOTE,
            "Missing BSMAP message dissector - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_is2000_chan_id_pilot_pn,
            { "ansi_a.is2000_chan_id_pilot_pn", PI_PROTOCOL, PI_NOTE,
            "This parameter has a unique encoding.  The most significant bit comes after the LSBs unlike typical IOS octet split values.",
            EXPFILL }
        },
        { &ei_ansi_a_unknown_dtap_msg,
            { "ansi_a.unknown_dtap_msg", PI_PROTOCOL, PI_WARN,
            "DTAP Message Unknown/Unsupported - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_unknown_bsmap_msg,
            { "ansi_a.unknown_bsmap_msg", PI_PROTOCOL, PI_WARN,
            "BSMAP Message Unknown/Unsupported - try checking decoder variant preference or dissector bug/later version spec (report to wireshark.org)",
            EXPFILL }
        },
        { &ei_ansi_a_undecoded,
            { "ansi_a.undecoded", PI_UNDECODED, PI_WARN,
            "Can't be bothered to do the rest of the decode",
            EXPFILL }
        }
    };

    expert_module_t     *expert_a_bsmap;

    static const enum_val_t a_variant_options[] = {
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
#define NUM_INDIVIDUAL_ELEMS    24
    gint *ett[NUM_INDIVIDUAL_ELEMS+MAX_NUM_DTAP_MSG+MAX_NUM_BSMAP_MSG+MAX_NUM_ELEM_1+NUM_FWD_MS_INFO_REC+NUM_REV_MS_INFO_REC];

    static stat_tap_table_ui dtap_stat_table = {
        REGISTER_STAT_GROUP_TELEPHONY_ANSI,
        "A-I/F DTAP Statistics",
        "ansi_a",
        "ansi_a,dtap",
        ansi_a_dtap_stat_init,
        ansi_a_dtap_stat_packet,
        ansi_a_stat_reset,
        NULL,
        NULL,
        sizeof(dtap_stat_fields)/sizeof(stat_tap_table_item), dtap_stat_fields,
        0, NULL,
        NULL,
        0
    };

    static stat_tap_table_ui bsmap_stat_table = {
        REGISTER_STAT_GROUP_TELEPHONY_ANSI,
        "A-I/F BSMAP Statistics",
        "ansi_a",
        "ansi_a,bsmap",
        ansi_a_bsmap_stat_init,
        ansi_a_bsmap_stat_packet,
        ansi_a_stat_reset,
        NULL,
        NULL,
        sizeof(bsmap_stat_fields)/sizeof(stat_tap_table_item), bsmap_stat_fields,
        0, NULL,
        NULL,
        0
    };

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
    ett[15] = &ett_scr_socr;
    ett[16] = &ett_cm2_band_class;
    ett[17] = &ett_vp_algs;
    ett[18] = &ett_chan_list;
    ett[19] = &ett_cic;
    ett[20] = &ett_is2000_mob_cap_fch_info;
    ett[21] = &ett_is2000_mob_cap_dcch_info;
    ett[22] = &ett_is2000_mob_cap_for_pdch_info;
    ett[23] = &ett_is2000_mob_cap_rev_pdch_info;

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

    expert_a_bsmap =
        expert_register_protocol(proto_a_bsmap);
    expert_register_field_array(expert_a_bsmap, ei, array_length(ei));

    proto_a_dtap =
        proto_register_protocol("ANSI A-I/F DTAP", "ANSI DTAP", "ansi_a_dtap");

    is637_dissector_table =
        register_dissector_table("ansi_a.sms", "IS-637-A (SMS)",
        proto_a_bsmap, FT_UINT8, BASE_DEC);

    is683_dissector_table =
        register_dissector_table("ansi_a.ota", "IS-683-A (OTA)",
        proto_a_bsmap, FT_UINT8, BASE_DEC);

    is801_dissector_table =
        register_dissector_table("ansi_a.pld", "IS-801 (PLD)",
        proto_a_bsmap, FT_UINT8, BASE_DEC);

    proto_register_subtree_array(ett, array_length(ett));

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

    prefs_register_bool_preference(ansi_a_module,
        "top_display_mid_so",
        "Show mobile ID and service option in the INFO column",
        "Whether the mobile ID and service options are displayed in the INFO column",
        &global_a_info_display);

    register_stat_tap_table_ui(&dtap_stat_table);
    register_stat_tap_table_ui(&bsmap_stat_table);
}


void
proto_reg_handoff_ansi_a(void)
{
    static gboolean ansi_a_prefs_initialized = FALSE;

    if (!ansi_a_prefs_initialized)
    {
        dissector_handle_t      bsmap_handle, sip_dtap_bsmap_handle;

        bsmap_handle = create_dissector_handle(dissect_bsmap, proto_a_bsmap);
        dtap_handle = create_dissector_handle(dissect_dtap, proto_a_dtap);
        sip_dtap_bsmap_handle = create_dissector_handle(dissect_sip_dtap_bsmap, proto_a_dtap);

        dissector_add_uint("bsap.pdu_type",  BSSAP_PDU_TYPE_BSMAP, bsmap_handle);
        dissector_add_uint("bsap.pdu_type",  BSSAP_PDU_TYPE_DTAP, dtap_handle);
        dissector_add_string("media_type", "application/femtointerfacemsg", sip_dtap_bsmap_handle);
        dissector_add_string("media_type", "application/vnd.3gpp2.femtointerfacemsg", sip_dtap_bsmap_handle);

        ansi_a_prefs_initialized = TRUE;
    }

    switch (global_a_variant)
    {
    case A_VARIANT_IOS501:
        ansi_a_bsmap_strings = ansi_a_ios501_bsmap_strings;
        ansi_a_dtap_strings = ansi_a_ios501_dtap_strings;
        ansi_a_elem_1_strings = ansi_a_ios501_elem_1_strings;
        ansi_a_elem_1_max = (elem_idx_t) MAX_IOS501_NUM_ELEM_1;
        break;

    default:
        ansi_a_bsmap_strings = ansi_a_ios401_bsmap_strings;
        ansi_a_dtap_strings = ansi_a_ios401_dtap_strings;
        ansi_a_elem_1_strings = ansi_a_ios401_elem_1_strings;
        ansi_a_elem_1_max = (elem_idx_t) MAX_IOS401_NUM_ELEM_1;
        break;
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
