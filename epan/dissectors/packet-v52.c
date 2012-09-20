/* packet-v52.c
 * $Id$
 * Implementation for V5.2 Interface dissection
 * References:
 * ETSI EN 300 324-1 V2.1.1 (2000-04)
 * ETSI EN 300 347-1 V2.2.2 (1999-12)
 *
 * Copyright 2009
 *
 * ISKRATEL d.o.o.             |       4S d.o.o.
 * http://www.iskratel.si/     |       http://www.4es.si/
 * <info@iskratel.si>          |       <projects@4es.si>
 * Vladimir Smrekar <vladimir.smrekar@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

static int proto_v52                           = -1;
static int hf_v52_discriminator                = -1;

static gint ett_v52                            = -1;
static gint ett_v52_info                       = -1;

static int hf_v52_address                      = -1;
static int hf_v52_low_address                  = -1;

static int hf_v52_msg_type                     = -1;
static int hf_v52_info_element                 = -1;

static int hf_v52_isdn_address                 = -1;
static int hf_v52_isdn_low_address             = -1;
static int hf_v52_pstn_address                 = -1;
static int hf_v52_pstn_low_address             = -1;
static int hf_v52_link_address                 = -1;
static int hf_v52_link_low_address             = -1;
static int hf_v52_bcc_address                  = -1;
static int hf_v52_bcc_low_address              = -1;
static int hf_v52_prot_address                 = -1;
static int hf_v52_prot_low_address             = -1;
static int hf_v52_ctrl_address                 = -1;
static int hf_v52_ctrl_low_address             = -1;
static int hf_v52_cadenced_ring                = -1;
static int hf_v52_pulse_notification           = -1;
static int hf_v52_info_length                  = -1;

/*PSTN Message*/
static int hf_v52_line_info                    = -1;
static int hf_v52_pulse_type                   = -1;
static int hf_v52_suppression_indicator        = -1;
static int hf_v52_pulse_duration               = -1;
static int hf_v52_ack_request_indicator        = -1;
static int hf_v52_number_of_pulses             = -1;
static int hf_v52_steady_signal                = -1;
static int hf_v52_auto_signalling_sequence     = -1;
static int hf_v52_sequence_response            = -1;
static int hf_v52_digit_ack                    = -1;
static int hf_v52_digit_spare                  = -1;
static int hf_v52_digit_info                   = -1;
static int hf_v52_res_unavailable              = -1;
static int hf_v52_state                        = -1;
static int hf_v52_cause_type                   = -1;
static int hf_v52_pstn_sequence_number         = -1;
static int hf_v52_duration_type                = -1;
/*Link control*/
static int hf_v52_link_control_function        = -1;
/*Protection protocol*/
static int hf_v52_rejection_cause              = -1;
static int hf_v52_error_cause                  = -1;
static int hf_v52_diagnostic_msg               = -1;
static int hf_v52_diagnostic_element           = -1;
/*BCC protocol*/
static int hf_v52_pstn_user_port_id            = -1;
static int hf_v52_pstn_user_port_id_lower      = -1;

static int hf_v52_isdn_user_port_id            = -1;
static int hf_v52_isdn_user_port_id_lower      = -1;

static int hf_v52_isdn_user_port_ts_num        = -1;
static int hf_v52_override                     = -1;
static int hf_v52_reject_cause_type            = -1;
static int hf_v52_bcc_protocol_error_cause     = -1;
static int hf_v52_connection_incomplete_reason = -1;

static int hf_v52_diagnostic_message           = -1;
static int hf_v52_diagnostic_information       = -1;

/*Control protocol*/
static int hf_v52_control_function_element     = -1;
static int hf_v52_control_function_id          = -1;
static int hf_v52_variant                      = -1;
static int hf_v52_if_up_id                     = -1;
static int hf_v52_if_id                        = -1;
static int hf_v52_if_low_id                    = -1;
static int hf_v52_if_all_id                    = -1;
static int hf_v52_performance_grading          = -1;
static int hf_v52_cp_rejection_cause           = -1;

static int hf_v52_v5_link_id                   = -1;
static int hf_v52_v5_time_slot                 = -1;
static int hf_v52_sequence_number              = -1;

static int hf_v52_v5_multi_slot_elements       = -1;

static int message_type_tmp                    = -1;

static void
dissect_v52_protocol_discriminator(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    unsigned int discriminator = tvb_get_guint8(tvb, offset);


    if (discriminator == 0x48) {
        proto_tree_add_uint_format(tree, hf_v52_discriminator, tvb, offset, 1, discriminator,
            "Protocol discriminator: V5.2 (0x%02X)",
            discriminator);
    } else {
        proto_tree_add_uint_format(tree, hf_v52_discriminator,
            tvb, offset, 1, discriminator,
            "Protocol discriminator: Reserved (0x%02X)",
            discriminator);
    }
}

/*============================*/
/*   V52 MESSAGE TYPE START   */
/*============================*/

/* message types of PSTN */
#define ESTABLISH              0x00
#define ESTABLISH_ACK          0x01
#define SIGNAL                 0x02
#define SIGNAL_ACK             0x03
#define DISCONNECT             0x08
#define DISCONNECT_COMPLETE    0x09
#define STATUS_ENQUIRY         0x0c
#define STATUS                 0x0d
#define PROTOCOL_PARAMETER     0x0e
/* message types of Control protocol */
#define PORT_CONTROL           0x10
#define PORT_CONTROL_ACK       0x11
#define COMMON_CONTROL         0x12
#define COMMON_CONTROL_ACK     0x13
/* message types of PROT protocol */
#define SWITCH_OVER_REQ        0x18
#define SWITCH_OVER_COM        0x19
#define OS_SWITCH_OVER_COM     0x1a
#define SWITCH_OVER_ACK        0x1b
#define SWITCH_OVER_REJECT     0x1c
#define PROT_PROTOCOL_ERROR    0x1d
#define RESET_SN_COM           0x1e
#define RESET_SN_ACK           0x1f
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
#define LINK_CONTROL           0x30
#define LINK_CONTROL_ACK       0x31

static const value_string msg_type_values [] = {
    { ESTABLISH,             "Establish" },
    { ESTABLISH_ACK,         "Establish Ack" },
    { SIGNAL,                "Signal" },
    { SIGNAL_ACK,            "Signal Ack" },
    { DISCONNECT,            "Disconnect" },
    { DISCONNECT_COMPLETE,   "Disconnect Complete" },
    { STATUS_ENQUIRY,        "Status Enqury" },
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
    { PROT_PROTOCOL_ERROR,   "Protocol Error" },
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
    { BCC_PROTOCOL_ERROR,    "Protocol Error" },
    { LINK_CONTROL,          "Link Control" },
    { LINK_CONTROL_ACK,      "Link Control Ack" },
    { 0,                     NULL } };

/* SHORT */
static const value_string msg_type_values_short [] = {
    { ESTABLISH,             "Establish" },
    { ESTABLISH_ACK,         "Establish Ack" },
    { SIGNAL,                "Signal" },
    { SIGNAL_ACK,            "Signal Ack" },
    { DISCONNECT,            "Disconnect" },
    { DISCONNECT_COMPLETE,   "Disconnect Com" },
    { STATUS_ENQUIRY,        "Status Enq" },
    { STATUS,                "Status" },
    { PROTOCOL_PARAMETER,    "Prot Para" },
    { PORT_CONTROL,          "PortCtrl" },
    { PORT_CONTROL_ACK,      "PortCtrl Ack" },
    { COMMON_CONTROL,        "CCtrl" },
    { COMMON_CONTROL_ACK,    "CCtrl Ack" },
    { SWITCH_OVER_REQ,       "SO Req" },
    { SWITCH_OVER_COM,       "SO Com" },
    { OS_SWITCH_OVER_COM,    "OS SO Com" },
    { SWITCH_OVER_ACK,       "SO Ack" },
    { SWITCH_OVER_REJECT,    "SO Rej" },
    { PROT_PROTOCOL_ERROR,   "Prot Err" },
    { RESET_SN_COM,          "Res SN Com" },
    { RESET_SN_ACK,          "Res SN Ack" },
    { ALLOCATION,            "BCC Alloc" },
    { ALLOCATION_COMPLETE,   "BCC Alloc Comp" },
    { ALLOCATION_REJECT,     "BCC Allo Rej" },
    { DE_ALLOCATION,         "BCC DE-Alloc" },
    { DE_ALLOCATION_COMPLETE,"BCC DE-Alloc Comp" },
    { DE_ALLOCATION_REJECT,  "BCC DE-Alloc Rej" },
    { AUDIT,                 "BCC Audit" },
    { AUDIT_COMPLETE,        "BCC Audit Comp" },
    { AN_FAULT,              "BCC AN Fault" },
    { AN_FAULT_ACKNOWLEDGE,  "BCC AN Fault Ack" },
    { BCC_PROTOCOL_ERROR,    "BCC Prot Error" },
    { LINK_CONTROL,          "LinkCtrl" },
    { LINK_CONTROL_ACK,      "LinkCtrl Ack" },
    { 0,                     NULL } };

static const value_string pulse_type_values [] = {
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

static const value_string suppression_indication_values [] = {
    { 0x0, "No suppression" },
    { 0x1, "Suppression allowed by pre-defined V5.1 SIGNAL msg from LE" },
    { 0x2, "Suppression allowed by pre-defined line signal from TE" },
    { 0x3, "Suppression allowed by pre-defined V5.1 SIGNAL msg from LE or line signal from TE" },
    { 0,   NULL } };

static const value_string ack_request_indication_values [] = {
    { 0x0, "No acknowledgement requested" },
    { 0x1, "Ending acknowledgement requested when finished each pulses" },
    { 0x2, "Ending acknowledgement requested when finished all pulses" },
    { 0x3, "Start of pulse acknowledgement requested" },
    { 0,   NULL } };

static const value_string steady_signal_values [] = {
    { 0x00, "Normal polarity" },
    { 0x01, "Reversed polarity" },
    { 0x02, "Battery on c-wire" },
    { 0x03, "No battery on c-wire" },
    { 0x04, "Off hook (loop closed)" },
    { 0x05, "On hook (loop open)" },
    { 0x06, "Battery on a-wire" },
    { 0x07, "A-wire on earth" },
    { 0x08, "No battery on a-wire" },
    { 0x09, "No battery on b-wire" },
    { 0x0a, "Reduced battery" },
    { 0x0b, "No battery" },
    { 0x0c, "Alternate reduced power / no power" },
    { 0x0d, "Normal battery" },
    { 0x0e, "Stop ringing" },
    { 0x0f, "Start pilot frequency" },
    { 0x10, "Stop pilot frequency" },
    { 0x11, "Low impedance on b-wire" },
    { 0x12, "B-wire connected to earth" },
    { 0x13, "B-wire disconnected from earth" },
    { 0x14, "Battery on b-wire" },
    { 0x15, "Low loop impedance" },
    { 0x16, "High loop impedance" },
    { 0x17, "Anomalous loop impedance" },
    { 0x18, "A-wire disconnected from earth" },
    { 0x19, "C-wire on earth" },
    { 0x1a, "C-wire disconnected from earth" },
    { 0x1d, "Ramp to reverse polarity" },
    { 0x1e, "Ramp to normal polarity" },
    { 0,    NULL } };

static const value_string digit_ack_values [] = {
    { 0x0, "No ending acknowledgement requested" },
    { 0x1, "Ending acknowledgement requested when digit transmission is finished" },
    { 0,   NULL } };

static const value_string line_info_values [] = {
    { 0x00, "Impedance marker reset" },
    { 0x01, "Impedance marker set" },
    { 0x02, "Low loop impedance" },
    { 0x03, "Anomalous loop impedance" },
    { 0x04, "Anomalous line condition received"},
    { 0,    NULL } };

static const value_string state_values [] = {
    { 0x00, "AN0" },
    { 0x01, "AN1" },
    { 0x02, "AN2" },
    { 0x03, "AN3" },
    { 0x04, "AN4" },
    { 0x05, "AN5" },
    { 0x06, "AN6" },
    { 0x07, "AN7" },
    { 0x0f, "Not applicable" },
    { 0,    NULL } };

static const value_string control_function_element_values [] = {
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
    { 0x19, "FE209 (TE out of service)" },
    { 0x1A, "FE210 (failure inside network)" },
    { 0,    NULL } };

static const value_string control_function_id_values [] = {
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
    { 0x12, "UNBLOCK ALL RELEVANT PSTN AND ISDN PORTS REQUEST" },
    { 0x13, "UNBLOCK ALL RELEVANT PSTN AND ISDN PORTS ACCEPTED" },
    { 0x14, "UNBLOCK ALL RELEVANT PSTN AND ISDN PORTS REJECTED" },
    { 0x15, "UNBLOCK ALL RELEVANT PSTN AND ISDN PORTS COMPLETED" },
    { 0x16, "UNBLOCK ALL RELEVANT PSTN PORTS REQUEST" },
    { 0x17, "UNBLOCK ALL RELEVANT PSTN PORTS ACCEPTED" },
    { 0x18, "UNBLOCK ALL RELEVANT PSTN PORTS REJECTED" },
    { 0x19, "UNBLOCK ALL RELEVANT PSTN PORTS COMPLETED" },
    { 0x1a, "UNBLOCK ALL RELEVANT ISDN PORTS REQUEST" },
    { 0x1b, "UNBLOCK ALL RELEVANT ISDN PORTS ACCEPTED" },
    { 0x1c, "UNBLOCK ALL RELEVANT ISDN PORTS REJECTED" },
    { 0x1d, "UNBLOCK ALL RELEVANT ISDN PORTS COMPLETED" },
    { 0x1e, "BLOCK ALL PSTN PORTS REQUEST" },
    { 0x1f, "BLOCK ALL PSTN PORTS ACCEPTED" },
    { 0x20, "BLOCK ALL PSTN PORTS REJECTED" },
    { 0x21, "BLOCK ALL PSTN PORTS COMPLETED" },
    { 0x22, "BLOCK ALL ISDN PORTS REQUEST" },
    { 0x23, "BLOCK ALL ISDN PORTS ACCEPTED" },
    { 0x24, "BLOCK ALL ISDN PORTS REJECTED" },
    { 0x25, "BLOCK ALL ISDN PORTS COMPLETED" },
    { 0,    NULL } };

static const value_string control_function_id_values_short [] = {
    { 0x00, "VerifyRe-pro" },
    { 0x01, "ReadyForRe-pro" },
    { 0x02, "NotReadyForRe-pro" },
    { 0x03, "SO ToNewVar" },
    { 0x04, "Re-pro Started" },
    { 0x05, "CannotRe-pro" },
    { 0x06, "ReqVar & intf ID" },
    { 0x07, "Var & intf ID" },
    { 0x08, "BlockStarted" },
    { 0x10, "RestartReq" },
    { 0x11, "RestartCompl" },
    { 0x12, "UNBLOCK ALL RELEVANT PSTN AND ISDN PORTS REQUEST" },
    { 0x13, "UNBLOCK ALL RELEVANT PSTN AND ISDN PORTS ACCEPTED" },
    { 0x14, "UNBLOCK ALL RELEVANT PSTN AND ISDN PORTS REJECTED" },
    { 0x15, "UNBLOCK ALL RELEVANT PSTN AND ISDN PORTS COMPLETED" },
    { 0x16, "UNBLOCK ALL RELEVANT PSTN PORTS REQUEST" },
    { 0x17, "UNBLOCK ALL RELEVANT PSTN PORTS ACCEPTED" },
    { 0x18, "UNBLOCK ALL RELEVANT PSTN PORTS REJECTED" },
    { 0x19, "UNBLOCK ALL RELEVANT PSTN PORTS COMPLETED" },
    { 0x1a, "UNBLOCK ALL RELEVANT ISDN PORTS REQUEST" },
    { 0x1b, "UNBLOCK ALL RELEVANT ISDN PORTS ACCEPTED" },
    { 0x1c, "UNBLOCK ALL RELEVANT ISDN PORTS REJECTED" },
    { 0x1d, "UNBLOCK ALL RELEVANT ISDN PORTS COMPLETED" },
    { 0x1e, "BLOCK ALL PSTN PORTS REQUEST" },
    { 0x1f, "BLOCK ALL PSTN PORTS ACCEPTED" },
    { 0x20, "BLOCK ALL PSTN PORTS REJECTED" },
    { 0x21, "BLOCK ALL PSTN PORTS COMPLETED" },
    { 0x22, "BLOCK ALL ISDN PORTS REQUEST" },
    { 0x23, "BLOCK ALL ISDN PORTS ACCEPTED" },
    { 0x24, "BLOCK ALL ISDN PORTS REJECTED" },
    { 0x25, "BLOCK ALL ISDN PORTS COMPLETED" },
    { 0,    NULL } };

static const value_string rejection_cause_values [] = {
    { 0x00, "No standby C-channel available" },
    { 0x01, "Target physical C-channel not operational" },
    { 0x02, "Target physical C-channel not provisioned" },
    { 0x03, "Protection switching impossible (AN/LE failure)" },
    { 0x04, "Protection group mismatch" },
    { 0x05, "Requested allocation exists already" },
    { 0x06, "Target physical C-channel already has logical C-channel" },
    { 0,    NULL } };

static const value_string error_cause_values [] = {
    { 0x01, "Protocol discriminator error" },
    { 0x04, "Message type unrecognized" },
    { 0x07, "Mandatory information element missing" },
    { 0x08, "Unrecognized information element" },
    { 0x09, "Mandatory information element content error" },
    { 0x0b, "Message not compatible with protection protocol state" },
    { 0x0c, "Repeated mandatory information element" },
    { 0x0d, "Too many information elements" },
    { 0x0f, "Logical C-Channel identification error" },
    { 0,    NULL } };

static const value_string performance_grading_values [] = {
    { 0x00, "normal grade" },
    { 0x01, "degraded" },
    { 0,    NULL } };

static const value_string cp_rejection_cause_values [] = {
    { 0x00, "variant unknown" },
    { 0x01, "variant known, not ready" },
    { 0x02, "re-provisioning in progress (re-pro)" },
    { 0,    NULL } };

static const value_string reject_cause_type_values [] = {
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

static const value_string bcc_protocol_error_cause_type_values [] = {
    { 0x01, "Protocol discriminator error" },
    { 0x04, "Message type unrecognized" },
    { 0x05, "Out of sequence information element" },
    { 0x06, "Repeated optional information element" },
    { 0x07, "Mandatory information element missing" },
    { 0x08, "Unrecognized information element" },
    { 0x09, "Mandatory information element content error" },
    { 0x0a, "Optional information element content error" },
    { 0x0b, "Message not compatible with the BCC protocol state" },
    { 0x0c, "Repeated mandatory information element" },
    { 0x0d, "Too many information element" },
    { 0x0f, "BCC Reference Number coding error" },
    { 0,    NULL } };

static const value_string connection_incomplete_reason_values [] = {
    { 0x00, "Incomplete normal" },
    { 0x01, "Access network fault" },
    { 0x02, "User port not provisioned" },
    { 0x03, "Invalid V5 time slot identification" },
    { 0x04, "Invalid V5 2048 kbit/s link identification" },
    { 0x05, "Time slot being used as physical C-channel" },
    { 0,    NULL } };

static const value_string link_control_function_values [] = {
    { 0x00, "FE-IDReq" },
    { 0x01, "FE-IDAck" },
    { 0x02, "FE-IDRel" },
    { 0x03, "FE-IDRej" },
    { 0x04, "FE301/302 (link unblock)" },
    { 0x05, "FE303/304 (link block)" },
    { 0x06, "FE305 (deferred link block request" },
    { 0x07, "FE306 (non-deferred link block request)" },
    { 0,    NULL } };

static const value_string cause_type_values [] = {
    { 0x00, "Response to STATUS ENQUIRY" },
    { 0x01, "Not used" },
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

/* PSTN protocol message info elements */
#define PULSE_NOTIFICATION       0xc0
#define LINE_INFORMATION         0x80
#define STATE                    0x90
#define AUTO_SIG_SEQUENCE        0xa0
#define SEQUENCE_RESPONSE        0xb0
#define PSTN_SEQUENCE_NUMBER     0x00
#define CADENCED_RINGING         0x01
#define PULSED_SIGNAL            0x02
#define STEADY_SIGNAL            0x03
#define DIGIT_SIGNAL             0x04
#define RECOGNITION_TIME         0x10
#define ENABLE_AUTO_ACK          0x11
#define DISABLE_AUTO_ACK         0x12
#define CAUSE                    0x13
#define RESOURCE_UNAVAILABLE     0x14
#define ENABLE_METERING          0x22
#define METERING_REPORT          0x23
#define ATTENUATION              0x24
/* Control protocol message info elements  */
#define PERFORMANCE_GRADING      0xe0
#define CP_REJECTION_CAUSE       0xf0
#define CONTROL_FUNCTION_ELEMENT 0x20
#define CONTROL_FUNCTION_ID      0x21
#define VARIANT                  0x22
#define INTERFACE_ID             0x23
/* Link control protocol message info elements */
#define LINK_CONTROL_FUNCTION 0x30
/* BCC protocol message info elements */
#define USER_PORT_ID             0x40
#define ISDN_PORT_TS_ID          0x41
#define V5_TIME_SLOT_ID          0x42
#define MULTI_SLOT_MAP           0x43
#define BCC_REJECT_CAUSE         0x44
#define BCC_PROTOCOL_ERROR_CAUSE 0x45
#define CONNECTION_INCOMPLETE    0x46
/* Protection protocol message info elements */
#define SEQUENCE_NUMBER          0x50
#define C_CHANNEL_ID             0x51
#define PP_REJECTION_CAUSE       0x52
#define PROTOCOL_ERROR           0x53

static const value_string info_element_values [] = {
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
    { ENABLE_METERING,         "Enable metering" },
    { METERING_REPORT,         "Metering report" },
    { ATTENUATION,             "Attenuation" },
    { PERFORMANCE_GRADING,     "Performance grading" },
    { CP_REJECTION_CAUSE,      "Rejection cause" },
    { CONTROL_FUNCTION_ELEMENT,"Control function element" },
    { CONTROL_FUNCTION_ID,     "Control function ID" },
    { VARIANT,                 "Variant" },
    { INTERFACE_ID,            "Interface ID" },
    { LINK_CONTROL_FUNCTION,   "Link control function" },
    { USER_PORT_ID,            "User port ID" },
    { ISDN_PORT_TS_ID,         "ISDN port TS ID" },
    { V5_TIME_SLOT_ID,         "V5 TS ID" },
    { MULTI_SLOT_MAP,          "Multi-Slot map" },
    { BCC_REJECT_CAUSE,        "Reject cause" },
    { BCC_PROTOCOL_ERROR_CAUSE,"Protocol error cause" },
    { CONNECTION_INCOMPLETE,   "Connection incomplete" },
    { SEQUENCE_NUMBER,         "Sequence number" },
    { C_CHANNEL_ID,            "Physical C-Channel ID" },
    { PP_REJECTION_CAUSE,      "Rejection cause" },
    { PROTOCOL_ERROR,          "Protocol error cause" },
    { 0,                       NULL } };

static const value_string info_element_values_short [] = {
    { PULSE_NOTIFICATION,      "PN" },
    { LINE_INFORMATION,        "LI" },
    { STATE,                   "ST" },
    { AUTO_SIG_SEQUENCE,       "ASS" },
    { SEQUENCE_RESPONSE,       "SR" },
    { PSTN_SEQUENCE_NUMBER,    "SN" },
    { CADENCED_RINGING,        "CR" },
    { PULSED_SIGNAL,           "PS" },
    { STEADY_SIGNAL,           "SS" },
    { DIGIT_SIGNAL,            "DS" },
    { RECOGNITION_TIME,        "RT" },
    { ENABLE_AUTO_ACK,         "EAA" },
    { DISABLE_AUTO_ACK,        "DAA" },
    { CAUSE,                   "CA" },
    { RESOURCE_UNAVAILABLE,    "RU" },
    { ENABLE_METERING,         "EM" },
    { METERING_REPORT,         "MR" },
    { ATTENUATION,             "ATT" },
    { PERFORMANCE_GRADING,     "PG" },
    { CP_REJECTION_CAUSE,      "RC" },
    { CONTROL_FUNCTION_ELEMENT,"CF element" },
    { CONTROL_FUNCTION_ID,     "CF ID" },
    { VARIANT,                 "Var" },
    { INTERFACE_ID,            "Interface ID" },
    { LINK_CONTROL_FUNCTION,   "LC F" },
    { USER_PORT_ID,            "UP ID" },
    { ISDN_PORT_TS_ID,         "ISDNP TS ID" },
    { V5_TIME_SLOT_ID,         "V5 TS ID" },
    { MULTI_SLOT_MAP,          "MS map" },
    { BCC_REJECT_CAUSE,        "RC" },
    { BCC_PROTOCOL_ERROR_CAUSE,"PEC" },
    { CONNECTION_INCOMPLETE,   "CI" },
    { SEQUENCE_NUMBER,         "SN" },
    { C_CHANNEL_ID,            "Phy CChannel ID" },
    { PP_REJECTION_CAUSE,      "RC" },
    { PROTOCOL_ERROR,          "PEC" },
    { 0,                       NULL } };


#define ADDRESS_OFFSET       1
#define ADDRESS_LENGTH       1
#define LOW_ADDRESS_OFFSET   2
#define LOW_ADDRESS_LENGTH   1
#define MSG_TYPE_OFFSET      3
#define MSG_TYPE_LENGTH      1
#define INFO_ELEMENT_OFFSET  4
#define INFO_ELEMENT_LENGTH  1


static void
dissect_pstn_sequence_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;
    guint8      pstn_sequence_number_tmp = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        pstn_sequence_number_tmp = tvb_get_guint8(info_tvb, info_offset+2)-0x80;

        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_pstn_sequence_number, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, " | SN: %u", pstn_sequence_number_tmp);
    }
}

static void
dissect_cadenced_ring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;
    guint8      cadenced_ring_tmp = 0;
    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        cadenced_ring_tmp = tvb_get_guint8(info_tvb, info_offset+2)-0x80;
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_cadenced_ring, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));

        col_append_fstr(pinfo->cinfo, COL_INFO, ": %u", cadenced_ring_tmp);

    }
}

static void
dissect_pulsed_signal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_pulse_type, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);

        if (data_length > 3) {
            proto_tree_add_item(info_tree, hf_v52_suppression_indicator, info_tvb, info_offset+3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(info_tree, hf_v52_pulse_duration, info_tvb, info_offset+3, 1, ENC_BIG_ENDIAN);
        }

        if (data_length > 4) {
            proto_tree_add_item(info_tree, hf_v52_ack_request_indicator, info_tvb, info_offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(info_tree, hf_v52_number_of_pulses, info_tvb, info_offset+4, 1, ENC_BIG_ENDIAN);
        }

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));

        col_append_str(pinfo->cinfo, COL_INFO, ": ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2), pulse_type_values, "Unknown element"));

    }
}

static void
dissect_steady_signal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;

    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_steady_signal, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));

        col_append_str(pinfo->cinfo, COL_INFO, ": ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, steady_signal_values, "Unknown element"));
    }
}

static void
dissect_digit_signal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      buffer = 0;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);

        buffer = tvb_get_guint8(info_tvb, info_offset+2)>>6;
        buffer = buffer&0x01;

        proto_tree_add_uint_format(info_tree, hf_v52_digit_ack, info_tvb, info_offset+2, 1, buffer,
                    "Digit ack request indication: %s",val_to_str_const(buffer,digit_ack_values,"unknown"));

        buffer = tvb_get_guint8(info_tvb, info_offset+2)>>4;
        buffer = buffer&0x03;

        proto_tree_add_item(info_tree, hf_v52_digit_spare, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_digit_info, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));

        col_append_fstr(pinfo->cinfo, COL_INFO, ": %u", buffer);


    }
}

static void
dissect_recognition_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      buffer = 0;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);

        buffer = tvb_get_guint8(info_tvb, info_offset+2)&0x7f;
        /*Signal = Coding of pulse type*/
        if(buffer>=0x6b)
            proto_tree_add_item(info_tree, hf_v52_pulse_type, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);
        /*Signal = Coding of steady signal type*/
        else if(buffer<=0x1a)
            proto_tree_add_item(info_tree, hf_v52_steady_signal, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(info_tree, hf_v52_duration_type, info_tvb, info_offset+3, 1, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_enable_auto_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      buffer = 0;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);

        buffer = tvb_get_guint8(info_tvb, info_offset+2)&0x7f;
        /*Signal*/
        if(buffer>=0x6b)
            proto_tree_add_item(info_tree, hf_v52_pulse_type, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);
        else if(buffer<=0x1a)
            proto_tree_add_item(info_tree, hf_v52_steady_signal, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);

        buffer = tvb_get_guint8(info_tvb, info_offset+3)&0x7f;
        /*Response*/
        if(buffer>=0x6b)
            proto_tree_add_item(info_tree, hf_v52_pulse_type, info_tvb, info_offset+3, 1, ENC_BIG_ENDIAN);
        else if(buffer<=0x1a)
            proto_tree_add_item(info_tree, hf_v52_steady_signal, info_tvb, info_offset+3,1,ENC_BIG_ENDIAN);

        if(tvb_length_remaining(info_tvb, info_offset+4)){
            proto_tree_add_item(info_tree, hf_v52_suppression_indicator, info_tvb, info_offset+4,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(info_tree, hf_v52_pulse_duration, info_tvb, info_offset+4,1,ENC_BIG_ENDIAN);
        }
        if(tvb_length_remaining(info_tvb, info_offset+5)){
            proto_tree_add_item(info_tree, hf_v52_ack_request_indicator, info_tvb, info_offset+5,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(info_tree, hf_v52_number_of_pulses, info_tvb, info_offset+5,1,ENC_BIG_ENDIAN);
        }

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_disable_auto_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      buffer = 0;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);

        buffer = tvb_get_guint8(info_tvb, info_offset+2)&0x7f;

        if(buffer>=0x6b)
            proto_tree_add_item(info_tree, hf_v52_pulse_type, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);
        else if(buffer<=0x1a)
            proto_tree_add_item(info_tree, hf_v52_steady_signal, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"), info_element);
        proto_tree_add_item(info_tree, hf_v52_cause_type, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);

        if(tvb_length_remaining(info_tvb, info_offset+3))
            proto_tree_add_uint_format(info_tree, hf_v52_msg_type, info_tvb, info_offset+3, 1, tvb_get_guint8(info_tvb, info_offset+3),
                                "Diagnostic: %s",val_to_str_const(tvb_get_guint8(info_tvb, info_offset+3), msg_type_values,"unknown"));

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));

        col_append_str(pinfo->cinfo, COL_INFO, ": ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, cause_type_values, "Unknown element"));
    }
}

static void
dissect_resource_unavailable(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_res_unavailable, info_tvb, info_offset+2, info_element_length, ENC_ASCII|ENC_NA);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_pulse_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = 1;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_pulse_notification, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_line_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = 1;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_line_info, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = 1;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_state, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_auto_sig_sequence(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = 1;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_auto_signalling_sequence, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_sequence_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = 1;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_sequence_response, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));
    }
}

static void
dissect_control_function_element(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_control_function_element, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        if (message_type_tmp == 0x11) {}
        else {
            col_append_str(pinfo->cinfo, COL_INFO, " | ");
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, control_function_element_values, "Unknown element"));
        }
    }
}

static void
dissect_control_function_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_control_function_id, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        if (message_type_tmp == 0x13) {}
        else {
            col_append_str(pinfo->cinfo, COL_INFO, " | ");
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, control_function_id_values_short, "Unknown layer3 element"));
        }
    }
}

static void
dissect_variant(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;
    guint8      variantValue = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_variant, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        variantValue = tvb_get_guint8(info_tvb, info_offset+2)-0x80;
        col_append_fstr(pinfo->cinfo, COL_INFO, " | Var: %u", variantValue);
    }
}

static void
dissect_interface_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;
    guint8      interfaceAllIdValue = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_if_up_id, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_if_id, info_tvb, info_offset+3, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_if_low_id, info_tvb, info_offset+4, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_if_all_id, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        interfaceAllIdValue = (tvb_get_guint8(info_tvb, info_offset+2)<<16)+(tvb_get_guint8(info_tvb, info_offset+3)<<8)+(tvb_get_guint8(info_tvb, info_offset+4));

        col_append_fstr(pinfo->cinfo, COL_INFO, " | Intf. ID: %u", interfaceAllIdValue);
    }
}

static void
dissect_sequence_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;
    guint8      hf_v52_sequence_number_tmp = 0;
    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        hf_v52_sequence_number_tmp = tvb_get_guint8(info_tvb, info_offset+2)-0x80;
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_sequence_number, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset), info_element_values_short, "Unknown element"));

        col_append_fstr(pinfo->cinfo, COL_INFO, ": %u", hf_v52_sequence_number_tmp);


    }
}

static void
dissect_physical_c_channel_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;
    guint8      hf_v52_v5_link_id_cc_tmp = 0;
    guint8      hf_v52_v5_time_slot_cc_tmp = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_v5_link_id, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_v5_time_slot, info_tvb, info_offset+3, info_element_length, ENC_BIG_ENDIAN);

        hf_v52_v5_link_id_cc_tmp = tvb_get_guint8(info_tvb, info_offset+2);
        hf_v52_v5_time_slot_cc_tmp =tvb_get_guint8(info_tvb, info_offset+3);

        col_append_fstr(pinfo->cinfo, COL_INFO, " | Phy C-ch: %u, %u", hf_v52_v5_link_id_cc_tmp, hf_v52_v5_time_slot_cc_tmp);
    }
}

static void
dissect_pp_rejection_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_rejection_cause, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, rejection_cause_values, "Unknown element"));
    }
}

static void
dissect_protocol_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_error_cause, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_diagnostic_msg, info_tvb, info_offset+3, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_diagnostic_element, info_tvb, info_offset+4, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, error_cause_values, "Unknown element"));

    }
}

static void
dissect_performance_grading(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = 1;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_performance_grading, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset)-0xe0, performance_grading_values, "Unknown element"));

    }
}

static void
dissect_cp_rejection_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = 1;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_cp_rejection_cause, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset)-0xe0, cp_rejection_cause_values, "Unknown element"));
    }
}

static void
dissect_user_port_identification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    int         hf_v52_pstn_user_port_tmp = 0;
    int         hf_v52_isdn_user_port_tmp = 0;
    guint8      info_element_length = 1;
    guint8      buffer = 0;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);

        buffer = tvb_get_guint8(info_tvb, info_offset+2)&0x01;

        if(buffer==0x01){
            proto_tree_add_item(info_tree, hf_v52_pstn_user_port_id, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(info_tree, hf_v52_pstn_user_port_id_lower, info_tvb, info_offset+3, 1, ENC_BIG_ENDIAN);

            hf_v52_pstn_user_port_tmp = (((tvb_get_guint8(info_tvb, info_offset+2)>>1)<<8)+(tvb_get_guint8(info_tvb, info_offset+3)));

            col_append_fstr(pinfo->cinfo, COL_INFO, " | PSTN port: %u", hf_v52_pstn_user_port_tmp);
        }
        else if(buffer == 0x00){
            proto_tree_add_item(info_tree, hf_v52_isdn_user_port_id, info_tvb, info_offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(info_tree, hf_v52_isdn_user_port_id_lower, info_tvb, info_offset+3, 1, ENC_BIG_ENDIAN);

            hf_v52_isdn_user_port_tmp = (((tvb_get_guint8(info_tvb, info_offset+2)>>2)<<7)+((tvb_get_guint8( info_tvb, info_offset+3)>>1)));

            col_append_fstr(pinfo->cinfo, COL_INFO, " | ISDN: %u", hf_v52_isdn_user_port_tmp);
        }
    }
}

static void
dissect_isdn_port_time_slot_identification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;
    guint8      isdn_user_port_ts_num_tmp = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_isdn_user_port_ts_num, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        isdn_user_port_ts_num_tmp = (tvb_get_guint8(info_tvb, info_offset+2)) -  128;
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_fstr(pinfo->cinfo, COL_INFO, "%x", isdn_user_port_ts_num_tmp);
    }
}

static void
dissect_v5_time_slot_identification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;
    guint8      v5_link_id_tmp = 0;
    guint8      v5_time_slot_tmp = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_v5_link_id, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_override, info_tvb, info_offset+3, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_v5_time_slot, info_tvb, info_offset+3, info_element_length, ENC_BIG_ENDIAN);

        v5_link_id_tmp = tvb_get_guint8(info_tvb, info_offset+2);
        v5_time_slot_tmp = tvb_get_guint8(info_tvb, info_offset+3);

        if (v5_time_slot_tmp >= 64) {
            v5_time_slot_tmp = v5_time_slot_tmp - 64;
        } else {};

        if (v5_time_slot_tmp >= 32) {
            v5_time_slot_tmp = v5_time_slot_tmp - 32;
        } else {};

            col_append_fstr(pinfo->cinfo, COL_INFO, " | V5 Link: %u, %u ", v5_link_id_tmp, v5_time_slot_tmp);
    }
}

static void
dissect_multi_slot_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_v5_link_id, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, " | V5MSlink ID:%u",tvb_get_guint8(info_tvb, info_offset+2));

        if(tvb_length_remaining(info_tvb, info_offset+3))
            proto_tree_add_item(info_tree, hf_v52_v5_multi_slot_elements, info_tvb, info_offset+3, info_element_length, ENC_BIG_ENDIAN);
        if(tvb_length_remaining(info_tvb, info_offset+4))
            proto_tree_add_item(info_tree, hf_v52_v5_multi_slot_elements, info_tvb, info_offset+4, info_element_length, ENC_BIG_ENDIAN);
        if(tvb_length_remaining(info_tvb, info_offset+5))
            proto_tree_add_item(info_tree, hf_v52_v5_multi_slot_elements, info_tvb, info_offset+5, info_element_length, ENC_BIG_ENDIAN);
        if(tvb_length_remaining(info_tvb, info_offset+6))
            proto_tree_add_item(info_tree, hf_v52_v5_multi_slot_elements, info_tvb, info_offset+6, info_element_length, ENC_BIG_ENDIAN);
        if(tvb_length_remaining(info_tvb, info_offset+7))
            proto_tree_add_item(info_tree, hf_v52_v5_multi_slot_elements, info_tvb, info_offset+7, info_element_length, ENC_BIG_ENDIAN);
        if(tvb_length_remaining(info_tvb, info_offset+8))
            proto_tree_add_item(info_tree, hf_v52_v5_multi_slot_elements, info_tvb, info_offset+8, info_element_length, ENC_BIG_ENDIAN);
        if(tvb_length_remaining(info_tvb, info_offset+9))
            proto_tree_add_item(info_tree, hf_v52_v5_multi_slot_elements, info_tvb, info_offset+9, info_element_length, ENC_BIG_ENDIAN);
        if(tvb_length_remaining(info_tvb, info_offset+10))
            proto_tree_add_item(info_tree, hf_v52_v5_multi_slot_elements, info_tvb, info_offset+10, info_element_length, ENC_BIG_ENDIAN);
    }
}

static void
dissect_bcc_rejct_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_reject_cause_type, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, reject_cause_type_values, "Unknown element"));
    }
}

static void
dissect_bcc_protocol_error_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_bcc_protocol_error_cause, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, bcc_protocol_error_cause_type_values, "Unknown element"));

        if(tvb_length_remaining(info_tvb, info_offset+3))
            proto_tree_add_item(info_tree, hf_v52_diagnostic_message, info_tvb, info_offset+3, info_element_length, ENC_BIG_ENDIAN);
        if(tvb_length_remaining(info_tvb, info_offset+4))
            proto_tree_add_item(info_tree, hf_v52_diagnostic_information, info_tvb, info_offset+4, info_element_length, ENC_BIG_ENDIAN);
    }
}

static void
dissect_connection_incomplete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_connection_incomplete_reason, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);


        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        if ((tvb_get_guint8(info_tvb, info_offset+2) < 0x80)) {
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2), connection_incomplete_reason_values, "Unknown element"));
        }
        else {
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, connection_incomplete_reason_values, "Unknown element"));
        }

    }
}

static void
dissect_link_control_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *info_tree = NULL;
    proto_item  *ti_info;
    guint8      info_element_length = 1;
    guint8      info_element = 0;

    guint16 data_length;
    tvbuff_t *info_tvb;
    int info_offset = 0;

    info_element = tvb_get_guint8(tvb, offset);

    data_length = tvb_get_guint8(tvb, offset+1)+2;
    info_tvb    = tvb_new_subset(tvb, offset, data_length, data_length);

    if (tree) {
        ti_info = proto_tree_add_text(tree, info_tvb, info_offset, -1, "Info Element:");
        info_tree = proto_item_add_subtree(ti_info, ett_v52_info);
    }

    if (info_tree != NULL) {
        proto_tree_add_item(info_tree, hf_v52_info_element, info_tvb, info_offset, info_element_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(info_tree, hf_v52_info_length, info_tvb, info_offset+1, info_element_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_info, " %s (0x%x)",val_to_str_const(info_element, info_element_values, "unknown info element"),info_element);
        proto_tree_add_item(info_tree, hf_v52_link_control_function, info_tvb, info_offset+2, info_element_length, ENC_BIG_ENDIAN);

        if (message_type_tmp == 0x31) {}
        else {
            col_append_str(pinfo->cinfo, COL_INFO, " | ");
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(info_tvb, info_offset+2)-0x80, link_control_function_values, "Unknown element"));
        }
    }
}



static void
dissect_v52_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int     offset = 4;
    guint8  info_element, info_element_length;
    /*int     old_offset;*/
    int     singleoctet;

    while(tvb_length_remaining(tvb,offset) > 0){
        singleoctet = 0;
        /* old_offset = offset; */
        info_element = tvb_get_guint8(tvb, offset);
        switch(info_element){
            case PSTN_SEQUENCE_NUMBER:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_pstn_sequence_number(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case CADENCED_RINGING:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_cadenced_ring(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case PULSED_SIGNAL:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_pulsed_signal(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case STEADY_SIGNAL:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_steady_signal(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case DIGIT_SIGNAL:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_digit_signal(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case RECOGNITION_TIME:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_recognition_time(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case ENABLE_AUTO_ACK:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_enable_auto_ack(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case DISABLE_AUTO_ACK:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_disable_auto_ack(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case CAUSE:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_cause(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case RESOURCE_UNAVAILABLE:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_resource_unavailable(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case PULSE_NOTIFICATION:
                dissect_pulse_notification(tvb, pinfo, tree, offset);
                singleoctet = 1;
            break;
            case LINE_INFORMATION:
                dissect_line_information(tvb, pinfo, tree, offset);
                singleoctet = 1;
            break;
            case STATE:
                dissect_state(tvb, pinfo, tree, offset);
                singleoctet = 1;
            break;
            case AUTO_SIG_SEQUENCE:
                dissect_auto_sig_sequence(tvb, pinfo, tree, offset);
                singleoctet = 1;
            break;
            case SEQUENCE_RESPONSE:
                dissect_sequence_response(tvb, pinfo, tree, offset);
                singleoctet = 1;
            break;

            case CONTROL_FUNCTION_ELEMENT:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_control_function_element(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case CONTROL_FUNCTION_ID:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_control_function_id(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case VARIANT:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_variant(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case INTERFACE_ID:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_interface_id(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case SEQUENCE_NUMBER:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_sequence_number(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case C_CHANNEL_ID:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_physical_c_channel_id(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case PP_REJECTION_CAUSE:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_pp_rejection_cause(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case PROTOCOL_ERROR:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_protocol_error(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case PERFORMANCE_GRADING:
                dissect_performance_grading(tvb, pinfo, tree, offset);
                singleoctet = 1;
            break;
            case CP_REJECTION_CAUSE:
                dissect_cp_rejection_cause(tvb, pinfo, tree, offset);
                singleoctet = 1;
            break;
            case USER_PORT_ID:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_user_port_identification(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case ISDN_PORT_TS_ID:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_isdn_port_time_slot_identification(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case V5_TIME_SLOT_ID:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_v5_time_slot_identification(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case MULTI_SLOT_MAP:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_multi_slot_map(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case BCC_REJECT_CAUSE:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_bcc_rejct_cause(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case BCC_PROTOCOL_ERROR_CAUSE:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_bcc_protocol_error_cause(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case CONNECTION_INCOMPLETE:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_connection_incomplete(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            case LINK_CONTROL_FUNCTION:
                info_element_length = tvb_get_guint8(tvb,offset+1);
                dissect_link_control_function(tvb, pinfo, tree, offset);
                offset +=info_element_length+2;
            break;
            default:
                offset += 1;
            break;
        }
        if (singleoctet == 1) {
            offset += 1;
        }
#if 0
        if (old_offset <= offset) {
            expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_WARN, "Zero-length information element");
            return;
        }
#endif
    }
}


static void
dissect_v52_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int     offset = 0;
    proto_tree  *v52_tree = NULL;
    proto_item  *ti;
    gboolean    addr = FALSE;
    guint8      bcc_all_address_tmp_up = -1;
    guint16     pstn_all_address_tmp, isdn_all_address_tmp, bcc_all_address_tmp, prot_all_address_tmp, link_all_address_tmp;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "V52");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_v52, tvb, offset, -1, ENC_NA);
        v52_tree = proto_item_add_subtree(ti, ett_v52);

        dissect_v52_protocol_discriminator(tvb, offset, v52_tree);
    }


    if (v52_tree != NULL) {


        message_type_tmp = tvb_get_guint8(tvb, MSG_TYPE_OFFSET);

        if ((message_type_tmp >= 0x00) && (message_type_tmp <= 0x0e)) {
            addr = TRUE;
            proto_tree_add_item(v52_tree, hf_v52_pstn_address, tvb, ADDRESS_OFFSET, ADDRESS_LENGTH, ENC_BIG_ENDIAN);
            proto_tree_add_item(v52_tree, hf_v52_pstn_low_address, tvb, LOW_ADDRESS_OFFSET, LOW_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

            pstn_all_address_tmp = (((tvb_get_guint8(tvb,ADDRESS_OFFSET)>>1)<<8)+(tvb_get_guint8(tvb,LOW_ADDRESS_OFFSET)));


            col_append_fstr(pinfo->cinfo, COL_INFO, " | PSTN: %u", pstn_all_address_tmp);
        }

        if ((message_type_tmp >= 0x10) && (message_type_tmp <= 0x13)) {
            addr = TRUE;
            if ((tvb_get_guint8(tvb, ADDRESS_OFFSET)&0x01) == 0x1) {
                pstn_all_address_tmp = (((tvb_get_guint8(tvb, ADDRESS_OFFSET)>>1)<<8)+(tvb_get_guint8(tvb, LOW_ADDRESS_OFFSET)));
                proto_tree_add_item(v52_tree, hf_v52_pstn_address, tvb, ADDRESS_OFFSET, ADDRESS_LENGTH, ENC_BIG_ENDIAN);
                proto_tree_add_item(v52_tree, hf_v52_pstn_low_address, tvb, LOW_ADDRESS_OFFSET, LOW_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

                col_append_fstr(pinfo->cinfo, COL_INFO, " | PSTN: %u", pstn_all_address_tmp);
            }
            else {
                isdn_all_address_tmp = (((tvb_get_guint8(tvb, ADDRESS_OFFSET)>>2)<<7)+((tvb_get_guint8(tvb, LOW_ADDRESS_OFFSET)>>1)));
                proto_tree_add_item(v52_tree, hf_v52_isdn_address, tvb, ADDRESS_OFFSET, ADDRESS_LENGTH, ENC_BIG_ENDIAN);
                proto_tree_add_item(v52_tree, hf_v52_isdn_low_address, tvb, LOW_ADDRESS_OFFSET, LOW_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

                col_append_fstr(pinfo->cinfo, COL_INFO, " | ISDN: %u", isdn_all_address_tmp);
            }
        }

        if ((message_type_tmp == 0x30) || (message_type_tmp == 0x31)) {
            addr = TRUE;
            link_all_address_tmp = tvb_get_guint8(tvb, LOW_ADDRESS_OFFSET);
            proto_tree_add_item(v52_tree, hf_v52_link_address, tvb, ADDRESS_OFFSET, ADDRESS_LENGTH, ENC_BIG_ENDIAN);
            proto_tree_add_item(v52_tree, hf_v52_link_low_address, tvb, LOW_ADDRESS_OFFSET, LOW_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, " | LinkId: %u", link_all_address_tmp);
        }

        if ((message_type_tmp >= 0x20) && (message_type_tmp <= 0x2a)) {
            addr = TRUE;
            proto_tree_add_item(v52_tree, hf_v52_bcc_address, tvb, ADDRESS_OFFSET, ADDRESS_LENGTH, ENC_BIG_ENDIAN);
            proto_tree_add_item(v52_tree, hf_v52_bcc_low_address, tvb, LOW_ADDRESS_OFFSET, LOW_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

            bcc_all_address_tmp_up = tvb_get_guint8(tvb, ADDRESS_OFFSET);
            if (bcc_all_address_tmp_up >= 128) {
                bcc_all_address_tmp_up = bcc_all_address_tmp_up - 128;
            }
            bcc_all_address_tmp = (bcc_all_address_tmp_up<<6) + tvb_get_guint8(tvb, LOW_ADDRESS_OFFSET);

            col_append_fstr(pinfo->cinfo, COL_INFO, " | ref: %u", bcc_all_address_tmp);
        }

        if ((message_type_tmp >= 0x18) && (message_type_tmp <= 0x1f)) {
            addr = TRUE;
            prot_all_address_tmp = (tvb_get_guint8(tvb, ADDRESS_OFFSET)<<8) + (tvb_get_guint8(tvb,LOW_ADDRESS_OFFSET));
            proto_tree_add_item(v52_tree, hf_v52_prot_address, tvb, ADDRESS_OFFSET, ADDRESS_LENGTH, ENC_BIG_ENDIAN);
            proto_tree_add_item(v52_tree, hf_v52_prot_low_address, tvb, LOW_ADDRESS_OFFSET, LOW_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

            if ((message_type_tmp == 0x1e) || (message_type_tmp == 0x1f)) {}
            else {
                col_append_fstr(pinfo->cinfo, COL_INFO, " | Log C-ch: %u", prot_all_address_tmp);
            }
        }

        if (addr == FALSE) {
            if ((tvb_get_guint8(tvb, ADDRESS_OFFSET)&0x01) == 0x1) {
                pstn_all_address_tmp = (((tvb_get_guint8(tvb, ADDRESS_OFFSET)>>1)<<8)+(tvb_get_guint8(tvb, LOW_ADDRESS_OFFSET)));
                proto_tree_add_item(v52_tree, hf_v52_pstn_address, tvb, ADDRESS_OFFSET, ADDRESS_LENGTH, ENC_BIG_ENDIAN);
                proto_tree_add_item(v52_tree, hf_v52_pstn_low_address, tvb, LOW_ADDRESS_OFFSET, LOW_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

                col_append_fstr(pinfo->cinfo, COL_INFO, " | PSTN: %u", pstn_all_address_tmp);

            }
            else {
                isdn_all_address_tmp = (((tvb_get_guint8(tvb, ADDRESS_OFFSET)>>2)<<7)+((tvb_get_guint8(tvb, LOW_ADDRESS_OFFSET)>>1)));
                proto_tree_add_item(v52_tree, hf_v52_isdn_address, tvb, ADDRESS_OFFSET, ADDRESS_LENGTH, ENC_BIG_ENDIAN);
                proto_tree_add_item(v52_tree, hf_v52_isdn_low_address, tvb, LOW_ADDRESS_OFFSET, LOW_ADDRESS_LENGTH, ENC_BIG_ENDIAN);

                col_append_fstr(pinfo->cinfo, COL_INFO, " | ISDN: %u", isdn_all_address_tmp);

            }
        }

        proto_tree_add_item(v52_tree, hf_v52_msg_type, tvb, MSG_TYPE_OFFSET, MSG_TYPE_LENGTH, ENC_BIG_ENDIAN);


        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(tvb, MSG_TYPE_OFFSET), msg_type_values_short, "Unknown msg type"));

        dissect_v52_info(tvb, pinfo, v52_tree);
    }
}

static void
dissect_v52(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_v52_message(tvb, pinfo, tree);
}

void
proto_register_v52(void)
{
    static hf_register_info hf[] = {
        { &hf_v52_discriminator,
          { "Protocol discriminator", "v52.disc", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_v52_address,
          { "Address",    "v52.address",
             FT_UINT8,    BASE_HEX, NULL,                               0xff,
             NULL, HFILL } },
        { &hf_v52_low_address,
          { "Address Low",    "v52.low_address",
             FT_UINT8,    BASE_HEX, NULL,                               0xff,
             NULL, HFILL } },
/* ISDN */
        { &hf_v52_isdn_address,
          { "Address isdn",    "v52.isdn_address",
             FT_UINT8,    BASE_HEX, NULL,                               0xfc,
             NULL, HFILL } },
        { &hf_v52_isdn_low_address,
          { "Address isdn Low",    "v52.isdn_low_address",
             FT_UINT8,    BASE_HEX, NULL,                               0xfe,
             NULL, HFILL } },
/* PSTN */
        { &hf_v52_pstn_address,
          { "Address pstn",    "v52.pstn_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0xfe,
          NULL, HFILL } },
        { &hf_v52_pstn_low_address,
          { "Address pstn Low",    "v52.pstn_low_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
/* LINK */
        { &hf_v52_link_address,
          { "Address link",    "v52.link_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
        { &hf_v52_link_low_address,
          { "Address link Low",    "v52.link_low_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
/* BCC */
        { &hf_v52_bcc_address,
          { "Address bcc",    "v52.bcc_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0x7f,
          NULL, HFILL } },
        { &hf_v52_bcc_low_address,
          { "Address bcc Low",    "v52.bcc_low_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0x3f,
          NULL, HFILL } },
/* PROTECTION */
        { &hf_v52_prot_address,
          { "Address prot",    "v52.prot_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
        { &hf_v52_prot_low_address,
          { "Address prot Low",    "v52.prot_low_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
/* CONTROL */
        { &hf_v52_ctrl_address,
          { "Address ctrl",    "v52.ctrl_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
        { &hf_v52_ctrl_low_address,
          { "Address ctrl Low",    "v52.ctrl_low_address",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
/* OTHER */
        {&hf_v52_msg_type,
          { "Message type",   "v52.msg_type",
          FT_UINT8,    BASE_HEX, VALS(msg_type_values),                 0x0,
          NULL, HFILL } },
        {&hf_v52_info_element,
          { "Information element",   "v52.info_element",
          FT_UINT8,    BASE_HEX, VALS(info_element_values),             0x0,
          NULL, HFILL } },
        {&hf_v52_info_length,
          { "Information length",   "v52.info_length",
          FT_UINT8,    BASE_DEC, NULL,                                  0x0,
          NULL, HFILL } },
        {&hf_v52_pulse_notification,
          { "Pulse notification",   "v52.pulse_notification",
          FT_UINT8,    BASE_HEX, NULL,                                  0x0,
          NULL, HFILL } },
        {&hf_v52_pstn_sequence_number,
          { "Sequence number",    "v52.pstn_sequence_number",
          FT_UINT8,    BASE_HEX, NULL,                                  0x7f,
          NULL, HFILL } },
        {&hf_v52_cadenced_ring,
          { "Cadenced ring",    "v52.cadenced_ring",
          FT_UINT8,    BASE_HEX, NULL,                                  0x7f,
          NULL, HFILL } },
        {&hf_v52_pulse_type,
          { "Pulse Type",       "v52.pulse_type",
          FT_UINT8,    BASE_HEX, VALS(pulse_type_values),               0x0,
          NULL, HFILL } },
        {&hf_v52_suppression_indicator,
          { "Suppression indicator",  "v52.suppression_indicator",
          FT_UINT8,    BASE_HEX, VALS(suppression_indication_values),   0x60,
          NULL, HFILL } },
        {&hf_v52_pulse_duration,
          { "Pulse duration type",   "v52.pulse_duration",
          FT_UINT8,    BASE_HEX, NULL,                                  0x1f,
          NULL, HFILL } },
        {&hf_v52_ack_request_indicator,
          { "Ack request indicator",    "v52.ack_request_indicator",
          FT_UINT8,    BASE_HEX, VALS(ack_request_indication_values),   0x60,
          NULL, HFILL } },
        {&hf_v52_number_of_pulses,
          { "Number of pulses",      "v52.number_of_pulses",
          FT_UINT8,    BASE_DEC, NULL,                                  0x1f,
          NULL, HFILL } },
        {&hf_v52_steady_signal,
          { "Steady Signal",         "v52.steady_signal",
          FT_UINT8,    BASE_HEX, VALS(steady_signal_values),            0x7f,
          NULL, HFILL } },
        {&hf_v52_digit_ack,
          { "Digit ack request indication","v52.digit_ack",
          FT_UINT8,    BASE_HEX, VALS(digit_ack_values),                0x40,
          NULL, HFILL } },
        {&hf_v52_digit_spare,
          { "Digit spare","v52.digit_spare",
          FT_UINT8,    BASE_HEX, NULL,                                  0x30,
          NULL, HFILL } },
        {&hf_v52_digit_info,
          { "Digit information",    "v52.digit_info",
          FT_UINT8,    BASE_HEX, NULL,                                  0x0f,
          NULL, HFILL } },
        {&hf_v52_duration_type,
          { "Duration Type",    "v52.duration_type",
          FT_UINT8,    BASE_HEX, NULL,                                  0x3f,
          NULL, HFILL } },
        {&hf_v52_res_unavailable,
          { "Resource unavailable", "v52.res_unavailable",
          FT_STRING,   BASE_NONE,NULL,                                  0x0,
          NULL, HFILL } },
        {&hf_v52_line_info,
          { "Line_Information",      "v52.line_info",
          FT_UINT8,    BASE_HEX, VALS(line_info_values),                0x0f,
          NULL, HFILL } },
        {&hf_v52_state,
          { "PSTN FSM state",       "v52.state",
          FT_UINT8,    BASE_HEX, VALS(state_values),                    0x0f,
          NULL, HFILL } },
        {&hf_v52_auto_signalling_sequence,
          { "Autonomous signalling sequence","v52.auto_signalling_sequence",
          FT_UINT8,    BASE_HEX, NULL,                                  0x0f,
          NULL, HFILL } },
        {&hf_v52_sequence_response,
          { "Sequence response",    "v52.sequence_response",
          FT_UINT8,    BASE_HEX, NULL,                                  0x0f,
          NULL, HFILL } },
        {&hf_v52_control_function_element,
          { "Control function element",    "v52.control_function_element",
          FT_UINT8,    BASE_HEX, VALS(control_function_element_values), 0x7f,
          NULL, HFILL } },
        {&hf_v52_control_function_id,
          { "Control function ID",    "v52.control_function",
          FT_UINT8,    BASE_HEX, VALS(control_function_id_values),      0x7f,
          NULL, HFILL } },
        {&hf_v52_variant,
          { "Variant",    "v52.variant",
          FT_UINT8,    BASE_DEC, NULL,                                  0x7f,
          NULL, HFILL } },
        {&hf_v52_if_up_id,
          { "Interface up ID",    "v52.interface_up_id",
          FT_UINT8,   BASE_HEX, NULL,                                   0xff,
          NULL, HFILL } },
        {&hf_v52_if_id,
          { "Interface ID",    "v52.interface_id",
          FT_UINT8,   BASE_HEX, NULL,                                   0xff,
          NULL, HFILL } },
        {&hf_v52_if_low_id,
          { "Interface down ID",    "v52.interface_low_id",
          FT_UINT8,   BASE_HEX, NULL,                                   0xff,
          NULL, HFILL } },
        {&hf_v52_if_all_id,
          { "Interface all ID",    "v52.interface_all_id",
          FT_UINT24,   BASE_DEC, NULL,                                  0xffffff,
          NULL, HFILL } },
        {&hf_v52_sequence_number,
          { "Sequence number",    "v52.sequence_number",
          FT_UINT8,    BASE_HEX, NULL,                                  0x7f,
          NULL, HFILL } },
        {&hf_v52_v5_link_id,
          { "V5 2048 kbit/s Link Identifier",    "v52.V5_ln_id",
          FT_UINT8,    BASE_HEX, NULL,                                  0x0,
                   NULL, HFILL } },
        {&hf_v52_v5_multi_slot_elements,
          { "Additional MS ID",    "v52.add_ms_id",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
        {&hf_v52_v5_time_slot,
          { "V5 Time Slot Number",    "v52.v5_time_slot",
          FT_UINT8,    BASE_DEC, NULL,                                  0x1f,
          NULL, HFILL } },
        {&hf_v52_rejection_cause,
          { "Rejection cause",    "v52.rejection_cause",
          FT_UINT8,    BASE_HEX, VALS(rejection_cause_values),          0x7f,
          NULL, HFILL } },
        {&hf_v52_error_cause,
          { "Protocol Error Cause type",    "v52.error_cause",
          FT_UINT8,    BASE_HEX, VALS(error_cause_values),              0x7f,
          NULL, HFILL } },
        {&hf_v52_diagnostic_msg,
          { "Diagnostic message",    "v52.diagnostic_message",
          FT_UINT8,    BASE_HEX, NULL,                                  0x7f,
          NULL, HFILL } },
        {&hf_v52_diagnostic_element,
          { "Diagnostic element",    "v52.diagnostic_element",
          FT_UINT8,    BASE_HEX, NULL,                                  0x0,
          NULL, HFILL } },
        {&hf_v52_performance_grading,
          { "Performance grading",    "v52.performance_grading",
          FT_UINT8,    BASE_HEX, VALS(performance_grading_values),      0x0f,
          NULL, HFILL } },
        {&hf_v52_cp_rejection_cause,
          { "Rejection cp cause",    "v52.cp_rejection_cause",
          FT_UINT8,    BASE_HEX, VALS(cp_rejection_cause_values),       0x0f,
          NULL, HFILL } },
        {&hf_v52_pstn_user_port_id,
          { "PSTN User Port identification Value","v52.pstn_user_port_id",
            FT_UINT8,    BASE_HEX, NULL,                                0xfe,
            NULL, HFILL } },
        {&hf_v52_pstn_user_port_id_lower,
          { "PSTN User Port Identification Value (lower)","v52.pstn_user_port_id_lower",
            FT_UINT8,    BASE_HEX, NULL,                                0xff,
            NULL, HFILL } },
        {&hf_v52_isdn_user_port_id,
          { "ISDN User Port Identification Value","v52.isdn_user_port_id",
          FT_UINT8,    BASE_HEX, NULL,                                  0xfc,
          NULL, HFILL } },
        {&hf_v52_isdn_user_port_id_lower,
          { "ISDN User Port Identification Value (lower)","v52.user_port_id_lower",
          FT_UINT8,    BASE_HEX, NULL,                                  0xfe,
          NULL, HFILL } },
        {&hf_v52_isdn_user_port_ts_num,
          { "ISDN user port time slot number","v52.isdn_user_port_ts_num",
          FT_UINT8,    BASE_HEX, NULL,                                  0x1f,
          NULL, HFILL } },
        {&hf_v52_override,
          { "Override",    "v52.override",
          FT_BOOLEAN,  8,        NULL,                                  0x20,
          NULL, HFILL } },
        {&hf_v52_reject_cause_type,
          { "Reject cause type",    "v52.reject_cause_type",
          FT_UINT8,    BASE_HEX, VALS(reject_cause_type_values),        0x7f,
          NULL, HFILL } },
        {&hf_v52_bcc_protocol_error_cause,
          { "Protocol error cause type",    "v52.bcc_protocol_cause",
          FT_UINT8,    BASE_HEX, VALS(bcc_protocol_error_cause_type_values),0x7f,
          NULL, HFILL } },
        {&hf_v52_diagnostic_message,
          { "Diagnostic message",    "v52.diagnoatic_message",
          FT_UINT8,    BASE_HEX, NULL,                                  0x7f,
          NULL, HFILL } },
        {&hf_v52_diagnostic_information,
          { "Diagnostic information",    "v52.diagnostic_inforation",
          FT_UINT8,    BASE_HEX, NULL,                                  0xff,
          NULL, HFILL } },
        {&hf_v52_connection_incomplete_reason,
          { "Reason",    "v52.connection_incomplete_reason",
          FT_UINT8,    BASE_HEX, VALS(connection_incomplete_reason_values), 0x0,
          NULL, HFILL } },
        {&hf_v52_link_control_function,
          { "Link control function","v52.link_control_function",
          FT_UINT8,    BASE_HEX, VALS(link_control_function_values),0x7f,
          NULL, HFILL } },
        {&hf_v52_cause_type,
          { "Cause type",           "v52.cause_type",
          FT_UINT8,    BASE_HEX, VALS(cause_type_values),       0x7f,
          NULL, HFILL } }
    };
    static gint *ett[] = {
        &ett_v52,
        &ett_v52_info,
    };

    proto_v52 = proto_register_protocol("V5.2", "V5.2", "v52");
    proto_register_field_array (proto_v52, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("v52", dissect_v52, proto_v52);
}


void
proto_reg_handoff_v52(void)
{
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
