/* packet-x25.c
 * Routines for X.25 packet disassembly
 * Olivier Abad <oabad@noos.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/ax25_pids.h>
#include <epan/llcsaps.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/nlpid.h>
#include <epan/x264_prt_id.h>
#include <epan/lapd_sapi.h>
#include <wiretap/wtap.h>
#include "packet-sflow.h"

void proto_register_x25(void);
void proto_reg_handoff_x25(void);

/*
 * Direction of packet.
 */
typedef enum {
    X25_FROM_DCE, /* DCE->DTE */
    X25_FROM_DTE, /* DTE->DCE */
    X25_UNKNOWN   /* direction unknown */
} x25_dir_t;

/*
 * 0 for data packets, 1 for non-data packets.
 */
#define X25_NONDATA_BIT                 0x01

#define X25_CALL_REQUEST                0x0B
#define X25_CALL_ACCEPTED               0x0F
#define X25_CLEAR_REQUEST               0x13
#define X25_CLEAR_CONFIRMATION          0x17
#define X25_INTERRUPT                   0x23
#define X25_INTERRUPT_CONFIRMATION      0x27
#define X25_RESET_REQUEST               0x1B
#define X25_RESET_CONFIRMATION          0x1F
#define X25_RESTART_REQUEST             0xFB
#define X25_RESTART_CONFIRMATION        0xFF
#define X25_REGISTRATION_REQUEST        0xF3
#define X25_REGISTRATION_CONFIRMATION   0xF7
#define X25_DIAGNOSTIC                  0xF1
#define X25_RR                          0x01
#define X25_RNR                         0x05
#define X25_REJ                         0x09
#define X25_DATA                        0x00

#define PACKET_IS_DATA(type)            (!(type & X25_NONDATA_BIT))
#define PACKET_TYPE_FC(type)            (type & 0x1F)

#define X25_MBIT_MOD8                   0x10
#define X25_MBIT_MOD128                 0x01

#define X25_ABIT                        0x8000

#define X25_QBIT                        0x8000
#define X25_DBIT                        0x4000

#define X25_FAC_CLASS_MASK              0xC0

#define X25_FAC_CLASS_A                 0x00
#define X25_FAC_CLASS_B                 0x40
#define X25_FAC_CLASS_C                 0x80
#define X25_FAC_CLASS_D                 0xC0

#define X25_FAC_COMP_MARK               0x00
#define X25_FAC_REVERSE                 0x01
#define X25_FAC_THROUGHPUT              0x02
#define X25_FAC_CUG                     0x03
#define X25_FAC_CHARGING_INFO           0x04
#define X25_FAC_CALLED_MODIF            0x08
#define X25_FAC_CUG_OUTGOING_ACC        0x09
#define X25_FAC_THROUGHPUT_MIN          0x0A
#define X25_FAC_EXPRESS_DATA            0x0B
#define X25_FAC_BILATERAL_CUG           0x41
#define X25_FAC_PACKET_SIZE             0x42
#define X25_FAC_WINDOW_SIZE             0x43
#define X25_FAC_RPOA_SELECTION          0x44
#define X25_FAC_CUG_EXT                 0x47
#define X25_FAC_CUG_OUTGOING_ACC_EXT    0x48
#define X25_FAC_TRANSIT_DELAY           0x49
#define X25_FAC_CALL_DURATION           0xC1
#define X25_FAC_SEGMENT_COUNT           0xC2
#define X25_FAC_CALL_TRANSFER           0xC3
#define X25_FAC_RPOA_SELECTION_EXT      0xC4
#define X25_FAC_MONETARY_UNIT           0xC5
#define X25_FAC_NUI                     0xC6
#define X25_FAC_CALLED_ADDR_EXT         0xC9
#define X25_FAC_ETE_TRANSIT_DELAY       0xCA
#define X25_FAC_CALLING_ADDR_EXT        0xCB
#define X25_FAC_CALL_DEFLECT            0xD1
#define X25_FAC_PRIORITY                0xD2

static int proto_x25 = -1;
static int hf_x25_facility = -1;
static int hf_x25_facilities_length = -1;
static int hf_x25_facility_length = -1;
static int hf_x25_facility_class = -1;
static int hf_x25_facility_classA = -1;
static int hf_x25_facility_classA_comp_mark = -1;
static int hf_x25_facility_classA_reverse = -1;
static int hf_x25_facility_classA_charging_info = -1;
static int hf_x25_facility_reverse_charging = -1;
static int hf_x25_facility_charging_info = -1;
static int hf_x25_facility_throughput_called_dte = -1;
static int hf_x25_throughput_called_dte = -1;
static int hf_x25_facility_classA_cug = -1;
static int hf_x25_facility_classA_called_motif = -1;
static int hf_x25_facility_classA_cug_outgoing_acc = -1;
static int hf_x25_facility_classA_throughput_min = -1;
static int hf_x25_facility_classA_express_data = -1;
static int hf_x25_facility_classA_unknown = -1;
static int hf_x25_facility_classB = -1;
static int hf_x25_facility_classB_bilateral_cug = -1;
static int hf_x25_facility_packet_size_called_dte = -1;
static int hf_x25_facility_packet_size_calling_dte = -1;
static int hf_x25_facility_data_network_id_code = -1;
static int hf_x25_facility_cug_ext = -1;
static int hf_x25_facility_cug_outgoing_acc_ext = -1;
static int hf_x25_facility_transit_delay = -1;
static int hf_x25_facility_classB_unknown = -1;
static int hf_x25_facility_classC = -1;
static int hf_x25_facility_classC_unknown = -1;
static int hf_x25_facility_classD = -1;
static int hf_x25_gfi = -1;
static int hf_x25_abit = -1;
static int hf_x25_qbit = -1;
static int hf_x25_dbit = -1;
static int hf_x25_mod = -1;
static int hf_x25_lcn = -1;
static int hf_x25_type = -1;
static int hf_x25_type_fc_mod8 = -1;
static int hf_x25_type_data = -1;
static int hf_x25_diagnostic = -1;
static int hf_x25_p_r_mod8 = -1;
static int hf_x25_p_r_mod128 = -1;
static int hf_x25_mbit_mod8 = -1;
static int hf_x25_mbit_mod128 = -1;
static int hf_x25_p_s_mod8 = -1;
static int hf_x25_p_s_mod128 = -1;
static int hf_x25_window_size_called_dte = -1;
static int hf_x25_window_size_calling_dte = -1;
static int hf_x25_dte_address_length = -1;
static int hf_x25_dce_address_length = -1;
static int hf_x25_calling_address_length = -1;
static int hf_x25_called_address_length = -1;
static int hf_x25_facility_call_transfer_reason = -1;
static int hf_x25_facility_monetary_unit = -1;
static int hf_x25_facility_nui = -1;
static int hf_x25_facility_cumulative_ete_transit_delay = -1;
static int hf_x25_facility_requested_ete_transit_delay = -1;
static int hf_x25_facility_max_acceptable_ete_transit_delay = -1;
static int hf_x25_facility_priority_data = -1;
static int hf_x25_facility_priority_estab_conn = -1;
static int hf_x25_facility_priority_keep_conn = -1;
static int hf_x25_facility_min_acceptable_priority_data = -1;
static int hf_x25_facility_min_acceptable_priority_estab_conn = -1;
static int hf_x25_facility_min_acceptable_priority_keep_conn = -1;
static int hf_x25_facility_classD_unknown = -1;
static int hf_x25_facility_call_transfer_num_semi_octets = -1;
static int hf_x25_facility_calling_addr_ext_num_semi_octets = -1;
static int hf_x25_facility_called_addr_ext_num_semi_octets = -1;
static int hf_x25_facility_call_deflect_num_semi_octets = -1;
static int hf_x264_length_indicator = -1;
static int hf_x264_un_tpdu_id = -1;
static int hf_x264_protocol_id = -1;
static int hf_x264_sharing_strategy = -1;
static int hf_x263_sec_protocol_id = -1;
static int hf_x25_reg_request_length = -1;
static int hf_x25_reg_confirm_length = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_x25_call_duration = -1;
static int hf_x25_segments_to_dte = -1;
static int hf_x25_segments_from_dte = -1;
static int hf_x25_dte_address = -1;
static int hf_x25_data_network_identification_code = -1;
static int hf_x25_facility_call_deflect_reason = -1;
static int hf_x25_alternative_dte_address = -1;
static int hf_x25_dce_address = -1;
static int hf_x25_called_address = -1;
static int hf_x25_calling_address = -1;
static int hf_x25_clear_cause = -1;
static int hf_x25_reset_cause = -1;
static int hf_x25_restart_cause = -1;
static int hf_x25_registration = -1;
static int hf_x25_user_data = -1;

static gint ett_x25 = -1;
static gint ett_x25_gfi = -1;
static gint ett_x25_facilities = -1;
static gint ett_x25_facility = -1;
static gint ett_x25_user_data = -1;

static gint ett_x25_segment = -1;
static gint ett_x25_segments = -1;
static gint hf_x25_segments = -1;
static gint hf_x25_segment = -1;
static gint hf_x25_segment_overlap = -1;
static gint hf_x25_segment_overlap_conflict = -1;
static gint hf_x25_segment_multiple_tails = -1;
static gint hf_x25_segment_too_long_segment = -1;
static gint hf_x25_segment_error = -1;
static gint hf_x25_segment_count = -1;
static gint hf_x25_reassembled_length = -1;
static gint hf_x25_fast_select = -1;
static gint hf_x25_icrd = -1;
static gint hf_x25_reg_confirm_cause = -1;
static gint hf_x25_reg_confirm_diagnostic = -1;

static expert_field ei_x25_facility_length = EI_INIT;

static dissector_handle_t x25_handle;

static const value_string vals_modulo[] = {
    { 1, "8" },
    { 2, "128" },
    { 0, NULL}
};

static const value_string vals_x25_type[] = {
    { X25_CALL_REQUEST,              "Call" },
    { X25_CALL_ACCEPTED,             "Call Accepted" },
    { X25_CLEAR_REQUEST,             "Clear" },
    { X25_CLEAR_CONFIRMATION,        "Clear Confirmation" },
    { X25_INTERRUPT,                 "Interrupt" },
    { X25_INTERRUPT_CONFIRMATION,    "Interrupt Confirmation" },
    { X25_RESET_REQUEST,             "Reset" },
    { X25_RESET_CONFIRMATION,        "Reset Confirmation" },
    { X25_RESTART_REQUEST,           "Restart" },
    { X25_RESTART_CONFIRMATION,      "Restart Confirmation" },
    { X25_REGISTRATION_REQUEST,      "Registration" },
    { X25_REGISTRATION_CONFIRMATION, "Registration Confirmation" },
    { X25_DIAGNOSTIC,                "Diagnostic" },
    { X25_RR,                        "RR" },
    { X25_RNR,                       "RNR" },
    { X25_REJ,                       "REJ" },
    { X25_DATA,                      "Data" },
    { 0,   NULL}
};

static struct true_false_string m_bit_tfs = {
    "More data follows",
    "End of data"
};

static const value_string x25_fast_select_vals[] = {
    { 0, "Not requested" },
    { 1, "Not requested" },
    { 2, "No restriction on response" },
    { 3, "Restriction on response" },
    { 0, NULL}
};

static const value_string x25_icrd_vals[] = {
    { 0, "Status not selected" },
    { 1, "Prevention requested" },
    { 2, "Allowance requested" },
    { 3, "Not allowed" },
    { 0, NULL}
};

static const value_string x25_clear_diag_vals[] = {
    {   0, "No additional information" },
    {   1, "Invalid P(S)" },
    {   2, "Invalid P(R)" },
    {  16, "Packet type invalid" },
    {  17, "Packet type invalid for state r1" },
    {  18, "Packet type invalid for state r2" },
    {  19, "Packet type invalid for state r3" },
    {  20, "Packet type invalid for state p1" },
    {  21, "Packet type invalid for state p2" },
    {  22, "Packet type invalid for state p3" },
    {  23, "Packet type invalid for state p4" },
    {  24, "Packet type invalid for state p5" },
    {  25, "Packet type invalid for state p6" },
    {  26, "Packet type invalid for state p7" },
    {  27, "Packet type invalid for state d1" },
    {  28, "Packet type invalid for state d2" },
    {  29, "Packet type invalid for state d3" },
    {  32, "Packet not allowed" },
    {  33, "Unidentifiable packet" },
    {  34, "Call on one-way logical channel" },
    {  35, "Invalid packet type on a PVC" },
    {  36, "Packet on unassigned LC" },
    {  37, "Reject not subscribed to" },
    {  38, "Packet too short" },
    {  39, "Packet too long" },
    {  40, "Invalid general format identifier" },
    {  41, "Restart/registration packet with nonzero bits" },
    {  42, "Packet type not compatible with facility" },
    {  43, "Unauthorised interrupt confirmation" },
    {  44, "Unauthorised interrupt" },
    {  45, "Unauthorised reject" },
    {  48, "Time expired" },
    {  49, "Time expired for incoming call" },
    {  50, "Time expired for clear indication" },
    {  51, "Time expired for reset indication" },
    {  52, "Time expired for restart indication" },
    {  53, "Time expired for call deflection" },
    {  64, "Call set-up/clearing or registration pb." },
    {  65, "Facility/registration code not allowed" },
    {  66, "Facility parameter not allowed" },
    {  67, "Invalid called DTE address" },
    {  68, "Invalid calling DTE address" },
    {  69, "Invalid facility/registration length" },
    {  70, "Incoming call barred" },
    {  71, "No logical channel available" },
    {  72, "Call collision" },
    {  73, "Duplicate facility requested" },
    {  74, "Non zero address length" },
    {  75, "Non zero facility length" },
    {  76, "Facility not provided when expected" },
    {  77, "Invalid CCITT-specified DTE facility" },
    {  78, "Max. nb of call redir/defl. exceeded" },
    {  80, "Miscellaneous" },
    {  81, "Improper cause code from DTE" },
    {  82, "Not aligned octet" },
    {  83, "Inconsistent Q bit setting" },
    {  84, "NUI problem" },
    { 112, "International problem" },
    { 113, "Remote network problem" },
    { 114, "International protocol problem" },
    { 115, "International link out of order" },
    { 116, "International link busy" },
    { 117, "Transit network facility problem" },
    { 118, "Remote network facility problem" },
    { 119, "International routing problem" },
    { 120, "Temporary routing problem" },
    { 121, "Unknown called DNIC" },
    { 122, "Maintenance action" },
    { 144, "Timer expired or retransmission count surpassed" },
    { 145, "Timer expired or retransmission count surpassed for INTERRUPT" },
    { 146, "Timer expired or retransmission count surpassed for DATA packet transmission" },
    { 147, "Timer expired or retransmission count surpassed for REJECT" },
    { 160, "DTE-specific signals" },
    { 161, "DTE operational" },
    { 162, "DTE not operational" },
    { 163, "DTE resource constraint" },
    { 164, "Fast select not subscribed" },
    { 165, "Invalid partially full DATA packet" },
    { 166, "D-bit procedure not supported" },
    { 167, "Registration/Cancellation confirmed" },
    { 224, "OSI network service problem" },
    { 225, "Disconnection (transient condition)" },
    { 226, "Disconnection (permanent condition)" },
    { 227, "Connection rejection - reason unspecified (transient condition)" },
    { 228, "Connection rejection - reason unspecified (permanent condition)" },
    { 229, "Connection rejection - quality of service not available (transient condition)" },
    { 230, "Connection rejection - quality of service not available (permanent condition)" },
    { 231, "Connection rejection - NSAP unreachable (transient condition)" },
    { 232, "Connection rejection - NSAP unreachable (permanent condition)" },
    { 233, "reset - reason unspecified" },
    { 234, "reset - congestion" },
    { 235, "Connection rejection - NSAP address unknown (permanent condition)" },
    { 240, "Higher layer initiated" },
    { 241, "Disconnection - normal" },
    { 242, "Disconnection - abnormal" },
    { 243, "Disconnection - incompatible information in user data" },
    { 244, "Connection rejection - reason unspecified (transient condition)" },
    { 245, "Connection rejection - reason unspecified (permanent condition)" },
    { 246, "Connection rejection - quality of service not available (transient condition)" },
    { 247, "Connection rejection - quality of service not available (permanent condition)" },
    { 248, "Connection rejection - incompatible information in user data" },
    { 249, "Connection rejection - unrecognizable protocol identifier in user data" },
    { 250, "Reset - user resynchronization" },
    { 0, NULL}
};

static value_string_ext x25_clear_diag_vals_ext = VALUE_STRING_EXT_INIT(x25_clear_diag_vals);

static const value_string x25_registration_code_vals[] = {
    { 0x03, "Invalid facility request" },
    { 0x05, "Network congestion" },
    { 0x13, "Local procedure error" },
    { 0x7F, "Registration/cancellation confirmed" },
    { 0, NULL}
};

static const value_string x25_facilities_class_vals[] = {
    { X25_FAC_CLASS_A>>6, "A" },
    { X25_FAC_CLASS_B>>6, "B" },
    { X25_FAC_CLASS_C>>6, "C" },
    { X25_FAC_CLASS_D>>6, "D" },
    { 0, NULL}
};

static const value_string x25_facilities_classA_vals[] = {
    { X25_FAC_COMP_MARK,        "Marker" },
    { X25_FAC_REVERSE,          "Reverse charging / Fast select" },
    { X25_FAC_CHARGING_INFO,    "Charging information" },
    { X25_FAC_THROUGHPUT,       "Throughput class negotiation" },
    { X25_FAC_CUG,              "Closed user group selection" },
    { X25_FAC_CALLED_MODIF,     "Called address modified" },
    { X25_FAC_CUG_OUTGOING_ACC, "Closed user group with outgoing access selection" },
    { X25_FAC_THROUGHPUT_MIN,   "Minimum throughput class" },
    { X25_FAC_EXPRESS_DATA,     "Negotiation of express data" },
    { 0, NULL}
};

static const value_string x25_facilities_classA_comp_mark_vals[] = {
    { 0x00, "Network complementary services - calling DTE" },
    { 0x0F, "DTE complementary services" },
    { 0xFF, "Network complementary services - called DTE" },
    { 0, NULL}
};

static const value_string x25_facilities_classA_throughput_vals[] = {
    {  3, "75 bps" },
    {  4, "150 bps" },
    {  5, "300 bps" },
    {  6, "600 bps" },
    {  7, "1200 bps" },
    {  8, "2400 bps" },
    {  9, "4800 bps" },
    { 10, "9600 bps" },
    { 11, "19200 bps" },
    { 12, "48000 bps" },
    { 13, "64000 bps" },
    { 0, NULL}
};

static const value_string x25_facilities_classB_vals[] = {
    { X25_FAC_BILATERAL_CUG,        "Bilateral closed user group selection" },
    { X25_FAC_PACKET_SIZE,          "Packet size" },
    { X25_FAC_WINDOW_SIZE,          "Window size" },
    { X25_FAC_RPOA_SELECTION,       "RPOA selection" },
    { X25_FAC_CUG_EXT,              "Extended closed user group selection" },
    { X25_FAC_CUG_OUTGOING_ACC_EXT, "Extended closed user group with outgoing access selection" },
    { X25_FAC_TRANSIT_DELAY,        "Transit delay selection and indication" },
    { 0, NULL}
};

static const value_string x25_facilities_classB_packet_size_vals[] = {
    { 0x04, "16" },
    { 0x05, "32" },
    { 0x06, "64" },
    { 0x07, "128" },
    { 0x08, "256" },
    { 0x09, "512" },
    { 0x0A, "1024" },
    { 0x0B, "2048" },
    { 0x0C, "4096" },
    { 0, NULL}
};

static const value_string x25_facilities_classC_vals[] = {
    { 0, NULL}
};

static const value_string x25_facilities_classD_vals[] = {
    { X25_FAC_CALL_DURATION,      "Call duration" },
    { X25_FAC_SEGMENT_COUNT,      "Segment count" },
    { X25_FAC_CALL_TRANSFER,      "Call redirection or deflection notification" },
    { X25_FAC_RPOA_SELECTION_EXT, "Extended RPOA selection" },
    { X25_FAC_CALLING_ADDR_EXT,   "Calling address extension" },
    { X25_FAC_MONETARY_UNIT,      "Monetary Unit" },
    { X25_FAC_NUI,                "Network User Identification selection" },
    { X25_FAC_CALLED_ADDR_EXT,    "Called address extension" },
    { X25_FAC_ETE_TRANSIT_DELAY,  "End to end transit delay" },
    { X25_FAC_CALL_DEFLECT,       "Call deflection selection" },
    { X25_FAC_PRIORITY,           "Priority" },
    { 0, NULL}
};

static struct true_false_string x25_reverse_charging_val = {
    "Requested",
    "Not requested"
};

static const value_string x25_facilities_call_transfer_reason_vals[] = {
    { 0x01, "originally called DTE busy" },
    { 0x07, "call dist. within a hunt group" },
    { 0x09, "originally called DTE out of order" },
    { 0x0F, "systematic call redirection" },
    { 0, NULL}
};

static const fragment_items x25_frag_items = {
    &ett_x25_segment,
    &ett_x25_segments,
    &hf_x25_segments,
    &hf_x25_segment,
    &hf_x25_segment_overlap,
    &hf_x25_segment_overlap_conflict,
    &hf_x25_segment_multiple_tails,
    &hf_x25_segment_too_long_segment,
    &hf_x25_segment_error,
    &hf_x25_segment_count,
    NULL,
    &hf_x25_reassembled_length,
    /* Reassembled data field */
    NULL,
    "segments"
};

static dissector_handle_t ip_handle;
static dissector_handle_t clnp_handle;
static dissector_handle_t ositp_handle;
static dissector_handle_t qllc_handle;

/* Preferences */
static gboolean payload_is_qllc_sna = FALSE;
static gboolean call_request_nodata_is_cotp = FALSE;
static gboolean payload_check_data = FALSE;
static gboolean reassemble_x25 = TRUE;

/* Reassembly of X.25 */

static reassembly_table x25_reassembly_table;

static dissector_table_t x25_subdissector_table;
static heur_dissector_list_t x25_heur_subdissector_list;

static void
x25_hash_add_proto_start(guint16 vc, guint32 frame, dissector_handle_t dissect)
{
    conversation_t *conv;

    /*
     * Is there already a circuit with this VC number?
     */
    conv = find_conversation_by_id(frame, ENDPOINT_X25, vc);
    if (conv != NULL) {
        /*
         * Yes - close it, as we're creating a new one.
         */
        conv->last_frame = frame - 1;
    }

    /*
     * Set up a new circuit.
     */
    conv = conversation_new_by_id(frame, ENDPOINT_X25, vc);

    /*
     * Set its dissector.
     */
    conversation_set_dissector(conv, dissect);
}

static void
x25_hash_add_proto_end(guint16 vc, guint32 frame)
{
    conversation_t *conv;

    /*
     * Try to find the circuit.
     */
    conv = find_conversation_by_id(frame, ENDPOINT_X25, vc);

    /*
     * If we succeeded, close it.
     */
    if (conv != NULL)
        conv->last_frame = frame;
}

static const range_string clear_code_rvals[] = {
    { 0x00, 0x00,  "DTE Originated" },
    { 0x01, 0x01,  "Number Busy" },
    { 0x03, 0x03,  "Invalid Facility Requested" },
    { 0x05, 0x05,  "Network Congestion" },
    { 0x09, 0x09,  "Out Of Order" },
    { 0x0B, 0x0B,  "Access Barred" },
    { 0x0D, 0x0D,  "Not Obtainable" },
    { 0x11, 0x11,  "Remote Procedure Error" },
    { 0x13, 0x13,  "Local Procedure Error" },
    { 0x15, 0x15,  "RPOA Out Of Order" },
    { 0x19, 0x19,  "Reverse Charging Acceptance Not Subscribed" },
    { 0x21, 0x21,  "Incompatible Destination" },
    { 0x29, 0x29,  "Fast Select Acceptance Not Subscribed" },
    { 0x39, 0x39,  "Destination Absent" },
    { 0x80, 0xff,  "DTE Originated" },
    { 0, 0, NULL }
};

static const range_string reset_code_rvals[] = {
    { 0x00, 0x00,  "DTE Originated" },
    { 0x01, 0x01,  "Out of order" },
    { 0x03, 0x03,  "Remote Procedure Error" },
    { 0x05, 0x05,  "Local Procedure Error" },
    { 0x07, 0x07,  "Network Congestion" },
    { 0x09, 0x09,  "Remote DTE operational" },
    { 0x0F, 0x0F,  "Network operational" },
    { 0x11, 0x11,  "Incompatible Destination" },
    { 0x1D, 0x1D,  "Network out of order" },
    { 0x80, 0xff,  "DTE Originated" },
    { 0, 0, NULL }
};

static const range_string restart_code_rvals[] = {
    { 0x00, 0x00,  "DTE Originated" },
    { 0x01, 0x01,  "Local Procedure Error" },
    { 0x03, 0x03,  "Network Congestion" },
    { 0x07, 0x07,  "Network Operational" },
    { 0x7F, 0x7F,  "Registration/cancellation confirmed" },
    { 0x80, 0xff,  "DTE Originated" },
    { 0, 0, NULL }
};

static char *
dte_address_util(wmem_allocator_t *pool, tvbuff_t *tvb, int offset, guint8 len)
{
    int i;
    char *tmpbuf = (char *)wmem_alloc(pool, 258);

    for (i = 0; (i<len)&&(i<256); i++) {
        if (i % 2 == 0) {
            tmpbuf[i] = ((tvb_get_guint8(tvb, offset+i/2) >> 4) & 0x0F) + '0';
            /* if > 9, convert to the right hexadecimal letter */
            if (tmpbuf[i] > '9')
                tmpbuf[i] += ('A' - '0' - 10);
        } else {
            tmpbuf[i] = (tvb_get_guint8(tvb, offset+i/2) & 0x0F) + '0';
            /* if > 9, convert to the right hexadecimal letter */
            if (tmpbuf[i] > '9')
                tmpbuf[i] += ('A' - '0' - 10);
        }
    }

    tmpbuf[i] = '\0';

    return tmpbuf;
}

static void
add_priority(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
    guint8 priority;

    priority = tvb_get_guint8(tvb, offset);
    if (priority == 255)
        proto_tree_add_uint_format_value(tree, hf, tvb, offset, 1, priority,
                                         "Unspecified (255)");
    else
        proto_tree_add_uint(tree, hf, tvb, offset, 1, priority);
}

static void
dump_facilities(proto_tree *tree, int *offset, tvbuff_t *tvb, packet_info *pinfo)
{
    guint8 fac, byte1, byte2, byte3;
    guint32 len;      /* facilities length */
    proto_item *ti = NULL;
    proto_tree *facilities_tree = NULL, *facility_tree = NULL;

    len = tvb_get_guint8(tvb, *offset);
    if (len && tree) {
        facilities_tree = proto_tree_add_subtree(tree, tvb, *offset, len + 1,
                                                 ett_x25_facilities, NULL, "Facilities");
        proto_tree_add_item(facilities_tree, hf_x25_facilities_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
    }
    (*offset)++;

    while (len > 0) {
        ti = proto_tree_add_item(facilities_tree, hf_x25_facility, tvb, *offset, -1, ENC_NA);
        fac = tvb_get_guint8(tvb, *offset);
        switch(fac & X25_FAC_CLASS_MASK) {
        case X25_FAC_CLASS_A:
            proto_item_set_len(ti, 2);
            proto_item_append_text(ti, ": %s",
                                   val_to_str(fac, x25_facilities_classA_vals, "Unknown (0x%02X)"));
            facility_tree = proto_item_add_subtree(ti, ett_x25_facility);
            proto_tree_add_item(facility_tree, hf_x25_facility_class, tvb, *offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(facility_tree, hf_x25_facility_classA, tvb, *offset, 1, ENC_BIG_ENDIAN);
            if (facility_tree) {
                switch (fac) {
                case X25_FAC_COMP_MARK:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_comp_mark, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_REVERSE:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_reverse, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(facility_tree, hf_x25_fast_select, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(facility_tree, hf_x25_icrd, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(facility_tree, hf_x25_facility_reverse_charging, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_CHARGING_INFO:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_charging_info, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(facility_tree, hf_x25_facility_charging_info, tvb, *offset+1, 1, ENC_NA);
                    break;
                case X25_FAC_THROUGHPUT:
                    proto_tree_add_item(facility_tree, hf_x25_facility_throughput_called_dte, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(facility_tree, hf_x25_throughput_called_dte, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_CUG:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_cug, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_CALLED_MODIF:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_called_motif, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_CUG_OUTGOING_ACC:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_cug_outgoing_acc, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_THROUGHPUT_MIN:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_throughput_min, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_EXPRESS_DATA:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_express_data, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                default:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classA_unknown, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    break;
                }
            }
            (*offset) += 2;
            len -= 2;
            break;
        case X25_FAC_CLASS_B:
            proto_item_set_len(ti, 3);
            proto_item_append_text(ti, ": %s",
                                   val_to_str(fac, x25_facilities_classB_vals, "Unknown (0x%02X)"));
            facility_tree = proto_item_add_subtree(ti, ett_x25_facility);
            proto_tree_add_item(facility_tree, hf_x25_facility_class, tvb, *offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(facility_tree, hf_x25_facility_classB, tvb, *offset, 1, ENC_BIG_ENDIAN);
            if (facility_tree) {
                switch (fac) {
                case X25_FAC_BILATERAL_CUG:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classB_bilateral_cug, tvb, *offset+1, 2, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_PACKET_SIZE:
                    proto_tree_add_item(facility_tree, hf_x25_facility_packet_size_called_dte, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(facility_tree, hf_x25_facility_packet_size_calling_dte, tvb, *offset+2, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_WINDOW_SIZE:
                    proto_tree_add_item(facility_tree, hf_x25_window_size_called_dte, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(facility_tree, hf_x25_window_size_calling_dte, tvb, *offset+2, 1, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_RPOA_SELECTION:
                    proto_tree_add_item(facility_tree, hf_x25_facility_data_network_id_code, tvb, *offset+1, 2, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_CUG_EXT:
                    proto_tree_add_item(facility_tree, hf_x25_facility_cug_ext, tvb, *offset+1, 2, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_CUG_OUTGOING_ACC_EXT:
                    proto_tree_add_item(facility_tree, hf_x25_facility_cug_outgoing_acc_ext, tvb, *offset+1, 2, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_TRANSIT_DELAY:
                    proto_tree_add_item(facility_tree, hf_x25_facility_transit_delay, tvb, *offset+1, 2, ENC_BIG_ENDIAN);
                    break;
                default:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classB_unknown, tvb, *offset+1, 2, ENC_BIG_ENDIAN);
                    break;
                }
            }
            (*offset) += 3;
            len -= 3;
            break;
        case X25_FAC_CLASS_C:
            proto_item_set_len(ti, 4);
            proto_item_append_text(ti, ": %s",
                                   val_to_str(fac, x25_facilities_classC_vals, "Unknown (0x%02X)"));
            facility_tree = proto_item_add_subtree(ti, ett_x25_facility);
            proto_tree_add_item(facility_tree, hf_x25_facility_class, tvb, *offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(facility_tree, hf_x25_facility_classC, tvb, *offset, 1, ENC_BIG_ENDIAN);
            if (facility_tree) {
                proto_tree_add_item(facility_tree, hf_x25_facility_classC_unknown, tvb, *offset+1, 2, ENC_BIG_ENDIAN);
            }
            (*offset) += 4;
            len -= 4;
            break;
        case X25_FAC_CLASS_D:
            proto_item_append_text(ti, ": %s",
                                   val_to_str(fac, x25_facilities_classD_vals, "Unknown (0x%02X)"));
            facility_tree = proto_item_add_subtree(ti, ett_x25_facility);
            proto_tree_add_item(facility_tree, hf_x25_facility_class, tvb, *offset, 1, ENC_BIG_ENDIAN);
            byte1 = tvb_get_guint8(tvb, *offset+1);
            proto_item_set_len(ti, byte1+2);
            proto_tree_add_item(facility_tree, hf_x25_facility_classD, tvb, *offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(facility_tree, hf_x25_facility_length, tvb, *offset+1, 1, ENC_BIG_ENDIAN);
            if (facility_tree) {
                switch (fac) {
                case X25_FAC_CALL_DURATION:
                {
                    int i;

                    if ((byte1 < 4) || (byte1 % 4)) {
                        expert_add_info(pinfo, ti, &ei_x25_facility_length);
                        return;
                    }
                    for (i = 0; (i<byte1); i+=4) {
                        proto_tree_add_bytes_format_value(facility_tree, hf_x25_call_duration, tvb, *offset+2+i, 4,
                                            NULL, "%u Day(s) %02X:%02X:%02X Hour(s)",
                                            tvb_get_guint8(tvb, *offset+2+i),
                                            tvb_get_guint8(tvb, *offset+3+i),
                                            tvb_get_guint8(tvb, *offset+4+i),
                                            tvb_get_guint8(tvb, *offset+5+i));
                    }
                }
                break;
                case X25_FAC_SEGMENT_COUNT:
                {
                    int i;

                    if ((byte1 < 8) || (byte1 % 8)) {
                        expert_add_info(pinfo, ti, &ei_x25_facility_length);
                        return;
                    }
                    for (i = 0; (i<byte1); i+=8) {
                        proto_tree_add_item(facility_tree, hf_x25_segments_to_dte, tvb, *offset+2+i, 4, ENC_NA);
                        proto_tree_add_item(facility_tree, hf_x25_segments_from_dte, tvb, *offset+6+i, 4, ENC_NA);
                    }
                }
                break;
                case X25_FAC_CALL_TRANSFER:
                {
                    char *tmpbuf;

                    if (byte1 < 2) {
                        expert_add_info(pinfo, ti, &ei_x25_facility_length);
                        return;
                    }
                    byte2 = tvb_get_guint8(tvb, *offset+2);
                    if ((byte2 & 0xC0) == 0xC0) {
                        proto_tree_add_uint_format_value(facility_tree, hf_x25_facility_call_transfer_reason, tvb,
                                                         *offset+2, 1, byte2, "call deflection by the originally called DTE address");
                    }
                    else {
                        proto_tree_add_uint(facility_tree, hf_x25_facility_call_transfer_reason, tvb, *offset+2, 1, byte2);
                    }
                    byte3 = tvb_get_guint8(tvb, *offset+3);
                    proto_tree_add_uint(facility_tree, hf_x25_facility_call_transfer_num_semi_octets, tvb, *offset+4, 1, byte3);
                    tmpbuf = dte_address_util(pinfo->pool, tvb, *offset + 4, byte3);

                    proto_tree_add_string(facility_tree, hf_x25_dte_address, tvb, *offset+4, byte1 - 2, tmpbuf);
                }
                break;
                case X25_FAC_RPOA_SELECTION_EXT:
                {
                    int i;

                    if ((byte1 < 2) || (byte1 % 2)) {
                        expert_add_info(pinfo, ti, &ei_x25_facility_length);
                        return;
                    }
                    for (i = 0; (i<byte1); i+=2) {
                        proto_tree_add_item(facility_tree, hf_x25_data_network_identification_code, tvb, *offset+2+i, 2, ENC_BIG_ENDIAN);
                    }
                }
                break;
                case X25_FAC_CALLING_ADDR_EXT:
                {
                    char *tmpbuf;

                    if (byte1 < 1) {
                        expert_add_info(pinfo, ti, &ei_x25_facility_length);
                        return;
                    }
                    byte2 = tvb_get_guint8(tvb, *offset+2) & 0x3F;
                    proto_tree_add_uint(facility_tree, hf_x25_facility_calling_addr_ext_num_semi_octets, tvb, *offset+2, 1, byte2);
                    tmpbuf = dte_address_util(pinfo->pool, tvb, *offset + 3, byte2);
                    proto_tree_add_string(facility_tree, hf_x25_dte_address, tvb, *offset+3, byte1 - 1, tmpbuf);
                }
                break;
                case X25_FAC_MONETARY_UNIT:
                    proto_tree_add_item(facility_tree, hf_x25_facility_monetary_unit, tvb, *offset+2, byte1, ENC_NA);
                    break;
                case X25_FAC_NUI:
                    proto_tree_add_item(facility_tree, hf_x25_facility_nui, tvb, *offset+2, byte1, ENC_NA);
                    break;
                case X25_FAC_CALLED_ADDR_EXT:
                {
                    char *tmpbuf;

                    if (byte1 < 1) {
                        expert_add_info(pinfo, ti, &ei_x25_facility_length);
                        return;
                    }
                    byte2 = tvb_get_guint8(tvb, *offset+2) & 0x3F;
                    proto_tree_add_uint(facility_tree, hf_x25_facility_called_addr_ext_num_semi_octets, tvb, *offset+2, 1, byte2);
                    tmpbuf = dte_address_util(pinfo->pool, tvb, *offset+3, byte2);

                    proto_tree_add_string(facility_tree, hf_x25_dte_address, tvb, *offset+3, byte1 - 1, tmpbuf);
                }
                break;
                case X25_FAC_ETE_TRANSIT_DELAY:
                    if (byte1 < 2)
                        break;
                    proto_tree_add_item(facility_tree, hf_x25_facility_cumulative_ete_transit_delay, tvb, *offset+2, 2, ENC_BIG_ENDIAN);
                    if (byte1 < 4)
                        break;
                    proto_tree_add_item(facility_tree, hf_x25_facility_requested_ete_transit_delay, tvb, *offset+4, 2, ENC_BIG_ENDIAN);
                    if (byte1 < 6)
                        break;
                    proto_tree_add_item(facility_tree, hf_x25_facility_max_acceptable_ete_transit_delay, tvb, *offset+6, 2, ENC_BIG_ENDIAN);
                    break;
                case X25_FAC_CALL_DEFLECT:
                {
                    char *tmpbuf;

                    if (byte1 < 2) {
                        expert_add_info(pinfo, ti, &ei_x25_facility_length);
                        return;
                    }
                    byte2 = tvb_get_guint8(tvb, *offset+2);
                    if ((byte2 & 0xC0) == 0xC0)
                        proto_tree_add_uint_format_value(facility_tree, hf_x25_facility_call_deflect_reason, tvb, *offset+2, 1,
                                            byte2, "call DTE originated");
                    else
                        proto_tree_add_uint_format_value(facility_tree, hf_x25_facility_call_deflect_reason, tvb, *offset+2, 1,
                                            byte2, "unknown");
                    byte3 = tvb_get_guint8(tvb, *offset+3);
                    proto_tree_add_uint(facility_tree, hf_x25_facility_call_deflect_num_semi_octets, tvb, *offset+3, 1, byte3);
                    tmpbuf = dte_address_util(pinfo->pool, tvb, *offset+4, byte3);

                    proto_tree_add_string(facility_tree, hf_x25_alternative_dte_address, tvb, *offset+4, byte1 - 2, tmpbuf);
                }
                break;
                case X25_FAC_PRIORITY:
                    if (byte1 < 1)
                        break;
                    add_priority(facility_tree, hf_x25_facility_priority_data, tvb, *offset+2);
                    if (byte1 < 2)
                        break;
                    add_priority(facility_tree, hf_x25_facility_priority_estab_conn, tvb, *offset+3);
                    if (byte1 < 3)
                        break;
                    add_priority(facility_tree, hf_x25_facility_priority_keep_conn, tvb, *offset+4);
                    if (byte1 < 4)
                        break;
                    add_priority(facility_tree, hf_x25_facility_min_acceptable_priority_data, tvb, *offset+5);
                    if (byte1 < 5)
                        break;
                    add_priority(facility_tree, hf_x25_facility_min_acceptable_priority_estab_conn, tvb, *offset+6);
                    if (byte1 < 6)
                        break;
                    add_priority(facility_tree, hf_x25_facility_min_acceptable_priority_keep_conn, tvb, *offset+7);
                    break;
                default:
                    proto_tree_add_item(facility_tree, hf_x25_facility_classD_unknown, tvb, *offset+2, byte1, ENC_NA);
                }
            }
            byte1 = tvb_get_guint8(tvb, *offset+1);
            (*offset) += byte1+2;
            len -= byte1+2;
            break;
        }
    }
}

static void
x25_ntoa(proto_tree *tree, int *offset, tvbuff_t *tvb,
         packet_info *pinfo, gboolean is_registration)
{
    int len1, len2;
    int i;
    char *addr1, *addr2;
    char *first, *second;
    guint8 byte;
    int localoffset;

    addr1=(char *)wmem_alloc(pinfo->pool, 16);
    addr2=(char *)wmem_alloc(pinfo->pool, 16);

    byte = tvb_get_guint8(tvb, *offset);
    len1 = (byte >> 0) & 0x0F;
    len2 = (byte >> 4) & 0x0F;

    if (tree) {
        if (is_registration) {
            proto_tree_add_item(tree, hf_x25_dte_address_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_x25_dce_address_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(tree, hf_x25_calling_address_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_x25_called_address_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
        }
    }
    (*offset)++;

    localoffset = *offset;
    byte = tvb_get_guint8(tvb, localoffset);

    first=addr1;
    second=addr2;
    for (i = 0; i < (len1 + len2); i++) {
        if (i < len1) {
            if (i % 2 != 0) {
                *first++ = ((byte >> 0) & 0x0F) + '0';
                localoffset++;
                byte = tvb_get_guint8(tvb, localoffset);
            } else {
                *first++ = ((byte >> 4) & 0x0F) + '0';
            }
        } else {
            if (i % 2 != 0) {
                *second++ = ((byte >> 0) & 0x0F) + '0';
                localoffset++;
                byte = tvb_get_guint8(tvb, localoffset);
            } else {
                *second++ = ((byte >> 4) & 0x0F) + '0';
            }
        }
    }

    *first  = '\0';
    *second = '\0';

    if (len1) {
        col_add_str(pinfo->cinfo, COL_RES_DL_DST, addr1);
        proto_tree_add_string(tree, is_registration ? hf_x25_dce_address : hf_x25_called_address, tvb, *offset,
                                (len1 + 1) / 2, addr1);
    }
    if (len2) {
        col_add_str(pinfo->cinfo, COL_RES_DL_SRC, addr2);
        proto_tree_add_string(tree, is_registration ? hf_x25_dte_address : hf_x25_calling_address, tvb, *offset + len1/2,
                                (len2+1)/2+(len1%2+(len2+1)%2)/2, addr2);
    }
    (*offset) += ((len1 + len2 + 1) / 2);
}

static void
x25_toa(proto_tree *tree, int *offset, tvbuff_t *tvb,
        packet_info *pinfo)
{
    int len1, len2;
    int i;
    char *addr1, *addr2;
    char *first, *second;
    guint8 byte;
    int localoffset;

    addr1=(char *)wmem_alloc(pinfo->pool, 256);
    addr2=(char *)wmem_alloc(pinfo->pool, 256);

    len1 = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_x25_called_address_length, tvb, *offset, 1, ENC_NA);
    (*offset)++;

    len2 = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(tree, hf_x25_calling_address_length, tvb, *offset, 1, ENC_NA);
    (*offset)++;

    localoffset = *offset;
    byte = tvb_get_guint8(tvb, localoffset);

    /*
     * XXX - the first two half-octets of the address are the TOA and
     * NPI; process them as such and, if the TOA says an address is
     * an alternative address, process it correctly (i.e., not as a
     * sequence of half-octets containing digit values).
     */
    first=addr1;
    second=addr2;
    for (i = 0; i < (len1 + len2); i++) {
        if (i < len1) {
            if (i % 2 != 0) {
                *first++ = ((byte >> 0) & 0x0F) + '0';
                localoffset++;
                byte = tvb_get_guint8(tvb, localoffset);
            } else {
                *first++ = ((byte >> 4) & 0x0F) + '0';
            }
        } else {
            if (i % 2 != 0) {
                *second++ = ((byte >> 0) & 0x0F) + '0';
                localoffset++;
                byte = tvb_get_guint8(tvb, localoffset);
            } else {
                *second++ = ((byte >> 4) & 0x0F) + '0';
            }
        }
    }

    *first  = '\0';
    *second = '\0';

    if (len1) {
        col_add_str(pinfo->cinfo, COL_RES_DL_DST, addr1);
        proto_tree_add_string(tree, hf_x25_called_address, tvb, *offset,
                                (len1 + 1) / 2, addr1);
    }
    if (len2) {
        col_add_str(pinfo->cinfo, COL_RES_DL_SRC, addr2);
        proto_tree_add_string(tree, hf_x25_calling_address, tvb, *offset + len1/2,
                                (len2+1)/2+(len1%2+(len2+1)%2)/2, addr2);
    }
    (*offset) += ((len1 + len2 + 1) / 2);
}

static int
get_x25_pkt_len(tvbuff_t *tvb)
{
    guint length, called_len, calling_len, dte_len, dce_len;
    guint8 byte2, bytex;

    byte2 = tvb_get_guint8(tvb, 2);
    switch (byte2)
    {
    case X25_CALL_REQUEST:
        bytex = tvb_get_guint8(tvb, 3);
        called_len  = (bytex >> 0) & 0x0F;
        calling_len = (bytex >> 4) & 0x0F;
        length = 4 + (called_len + calling_len + 1) / 2; /* addr */
        if (length < tvb_reported_length(tvb))
            length += (1 + tvb_get_guint8(tvb, length)); /* facilities */

        return MIN(tvb_reported_length(tvb),length);

    case X25_CALL_ACCEPTED:
        /* The calling/called address length byte (following the packet type)
         * is not mandatory, so we must check the packet length before trying
         * to read it */
        if (tvb_reported_length(tvb) == 3)
            return(3);
        bytex = tvb_get_guint8(tvb, 3);
        called_len  = (bytex >> 0) & 0x0F;
        calling_len = (bytex >> 4) & 0x0F;
        length = 4 + (called_len + calling_len + 1) / 2; /* addr */
        if (length < tvb_reported_length(tvb))
            length += (1 + tvb_get_guint8(tvb, length)); /* facilities */

        return MIN(tvb_reported_length(tvb),length);

    case X25_CLEAR_REQUEST:
    case X25_RESET_REQUEST:
    case X25_RESTART_REQUEST:
        return MIN(tvb_reported_length(tvb),5);

    case X25_DIAGNOSTIC:
        return MIN(tvb_reported_length(tvb),4);

    case X25_CLEAR_CONFIRMATION:
    case X25_INTERRUPT:
    case X25_INTERRUPT_CONFIRMATION:
    case X25_RESET_CONFIRMATION:
    case X25_RESTART_CONFIRMATION:
        return MIN(tvb_reported_length(tvb),3);

    case X25_REGISTRATION_REQUEST:
        bytex = tvb_get_guint8(tvb, 3);
        dce_len = (bytex >> 0) & 0x0F;
        dte_len = (bytex >> 4) & 0x0F;
        length = 4 + (dte_len + dce_len + 1) / 2; /* addr */
        if (length < tvb_reported_length(tvb))
            length += (1 + tvb_get_guint8(tvb, length)); /* registration */

        return MIN(tvb_reported_length(tvb),length);

    case X25_REGISTRATION_CONFIRMATION:
        bytex = tvb_get_guint8(tvb, 5);
        dce_len = (bytex >> 0) & 0x0F;
        dte_len = (bytex >> 4) & 0x0F;
        length = 6 + (dte_len + dce_len + 1) / 2; /* addr */
        if (length < tvb_reported_length(tvb))
            length += (1 + tvb_get_guint8(tvb, length)); /* registration */

        return MIN(tvb_reported_length(tvb),length);
    }

    if (PACKET_IS_DATA(byte2))
        return MIN(tvb_reported_length(tvb),3);

    switch (PACKET_TYPE_FC(byte2))
    {
    case X25_RR:
        return MIN(tvb_reported_length(tvb),3);

    case X25_RNR:
        return MIN(tvb_reported_length(tvb),3);

    case X25_REJ:
        return MIN(tvb_reported_length(tvb),3);
    }

    return 0;
}

static const value_string prt_id_vals[] = {
    {PRT_ID_ISO_8073,           "ISO 8073 COTP"},
    {PRT_ID_ISO_8602,           "ISO 8602 CLTP"},
    {PRT_ID_ISO_10736_ISO_8073, "ISO 10736 in conjunction with ISO 8073 COTP"},
    {PRT_ID_ISO_10736_ISO_8602, "ISO 10736 in conjunction with ISO 8602 CLTP"},
    {0x00,                      NULL}
};

static const value_string sharing_strategy_vals[] = {
    {0x00,            "No sharing"},
    {0x00,            NULL}
};

static void
dissect_x25_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    x25_dir_t dir, gboolean side)
{
    proto_tree *x25_tree=0, *gfi_tree=0, *userdata_tree=0;
    proto_item *ti;
    guint localoffset=0;
    guint x25_pkt_len;
    int modulo;
    guint16 vc;
    dissector_handle_t dissect;
    gboolean toa;         /* TOA/NPI address format */
    guint16 bytes0_1;
    guint8 pkt_type;
    const char *short_name = NULL, *long_name = NULL;
    tvbuff_t *next_tvb = NULL;
    gboolean q_bit_set = FALSE;
    gboolean m_bit_set;
    gint payload_len;
    guint32 frag_key;
    fragment_head *fd_head;
    heur_dtbl_entry_t *hdtbl_entry;


    guint8 spi;
    int is_x_264;
    guint8 prt_id;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "X.25");
    col_clear(pinfo->cinfo, COL_INFO);

    bytes0_1 = tvb_get_ntohs(tvb, 0);

    modulo = ((bytes0_1 & 0x2000) ? 128 : 8);
    vc     = (int)(bytes0_1 & 0x0FFF);

    conversation_create_endpoint_by_id(pinfo, ENDPOINT_X25, vc);

    if (bytes0_1 & X25_ABIT) toa = TRUE;
    else toa = FALSE;

    x25_pkt_len = get_x25_pkt_len(tvb);
    if (x25_pkt_len < 3) /* packet too short */
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Invalid/short X.25 packet");
        if (tree)
            proto_tree_add_protocol_format(tree, proto_x25, tvb, 0, -1,
                    "Invalid/short X.25 packet");
        return;
    }

    pkt_type = tvb_get_guint8(tvb, 2);
    if (PACKET_IS_DATA(pkt_type)) {
        if (bytes0_1 & X25_QBIT)
            q_bit_set = TRUE;
    }

    if (tree) {
        ti = proto_tree_add_item(tree, proto_x25, tvb, 0, x25_pkt_len, ENC_NA);
        x25_tree = proto_item_add_subtree(ti, ett_x25);
        ti = proto_tree_add_item(x25_tree, hf_x25_gfi, tvb, 0, 2, ENC_BIG_ENDIAN);
        gfi_tree = proto_item_add_subtree(ti, ett_x25_gfi);

        if (PACKET_IS_DATA(pkt_type)) {
            proto_tree_add_boolean(gfi_tree, hf_x25_qbit, tvb, 0, 2,
                bytes0_1);
        }
        else if (pkt_type == X25_CALL_REQUEST ||
            pkt_type == X25_CALL_ACCEPTED ||
            pkt_type == X25_CLEAR_REQUEST ||
            pkt_type == X25_CLEAR_CONFIRMATION) {
            proto_tree_add_boolean(gfi_tree, hf_x25_abit, tvb, 0, 2,
                bytes0_1);
        }

        if (pkt_type == X25_CALL_REQUEST || pkt_type == X25_CALL_ACCEPTED ||
            PACKET_IS_DATA(pkt_type)) {
            proto_tree_add_boolean(gfi_tree, hf_x25_dbit, tvb, 0, 2,
                bytes0_1);
        }
        proto_tree_add_uint(gfi_tree, hf_x25_mod, tvb, 0, 2, bytes0_1);
    }

    switch (pkt_type) {
    case X25_CALL_REQUEST:
        switch (dir) {

        case X25_FROM_DCE:
            short_name = "Inc. call";
            long_name = "Incoming call";
            break;

        case X25_FROM_DTE:
            short_name = "Call req.";
            long_name = "Call request";
            break;

        case X25_UNKNOWN:
            short_name = "Inc. call/Call req.";
            long_name = "Incoming call/Call request";
            break;
        }
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d", short_name, vc);
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb,
                    0, 2, bytes0_1);
            proto_tree_add_uint_format_value(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_CALL_REQUEST, "%s", long_name);
        }
        localoffset = 3;
        if (localoffset < x25_pkt_len) { /* calling/called addresses */
            if (toa)
                x25_toa(x25_tree, (gint*)&localoffset, tvb, pinfo);
            else
                x25_ntoa(x25_tree, (gint*)&localoffset, tvb, pinfo, FALSE);
        }

        if (localoffset < x25_pkt_len) /* facilities */
            dump_facilities(x25_tree, (gint*)&localoffset, tvb, pinfo);

        if (localoffset < tvb_reported_length(tvb)) /* user data */
        {

            userdata_tree = proto_tree_add_subtree(x25_tree, tvb, localoffset, -1,
                                                   ett_x25_user_data, &ti, "User data");

            /* X.263/ISO 9577 says that:

                    When CLNP or ESIS are run over X.25, the SPI
                    is 0x81 or 0x82, respectively; those are the
                    NLPIDs for those protocol.

                    When X.224/ISO 8073 COTP is run over X.25, and
                    when ISO 11570 explicit identification is being
                    used, the first octet of the user data field is
                    a TPDU length field, and the rest is "as defined
                    in ITU-T Rec. X.225 | ISO/IEC 8073, Annex B,
                    or ITU-T Rec. X.264 and ISO/IEC 11570".

                    When X.264/ISO 11570 default identification is
                    being used, there is no user data field in the
                    CALL REQUEST packet.  This is for X.225/ISO 8073
                    COTP.

               It also says that SPI values from 0x03 through 0x3f are
               reserved and are in use by X.224/ISO 8073 Annex B and
               X.264/ISO 11570.  The note says that those values are
               not NLPIDs, they're "used by the respective higher layer
               protocol" and "not used for higher layer protocol
               identification".  I infer from this and from what
               X.264/ISO 11570 says that this means that values in those
               range are valid values for the first octet of an
               X.224/ISO 8073 packet or for X.264/ISO 11570.

               Annex B of X.225/ISO 8073 mentions some additional TPDU
               types that can be put in what I presume is the user
               data of connect requests.  It says that:

                    The sending transport entity shall:

                        a) either not transmit any TPDU in the NS-user data
                           parameter of the N-CONNECT request primitive; or

                        b) transmit the UN-TPDU (see ITU-T Rec. X.264 and
                           ISO/IEC 11570) followed by the NCM-TPDU in the
                           NS-user data parameter of the N-CONNECT request
                           primitive.

               I don't know if this means that the user data field
               will contain a UN TPDU followed by an NCM TPDU or not.

               X.264/ISO 11570 says that:

                    When default identification is being used,
                    X.225/ISO 8073 COTP is identified.  No user data
                    is sent in the network-layer connection request.

                    When explicit identification is being used,
                    the user data is a UN TPDU ("Use of network
                    connection TPDU"), which specifies the transport
                    protocol to use over this network connection.
                    It also says that the length of a UN TPDU shall
                    not exceed 32 octets, i.e. shall not exceed 0x20;
                    it says this is "due to the desire not to conflict
                    with the protocol identifier field carried by X.25
                    CALL REQUEST/INCOMING CALL packets", and says that
                    field has values specified in X.244.  X.244 has been
                    superseded by X.263/ISO 9577, so that presumably
                    means the goal is to allow a UN TPDU's length
                    field to be distinguished from an NLPID, allowing
                    you to tell whether X.264/ISO 11570 explicit
                    identification is being used or an NLPID is
                    being used as the SPI.

               I read this as meaning that, if the ISO mechanisms are
               used to identify the protocol being carried over X.25:

                    if there's no user data in the CALL REQUEST/
                    INCOMING CALL packet, it's COTP;

                    if there is user data, then:

                        if the first octet is less than or equal to
                        32, it might be a UN TPDU, and that identifies
                        the transport protocol being used, and
                        it may be followed by more data, such
                        as a COTP NCM TPDU if it's COTP;

                        if the first octet is greater than 32, it's
                        an NLPID, *not* a TPDU length, and the
                        stuff following it is *not* a TPDU.

               Figure A.2 of X.263/ISO 9577 seems to say that the
               first octet of the user data is a TPDU length field,
               in the range 0x03 through 0x82, and says they are
               for X.225/ISO 8073 Annex B or X.264/ISO 11570.

               However, X.264/ISO 11570 seems to imply that the length
               field would be that of a UN TPDU, which must be less
               than or equal to 0x20, and X.225/ISO 8073 Annex B seems
               to indicate that the user data must begin with
               an X.264/ISO 11570 UN TPDU, so I'd say that A.2 should
               have said "in the range 0x03 through 0x20", instead
               (the length value doesn't include the length field,
               and the minimum UN TPDU has length, type, PRT-ID,
               and SHARE, so that's 3 bytes without the length). */
            spi = tvb_get_guint8(tvb, localoffset);
            if (spi > 32 || spi < 3) {
                /* First octet is > 32, or < 3, so the user data isn't an
                   X.264/ISO 11570 UN TPDU */
                is_x_264 = FALSE;
            } else {
                /* First octet is >= 3 and <= 32, so the user data *might*
                   be an X.264/ISO 11570 UN TPDU.  Check whether we have
                   enough data to see if it is. */
                if (tvb_bytes_exist(tvb, localoffset+1, 1)) {
                    /* We do; check whether the second octet is 1. */
                    if (tvb_get_guint8(tvb, localoffset+1) == 0x01) {
                        /* Yes, the second byte is 1, so it looks like
                           a UN TPDU. */
                        is_x_264 = TRUE;
                    } else {
                        /* No, the second byte is not 1, so it's not a
                           UN TPDU. */
                        is_x_264 = FALSE;
                    }
                } else {
                    /* We can't see the second byte of the putative UN
                       TPDU, so we don't know if that's what it is. */
                    is_x_264 = -1;
                }
            }
            if (is_x_264 == -1) {
                /*
                 * We don't know what it is; just skip it.
                 */
                localoffset = tvb_reported_length(tvb);
            } else if (is_x_264) {
                /* It looks like an X.264 UN TPDU, so show it as such. */
                if (userdata_tree) {
                        proto_tree_add_item( userdata_tree, hf_x264_length_indicator, tvb, localoffset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item( userdata_tree, hf_x264_un_tpdu_id, tvb, localoffset+1, 1, ENC_BIG_ENDIAN);
                }
                prt_id = tvb_get_guint8(tvb, localoffset+2);
                if (userdata_tree) {
                        proto_tree_add_item( userdata_tree, hf_x264_protocol_id, tvb, localoffset+2, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item( userdata_tree, hf_x264_sharing_strategy, tvb, localoffset+3, 1, ENC_BIG_ENDIAN);
                }

                /* XXX - dissect the variable part? */

                /* The length doesn't include the length octet itself. */
                localoffset += spi + 1;

                switch (prt_id) {

                case PRT_ID_ISO_8073:
                    /* ISO 8073 COTP */
                    if (!pinfo->fd->visited)
                        x25_hash_add_proto_start(vc, pinfo->num, ositp_handle);
                    /* XXX - dissect the rest of the user data as COTP?
                       That needs support for NCM TPDUs, etc. */
                    break;

                case PRT_ID_ISO_8602:
                    /* ISO 8602 CLTP */
                    if (!pinfo->fd->visited)
                        x25_hash_add_proto_start(vc, pinfo->num, ositp_handle);
                    break;
                }
            } else if (is_x_264 == 0) {
                /* It doesn't look like a UN TPDU, so compare the first
                   octet of the CALL REQUEST packet with various X.263/
                   ISO 9577 NLPIDs, as per Annex A of X.263/ISO 9577. */

                if (userdata_tree) {
                        proto_tree_add_item( userdata_tree, hf_x263_sec_protocol_id, tvb, localoffset, 1, ENC_BIG_ENDIAN);
                }

                if (!pinfo->fd->visited) {
                    /*
                     * Is there a dissector handle for this SPI?
                     * If so, assign it to this virtual circuit.
                     */
                    dissect = dissector_get_uint_handle(x25_subdissector_table, spi);
                    if (dissect != NULL)
                            x25_hash_add_proto_start(vc, pinfo->num, dissect);
                }

                /*
                 * If there's only one octet of user data, it's just
                 * an NLPID; don't try to dissect it.
                 */
                if (localoffset + 1 == tvb_reported_length(tvb))
                    return;

                /*
                 * There's more than one octet of user data, so we'll
                 * dissect it; for some protocols, the NLPID is considered
                 * to be part of the PDU, so, for those cases, we don't
                 * skip past it.  For other protocols, we skip the NLPID.
                 */
                switch (spi) {

                case NLPID_ISO8473_CLNP:
                case NLPID_ISO9542_ESIS:
                case NLPID_ISO10589_ISIS:
                case NLPID_ISO10747_IDRP:
                case NLPID_SNDCF:
                    /*
                     * The NLPID is part of the PDU.  Don't skip it.
                     * But if it's all there is to the PDU, don't
                     * bother dissecting it.
                     */
                    break;

                case NLPID_SPI_X_29:
                    /*
                     * The first 4 bytes of the call user data are
                     * the SPI plus 3 reserved bytes; they are not
                     * part of the data to be dissected as X.29 data.
                     */
                    localoffset += 4;
                    break;

                default:
                    /*
                     * The NLPID isn't part of the PDU - skip it.
                     * If that means there's nothing to dissect
                     */
                    localoffset++;
                }
            }
        } else {
          /* if there's no user data in the CALL REQUEST/
             INCOMING CALL packet, it's COTP; */

           if (call_request_nodata_is_cotp){
              x25_hash_add_proto_start(vc, pinfo->num, ositp_handle);
           }
        }
        break;
    case X25_CALL_ACCEPTED:
        switch (dir) {

        case X25_FROM_DCE:
            short_name = "Call conn.";
            long_name = "Call connected";
            break;

        case X25_FROM_DTE:
            short_name = "Call acc.";
            long_name = "Call accepted";
            break;

        case X25_UNKNOWN:
            short_name = "Call conn./Call acc.";
            long_name = "Call connected/Call accepted";
            break;
        }
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d", short_name, vc);
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
            proto_tree_add_uint_format_value(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_CALL_ACCEPTED, "%s", long_name);
        }
        localoffset = 3;
        if (localoffset < x25_pkt_len) { /* calling/called addresses */
            if (toa)
                x25_toa(x25_tree, (gint*)&localoffset, tvb, pinfo);
            else
                x25_ntoa(x25_tree, (gint*)&localoffset, tvb, pinfo, FALSE);
        }

        if (localoffset < x25_pkt_len) /* facilities */
            dump_facilities(x25_tree, (gint*)&localoffset, tvb, pinfo);
        break;
    case X25_CLEAR_REQUEST:
        switch (dir) {

        case X25_FROM_DCE:
            short_name = "Clear ind.";
            long_name = "Clear indication";
            break;

        case X25_FROM_DTE:
            short_name = "Clear req.";
            long_name = "Clear request";
            break;

        case X25_UNKNOWN:
            short_name = "Clear ind./Clear req.";
            long_name = "Clear indication/Clear request";
            break;
        }
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d %s - %s", short_name,
                    vc, rval_to_str(tvb_get_guint8(tvb, 3), clear_code_rvals, "Unknown (0x%02x)"),
                    val_to_str_ext(tvb_get_guint8(tvb, 4), &x25_clear_diag_vals_ext, "Unknown (0x%02x)"));
        x25_hash_add_proto_end(vc, pinfo->num);
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
            proto_tree_add_uint_format_value(x25_tree, hf_x25_type, tvb,
                    localoffset+2, 1, X25_CLEAR_REQUEST, "%s",
                    long_name);
            proto_tree_add_item(x25_tree, hf_x25_clear_cause, tvb, 3, 1, ENC_NA);
            proto_tree_add_item(x25_tree, hf_x25_diagnostic, tvb, 4, 1, ENC_BIG_ENDIAN);
        }
        localoffset = x25_pkt_len;
        break;
    case X25_CLEAR_CONFIRMATION:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Clear Conf. VC:%d", vc);
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
            proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_CLEAR_CONFIRMATION);
        }
        localoffset = x25_pkt_len;

        if (localoffset < tvb_reported_length(tvb)) { /* extended clear conf format */
            if (toa)
                x25_toa(x25_tree, (gint*)&localoffset, tvb, pinfo);
            else
                x25_ntoa(x25_tree,(gint*)&localoffset, tvb, pinfo, FALSE);
        }

        if (localoffset < tvb_reported_length(tvb)) /* facilities */
            dump_facilities(x25_tree, (gint*)&localoffset, tvb, pinfo);
        break;
    case X25_DIAGNOSTIC:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Diag. %d",
                    (int)tvb_get_guint8(tvb, 3));
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_DIAGNOSTIC);
            proto_tree_add_item(x25_tree, hf_x25_diagnostic, tvb, 3, 1, ENC_NA);
        }
        localoffset = x25_pkt_len;
        break;
    case X25_INTERRUPT:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Interrupt VC:%d", vc);
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
            proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_INTERRUPT);
        }
        localoffset = x25_pkt_len;
        break;
    case X25_INTERRUPT_CONFIRMATION:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Interrupt Conf. VC:%d", vc);
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
            proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_INTERRUPT_CONFIRMATION);
        }
        localoffset = x25_pkt_len;
        break;
    case X25_RESET_REQUEST:
        switch (dir) {

        case X25_FROM_DCE:
            short_name = "Reset ind.";
            long_name = "Reset indication";
            break;

        case X25_FROM_DTE:
            short_name = "Reset req.";
            long_name = "Reset request";
            break;

        case X25_UNKNOWN:
            short_name = "Reset ind./Reset req.";
            long_name = "Reset indication/Reset request";
            break;
        }
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d %s - Diag.:%d",
                    short_name, vc, rval_to_str(tvb_get_guint8(tvb, 3), reset_code_rvals, "Unknown (0x%02x)"),
                    (int)tvb_get_guint8(tvb, 4));
        x25_hash_add_proto_end(vc, pinfo->num);
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
            proto_tree_add_uint_format_value(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_RESET_REQUEST, "%s", long_name);
            proto_tree_add_item(x25_tree, hf_x25_reset_cause, tvb, 3, 1, ENC_NA);
            proto_tree_add_item(x25_tree, hf_x25_diagnostic, tvb, 4, 1, ENC_NA);
        }
        localoffset = x25_pkt_len;
        break;
    case X25_RESET_CONFIRMATION:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Reset conf. VC:%d", vc);
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
            proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_RESET_CONFIRMATION);
        }
        localoffset = x25_pkt_len;
        break;
        case X25_RESTART_REQUEST:
        switch (dir) {

        case X25_FROM_DCE:
            short_name = "Restart ind.";
            long_name = "Restart indication";
            break;

        case X25_FROM_DTE:
            short_name = "Restart req.";
            long_name = "Restart request";
            break;

        case X25_UNKNOWN:
            short_name = "Restart ind./Restart req.";
            long_name = "Restart indication/Restart request";
            break;
        }
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s - Diag.:%d",
                    short_name,
                    rval_to_str(tvb_get_guint8(tvb, 3), restart_code_rvals, "Unknown (0x%02x)"),
                    (int)tvb_get_guint8(tvb, 4));
        if (x25_tree) {
            proto_tree_add_uint_format_value(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_RESTART_REQUEST, "%s", long_name);
            proto_tree_add_item(x25_tree, hf_x25_restart_cause, tvb, 3, 1, ENC_NA);
            proto_tree_add_item(x25_tree, hf_x25_diagnostic, tvb, 4, 1, ENC_NA);
        }
        localoffset = x25_pkt_len;
        break;
    case X25_RESTART_CONFIRMATION:
        col_set_str(pinfo->cinfo, COL_INFO, "Restart conf.");
        if (x25_tree)
            proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_RESTART_CONFIRMATION);
        localoffset = x25_pkt_len;
        break;
    case X25_REGISTRATION_REQUEST:
        col_set_str(pinfo->cinfo, COL_INFO, "Registration req.");
        if (x25_tree)
            proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_REGISTRATION_REQUEST);
        localoffset = 3;
        if (localoffset < x25_pkt_len)
            x25_ntoa(x25_tree, (gint*)&localoffset, tvb, pinfo, TRUE);

        if (x25_tree) {
                if (localoffset < x25_pkt_len)
                        proto_tree_add_item( x25_tree, hf_x25_reg_request_length, tvb, localoffset, 1, ENC_BIG_ENDIAN);
                if (localoffset+1 < x25_pkt_len)
                        proto_tree_add_item(x25_tree, hf_x25_registration, tvb, localoffset+1, tvb_get_guint8(tvb, localoffset) & 0x7F, ENC_NA);
        }
        localoffset = tvb_reported_length(tvb);
        break;
    case X25_REGISTRATION_CONFIRMATION:
        col_set_str(pinfo->cinfo, COL_INFO, "Registration conf.");
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
                    X25_REGISTRATION_CONFIRMATION);
            proto_tree_add_item(x25_tree, hf_x25_reg_confirm_cause, tvb, 3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(x25_tree, hf_x25_reg_confirm_diagnostic, tvb, 4, 1, ENC_BIG_ENDIAN);
        }
        localoffset = 5;
        if (localoffset < x25_pkt_len)
            x25_ntoa(x25_tree, (gint*)&localoffset, tvb, pinfo, TRUE);

        if (x25_tree) {
                if (localoffset < x25_pkt_len)
                        proto_tree_add_item( x25_tree, hf_x25_reg_confirm_length, tvb, localoffset, 1, ENC_BIG_ENDIAN);
                if (localoffset+1 < x25_pkt_len)
                        proto_tree_add_item(x25_tree, hf_x25_registration, tvb, localoffset+1, tvb_get_guint8(tvb, localoffset) & 0x7F, ENC_NA);
        }
        localoffset = tvb_reported_length(tvb);
        break;
    default:
        localoffset = 2;
        if (x25_tree) {
            proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
                                2, bytes0_1);
        }
        if (PACKET_IS_DATA(pkt_type)) {
            if (modulo == 8)
                col_add_fstr(pinfo->cinfo, COL_INFO,
                            "Data VC:%d P(S):%d P(R):%d %s", vc,
                            (pkt_type >> 1) & 0x07,
                            (pkt_type >> 5) & 0x07,
                            (pkt_type & X25_MBIT_MOD8) ? " M" : "");
            else
                col_add_fstr(pinfo->cinfo, COL_INFO,
                            "Data VC:%d P(S):%d P(R):%d %s", vc,
                            tvb_get_guint8(tvb, localoffset+1) >> 1,
                            pkt_type >> 1,
                            (tvb_get_guint8(tvb, localoffset+1) & X25_MBIT_MOD128) ? " M" : "");
            if (x25_tree) {
                if (modulo == 8) {
                    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
                            localoffset, 1, pkt_type);
                    proto_tree_add_boolean(x25_tree, hf_x25_mbit_mod8, tvb,
                            localoffset, 1, pkt_type);
                    proto_tree_add_uint(x25_tree, hf_x25_p_s_mod8, tvb,
                            localoffset, 1, pkt_type);
                    proto_tree_add_uint(x25_tree, hf_x25_type_data, tvb,
                            localoffset, 1, pkt_type);
                }
                else {
                    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod128, tvb,
                            localoffset, 1, pkt_type);
                    proto_tree_add_uint(x25_tree, hf_x25_type_data, tvb,
                            localoffset, 1, pkt_type);
                    proto_tree_add_item(x25_tree, hf_x25_p_s_mod128, tvb,
                            localoffset+1, 1, ENC_NA);
                    proto_tree_add_item(x25_tree, hf_x25_mbit_mod128, tvb,
                            localoffset+1, 1, ENC_NA);
                }
            }
            if (modulo == 8) {
                m_bit_set = pkt_type & X25_MBIT_MOD8;
                localoffset += 1;
            } else {
                m_bit_set = tvb_get_guint8(tvb, localoffset+1) & X25_MBIT_MOD128;
                localoffset += 2;
            }
            payload_len = tvb_reported_length_remaining(tvb, localoffset);
            if (reassemble_x25) {
                /*
                 * Reassemble received and sent traffic separately.
                 * We don't reassemble traffic with an unknown direction
                 * at all.
                 */
                frag_key = vc;
                if (side) {
                    /*
                     * OR in an extra bit to distinguish from traffic
                     * in the other direction.
                     */
                    frag_key |= 0x10000;
                }
                fd_head = fragment_add_seq_next(&x25_reassembly_table,
                                                tvb, localoffset,
                                                pinfo, frag_key, NULL,
                                                payload_len, m_bit_set);
                pinfo->fragmented = m_bit_set;

                /* Fragment handling is not adapted to handle several x25
                 * packets in the same frame. This is common with XOT and
                 * shorter packet sizes.
                 * Therefore, fragment_add_seq_next seem to always return fd_head
                 * A fix to use m_bit_set to only show fragments for last pkt
                 */
                if (!m_bit_set && fd_head) {
                    if (fd_head->next) {
                        proto_item *frag_tree_item;

                        /* This is the last packet */
                        next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
                        add_new_data_source(pinfo, next_tvb, "Reassembled X.25");
                        if (x25_tree) {
                           show_fragment_seq_tree(fd_head,
                                                  &x25_frag_items,
                                                  x25_tree,
                                                  pinfo, next_tvb, &frag_tree_item);
                        }
                    }
                }

                if (m_bit_set && next_tvb == NULL) {
                    /*
                     * This isn't the last packet, so just
                     * show it as X.25 user data.
                     */
                    proto_tree_add_item(x25_tree, hf_x25_user_data, tvb, localoffset, -1, ENC_NA);
                    return;
                }
            }
        } else {
            /*
             * Non-data packets (RR, RNR, REJ).
             */
            if (modulo == 8) {
                if (x25_tree) {
                    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
                            localoffset, 1, pkt_type);
                    proto_tree_add_item(x25_tree, hf_x25_type_fc_mod8, tvb,
                                        localoffset, 1, ENC_BIG_ENDIAN);
                }
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d P(R):%d",
                             val_to_str(PACKET_TYPE_FC(pkt_type), vals_x25_type, "Unknown (0x%02X)"),
                             vc, (pkt_type >> 5) & 0x07);
                localoffset += 1;
            } else {
                if (x25_tree) {
                    proto_tree_add_item(x25_tree, hf_x25_type, tvb,
                                        localoffset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(x25_tree, hf_x25_p_r_mod128, tvb,
                                        localoffset+1, 1, ENC_BIG_ENDIAN);
                }
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d P(R):%d",
                             val_to_str(PACKET_TYPE_FC(pkt_type), vals_x25_type, "Unknown (0x%02X)"),
                             vc, tvb_get_guint8(tvb, localoffset+1) >> 1);
                localoffset += 2;
            }
        }
        break;
    }

    if (localoffset >= tvb_reported_length(tvb))
      return;
    if (pinfo->fragmented)
      return;

    if (!next_tvb)
      next_tvb = tvb_new_subset_remaining(tvb, localoffset);

    /* See if there's already a dissector for this circuit. */
    if (try_conversation_dissector_by_id(ENDPOINT_X25, vc, next_tvb, pinfo,
                              tree, &q_bit_set)) {
                return; /* found it and dissected it */
    }

    /* Did the user suggest QLLC/SNA? */
    if (payload_is_qllc_sna) {
        /* Yes - dissect it as QLLC/SNA. */
        if (!pinfo->fd->visited)
            x25_hash_add_proto_start(vc, pinfo->num, qllc_handle);
        call_dissector_with_data(qllc_handle, next_tvb, pinfo, tree, &q_bit_set);
        return;
    }

    if (payload_check_data){
    /* If the Call Req. has not been captured, let's look at the first
       two bytes of the payload to see if this looks like COTP. */
    if (tvb_get_guint8(next_tvb, 0) == tvb_reported_length(next_tvb)-1) {
      /* First byte contains the length of the remaining buffer */
      if ((tvb_get_guint8(next_tvb, 1) & 0x0F) == 0) {
        /* Second byte contains a valid COTP TPDU */
        if (!pinfo->fd->visited)
            x25_hash_add_proto_start(vc, pinfo->num, ositp_handle);
        call_dissector(ositp_handle, next_tvb, pinfo, tree);
        return;
      }
    }

    /* Then let's look at the first byte of the payload to see if this
       looks like IP or CLNP. */
    switch (tvb_get_guint8(next_tvb, 0)) {

    case 0x45:
        /* Looks like an IP header */
        if (!pinfo->fd->visited)
            x25_hash_add_proto_start(vc, pinfo->num, ip_handle);
        call_dissector(ip_handle, next_tvb, pinfo, tree);
        return;

    case NLPID_ISO8473_CLNP:
        if (!pinfo->fd->visited)
            x25_hash_add_proto_start(vc, pinfo->num, clnp_handle);
        call_dissector(clnp_handle, next_tvb, pinfo, tree);
        return;
    }
    }

    /* Try the heuristic dissectors. */
    if (dissector_try_heuristic(x25_heur_subdissector_list, next_tvb, pinfo,
                                tree, &hdtbl_entry, NULL)) {
        return;
    }

    /* All else failed; dissect it as raw data */
    call_data_dissector(next_tvb, pinfo, tree);
}

/*
 * X.25 dissector for use when "pinfo->pseudo_header" points to a
 * "struct x25_phdr".
 */
static int
dissect_x25_dir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_x25_common(tvb, pinfo, tree,
        (pinfo->pseudo_header->dte_dce.flags & FROM_DCE) ? X25_FROM_DCE :
                                                       X25_FROM_DTE,
        pinfo->pseudo_header->dte_dce.flags & FROM_DCE);
    return tvb_captured_length(tvb);
}

/*
 * X.25 dissector for use when "pinfo->pseudo_header" doesn't point to a
 * "struct x25_phdr".
 */
static int
dissect_x25(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int direction;

    /*
     * We don't know if this packet is DTE->DCE or DCE->DCE.
     * However, we can, at least, distinguish between the two
     * sides of the conversation, based on the addresses and
     * ports.
     */
    direction = cmp_address(&pinfo->src, &pinfo->dst);
    if (direction == 0)
        direction = (pinfo->srcport > pinfo->destport)*2 - 1;
    dissect_x25_common(tvb, pinfo, tree, X25_UNKNOWN, direction > 0);
    return tvb_captured_length(tvb);
}

void
proto_register_x25(void)
{
    static hf_register_info hf[] = {
        { &hf_x25_facility,
          { "Facility", "x25.facility", FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facilities_length,
          { "Facilities Length", "x25.facilities_length", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_length,
          { "Length", "x25.facility_length", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_class,
          { "Facility Class", "x25.facility.class", FT_UINT8, BASE_HEX, VALS(x25_facilities_class_vals), X25_FAC_CLASS_MASK,
            NULL, HFILL }},
        { &hf_x25_facility_classA,
          { "Code", "x25.facility.classA", FT_UINT8, BASE_HEX, VALS(x25_facilities_classA_vals), 0,
            "Facility ClassA Code", HFILL }},
        { &hf_x25_facility_classA_comp_mark,
          { "Parameter", "x25.facility.comp_mark", FT_UINT8, BASE_DEC, VALS(x25_facilities_classA_comp_mark_vals), 0,
            "Facility Marker Parameter", HFILL }},
        { &hf_x25_facility_classA_reverse,
          { "Parameter", "x25.facility.reverse", FT_UINT8, BASE_HEX, NULL, 0,
            "Facility Reverse Charging Parameter", HFILL }},
        { &hf_x25_facility_classA_charging_info,
          { "Parameter", "x25.facility.charging_info", FT_UINT8, BASE_HEX, NULL, 0,
            "Facility Charging Information Parameter", HFILL }},
        { &hf_x25_facility_reverse_charging,
          { "Reverse charging", "x25.reverse_charging", FT_BOOLEAN, 8, TFS(&x25_reverse_charging_val), 0x01,
            NULL, HFILL }},
        { &hf_x25_facility_charging_info,
          { "Charging information", "x25.charging_info", FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }},
        { &hf_x25_facility_throughput_called_dte,
          { "From the called DTE", "x25.facility.throughput.called_dte", FT_UINT8, BASE_DEC, VALS(x25_facilities_classA_throughput_vals), 0xF0,
            "Facility Throughput called DTE", HFILL }},
        { &hf_x25_throughput_called_dte,
          { "From the calling DTE", "x25.facility.throughput.calling_dte", FT_UINT8, BASE_DEC, VALS(x25_facilities_classA_throughput_vals), 0x0F,
            "Facility Throughput calling DTE", HFILL }},
        { &hf_x25_facility_classA_cug,
          { "Closed user group", "x25.facility.cug", FT_UINT8, BASE_HEX, NULL, 0,
            "Facility Closed user group", HFILL }},
        { &hf_x25_facility_classA_called_motif,
          { "Parameter", "x25.facility.called_motif", FT_UINT8, BASE_HEX, NULL, 0,
            "Facility Called address modified parameter", HFILL }},
        { &hf_x25_facility_classA_cug_outgoing_acc,
          { "Closed user group", "x25.facility.cug_outgoing_acc", FT_UINT8, BASE_HEX, NULL, 0,
            "Facility Closed user group with outgoing access selection", HFILL }},
        { &hf_x25_facility_classA_throughput_min,
          { "Parameter", "x25.facility.throughput_min", FT_UINT8, BASE_HEX, NULL, 0,
            "Facility Minimum throughput class parameter", HFILL }},
        { &hf_x25_facility_classA_express_data,
          { "Parameter", "x25.facility.express_data", FT_UINT8, BASE_HEX, NULL, 0,
            "Facility Negotiation of express data parameter", HFILL }},
        { &hf_x25_facility_classA_unknown,
          { "Parameter", "x25.facility.classA_unknown", FT_UINT8, BASE_HEX, NULL, 0,
            "Facility Class A unknown parameter", HFILL }},
        { &hf_x25_facility_classB,
          { "Code", "x25.facility.classB", FT_UINT8, BASE_HEX, VALS(x25_facilities_classB_vals), 0,
            "Facility ClassB Code", HFILL }},
        { &hf_x25_facility_classB_bilateral_cug,
          { "Bilateral CUG", "x25.facility.bilateral_cug", FT_UINT16, BASE_HEX, NULL, 0,
            "Facility Bilateral CUG", HFILL }},
        { &hf_x25_facility_packet_size_called_dte,
          { "From the called DTE", "x25.facility.packet_size.called_dte", FT_UINT8, BASE_DEC, VALS(x25_facilities_classB_packet_size_vals), 0,
            "Facility Packet size from the called DTE", HFILL }},
        { &hf_x25_facility_packet_size_calling_dte,
          { "From the calling DTE", "x25.facility.packet_size.calling_dte", FT_UINT8, BASE_DEC, VALS(x25_facilities_classB_packet_size_vals), 0,
            "Facility Packet size from the calling DTE", HFILL }},
        { &hf_x25_facility_data_network_id_code,
          { "Data network identification code", "x25.facility.data_network_id_code", FT_UINT16, BASE_HEX, NULL, 0,
            "Facility RPOA selection data network identification code", HFILL }},
        { &hf_x25_facility_cug_ext,
          { "Closed user group", "x25.facility.cug_ext", FT_UINT16, BASE_HEX, NULL, 0,
            "Facility Extended closed user group selection", HFILL }},
        { &hf_x25_facility_cug_outgoing_acc_ext,
          { "Closed user group", "x25.facility.cug_outgoing_acc_ext", FT_UINT16, BASE_HEX, NULL, 0,
            "Facility Extended closed user group with outgoing access selection", HFILL }},
        { &hf_x25_facility_transit_delay,
          { "Transit delay (ms)", "x25.facility.transit_delay", FT_UINT16, BASE_DEC, NULL, 0,
            "Facility Transit delay selection and indication", HFILL }},
        { &hf_x25_facility_classB_unknown,
          { "Parameter", "x25.facility.classB_unknown", FT_UINT16, BASE_HEX, NULL, 0,
            "Facility Class B unknown parameter", HFILL }},
        { &hf_x25_facility_classC_unknown,
          { "Parameter", "x25.facility.classC_unknown", FT_UINT24, BASE_HEX, NULL, 0,
            "Facility Class C unknown parameter", HFILL }},
        { &hf_x25_facility_classC,
          { "Code", "x25.facility.classC", FT_UINT8, BASE_HEX, VALS(x25_facilities_classC_vals), 0,
            "Facility ClassC Code", HFILL }},
        { &hf_x25_facility_classD,
          { "Code", "x25.facility.classD", FT_UINT8, BASE_HEX, VALS(x25_facilities_classD_vals), 0,
            "Facility ClassD Code", HFILL }},
        { &hf_x25_gfi,
          { "GFI", "x25.gfi", FT_UINT16, BASE_DEC, NULL, 0xF000,
            "General format identifier", HFILL }},
        { &hf_x25_abit,
          { "A Bit", "x25.a", FT_BOOLEAN, 16, NULL, X25_ABIT,
            "Address Bit", HFILL }},
        { &hf_x25_qbit,
          { "Q Bit", "x25.q", FT_BOOLEAN, 16, NULL, X25_QBIT,
            "Qualifier Bit", HFILL }},
        { &hf_x25_dbit,
          { "D Bit", "x25.d", FT_BOOLEAN, 16, NULL, X25_DBIT,
            "Delivery Confirmation Bit", HFILL }},
        { &hf_x25_mod,
          { "Modulo", "x25.mod", FT_UINT16, BASE_DEC, VALS(vals_modulo), 0x3000,
            "Specifies whether the frame is modulo 8 or 128", HFILL }},
        { &hf_x25_lcn,
          { "Logical Channel", "x25.lcn", FT_UINT16, BASE_DEC, NULL, 0x0FFF,
            "Logical Channel Number", HFILL }},
        { &hf_x25_type,
          { "Packet Type", "x25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x0,
            NULL, HFILL }},
        { &hf_x25_type_fc_mod8,
          { "Packet Type", "x25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x1F,
            NULL, HFILL }},
        { &hf_x25_type_data,
          { "Packet Type", "x25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x01,
            NULL, HFILL }},
        { &hf_x25_diagnostic,
          { "Diagnostic", "x25.diagnostic", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &x25_clear_diag_vals_ext, 0,
            NULL, HFILL }},
        { &hf_x25_p_r_mod8,
          { "P(R)", "x25.p_r", FT_UINT8, BASE_DEC, NULL, 0xE0,
            "Packet Receive Sequence Number", HFILL }},
        { &hf_x25_p_r_mod128,
          { "P(R)", "x25.p_r", FT_UINT8, BASE_DEC, NULL, 0xFE,
            "Packet Receive Sequence Number", HFILL }},
        { &hf_x25_mbit_mod8,
          { "M Bit", "x25.m", FT_BOOLEAN, 8, TFS(&m_bit_tfs), X25_MBIT_MOD8,
            "More Bit", HFILL }},
        { &hf_x25_mbit_mod128,
          { "M Bit", "x25.m", FT_BOOLEAN, 8, TFS(&m_bit_tfs), X25_MBIT_MOD128,
            "More Bit", HFILL }},
        { &hf_x25_p_s_mod8,
          { "P(S)", "x25.p_s", FT_UINT8, BASE_DEC, NULL, 0x0E,
            "Packet Send Sequence Number", HFILL }},
        { &hf_x25_p_s_mod128,
          { "P(S)", "x25.p_s", FT_UINT8, BASE_DEC, NULL, 0xFE,
            "Packet Send Sequence Number", HFILL }},
        { &hf_x25_window_size_called_dte,
          { "From the called DTE", "x25.window_size.called_dte", FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }},
        { &hf_x25_window_size_calling_dte,
          { "From the calling DTE", "x25.window_size.calling_dte", FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }},
        { &hf_x25_dte_address_length,
          { "DTE address length", "x25.dte_address_length", FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }},
        { &hf_x25_dce_address_length,
          { "DCE address length", "x25.dce_address_length", FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }},
        { &hf_x25_calling_address_length,
          { "Calling address length", "x25.calling_address_length", FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }},
        { &hf_x25_called_address_length,
          { "Called address length", "x25.called_address_length", FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }},
        { &hf_x25_facility_call_transfer_reason,
          { "Reason", "x25.facility.call_transfer_reason", FT_UINT8, BASE_DEC, VALS(x25_facilities_call_transfer_reason_vals), 0,
            NULL, HFILL }},
        { &hf_x25_facility_monetary_unit,
          { "Monetary unit", "x25.facility.monetary_unit", FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_nui,
          { "NUI", "x25.facility.nui", FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_cumulative_ete_transit_delay,
          { "Cumulative end-to-end transit delay (ms)", "x25.facility.cumulative_ete_transit_delay", FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_requested_ete_transit_delay,
          { "Requested end-to-end transit delay (ms)", "x25.facility.requested_ete_transit_delay", FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_max_acceptable_ete_transit_delay,
          { "Maximum acceptable end-to-end transit delay (ms)", "x25.facility.mac_acceptable_ete_transit_delay", FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_priority_data,
          { "Priority for data", "x25.facility.priority_data", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_priority_estab_conn,
          { "Priority for establishing connection", "x25.facility.priority_estab_conn", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_priority_keep_conn,
          { "Priority for keeping connection", "x25.facility.priority_keep_conn", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_min_acceptable_priority_data,
          { "Minimum acceptable priority for data", "x25.facility.min_acceptable_priority_data", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_min_acceptable_priority_estab_conn,
          { "Minimum acceptable priority for establishing connection", "x25.facility.min_acceptable_priority_estab_conn", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_min_acceptable_priority_keep_conn,
          { "Minimum acceptable priority for keeping connection", "x25.facility.min_acceptable_priority_keep_conn", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_classD_unknown,
          { "Parameter", "x25.facility.classD_unknown", FT_BYTES, BASE_NONE, NULL, 0,
            "Facility Class D unknown parameter", HFILL }},
        { &hf_x25_facility_call_transfer_num_semi_octets,
          { "Number of semi-octets in DTE address", "x25.facility.call_transfer_num_semi_octets", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_calling_addr_ext_num_semi_octets,
          { "Number of semi-octets in DTE address", "x25.facility.calling_addr_ext_num_semi_octets", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_called_addr_ext_num_semi_octets,
          { "Number of semi-octets in DTE address", "x25.facility.called_addr_ext_num_semi_octets", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x25_facility_call_deflect_num_semi_octets,
          { "Number of semi-octets in the alternative DTE address", "x25.facility.call_deflect_num_semi_octets", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x264_length_indicator,
          { "X.264 length indicator", "x25.x264_length_indicator", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_x264_un_tpdu_id,
          { "X.264 UN TPDU identifier", "x25.x264_un_tpdu_id", FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }},
        { &hf_x264_protocol_id,
          { "X.264 protocol identifier", "x25.x264_protocol_id", FT_UINT8, BASE_HEX, VALS(prt_id_vals), 0,
            NULL, HFILL }},
        { &hf_x264_sharing_strategy,
          { "X.264 sharing strategy", "x25.x264_sharing_strategy", FT_UINT8, BASE_HEX, VALS(sharing_strategy_vals), 0,
            NULL, HFILL }},
        { &hf_x263_sec_protocol_id,
          { "X.263 secondary protocol ID", "x25.x263_sec_protocol_id", FT_UINT8, BASE_HEX, VALS(nlpid_vals), 0,
            NULL, HFILL }},
        { &hf_x25_reg_request_length,
          { "Registration length", "x25.reg_request_length", FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }},
        { &hf_x25_reg_confirm_length,
          { "Registration length", "x25.reg_confirm_length", FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }},

        { &hf_x25_segment_overlap,
          { "Fragment overlap", "x25.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }},

        { &hf_x25_segment_overlap_conflict,
          { "Conflicting data in fragment overlap",     "x25.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},

        { &hf_x25_segment_multiple_tails,
          { "Multiple tail fragments found",    "x25.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},

        { &hf_x25_segment_too_long_segment,
          { "Fragment too long",        "x25.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},

        { &hf_x25_segment_error,
          { "Defragmentation error", "x25.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }},

        { &hf_x25_segment_count,
          { "Fragment count", "x25.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_x25_reassembled_length,
          { "Reassembled X.25 length", "x25.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},

        { &hf_x25_segment,
          { "X.25 Fragment", "x25.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_x25_segments,
          { "X.25 Fragments", "x25.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_x25_fast_select,
          { "Fast select", "x25.fast_select", FT_UINT8, BASE_DEC, VALS(x25_fast_select_vals), 0xC0,
            NULL, HFILL }},

        { &hf_x25_icrd,
          { "ICRD", "x25.icrd", FT_UINT8, BASE_DEC, VALS(x25_icrd_vals), 0x30,
            NULL, HFILL }},

        { &hf_x25_reg_confirm_cause,
          { "Cause", "x25.reg_confirm.cause", FT_UINT8, BASE_DEC, VALS(x25_registration_code_vals), 0,
            NULL, HFILL }},

        { &hf_x25_reg_confirm_diagnostic,
          { "Diagnostic", "x25.reg_confirm.diagnostic", FT_UINT8, BASE_DEC, VALS(x25_registration_code_vals), 0,
            NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_x25_call_duration, { "Call duration", "x25.call_duration", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_segments_to_dte, { "Segments sent to DTE", "x25.segments_to_dte", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_segments_from_dte, { "Segments received from DTE", "x25.segments_from_dte", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_dte_address, { "DTE address", "x25.dte_address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_data_network_identification_code, { "Data network identification code", "x25.data_network_identification_code", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_facility_call_deflect_reason, { "Reason", "x25.facility.call_deflect_reason", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_alternative_dte_address, { "Alternative DTE address", "x25.alternative_dte_address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_dce_address, { "DCE address", "x25.dce_address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_called_address, { "Called address", "x25.called_address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_calling_address, { "Calling address", "x25.calling_address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_clear_cause, { "Cause", "x25.clear_cause", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(clear_code_rvals), 0x0, NULL, HFILL }},
      { &hf_x25_reset_cause, { "Cause", "x25.reset_cause", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(reset_code_rvals), 0x0, NULL, HFILL }},
      { &hf_x25_restart_cause, { "Cause", "x25.restart_cause", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(restart_code_rvals), 0x0, NULL, HFILL }},
      { &hf_x25_registration, { "Registration", "x25.registration", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_x25_user_data, { "User data", "x25.user_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_x25,
        &ett_x25_gfi,
        &ett_x25_facilities,
        &ett_x25_facility,
        &ett_x25_user_data,
        &ett_x25_segment,
        &ett_x25_segments
    };

    static ei_register_info ei[] = {
        { &ei_x25_facility_length, { "x25.facility_length.bogus", PI_PROTOCOL, PI_WARN, "Bogus length", EXPFILL }},
    };

    module_t *x25_module;
    expert_module_t* expert_x25;

    proto_x25 = proto_register_protocol ("X.25", "X.25", "x25");
    proto_register_field_array (proto_x25, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_x25 = expert_register_protocol(proto_x25);
    expert_register_field_array(expert_x25, ei, array_length(ei));

    x25_subdissector_table = register_dissector_table("x.25.spi",
        "X.25 secondary protocol identifier", proto_x25, FT_UINT8, BASE_HEX);
    x25_heur_subdissector_list = register_heur_dissector_list("x.25", proto_x25);

    register_dissector("x.25_dir", dissect_x25_dir, proto_x25);
    x25_handle = register_dissector("x.25", dissect_x25, proto_x25);

    /* Preferences */
    x25_module = prefs_register_protocol(proto_x25, NULL);
    /* For reading older preference files with "x.25." preferences */
    prefs_register_module_alias("x.25", x25_module);
    prefs_register_obsolete_preference(x25_module, "non_q_bit_is_sna");
    prefs_register_bool_preference(x25_module, "payload_is_qllc_sna",
            "Default to QLLC/SNA",
            "If CALL REQUEST not seen or didn't specify protocol, dissect as QLLC/SNA",
            &payload_is_qllc_sna);
    prefs_register_bool_preference(x25_module, "call_request_nodata_is_cotp",
            "Assume COTP for Call Request without data",
            "If CALL REQUEST has no data, assume the protocol handled is COTP",
            &call_request_nodata_is_cotp);
    prefs_register_bool_preference(x25_module, "payload_check_data",
            "Check data for COTP/IP/CLNP",
            "If CALL REQUEST not seen or didn't specify protocol, check user data before checking heuristic dissectors",
            &payload_check_data);
    prefs_register_bool_preference(x25_module, "reassemble",
                                   "Reassemble fragmented X.25 packets",
                                   "Reassemble fragmented X.25 packets",
                                   &reassemble_x25);
    reassembly_table_register(&x25_reassembly_table,
                          &addresses_reassembly_table_functions);
}

void
proto_reg_handoff_x25(void)
{
    /*
     * Get handles for various dissectors.
     */
    ip_handle = find_dissector_add_dependency("ip", proto_x25);
    clnp_handle = find_dissector_add_dependency("clnp", proto_x25);
    ositp_handle = find_dissector_add_dependency("ositp", proto_x25);
    qllc_handle = find_dissector_add_dependency("qllc", proto_x25);

    dissector_add_uint("llc.dsap", SAP_X25, x25_handle);
    dissector_add_uint("lapd.sapi", LAPD_SAPI_X25, x25_handle);
    dissector_add_uint("ax25.pid", AX25_P_ROSE, x25_handle);
    dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_X25, x25_handle);
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
