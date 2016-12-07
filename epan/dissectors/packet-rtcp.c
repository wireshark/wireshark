/* packet-rtcp.c
 *
 * Routines for RTCP dissection
 * RTCP = Real-time Transport Control Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <h323@ramdyne.nl>
 *
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * Copyright 2005, Nagarjuna Venna <nvenna@brixnet.com>
 *
 * Copyright 2010, Matteo Valdina <zanfire@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This dissector tries to dissect the RTCP protocol according to Annex A
 * of ITU-T Recommendation H.225.0 (02/98) and RFC 1889
 * H.225.0 literally copies RFC 1889, but omitting a few sections.
 *
 * RTCP traffic is handled by an uneven UDP portnumber. This can be any
 * port number, but there is a registered port available, port 5005
 * See Annex B of ITU-T Recommendation H.225.0, section B.7
 *
 * Information on PoC can be found from http://www.openmobilealliance.org/
 *
 * RTCP XR is specified in RFC 3611.
 *
 * See also http://www.iana.org/assignments/rtp-parameters
 *
 * RTCP FB is specified in RFC 4585 and extended by RFC 5104
 *
 * MS-RTP: Real-time Transport Protocol (RTP) Extensions http://msdn.microsoft.com/en-us/library/office/cc431492.aspx
 *
 */

/*
 * The part of this dissector for IDMS XR blocks was written by
 * Torsten Loebner (loebnert@googlemail.com) in the context of a graduation
 * project with the research organization TNO in Delft, Netherland.
 * The extension is based on the RTCP XR block specified in
 * ETSI TS 182 063 v3.5.2 Annex W (http://www.etsi.org/deliver/etsi_ts/183000_183099/183063/),
 * which was registered by IANA as RTCP XR Block Type 12
 * (http://www.iana.org/assignments/rtcp-xr-block-types/rtcp-xr-block-types.xml).
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>

#include "packet-rtcp.h"
#include "packet-rtp.h"
#include "packet-ntp.h"
#include <epan/conversation.h>

#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/proto_data.h>

void proto_register_rtcp(void);
void proto_reg_handoff_rtcp(void);

/* Version is the first 2 bits of the first octet*/
#define RTCP_VERSION(octet) ((octet) >> 6)

/* Padding is the third bit; no need to shift, because true is any value
   other than 0! */
#define RTCP_PADDING(octet) ((octet) & 0x20)

/* Receiver/ Sender count is the 5 last bits  */
#define RTCP_COUNT(octet)   ((octet) & 0x1F)

static dissector_handle_t rtcp_handle;

/* add dissector table to permit sub-protocol registration */
static dissector_table_t rtcp_dissector_table;
static dissector_table_t rtcp_psfb_dissector_table;
static dissector_table_t rtcp_rtpfb_dissector_table;

static const value_string rtcp_version_vals[] =
{
    { 2, "RFC 1889 Version" },
    { 0, "Old VAT Version" },
    { 1, "First Draft Version" },
    { 0, NULL },
};

#define RTCP_PT_MIN  192
/* Supplemental H.261 specific RTCP packet types according to Section C.3.5 */
#define RTCP_FIR     192
#define RTCP_NACK    193
#define RTCP_SMPTETC 194
#define RTCP_IJ      195
/* RTCP packet types according to Section A.11.1 */
/* And http://www.iana.org/assignments/rtp-parameters */
#define RTCP_SR      200
#define RTCP_RR      201
#define RTCP_SDES    202
#define RTCP_BYE     203
#define RTCP_APP     204
#define RTCP_RTPFB   205
#define RTCP_PSFB    206
#define RTCP_XR      207
#define RTCP_AVB     208
#define RTCP_RSI     209
#define RTCP_TOKEN   210

#define RTCP_PT_MAX  210

static const value_string rtcp_packet_type_vals[] =
{
    { RTCP_SR,      "Sender Report" },
    { RTCP_RR,      "Receiver Report" },
    { RTCP_SDES,    "Source description" },
    { RTCP_BYE,     "Goodbye" },
    { RTCP_APP,     "Application specific" },
    { RTCP_RTPFB,   "Generic RTP Feedback" },
    { RTCP_PSFB,    "Payload-specific Feedback" },
    { RTCP_XR,      "Extended report (RFC 3611)"},
    { RTCP_AVB,     "AVB RTCP packet (IEEE1733)" },
    { RTCP_RSI,     "Receiver Summary Information" },
    { RTCP_TOKEN,   "Port Mapping" },
    { RTCP_FIR,     "Full Intra-frame Request (H.261)" },
    { RTCP_NACK,    "Negative Acknowledgement (H.261)" },
    { RTCP_SMPTETC, "SMPTE time-code mapping" },
    { RTCP_IJ,      "Extended inter-arrival jitter report" },
    { 0,         NULL }
};

/* RTCP SDES types (Section A.11.2) */
#define RTCP_SDES_END         0
#define RTCP_SDES_CNAME       1
#define RTCP_SDES_NAME        2
#define RTCP_SDES_EMAIL       3
#define RTCP_SDES_PHONE       4
#define RTCP_SDES_LOC         5
#define RTCP_SDES_TOOL        6
#define RTCP_SDES_NOTE        7
#define RTCP_SDES_PRIV        8
#define RTCP_SDES_H323_CADDR  9
#define RTCP_SDES_APSI       10

static const value_string rtcp_sdes_type_vals[] =
{
    { RTCP_SDES_END,        "END" },
    { RTCP_SDES_CNAME,      "CNAME (user and domain)" },
    { RTCP_SDES_NAME,       "NAME (common name)" },
    { RTCP_SDES_EMAIL,      "EMAIL (e-mail address)" },
    { RTCP_SDES_PHONE,      "PHONE (phone number)" },
    { RTCP_SDES_LOC,        "LOC (geographic location)" },
    { RTCP_SDES_TOOL,       "TOOL (name/version of source app)" },
    { RTCP_SDES_NOTE,       "NOTE (note about source)" },
    { RTCP_SDES_PRIV,       "PRIV (private extensions)" },
    { RTCP_SDES_H323_CADDR, "H323-CADDR (H.323 callable address)" },
    { RTCP_SDES_APSI,       "Application Specific Identifier" },
    { 0,               NULL }
};

/* RTCP XR Blocks (Section 4, RTC 3611)
 * or http://www.iana.org/assignments/rtcp-xr-block-types */
#define RTCP_XR_LOSS_RLE     1
#define RTCP_XR_DUP_RLE      2
#define RTCP_XR_PKT_RXTIMES  3
#define RTCP_XR_REF_TIME     4
#define RTCP_XR_DLRR         5
#define RTCP_XR_STATS_SUMRY  6
#define RTCP_XR_VOIP_METRCS  7
#define RTCP_XR_BT_XNQ       8
#define RTCP_XR_TI_VOIP      9
#define RTCP_XR_PR_LOSS_RLE 10
#define RTCP_XR_MC_ACQ      11
#define RTCP_XR_IDMS        12

static const value_string rtcp_xr_type_vals[] =
{
    { RTCP_XR_LOSS_RLE,     "Loss Run Length Encoding Report Block" },
    { RTCP_XR_DUP_RLE,      "Duplicate Run Length Encoding Report Block" },
    { RTCP_XR_PKT_RXTIMES,  "Packet Receipt Times Report Block" },
    { RTCP_XR_REF_TIME,     "Receiver Reference Time Report Block" },
    { RTCP_XR_DLRR,         "DLRR Report Block" },
    { RTCP_XR_STATS_SUMRY,  "Statistics Summary Report Block" },
    { RTCP_XR_VOIP_METRCS,  "VoIP Metrics Report Block" },
    { RTCP_XR_BT_XNQ,       "BT XNQ RTCP XR (RFC5093) Report Block" },
    { RTCP_XR_TI_VOIP,      "Texas Instruments Extended VoIP Quality Block" },
    { RTCP_XR_PR_LOSS_RLE,  "Post-repair Loss RLE Report Block" },
    { RTCP_XR_MC_ACQ,       "Multicast Acquisition Report Block" },
    { RTCP_XR_IDMS,         "Inter-destination Media Synchronization Block" }, /* [http://www.etsi.org/deliver/etsi_ts/183000_183099/183063/][ETSI 183 063][Miguel_Angel_Reina_Ortega] */
    { 0, NULL}
};

/* XR VoIP Metrics Block - PLC Algorithms */
static const value_string rtcp_xr_plc_algo_vals[] =
{
    { 0, "Unspecified" },
    { 1, "Disabled" },
    { 2, "Enhanced" },
    { 3, "Standard" },
    { 0, NULL }
};

/* XR VoIP Metrics Block - JB Adaptive */
static const value_string rtcp_xr_jb_adaptive_vals[] =
{
    { 0, "Unknown" },
    { 1, "Reserved" },
    { 2, "Non-Adaptive" },
    { 3, "Adaptive" },
    { 0, NULL }
};

/* XR Stats Summary Block - IP TTL or Hop Limit */
static const value_string rtcp_xr_ip_ttl_vals[] =
{
    { 0, "No TTL Values" },
    { 1, "IPv4" },
    { 2, "IPv6" },
    { 3, "Undefined" },
    { 0, NULL }
};

/* XR IDMS synchronization packet sender type */
static const value_string rtcp_xr_idms_spst[] =
{
    {  0, "Reserved" },
    {  1, "SC" },
    {  2, "MSAS" },
    {  3, "SC' INPUT" },
    {  4, "SC' OUTPUT" },
    {  5, "Reserved" },
    {  6, "Reserved" },
    {  7, "Reserved" },
    {  8, "Reserved" },
    {  9, "Reserved" },
    { 10, "Reserved" },
    { 11, "Reserved" },
    { 12, "Reserved" },
    { 13, "Reserved" },
    { 14, "Reserved" },
    { 15, "Reserved" },
    { 0, NULL }
};

/* RTCP Application PoC1 Value strings
 * OMA-TS-PoC-UserPlane-V1_0-20060609-A
 */

#define TBCP_BURST_REQUEST                  0
#define TBCP_BURST_GRANTED                  1
#define TBCP_BURST_TAKEN_EXPECT_NO_REPLY    2
#define TBCP_BURST_DENY                     3
#define TBCP_BURST_RELEASE                  4
#define TBCP_BURST_IDLE                     5
#define TBCP_BURST_REVOKE                   6
#define TBCP_BURST_ACKNOWLEDGMENT           7
#define TBCP_QUEUE_STATUS_REQUEST           8
#define TBCP_QUEUE_STATUS_RESPONSE          9
#define TBCP_DISCONNECT                    11
#define TBCP_CONNECT                       15
#define TBCP_BURST_TAKEN_EXPECT_REPLY      18


static const value_string rtcp_app_poc1_floor_cnt_type_vals[] =
{
    {  TBCP_BURST_REQUEST,                 "TBCP Talk Burst Request"},
    {  TBCP_BURST_GRANTED,                 "TBCP Talk Burst Granted"},
    {  TBCP_BURST_TAKEN_EXPECT_NO_REPLY,   "TBCP Talk Burst Taken (no ack expected)"},
    {  TBCP_BURST_DENY,                    "TBCP Talk Burst Deny"},
    {  TBCP_BURST_RELEASE,                 "TBCP Talk Burst Release"},
    {  TBCP_BURST_IDLE,                    "TBCP Talk Burst Idle"},
    {  TBCP_BURST_REVOKE,                  "TBCP Talk Burst Revoke"},
    {  TBCP_BURST_ACKNOWLEDGMENT,          "TBCP Talk Burst Acknowledgement"},
    {  TBCP_QUEUE_STATUS_REQUEST,          "TBCP Queue Status Request"},
    {  TBCP_QUEUE_STATUS_RESPONSE,         "TBCP Queue Status Response"},
    {  TBCP_DISCONNECT,                    "TBCP Disconnect"},
    {  TBCP_CONNECT,                       "TBCP Connect"},
    {  TBCP_BURST_TAKEN_EXPECT_REPLY,      "TBCP Talk Burst Taken (ack expected)"},
    {  0,   NULL }
};

static const value_string rtcp_app_poc1_reason_code1_vals[] =
{
    {  1,   "Another PoC User has permission"},
    {  2,   "Internal PoC server error"},
    {  3,   "Only one participant in the group"},
    {  4,   "Retry-after timer has not expired"},
    {  5,   "Listen only"},
    {  0,   NULL }
};

static const value_string rtcp_app_poc1_reason_code2_vals[] =
{
    {  1,   "Only one user"},
    {  2,   "Talk burst too long"},
    {  3,   "No permission to send a Talk Burst"},
    {  4,   "Talk burst pre-empted"},
    {  0,   NULL }
};

static const value_string rtcp_app_poc1_reason_code_ack_vals[] =
{
    {  0,   "Accepted"},
    {  1,   "Busy"},
    {  2,   "Not accepted"},
    {  0,   NULL }
};
static const value_string rtcp_app_poc1_conn_sess_type_vals[] =
{
    {  0,   "None"},
    {  1,   "1-to-1"},
    {  2,   "Ad-hoc"},
    {  3,   "Pre-arranged"},
    {  4,   "Chat"},
    {  0,   NULL }
};

static const value_string rtcp_app_poc1_qsresp_priority_vals[] =
{
    {  0,   "No priority (un-queued)"},
    {  1,   "Normal priority"},
    {  2,   "High priority"},
    {  3,   "Pre-emptive priority"},
    {  0,   NULL }
};

/* 3GPP 29.414 RTP Multiplexing */
static const value_string rtcp_app_mux_selection_vals[] =
{
    {  0,   "No multiplexing applied"},
    {  1,   "Multiplexing without RTP header compression applied"},
    {  2,   "Multiplexing with RTP header compression applied"},
    {  3,   "Reserved"},
    {  0,   NULL}
};

/* RFC 4585 and RFC 5104 */
static const value_string rtcp_rtpfb_fmt_vals[] =
{
    {   1,  "Generic negative acknowledgement (NACK)"},
    {   3,  "Temporary Maximum Media Stream Bit Rate Request (TMMBR)"},
    {   4,  "Temporary Maximum Media Stream Bit Rate Notification (TMMBN)"},
    {  31,  "Reserved for future extensions"},
    {   0,  NULL }
};

static const value_string rtcp_psfb_fmt_vals[] =
{
    {   1,  "Picture Loss Indication"},
    {   2,  "Slice Loss Indication"},
    {   3,  "Reference Picture Selection Indication"},
    {   4,  "Full Intra Request (FIR) Command"},
    {   5,  "Temporal-Spatial Trade-off Request (TSTR)"},
    {   6,  "Temporal-Spatial Trade-off Notification (TSTN)"},
    {   7,  "Video Back Channel Message (VBCM)"},
    {  15,  "Application Layer Feedback"},
    {  31,  "Reserved for future extensions"},
    {   0,  NULL }
};

static const value_string rtcp_psfb_fmt_summary_vals[] =
{
    {   1,  "PLI"},
    {   2,  "SLI"},
    {   3,  "RPSI"},
    {   4,  "FIR"},
    {   5,  "TSTR"},
    {   6,  "TSTN"},
    {   7,  "VBCM"},
    {  15,  "ALFB"},
    {  31,  "Reserved"},
    {   0,  NULL }
};

/* Microsoft Profile Specific Extension Types */
static const value_string rtcp_ms_profile_extension_vals[] =
{
    {   1,  "MS - Estimated Bandwidth"},
    {   4,  "MS - Packet Loss Notification"},
    {   5,  "MS - Video Preference"},
    {   6,  "MS - Padding"},
    {   7,  "MS - Policy Server Bandwidth"},
    {   8,  "MS - TURN Server Bandwidth"},
    {   9,  "MS - Audio Healer Metrics"},
    {   10,  "MS - Receiver-side Bandwidth Limit"},
    {   11,  "MS - Packet Train Packet"},
    {   12,  "MS - Peer Info Exchange"},
    {   13,  "MS - Network Congestion Notification"},
    {   14,  "MS - Modality Send Bandwidth Limit"},
    {   0,  NULL }
};

static const value_string rtcp_ssrc_values[] = {
    {  0xFFFFFFFF,   "SOURCE_NONE" },
    {  0xFFFFFFFE,   "SOURCE_ANY" },
    {   0,  NULL }
};

/* RTCP header fields                   */
static int proto_rtcp = -1;
static int hf_rtcp_version = -1;
static int hf_rtcp_padding = -1;
static int hf_rtcp_rc = -1;
static int hf_rtcp_sc = -1;
static int hf_rtcp_pt = -1;
static int hf_rtcp_length = -1;
static int hf_rtcp_ssrc_sender = -1;
static int hf_rtcp_ssrc_media_source = -1;
static int hf_rtcp_ntp = -1;
static int hf_rtcp_ntp_msw = -1;
static int hf_rtcp_ntp_lsw = -1;
static int hf_rtcp_rtp_timestamp = -1;
static int hf_rtcp_sender_pkt_cnt = -1;
static int hf_rtcp_sender_oct_cnt = -1;
static int hf_rtcp_ssrc_source = -1;
static int hf_rtcp_ssrc_fraction = -1;
static int hf_rtcp_ssrc_cum_nr = -1;
static int hf_rtcp_ssrc_discarded = -1;
/* First the 32 bit number, then the split
 * up 16 bit values */
/* These two are added to a subtree */
static int hf_rtcp_ssrc_ext_high_seq = -1;
static int hf_rtcp_ssrc_high_seq = -1;
static int hf_rtcp_ssrc_high_cycles = -1;
static int hf_rtcp_ssrc_jitter = -1;
static int hf_rtcp_ssrc_lsr = -1;
static int hf_rtcp_ssrc_dlsr = -1;
/* static int hf_rtcp_ssrc_csrc = -1; */
static int hf_rtcp_sdes_type = -1;
static int hf_rtcp_sdes_length = -1;
static int hf_rtcp_sdes_text = -1;
static int hf_rtcp_sdes_prefix_len = -1;
static int hf_rtcp_sdes_prefix_string = -1;
static int hf_rtcp_subtype = -1;
static int hf_rtcp_name_ascii = -1;
static int hf_rtcp_app_data = -1;
static int hf_rtcp_fsn = -1;
static int hf_rtcp_blp = -1;
static int hf_rtcp_padding_count = -1;
static int hf_rtcp_padding_data = -1;
static int hf_rtcp_profile_specific_extension_type = -1;
static int hf_rtcp_profile_specific_extension_length = -1;
static int hf_rtcp_profile_specific_extension = -1;
static int hf_rtcp_app_poc1 = -1;
static int hf_rtcp_app_poc1_subtype = -1;
static int hf_rtcp_app_poc1_sip_uri = -1;
static int hf_rtcp_app_poc1_disp_name = -1;
static int hf_rtcp_app_poc1_priority = -1;
static int hf_rtcp_app_poc1_request_ts = -1;
static int hf_rtcp_app_poc1_stt = -1;
static int hf_rtcp_app_poc1_partic = -1;
static int hf_rtcp_app_poc1_ssrc_granted = -1;
static int hf_rtcp_app_poc1_last_pkt_seq_no = -1;
static int hf_rtcp_app_poc1_ignore_seq_no = -1;
static int hf_rtcp_app_poc1_reason_code1 = -1;
static int hf_rtcp_app_poc1_reason1_phrase = -1;
static int hf_rtcp_app_poc1_reason_code2 = -1;
static int hf_rtcp_app_poc1_new_time_request = -1;
static int hf_rtcp_app_poc1_ack_subtype = -1;
static int hf_rtcp_app_poc1_ack_reason_code = -1;
static int hf_rtcp_app_poc1_qsresp_priority = -1;
static int hf_rtcp_app_poc1_qsresp_position = -1;
static int hf_rtcp_app_poc1_conn_content[5] = { -1, -1, -1, -1, -1 };
static int hf_rtcp_app_poc1_conn_session_type = -1;
static int hf_rtcp_app_poc1_conn_add_ind_mao = -1;
static int hf_rtcp_app_poc1_conn_sdes_items[5] = { -1, -1, -1, -1, -1 };
static int hf_rtcp_app_mux = -1;
static int hf_rtcp_app_mux_mux = -1;
static int hf_rtcp_app_mux_cp = -1;
static int hf_rtcp_app_mux_selection = -1;
static int hf_rtcp_app_mux_localmuxport = -1;
static int hf_rtcp_xr_block_type = -1;
static int hf_rtcp_xr_block_specific = -1;
static int hf_rtcp_xr_block_length = -1;
static int hf_rtcp_xr_thinning = -1;
static int hf_rtcp_xr_voip_metrics_burst_density = -1;
static int hf_rtcp_xr_voip_metrics_gap_density = -1;
static int hf_rtcp_xr_voip_metrics_burst_duration = -1;
static int hf_rtcp_xr_voip_metrics_gap_duration = -1;
static int hf_rtcp_xr_voip_metrics_rtdelay = -1;
static int hf_rtcp_xr_voip_metrics_esdelay = -1;
static int hf_rtcp_xr_voip_metrics_siglevel = -1;
static int hf_rtcp_xr_voip_metrics_noiselevel = -1;
static int hf_rtcp_xr_voip_metrics_rerl = -1;
static int hf_rtcp_xr_voip_metrics_gmin = -1;
static int hf_rtcp_xr_voip_metrics_rfactor = -1;
static int hf_rtcp_xr_voip_metrics_extrfactor = -1;
static int hf_rtcp_xr_voip_metrics_moslq = -1;
static int hf_rtcp_xr_voip_metrics_moscq = -1;
static int hf_rtcp_xr_voip_metrics_plc = -1;
static int hf_rtcp_xr_voip_metrics_jbadaptive = -1;
static int hf_rtcp_xr_voip_metrics_jbrate = -1;
static int hf_rtcp_xr_voip_metrics_jbnominal = -1;
static int hf_rtcp_xr_voip_metrics_jbmax = -1;
static int hf_rtcp_xr_voip_metrics_jbabsmax = -1;
static int hf_rtcp_xr_stats_loss_flag = -1;
static int hf_rtcp_xr_stats_dup_flag = -1;
static int hf_rtcp_xr_stats_jitter_flag = -1;
static int hf_rtcp_xr_stats_ttl = -1;
static int hf_rtcp_xr_beginseq = -1;
static int hf_rtcp_xr_endseq = -1;
static int hf_rtcp_xr_chunk_null_terminator = -1;
static int hf_rtcp_xr_chunk_length = -1;
static int hf_rtcp_xr_chunk_bit_vector = -1;
static int hf_rtcp_xr_receipt_time_seq = -1;
static int hf_rtcp_xr_stats_lost = -1;
static int hf_rtcp_xr_stats_dups = -1;
static int hf_rtcp_xr_stats_minjitter = -1;
static int hf_rtcp_xr_stats_maxjitter = -1;
static int hf_rtcp_xr_stats_meanjitter = -1;
static int hf_rtcp_xr_stats_devjitter = -1;
static int hf_rtcp_xr_stats_minttl = -1;
static int hf_rtcp_xr_stats_maxttl = -1;
static int hf_rtcp_xr_stats_meanttl = -1;
static int hf_rtcp_xr_stats_devttl = -1;
static int hf_rtcp_xr_timestamp = -1;
static int hf_rtcp_xr_lrr = -1;
static int hf_rtcp_xr_dlrr = -1;
static int hf_rtcp_xr_idms_spst = -1;
static int hf_rtcp_xr_idms_pt = -1;
static int hf_rtcp_xr_idms_msci = -1;
static int hf_rtcp_xr_idms_source_ssrc = -1;
static int hf_rtcp_xr_idms_ntp_rcv_ts = -1;
static int hf_rtcp_xr_idms_rtp_ts = -1;
static int hf_rtcp_xr_idms_ntp_pres_ts = -1;
static int hf_rtcp_length_check = -1;
static int hf_rtcp_rtpfb_fmt = -1;
static int hf_rtcp_rtpfb_nack_pid = -1;
static int hf_rtcp_rtpfb_nack_blp = -1;
static int hf_rtcp_psfb_fmt = -1;
static int hf_rtcp_fci = -1;
static int hf_rtcp_psfb_fir_fci_ssrc = -1;
static int hf_rtcp_psfb_fir_fci_csn = -1;
static int hf_rtcp_psfb_fir_fci_reserved = -1;
static int hf_rtcp_psfb_sli_first = -1;
static int hf_rtcp_psfb_sli_number = -1;
static int hf_rtcp_psfb_sli_picture_id = -1;
#if 0
static int hf_rtcp_psfb_remb_fci_identifier = -1;
static int hf_rtcp_psfb_remb_fci_number_ssrcs = -1;
static int hf_rtcp_psfb_remb_fci_ssrc = -1;
static int hf_rtcp_psfb_remb_fci_exp = -1;
static int hf_rtcp_psfb_remb_fci_mantissa = -1;
static int hf_rtcp_psfb_remb_fci_bitrate = -1;
#endif
static int hf_rtcp_rtpfb_tmbbr_fci_ssrc = -1;
static int hf_rtcp_rtpfb_tmbbr_fci_exp = -1;
static int hf_rtcp_rtpfb_tmbbr_fci_mantissa = -1;
static int hf_rtcp_rtpfb_tmbbr_fci_bitrate = -1;
static int hf_rtcp_rtpfb_tmbbr_fci_measuredoverhead = -1;
static int hf_srtcp_e = -1;
static int hf_srtcp_index = -1;
static int hf_srtcp_mki = -1;
static int hf_srtcp_auth_tag = -1;
static int hf_rtcp_xr_btxnq_begseq = -1;               /* added for BT XNQ block (RFC5093) */
static int hf_rtcp_xr_btxnq_endseq = -1;
static int hf_rtcp_xr_btxnq_vmaxdiff = -1;
static int hf_rtcp_xr_btxnq_vrange = -1;
static int hf_rtcp_xr_btxnq_vsum = -1;
static int hf_rtcp_xr_btxnq_cycles = -1;
static int hf_rtcp_xr_btxnq_jbevents = -1;
static int hf_rtcp_xr_btxnq_tdegnet = -1;
static int hf_rtcp_xr_btxnq_tdegjit = -1;
static int hf_rtcp_xr_btxnq_es = -1;
static int hf_rtcp_xr_btxnq_ses = -1;
static int hf_rtcp_xr_btxnq_spare = -1;

/* RTCP setup fields */
static int hf_rtcp_setup = -1;
static int hf_rtcp_setup_frame = -1;
static int hf_rtcp_setup_method = -1;

/* RTCP roundtrip delay fields */
static int hf_rtcp_last_sr_timestamp_frame = -1;
static int hf_rtcp_time_since_last_sr = -1;
static int hf_rtcp_roundtrip_delay = -1;

/* MS Profile Specific Extension Fields */
static int hf_rtcp_pse_ms_bandwidth = -1;
static int hf_rtcp_pse_ms_confidence_level = -1;
static int hf_rtcp_pse_ms_seq_num = -1;
static int hf_rtcp_pse_ms_frame_resolution_width = -1;
static int hf_rtcp_pse_ms_frame_resolution_height = -1;
static int hf_rtcp_pse_ms_bitrate = -1;
static int hf_rtcp_pse_ms_frame_rate = -1;
static int hf_rtcp_pse_ms_concealed_frames = -1;
static int hf_rtcp_pse_ms_stretched_frames = -1;
static int hf_rtcp_pse_ms_compressed_frames = -1;
static int hf_rtcp_pse_ms_total_frames = -1;
static int hf_rtcp_pse_ms_receive_quality_state = -1;
static int hf_rtcp_pse_ms_fec_distance_request = -1;
static int hf_rtcp_pse_ms_last_packet_train = -1;
static int hf_rtcp_pse_ms_packet_idx = -1;
static int hf_rtcp_pse_ms_packet_cnt = -1;
static int hf_rtcp_pse_ms_packet_train_byte_cnt = -1;
static int hf_rtcp_pse_ms_inbound_bandwidth = -1;
static int hf_rtcp_pse_ms_outbound_bandwidth = -1;
static int hf_rtcp_pse_ms_no_cache = -1;
static int hf_rtcp_pse_ms_congestion_info = -1;
static int hf_rtcp_pse_ms_modality = -1;
/* Microsoft PLI Extension */
static int hf_rtcp_psfb_pli_ms_request_id = -1;
static int hf_rtcp_psfb_pli_ms_sfr = -1;
/* Microsoft Video Source Request */
static int hf_rtcp_psfb_ms_type = -1;
static int hf_rtcp_psfb_ms_length = -1;
static int hf_rtcp_psfb_ms_msi = -1;
static int hf_rtcp_psfb_ms_vsr_request_id = -1;
static int hf_rtcp_psfb_ms_vsr_version = -1;
static int hf_rtcp_psfb_ms_vsr_key_frame_request = -1;
static int hf_rtcp_psfb_ms_vsr_num_entries = -1;
static int hf_rtcp_psfb_ms_vsr_entry_length = -1;
static int hf_rtcp_psfb_ms_vsre_payload_type = -1;
static int hf_rtcp_psfb_ms_vsre_ucconfig_mode = -1;
static int hf_rtcp_psfb_ms_vsre_no_sp_frames = -1;
static int hf_rtcp_psfb_ms_vsre_baseline = -1;
static int hf_rtcp_psfb_ms_vsre_cgs = -1;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_bitmask = -1;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_4by3 = -1;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_16by9 = -1;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_1by1 = -1;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_3by4 = -1;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_9by16 = -1;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_20by3 = -1;
static int hf_rtcp_psfb_ms_vsre_max_width = -1;
static int hf_rtcp_psfb_ms_vsre_max_height = -1;
static int hf_rtcp_psfb_ms_vsre_min_bitrate = -1;
static int hf_rtcp_psfb_ms_vsre_bitrate_per_level = -1;
static int hf_rtcp_psfb_ms_vsre_bitrate_histogram = -1;
static int hf_rtcp_psfb_ms_vsre_frame_rate_mask = -1;
static int hf_rtcp_psfb_ms_vsre_frame_rate_7_5 = -1;
static int hf_rtcp_psfb_ms_vsre_frame_rate_12_5 = -1;
static int hf_rtcp_psfb_ms_vsre_frame_rate_15 = -1;
static int hf_rtcp_psfb_ms_vsre_frame_rate_25 = -1;
static int hf_rtcp_psfb_ms_vsre_frame_rate_30 = -1;
static int hf_rtcp_psfb_ms_vsre_frame_rate_50= -1;
static int hf_rtcp_psfb_ms_vsre_frame_rate_60 = -1;
static int hf_rtcp_psfb_ms_vsre_must_instances = -1;
static int hf_rtcp_psfb_ms_vsre_may_instances = -1;
static int hf_rtcp_psfb_ms_vsre_quality_histogram = -1;
static int hf_rtcp_psfb_ms_vsre_max_pixels = -1;

/* RTCP fields defining a sub tree */
static gint ett_rtcp                    = -1;
static gint ett_rtcp_sr                 = -1;
static gint ett_rtcp_rr                 = -1;
static gint ett_rtcp_sdes               = -1;
static gint ett_rtcp_bye                = -1;
static gint ett_rtcp_app                = -1;
static gint ett_rtcp_rtpfb              = -1;
static gint ett_rtcp_psfb               = -1;
static gint ett_rtcp_xr                 = -1;
static gint ett_rtcp_fir                = -1;
static gint ett_rtcp_nack               = -1;
static gint ett_ssrc                    = -1;
static gint ett_ssrc_item               = -1;
static gint ett_ssrc_ext_high           = -1;
static gint ett_sdes                    = -1;
static gint ett_sdes_item               = -1;
static gint ett_PoC1                    = -1;
static gint ett_mux                     = -1;
static gint ett_rtcp_setup              = -1;
static gint ett_rtcp_roundtrip_delay    = -1;
static gint ett_xr_block                = -1;
static gint ett_xr_block_contents       = -1;
static gint ett_xr_ssrc                 = -1;
static gint ett_xr_loss_chunk           = -1;
static gint ett_poc1_conn_contents      = -1;
static gint ett_rtcp_nack_blp           = -1;
static gint ett_pse                     = -1;
static gint ett_ms_vsr                  = -1;
static gint ett_ms_vsr_entry            = -1;
static gint ett_ms_ds                   = -1;

static expert_field ei_rtcp_bye_reason_not_padded = EI_INIT;
static expert_field ei_rtcp_xr_block_length_bad = EI_INIT;
static expert_field ei_rtcp_roundtrip_delay = EI_INIT;
static expert_field ei_rtcp_length_check = EI_INIT;
static expert_field ei_rtcp_roundtrip_delay_negative = EI_INIT;
static expert_field ei_rtcp_psfb_ms_type = EI_INIT;
static expert_field ei_rtcp_missing_sender_ssrc = EI_INIT;
static expert_field ei_rtcp_missing_block_header = EI_INIT;
static expert_field ei_rtcp_block_length = EI_INIT;
static expert_field ei_srtcp_encrypted_payload = EI_INIT;

/* Main dissection function */
static int dissect_rtcp( tvbuff_t *tvb, packet_info *pinfo,
     proto_tree *tree, void* data );

/* Displaying set info */
static gboolean global_rtcp_show_setup_info = TRUE;
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Related to roundtrip calculation (using LSR and DLSR) */
static gboolean global_rtcp_show_roundtrip_calculation = FALSE;
#define MIN_ROUNDTRIP_TO_REPORT_DEFAULT 10
static guint global_rtcp_show_roundtrip_calculation_minimum = MIN_ROUNDTRIP_TO_REPORT_DEFAULT;
static void remember_outgoing_sr(packet_info *pinfo, guint32 lsr);
static void calculate_roundtrip_delay(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, guint32 lsr, guint32 dlsr);
static void add_roundtrip_delay_info(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree,
                                     guint frame,
                                     guint gap_between_reports, gint delay);


/* Set up an RTCP conversation using the info given */
void srtcp_add_address( packet_info *pinfo,
                       address *addr, int port,
                       int other_port,
                       const gchar *setup_method, guint32 setup_frame_number,
                       struct srtp_info *srtcp_info)
{
    address                         null_addr;
    conversation_t                 *p_conv;
    struct _rtcp_conversation_info *p_conv_data;

    /*
     * If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again.
     */
    if (pinfo->fd->flags.visited)
    {
        return;
    }

    clear_address(&null_addr);

    /*
     * Check if the ip address and port combination is not
     * already registered as a conversation.
     */
    p_conv = find_conversation( pinfo->num, addr, &null_addr, PT_UDP, port, other_port,
                                NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

    /*
     * If not, create a new conversation.
     */
    if ( ! p_conv ) {
        p_conv = conversation_new( pinfo->num, addr, &null_addr, PT_UDP,
                                   (guint32)port, (guint32)other_port,
                                   NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
    }

    /* Set dissector */
    conversation_set_dissector(p_conv, rtcp_handle);

    /*
     * Check if the conversation has data associated with it.
     */
    p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);

    /*
     * If not, add a new data item.
     */
    if ( ! p_conv_data ) {
        /* Create conversation data */
        p_conv_data = wmem_new0(wmem_file_scope(), struct _rtcp_conversation_info);
        conversation_add_proto_data(p_conv, proto_rtcp, p_conv_data);
    }

    /*
     * Update the conversation data.
     */
    p_conv_data->setup_method_set = TRUE;
    g_strlcpy(p_conv_data->setup_method, setup_method, MAX_RTCP_SETUP_METHOD_SIZE);
    p_conv_data->setup_frame_number = setup_frame_number;
    p_conv_data->srtcp_info = srtcp_info;
}

/* Set up an RTCP conversation using the info given */
void rtcp_add_address( packet_info *pinfo,
                       address *addr, int port,
                       int other_port,
                       const gchar *setup_method, guint32 setup_frame_number)
{
    srtcp_add_address(pinfo, addr, port, other_port, setup_method, setup_frame_number, NULL);
}

static gboolean
dissect_rtcp_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    unsigned int offset = 0;
    unsigned int first_byte;
    unsigned int packet_type;

    /* Look at first byte */
    first_byte = tvb_get_guint8(tvb, offset);

    /* Are version bits set to 2? */
    if (((first_byte & 0xC0) >> 6) != 2)
    {
        return FALSE;
    }

    /* Look at packet type */
    packet_type = tvb_get_guint8(tvb, offset + 1);

    /* First packet within compound packet is supposed to be a sender
       or receiver report.
       - allow BYE because this happens anyway
       - allow APP because TBCP ("PoC1") packets aren't compound...
       - allow PSFB for MS */
    if (!((packet_type == RTCP_SR)  || (packet_type == RTCP_RR) ||
          (packet_type == RTCP_BYE) || (packet_type == RTCP_APP) ||
          (packet_type == RTCP_PSFB)))
    {
        return FALSE;
    }

    /* Overall length must be a multiple of 4 bytes */
    if (tvb_reported_length(tvb) % 4)
    {
        return FALSE;
    }

    /* OK, dissect as RTCP */
    dissect_rtcp(tvb, pinfo, tree, data);
    return TRUE;
}

static gboolean
dissect_rtcp_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Was it sent to an odd-numbered port? */
    if ((pinfo->destport % 2) == 0)
    {
        return FALSE;   /* no */
    }

    return dissect_rtcp_heur(tvb, pinfo, tree, data);
}

/* Dissect the length field. Append to this field text indicating the number of
   actual bytes this translates to (i.e. (raw value + 1) * 4) */
static int dissect_rtcp_length_field( proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item     *ti;
    unsigned short  raw_length = tvb_get_ntohs( tvb, offset );

    ti = proto_tree_add_item( tree, hf_rtcp_length, tvb, offset, 2,  ENC_BIG_ENDIAN);
    proto_item_append_text(ti, " (%u bytes)", (raw_length+1)*4);
    offset += 2;
    return offset;
}


static int
dissect_rtcp_nack( tvbuff_t *tvb, int offset, proto_tree *tree )
{
    /* Packet type = FIR (H261) */
    proto_tree_add_item( tree, hf_rtcp_rc, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;
    /* Packet type, 8 bits  = APP */
    proto_tree_add_item( tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    /* Packet length in 32 bit words minus one */
    offset = dissect_rtcp_length_field(tree, tvb, offset);

    /* SSRC  */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* FSN, 16 bits */
    proto_tree_add_item( tree, hf_rtcp_fsn, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    /* BLP, 16 bits */
    proto_tree_add_item( tree, hf_rtcp_blp, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    return offset;
}

static int
dissect_rtcp_rtpfb_tmmbr( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree, proto_item *top_item, int num_fci, int is_notification)
{
    int         bitrate;
    int         exp;
    guint32     mantissa;
    proto_tree *fci_tree;

    if (is_notification == 1) {
        fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 8, ett_ssrc, NULL, "TMMBN %d", num_fci );
    } else {
        fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 8, ett_ssrc, NULL, "TMMBR %d", num_fci );
    }

    /* SSRC 32 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;
    /* Exp 6 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_exp, tvb, offset, 1, ENC_BIG_ENDIAN );
    exp = (tvb_get_guint8(tvb, offset) & 0xfc) >> 2;
        /* Mantissa 17 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_mantissa, tvb, offset, 3, ENC_BIG_ENDIAN );
    mantissa = (tvb_get_ntohl( tvb, offset) & 0x3fffe00) >> 9;
    bitrate = mantissa << exp;
    proto_tree_add_string_format_value( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_bitrate, tvb, offset, 3, "", "%u", bitrate);
    offset += 3;
    /* Overhead */
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_measuredoverhead, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset += 1;

    if (top_item != NULL) {
          proto_item_append_text(top_item, ": TMMBR: %u", bitrate);
      }

    return offset;
}

/* Dissect Application Specific Feedback messages */
static int
dissect_rtcp_asfb_ms( tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo)
{
    guint8  num_entries;
    guint8  desc = 0;
    guint16  type;
    guint16 length;
    guint8  i;
    guint32 msi;
    guint32 min_bitrate, bitrate_per_level;
    proto_tree *rtcp_ms_vsr_tree;
    proto_tree *rtcp_ms_vsr_entry_tree;
    proto_tree *rtcp_ms_ds_tree;
    proto_item *item, *type_item;

    type = tvb_get_ntohs(tvb, offset);
    type_item = proto_tree_add_item( tree, hf_rtcp_psfb_ms_type, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    length = tvb_get_ntohs(tvb, offset) - 4;
    proto_tree_add_item( tree, hf_rtcp_psfb_ms_length, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    if (type == 1)
    {
        rtcp_ms_vsr_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ms_vsr, &item, "MS Video Source Request");

        col_append_fstr(pinfo->cinfo, COL_INFO,"( MS-VSR )");

        item = proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_msi, tvb, offset, 4, ENC_BIG_ENDIAN );
        msi = tvb_get_ntohl (tvb, offset);
        /* Decode if it is NONE or ANY and add to line */
        proto_item_append_text(item," %s", val_to_str_const(msi, rtcp_ssrc_values, ""));
        offset += 4;

        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_request_id, tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;
        /* 2 reserved bytes */
        offset += 2;
        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_version, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_key_frame_request, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
        num_entries = tvb_get_guint8(tvb, offset);
        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_num_entries, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_entry_length, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
        /* 4 reserved bytes */
        offset += 4;

        while (num_entries-- && tvb_captured_length_remaining (tvb, offset) >= 0x44)
        {
            rtcp_ms_vsr_entry_tree = proto_tree_add_subtree_format(rtcp_ms_vsr_tree, tvb, offset, 0x44,
                                     ett_ms_vsr_entry, NULL, "MS Video Source Request Entry #%d", ++desc);

            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_payload_type,    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_ucconfig_mode,  tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_no_sp_frames,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_baseline,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_cgs,  tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_bitmask,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_20by3,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_9by16,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_3by4,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_1by1,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_16by9,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_4by3,  tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_max_width,  tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_max_height,  tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_min_bitrate,  tvb, offset, 4, ENC_BIG_ENDIAN);
            min_bitrate = tvb_get_ntohl (tvb, offset);
            offset += 4;
            /* 4 Reserved bytes */
            offset += 4;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_bitrate_per_level,  tvb, offset, 4, ENC_BIG_ENDIAN);
            bitrate_per_level = tvb_get_ntohl (tvb, offset);
            offset += 4;
            for (i = 0 ; i < 10 ; i++)
            {
                item = proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_bitrate_histogram,  tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_item_prepend_text(item,"Bitrate %d - %d ",
                        min_bitrate + i * bitrate_per_level,
                        min_bitrate + (i + 1) * bitrate_per_level);
                offset += 2;
            }
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_mask,  tvb, offset, 4, ENC_BIG_ENDIAN);
            offset +=3;      /* Move to low byte of mask where valid setting are */
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_60,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_50,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_30,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_25,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_15,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_12_5,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_7_5,  tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_must_instances,  tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_may_instances,  tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            for (i = 0 ; i < 8 ; i++)
            {
                item = proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_quality_histogram,  tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_item_prepend_text(item, "Quality Level %d ", i+1 );
                offset += 2;
            }
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_max_pixels,  tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    }
    else if (type == 3)
    {
        /* MS Dominant Speaker History */
        rtcp_ms_ds_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ms_ds, NULL, "MS Dominant Speaker History");
        col_append_fstr(pinfo->cinfo, COL_INFO,"( MS-DSH )");
        while (length-- && tvb_captured_length_remaining (tvb, offset) >= 4)
        {
            item = proto_tree_add_item( rtcp_ms_ds_tree, hf_rtcp_psfb_ms_msi, tvb, offset, 4, ENC_BIG_ENDIAN );
            msi = tvb_get_ntohl (tvb, offset);
            proto_item_append_text(item," %s", val_to_str_const(msi, rtcp_ssrc_values, ""));
            offset += 4;
            length --;
        }
    }
    else
    {
        expert_add_info(pinfo, type_item, &ei_rtcp_psfb_ms_type);
        offset += tvb_captured_length_remaining (tvb, offset);
    }
    return offset;
}

#if 0
static int
dissect_rtcp_psfb_remb( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree, proto_item *top_item, int num_fci, int *read_fci)
{
    guint       exp, indexSsrcs;
    guint8      numberSsrcs;
    guint32     mantissa, bitrate;
    proto_tree *fci_tree;

    fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 8, ett_ssrc, NULL, "REMB %d", num_fci );

    /* Uniquie identifier 'REMB' */
    proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_identifier, tvb, offset, 4, ENC_ASCII|ENC_NA );
    offset += 4;

    /* Number of ssrcs - they will each be parsed below */
    proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_number_ssrcs, tvb, offset, 1, ENC_BIG_ENDIAN );
    numberSsrcs = tvb_get_guint8( tvb, offset);
    offset += 1;

    /* Exp 6 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_exp, tvb, offset, 1, ENC_BIG_ENDIAN );
    exp = (tvb_get_guint8(tvb, offset) & 0xfc) ;
    exp = exp >> 2;

    /* Mantissa 18 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_mantissa, tvb, offset, 3, ENC_BIG_ENDIAN );
    mantissa = (tvb_get_ntohl( tvb, offset - 1) & 0x0003ffff);
    bitrate = mantissa << exp;
    proto_tree_add_string_format_value( fci_tree, hf_rtcp_psfb_remb_fci_bitrate, tvb, offset, 3, "", "%u", bitrate);
    offset += 3;

    for  (indexSsrcs = 0; indexSsrcs < numberSsrcs; indexSsrcs++)
    {
        /* SSRC 32 bit*/
        proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
        offset += 4;
    }

    if (top_item != NULL) {
        proto_item_append_text(top_item, ": REMB: max bitrate=%u", bitrate);
    }
    *read_fci = 2 + (numberSsrcs);

    return offset;
}
#endif


static int
dissect_rtcp_rtpfb_nack( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree, proto_item *top_item)
{
    int           i;
    int           nack_num_frames_lost;
    proto_tree   *bitfield_tree;
    unsigned int  rtcp_rtpfb_nack_pid;
    unsigned int  rtcp_rtpfb_nack_blp;
    proto_item   *ti;

    proto_tree_add_item(rtcp_tree, hf_rtcp_rtpfb_nack_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    rtcp_rtpfb_nack_pid = tvb_get_ntohs(tvb, offset);
    offset += 2;

    ti = proto_tree_add_item(rtcp_tree, hf_rtcp_rtpfb_nack_blp, tvb, offset, 2, ENC_BIG_ENDIAN);
    rtcp_rtpfb_nack_blp = tvb_get_ntohs(tvb, offset);
    bitfield_tree = proto_item_add_subtree(ti, ett_rtcp_nack_blp);
    nack_num_frames_lost = 1;
    if (rtcp_rtpfb_nack_blp) {
        proto_item_append_text(ti, " (Frames");
        for (i = 0; i < 16; i ++) {
            if (rtcp_rtpfb_nack_blp & (1<<i)) {
                proto_tree_add_uint_format(bitfield_tree, hf_rtcp_rtpfb_nack_pid, tvb, offset, 2, rtcp_rtpfb_nack_pid + i + 1,
                    "Frame %u also lost", rtcp_rtpfb_nack_pid + i + 1);
                proto_item_append_text(ti, " %u", rtcp_rtpfb_nack_pid + i + 1);
                nack_num_frames_lost ++;
            }
        }
        proto_item_append_text(ti, " lost)");
    } else {
        proto_item_append_text(ti, " (No additional frames lost)");
    }
    offset += 2;

    if (top_item != NULL) {
        proto_item_append_text(top_item, ": NACK: %d frames lost", nack_num_frames_lost);
    }
    return offset;
}


static int
dissect_rtcp_rtpfb( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree, proto_item *top_item, packet_info *pinfo )
{
    unsigned int counter;
    unsigned int rtcp_rtpfb_fmt;
    int          packet_length;
    int          start_offset   = offset;

    /* Transport layer FB message */
    /* Feedback message type (FMT): 5 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_rtpfb_fmt, tvb, offset, 1, ENC_BIG_ENDIAN );
    rtcp_rtpfb_fmt = (tvb_get_guint8(tvb, offset) & 0x1f);
    offset++;

    /* Packet type, 8 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    /* Packet length in 32 bit words MINUS one, 16 bits */
    packet_length = (tvb_get_ntohs(tvb, offset) + 1) * 4;
    offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);

    /* SSRC of packet sender, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* SSRC of media source, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* Check if we have a type specific dissector,
     * if we do, just return from here
     */
    if (packet_length > 12) {
      tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset, packet_length - 12);

      if (dissector_try_uint (rtcp_rtpfb_dissector_table, rtcp_rtpfb_fmt,
              subtvb, pinfo, rtcp_tree))
        return start_offset + packet_length;
    }

    /* Transport-Layer Feedback Message Elements */
    counter = 0;
    while ((offset - start_offset) < packet_length) {
      counter++;
      if (rtcp_rtpfb_fmt == 1) {
        offset = dissect_rtcp_rtpfb_nack(tvb, offset, rtcp_tree, top_item);
      } else if (rtcp_rtpfb_fmt == 3) {
        offset = dissect_rtcp_rtpfb_tmmbr(tvb, offset, rtcp_tree, top_item, counter, 0);
      } else if (rtcp_rtpfb_fmt == 4) {
        offset = dissect_rtcp_rtpfb_tmmbr(tvb, offset, rtcp_tree, top_item, counter, 1);
      } else {
        /* Unknown FMT */
        proto_tree_add_item(rtcp_tree, hf_rtcp_fci, tvb, offset, start_offset + packet_length - offset, ENC_NA );
        offset = start_offset + packet_length;
      }
    }

    return offset;
}
static int
dissect_rtcp_psfb( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree,
    int packet_length, proto_item *top_item _U_, packet_info *pinfo _U_)
{
    unsigned int  counter;
    unsigned int  num_fci;
    unsigned int  read_fci;
    proto_tree   *fci_tree;
    proto_item   *ti;
    unsigned int  rtcp_psfb_fmt;
    int           base_offset = offset;
    int           i;

    /* Payload-specific FB message */
    /* Feedback message type (FMT): 5 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_psfb_fmt, tvb, offset, 1, ENC_BIG_ENDIAN );
    rtcp_psfb_fmt = (tvb_get_guint8(tvb, offset) & 0x1f);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s  ",
                  val_to_str_const(rtcp_psfb_fmt, rtcp_psfb_fmt_summary_vals, "Unknown"));

    offset++;

    /* Packet type, 8 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    /* Packet length in 32 bit words MINUS one, 16 bits */
    num_fci = (tvb_get_ntohs(tvb, offset) - 2);
    offset  = dissect_rtcp_length_field(rtcp_tree, tvb, offset);

    /* SSRC of packet sender, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* SSRC of media source, 32 bits */
    ti = proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    /* Decode if it is NONE or ANY and add to line */
    proto_item_append_text(ti," %s", val_to_str_const(tvb_get_ntohl(tvb,offset), rtcp_ssrc_values, ""));
    offset += 4;

    /* Check if we have a type specific dissector,
     * if we do, just return from here
     */
    if (packet_length > 12) {
      tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset, packet_length - 12);

      if (dissector_try_uint (rtcp_psfb_dissector_table, rtcp_psfb_fmt,
              subtvb, pinfo, rtcp_tree))
        return base_offset + packet_length;
    }

    /* Feedback Control Information (FCI) */
    counter  = 0;
    read_fci = 0;
    while ( read_fci < num_fci ) {
        switch (rtcp_psfb_fmt)
        {
        case 1:     /* Picture Loss Indications (PLI) */
        {
            /* Handle MS PLI Extension */
            fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 12, ett_ssrc, NULL, "MS PLI");
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_pli_ms_request_id, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset += 2;
            /* 2 reserved bytes */
            offset += 2;
            for (i = 0 ; i < 8 ; i++)
            {
                ti = proto_tree_add_item( fci_tree, hf_rtcp_psfb_pli_ms_sfr, tvb, offset, 1, ENC_BIG_ENDIAN );
                proto_item_prepend_text(ti,"PRID %d - %d ",
                        i * 8, (i+1) * 8 - 1);
                offset++;
            }
            read_fci += 3;
            break;
        }
        case 2:     /* Slice Loss Indication (SLI) */
            /* Handle SLI */
            fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 4, ett_ssrc, NULL, "SLI %u", ++counter );
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_sli_first,      tvb, offset, 4, ENC_BIG_ENDIAN );
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_sli_number,     tvb, offset, 4, ENC_BIG_ENDIAN );
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_sli_picture_id, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            read_fci++;
            break;
        case 4:     /* Handle FIR */
        {
            /* Create a new subtree for a length of 8 bytes */
            fci_tree  = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 8, ett_ssrc, NULL, "FIR %u", ++counter );
            /* SSRC 32 bit*/
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_fir_fci_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset   += 4;
            /* Command Sequence Number 8 bit*/
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_fir_fci_csn, tvb, offset, 1, ENC_BIG_ENDIAN );
            /*proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );*/
            offset   += 1;
            /* Reserved 24 bit*/
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_fir_fci_reserved, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset   += 3;
            read_fci += 2;
            break;
        }
        case 15:
        {
            /*
             * Handle Application Layer Feedback messages.
             *
             * XXX - how do we determine how to interpret these?
             *
             * REMB (Receiver Estimated Maximum Bitrate) is, according
             * to section 2.3 "Signaling of use of this extension" of
             * http://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03,
             * indicated as an SDP option when the session is set up.
             *
             * MS-RTP is, according to MS-RTP and according to MS-SDPEXT
             * section 3.1.5.30.2 "a=rtcp-fb attribute", indicated as an
             * SDP option when the session is set up.
             *
             * Those would work if we have the SDP setup traffic and parse
             * the a=rtcp-fb attribute, but if we don't, we'd need to have
             * the user specify it somehow.
             */
#if 0
            /* Handle REMB (Receiver Estimated Maximum Bitrate) - http://tools.ietf.org/html/draft-alvestrand-rmcat-remb-00 */
            offset = dissect_rtcp_psfb_remb(tvb, offset, rtcp_tree, top_item, counter, &read_fci);
#else
            /* Handle MS Application Layer Feedback Messages - MS-RTP */
            offset = dissect_rtcp_asfb_ms(tvb, offset, rtcp_tree, pinfo);
            read_fci = num_fci;     /* Consume all the bytes. */
#endif
            break;
        }
        case 3:             /* Reference Picture Selection Indication (RPSI) - Not decoded*/
        default:
            /* Consume anything left so it doesn't make an infinite loop. */
            read_fci = num_fci;
            break;
        }
    }

    /* Append undecoded FCI information */
    if ((packet_length - (offset - base_offset)) > 0) {
        proto_tree_add_item( rtcp_tree, hf_rtcp_fci, tvb, offset, packet_length - (offset - base_offset), ENC_NA );
        offset = base_offset + packet_length;
    }
    return offset;
}

static int
dissect_rtcp_fir( tvbuff_t *tvb, int offset, proto_tree *tree )
{
    /* Packet type = FIR (H261) */
    proto_tree_add_item( tree, hf_rtcp_rc, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;
    /* Packet type, 8 bits  = APP */
    proto_tree_add_item( tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    /* Packet length in 32 bit words minus one */
    offset = dissect_rtcp_length_field(tree, tvb, offset);

    /* SSRC  */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    return offset;
}

static int
dissect_rtcp_app( tvbuff_t *tvb,packet_info *pinfo, int offset, proto_tree *tree,
                  unsigned int padding, unsigned int packet_len, guint rtcp_subtype,
                  guint32 app_length )
{
    unsigned int  counter;
    char          ascii_name[5];
    guint         sdes_type;
    guint         item_len;
    proto_tree   *PoC1_tree;
    proto_item   *PoC1_item;

    /* XXX If more application types are to be dissected it may be useful to use a table like in packet-sip.c */
    static const char poc1_app_name_str[] = "PoC1";
    static const char mux_app_name_str[] = "3GPP";


    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset     += 4;
    packet_len -= 4;

    /* Application Name (ASCII) */
    for( counter = 0; counter < 4; counter++ )
        ascii_name[ counter ] = tvb_get_guint8( tvb, offset + counter );
    /* g_strlcpy( ascii_name, pd + offset, 4 ); */
    ascii_name[4] = '\0';
    proto_tree_add_string( tree, hf_rtcp_name_ascii, tvb, offset, 4,
                           ascii_name );

    /* See if we can handle this application type */
    if ( g_ascii_strncasecmp(ascii_name, poc1_app_name_str,4 ) == 0 )
    {
        /* PoC1 Application */
        guint8      t2timer_code, participants_code;
        proto_item *item;
        item            = proto_tree_add_uint( tree, hf_rtcp_app_poc1_subtype, tvb, offset - 8, 1, rtcp_subtype );
        PROTO_ITEM_SET_GENERATED(item);
        col_add_fstr(pinfo->cinfo, COL_INFO,"(%s) %s",ascii_name,
                     val_to_str(rtcp_subtype,rtcp_app_poc1_floor_cnt_type_vals,"unknown (%u)") );
        offset         += 4;
        packet_len     -= 4;
        if ( packet_len == 0 )
            return offset;      /* No more data */
        /* Applications specific data */
        if ( padding ) {
            /* If there's padding present, we have to remove that from the data part
            * The last octet of the packet contains the length of the padding
            */
            packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
        }
        /* Create a subtree for the PoC1 Application items; we don't yet know
           the length */

        /* Top-level poc tree */
        PoC1_item = proto_tree_add_item(tree, hf_rtcp_app_poc1, tvb, offset, packet_len, ENC_NA);
        PoC1_tree = proto_item_add_subtree( PoC1_item, ett_PoC1 );

        /* Dissect it according to its subtype */
        switch ( rtcp_subtype ) {

            case TBCP_BURST_REQUEST:
                {
                guint8  code;
                guint16 priority;

                /* Both items here are optional */
                if (tvb_reported_length_remaining( tvb, offset) == 0)
                {
                    return offset;
                }

                /* Look for a code in the first byte */
                code        = tvb_get_guint8(tvb, offset);
                offset     += 1;
                packet_len -= 1;

                /* Priority (optional) */
                if (code == 102)
                {
                    item_len    = tvb_get_guint8(tvb, offset);
                    offset     += 1;
                    packet_len -= 1;
                    if (item_len != 2) /* SHALL be 2 */
                        return offset;

                    priority    = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_priority, tvb, offset, 2, ENC_BIG_ENDIAN );
                    offset     += 2;
                    packet_len -= 2;

                    col_append_fstr(pinfo->cinfo, COL_INFO,
                                   " \"%s\"",
                                   val_to_str_const(priority,
                                                    rtcp_app_poc1_qsresp_priority_vals,
                                                    "Unknown"));

                    /* Look for (optional) next code */
                    if (tvb_reported_length_remaining( tvb, offset) == 0)
                    {
                        return offset;
                    }
                    code        = tvb_get_guint8(tvb, offset);
                    offset     += 1;
                    packet_len -= 1;

                }

                /* Request timestamp (optional) */
                if (code == 103)
                {
                    const gchar *buff;

                    item_len    = tvb_get_guint8(tvb, offset);
                    offset     += 1;
                    packet_len -= 1;
                    if (item_len != 8) /* SHALL be 8 */
                        return offset;

                    proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_request_ts,
                                        tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
                    buff = tvb_ntp_fmt_ts(tvb, offset);

                    offset     += 8;
                    packet_len -= 8;

                    col_append_fstr(pinfo->cinfo, COL_INFO, " ts=\"%s\"", buff);
                }
                }
                break;

            case TBCP_BURST_GRANTED:
                {
                proto_item *ti;
                guint16     stop_talking_time;
                guint16     participants;

                /* Stop talking timer (now mandatory) */
                t2timer_code  = tvb_get_guint8(tvb, offset);
                offset       += 1;
                packet_len   -= 1;
                if (t2timer_code != 101) /* SHALL be 101 */
                    return offset;

                item_len    = tvb_get_guint8(tvb, offset);
                offset     += 1;
                packet_len -= 1;
                if (item_len != 2) /* SHALL be 2 */
                    return offset;

                stop_talking_time = tvb_get_ntohs(tvb, offset);
                ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_stt, tvb, offset, 2, ENC_BIG_ENDIAN );

                /* Append text with meanings of value */
                switch (stop_talking_time)
                {
                    case 0:
                        proto_item_append_text(ti, " unknown");
                        break;
                    case 65535:
                        proto_item_append_text(ti, " infinity");
                        break;
                    default:
                        proto_item_append_text(ti, " seconds");
                        break;
                }
                offset     += item_len;
                packet_len -= item_len;

                col_append_fstr(pinfo->cinfo, COL_INFO, " stop-talking-time=%u",
                                stop_talking_time);

                /* Participants (optional) */
                if (tvb_reported_length_remaining( tvb, offset) == 0)
                {
                    return offset;
                }
                participants_code  = tvb_get_guint8(tvb, offset);
                offset            += 1;
                packet_len        -= 1;
                if (participants_code != 100) /* SHALL be 100 */
                    return offset;

                item_len    = tvb_get_guint8(tvb, offset);
                offset     += 1;
                packet_len -= 1;
                if (item_len != 2) /* SHALL be 2 */
                    return offset;

                participants = tvb_get_ntohs(tvb, offset);
                ti           = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_partic, tvb, offset, 2, ENC_BIG_ENDIAN );

                /* Append text with meanings of extreme values */
                switch (participants)
                {
                    case 0:
                        proto_item_append_text(ti, " (not known)");
                        break;
                    case 65535:
                        proto_item_append_text(ti, " (or more)");
                        break;
                    default:
                        break;
                }
                offset     += item_len;
                packet_len -= item_len;

                col_append_fstr(pinfo->cinfo, COL_INFO, " participants=%u",
                                participants);
                }
                break;

            case TBCP_BURST_TAKEN_EXPECT_NO_REPLY:
            case TBCP_BURST_TAKEN_EXPECT_REPLY:
                {
                guint16 participants;
                proto_item *ti;

                /* SSRC of PoC client */
                proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ssrc_granted, tvb, offset, 4, ENC_BIG_ENDIAN );
                offset     += 4;
                packet_len -= 4;

                /* SDES type (must be CNAME) */
                sdes_type = tvb_get_guint8( tvb, offset );
                proto_tree_add_item( PoC1_tree, hf_rtcp_sdes_type, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                packet_len--;
                if (sdes_type != RTCP_SDES_CNAME)
                {
                    return offset;
                }

                /* SIP URI */
                item_len = tvb_get_guint8( tvb, offset );
                /* Item len of 1 because it's an FT_UINT_STRING... */
                proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_sip_uri,
                                    tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN );
                offset++;

                col_append_fstr(pinfo->cinfo, COL_INFO, " CNAME=\"%s\"",
                                tvb_get_string_enc(wmem_packet_scope(), tvb, offset, item_len, ENC_ASCII));

                offset     += item_len;
                packet_len  = packet_len - item_len - 1;

                /* In the application dependent data, the TBCP Talk Burst Taken message SHALL carry
                 * a SSRC field and SDES items, CNAME and MAY carry SDES item NAME to identify the
                 * PoC Client that has been granted permission to send a Talk Burst.
                 *
                 * The SDES item NAME SHALL be included if it is known by the PoC Server.
                 * Therefore the length of the packet will vary depending on number of SDES items
                 * and the size of the SDES items.
                 */
                if ( packet_len == 0 )
                    return offset;

                /* SDES type (must be NAME if present) */
                sdes_type = tvb_get_guint8( tvb, offset );
                if (sdes_type == RTCP_SDES_NAME) {
                    proto_tree_add_item( PoC1_tree, hf_rtcp_sdes_type, tvb, offset, 1, ENC_BIG_ENDIAN );
                    offset++;
                    packet_len--;

                    /* Display name */
                    item_len = tvb_get_guint8( tvb, offset );
                    /* Item len of 1 because it's an FT_UINT_STRING... */
                    proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_disp_name,
                                        tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
                    offset++;

                    col_append_fstr(pinfo->cinfo, COL_INFO, " DISPLAY-NAME=\"%s\"",
                                    tvb_get_string_enc(wmem_packet_scope(), tvb, offset, item_len, ENC_ASCII));

                    offset     += item_len;
                    packet_len  = packet_len - item_len - 1;

                    if (packet_len == 0) {
                        return offset;
                    }

                    /* Move onto next 4-byte boundary */
                    if (offset % 4) {
                        int padding2  = (4-(offset%4));
                        offset       += padding2;
                        packet_len   -= padding2;
                    }
                }

                /* Participants (optional) */
                if (tvb_reported_length_remaining( tvb, offset) == 0) {
                    return offset;
                }
                participants_code  = tvb_get_guint8(tvb, offset);
                offset            += 1;
                packet_len        -= 1;
                if (participants_code != 100) { /* SHALL be 100 */
                    return offset;
                }
                item_len    = tvb_get_guint8(tvb, offset);
                offset     += 1;
                packet_len -= 1;
                if (item_len != 2) { /* SHALL be 2 */
                    return offset;
                }

                participants = tvb_get_ntohs(tvb, offset);
                ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_partic, tvb, offset, 2, ENC_BIG_ENDIAN );

                /* Append text with meanings of extreme values */
                switch (participants) {
                    case 0:
                        proto_item_append_text(ti, " (not known)");
                        break;
                    case 65535:
                        proto_item_append_text(ti, " (or more)");
                        break;
                    default:
                        break;
                }

                col_append_fstr(pinfo->cinfo, COL_INFO, " Participants=%u",
                                participants);
                offset     += item_len;
                packet_len -= item_len;
                }
                break;

            case TBCP_BURST_DENY:
                {
                guint8 reason_code;

                /* Reason code */
                reason_code = tvb_get_guint8(tvb, offset);
                proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason_code1, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                packet_len--;

                col_append_fstr(pinfo->cinfo, COL_INFO, " reason-code=\"%s\"",
                                val_to_str_const(reason_code,
                                                 rtcp_app_poc1_reason_code1_vals,
                                                 "Unknown"));

                /* Reason phrase */
                item_len = tvb_get_guint8( tvb, offset );
                if ( item_len != 0 )
                    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason1_phrase, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN );

                offset     += (item_len+1);
                packet_len -= (item_len+1);
                }
                break;

            case TBCP_BURST_RELEASE:
                {
                guint16 last_seq_no;
                /*guint16 ignore_last_seq_no;*/

                /* Sequence number of last RTP packet in burst */
                proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_last_pkt_seq_no, tvb, offset, 2, ENC_BIG_ENDIAN );
                last_seq_no = tvb_get_ntohs(tvb, offset);

                /* Bit 16 is ignore flag */
                offset += 2;
                proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ignore_seq_no, tvb, offset, 2, ENC_BIG_ENDIAN );
                /*ignore_last_seq_no = (tvb_get_ntohs(tvb, offset) & 0x8000);*/

                                /* XXX: Was the intention to also show the "ignore_last_seq_no' flag in COL_INFO ? */
                col_append_fstr(pinfo->cinfo, COL_INFO, " last_rtp_seq_no=%u",
                                last_seq_no);

                /* 15 bits of padding follows */

                offset     += 2;
                packet_len -= 4;
                }
                break;

            case TBCP_BURST_IDLE:
                break;

            case TBCP_BURST_REVOKE:
                {
                    /* Reason code */
                    guint16 reason_code = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason_code2, tvb, offset, 2, ENC_BIG_ENDIAN );

                    /* The meaning of this field depends upon the reason code... */
                    switch (reason_code)
                    {
                        case 1: /* Only one user */
                            /* No additional info */
                            break;
                        case 2: /* Talk burst too long */
                            /* Additional info is 16 bits with time (in seconds) client can request */
                            proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_new_time_request, tvb, offset + 2, 2, ENC_BIG_ENDIAN );
                            break;
                        case 3: /* No permission */
                            /* No additional info */
                            break;
                        case 4: /* Pre-empted */
                            /* No additional info */
                            break;
                    }

                    col_append_fstr(pinfo->cinfo, COL_INFO, " reason-code=\"%s\"",
                                    val_to_str_const(reason_code,
                                                     rtcp_app_poc1_reason_code2_vals,
                                                     "Unknown"));
                    offset     += 4;
                    packet_len -= 4;
                }
                break;

            case TBCP_BURST_ACKNOWLEDGMENT:
                {
                guint8 subtype;

                /* Code of message being acknowledged */
                subtype = (tvb_get_guint8(tvb, offset) & 0xf8) >> 3;
                proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_ack_subtype, tvb, offset, 1, ENC_BIG_ENDIAN );

                col_append_fstr(pinfo->cinfo, COL_INFO, " (for %s)",
                                val_to_str_const(subtype,
                                                 rtcp_app_poc1_floor_cnt_type_vals,
                                                 "Unknown"));

                /* Reason code only seen if subtype was Connect */
                if (subtype == TBCP_CONNECT)
                {
                    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_ack_reason_code, tvb, offset, 2, ENC_BIG_ENDIAN );
                }

                /* 16 bits of padding follow */
                offset     += 4;
                packet_len -= 4;
                }
                break;

            case TBCP_QUEUE_STATUS_REQUEST:
                break;

            case TBCP_QUEUE_STATUS_RESPONSE:
                {
                guint16     position;
                proto_item *ti;

                /* Priority */
                proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_qsresp_priority, tvb, offset, 1, ENC_BIG_ENDIAN );

                /* Queue position. 65535 indicates 'position not available' */
                position = tvb_get_ntohs(tvb, offset+1);
                ti = proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_qsresp_position, tvb, offset+1, 2, ENC_BIG_ENDIAN );
                if (position == 0)
                {
                    proto_item_append_text(ti, " (client is un-queued)");
                }
                if (position == 65535)
                {
                    proto_item_append_text(ti, " (position not available)");
                }

                col_append_fstr(pinfo->cinfo, COL_INFO, " position=%u", position);

                /* 1 bytes of padding  follows */

                offset     += 4;
                packet_len -= 4;
                }
                break;

            case TBCP_DISCONNECT:
                break;

            case TBCP_CONNECT:
                {
                proto_item   *content;
                proto_tree   *content_tree = proto_tree_add_subtree(PoC1_tree, tvb, offset, 2,
                                            ett_poc1_conn_contents, &content, "SDES item content");
                gboolean      contents[5];
                unsigned int  i;
                guint8        items_set = 0;

                guint16 items_field = tvb_get_ntohs(tvb, offset );

                /* Dissect each defined bit flag in the SDES item content */
                for ( i = 0; i < 5; i++)
                {
                    proto_tree_add_item( content_tree, hf_rtcp_app_poc1_conn_content[i], tvb, offset, 2, ENC_BIG_ENDIAN );
                    contents[i] = items_field & (1 << (15-i));
                    if (contents[i]) ++items_set;
                }

                /* Show how many flags were set */
                proto_item_append_text(content, " (%u items)", items_set);

                /* Session type */
                proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_session_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN );

                /* Additional indications */
                proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_add_ind_mao, tvb, offset + 3, 1, ENC_BIG_ENDIAN );

                offset     += 4;
                packet_len -= 4;

                /* One SDES item for every set flag in contents array */
                for ( i = 0; i < array_length(contents); ++i ) {
                    if ( contents[i] ) {
                        guint /*sdes_type2,*/ sdes_len2;
                        /* (sdes_type2 not currently used...).  Could complain if type
                           doesn't match expected for item... */
                        /*sdes_type2 = tvb_get_guint8( tvb, offset );*/
                        offset += 1;
                        sdes_len2  = tvb_get_guint8( tvb, offset );

                        /* Add SDES field indicated as present */
                        proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_sdes_items[i], tvb, offset, 1, ENC_BIG_ENDIAN );

                        /* Move past field */
                        offset += sdes_len2 + 1;
                        packet_len -= (sdes_len2 + 2);
                    }
                }
                break;
            }

            default:
                break;
        }
        if ((int)(offset + packet_len) >= offset)
            offset += packet_len;
        return offset;
    }
    else if ( g_ascii_strncasecmp(ascii_name, mux_app_name_str,4 ) == 0 )
    {
        /* 3GPP Nb protocol extension (3GPP 29.414) for RTP Multiplexing */
        col_append_fstr(pinfo->cinfo, COL_INFO,"( %s ) subtype=%u",ascii_name, rtcp_subtype);
        offset     += 4;
        packet_len -= 4;
        /* Applications specific data */
        if ( padding ) {
            /* If there's padding present, we have to remove that from the data part
            * The last octet of the packet contains the length of the padding
            */
            packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
        }
        if (packet_len == 4)
        {
            guint16 local_port = 0;

            proto_item *mux_item = proto_tree_add_item(tree, hf_rtcp_app_mux, tvb, offset, packet_len, ENC_NA);
            proto_tree *mux_tree = proto_item_add_subtree( mux_item, ett_mux );
            proto_tree_add_item( mux_tree, hf_rtcp_app_mux_mux, tvb, offset, 1, ENC_BIG_ENDIAN );
            proto_tree_add_item( mux_tree, hf_rtcp_app_mux_cp, tvb, offset, 1, ENC_BIG_ENDIAN );
            proto_tree_add_item( mux_tree, hf_rtcp_app_mux_selection, tvb, offset, 1, ENC_BIG_ENDIAN );
            local_port = tvb_get_ntohs( tvb, offset+2 );
            proto_tree_add_uint( mux_tree, hf_rtcp_app_mux_localmuxport, tvb, offset+2, 2, local_port*2 );
        }
        else
        {
            /* fall back to just showing the data if it's the wrong length */
            proto_tree_add_item( tree, hf_rtcp_app_data, tvb, offset, packet_len, ENC_NA );
        }
        if ((int)(offset + packet_len) >= offset)
            offset += packet_len;
        return offset;
    }
    else
    {
        tvbuff_t *next_tvb;     /* tvb to pass to subdissector */
        /* tvb         == Pass the entire APP payload so the subdissector can have access to the
         * entire data set
         */
        next_tvb        = tvb_new_subset_length(tvb, offset-8, app_length+4);
        /* look for registered sub-dissectors */
        if (dissector_try_string(rtcp_dissector_table, ascii_name, next_tvb, pinfo, tree, NULL)) {
            /* found subdissector - return tvb_reported_length */
            offset     += 4;
            packet_len -= 4;
            if ( padding ) {
                /* If there's padding present, we have to remove that from the data part
                * The last octet of the packet contains the length of the padding
                */
                packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
            }
            if ((int)(offset + packet_len) >= offset)
                offset += packet_len;
            return offset;
        }
        else
        {
            /* Unhandled application type, just show app name and raw data */
            col_append_fstr(pinfo->cinfo, COL_INFO,"( %s ) subtype=%u",ascii_name, rtcp_subtype);
            offset     += 4;
            packet_len -= 4;
            /* Applications specific data */
            if ( padding ) {
                /* If there's padding present, we have to remove that from the data part
                * The last octet of the packet contains the length of the padding
                */
                packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
            }
            proto_tree_add_item( tree, hf_rtcp_app_data, tvb, offset, packet_len, ENC_NA );
            if ((int)(offset + packet_len) >= offset)
                offset += packet_len;
            return offset;
        }
    }

}


static int
dissect_rtcp_bye( tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
    unsigned int count )
{
    unsigned int chunk;
    unsigned int reason_length = 0;
    gint         reason_offset = 0;

    chunk = 1;
    while ( chunk <= count ) {
        /* source identifier, 32 bits */
        proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        chunk++;
    }

    if ( tvb_reported_length_remaining( tvb, offset ) > 0 ) {
        /* Bye reason consists of an 8 bit length l and a string with length l */
        reason_length = tvb_get_guint8( tvb, offset );
        proto_tree_add_item( tree, hf_rtcp_sdes_length, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;

        reason_offset = offset;
        proto_tree_add_item( tree, hf_rtcp_sdes_text, tvb, offset, reason_length, ENC_ASCII|ENC_NA);
        offset += reason_length;
    }

    /* BYE packet padded out if string didn't fit in previous word */
    if (offset % 4)
    {
        gint pad_size = (4 - (offset % 4));
        int i;

        /* Check padding */
        for (i = 0; i < pad_size; i++)
        {
            if ((!(tvb_offset_exists(tvb, offset + i))) ||
                (tvb_get_guint8(tvb, offset + i) != 0))
            {
                proto_tree_add_expert(tree, pinfo, &ei_rtcp_bye_reason_not_padded, tvb, reason_offset, reason_length);
            }
        }

        offset += pad_size;
    }

    return offset;
}

static int
dissect_rtcp_sdes( tvbuff_t *tvb, int offset, proto_tree *tree,
    unsigned int count )
{
    unsigned int  chunk;
    proto_item   *sdes_item;
    proto_tree   *sdes_tree;
    proto_tree   *sdes_item_tree;
    proto_item   *ti;
    int           start_offset;
    int           items_start_offset;
    guint32       ssrc;
    unsigned int  item_len;
    unsigned int  sdes_type;
    unsigned int  prefix_len;

    chunk = 1;
    while ( chunk <= count ) {
        /* Create a subtree for this chunk; we don't yet know
           the length. */
        start_offset = offset;

        ssrc = tvb_get_ntohl( tvb, offset );
        sdes_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
            ett_sdes, &sdes_item, "Chunk %u, SSRC/CSRC 0x%X", chunk, ssrc);

        /* SSRC_n source identifier, 32 bits */
        proto_tree_add_item( sdes_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        /* Create a subtree for the SDES items; we don't yet know
           the length */
        items_start_offset = offset;
        sdes_item_tree = proto_tree_add_subtree(sdes_tree, tvb, offset, -1,
            ett_sdes_item, &ti, "SDES items" );

        /*
         * Not every message is ended with "null" bytes, so check for
         * end of frame as well.
         */
        while ( tvb_reported_length_remaining( tvb, offset ) > 0 ) {
            /* ID, 8 bits */
            sdes_type = tvb_get_guint8( tvb, offset );
            proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_type, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            if ( sdes_type == RTCP_SDES_END ) {
                /* End of list */
                break;
            }

            /* Item length, 8 bits */
            item_len = tvb_get_guint8( tvb, offset );
            proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_length, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            if ( item_len != 0 ) {
                if ( sdes_type == RTCP_SDES_PRIV ) {
                    /* PRIV adds two items between the
                     * SDES length and value - an 8 bit
                     * length giving the length of a
                     * "prefix string", and the string.
                     */
                    prefix_len = tvb_get_guint8( tvb, offset );
                    if ( prefix_len + 1 > item_len ) {
                        proto_tree_add_uint_format_value( sdes_item_tree,
                            hf_rtcp_sdes_prefix_len, tvb,
                            offset, 1, prefix_len,
                            "%u (bogus, must be <= %u)",
                            prefix_len, item_len - 1);
                        offset += item_len;
                        continue;
                    }
                    proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_prefix_len, tvb, offset, 1, ENC_BIG_ENDIAN );
                    offset++;

                    proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_prefix_string, tvb, offset, prefix_len, ENC_ASCII|ENC_NA );
                    offset   += prefix_len;
                    item_len -= prefix_len +1;
                    if ( item_len == 0 )
                        continue;
                }
                proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_text, tvb, offset, item_len, ENC_ASCII|ENC_NA );
                offset += item_len;
            }
        }

        /* Set the length of the items subtree. */
        proto_item_set_len(ti, offset - items_start_offset);

        /* 32 bits = 4 bytes, so.....
         * If offset % 4 != 0, we divide offset by 4, add one and then
         * multiply by 4 again to reach the boundary
         */
        if ( offset % 4 != 0 )
            offset = ((offset / 4) + 1 ) * 4;

        /* Set the length of this chunk. */
        proto_item_set_len(sdes_item, offset - start_offset);

        chunk++;
    }

    return offset;
}

static void parse_xr_type_specific_field(tvbuff_t *tvb, gint offset, guint block_type,
                                         proto_tree *tree, guint8 *thinning)
{
    static const int * flags[] = {
        &hf_rtcp_xr_stats_loss_flag,
        &hf_rtcp_xr_stats_dup_flag,
        &hf_rtcp_xr_stats_jitter_flag,
        &hf_rtcp_xr_stats_ttl,
        NULL
    };

    switch (block_type) {
        case RTCP_XR_LOSS_RLE:
        case RTCP_XR_DUP_RLE:
        case RTCP_XR_PKT_RXTIMES:
            *thinning = tvb_get_guint8(tvb, offset) & 0x0F;
            proto_tree_add_item(tree, hf_rtcp_xr_thinning, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        case RTCP_XR_STATS_SUMRY:
            proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);
            break;

        default:
            proto_tree_add_item(tree, hf_rtcp_xr_block_specific, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
    }
}

static gboolean validate_xr_block_length(tvbuff_t *tvb, packet_info *pinfo, int offset, guint block_type, guint block_len, proto_tree *tree)
{
    proto_item *ti;

    ti = proto_tree_add_uint(tree, hf_rtcp_xr_block_length, tvb, offset, 2, block_len);
    switch (block_type) {
        case RTCP_XR_REF_TIME:
            if (block_len != 2)
                expert_add_info_format(pinfo, ti, &ei_rtcp_xr_block_length_bad, "Invalid block length, should be 2");
            return FALSE;

        case RTCP_XR_STATS_SUMRY:
            if (block_len != 9)
                expert_add_info_format(pinfo, ti, &ei_rtcp_xr_block_length_bad, "Invalid block length, should be 9");
            return FALSE;

        case RTCP_XR_VOIP_METRCS:
        case RTCP_XR_BT_XNQ:
            if (block_len != 8)
                expert_add_info_format(pinfo, ti, &ei_rtcp_xr_block_length_bad, "Invalid block length, should be 8");
            return FALSE;

        case RTCP_XR_IDMS:
            if (block_len != 7)
                expert_add_info_format(pinfo, ti, &ei_rtcp_xr_block_length_bad, "Invalid block length, should be 7");
            return FALSE;

        default:
            break;
    }
    return TRUE;
}

static int
dissect_rtcp_xr(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, gint packet_len)
{
    guint       block_num;

    /* Packet length should at least be 4 */
    if (packet_len < 4) {
        proto_tree_add_expert(tree, pinfo, &ei_rtcp_missing_sender_ssrc, tvb, offset, packet_len);
        return offset + packet_len;
    }

    /* SSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset     += 4;
    packet_len -= 4;

    for( block_num = 1; packet_len > 0; block_num++) {
        guint block_type     = tvb_get_guint8(tvb, offset), block_length = 0;
        gint  content_length = 0;
        guint8 thinning = 0;
        /*gboolean valid = TRUE;*/

        /* Create a subtree for this block, don't know the length yet*/
        proto_item *block;
        proto_tree *xr_block_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_xr_block, &block, "Block %u", block_num);
        proto_tree *content_tree;

        proto_tree_add_item(xr_block_tree, hf_rtcp_xr_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (packet_len >= 2) {
            parse_xr_type_specific_field(tvb, offset + 1, block_type, xr_block_tree, &thinning);
            if (packet_len >= 4) {
                block_length = tvb_get_ntohs(tvb, offset + 2);
                /* XXX: What if FALSE return from the following ?? */
                /*valid =*/ validate_xr_block_length(tvb, pinfo, offset + 2, block_type, block_length, xr_block_tree);
            }
        } else {
            expert_add_info(pinfo, block, &ei_rtcp_missing_block_header);
            return offset + packet_len;
        }

        content_length = block_length * 4;
        proto_item_set_len(block, content_length + 4);

        if (content_length > packet_len) {
            expert_add_info(pinfo, block, &ei_rtcp_block_length);
        }

        offset     += 4;
        packet_len -= 4;

        content_tree = proto_tree_add_subtree(xr_block_tree, tvb, offset, content_length, ett_xr_block_contents, NULL, "Contents");

        switch (block_type) {
        case RTCP_XR_VOIP_METRCS: {
            guint fraction_rate;

            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Loss Rate */
            fraction_rate = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format_value(content_tree, hf_rtcp_ssrc_fraction, tvb, offset, 1,
                                       fraction_rate, "%u / 256", fraction_rate);
            offset++;

            /* Discard Rate */
            fraction_rate = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format_value(content_tree, hf_rtcp_ssrc_discarded, tvb, offset, 1,
                                       fraction_rate, "%u / 256", fraction_rate);
            offset++;

            /* Burst Density */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_burst_density, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Gap Density */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gap_density, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Burst Duration */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_burst_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Gap Duration */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gap_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Round Trip Delay */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rtdelay, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* End System Delay */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_esdelay, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Signal Level */
            if (tvb_get_guint8(tvb, offset) == 0x7f)
                proto_tree_add_int_format_value(content_tree, hf_rtcp_xr_voip_metrics_siglevel, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_siglevel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Noise Level */
            if (tvb_get_guint8(tvb, offset) == 0x7f)
                proto_tree_add_int_format_value(content_tree, hf_rtcp_xr_voip_metrics_noiselevel, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_noiselevel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* RERL */
            if (tvb_get_guint8(tvb, offset) == 0x7f)
                proto_tree_add_uint_format_value(content_tree, hf_rtcp_xr_voip_metrics_rerl, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rerl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* GMin */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gmin, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* R factor */
            if (tvb_get_guint8(tvb, offset) == 0x7f)
                proto_tree_add_uint_format_value(content_tree, hf_rtcp_xr_voip_metrics_rfactor, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rfactor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* external R Factor */
            if (tvb_get_guint8(tvb, offset) == 0x7f)
                proto_tree_add_uint_format_value(content_tree, hf_rtcp_xr_voip_metrics_extrfactor, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_extrfactor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* MOS LQ */
            if (tvb_get_guint8(tvb, offset) == 0x7f)
                proto_tree_add_float_format_value(content_tree, hf_rtcp_xr_voip_metrics_moslq, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_float(content_tree, hf_rtcp_xr_voip_metrics_moslq, tvb, offset, 1,
                                 (float) (tvb_get_guint8(tvb, offset) / 10.0));
            offset++;

            /* MOS CQ */
            if (tvb_get_guint8(tvb, offset) == 0x7f)
                proto_tree_add_float_format_value(content_tree, hf_rtcp_xr_voip_metrics_moscq, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_float(content_tree, hf_rtcp_xr_voip_metrics_moscq, tvb, offset, 1,
                                     (float) (tvb_get_guint8(tvb, offset) / 10.0));
            offset++;

            /* PLC, JB Adaptive, JB Rate */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_plc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbadaptive, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbrate, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 2; /* skip over reseved bit */

            /* JB Nominal */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbnominal, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* JB Max */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbmax, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* JB Abs max */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbabsmax, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            break;
        }

        case RTCP_XR_STATS_SUMRY: {
            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Begin Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Lost Pkts */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_lost, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Dup Pkts */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_dups, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Min Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_minjitter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Max Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_maxjitter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Mean Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_meanjitter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Dev Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_devjitter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Min TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_minttl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset ++;

            /* Max TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_maxttl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset ++;

            /* Mean TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_meanttl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset ++;

            /* Dev TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_devttl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset ++;

            break;
        }

        case RTCP_XR_REF_TIME: {
            proto_tree_add_item(content_tree, hf_rtcp_xr_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            break;
        }

        case RTCP_XR_DLRR: {
            /* Each report block is 12 bytes */
            gint sources = content_length / 12;
            gint counter = 0;
            for(counter = 0; counter < sources; counter++) {
                /* Create a new subtree for a length of 12 bytes */
                proto_tree *ssrc_tree = proto_tree_add_subtree_format(content_tree, tvb, offset, 12, ett_xr_ssrc, NULL, "Source %u", counter + 1);

                /* SSRC_n source identifier, 32 bits */
                proto_tree_add_item(ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* Last RR timestamp */
                proto_tree_add_item(ssrc_tree, hf_rtcp_xr_lrr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* Delay since last RR timestamp */
                proto_tree_add_item(ssrc_tree, hf_rtcp_xr_dlrr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

            if (content_length % 12 != 0)
                offset += content_length % 12;
            break;
        }

        case RTCP_XR_PKT_RXTIMES: {
            /* 8 bytes of fixed header */
            guint32 rcvd_time;
            gint count = 0, skip = 8;
            guint16 begin = 0;

            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Begin Seq */
            begin = tvb_get_ntohs(tvb, offset);
            /* Apply Thinning value */
            begin = (begin + ((1<<thinning)-1)) & ~((1<<thinning)-1);
            proto_tree_add_item(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            for(count = 0; skip < content_length; skip += 4, count++) {
                rcvd_time = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint_format(content_tree, hf_rtcp_xr_receipt_time_seq, tvb,
                                           offset, 4, rcvd_time, "Seq: %u, Receipt Time: %u",
                                           (begin + (count<<thinning)) % 65536, rcvd_time);
                offset += 4;
            }
            break;
        }

        case RTCP_XR_LOSS_RLE:
        case RTCP_XR_DUP_RLE: {
            /* 8 bytes of fixed header */
            gint count = 0, skip = 8;
            proto_tree *chunks_tree;

            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Begin Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* report Chunks */
            chunks_tree = proto_tree_add_subtree(content_tree, tvb, offset, content_length, ett_xr_loss_chunk, NULL, "Report Chunks");

            for(count = 1; skip < content_length; skip += 2, count++) {
                guint value = tvb_get_ntohs(tvb, offset);

                if (value == 0) {
                    proto_tree_add_none_format(chunks_tree, hf_rtcp_xr_chunk_null_terminator, tvb, offset, 2, "Chunk: %u -- Null Terminator ",
                                        count);
                } else if ( ! ( value & 0x8000 )) {
                    const gchar *run_type = (value & 0x4000) ? "1s" : "0s";
                    value &= 0x3FFF;
                    proto_tree_add_uint_format(chunks_tree, hf_rtcp_xr_chunk_length, tvb, offset, 2, value, "Chunk: %u -- Length Run %s, length: %u",
                                        count, run_type, value);
                } else {
                    proto_tree_add_uint_format(chunks_tree, hf_rtcp_xr_chunk_bit_vector, tvb, offset, 2, value &  0x7FFF,
                                        "Chunk: %u -- Bit Vector 0x%x", count, value &  0x7FFF);
                }
                offset += 2;
            }

            break;
        }
        case RTCP_XR_BT_XNQ: {                                      /* BT XNQ block as defined in RFC5093 */
            guint temp_value; /* used when checking spare bits in block type 8 */

            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_begseq, tvb, offset, 2, ENC_BIG_ENDIAN);          /* Begin Sequence number */
            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_endseq, tvb, offset+2, 2, ENC_BIG_ENDIAN);        /* End Sequence number */
            offset += 4;

            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_vmaxdiff, tvb, offset, 2, ENC_BIG_ENDIAN);        /* vmaxdiff */
            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_vrange, tvb, offset+2, 2, ENC_BIG_ENDIAN);        /* vrange */
            offset += 4;

            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_vsum, tvb, offset, 4, ENC_BIG_ENDIAN);            /* vsum */
            offset += 4;

            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_cycles, tvb, offset, 2, ENC_BIG_ENDIAN);          /* cycle count */
            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_jbevents, tvb, offset+2, 2, ENC_BIG_ENDIAN);      /* jitter buffer events */
            offset += 4;

            temp_value = tvb_get_ntohl(tvb, offset);                                                    /* tDegNet */
            if ((temp_value & 0x0ff000000) != 0)
                proto_tree_add_string(content_tree, hf_rtcp_xr_btxnq_spare, tvb, offset, 1, "Warning - spare bits not 0");
            proto_tree_add_uint(content_tree, hf_rtcp_xr_btxnq_tdegnet, tvb, offset+1, 3, temp_value & 0x0ffffff);
            offset += 4;

            temp_value = tvb_get_ntohl(tvb, offset);                                                    /* tDegJit */
            if ((temp_value & 0x0ff000000) != 0)
                proto_tree_add_string(content_tree, hf_rtcp_xr_btxnq_spare, tvb, offset, 1, "Warning - spare bits not 0");
            proto_tree_add_uint(content_tree, hf_rtcp_xr_btxnq_tdegjit, tvb, offset+1, 3, temp_value & 0x0ffffff);
            offset += 4;

            temp_value = tvb_get_ntohl(tvb, offset);                                                    /* ES */
            if ((temp_value & 0x0ff000000) != 0)
                proto_tree_add_string(content_tree, hf_rtcp_xr_btxnq_spare, tvb, offset, 1, "Warning - spare bits not 0");
            proto_tree_add_uint(content_tree, hf_rtcp_xr_btxnq_es, tvb, offset+1, 3, temp_value & 0x0ffffff);
            offset += 4;

            temp_value = tvb_get_ntohl(tvb, offset);                                                    /* SES */
            if ((temp_value & 0x0ff000000) != 0)
                proto_tree_add_string(content_tree, hf_rtcp_xr_btxnq_spare, tvb, offset, 1, "Warning - spare bits not 0");
            proto_tree_add_uint(content_tree, hf_rtcp_xr_btxnq_ses, tvb, offset+1, 3, temp_value & 0x0ffffff);
            offset += 4;

            break;
        }
        case RTCP_XR_IDMS: {
            proto_item *item;
            int         hour,min,sec,msec;
            guint32     tmp_ts;
            offset -= 3;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_spst, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=3;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_pt, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_msci, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_source_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_ntp_rcv_ts, tvb, offset, 8, ENC_BIG_ENDIAN);
            item = proto_tree_add_item(content_tree, hf_rtcp_ntp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(item);

            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_rtp_ts, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;

            tmp_ts = tvb_get_ntohl(tvb,offset);
            hour   = (  (int) ( tmp_ts >> 16 ) ) / 3600;
            min    = (( (int) ( tmp_ts >> 16 ) ) - hour * 3600) / 60;
            sec    = (( (int) ( tmp_ts >> 16 ) ) - hour * 3600 - min * 60);
            msec   = (  (int) ( tmp_ts & 0x0000FFFF ) ) / 66;
            proto_tree_add_uint_format_value(content_tree, hf_rtcp_xr_idms_ntp_pres_ts, tvb, offset, 4, tmp_ts,
                                             "%d:%02d:%02d:%03d [h:m:s:ms]", hour,min,sec,msec);
            offset+=4;
        }
            break;
        default:
            /* skip over the unknown block */
            offset += content_length;
            break;
        } /* switch (block_type) */
        packet_len -= content_length;
    } /* for (block_num = ...) */
    return offset;
}

static int
dissect_rtcp_avb( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree,
    unsigned int packet_length _U_ )
{
    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* Name (ASCII) */
    proto_tree_add_item( tree, hf_rtcp_name_ascii, tvb, offset, 4, ENC_ASCII|ENC_NA );
    offset += 4;

/*    32 bit wide
gmTimeBaseIndicator | gmIdentity - low 16 bit
gmIdentity - mid 32 bit
gmIdentity - high 32 bit
stream_id - lower 32 bit
stream_id - higher 32 bit
as_timestamp
*/
    offset += 6 * 4;

    /* RTP timestamp, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_rtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    return offset;
}

static int
dissect_rtcp_rsi( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree,
    unsigned int packet_length )
{
    proto_item *item;

    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* NTP timestamp */
    proto_tree_add_item(tree, hf_rtcp_ntp_msw, tvb, offset, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_rtcp_ntp_lsw, tvb, offset+4, 4, ENC_BIG_ENDIAN);

    item = proto_tree_add_item(tree, hf_rtcp_ntp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    offset += 8;

    /* Sub report blocks */

    return offset + (packet_length - 16);
}

static int
dissect_rtcp_token( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree,
                    unsigned int packet_len, guint rtcp_subtype _U_ )
{
    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* subtypes */

    return offset + (packet_len - 4);
}

static void
dissect_rtcp_profile_specific_extensions (packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, int offset, int remaining)
{
    gint16  extension_type;
    gint16  extension_length;
    proto_tree *pse_tree;
    proto_item *pse_item;
    proto_item *item;

    col_append_fstr(pinfo->cinfo, COL_INFO, "(");
    while (remaining)
    {
        extension_type   = tvb_get_ntohs (tvb, offset);
        extension_length = tvb_get_ntohs (tvb, offset+2);
        if (extension_length < 4) {
            extension_length = 4; /* expert info? */
        }

        pse_tree = proto_tree_add_subtree(tree, tvb, offset, extension_length, ett_pse, &pse_item, "Payload Specific Extension");
        proto_item_append_text(pse_item, " (%s)",
                val_to_str_const(extension_type, rtcp_ms_profile_extension_vals, "Unknown"));
        col_append_fstr(pinfo->cinfo, COL_INFO, "PSE:%s  ",
                      val_to_str_const(extension_type, rtcp_ms_profile_extension_vals, "Unknown"));

        proto_tree_add_item(pse_tree, hf_rtcp_profile_specific_extension_type, tvb, offset,
                2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(pse_tree, hf_rtcp_profile_specific_extension_length, tvb, offset,
                2, ENC_BIG_ENDIAN);
        offset += 2;

        switch (extension_type)
        {
        case 1:
            /* MS Estimated Bandwidth */
            item = proto_tree_add_item(pse_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
            /* Decode if it is NONE or ANY and add to line */
            proto_item_append_text(item," %s", val_to_str_const(tvb_get_ntohl (tvb, offset), rtcp_ssrc_values, ""));
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            /* Confidence level byte is optional so check length first */
            if (extension_length == 16)
            {
                proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_confidence_level, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
            }
            break;
        case 4:
            /* MS Packet Loss Notification */
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_seq_num, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            break;
        case 5:
            /* MS Video Preference */
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_frame_resolution_width, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_frame_resolution_height, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bitrate, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_frame_rate, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
            break;
        case 7:
            /* MS Policy Server Bandwidth */
            /* First 4 bytes are reserved */
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;
        case 8:
            /* MS TURN Server Bandwidth */
            /* First 4 bytes are reserved */
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;
        case 9:
            /* MS Audio Healer Metrics */
            item = proto_tree_add_item(pse_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
            /* Decode if it is NONE or ANY and add to line */
            proto_item_append_text(item," %s", val_to_str_const(tvb_get_ntohl (tvb, offset), rtcp_ssrc_values, ""));
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_concealed_frames, tvb, offset+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_stretched_frames, tvb, offset+8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_compressed_frames, tvb, offset+12, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_total_frames, tvb, offset+16, 4, ENC_BIG_ENDIAN);
            /* 2 bytes Reserved */
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_receive_quality_state, tvb, offset+22, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_fec_distance_request, tvb, offset+23, 1, ENC_BIG_ENDIAN);
            break;
        case 10:
            /* MS Receiver-side Bandwidth Limit */
            /* First 4 bytes are reserved */
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;
        case 11:
            /* MS Packet Train Packet */
            item = proto_tree_add_item(pse_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
            /* Decode if it is NONE or ANY and add to line */
            proto_item_append_text(item," %s", val_to_str_const(tvb_get_ntohl (tvb, offset), rtcp_ssrc_values, ""));
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_last_packet_train, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_packet_idx, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_packet_cnt, tvb, offset+5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_packet_train_byte_cnt, tvb, offset+6, 2, ENC_BIG_ENDIAN);
            break;
        case 12:
            /* MS Peer Info Exchange */
            item = proto_tree_add_item(pse_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
            /* Decode if it is NONE or ANY and add to line */
            proto_item_append_text(item," %s", val_to_str_const(tvb_get_ntohl (tvb, offset), rtcp_ssrc_values, ""));
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_inbound_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_outbound_bandwidth, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_no_cache, tvb, offset + 12, 1, ENC_BIG_ENDIAN);
            break;
        case 13:
            /* MS Network Congestion Notification */
            proto_tree_add_item(pse_tree, hf_rtcp_ntp_msw, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_ntp_lsw, tvb, offset+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_ntp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_congestion_info, tvb, offset + 12, 1, ENC_BIG_ENDIAN);
            break;
        case 14:
            /* MS Modality Send Bandwidth Limit */
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_modality, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* 3 bytes Reserved */
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            break;

        case 6:
            /* MS Padding */
        default:
            /* Unrecognized */
            proto_tree_add_item(pse_tree, hf_rtcp_profile_specific_extension, tvb, offset,
                    extension_length - 4, ENC_NA);
            break;
        }
        remaining -= extension_length;
        offset += extension_length - 4;
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ")  ");
}

static int
dissect_rtcp_rr( packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree,
    unsigned int count, unsigned int packet_length )
{
    unsigned int  counter;
    proto_tree   *ssrc_tree;
    proto_tree   *ssrc_sub_tree;
    proto_tree   *high_sec_tree;
    proto_item   *ti;
    guint8        rr_flt;
    int           rr_offset = offset;


    counter = 1;
    while ( counter <= count ) {
        guint32 lsr, dlsr;

        /* Create a new subtree for a length of 24 bytes */
        ssrc_tree = proto_tree_add_subtree_format(tree, tvb, offset, 24,
            ett_ssrc, NULL, "Source %u", counter );

        /* SSRC_n source identifier, 32 bits */
        proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        ssrc_sub_tree = proto_tree_add_subtree(ssrc_tree, tvb, offset, 20, ett_ssrc_item, NULL, "SSRC contents" );

        /* Fraction lost, 8bits */
        rr_flt = tvb_get_guint8( tvb, offset );
        proto_tree_add_uint_format_value( ssrc_sub_tree, hf_rtcp_ssrc_fraction, tvb,
            offset, 1, rr_flt, "%u / 256", rr_flt );
        offset++;

        /* Cumulative number of packets lost, 24 bits */
        proto_tree_add_item( ssrc_sub_tree, hf_rtcp_ssrc_cum_nr, tvb,
            offset, 3, ENC_BIG_ENDIAN );
        offset += 3;

        /* Extended highest sequence nr received, 32 bits
         * Just for the sake of it, let's add another subtree
         * because this might be a little clearer
         */
        ti = proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_ext_high_seq,
            tvb, offset, 4, ENC_BIG_ENDIAN );
        high_sec_tree = proto_item_add_subtree( ti, ett_ssrc_ext_high );
        /* Sequence number cycles */
        proto_tree_add_item( high_sec_tree, hf_rtcp_ssrc_high_cycles,
            tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;
        /* highest sequence number received */
        proto_tree_add_item( high_sec_tree, hf_rtcp_ssrc_high_seq,
            tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;

        /* Interarrival jitter */
        proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_jitter, tvb,
            offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        /* Last SR timestamp */
        lsr = tvb_get_ntohl( tvb, offset );
        proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_lsr, tvb,
                             offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        /* Delay since last SR timestamp */
        dlsr = tvb_get_ntohl( tvb, offset );
        ti = proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_dlsr, tvb,
                                  offset, 4, ENC_BIG_ENDIAN );
        proto_item_append_text(ti, " (%d milliseconds)",
                               (int)(((double)dlsr/(double)65536) * 1000.0));
        offset += 4;

        /* Do roundtrip calculation */
        if (global_rtcp_show_roundtrip_calculation)
        {
            /* Based on delay since SR was sent in other direction */
            calculate_roundtrip_delay(tvb, pinfo, ssrc_tree, lsr, dlsr);
        }

        counter++;
    }

    /* If length remaining, assume profile-specific extension bytes */
    if ((offset-rr_offset) < (int)packet_length)
    {
        dissect_rtcp_profile_specific_extensions (pinfo, tvb, tree, offset, packet_length - (offset - rr_offset));
        offset = rr_offset + packet_length;
    }

    return offset;
}

static int
dissect_rtcp_sr( packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree,
    unsigned int count, unsigned int packet_length )
{
    proto_item *item;
    guint32     ts_msw, ts_lsw;
    int         sr_offset = offset;

    /* NTP timestamp */
    ts_msw = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_rtcp_ntp_msw, tvb, offset, 4, ENC_BIG_ENDIAN);

    ts_lsw = tvb_get_ntohl(tvb, offset+4);
    proto_tree_add_item(tree, hf_rtcp_ntp_lsw, tvb, offset+4, 4, ENC_BIG_ENDIAN);

    item = proto_tree_add_item(tree, hf_rtcp_ntp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(item);
    offset += 8;

    /* RTP timestamp, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_rtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;
    /* Sender's packet count, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_sender_pkt_cnt, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;
    /* Sender's octet count, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_sender_oct_cnt, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* Record the time of this packet in the sender's conversation */
    if (global_rtcp_show_roundtrip_calculation)
    {
        /* Use middle 32 bits of 64-bit time value */
        guint32 lsr = ((ts_msw & 0x0000ffff) << 16 | (ts_lsw & 0xffff0000) >> 16);

        /* Record the time that we sent this in appropriate conversation */
        remember_outgoing_sr(pinfo, lsr);
    }

    /* The rest of the packet is equal to the RR packet */
    if ( count != 0 )
        offset = dissect_rtcp_rr( pinfo, tvb, offset, tree, count, packet_length-(offset-sr_offset) );
    else
    {
        /* If length remaining, assume profile-specific extension bytes */
        if ((offset-sr_offset) < (int)packet_length)
        {
            dissect_rtcp_profile_specific_extensions (pinfo, tvb,  tree, offset, packet_length - (offset - sr_offset));
            offset = sr_offset + packet_length;
        }
    }

    return offset;
}

/* Look for conversation info and display any setup info found */
void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Conversation and current data */
    struct _rtcp_conversation_info *p_conv_data;

    /* Use existing packet data if available */
    p_conv_data = (struct _rtcp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0);

    if (!p_conv_data)
    {
        conversation_t *p_conv;
        /* First time, get info from conversation */
        p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                   pinfo->ptype,
                                   pinfo->destport, pinfo->srcport, NO_ADDR_B);

        if (p_conv)
        {
            /* Look for data in conversation */
            struct _rtcp_conversation_info *p_conv_packet_data;
            p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);

            if (p_conv_data)
            {
                /* Save this conversation info into packet info */
                p_conv_packet_data = (struct _rtcp_conversation_info *)wmem_memdup(wmem_file_scope(),
                      p_conv_data, sizeof(struct _rtcp_conversation_info));

                p_add_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0, p_conv_packet_data);
            }
        }
    }

    /* Create setup info subtree with summary info. */
    if (p_conv_data && p_conv_data->setup_method_set)
    {
        proto_tree *rtcp_setup_tree;
        proto_item *ti =  proto_tree_add_string_format(tree, hf_rtcp_setup, tvb, 0, 0,
                                                       "",
                                                       "Stream setup by %s (frame %u)",
                                                       p_conv_data->setup_method,
                                                       p_conv_data->setup_frame_number);
        PROTO_ITEM_SET_GENERATED(ti);
        rtcp_setup_tree = proto_item_add_subtree(ti, ett_rtcp_setup);
        if (rtcp_setup_tree)
        {
            /* Add details into subtree */
            proto_item *item = proto_tree_add_uint(rtcp_setup_tree, hf_rtcp_setup_frame,
                                                   tvb, 0, 0, p_conv_data->setup_frame_number);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_string(rtcp_setup_tree, hf_rtcp_setup_method,
                                         tvb, 0, 0, p_conv_data->setup_method);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }
}


/* Update conversation data to record time that outgoing rr/sr was sent */
static void remember_outgoing_sr(packet_info *pinfo, guint32 lsr)
{
    conversation_t                 *p_conv;
    struct _rtcp_conversation_info *p_conv_data;
    struct _rtcp_conversation_info *p_packet_data;

    /* This information will be accessed when an incoming packet comes back to
       the side that sent this packet, so no use storing in the packet
       info.  However, do store the fact that we've already set this info
       before  */


    /**************************************************************************/
    /* First of all, see if we've already stored this information for this sr */

    /* Look first in packet info */
    p_packet_data = (struct _rtcp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0);
    if (p_packet_data && p_packet_data->last_received_set &&
        (p_packet_data->last_received_frame_number >= pinfo->num))
    {
        /* We already did this, OK */
        return;
    }


    /**************************************************************************/
    /* Otherwise, we want to find/create the conversation and update it       */

    /* First time, get info from conversation.
       Even though we think of this as an outgoing packet being sent,
       we store the time as being received by the destination. */
    p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                               pinfo->ptype,
                               pinfo->destport, pinfo->srcport, NO_ADDR_B);

    /* If the conversation doesn't exist, create it now. */
    if (!p_conv)
    {
        p_conv = conversation_new(pinfo->num, &pinfo->net_dst, &pinfo->net_src, PT_UDP,
                                  pinfo->destport, pinfo->srcport,
                                  NO_ADDR2);
        if (!p_conv)
        {
            /* Give up if can't create it */
            return;
        }
    }


    /****************************************************/
    /* Now find/create conversation data                */
    p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);
    if (!p_conv_data)
    {
        /* Allocate memory for data */
        p_conv_data = wmem_new0(wmem_file_scope(), struct _rtcp_conversation_info);

        /* Add it to conversation. */
        conversation_add_proto_data(p_conv, proto_rtcp, p_conv_data);
    }

    /*******************************************************/
    /* Update conversation data                            */
    p_conv_data->last_received_set = TRUE;
    p_conv_data->last_received_frame_number = pinfo->num;
    p_conv_data->last_received_timestamp = pinfo->abs_ts;
    p_conv_data->last_received_ts = lsr;


    /****************************************************************/
    /* Update packet info to record conversation state              */

    /* Will use/create packet info */
    if (!p_packet_data)
    {
        p_packet_data = wmem_new0(wmem_file_scope(), struct _rtcp_conversation_info);

        p_add_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0, p_packet_data);
    }

    /* Copy current conversation data into packet info */
    p_packet_data->last_received_set = TRUE;
    p_packet_data->last_received_frame_number = p_conv_data->last_received_frame_number;
}


/* Use received sr to work out what the roundtrip delay is
   (at least between capture point and the other endpoint involved in
    the conversation) */
static void calculate_roundtrip_delay(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, guint32 lsr, guint32 dlsr)
{
    /*****************************************************/
    /* This is called dissecting an SR.  We need to:
       - look in the packet info for stored calculation.  If found, use.
       - look up the conversation of the sending side to see when the
         'last SR' was detected (received)
       - calculate the network delay using the that packet time,
         this packet time, and dlsr
    *****************************************************/

    conversation_t                 *p_conv;
    struct _rtcp_conversation_info *p_conv_data;
    struct _rtcp_conversation_info *p_packet_data;


    /*************************************************/
    /* Look for previous result                      */
    p_packet_data = (struct _rtcp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0);
    if (p_packet_data && p_packet_data->lsr_matched)
    {
        /* Show info. */
        add_roundtrip_delay_info(tvb, pinfo, tree,
                                 p_packet_data->calculated_delay_used_frame,
                                 p_packet_data->calculated_delay_report_gap,
                                 p_packet_data->calculated_delay);
        return;
    }


    /********************************************************************/
    /* Look for captured timestamp of last SR in conversation of sender */
    /* of this packet                                                   */
    p_conv = find_conversation(pinfo->num, &pinfo->net_src, &pinfo->net_dst,
                               pinfo->ptype,
                               pinfo->srcport, pinfo->destport, NO_ADDR_B);
    if (!p_conv)
    {
        return;
    }

    /* Look for conversation data  */
    p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);
    if (!p_conv_data)
    {
        return;
    }

    if (p_conv_data->last_received_set)
    {
        /* Store result of calculation in packet info */
        if (!p_packet_data)
        {
            /* Create packet info if it doesn't exist */
            p_packet_data = wmem_new0(wmem_file_scope(), struct _rtcp_conversation_info);

            /* Set as packet info */
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0, p_packet_data);
        }

        /* Don't allow match seemingly calculated from same (or later!) frame */
        if (pinfo->num <= p_conv_data->last_received_frame_number)
        {
            return;
        }

        /* The previous report must match the lsr given here */
        if (p_conv_data->last_received_ts == lsr)
        {
            /* Look at time of since original packet was sent */
            gint seconds_between_packets = (gint)
                  (pinfo->abs_ts.secs - p_conv_data->last_received_timestamp.secs);
            gint nseconds_between_packets =
                  pinfo->abs_ts.nsecs - p_conv_data->last_received_timestamp.nsecs;

            gint total_gap = (seconds_between_packets*1000) +
                             (nseconds_between_packets / 1000000);
            gint dlsr_ms = (int)(((double)dlsr/(double)65536) * 1000.0);
            gint delay;

            /* Delay is gap - dlsr  (N.B. this is allowed to be -ve) */
            delay = total_gap - dlsr_ms;

            /* Record that the LSR matches */
            p_packet_data->lsr_matched = TRUE;

            /* No useful calculation can be done if dlsr not set... */
            if (dlsr)
            {
                p_packet_data->calculated_delay = delay;
                p_packet_data->calculated_delay_report_gap = total_gap;
                p_packet_data->calculated_delay_used_frame = p_conv_data->last_received_frame_number;
            }

            /* Show info. */
            add_roundtrip_delay_info(tvb, pinfo, tree,
                                     p_conv_data->last_received_frame_number,
                                     total_gap,
                                     delay);
        }
    }
}

/* Show the calculated roundtrip delay info by adding protocol tree items
   and appending text to the info column */
static void add_roundtrip_delay_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                     guint frame, guint gap_between_reports,
                                     gint delay)
{
    /* 'Last SR' frame used in calculation.  Show this even if no delay shown */
    proto_item *item = proto_tree_add_uint(tree,
                                           hf_rtcp_last_sr_timestamp_frame,
                                           tvb, 0, 0, frame);
    PROTO_ITEM_SET_GENERATED(item);

    /* Time elapsed since 'Last SR' time in capture */
    item = proto_tree_add_uint(tree,
                               hf_rtcp_time_since_last_sr,
                               tvb, 0, 0, gap_between_reports);
    PROTO_ITEM_SET_GENERATED(item);

    /* Don't report on calculated delays below the threshold.
       Will report delays less than -threshold, to highlight
       problems with generated reports */
    if (abs(delay) < (int)global_rtcp_show_roundtrip_calculation_minimum)
    {
        return;
    }

    /* Calculated delay in ms */
    item = proto_tree_add_int(tree, hf_rtcp_roundtrip_delay, tvb, 0, 0, delay);
    PROTO_ITEM_SET_GENERATED(item);

    /* Add to expert info */
    if (delay >= 0)
    {
        expert_add_info_format(pinfo, item, &ei_rtcp_roundtrip_delay, "RTCP round-trip delay detected (%d ms)", delay);
    }
    else
    {
        expert_add_info_format(pinfo, item, &ei_rtcp_roundtrip_delay_negative, "Negative RTCP round-trip delay detected (%d ms)", delay);
    }

    /* Report delay in INFO column */
    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (roundtrip delay <-> %s = %dms, using frame %u)  ",
                    address_to_str(wmem_packet_scope(), &pinfo->net_src), delay, frame);
}

static int
rtcp_packet_type_to_tree( int rtcp_packet_type)
{
    int tree;

    switch(rtcp_packet_type) {
        case RTCP_SR:    tree = ett_rtcp_sr;    break;
        case RTCP_RR:    tree = ett_rtcp_rr;    break;
        case RTCP_SDES:  tree = ett_rtcp_sdes;  break;
        case RTCP_BYE:   tree = ett_rtcp_bye;   break;
        case RTCP_APP:   tree = ett_rtcp_app;   break;
        case RTCP_RTPFB: tree = ett_rtcp_rtpfb; break;
        case RTCP_PSFB:  tree = ett_rtcp_psfb;  break;
        case RTCP_XR:    tree = ett_rtcp_xr;    break;
        case RTCP_FIR:   tree = ett_rtcp_fir;   break;
        case RTCP_NACK:  tree = ett_rtcp_nack;  break;
        default:         tree = ett_rtcp;
    }
    return tree;
}

static int
dissect_rtcp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_item       *ti;
    proto_tree       *rtcp_tree           = NULL;
    guint             padding_set         = 0;
    guint             offset              = 0;
    guint             total_packet_length = 0;
    guint             padding_offset      = 0;
    gboolean          srtcp_encrypted     = FALSE;
    gboolean          srtcp_now_encrypted = FALSE;
    conversation_t   *p_conv;
    struct srtp_info *srtcp_info          = NULL;
    guint32           srtcp_offset        = 0;
    guint32           srtcp_index         = 0;

    /* first see if this conversation is encrypted SRTP, and if so do not try to dissect the payload(s) */
    p_conv = find_conversation(pinfo->num, &pinfo->net_src, &pinfo->net_dst,
                               pinfo->ptype,
                               pinfo->srcport, pinfo->destport, NO_ADDR_B);
    if (p_conv)
    {
        struct _rtcp_conversation_info *p_conv_data;
        p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);
        if (p_conv_data && p_conv_data->srtcp_info)
        {
            gboolean e_bit;
            srtcp_info = p_conv_data->srtcp_info;
            /* get the offset to the start of the SRTCP fields at the end of the packet */
            srtcp_offset = tvb_reported_length_remaining(tvb, offset) - srtcp_info->auth_tag_len - srtcp_info->mki_len - 4;
            /* It has been setup as SRTCP, but skip to the SRTCP E field at the end
               to see if this particular packet is encrypted or not. The E bit is the MSB. */
            srtcp_index = tvb_get_ntohl(tvb,srtcp_offset);
            e_bit = (srtcp_index & 0x80000000) ? TRUE : FALSE;
            srtcp_index &= 0x7fffffff;

            if (srtcp_info->encryption_algorithm!=SRTP_ENC_ALG_NULL) {
                /* just flag it for now - the first SR or RR header and SSRC are unencrypted */
                if (e_bit)
                    srtcp_encrypted = TRUE;
            }
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, (srtcp_info) ? "SRTCP" : "RTCP");

    /*
     * Check if there are at least 4 bytes left in the frame,
     * the last 16 bits of those is the length of the current
     * RTCP message. The last compound message contains padding,
     * that enables us to break from the while loop.
     */
    while ( !srtcp_now_encrypted && tvb_bytes_exist( tvb, offset, 4) ) {
        guint temp_byte;
        guint elem_count;
        guint packet_type;
        guint packet_length;
        /*
         * First retrieve the packet_type
         */
        packet_type = tvb_get_guint8( tvb, offset + 1 );

        /*
         * Check if it's a valid type
         */
        if ( ( packet_type < RTCP_PT_MIN ) || ( packet_type >  RTCP_PT_MAX ) )
            break;

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s   ",
                      val_to_str_const(packet_type, rtcp_packet_type_vals, "Unknown"));

        /*
         * get the packet-length for the complete RTCP packet
         */
        packet_length = ( tvb_get_ntohs( tvb, offset + 2 ) + 1 ) * 4;
        total_packet_length += packet_length;

        ti = proto_tree_add_item(tree, proto_rtcp, tvb, offset, packet_length, ENC_NA );
        proto_item_append_text(ti, " (%s)",
                               val_to_str_const(packet_type,
                                                rtcp_packet_type_vals,
                                                "Unknown"));

        rtcp_tree = proto_item_add_subtree( ti, rtcp_packet_type_to_tree(packet_type) );

        /* Conversation setup info */
        if (global_rtcp_show_setup_info)
        {
            show_setup_info(tvb, pinfo, rtcp_tree);
        }


        temp_byte = tvb_get_guint8( tvb, offset );

        proto_tree_add_item( rtcp_tree, hf_rtcp_version, tvb,
                             offset, 1, ENC_BIG_ENDIAN);
        padding_set = RTCP_PADDING( temp_byte );
        padding_offset = offset + packet_length - 1;

        proto_tree_add_boolean( rtcp_tree, hf_rtcp_padding, tvb,
                                offset, 1, temp_byte );
        elem_count = RTCP_COUNT( temp_byte );

        switch ( packet_type ) {
            case RTCP_SR:
            case RTCP_RR:
                /* Receiver report count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_rc, tvb, offset, 1, temp_byte );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                /* Sender Synchronization source, 32 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN );
                offset += 4;

                if (srtcp_encrypted) { /* rest of the payload is encrypted - do not try to dissect */
                    srtcp_now_encrypted = TRUE;
                    break;
                }

                if ( packet_type == RTCP_SR )
                    offset = dissect_rtcp_sr( pinfo, tvb, offset, rtcp_tree, elem_count, packet_length-8 );
                else
                    offset = dissect_rtcp_rr( pinfo, tvb, offset, rtcp_tree, elem_count, packet_length-8 );
                break;
            case RTCP_SDES:
                /* Source count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_sc, tvb, offset, 1, temp_byte );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_sdes( tvb, offset, rtcp_tree, elem_count );
                break;
            case RTCP_BYE:
                /* Source count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_sc, tvb, offset, 1, temp_byte );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_bye( tvb, pinfo, offset, rtcp_tree, elem_count );
                break;
            case RTCP_APP: {
                /* Subtype, 5 bits */
                guint rtcp_subtype;
                guint app_length;
                rtcp_subtype = elem_count;
                proto_tree_add_uint( rtcp_tree, hf_rtcp_subtype, tvb, offset, 1, elem_count );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                app_length = tvb_get_ntohs( tvb, offset ) <<2;
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_app( tvb, pinfo, offset,rtcp_tree, padding_set, packet_length - 4, rtcp_subtype, app_length);
            }
                break;
            case RTCP_XR:
                /* Reserved, 5 bits, Ignore */
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_xr( tvb, pinfo, offset, rtcp_tree, packet_length - 4 );
                break;
            case RTCP_AVB:
                /* Subtype, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_subtype, tvb, offset, 1, elem_count );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_avb( tvb, pinfo, offset, rtcp_tree, packet_length - 4 );
                break;
            case RTCP_RSI:
                /* Reserved, 5 bits, Ignore */
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_rsi( tvb, pinfo, offset, rtcp_tree, packet_length - 4 );
                break;
            case RTCP_TOKEN: {
                /* Subtype, 5 bits */
                guint rtcp_subtype;
                rtcp_subtype = elem_count;
                proto_tree_add_uint( rtcp_tree, hf_rtcp_subtype, tvb, offset, 1, elem_count );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_token( tvb, pinfo, offset, rtcp_tree, packet_length - 4, rtcp_subtype );
            }
                break;
            case RTCP_FIR:
                offset = dissect_rtcp_fir( tvb, offset, rtcp_tree );
                break;
            case RTCP_NACK:
                offset = dissect_rtcp_nack( tvb, offset, rtcp_tree );
                break;
            case RTCP_RTPFB:
                offset = dissect_rtcp_rtpfb( tvb, offset, rtcp_tree, ti, pinfo );
                break;
            case RTCP_PSFB:
                offset = dissect_rtcp_psfb( tvb, offset, rtcp_tree, packet_length, ti, pinfo );
                break;
            default:
                /*
                 * To prevent endless loops in case of an unknown message type
                 * increase offset. Some time the while will end :-)
                 */
                offset++;
                break;
        }

        col_set_fence(pinfo->cinfo, COL_INFO);
    }
    /* If the padding bit is set, the last octet of the
     * packet contains the length of the padding
     * We only have to check for this at the end of the LAST RTCP message
     */
    if ( padding_set ) {
        guint padding_length;
        /* The last RTCP message in the packet has padding - find it.
         *
         * The padding count is found at an offset of padding_offset; it
         * contains the number of padding octets, including the padding
         * count itself.
         */
        padding_length = tvb_get_guint8( tvb, padding_offset);

        /* This length includes the padding length byte itself, so 0 is not
         * a valid value. */
        if (padding_length != 0) {
            proto_tree_add_item( rtcp_tree, hf_rtcp_padding_data, tvb, offset, padding_length - 1, ENC_NA );
            offset += padding_length - 1;
        }
        proto_tree_add_item( rtcp_tree, hf_rtcp_padding_count, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
    }

    /* If the payload was encrypted, the main payload was not dissected */
    if (srtcp_encrypted == TRUE) {
        proto_tree_add_expert(rtcp_tree, pinfo, &ei_srtcp_encrypted_payload, tvb, offset, srtcp_offset-offset);
        proto_tree_add_item(rtcp_tree, hf_srtcp_e, tvb, srtcp_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_uint(rtcp_tree, hf_srtcp_index, tvb, srtcp_offset, 4, srtcp_index);
        srtcp_offset += 4;
        if (srtcp_info->mki_len) {
            proto_tree_add_item(rtcp_tree, hf_srtcp_mki, tvb, srtcp_offset, srtcp_info->mki_len, ENC_NA);
            srtcp_offset += srtcp_info->mki_len;
        }

        if (srtcp_info->auth_tag_len) {
            proto_tree_add_item(rtcp_tree, hf_srtcp_auth_tag, tvb, srtcp_offset, srtcp_info->auth_tag_len, ENC_NA);
            /*srtcp_offset += srtcp_info->auth_tag_len;*/
        }
    }
    /* offset should be total_packet_length by now... */
    else if (offset == total_packet_length)
    {
        ti = proto_tree_add_boolean_format_value(tree, hf_rtcp_length_check, tvb,
                                            0, 0, TRUE, "OK - %u bytes",
                                            offset);
        /* Hidden might be less annoying here...? */
        PROTO_ITEM_SET_GENERATED(ti);
    }
    else
    {
        ti = proto_tree_add_boolean_format_value(tree, hf_rtcp_length_check, tvb,
                                            0, 0, FALSE,
                                            "Wrong (expected %u bytes, found %d)",
                                            total_packet_length, offset);
        PROTO_ITEM_SET_GENERATED(ti);

        expert_add_info_format(pinfo, ti, &ei_rtcp_length_check, "Incorrect RTCP packet length information (expected %u bytes, found %d)", total_packet_length, offset);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_rtcp(void)
{
    static hf_register_info hf[] = {
        {
            &hf_rtcp_version,
            {
                "Version",
                "rtcp.version",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_version_vals),
                0xC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_padding,
            {
                "Padding",
                "rtcp.padding",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rc,
            {
                "Reception report count",
                "rtcp.rc",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x1F,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sc,
            {
                "Source count",
                "rtcp.sc",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x1F,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pt,
            {
                "Packet type",
                "rtcp.pt",
                FT_UINT8,
                BASE_DEC,
                VALS( rtcp_packet_type_vals ),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_length,
            {
                "Length",
                "rtcp.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "32-bit words (-1) in packet", HFILL
            }
        },
        {
            &hf_rtcp_ssrc_sender,
            {
                "Sender SSRC",
                "rtcp.senderssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
      &hf_rtcp_ssrc_media_source,
            {
                "Media source SSRC",
                "rtcp.mediassrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ntp_msw,
            {
                "Timestamp, MSW",
                "rtcp.timestamp.ntp.msw",
                FT_UINT32,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ntp_lsw,
            {
                "Timestamp, LSW",
                "rtcp.timestamp.ntp.lsw",
                FT_UINT32,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ntp,
            {
                "MSW and LSW as NTP timestamp",
                "rtcp.timestamp.ntp",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtp_timestamp,
            {
                "RTP timestamp",
                "rtcp.timestamp.rtp",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sender_pkt_cnt,
            {
                "Sender's packet count",
                "rtcp.sender.packetcount",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sender_oct_cnt,
            {
                "Sender's octet count",
                "rtcp.sender.octetcount",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_source,
            {
                "Identifier",
                "rtcp.ssrc.identifier",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_fraction,
            {
                "Fraction lost",
                "rtcp.ssrc.fraction",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_cum_nr,
            {
                "Cumulative number of packets lost",
                "rtcp.ssrc.cum_nr",
                FT_INT24,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_ext_high_seq,
            {
                "Extended highest sequence number received",
                "rtcp.ssrc.ext_high",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_high_seq,
            {
                "Highest sequence number received",
                "rtcp.ssrc.high_seq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_high_cycles,
            {
                "Sequence number cycles count",
                "rtcp.ssrc.high_cycles",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_jitter,
            {
                "Interarrival jitter",
                "rtcp.ssrc.jitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_lsr,
            {
                "Last SR timestamp",
                "rtcp.ssrc.lsr",
                FT_UINT32,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_dlsr,
            {
                "Delay since last SR timestamp",
                "rtcp.ssrc.dlsr",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
#if 0
        {
            &hf_rtcp_ssrc_csrc,
            {
                "SSRC / CSRC identifier",
                "rtcp.sdes.ssrc_csrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
#endif
        {
            &hf_rtcp_sdes_type,
            {
                "Type",
                "rtcp.sdes.type",
                FT_UINT8,
                BASE_DEC,
                VALS( rtcp_sdes_type_vals ),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sdes_length,
            {
                "Length",
                "rtcp.sdes.length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sdes_text,
            {
                "Text",
                "rtcp.sdes.text",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sdes_prefix_len,
            {
                "Prefix length",
                "rtcp.sdes.prefix.length",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sdes_prefix_string,
            {
                "Prefix string",
                "rtcp.sdes.prefix.string",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_subtype,
            {
                "Subtype",
                "rtcp.app.subtype",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_name_ascii,
            {
                "Name (ASCII)",
                "rtcp.app.name",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_data,
            {
                "Application specific data",
                "rtcp.app.data",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1,
            {
                "PoC1 Application specific data",
                "rtcp.app.poc1",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_subtype,
            {
                "Subtype",
                "rtcp.app.PoC1.subtype",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_floor_cnt_type_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_sip_uri,
            {
                "SIP URI",
                "rtcp.app.poc1.sip.uri",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_disp_name,
            {
                "Display Name",
                "rtcp.app.poc1.disp.name",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_priority,
            {
                "Priority",
                "rtcp.app.poc1.priority",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_qsresp_priority_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_request_ts,
            {
                "Talk Burst Request Timestamp",
                "rtcp.app.poc1.request.ts",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_stt,
            {
                "Stop talking timer",
                "rtcp.app.poc1.stt",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_partic,
            {
                "Number of participants",
                "rtcp.app.poc1.participants",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_ssrc_granted,
            {
                "SSRC of client granted permission to talk",
                "rtcp.app.poc1.ssrc.granted",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_last_pkt_seq_no,
            {
                "Sequence number of last RTP packet",
                "rtcp.app.poc1.last.pkt.seq.no",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_ignore_seq_no,
            {
                "Ignore sequence number field",
                "rtcp.app.poc1.ignore.seq.no",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x8000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_reason_code1,
            {
                "Reason code",
                "rtcp.app.poc1.reason.code",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_reason_code1_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_reason1_phrase,
            {
                "Reason Phrase",
                "rtcp.app.poc1.reason.phrase",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_reason_code2,
            {
                "Reason code",
                "rtcp.app.poc1.reason.code",
                FT_UINT16,
                BASE_DEC,
                VALS(rtcp_app_poc1_reason_code2_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_new_time_request,
            {
                "New time client can request (seconds)",
                "rtcp.app.poc1.new.time.request",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "Time in seconds client can request for", HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_ack_subtype,
            {
                "Subtype",
                "rtcp.app.poc1.ack.subtype",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_floor_cnt_type_vals),
                0xf8,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_ack_reason_code,
            {
                "Reason code",
                "rtcp.app.poc1.ack.reason.code",
                FT_UINT16,
                BASE_DEC,
                VALS(rtcp_app_poc1_reason_code_ack_vals),
                0x07ff,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_qsresp_priority,
            {
                "Priority",
                "rtcp.app.poc1.qsresp.priority",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_qsresp_priority_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_qsresp_position,
            {
                "Position (number of clients ahead)",
                "rtcp.app.poc1.qsresp.position",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[0],
            {
                "Identity of inviting client",
                "rtcp.app.poc1.conn.content.a.id",
                FT_BOOLEAN,
                16,
                NULL,
                0x8000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[1],
            {
                "Nick name of inviting client",
                "rtcp.app.poc1.conn.content.a.dn",
                FT_BOOLEAN,
                16,
                NULL,
                0x4000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[2],
            {
                "Session identity",
                "rtcp.app.poc1.conn.content.sess.id",
                FT_BOOLEAN,
                16,
                NULL,
                0x2000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[3],
            {
                "Group name",
                "rtcp.app.poc1.conn.content.grp.dn",
                FT_BOOLEAN,
                16,
                NULL,
                0x1000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[4],
            {
                "Group identity",
                "rtcp.app.poc1.conn.content.grp.id",
                FT_BOOLEAN,
                16,
                NULL,
                0x0800,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_session_type,
            {
                "Session type",
                "rtcp.app.poc1.conn.session.type",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_conn_sess_type_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_add_ind_mao,
            {
                "Manual answer override",
                "rtcp.app.poc1.conn.add.ind.mao",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[0],
            {
                "Identity of inviting client",
                "rtcp.app.poc1.conn.sdes.a.id",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[1],
            {
                "Nick name of inviting client",
                "rtcp.app.poc1.conn.sdes.a.dn",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[2],
            {
                "Session identity",
                "rtcp.app.poc1.conn.sdes.sess.id",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[3],
            {
                "Group Name",
                "rtcp.app.poc1.conn.sdes.grp.dn",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[4],
            {
                "Group identity",
                "rtcp.app.poc1.conn.sdes.grp.id",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_mux,
            {
                "RtpMux Application specific data",
                "rtcp.app.mux",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_mux_mux,
            {
                "Multiplexing supported",
                "rtcp.app.mux.mux",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
                },
        {
            &hf_rtcp_app_mux_cp,
            {
                "Header compression supported",
                "rtcp.app.mux.cp",
                FT_BOOLEAN,
                8,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_mux_selection,
            {
                "Multiplexing selection",
                "rtcp.app.mux.selection",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_mux_selection_vals),
                0x30,
                NULL, HFILL
            }
        },
                {
                    &hf_rtcp_app_mux_localmuxport,
            {
                "Local Mux Port",
                "rtcp.app.mux.muxport",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_fsn,
            {
                "First sequence number",
                "rtcp.nack.fsn",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_blp,
            {
                "Bitmask of following lost packets",
                "rtcp.nack.blp",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_padding_count,
            {
                "Padding count",
                "rtcp.padding.count",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_padding_data,
            {
                "Padding data",
                "rtcp.padding.data",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_profile_specific_extension_type,
            {
                "Extension Type",
                "rtcp.profile-specific-extension.type",
                FT_UINT16,
                BASE_DEC,
                VALS( rtcp_ms_profile_extension_vals ),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_profile_specific_extension_length,
            {
                "Extension Length",
                "rtcp.profile-specific-extension.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_profile_specific_extension,
            {
                "Profile-specific extension",
                "rtcp.profile-specific-extension",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_setup,
            {
                "Stream setup",
                "rtcp.setup",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Stream setup, method and frame number", HFILL
            }
        },
        {
            &hf_rtcp_setup_frame,
            {
                "Setup frame",
                "rtcp.setup-frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                "Frame that set up this stream", HFILL
            }
        },
        {
            &hf_rtcp_setup_method,
            {
                "Setup Method",
                "rtcp.setup-method",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Method used to set up this stream", HFILL
            }
        },
        {
            &hf_rtcp_last_sr_timestamp_frame,
            {
                "Frame matching Last SR timestamp",
                "rtcp.lsr-frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                "Frame matching LSR field (used to calculate roundtrip delay)", HFILL
            }
        },
        {
            &hf_rtcp_time_since_last_sr,
            {
                "Time since Last SR captured",
                "rtcp.lsr-frame-captured",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "Time since frame matching LSR field was captured", HFILL
            }
        },
        {
            &hf_rtcp_roundtrip_delay,
            {
                "Roundtrip Delay(ms)",
                "rtcp.roundtrip-delay",
                FT_INT32,
                BASE_DEC,
                NULL,
                0x0,
                "Calculated roundtrip delay in ms", HFILL
            }
        },
        {
            &hf_rtcp_xr_block_type,
            {
                "Type",
                "rtcp.xr.bt",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_type_vals),
                0x0,
                "Block Type", HFILL
            }
        },
        {
            &hf_rtcp_xr_block_specific,
            {
                "Type Specific",
                "rtcp.xr.bs",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "Reserved", HFILL
            }
        },
        {
            &hf_rtcp_xr_block_length,
            {
                "Length",
                "rtcp.xr.bl",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "Block Length", HFILL
            }
        },
        {
            &hf_rtcp_ssrc_discarded,
            {
                "Fraction discarded",
                "rtcp.ssrc.discarded",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "Discard Rate", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_burst_density,
            {
                "Burst Density",
                "rtcp.xr.voipmetrics.burstdensity",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_gap_density,
            {
                "Gap Density",
                "rtcp.xr.voipmetrics.gapdensity",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_burst_duration,
            {
                "Burst Duration(ms)",
                "rtcp.xr.voipmetrics.burstduration",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_gap_duration,
            {
                "Gap Duration(ms)",
                "rtcp.xr.voipmetrics.gapduration",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_rtdelay,
            {
                "Round Trip Delay(ms)",
                "rtcp.xr.voipmetrics.rtdelay",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_esdelay,
            {
                "End System Delay(ms)",
                "rtcp.xr.voipmetrics.esdelay",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_siglevel,
            {
                "Signal Level",
                "rtcp.xr.voipmetrics.signallevel",
                FT_INT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_noiselevel,
            {
                "Noise Level",
                "rtcp.xr.voipmetrics.noiselevel",
                FT_INT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_rerl,
            {
                "Residual Echo Return Loss",
                "rtcp.xr.voipmetrics.rerl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_gmin,
            {
                "Gmin",
                "rtcp.xr.voipmetrics.gmin",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_rfactor,
            {
                "R Factor",
                "rtcp.xr.voipmetrics.rfactor",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "R Factor is in the range of 0 to 100", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_extrfactor,
            {
                "External R Factor",
                "rtcp.xr.voipmetrics.extrfactor",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "R Factor is in the range of 0 to 100", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_moslq,
            {
                "MOS - Listening Quality",
                "rtcp.xr.voipmetrics.moslq",
                FT_FLOAT,
                BASE_NONE,
                NULL,
                0x0,
                "MOS is in the range of 1 to 5", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_moscq,
            {
                "MOS - Conversational Quality",
                "rtcp.xr.voipmetrics.moscq",
                FT_FLOAT,
                BASE_NONE,
                NULL,
                0x0,
                "MOS is in the range of 1 to 5", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_plc,
            {
                "Packet Loss Concealment Algorithm",
                "rtcp.xr.voipmetrics.plc",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_plc_algo_vals),
                0xC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbadaptive,
            {
                "Adaptive Jitter Buffer Algorithm",
                "rtcp.xr.voipmetrics.jba",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_jb_adaptive_vals),
                0x30,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbrate,
            {
                "Jitter Buffer Rate",
                "rtcp.xr.voipmetrics.jbrate",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbnominal,
            {
                "Nominal Jitter Buffer Size",
                "rtcp.xr.voipmetrics.jbnominal",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbmax,
            {
                "Maximum Jitter Buffer Size",
                "rtcp.xr.voipmetrics.jbmax",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbabsmax,
            {
                "Absolute Maximum Jitter Buffer Size",
                "rtcp.xr.voipmetrics.jbabsmax",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_thinning,
            {
                "Thinning factor",
                "rtcp.xr.tf",
                FT_UINT8,
                BASE_DEC,
                                NULL,
                0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_loss_flag,
            {
                "Loss Report Flag",
                "rtcp.xr.stats.lrflag",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_dup_flag,
            {
                "Duplicates Report Flag",
                "rtcp.xr.stats.dupflag",
                FT_BOOLEAN,
                8,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_jitter_flag,
            {
                "Jitter Report Flag",
                "rtcp.xr.stats.jitterflag",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_ttl,
            {
                "TTL or Hop Limit Flag",
                "rtcp.xr.stats.ttl",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_ip_ttl_vals),
                0x18,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_endseq,
            {
                "End Sequence Number",
                "rtcp.xr.endseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_chunk_null_terminator,
            {
                "Null Terminator",
                "rtcp.xr.chunk.null_terminator",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_chunk_length,
            {
                "Check length",
                "rtcp.xr.chunk.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_chunk_bit_vector,
            {
                "Bit Vector",
                "rtcp.xr.chunk.bit_vector",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        {
            &hf_rtcp_xr_beginseq,
            {
                "Begin Sequence Number",
                "rtcp.xr.beginseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_receipt_time_seq,
            {
                "Receipt Time",
                "rtcp.xr.receipt_time_seq",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_lost,
            {
                "Lost Packets",
                "rtcp.xr.stats.lost",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_dups,
            {
                "Duplicate Packets",
                "rtcp.xr.stats.dups",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_minjitter,
            {
                "Minimum Jitter",
                "rtcp.xr.stats.minjitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_maxjitter,
            {
                "Maximum Jitter",
                "rtcp.xr.stats.maxjitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_meanjitter,
            {
                "Mean Jitter",
                "rtcp.xr.stats.meanjitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_devjitter,
            {
                "Standard Deviation of Jitter",
                "rtcp.xr.stats.devjitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_minttl,
            {
                "Minimum TTL or Hop Limit",
                "rtcp.xr.stats.minttl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_maxttl,
            {
                "Maximum TTL or Hop Limit",
                "rtcp.xr.stats.maxttl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_meanttl,
            {
                "Mean TTL or Hop Limit",
                "rtcp.xr.stats.meanttl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_devttl,
            {
                "Standard Deviation of TTL",
                "rtcp.xr.stats.devttl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_timestamp,
            {
                "Timestamp",
                "rtcp.xr.timestamp",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_lrr,
            {
                "Last RR timestamp",
                "rtcp.xr.lrr",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_dlrr,
            {
                "Delay since last RR timestamp",
                "rtcp.xr.dlrr",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_length_check,
            {
                "RTCP frame length check",
                "rtcp.length_check",
                FT_BOOLEAN,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_fmt,
            {
                "RTCP Feedback message type (FMT)",
                "rtcp.rtpfb.fmt",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_rtpfb_fmt_vals),
                0x1f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_fmt,
            {
                "RTCP Feedback message type (FMT)",
                "rtcp.psfb.fmt",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_psfb_fmt_vals),
                0x1f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_nack_pid,
            {
                "RTCP Transport Feedback NACK PID",
                "rtcp.rtpfb.nack_pid",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_nack_blp,
            {
                "RTCP Transport Feedback NACK BLP",
                "rtcp.rtpfb.nack_blp",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_fci,
            {
                "Feedback Control Information (FCI)",
                "rtcp.fci",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_spst,
            {
                "Syncronization Packet Sender Type",
                "rtcp.xr.idms.spst",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_idms_spst),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_pt,
            {
                "Payload Type",
                "rtcp.xr.idms.pt",
                FT_UINT8,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_msci,
            {
                "Media Stream Correlation Identifier",
                "rtcp.xr.idms.msci",
                FT_UINT32,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_source_ssrc,
            {
                "Source SSRC",
                "rtcp.xr.idms.source_ssrc",
                FT_UINT32,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_ntp_rcv_ts,
            {
                "NTP Timestamp of packet reception",
                "rtcp.xr.idms.ntp_rcv_ts",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_rtp_ts,
            {
                "RTP Timestamp of packet",
                "rtcp.xr.idms.rtp_ts",
                FT_UINT32,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_ntp_pres_ts,
            {
                "NTP Timestamp of presentation",
                "rtcp.xr.idms.ntp_pres_ts",
                FT_UINT32,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_fir_fci_ssrc,
            {
                "SSRC",
                "rtcp.psfb.fir.fci.ssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_fir_fci_csn,
            {
                "Command Sequence Number",
                "rtcp.psfb.fir.fci.csn",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_fir_fci_reserved,
            {
                "Reserved",
                "rtcp.psfb.fir.fci.reserved",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
            &hf_rtcp_psfb_sli_first,
            {
                "First MB",
                "rtcp.psfb.fir.sli.first",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0xFFF80000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_sli_number,
            {
                "Number of MBs",
                "rtcp.psfb.fir.sli.number",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0007FFC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_sli_picture_id,
            {
                "Picture ID",
                "rtcp.psfb.fir.sli.picture_id",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0007FFC0,
                NULL, HFILL
            }
        },
#if 0
        {
      &hf_rtcp_psfb_remb_fci_identifier,
            {
                "Unique Identifier",
                "rtcp.psfb.remb.identifier",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_ssrc,
            {
                "SSRC",
                "rtcp.psfb.remb.fci.ssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_number_ssrcs,
            {
                "Number of Ssrcs",
                "rtcp.psfb.remb.fci.number_ssrcs",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xff,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_exp,
            {
                "BR Exp",
                "rtcp.psfb.remb.fci.br_exp",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xfc,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_mantissa,
            {
                "Br Mantissa",
                "rtcp.psfb.remb.fci.br_mantissa",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x03ffff,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_bitrate,
            {
                "Maximum bit rate",
                "rtcp.psfb.remb.fci.bitrate",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
#endif
    {
      &hf_rtcp_rtpfb_tmbbr_fci_ssrc,
            {
                "SSRC",
                "rtcp.rtpfb.tmmbr.fci.ssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_exp,
            {
                "MxTBR Exp",
                "rtcp.rtpfb.tmmbr.fci.exp",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xfc,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_mantissa,
            {
                "MxTBR Mantissa",
                "rtcp.rtpfb.tmmbr.fci.mantissa",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x3fffe,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_bitrate,
            {
                "Maximum total media bit rate",
                "rtcp.rtpfb.tmmbr.fci.bitrate",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_measuredoverhead,
            {
                "Measured Overhead",
                "rtcp.rtpfb.tmmbr.fci.measuredoverhead",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x1ff,
                NULL, HFILL
            }
        },


        {
            &hf_srtcp_e,
            {
                "SRTCP E flag",
                "srtcp.e",
                FT_BOOLEAN,
                32,
                NULL,
                0x80000000,
                "SRTCP Encryption Flag", HFILL
            }
        },
        {
            &hf_srtcp_index,
            {
                "SRTCP Index",
                "srtcp.index",
                FT_UINT32,
                BASE_DEC_HEX,
                NULL,
                0x7fffffff,
                NULL, HFILL
            }
        },
        {
            &hf_srtcp_mki,
            {
                "SRTCP MKI",
                "srtcp.mki",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0,
                "SRTCP Master Key Index", HFILL
            }
        },
        {
            &hf_srtcp_auth_tag,
            {
                "SRTCP Auth Tag",
                "srtcp.auth_tag",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0,
                "SRTCP Authentication Tag", HFILL
            }
        },
        /* additions for BT XNQ block as defined in RFC5093 */
        {
            &hf_rtcp_xr_btxnq_begseq,
            {
                "Starting sequence number",
                "rtcp.xr.btxnq.begseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_endseq,
            {
                "Last sequence number",
                "rtcp.xr.btxnq.endseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_vmaxdiff,
            {
                "Maximum IPDV difference in 1 cycle",
                "rtcp.xr.btxnq.vmaxdiff",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_vrange,
            {
                "Maximum IPDV difference seen to date",
                "rtcp.xr.btxnq.vrange",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_vsum,
            {
                "Sum of peak IPDV differences to date",
                "rtcp.xr.btxnq.vsum",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_cycles,
            {
                "Number of cycles in calculation",
                "rtcp.xr.btxnq.cycles",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_jbevents,
            {
                "Number of jitter buffer adaptations to date",
                "rtcp.xr.btxnq.jbevents",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_spare,
            {
                "Spare/reserved bits",
                "rtcp.xr.btxnq.spare",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_tdegnet,
            {
                "Time degraded by packet loss or late delivery",
                "rtcp.xr.btxnq.tdegnet",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_tdegjit,
            {
                "Time degraded by jitter buffer adaptation events",
                "rtcp.xr.btxnq.tdegjit",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_es,
            {
                "ES due to unavailable packet events",
                "rtcp.xr.btxnq.es",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_ses,
            {
                "SES due to unavailable packet events",
                "rtcp.xr.btxnq.ses",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* MS Profile Specific Extension Fields */
        {
            &hf_rtcp_pse_ms_bandwidth,
            {
                "Bandwidth",
                "rtcp.ms_pse.bandwidth",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_confidence_level,
            {
                "Confidence Level",
                "rtcp.ms_pse.confidence_level",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_seq_num,
            {
                "Sequence Number",
                "rtcp.ms_pse.seq_num",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_frame_resolution_width,
            {
                "Frame Resolution Width",
                "rtcp.ms_pse.frame_res_width",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_frame_resolution_height,
            {
                "Frame Resolution Height",
                "rtcp.ms_pse.frame_res_height",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_bitrate,
            {
                "Bitrate",
                "rtcp.ms_pse.bitrate",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_frame_rate,
            {
                "Frame Rate",
                "rtcp.ms_pse.frame_rate",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_concealed_frames,
            {
                "Concealed Frames",
                "rtcp.ms_pse.concealed_frames",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_stretched_frames,
            {
                "Stretched Frames",
                "rtcp.ms_pse.stretched_frames",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_compressed_frames,
            {
                "Compressed Frames",
                "rtcp.ms_pse.compressed_frames",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_total_frames,
            {
                "Total Frames",
                "rtcp.ms_pse.total_frames",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_receive_quality_state,
            {
                "Received Quality State",
                "rtcp.ms_pse.receive_quality_state",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_fec_distance_request,
            {
                "FEC Distance Request",
                "rtcp.ms_pse.fec_distance_request",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_last_packet_train,
            {
                "Last Packet Train Flag",
                "rtcp.ms_pse.last_packet_train",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_packet_idx,
            {
                "Packet Index",
                "rtcp.ms_pse.packet_index",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_packet_cnt,
            {
                "Packet Count",
                "rtcp.ms_pse.packet_count",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_packet_train_byte_cnt,
            {
                "Packet Train Byte Count",
                "rtcp.ms_pse.packet_train_byte_count",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_inbound_bandwidth,
            {
                "Inbound Link Bandwidth",
                "rtcp.ms_pse.inbound_bandwidth",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_outbound_bandwidth,
            {
                "Outbound Link Bandwidth",
                "rtcp.ms_pse.outbound_bandwidth",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_no_cache,
            {
                "No Cache Flag",
                "rtcp.ms_pse.no_cache",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_congestion_info,
            {
                "Congestion Information",
                "rtcp.ms_pse.congestion_info",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_modality,
            {
                "Modality",
                "rtcp.ms_pse.modality",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        /* Microsoft PLI */
        {
            &hf_rtcp_psfb_pli_ms_request_id,
            {
                "Request ID",
                "rtcp.psfb.ms.pli.request_id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_pli_ms_sfr,
            {
                "Sync Frame Request",
                "rtcp.psfb.ms.pli.sync_frame_request",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        /* Microsoft Application Feedback Video Source Request */
        {
            &hf_rtcp_psfb_ms_type,
            {
                "Application Layer Feedback Type",
                "rtcp.psfb.ms.afb_type",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_length,
            {
                "Length",
                "rtcp.psfb.ms.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_msi,
            {
                "Requested Media Source ID (MSI)",
                "rtcp.psfb.ms.msi",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_request_id,
            {
                "Request Id",
                "rtcp.psfb.ms.vsr.request_id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_version,
            {
                "Version",
                "rtcp.psfb.ms.vsr.version",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_key_frame_request,
            {
                "Key Frame Request",
                "rtcp.psfb.ms.vsr.key_frame_request",
                FT_BOOLEAN,
                8,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_num_entries,
            {
                "Number of Entries",
                "rtcp.psfb.ms.vsr.num_entries",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_entry_length,
            {
                "Entry Length",
                "rtcp.psfb.ms.vsr.entry_length",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_payload_type,
            {
                "Payload Type",
                "rtcp.psfb.ms.vsr.entry.payload_type",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_ucconfig_mode,
            {
                "UCConfig Mode",
                "rtcp.psfb.ms.vsr.entry.ucconfig_mode",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_no_sp_frames,
            {
                "No support for SP Frames (RT only)",
                "rtcp.psfb.ms.vsr.entry.no_sp_frames",
                FT_BOOLEAN,
                8,
                NULL,
                0x04,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_baseline,
            {
                "Only Supports Constrained Baseline (H.264 only)",
                "rtcp.psfb.ms.vsr.entry.no_sp_baseline",
                FT_BOOLEAN,
                8,
                NULL,
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_cgs,
            {
                "Supports CGS rewrite (H.264 only)",
                "rtcp.psfb.ms.vsr.entry.cgs",
                FT_BOOLEAN,
                8,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_bitmask,
            {
                "Aspect Ratio Bitmask",
                "rtcp.psfb.ms.vsr.entry.apsect_ratio",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_4by3,
            {
                "Aspect Ratio 4 by 3",
                "rtcp.psfb.ms.vsr.entry.apsect_ratio_4by3",
                FT_BOOLEAN,
                8,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_16by9,
            {
                "Aspect Ratio 16 by 9",
                "rtcp.psfb.ms.vsr.entry.apsect_ratio_16by9",
                FT_BOOLEAN,
                8,
                NULL,
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_1by1,
            {
                "Aspect Ratio 1 by 1",
                "rtcp.psfb.ms.vsr.entry.apsect_ratio_1by1",
                FT_BOOLEAN,
                8,
                NULL,
                0x04,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_3by4,
            {
                "Aspect Ratio 3 by 4",
                "rtcp.psfb.ms.vsr.entry.apsect_ratio_3by4",
                FT_BOOLEAN,
                8,
                NULL,
                0x08,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_9by16,
            {
                "Aspect Ratio 9 by 16",
                "rtcp.psfb.ms.vsr.entry.apsect_ratio_9by16",
                FT_BOOLEAN,
                8,
                NULL,
                0x10,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_20by3,
            {
                "Aspect Ratio 20 by 3",
                "rtcp.psfb.ms.vsr.entry.apsect_ratio_20by3",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_max_width,
            {
                "Max Width",
                "rtcp.psfb.ms.vsr.entry.max_width",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_max_height,
            {
                "Max Height",
                "rtcp.psfb.ms.vsr.entry.max_height",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_min_bitrate,
            {
                "Min bit rate",
                "rtcp.psfb.ms.vsr.entry.min_bitrate",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_bitrate_per_level,
            {
                "Bit rate per level",
                "rtcp.psfb.ms.vsr.entry.bitrate_per_level",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_bitrate_histogram,
            {
                "Receiver Count",
                "rtcp.psfb.ms.vsr.entry.bitrate_histogram",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_mask,
            {
                "Frame rate mask",
                "rtcp.psfb.ms.vsr.entry.frame_rate_mask",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_7_5,
            {
                "7.5 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_7_5",
                FT_BOOLEAN,
                8,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_12_5,
            {
                "12.5 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_12_5",
                FT_BOOLEAN,
                8,
                NULL,
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_15,
            {
                "15 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_15",
                FT_BOOLEAN,
                8,
                NULL,
                0x04,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_25,
            {
                "25 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_25",
                FT_BOOLEAN,
                8,
                NULL,
                0x08,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_30,
            {
                "30 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_30",
                FT_BOOLEAN,
                8,
                NULL,
                0x10,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_50,
            {
                "50 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_50",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_60,
            {
                "60 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_60",
                FT_BOOLEAN,
                8,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_must_instances,
            {
                "Number of MUST instances",
                "rtcp.psfb.ms.vsr.entry.musts",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_may_instances,
            {
                "Number of MAY instances",
                "rtcp.psfb.ms.vsr.entry.mays",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_quality_histogram,
            {
                "Receiver Count",
                "rtcp.psfb.ms.vsr.entry.quality_histogram",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_max_pixels,
            {
                "Max Pixels per Frame",
                "rtcp.psfb.ms.vsr.entry.max_pixels",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_rtcp,
        &ett_rtcp_sr,
        &ett_rtcp_rr,
        &ett_rtcp_sdes,
        &ett_rtcp_bye,
        &ett_rtcp_app,
        &ett_rtcp_rtpfb,
        &ett_rtcp_psfb,
        &ett_rtcp_xr,
        &ett_rtcp_fir,
        &ett_rtcp_nack,
        &ett_ssrc,
        &ett_ssrc_item,
        &ett_ssrc_ext_high,
        &ett_sdes,
        &ett_sdes_item,
        &ett_PoC1,
        &ett_mux,
        &ett_rtcp_setup,
        &ett_rtcp_roundtrip_delay,
        &ett_xr_block,
        &ett_xr_block_contents,
        &ett_xr_ssrc,
        &ett_xr_loss_chunk,
        &ett_poc1_conn_contents,
        &ett_rtcp_nack_blp,
        &ett_pse,
        &ett_ms_vsr,
        &ett_ms_vsr_entry,
        &ett_ms_ds
    };

    static ei_register_info ei[] = {
        { &ei_rtcp_bye_reason_not_padded, { "rtcp.bye_reason_not_padded", PI_MALFORMED, PI_WARN, "Reason string is not NULL padded (see RFC3550, section 6.6)", EXPFILL }},
        { &ei_rtcp_xr_block_length_bad, { "rtcp.invalid_block_length", PI_PROTOCOL, PI_WARN, "Invalid block length, should be 2", EXPFILL }},
        { &ei_rtcp_roundtrip_delay, { "rtcp.roundtrip-delay.expert", PI_SEQUENCE, PI_NOTE, "RTCP round-trip delay detected (%d ms)", EXPFILL }},
        { &ei_rtcp_roundtrip_delay_negative, { "rtcp.roundtrip-delay.negative", PI_SEQUENCE, PI_ERROR, "Negative RTCP round-trip delay detected (%d ms)", EXPFILL }},
        { &ei_rtcp_length_check, { "rtcp.length_check.bad", PI_MALFORMED, PI_WARN, "Incorrect RTCP packet length information (expected %u bytes, found %d)", EXPFILL }},
        { &ei_rtcp_psfb_ms_type, { "rtcp.psfb.ms.afb_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown Application Layer Feedback Type", EXPFILL }},
        { &ei_rtcp_missing_sender_ssrc, { "rtcp.missing_sender_ssrc", PI_PROTOCOL, PI_WARN, "Missing Sender SSRC", EXPFILL }},
        { &ei_rtcp_missing_block_header, { "rtcp.missing_block_header", PI_PROTOCOL, PI_WARN, "Missing Required Block Headers", EXPFILL }},
        { &ei_rtcp_block_length, { "rtcp.block_length.invalid", PI_PROTOCOL, PI_WARN, "Block length is greater than packet length", EXPFILL }},
        { &ei_srtcp_encrypted_payload, { "srtcp.encrypted_payload", PI_UNDECODED, PI_WARN, "Encrypted RTCP Payload - not dissected", EXPFILL }},
    };

    module_t *rtcp_module;
    expert_module_t* expert_rtcp;

    proto_rtcp = proto_register_protocol("Real-time Transport Control Protocol",
                                             "RTCP", "rtcp");
    proto_register_field_array(proto_rtcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rtcp = expert_register_protocol(proto_rtcp);
    expert_register_field_array(expert_rtcp, ei, array_length(ei));

    register_dissector("rtcp", dissect_rtcp, proto_rtcp);

    rtcp_module = prefs_register_protocol(proto_rtcp, NULL);

    prefs_register_bool_preference(rtcp_module, "show_setup_info",
        "Show stream setup information",
        "Where available, show which protocol and frame caused "
        "this RTCP stream to be created",
        &global_rtcp_show_setup_info);

    prefs_register_obsolete_preference(rtcp_module, "heuristic_rtcp");

    prefs_register_bool_preference(rtcp_module, "show_roundtrip_calculation",
        "Show relative roundtrip calculations",
        "Try to work out network delay by comparing time between packets "
        "as captured and delays as seen by endpoint",
        &global_rtcp_show_roundtrip_calculation);

    prefs_register_uint_preference(rtcp_module, "roundtrip_min_threshhold",
        "Minimum roundtrip calculation to report (ms)",
        "Minimum (absolute) calculated roundtrip delay time in milliseconds that "
        "should be reported",
        10, &global_rtcp_show_roundtrip_calculation_minimum);

    /* Register table for sub-dissetors */
    rtcp_dissector_table = register_dissector_table("rtcp.app.name", "RTCP Application Name", proto_rtcp, FT_STRING, BASE_NONE);
    rtcp_psfb_dissector_table = register_dissector_table("rtcp.psfb.fmt", "RTCP Payload Specific Feedback Message Format", proto_rtcp, FT_UINT8, BASE_DEC);
    rtcp_rtpfb_dissector_table = register_dissector_table("rtcp.rtpfb.fmt", "RTCP Generic RTP Feedback Message Format", proto_rtcp, FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_rtcp(void)
{
    /*
     * Register this dissector as one that can be selected by a
     * UDP port number.
     */
    rtcp_handle = find_dissector("rtcp");
    dissector_add_for_decode_as("udp.port", rtcp_handle);
    dissector_add_for_decode_as("flip.payload", rtcp_handle );

    heur_dissector_add( "udp", dissect_rtcp_heur_udp, "RTCP over UDP", "rtcp_udp", proto_rtcp, HEURISTIC_ENABLE);
    heur_dissector_add("stun", dissect_rtcp_heur, "RTCP over TURN", "rtcp_stun", proto_rtcp, HEURISTIC_ENABLE);
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
