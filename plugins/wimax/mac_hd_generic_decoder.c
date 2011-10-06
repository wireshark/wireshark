/* mac_hd_generic_decoder.c
 * WiMax Generic MAC Header decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* TODO:  Add FT_UINT24 and FT_INT24 cases to gtk_widget_get_toplevel()
 * to prevent having to make all the changes from BASE_DEC to BASE_HEX
 * made to this file today: 10/20/06.
 */

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
#define DEBUG
*/

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/address.h>
#include <epan/reassemble.h>
#include "crc.h"
#include "wimax_utils.h"

extern gint proto_wimax;

extern gint seen_a_service_type;
extern gboolean first_gmh;			/* defined in wimax_pdu_decoder.c */

extern gint8 arq_enabled;                       /* declared in packet-wmx.c */
extern gint  scheduling_service_type;           /* declared in packet-wmx.c */
extern gint  mac_sdu_length;                    /* declared in packet-wmx.c */

extern address bs_address;			/* declared in packet-wmx.c */
extern guint max_logical_bands;			/* declared in wimax_compact_dlmap_ie_decoder.c */
extern gboolean is_down_link(packet_info *pinfo);/* declared in packet-wmx.c */
extern void proto_register_mac_mgmt_msg(void);  /* defined in macmgmtmsgdecoder.c */
extern void init_wimax_globals(void);		/* defined in msg_ulmap.c */

extern void dissect_mac_mgmt_msg_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* global variables */
gboolean include_cor2_changes = FALSE;

/* Well-known CIDs */
guint cid_initial_ranging  = 0x0000;
guint global_cid_max_basic = 320;
guint cid_max_primary      = 640;
guint cid_aas_ranging      = 0xFeFF;
guint cid_normal_multicast = 0xFFFa;
guint cid_sleep_multicast  = 0xFFFb;
guint cid_idle_multicast   = 0xFFFc;
guint cid_frag_broadcast   = 0xFFFd;
guint cid_padding          = 0xFFFe;
guint cid_broadcast        = 0xFFFF;

/* Maximum number of CID's */
#define MAX_CID 64

/* forward reference */
static gint extended_subheader_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint arq_feedback_payload_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *parent_item);

/* Static variables */
static GHashTable *payload_frag_table = NULL;

gint proto_mac_header_generic_decoder = -1;
static gint ett_mac_header_generic_decoder = -1;
/* static gint ett_mac_subheader_decoder = -1; */
static gint ett_mac_mesh_subheader_decoder = -1;
static gint ett_mac_frag_subheader_decoder = -1;
static gint ett_mac_grant_mgmt_subheader_decoder = -1;
static gint ett_mac_pkt_subheader_decoder = -1;
static gint ett_mac_fast_fb_subheader_decoder = -1;
static gint ett_mac_ext_subheader_decoder = -1;
static gint ett_mac_ext_subheader_dl_decoder = -1;
static gint ett_mac_ext_subheader_ul_decoder = -1;
static gint ett_mac_arq_fb_payload_decoder = -1;
static gint ett_mac_data_pdu_decoder = -1;
static gint hf_mac_header_generic_value_bytes = -1;

static guint frag_type, frag_len;
static guint extended_type, arq_fb_payload, seq_number;

static guint cid_adjust[MAX_CID];  /* Must not start with 0 */
static guint cid_vernier[MAX_CID];
static guint cid_adj_array_size = 0;
static guint *cid_adj_array = NULL;
static guint8 *frag_num_array = NULL;

static address save_src;
static address save_dst;

#define WIMAX_MAC_HEADER_SIZE      6
#define IP_HEADER_BYTE 0x45

#define EXTENDED_SUB_HEADER_RSV_MASK   0x80
#define EXTENDED_SUB_HEADER_TYPE_MASK  0x7F

/* WIMAX GENERIC MAC HEADER FIELDS (figure 19) */
/* 1st to 3rd bytes */
#define WIMAX_MAC_HEADER_GENERIC_HT           0x800000
#define WIMAX_MAC_HEADER_GENERIC_EC           0x400000
#define WIMAX_MAC_HEADER_GENERIC_TYPE_5       0x200000
#define WIMAX_MAC_HEADER_GENERIC_TYPE_4       0x100000
#define WIMAX_MAC_HEADER_GENERIC_TYPE_3       0x080000
#define WIMAX_MAC_HEADER_GENERIC_TYPE_2       0x040000
#define WIMAX_MAC_HEADER_GENERIC_TYPE_1       0x020000
#define WIMAX_MAC_HEADER_GENERIC_TYPE_0       0x010000
#define WIMAX_MAC_HEADER_GENERIC_ESF          0x008000
#define WIMAX_MAC_HEADER_GENERIC_CI           0x004000
#define WIMAX_MAC_HEADER_GENERIC_EKS          0x003000
#define WIMAX_MAC_HEADER_GENERIC_RSV          0x000800
#define WIMAX_MAC_HEADER_GENERIC_LEN          0x0007FF

/* WIMAX GENERIC MAC HEADER 1st byte masks */
#define WIMAX_MAC_HEADER_GENERIC_HT_MASK     0x80
#define WIMAX_MAC_HEADER_GENERIC_EC_MASK     0x40
#define WIMAX_MAC_HEADER_GENERIC_TYPE_MASK   0x3F
/* WiMax Generic MAC Header Sub Type Masks */
#define GENERIC_SUB_TYPE_0         0x01
#define GENERIC_SUB_TYPE_1         0x02
#define GENERIC_SUB_TYPE_2         0x04
#define GENERIC_SUB_TYPE_3         0x08
#define GENERIC_SUB_TYPE_4         0x10
#define GENERIC_SUB_TYPE_5         0x20

/* WIMAX GENERIC MAC HEADER 2nd byte masks */
#define WIMAX_MAC_HEADER_GENERIC_ESF_MASK    0x80
#define WIMAX_MAC_HEADER_GENERIC_CI_MASK     0x40
#define WIMAX_MAC_HEADER_GENERIC_EKS_MASK    0x30
#define WIMAX_MAC_HEADER_GENERIC_LEN_MASK    0x07

static int hf_mac_header_generic_ht = -1;
static int hf_mac_header_generic_ec = -1;
static int hf_mac_header_generic_type_0 = -1;
static int hf_mac_header_generic_type_1 = -1;
static int hf_mac_header_generic_type_2 = -1;
static int hf_mac_header_generic_type_3 = -1;
static int hf_mac_header_generic_type_4 = -1;
static int hf_mac_header_generic_type_5 = -1;
static int hf_mac_header_generic_esf = -1;
static int hf_mac_header_generic_ci = -1;
static int hf_mac_header_generic_eks = -1;
static int hf_mac_header_generic_rsv = -1;
static int hf_mac_header_generic_len = -1;
static int hf_mac_header_generic_cid = -1;
static int hf_mac_header_generic_hcs = -1;
static int hf_mac_header_generic_crc = -1;

/* MAC Header types */
static const value_string ht_msgs[] =
{
	{ 0, "Generic" },
	{ 1, "Signaling" },
	{ 0,  NULL}
};

/* Encryption Controls */
static const value_string ec_msgs[] =
{
	{ 0, "Not encrypted" },
	{ 1, "Encrypted" },
	{ 0,  NULL}
};

/* ESF messages */
static const value_string esf_msgs[] =
{
	{ 0, "Extended subheader is absent" },
	{ 1, "Extended subheader is present" },
	{ 0,  NULL}
};

/* CRC Indicator messages */
static const value_string ci_msgs[] =
{
	{ 0, "No CRC is included" },
	{ 1, "CRC is included" },
	{ 0,  NULL}
};

/* Sub-Type message 0 */
static const value_string type_msg0[] =
{
	{ 0, "Fast-feedback allocation subheader(DL)/Grant management subheader(UL) is absent" },
	{ 1, "Fast-feedback allocation subheader(DL)/Grant management subheader(UL) is present" },
	{ 0,  NULL}
};

/* Sub-Type message 1 */
static const value_string type_msg1[] =
{
	{ 0, "Packing subheader is absent" },
	{ 1, "Packing Subheader is present" },
	{ 0,  NULL}
};

/* Sub-Type message 2 */
static const value_string type_msg2[] =
{
	{ 0, "Fragmentation subheader is absent" },
	{ 1, "Fragmentation subheader is present" },
	{ 0,  NULL}
};

/* Sub-Type message 3 */
static const value_string type_msg3[] =
{
	{ 0, "The subheader is not extended" },
	{ 1, "The subheader is extended" },
	{ 0,  NULL}
};

/* Sub-Type message 4 */
static const value_string type_msg4[] =
{
	{ 0, "ARQ feedback payload is absent" },
	{ 1, "ARQ feedback payload is present" },
	{ 0,  NULL}
};

/* Sub-Type message 5 */
static const value_string type_msg5[] =
{
	{ 0, "Mesh subheader is absent" },
	{ 1, "Mesh subheader is present" },
	{ 0,  NULL}
};

/* Fast-Feedback Feedback Types */
static const value_string fast_fb_types[] =
{
	{ 0, "Fast DL measurement" },
	{ 1, "Fast MIMO Feedback, Antenna #0" },
	{ 2, "Fast MIMO Feedback, Antenna #1" },
	{ 3, "MIMO Mode and Permutation Mode Feedback" },
	{ 0,  NULL}
};

/* Extended sub-headers */
/* DL sub-header types */
enum
{
SDU_SN,
DL_SLEEP_CONTROL,
FEEDBACK_REQ,
SN_REQ,
PDU_SN_SHORT_DL,
PDU_SN_LONG_DL
} DL_EXT_SUBHEADER;

static const value_string dl_ext_sub_header_type[] =
{
	{0, "SDU_SN"},
	{1, "DL Sleep Control"},
	{2, "Feedback Request"},
	{3, "SN Request"},
	{4, "PDU SN (short)"},
	{5, "PDU SN (long)"},
	{0,  NULL}
};

/* DL Sleep Control Extended Subheader field masks (table 13e) */
#define DL_SLEEP_CONTROL_POWER_SAVING_CLASS_ID_MASK       0xFC0000	/*0x00003F*/
#define DL_SLEEP_CONTROL_OPERATION_MASK                   0x020000	/*0x000040*/
#define DL_SLEEP_CONTROL_FINAL_SLEEP_WINDOW_EXPONENT_MASK 0x01C000	/*0x000380*/
#define DL_SLEEP_CONTROL_FINAL_SLEEP_WINDOW_BASE_MASK     0x003FF0	/*0x0FFC00*/
#define DL_SLEEP_CONTROL_RESERVED_MASK                    0x00000F	/*0xF00000*/

/* Feedback Request Extended Subheader field masks (table 13f) */
#define FEEDBACK_REQUEST_UIUC_MASK                        0xF00000	/*0x00000F*/
#define FEEDBACK_REQUEST_FEEDBACK_TYPE_MASK               0x0F0000	/*0x0000F0*/
#define FEEDBACK_REQUEST_OFDMA_SYMBOL_OFFSET_MASK         0x00FC00	/*0x003F00*/
#define FEEDBACK_REQUEST_SUBCHANNEL_OFFSET_MASK           0x0003F0	/*0x0FC000*/
#define FEEDBACK_REQUEST_NUMBER_OF_SLOTS_MASK             0x00000E	/*0x700000*/
#define FEEDBACK_REQUEST_FRAME_OFFSET_MASK                0x000001	/*0x800000*/

/* OFDMA UIUC Values ??? */
static const value_string uiuc_values[] =
{
	{ 0, "Fast-Feedback Channel" },
	{ 1, "Burst Profile 1" },
	{ 2, "Burst Profile 2" },
	{ 3, "Burst Profile 3" },
	{ 4, "Burst Profile 4" },
	{ 5, "Burst Profile 5" },
	{ 6, "Burst Profile 6" },
	{ 7, "Burst Profile 7" },
	{ 8, "Burst Profile 8" },
	{ 9, "Burst Profile 9" },
	{ 10, "Burst Profile 10" },
	{ 11, "Extended UIUC 2 IE" },
	{ 12, "CDMA Bandwidth Request, CDMA Ranging" },
	{ 13, "PAPR Reduction Allocation, Safety Zone" },
	{ 14, "CDMA Allocation IE" },
	{ 15, "Extended UIUC" },
	{ 0,  NULL}
};

/* UL sub-header types */
enum
{
MIMO_MODE_FEEDBACK,
UL_TX_POWER_REPORT,
MINI_FEEDBACK,
PDU_SN_SHORT_UL,
PDU_SN_LONG_UL
} UL_EXT_SUBHEADER;

static const value_string ul_ext_sub_header_type[] =
{
	{0, "MIMO Mode Feedback"},
	{1, "UL TX Power Report"},
	{2, "Mini-feedback"},
	{3, "PDU SN (short)"},
	{4, "PDU SN (long)"},
	{0,  NULL}
};

/* MIMO Mode Feedback Extended Subheader field masks (table 13g) */
#define MIMO_FEEDBACK_TYPE_MASK                  0xC0	/*0x03*/
#define MIMO_FEEDBACK_CONTENT_MASK               0x3F	/*0xFC*/
/* Mimo Feedback Types ??? */
static const value_string mimo_fb_types[] =
{
	{ 0, "Fast DL measurement" },
	{ 1, "Default Feedback with Antenna Grouping" },
	{ 2, "Antenna Selection and Reduced Codebook" },
	{ 3, "Quantized Precoding Weight Feedback" },
	{ 0,  NULL}
};

/* MNI-Feedback Extended Subheader field masks (table 13i) */
#define MINI_FEEDBACK_TYPE_MASK                  0xF000	/*0x000F*/
#define MINI_FEEDBACK_CONTENT_MASK               0x0FFF	/*0xFFF0*/
/* Feedback Types */
static const value_string fb_types[] =
{
	{ 0, "CQI and MIMO Feedback" },
	{ 1, "DL average CINR" },
	{ 2, "MIMO Coefficients Feedback" },
	{ 3, "Preferred DL Channel DIUC Feedback" },
	{ 4, "UL Transmission Power" },
	{ 5, "PHY Channel Feedback" },
	{ 6, "AMC Band Indication Bitmap" },
	{ 7, "Life Span of Short-term Precoding Feedback" },
	{ 8, "Multiple Types of Feedback" },
	{ 9, "Long-term Precoding Feedback" },
 	{ 10, "Combined DL Average CINR of Active BSs" },
	{ 11, "MIMO Channel Feedback" },
	{ 12, "CINR Feedback" },
	{ 13, "Close-loop MIMO Feedback" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0,  NULL}
};

/* common fields */
static gint hf_mac_header_generic_ext_subheader_rsv = -1;
/* DL sub-header */
static gint hf_mac_header_generic_ext_subheader_type_dl = -1;
static gint hf_mac_header_generic_ext_subheader_sdu_sn = -1;
static gint hf_mac_header_generic_ext_subheader_dl_sleep_control_pscid = -1;
static gint hf_mac_header_generic_ext_subheader_dl_sleep_control_op = -1;
static gint hf_mac_header_generic_ext_subheader_dl_sleep_control_fswe = -1;
static gint hf_mac_header_generic_ext_subheader_dl_sleep_control_fswb = -1;
static gint hf_mac_header_generic_ext_subheader_dl_sleep_control_rsv = -1;
static gint hf_mac_header_generic_ext_subheader_fb_req_uiuc = -1;
static gint hf_mac_header_generic_ext_subheader_fb_req_fb_type = -1;
static gint hf_mac_header_generic_ext_subheader_fb_req_ofdma_symbol_offset = -1;
static gint hf_mac_header_generic_ext_subheader_fb_req_subchannel_offset = -1;
static gint hf_mac_header_generic_ext_subheader_fb_req_slots = -1;
static gint hf_mac_header_generic_ext_subheader_fb_req_frame_offset = -1;

/* DL Sleep Control Operations */
static const value_string dl_sleep_control_ops[] =
{
	{ 0, "De-activate Power Saving Class" },
	{ 1, "Activate Power Saving Class" },
	{ 0,  NULL}
};

/* UL sub-header */
static gint hf_mac_header_generic_ext_subheader_type_ul = -1;
static gint hf_mac_header_generic_ext_subheader_mimo_mode_fb_type = -1;
static gint hf_mac_header_generic_ext_subheader_mimo_fb_content = -1;
static gint hf_mac_header_generic_ext_subheader_ul_tx_pwr_rep = -1;
static gint hf_mac_header_generic_ext_subheader_mini_fb_type = -1;
static gint hf_mac_header_generic_ext_subheader_mini_fb_content = -1;
/* common fields */
static gint hf_mac_header_generic_ext_subheader_pdu_sn_short = -1;
static gint hf_mac_header_generic_ext_subheader_pdu_sn_long = -1;

/* SN Request subheader */
#define SN_REQUEST_SUBHEADER_SN_REPORT_INDICATION_1_MASK 0x01
#define SN_REQUEST_SUBHEADER_SN_REPORT_INDICATION_2_MASK 0x02
#define SN_REQUEST_SUBHEADER_RESERVED_MASK               0xFC

static gint hf_mac_header_generic_ext_subheader_sn_req_rep_ind_1 = -1;
static gint hf_mac_header_generic_ext_subheader_sn_req_rep_ind_2 = -1;
static gint hf_mac_header_generic_ext_subheader_sn_req_rsv = -1;
/* SN Report Indication message */
static const value_string sn_rep_msg[] =
{
	{ 0, "" },
	{ 1, "request transmission" },
	{ 0,  NULL}
};

/* Mesh Subheader */
static gint hf_mac_header_generic_mesh_subheader = -1;

/* Fragmentation Subheader (table 8) */
#define FRAGMENTATION_SUBHEADER_FC_MASK         0xC000	/*0x0003*/
#define FRAGMENTATION_SUBHEADER_BSN_MASK        0x3FF8	/*0x1FFC*/
#define FRAGMENTATION_SUBHEADER_RSV_EXT_MASK    0x0007	/*0xE000*/
#define FRAGMENTATION_SUBHEADER_FSN_MASK        0x38	/*0x1C*/
#define FRAGMENTATION_SUBHEADER_RSV_MASK        0x07	/*0xE0*/
#define FRAGMENT_TYPE_MASK  0xC0
#define SEQ_NUMBER_MASK     0x38
#define SEQ_NUMBER_MASK_11  0x3FF8

#define NO_FRAG     0
#define LAST_FRAG   1
#define FIRST_FRAG  2
#define MIDDLE_FRAG 3

static gint hf_mac_header_generic_frag_subhd_fc = -1;
static gint hf_mac_header_generic_frag_subhd_fc_ext = -1;
static gint hf_mac_header_generic_frag_subhd_bsn = -1;
static gint hf_mac_header_generic_frag_subhd_fsn = -1;
static gint hf_mac_header_generic_frag_subhd_fsn_ext = -1;
static gint hf_mac_header_generic_frag_subhd_rsv = -1;
static gint hf_mac_header_generic_frag_subhd_rsv_ext = -1;

/* Fragment Types */
static const value_string frag_types[] =
{
	{ 0, "No fragmentation" },
	{ 1, "Last fragment" },
	{ 2, "First fragment" },
	{ 3, "Continuing (middle) fragment" },
	{ 0,  NULL}
};

/* Packing Subheader (table 11) */
#define PACKING_SUBHEADER_FC_MASK           0xC00000
#define PACKING_SUBHEADER_BSN_MASK          0x3FF800
#define PACKING_SUBHEADER_FSN_MASK          0x38
#define PACKING_SUBHEADER_LENGTH_MASK       0x07FF
#define PACKING_SUBHEADER_LENGTH_EXT_MASK   0x0007FF

#define FRAG_LENGTH_MASK    0x0007FF00

static gint hf_mac_header_generic_packing_subhd_fc = -1;
static gint hf_mac_header_generic_packing_subhd_fc_ext = -1;
static gint hf_mac_header_generic_packing_subhd_bsn = -1;
static gint hf_mac_header_generic_packing_subhd_fsn = -1;
static gint hf_mac_header_generic_packing_subhd_fsn_ext = -1;
static gint hf_mac_header_generic_packing_subhd_len = -1;
static gint hf_mac_header_generic_packing_subhd_len_ext = -1;

/* Fast-feedback Allocation Subheader (table 13) */
#define FAST_FEEDBACK_ALLOCATION_OFFSET_MASK 0xFC	/*0x3F*/
#define FAST_FEEDBACK_FEEDBACK_TYPE_MASK     0x03	/*0xC0*/

static gint hf_mac_header_generic_fast_fb_subhd_alloc_offset = -1;
static gint hf_mac_header_generic_fast_fb_subhd_fb_type = -1;

/* Grant Management Subheader (table 9 & 10) */
#define GRANT_MGMT_SUBHEADER_UGS_SI_MASK          0x8000	/*0x0001*/
#define GRANT_MGMT_SUBHEADER_UGS_PM_MASK          0x4000	/*0x0002*/
#define GRANT_MGMT_SUBHEADER_UGS_FLI_MASK         0x2000	/*0x0004*/
#define GRANT_MGMT_SUBHEADER_UGS_FL_MASK          0x1E00	/*0x0078*/
#define GRANT_MGMT_SUBHEADER_UGS_RSV_MASK         0x01FF	/*0xFF80*/
#define GRANT_MGMT_SUBHEADER_EXT_PBR_MASK         0xFFE0	/*0x07FF*/
#define GRANT_MGMT_SUBHEADER_EXT_FLI_MASK         0x0010	/*0x0800*/
#define GRANT_MGMT_SUBHEADER_EXT_FL_MASK          0x000F	/*0xF000*/

enum
{
	SCHEDULE_SERVICE_TYPE_RSVD,
	SCHEDULE_SERVICE_TYPE_UNDEFINED,
	SCHEDULE_SERVICE_TYPE_BE,
	SCHEDULE_SERVICE_TYPE_NRTPS,
	SCHEDULE_SERVICE_TYPE_RTPS,
	SCHEDULE_SERVICE_TYPE_EXT_RTPS,
	SCHEDULE_SERVICE_TYPE_UGS
} SCHEDULE_SERVICE_TYPE;

static gint hf_mac_header_generic_grant_mgmt_ugs_tree 		= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_ugs_si 	= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_ugs_pm	= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_ugs_fli	= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_ugs_fl	= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_ugs_rsv	= -1;
static gint hf_mac_header_generic_grant_mgmt_ext_rtps_tree	= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_ext_pbr	= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_ext_fli	= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_ext_fl	= -1;
static gint hf_mac_header_generic_grant_mgmt_ext_pbr_tree	= -1;
static gint hf_mac_header_generic_grant_mgmt_subhd_pbr		= -1;

/* Slip Indicators */
static const value_string si_msgs[] =
{
	{ 0, "No action" },
	{ 1, "A slip of UL grants relative to the UL queue depth" },
	{ 0,  NULL}
};

/* Poll-Me Messages */
static const value_string pm_msgs[] =
{
	{ 0, "No action" },
	{ 1, "Request a bandwidth poll" },
	{ 0,  NULL}
};

/* Frame Latency Indications */
static const value_string fli_msgs[] =
{
	{ 0, "Frame latency field disabled" },
	{ 1, "Frame latency field enabled" },
	{ 0,  NULL}
};

/* ARQ Feedback Payload */

/* ARQ Feedback IE bit masks (table 111) */
#define ARQ_FB_IE_LAST_BIT_MASK      0x8000	/*0x0001*/
#define ARQ_FB_IE_ACK_TYPE_MASK      0x6000	/*0x0006*/
#define ARQ_FB_IE_BSN_MASK           0x1FFC	/*0x3FF8*/
#define ARQ_FB_IE_NUM_MAPS_MASK      0x0003	/*0xC000*/
#define ARQ_FB_IE_SEQ_FORMAT_MASK    0x8000	/*0x0001*/
#define ARQ_FB_IE_SEQ_ACK_MAP_MASK   0x7000	/*0x000E*/
#define ARQ_FB_IE_SEQ1_LENGTH_MASK   0x0F00	/*0x00F0*/
#define ARQ_FB_IE_SEQ2_LENGTH_MASK   0x00F0	/*0x0F00*/
#define ARQ_FB_IE_SEQ3_LENGTH_MASK   0x000F	/*0xF000*/
#define ARQ_FB_IE_SEQ_ACK_MAP_2_MASK 0x6000	/*0x0006*/
#define ARQ_FB_IE_SEQ1_LENGTH_6_MASK 0x1F80	/*0x01F8*/
#define ARQ_FB_IE_SEQ2_LENGTH_6_MASK 0x007E	/*0x7E00*/
#define ARQ_FB_IE_RSV_MASK           0x0001	/*0x8000*/

static gint hf_mac_header_generic_arq_fb_ie_cid = -1;
static gint hf_mac_header_generic_arq_fb_ie_last = -1;
static gint hf_mac_header_generic_arq_fb_ie_ack_type = -1;
static gint hf_mac_header_generic_arq_fb_ie_bsn = -1;
static gint hf_mac_header_generic_arq_fb_ie_num_maps = -1;
static gint hf_ack_type_reserved = -1;
static gint hf_mac_header_generic_arq_fb_ie_sel_ack_map = -1;
static gint hf_mac_header_generic_arq_fb_ie_seq_format = -1;
static gint hf_mac_header_generic_arq_fb_ie_seq_ack_map = -1;
static gint hf_mac_header_generic_arq_fb_ie_seq1_length = -1;
static gint hf_mac_header_generic_arq_fb_ie_seq2_length = -1;
static gint hf_mac_header_generic_arq_fb_ie_seq3_length = -1;
static gint hf_mac_header_generic_arq_fb_ie_seq_ack_map_2 = -1;
static gint hf_mac_header_generic_arq_fb_ie_seq1_length_6 = -1;
static gint hf_mac_header_generic_arq_fb_ie_seq2_length_6 = -1;
static gint hf_mac_header_generic_arq_fb_ie_rsv = -1;

/* Last IE Indicators */
static const value_string last_ie_msgs[] =
{
	{ 0, "No" },
	{ 1, "Yes" },
	{ 0,  NULL}
};

/* Register Wimax defrag table init routine. */
void wimax_defragment_init(void)
{
	gint i;

	fragment_table_init(&payload_frag_table);

	/* Init fragmentation variables. */
	for (i = 0; i < MAX_CID; i++)
	{
		cid_adjust[i] = 1;	/* Must not start with 0 */
		cid_vernier[i] = 0;
	}
	cid_adj_array_size = 0;
	/* Free the array memory. */
	if (cid_adj_array) {
		g_free(cid_adj_array);
	}
	cid_adj_array = NULL;
	if (frag_num_array) {
		g_free(frag_num_array);
	}
	frag_num_array = NULL;

	/* Initialize to make sure bs_address gets set in FCH decoder. */
	bs_address.len = 0;

	/* Initialize the Scheduling Service Type flag */
	seen_a_service_type = 0;

	max_logical_bands = 12;

	/* Initialize UL_MAP globals. */
	init_wimax_globals();
}

static guint decode_packing_subheader(tvbuff_t *payload_tvb, packet_info *pinfo, proto_tree *tree, guint payload_length, guint payload_offset, proto_item *parent_item)
{
	proto_item *generic_item = NULL;
	proto_tree *generic_tree = NULL;
	guint starting_offset = payload_offset;

	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Packing subhdr");
	/* add the Packing subheader info */
	proto_item_append_text(parent_item, ", Packing Subheader");
	/* display Packing subheader type */
	generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, payload_tvb, payload_offset, ((arq_enabled|extended_type)?3:2), "Packing subheader (%u bytes)", ((arq_enabled|extended_type)?3:2));
	/* add Packing subheader subtree */
	generic_tree = proto_item_add_subtree(generic_item, ett_mac_pkt_subheader_decoder);
	/* decode and display the Packing subheader */
	/* Get the fragment type */
	frag_type = (tvb_get_guint8(payload_tvb, payload_offset) & FRAGMENT_TYPE_MASK) >> 6;
	/* if ARQ Feedback payload is present */
	if (arq_fb_payload)
	{	/* get the frag length */
		frag_len = ((tvb_get_ntohl(payload_tvb, payload_offset) & FRAG_LENGTH_MASK) >> 8);
		/* get the sequence number */
		seq_number = (tvb_get_ntohs(payload_tvb, payload_offset) & SEQ_NUMBER_MASK_11) >> 3;
		proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_fc_ext, payload_tvb, payload_offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_bsn, payload_tvb, payload_offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_len_ext, payload_tvb, payload_offset, 3, ENC_BIG_ENDIAN);
		/* update the length and offset */
		payload_length -= 3;
		payload_offset += 3;
		frag_len -= 3;
	}
	else
	{
		if (extended_type)
		{	/* get the frag length */
			frag_len = ((tvb_get_ntohl(payload_tvb, payload_offset) & FRAG_LENGTH_MASK) >> 8);
			/* get the sequence number */
			seq_number = (tvb_get_ntohs(payload_tvb, payload_offset) & SEQ_NUMBER_MASK_11) >> 3;
			proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_fc_ext, payload_tvb, payload_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_fsn_ext, payload_tvb, payload_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_len_ext, payload_tvb, payload_offset, 3, ENC_BIG_ENDIAN);
			/* update the length and offset */
			payload_length -= 3;
			payload_offset += 3;
			frag_len -= 3;
		}
		else
		{	/* get the frag length */
			frag_len = (tvb_get_ntohs(payload_tvb, payload_offset) & PACKING_SUBHEADER_LENGTH_MASK);
			/* get the sequence number */
			seq_number = (tvb_get_guint8(payload_tvb, payload_offset) & SEQ_NUMBER_MASK) >> 3;
			proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_fc, payload_tvb, payload_offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_fsn, payload_tvb, payload_offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(generic_tree, hf_mac_header_generic_packing_subhd_len, payload_tvb, payload_offset, 2, ENC_BIG_ENDIAN);
			/* update the length and offset */
			payload_length -= 2;
			payload_offset += 2;
			frag_len -= 2;
		}
	}
	/* Prevent a crash! */
	if ((gint)frag_len < 0)
		frag_len = 0;
	/* Return the number of bytes decoded. */
	return payload_offset - starting_offset;
}


void dissect_mac_header_generic_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint payload_offset;
	guint payload_length = 0;

	static guint8 frag_number[MAX_CID];
	static guint cid_list[MAX_CID];
	static guint cid_base;
	static char *reassem_str = "Reassembled Data transport PDU (%u bytes)";
	static char *data_str = "Data transport PDU (%u bytes)";
	char *str_ptr;
	gint length, i, cid_index;
	guint tvb_len, ret_length, ubyte, new_tvb_len;
	guint new_payload_len = 0;
	guint /*mac_ht,*/ mac_ec, mac_esf, mac_ci, /*mac_eks,*/ mac_len, mac_cid, cid;
	guint ffb_grant_mgmt_subheader, packing_subheader, fragment_subheader;
	guint mesh_subheader;
	guint packing_length;
	guint32 mac_crc, calculated_crc;
	proto_item *parent_item = NULL;
	proto_item *generic_item = NULL;
	proto_tree *generic_tree = NULL;
	proto_item *child_item = NULL;
	proto_tree *child_tree = NULL;
	tvbuff_t *payload_tvb;
	tvbuff_t *data_pdu_tvb;
	fragment_data *payload_frag;
	gboolean first_arq_fb_payload = TRUE;

	dissector_handle_t mac_payload_handle;

	proto_mac_header_generic_decoder = proto_wimax;
	if (tree)
	{	/* we are being asked for details */
#ifdef DEBUG
		/* update the info column */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "GMH");
#endif
		/* Get the frame length */
		tvb_len =  tvb_reported_length(tvb);
		if (tvb_len < WIMAX_MAC_HEADER_SIZE)
		{	/* display the error message */
			generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, tvb_len, "Error: the size of Generic MAC Header tvb is too small! (%u bytes)", tvb_len);
			/* add subtree */
			generic_tree = proto_item_add_subtree(generic_item, ett_mac_header_generic_decoder);
			/* display the Generic MAC Header in Hex */
			proto_tree_add_item(generic_tree, hf_mac_header_generic_value_bytes, tvb, offset, tvb_len, ENC_NA);
			return;
		}
		/* get the parent */
		parent_item = proto_tree_get_parent(tree);
		/* add the MAC header info */
		proto_item_append_text(parent_item, " - Generic MAC Header");
		/* display MAC header message */
		generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, WIMAX_MAC_HEADER_SIZE, "Generic MAC Header (%u bytes)", WIMAX_MAC_HEADER_SIZE);
		/* add MAC header subtree */
		generic_tree = proto_item_add_subtree(generic_item, ett_mac_header_generic_decoder);
		/* Decode and display the MAC header */
		/* Get the first byte */
		ubyte = tvb_get_guint8(tvb, offset);
		/* get the Header Type (HT) */
		/*mac_ht = ((ubyte & WIMAX_MAC_HEADER_GENERIC_HT_MASK)?1:0); XX: not used ?? */
		/* get the Encryption Control (EC) */
		mac_ec = ((ubyte & WIMAX_MAC_HEADER_GENERIC_EC_MASK)?1:0);
		/* get the sub types */
		ffb_grant_mgmt_subheader = ((ubyte & GENERIC_SUB_TYPE_0)?1:0);
		packing_subheader = ((ubyte & GENERIC_SUB_TYPE_1)?1:0);
		fragment_subheader = ((ubyte & GENERIC_SUB_TYPE_2)?1:0);
		extended_type = ((ubyte & GENERIC_SUB_TYPE_3)?1:0);
		arq_fb_payload = ((ubyte & GENERIC_SUB_TYPE_4)?1:0);
		mesh_subheader = ((ubyte & GENERIC_SUB_TYPE_5)?1:0);
		/* Get the 2nd byte */
		ubyte = tvb_get_guint8(tvb, (offset+1));
		/* get the Extended subheader field (ESF) */
		mac_esf = ((ubyte & WIMAX_MAC_HEADER_GENERIC_ESF_MASK)?1:0);
		/* get the CRC indicator (CI) */
		mac_ci = ((ubyte & WIMAX_MAC_HEADER_GENERIC_CI_MASK)?1:0);
		/* get the Encryption key sequence (EKS) */
		/*mac_eks = ((ubyte & WIMAX_MAC_HEADER_GENERIC_EKS_MASK)>>4); XX: not used ?? */
		/* get the MAC length */
		mac_len = (tvb_get_ntohs(tvb, (offset+1)) & WIMAX_MAC_HEADER_GENERIC_LEN);
		/* get the CID */
		mac_cid = tvb_get_ntohs(tvb, (offset+3));
		/* display the Header Type (HT) */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_ht, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the Encryption Control (EC) */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_ec, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the sub-types (Type) */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_type_5, tvb, offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(generic_tree, hf_mac_header_generic_type_4, tvb, offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(generic_tree, hf_mac_header_generic_type_3, tvb, offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(generic_tree, hf_mac_header_generic_type_2, tvb, offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(generic_tree, hf_mac_header_generic_type_1, tvb, offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(generic_tree, hf_mac_header_generic_type_0, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the Extended sub-header Field (ESF) */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_esf, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the CRC Indicator (CI) */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_ci, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the Encryption Key Sequence (EKS) */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_eks, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the reserved field */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_rsv, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the length */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_len, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* Decode and display the CID */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_cid, tvb, (offset+3), 2, ENC_BIG_ENDIAN);
		/* Decode and display the HCS */
		proto_tree_add_item(generic_tree, hf_mac_header_generic_hcs, tvb, (offset+5), 1, ENC_BIG_ENDIAN);
		/* get the frame length without MAC header */
		length = mac_len - WIMAX_MAC_HEADER_SIZE;
#ifdef DEBUG
		proto_item_append_text(parent_item, "tvb length=%u, mac length=%u, frame length=%u,", tvb_len, mac_len, length);
#endif
		/* set the offset for the frame */
		offset += WIMAX_MAC_HEADER_SIZE;
		/* the processing of the subheaders is order sensitive */
		/* do not change the order */

		if (mac_ec)
		{
			if (mac_ci)
			{
				if (length >= (gint)sizeof(mac_crc))
				{
					length -= sizeof(mac_crc);
				}
			}
			generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, length, "Encrypted PDU (%u bytes)", length);
			/* add payload subtree */
			generic_tree = proto_item_add_subtree(generic_item, ett_mac_data_pdu_decoder);
			proto_tree_add_item(generic_tree, hf_mac_header_generic_value_bytes, tvb, offset, length, ENC_NA);
			goto check_crc;
		}

		/* if Extended subheader is present */
		if (mac_esf)
		{	/* add the Extended subheader info */
			proto_item_append_text(parent_item, ", Extended Subheader(s)");
			ret_length = extended_subheader_decoder(tvb_new_subset(tvb, offset, length, length), pinfo, tree);
			/* update the length and offset */
			length -= ret_length;
			offset += ret_length;
		}
		/* if Mesh subheader is present */
		if (mesh_subheader)
		{	/* update the info column */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Mesh subhdr");
			/* add the Mesh subheader info */
			proto_item_append_text(parent_item, ", Mesh Subheader");
			/* display Mesh subheader type */
			generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, length, "Mesh subheader (2 bytes)");
			/* add Mesh subheader subtree */
			generic_tree = proto_item_add_subtree(generic_item, ett_mac_mesh_subheader_decoder);
			/* decode and display the Mesh subheader */
			proto_tree_add_item(generic_tree, hf_mac_header_generic_mesh_subheader, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* update the length and offset */
			length -= 2;
			offset += 2;
		}
		/* if Fast-feedback allocation (DL) subheader or Grant management (UL) subheader is present */
		if (ffb_grant_mgmt_subheader)
		{	/* check if it is downlink packet */
			if (is_down_link(pinfo))
			{	/* Fast-feedback allocation (DL) subheader is present */
				/* update the info column */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Fast-fb subhdr");
				/* add the Fast-feedback subheader info */
				proto_item_append_text(parent_item, ", Fast-feedback Subheader");
				/* display Fast-feedback allocation subheader type */
				generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, length, "Fast-feedback allocation (DL) subheader (%u bytes)", length);
				/* add Fast-feedback allocation subheader subtree */
				generic_tree = proto_item_add_subtree(generic_item, ett_mac_fast_fb_subheader_decoder);
				proto_tree_add_item(generic_tree, hf_mac_header_generic_fast_fb_subhd_alloc_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(generic_tree, hf_mac_header_generic_fast_fb_subhd_fb_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				/* update the length and offset */
				length -= 1;
				offset += 1;
			}
			else	/* Grant management (UL) subheader is present */
			{	/* update the info column */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Grant mgmt subhdr");
				/* add the Grant management subheader info */
				proto_item_append_text(parent_item, ", Grant Management Subheader");
				/* display Grant management subheader type */
				generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, 2, "Grant management (UL) subheader (2 bytes)");
				/* add Grant management subheader subtree */
				generic_tree = proto_item_add_subtree(generic_item, ett_mac_grant_mgmt_subheader_decoder);
				scheduling_service_type = get_service_type();
				switch (scheduling_service_type)
				{
				case SCHEDULE_SERVICE_TYPE_UGS:
					proto_item_append_text(generic_item, ": It looks like UGS is the correct Scheduling Service Type");
				break;
				case SCHEDULE_SERVICE_TYPE_EXT_RTPS:
					proto_item_append_text(generic_item, ": It looks like Extended rtPS is the correct Scheduling Service Type");
				break;
				case -1:
					proto_item_append_text(generic_item, ": Cannot determine the correct Scheduling Service Type");
				break;
				default:
					proto_item_append_text(generic_item, ": It looks like Piggyback Request is the correct Scheduling Service Type");
				break;
				}
				/* Create tree for Scheduling Service Type (UGS) */
				child_item = proto_tree_add_item(generic_tree, hf_mac_header_generic_grant_mgmt_ugs_tree, tvb, offset, 2, ENC_BIG_ENDIAN);
				child_tree = proto_item_add_subtree(child_item, ett_mac_grant_mgmt_subheader_decoder);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_ugs_si, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_ugs_pm, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_ugs_fli, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_ugs_fl, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_ugs_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);

				/* Create tree for Scheduling Service Type (Extended RTPS) */
				child_item = proto_tree_add_item(generic_tree, hf_mac_header_generic_grant_mgmt_ext_rtps_tree, tvb, offset, 2, ENC_BIG_ENDIAN);
				child_tree = proto_item_add_subtree(child_item, ett_mac_grant_mgmt_subheader_decoder);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_ext_pbr, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_ext_fli, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_ext_fl, tvb, offset, 2, ENC_BIG_ENDIAN);

				/* Create tree for Scheduling Service Type (Piggyback Request) */
				child_item = proto_tree_add_item(generic_tree, hf_mac_header_generic_grant_mgmt_ext_pbr_tree, tvb, offset, 2, ENC_BIG_ENDIAN);
				child_tree = proto_item_add_subtree(child_item, ett_mac_grant_mgmt_subheader_decoder);
				proto_tree_add_item(child_tree, hf_mac_header_generic_grant_mgmt_subhd_pbr, tvb, offset, 2, ENC_BIG_ENDIAN);

				/* update the length and offset */
				length -= 2;
				offset += 2;
			}
		}
		/* if Fragmentation subheader is present */
		if (fragment_subheader)
		{	/* update the info column */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Frag subhdr");
			/* add the Fragmentation subheader info */
			proto_item_append_text(parent_item, ", Frag Subheader");
			/* display Fragmentation subheader type */
			generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, ((arq_enabled|extended_type)?2:1), "Fragmentation subheader (%u bytes)", ((arq_enabled|extended_type)?2:1));
			/* add Fragmentation subheader subtree */
			generic_tree = proto_item_add_subtree(generic_item, ett_mac_frag_subheader_decoder);
			/* Get the fragment type */
			frag_type = (tvb_get_guint8(tvb, offset) & FRAGMENT_TYPE_MASK) >> 6;
			if (arq_fb_payload)
			{	/* get the sequence number */
				seq_number = (tvb_get_ntohs(tvb, offset) & SEQ_NUMBER_MASK_11) >> 3;
				/* decode and display the header */
				proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_fc_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_bsn, tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_rsv_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* update the length and offset */
				length -= 2;
				offset += 2;
			}
			else
			{
				if (extended_type)
				{	/* get the sequence number */
					seq_number = (tvb_get_ntohs(tvb, offset) & SEQ_NUMBER_MASK_11) >> 3;
					/* decode and display the header */
					proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_fc_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_fsn_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_rsv_ext, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* update the length and offset */
					length -= 2;
					offset += 2;
				}
				else
				{	/* get the sequence number */
					seq_number = (tvb_get_guint8(tvb, offset) & SEQ_NUMBER_MASK) >> 3;
					/* decode and display the header */
					proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_fc, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_fsn, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(generic_tree, hf_mac_header_generic_frag_subhd_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
					/* update the length and offset */
					length -= 1;
					offset += 1;
				}
			}
			frag_len = length;
		}
		else	/* ??? default fragment type: no fragment */
		{
			frag_type = NO_FRAG;
		}
		/* Decode the MAC payload if there is any */
		if (mac_ci)
		{
			if (length < (gint)sizeof(mac_crc))
			{	/* display error message */
				proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, length, "Error - the frame is too short (%u bytes)", length);
				return;
			}
			length -= sizeof(mac_crc);
		}
		while (length > 0)
		{
			frag_len = length; /* Can be changed by Packing subhdr */
			if (packing_subheader)
			{
				packing_length = decode_packing_subheader(tvb, pinfo, tree, length, offset, parent_item);
				length -= packing_length;
				offset += packing_length;
				generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, frag_len, "Data transport PDU (%u bytes)", frag_len);
				/* add payload subtree */
				generic_tree = proto_item_add_subtree(generic_item, ett_mac_data_pdu_decoder);
				proto_tree_add_item(generic_tree, hf_mac_header_generic_value_bytes, tvb, offset, frag_len, ENC_NA);
			}
			/* defragment first if it is fragmented */
			if (frag_type == NO_FRAG)
			{	/* not fragmented payload */
				payload_tvb =  tvb_new_subset(tvb, offset, frag_len, frag_len);
				payload_length = frag_len;
				new_payload_len = frag_len;
			}
			else	/* fragmented payload */
			{	/* add the frag */
				/* Make sure cid will not match a previous packet with different data */
				for (i = 0; i < MAX_CID; i++)
				{
					if (cid_list[i] == mac_cid)
					{
						cid_base = i * (0xFFFFFFFF / MAX_CID);
						break;
					}
					if (cid_list[i] == 0)
					{
						cid_list[i] = mac_cid;
						cid_base = i * (0xFFFFFFFF / MAX_CID);
						break;
					}
				}
				cid_index = i;
				while (pinfo->fd->num > cid_adj_array_size)
				{
					cid_adj_array_size += 1024;
					cid_adj_array = g_realloc(cid_adj_array, sizeof(guint) * cid_adj_array_size);
					frag_num_array = g_realloc(frag_num_array, sizeof(guint8) * cid_adj_array_size);
					/* Clear the added memory */
					memset(&cid_adj_array[cid_adj_array_size - 1024], 0, sizeof(guint) * 1024);
				}
				if (first_gmh)
				{
					/* New cid_adjust for each packet with fragment(s) */
					cid_adjust[cid_index] += cid_vernier[cid_index];
					/* cid_vernier must always be 0 at start of packet. */
					cid_vernier[cid_index] = 0;
				}
				/* Create artificial sequence numbers. */
				frag_number[cid_index]++;
				if (frag_type == FIRST_FRAG)
				{
					frag_number[cid_index] = 0;
				}
				if (cid_adj_array[pinfo->fd->num])
				{
					/* We apparently just clicked on the packet again. */
					cid_adjust[cid_index] = cid_adj_array[pinfo->fd->num];
					/* Set the frag_number at start of packet. */
					if (first_gmh)
					{
						frag_number[cid_index] = frag_num_array[pinfo->fd->num];
					}
				} else {
					/* Save for next time we click on this packet. */
					cid_adj_array[pinfo->fd->num] = cid_adjust[cid_index];
					if (first_gmh)
					{
						frag_num_array[pinfo->fd->num] = frag_number[cid_index];
					}
				}
				/* Reset in case we stay in this while() loop to finish the packet. */
				first_gmh = FALSE;
				cid = cid_base + cid_adjust[cid_index] + cid_vernier[cid_index];
				/* Save address pointers. */
				save_src = pinfo->src;
				save_dst = pinfo->dst;
				/* Use dl_src and dl_dst in defrag. */
				pinfo->src = pinfo->dl_src;
				pinfo->dst = pinfo->dl_dst;
				payload_frag = fragment_add_seq(tvb, offset, pinfo, cid, payload_frag_table, frag_number[cid_index], frag_len, ((frag_type==LAST_FRAG)?0:1));
				/* Restore address pointers. */
				pinfo->src = save_src;
				pinfo->dst = save_dst;
				if (frag_type == LAST_FRAG)
				{
					/* Make sure fragment_add_seq() sees next one as a new frame. */
					cid_vernier[cid_index]++;
				}
				/* Don't show reassem packet until last frag. */
				proto_tree_add_text(tree, tvb, offset, frag_len, "Payload Fragment (%d bytes)", frag_len);

				if (payload_frag && frag_type == LAST_FRAG)
				{	/* defragmented completely */
					payload_length = payload_frag->len;
					/* create the new tvb for defragmented frame */
					payload_tvb = tvb_new_child_real_data(tvb, payload_frag->data, payload_length, payload_length);
					/* add the defragmented data to the data source list */
					add_new_data_source(pinfo, payload_tvb, "Reassembled WiMax MAC payload");
					/* save the tvb langth */
					new_payload_len = payload_length;
				}
				else /* error or defragment is not complete */
				{
					payload_tvb = NULL;
#ifdef DEBUG	/* for debug only */
/*					if (frag_type == LAST_FRAG)*/
					{	/* error */
						/* update the info column */
						col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Dropped the incomplete frame");
					}
#endif
#if 0
					if (frag_type == FIRST_FRAG)
					{	/* Set up to decode the first fragment (even though next fragment not read yet) */
						payload_tvb =  tvb_new_subset(tvb, offset, length, length);
						payload_length = length;
						frag_len = length;
					}
#endif
				}
			}
			/* process the defragmented payload */
			if (payload_tvb)
			{	/* reset the payload_offset */
				payload_offset = 0;
				/* process the payload */
				if (payload_length > 0)
				{
					if (!new_payload_len)
						continue;
					/* if ARQ Feedback payload is present, it should be the first SDU */
					if (first_arq_fb_payload && arq_fb_payload)
					{	/* decode and display the ARQ feedback payload */
						first_arq_fb_payload = FALSE;
						ret_length = arq_feedback_payload_decoder(tvb_new_subset(payload_tvb, payload_offset, new_payload_len, new_payload_len), pinfo, generic_tree, parent_item);
#ifdef DEBUG /* for debug only */
						if (ret_length != new_payload_len)
						{	/* error */
							/* update the info column */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "incorrect ARQ fb payload size");
						}
#endif
					}
					else	/* decode SDUs */
					{	/* check the payload type */
						if (mac_cid == cid_padding)
						{	/* update the info column */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Padding CID");
							/* get the parent */
							generic_item = proto_tree_get_parent(tree);
							/* add the MAC header info */
							proto_item_append_text(generic_item, ", Padding CID");
							/* display padding CID */
							generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, payload_tvb, payload_offset, new_payload_len, "Padding CID (%u bytes)", new_payload_len);
							/* add payload subtree */
							generic_tree = proto_item_add_subtree(generic_item, ett_mac_header_generic_decoder);
							/* display the Padding CID payload  in Hex */
							proto_tree_add_item(generic_tree, hf_mac_header_generic_value_bytes, payload_tvb, payload_offset, new_payload_len, ENC_NA);
						}
						else if ((mac_cid <= (2 * global_cid_max_basic)) || (mac_cid == cid_aas_ranging)
							|| (mac_cid >= cid_normal_multicast))
						{	/* MAC management message */
							dissect_mac_mgmt_msg_decoder(tvb_new_subset(payload_tvb, payload_offset, new_payload_len, new_payload_len), pinfo, tree);
						}
						else /* data transport PDU */
						{	/* update the info column */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Data");
							/* add the MAC payload info */
							proto_item_append_text(parent_item, ", Data");
							/* display payload info */
							if ((new_payload_len + payload_offset) > payload_length)
							{
								new_tvb_len = new_payload_len - payload_offset;
							}
							else
							{
								new_tvb_len = new_payload_len;
							}
							if (frag_type == LAST_FRAG || frag_type == NO_FRAG)
							{
								if (frag_type == NO_FRAG)
								{
									str_ptr = data_str;
									new_payload_len = frag_len;
								}
								else
								{
									str_ptr = reassem_str;
								}
								{
								data_pdu_tvb = tvb_new_subset(payload_tvb, payload_offset, new_tvb_len, new_tvb_len);
								generic_item = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, data_pdu_tvb, payload_offset, new_payload_len, str_ptr, new_payload_len);
								/* add payload subtree */
								generic_tree = proto_item_add_subtree(generic_item, ett_mac_data_pdu_decoder);
								/* check the data type */
								if (tvb_get_guint8(payload_tvb, payload_offset) == IP_HEADER_BYTE)
								{
									mac_payload_handle = find_dissector("ip");
									if (mac_payload_handle)
										call_dissector(mac_payload_handle, tvb_new_subset(payload_tvb, payload_offset, new_tvb_len, new_tvb_len), pinfo, generic_tree);
									else	/* display the Generic MAC Header in Hex */
										proto_tree_add_item(generic_tree, hf_mac_header_generic_value_bytes, payload_tvb, payload_offset, new_tvb_len, ENC_NA);
								}
								else	/* display the Generic MAC Header in Hex */
									proto_tree_add_item(generic_tree, hf_mac_header_generic_value_bytes, payload_tvb, payload_offset, new_tvb_len, ENC_NA);
								}
							}
						}
					}
					payload_length -= new_payload_len;
					payload_offset += new_payload_len;
				}	/* end of while loop */
			}	/* end of payload processing */
			length -= frag_len;
			offset += frag_len;
		} /* end of payload decoding */
check_crc:
		/* Decode and display the CRC if it is present */
		if (mac_ci)
		{
			/* add the CRC info */
			proto_item_append_text(parent_item, ", CRC");
			/* check the length */
			if (MIN(tvb_len, tvb_reported_length(tvb)) >= mac_len)
			{	/* get the CRC */
				mac_crc = tvb_get_ntohl(tvb, mac_len - sizeof(mac_crc));
				/* calculate the CRC */
        	    calculated_crc = wimax_mac_calc_crc32(tvb_get_ptr(tvb, 0, mac_len - sizeof(mac_crc)), mac_len - sizeof(mac_crc));
				/* display the CRC */
				generic_item = proto_tree_add_item(tree, hf_mac_header_generic_crc, tvb, mac_len - sizeof(mac_crc), sizeof(mac_crc), ENC_BIG_ENDIAN);
				if (mac_crc != calculated_crc)
				{
			    		proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
				}
		    	}
			else
			{	/* display error message */
				proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, 0, tvb_len, "CRC missing - the frame is too short (%u bytes)", tvb_len);
			}
		}
		else	/* CRC is not included */
		{	/* add the CRC info */
			proto_item_append_text(parent_item, ", No CRC");
			/* display message */
			proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, 0, tvb_len, "CRC is not included in this frame!");
		}
	}
}

static gint extended_subheader_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	gint length, ext_length, ubyte, i;
	proto_item *ti = NULL;
	proto_tree *sub_tree = NULL;
	proto_tree *ti_tree = NULL;

	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Ext subhdrs");

	/* Get the tvb reported length */
	length =  tvb_reported_length(tvb);
	if (!length)
	{	/* display the error message */
		proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, length, "Error: extended subheader tvb is empty ! (%u bytes)", length);
		return length;
	}

	/* Get the length of the extended subheader group */
	ext_length = tvb_get_guint8(tvb, offset);
	/* display subheader type */
	ti = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, length, "Extended subheader group (%u bytes)", ext_length);
	/* add extended subheader subtree */
	sub_tree = proto_item_add_subtree(ti, ett_mac_ext_subheader_decoder);
	/* decode and display the extended subheaders */
	for (i=1; i<ext_length;)
	{	/* Get the extended subheader type */
		ubyte = (tvb_get_guint8(tvb, (offset+i)) & EXTENDED_SUB_HEADER_TYPE_MASK);
		/* decode and display the extended subheader type (MSB) */
		proto_tree_add_item(sub_tree, hf_mac_header_generic_ext_subheader_rsv, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
		/* for downlink */
		if (is_down_link(pinfo)) /* for downlink */
		{	/* decode and display the extended subheader type */
			ti = proto_tree_add_item(sub_tree, hf_mac_header_generic_ext_subheader_type_dl, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
			/* add subtree */
			ti_tree = proto_item_add_subtree(ti, ett_mac_ext_subheader_dl_decoder);
			i++;
			switch (ubyte)
			{
			case SDU_SN:
				/* decode and display the extended sdu sn subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_sdu_sn, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				i++;
			break;
			case DL_SLEEP_CONTROL:
				/* decode and display the extended dl sleep control subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_dl_sleep_control_pscid, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_dl_sleep_control_op, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_dl_sleep_control_fswe, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_dl_sleep_control_fswb, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_dl_sleep_control_rsv, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				i += 3;
			break;
			case FEEDBACK_REQ:
				/* decode and display the extended feedback request subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_fb_req_uiuc, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_fb_req_fb_type,  tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_fb_req_ofdma_symbol_offset, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_fb_req_subchannel_offset, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_fb_req_slots, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_fb_req_frame_offset, tvb, (offset+i), 3, ENC_BIG_ENDIAN);
				i += 3;
			break;
			case SN_REQ:
				/* decode and display the extended SN request subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_sn_req_rep_ind_1, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_sn_req_rep_ind_2, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_sn_req_rsv, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				i++;
			break;
			case PDU_SN_SHORT_DL:
				/* decode and display the extended pdu sn (short) subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_pdu_sn_short, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				i++;
			break;
			case PDU_SN_LONG_DL:
				/* decode and display the extended pdu sn (long) subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_pdu_sn_long, tvb, (offset+i), 2, ENC_BIG_ENDIAN);
				i += 2;
			break;
			default: /* reserved */
			break;
			}
		}
		else /* for uplink */
		{	/* decode and display the extended subheader type */
			ti = proto_tree_add_item(sub_tree, hf_mac_header_generic_ext_subheader_type_ul, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
			/* add subtree */
			ti_tree = proto_item_add_subtree(ti, ett_mac_ext_subheader_ul_decoder);
			i++;
			switch (ubyte)
			{
			case MIMO_MODE_FEEDBACK:
				/* decode and display the extended MIMO Mode Feedback subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_mimo_mode_fb_type, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_mimo_fb_content, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				i++;
			break;
			case UL_TX_POWER_REPORT:
				/* decode and display the extended ul tx power report subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_ul_tx_pwr_rep, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				i++;
			break;
			case MINI_FEEDBACK:
				/* decode and display the extended MINI Feedback subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_mini_fb_type, tvb, (offset+i), 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_mini_fb_content, tvb, (offset+i), 2, ENC_BIG_ENDIAN);
				i += 2;
			break;
			case PDU_SN_SHORT_UL:
				/* decode and display the extended pdu sn (short) subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_pdu_sn_short, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
				i++;
			break;
			case PDU_SN_LONG_UL:
				/* decode and display the extended pdu sn (long) subheader */
				proto_tree_add_item(ti_tree, hf_mac_header_generic_ext_subheader_pdu_sn_long, tvb, (offset+i), 2, ENC_BIG_ENDIAN);
				i += 2;
			break;
			default: /* reserved */
			break;
			}
		}
	}
	/* return the extended subheader length */
	return ext_length;
}

static gint arq_feedback_payload_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *parent_item)
{
	gint length, i;
	gint offset;
	gint last_ie = 0;
	gint ack_type, num_maps, seq_format;
	gint word2, word3;
	proto_item *ti = NULL;
	proto_item *sub_ti = NULL;
	proto_tree *sub_tree = NULL;

	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "ARQ feedback payld");

	/* add the MAC header info */
	proto_item_append_text(parent_item, ", ARQ feedback payload");

	/* reset the offset */
	offset = 0;

	/* Get the tvb reported length */
	length =  tvb_reported_length(tvb);
	if (!length)
	{	/* display the error message */
		proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, length, "Error: ARQ feedback payload tvb is empty ! (%u bytes)", length);
		return length;
	}

	/* display subheader type */
	ti = proto_tree_add_protocol_format(tree, proto_mac_header_generic_decoder, tvb, offset, length, "ARQ feedback payload ");
	/* add extended subheader subtree */
	sub_tree = proto_item_add_subtree(ti, ett_mac_arq_fb_payload_decoder);
	/* decode and display the ARQ Feedback IEs */
	while (!last_ie)
	{	/* decode and display CID */
		proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_cid, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* move to next 16-bit word */
		offset += 2;
		/* Get the 2nd 16-bit */
		word2 = tvb_get_ntohs(tvb, offset);
		/* get the last bit */
		last_ie = (word2 & ARQ_FB_IE_LAST_BIT_MASK);
		/* get the ACK type */
		ack_type = ((word2 & ARQ_FB_IE_ACK_TYPE_MASK) >> 13);
		/* get the number of ACK maps */
		num_maps = (word2 & ARQ_FB_IE_NUM_MAPS_MASK) + 1;
		/* decode and display the 2nd word */
		proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_last, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_ack_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_bsn, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* decode and display the 3rd word */
		if (ack_type != 1)
		{
			sub_ti = proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_num_maps, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* move to next 16-bit word */
			offset += 2;
			proto_item_append_text(sub_ti, " (%d map(s))", num_maps);
			for (i = 0; i < num_maps; i++)
			{
				if (ack_type != 3)
				{
					proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_sel_ack_map, tvb, offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* Get the next 16-bit */
					word3 = tvb_get_ntohs(tvb, offset);
					/* get the sequence format */
					seq_format = (word3 & ARQ_FB_IE_SEQ_FORMAT_MASK);
					/* decode and display the sequence format */
					proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_seq_format, tvb, offset, 2, ENC_BIG_ENDIAN);
					if (!seq_format)
					{
						proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_seq_ack_map_2, tvb, offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_seq1_length_6, tvb, offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_seq2_length_6, tvb, offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
					}
					else
					{
						proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_seq_ack_map, tvb, offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_seq1_length, tvb, offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_seq2_length, tvb, offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(sub_tree, hf_mac_header_generic_arq_fb_ie_seq3_length, tvb, offset, 2, ENC_BIG_ENDIAN);
					}
				}
				/* move to next 16-bit word */
				offset += 2;
			}
		}
		else
		{
			/* Number of ACK Maps bits are reserved when ACK TYPE == 1 */
			proto_tree_add_item(sub_tree, hf_ack_type_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* move to next 16-bit word */
			offset += 2;
		}
	}
	/* append text */
	proto_item_append_text(ti,"(%u bytes)", offset);
	/* return the offset */
	return offset;
}

/* Register Wimax Generic Mac Header Protocol and Dissector */
void proto_register_mac_header_generic(void)
{
	/* Generic MAC header display */
	static hf_register_info hf[] =
	{
		{
			&hf_mac_header_generic_value_bytes,
			{
				"Values", "wmx.genericValueBytes",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ht,
			{
				"MAC Header Type", "wmx.genericHt",
				FT_UINT24, BASE_HEX, VALS(ht_msgs), WIMAX_MAC_HEADER_GENERIC_HT,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ec,
			{
				"MAC Encryption Control", "wmx.genericEc",
				FT_UINT24, BASE_HEX, VALS(ec_msgs), WIMAX_MAC_HEADER_GENERIC_EC,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_type_0,
			{
				"MAC Sub-type Bit 0", "wmx.genericType0",
				FT_UINT24, BASE_HEX, VALS(type_msg0), WIMAX_MAC_HEADER_GENERIC_TYPE_0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_type_1,
			{
				"MAC Sub-type Bit 1", "wmx.genericType1",
				FT_UINT24, BASE_HEX, VALS(type_msg1), WIMAX_MAC_HEADER_GENERIC_TYPE_1,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_type_2,
			{
				"MAC Sub-type Bit 2", "wmx.genericType2",
				FT_UINT24, BASE_HEX, VALS(type_msg2), WIMAX_MAC_HEADER_GENERIC_TYPE_2,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_type_3,
			{
				"MAC Sub-type Bit 3", "wmx.genericType3",
				FT_UINT24, BASE_HEX, VALS(type_msg3), WIMAX_MAC_HEADER_GENERIC_TYPE_3,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_type_4,
			{
				"MAC Sub-type Bit 4", "wmx.genericType4",
				FT_UINT24, BASE_HEX, VALS(type_msg4), WIMAX_MAC_HEADER_GENERIC_TYPE_4,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_type_5,
			{
				"MAC Sub-type Bit 5", "wmx.genericType5",
				FT_UINT24, BASE_HEX, VALS(type_msg5), WIMAX_MAC_HEADER_GENERIC_TYPE_5,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_esf,
			{
				"Extended Sub-header Field", "wmx.genericEsf",
				FT_UINT24, BASE_HEX, VALS(esf_msgs), WIMAX_MAC_HEADER_GENERIC_ESF,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ci,
			{
				"CRC Indicator", "wmx.genericCi",
				FT_UINT24, BASE_HEX, VALS(ci_msgs), WIMAX_MAC_HEADER_GENERIC_CI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_eks,
			{
				"Encryption Key Sequence", "wmx.genericEks",
				FT_UINT24, BASE_HEX, NULL, WIMAX_MAC_HEADER_GENERIC_EKS,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_rsv,
			{
				"Reserved", "wmx.genericRsv",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_GENERIC_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_len,
			{
				"Length", "wmx.genericLen",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_GENERIC_LEN,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_cid,
			{
				"Connection ID", "wmx.genericCid",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_hcs,
			{
				"Header Check Sequence", "wmx.genericHcs",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_crc,
			{
				"CRC", "wmx.genericCrc",
				FT_UINT32, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	/* Extended Subheader display */
	static hf_register_info hf_ext[] =
	{
		{
			&hf_mac_header_generic_ext_subheader_rsv,
			{
				"Reserved", "wmx.genericExtSubhd.Rsv",
				FT_UINT8, BASE_DEC, NULL, EXTENDED_SUB_HEADER_RSV_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_type_dl,
			{
				"DL Extended Subheader Type", "wmx.genericExtSubhd.Dl",
				FT_UINT8, BASE_DEC, VALS(dl_ext_sub_header_type), EXTENDED_SUB_HEADER_TYPE_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_type_ul,
			{
				"UL Extended Subheader Type", "wmx.genericExtSubhd.Ul",
				FT_UINT8, BASE_DEC, VALS(ul_ext_sub_header_type), EXTENDED_SUB_HEADER_TYPE_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_sdu_sn,
			{
				"SDU Sequence Number", "wmx.genericExtSubhd.SduSn",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_dl_sleep_control_pscid,
			{
				"Power Saving Class ID", "wmx.genericExtSubhd.DlSleepCtrlPSCID",
				FT_UINT24, BASE_DEC, NULL, DL_SLEEP_CONTROL_POWER_SAVING_CLASS_ID_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_dl_sleep_control_op,
			{
				"Operation", "wmx.genericExtSubhd.DlSleepCtrlOP",
				FT_UINT24, BASE_HEX, VALS(dl_sleep_control_ops), DL_SLEEP_CONTROL_OPERATION_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_dl_sleep_control_fswe,
			{
				"Final Sleep Window Exponent", "wmx.genericExtSubhd.DlSleepCtrlFSWE",
				FT_UINT24, BASE_DEC, NULL, DL_SLEEP_CONTROL_FINAL_SLEEP_WINDOW_EXPONENT_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_dl_sleep_control_fswb,
			{
				"Final Sleep Window Base", "wmx.genericExtSubhd.DlSleepCtrlFSWB",
				FT_UINT24, BASE_DEC, NULL, DL_SLEEP_CONTROL_FINAL_SLEEP_WINDOW_BASE_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_dl_sleep_control_rsv,
			{
				"Reserved", "wmx.genericExtSubhd.DlSleepCtrlRsv",
				FT_UINT24, BASE_DEC, NULL, DL_SLEEP_CONTROL_RESERVED_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_fb_req_uiuc,
			{
				"UIUC", "wmx.genericExtSubhd.FbReqUIUC",
				FT_UINT24, BASE_HEX, VALS(uiuc_values), FEEDBACK_REQUEST_UIUC_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_fb_req_fb_type,
			{
				"Feedback Type", "wmx.genericExtSubhd.FbReqFbType",
				FT_UINT24, BASE_HEX, VALS(fb_types), FEEDBACK_REQUEST_FEEDBACK_TYPE_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_fb_req_ofdma_symbol_offset,
			{
				"OFDMA Symbol Offset", "wmx.genericExtSubhd.FbReqOfdmaSymbolOffset",
				FT_UINT24, BASE_HEX, NULL, FEEDBACK_REQUEST_OFDMA_SYMBOL_OFFSET_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_fb_req_subchannel_offset,
			{
				"Subchannel Offset", "wmx.genericExtSubhd.FbReqSubchannelOffset",
				FT_UINT24, BASE_HEX, NULL, FEEDBACK_REQUEST_SUBCHANNEL_OFFSET_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_fb_req_slots,
			{
				"Number of Slots", "wmx.genericExtSubhd.FbReqSlots",
				FT_UINT24, BASE_HEX, NULL, FEEDBACK_REQUEST_NUMBER_OF_SLOTS_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_fb_req_frame_offset,
			{
				"Frame Offset", "wmx.genericExtSubhd.FbReqFrameOffset",
				FT_UINT24, BASE_HEX, NULL, FEEDBACK_REQUEST_FRAME_OFFSET_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_sn_req_rep_ind_1,
			{
				"First SN Report Indication", "wmx.genericExtSubhd.SnReqRepInd1",
				FT_UINT8, BASE_DEC, VALS(sn_rep_msg), SN_REQUEST_SUBHEADER_SN_REPORT_INDICATION_1_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_sn_req_rep_ind_2,
			{
				"Second SN Report Indication", "wmx.genericExtSubhd.SnReqRepInd2",
				FT_UINT8, BASE_DEC, VALS(sn_rep_msg), SN_REQUEST_SUBHEADER_SN_REPORT_INDICATION_2_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_sn_req_rsv,
			{
				"Reserved", "wmx.genericExtSubhd.SnReqRsv",
				FT_UINT8, BASE_DEC, NULL, SN_REQUEST_SUBHEADER_RESERVED_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_mimo_mode_fb_type,
			{
				"Feedback Type", "wmx.genericExtSubhd.MimoFbType",
				FT_UINT8, BASE_DEC, VALS(mimo_fb_types), MIMO_FEEDBACK_TYPE_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_mimo_fb_content,
			{
				"Feedback Content", "wmx.genericExtSubhd.MimoFbContent",
				FT_UINT8, BASE_DEC, NULL, MIMO_FEEDBACK_CONTENT_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_ul_tx_pwr_rep,
			{
				"UL TX Power", "wmx.genericExtSubhd.UlTxPwr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_mini_fb_type,
			{
				"Feedback Type", "wmx.genericExtSubhd.MiniFbType",
				FT_UINT16, BASE_DEC, VALS(fb_types), MINI_FEEDBACK_TYPE_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_mini_fb_content,
			{
				"Feedback Content", "wmx.genericExtSubhd.MiniFbContent",
				FT_UINT16, BASE_DEC, NULL, MINI_FEEDBACK_CONTENT_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_pdu_sn_short,
			{
				"PDU Sequence Number", "wmx.genericExtSubhd.PduSnShort",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_ext_subheader_pdu_sn_long,
			{
				"PDU Sequence Number", "wmx.genericExtSubhd.PduSnLong",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	/* Mesh Subheader display */
	static hf_register_info hf_mesh[] =
	{
		{
			&hf_mac_header_generic_mesh_subheader,
			{
				"Xmt Node Id", "wmx.genericMeshSubhd",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	/* Fragmentation Subheader display */
	static hf_register_info hf_frag[] =
	{
		{
			&hf_mac_header_generic_frag_subhd_fc,
			{
				"Fragment Type", "wmx.genericFragSubhd.Fc",
				FT_UINT8, BASE_DEC, VALS(frag_types), FRAGMENTATION_SUBHEADER_FC_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_frag_subhd_fc_ext,
			{
				"Fragment Type", "wmx.genericFragSubhd.FcExt",
				FT_UINT16, BASE_DEC, VALS(frag_types), FRAGMENTATION_SUBHEADER_FC_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_frag_subhd_bsn,
			{
				"Block Sequence Number (BSN)", "wmx.genericFragSubhd.Bsn",
				FT_UINT16, BASE_DEC, NULL, FRAGMENTATION_SUBHEADER_BSN_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_frag_subhd_fsn,
			{
				"Fragment Sequence Number (FSN)", "wmx.genericFragSubhd.Fsn",
				FT_UINT8, BASE_DEC, NULL, FRAGMENTATION_SUBHEADER_FSN_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_frag_subhd_fsn_ext,
			{
				"Fragment Sequence Number (FSN)", "wmx.genericFragSubhd.FsnExt",
				FT_UINT16, BASE_DEC, NULL, FRAGMENTATION_SUBHEADER_BSN_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_frag_subhd_rsv,
			{
				"Reserved", "wmx.genericFragSubhd.Rsv",
				FT_UINT8, BASE_DEC, NULL, FRAGMENTATION_SUBHEADER_RSV_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_frag_subhd_rsv_ext,
			{
				"Reserved", "wmx.genericFragSubhd.RsvExt",
				FT_UINT16, BASE_DEC, NULL, FRAGMENTATION_SUBHEADER_RSV_EXT_MASK,
				NULL, HFILL
			}
		}
	};

	/* Packing Subheader display */
	static hf_register_info hf_pack[] =
	{
		{
			&hf_mac_header_generic_packing_subhd_fc,
			{
				"Fragment Type", "wmx.genericPackSubhd.Fc",
				FT_UINT16, BASE_DEC, VALS(frag_types), PACKING_SUBHEADER_FC_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_packing_subhd_fc_ext,
			{
				"Fragment Type", "wmx.genericPackSubhd.FcExt",
				FT_UINT24, BASE_HEX, VALS(frag_types), PACKING_SUBHEADER_FC_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_packing_subhd_bsn,
			{
				"First Block Sequence Number", "wmx.genericPackSubhd.Bsn",
				FT_UINT24, BASE_DEC, NULL, PACKING_SUBHEADER_BSN_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_packing_subhd_fsn,
			{
				"Fragment Number", "wmx.genericPackSubhd.Fsn",
				FT_UINT16, BASE_DEC, NULL, PACKING_SUBHEADER_FSN_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_packing_subhd_fsn_ext,
			{
				"Fragment Number", "wmx.genericPackSubhd.FsnExt",
				FT_UINT24, BASE_DEC, NULL, PACKING_SUBHEADER_BSN_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_packing_subhd_len,
			{
				"Length", "wmx.genericPackSubhd.Len",
				FT_UINT16, BASE_DEC, NULL, PACKING_SUBHEADER_LENGTH_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_packing_subhd_len_ext,
			{
				"Length", "wmx.genericPackSubhd.LenExt",
				FT_UINT24, BASE_DEC, NULL, PACKING_SUBHEADER_LENGTH_EXT_MASK,
				NULL, HFILL
			}
		}
	};

	/* Fast-feedback Allocation Subheader display */
	static hf_register_info hf_fast[] =
	{
		{
			&hf_mac_header_generic_fast_fb_subhd_alloc_offset,
			{
				"Allocation Offset", "wmx.genericFastFbSubhd.AllocOffset",
				FT_UINT8, BASE_DEC, NULL, FAST_FEEDBACK_ALLOCATION_OFFSET_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_fast_fb_subhd_fb_type,
			{
				"Feedback Type", "wmx.genericFastFbSubhd.FbType",
				FT_UINT8, BASE_DEC, VALS(fast_fb_types), FAST_FEEDBACK_FEEDBACK_TYPE_MASK,
				NULL, HFILL
			}
		}
	};

	/* Grant Management Subheader display */
	static hf_register_info hf_grant[] =
	{
		{
			&hf_mac_header_generic_grant_mgmt_ext_pbr_tree,
			{
				"Scheduling Service Type (Default)",
				"wimax.genericGrantSubhd.Default",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_pbr,
			{
				"PiggyBack Request", "wmx.genericGrantSubhd.Pbr",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_ugs_tree,
			{
				"Scheduling Service Type (UGS)", "wmx.genericGrantSubhd.UGS",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_ugs_si,
			{
				"Slip Indicator", "wmx.genericGrantSubhd.Si",
				FT_UINT16, BASE_DEC, VALS(si_msgs), GRANT_MGMT_SUBHEADER_UGS_SI_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_ugs_pm,
			{
				"Poll-Me", "wmx.genericGrantSubhd.Pm",
				FT_UINT16, BASE_DEC, VALS(pm_msgs), GRANT_MGMT_SUBHEADER_UGS_PM_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_ugs_fli,
			{
				"Frame Latency Indication", "wmx.genericGrantSubhd.Fli",
				FT_UINT16, BASE_DEC, VALS(fli_msgs), GRANT_MGMT_SUBHEADER_UGS_FLI_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_ugs_fl,
			{
				"Frame Latency", "wmx.genericGrantSubhd.Fl",
				FT_UINT16, BASE_DEC, NULL, GRANT_MGMT_SUBHEADER_UGS_FL_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_ugs_rsv,
			{
				"Reserved", "wmx.genericGrantSubhd.Rsv",
				FT_UINT16, BASE_DEC, NULL, GRANT_MGMT_SUBHEADER_UGS_RSV_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_ext_rtps_tree,
			{
				"Scheduling Service Type (Extended rtPS)",
				"wimax.genericGrantSubhd.ExtendedRTPS",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_ext_pbr,
			{
				"Extended PiggyBack Request", "wmx.genericGrantSubhd.ExtPbr",
				FT_UINT16, BASE_DEC, NULL, GRANT_MGMT_SUBHEADER_EXT_PBR_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_ext_fli,
			{
				"Frame Latency Indication", "wmx.genericGrantSubhd.ExtFli",
				FT_UINT16, BASE_DEC, VALS(fli_msgs), GRANT_MGMT_SUBHEADER_EXT_FLI_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_grant_mgmt_subhd_ext_fl,
			{
				"Frame Latency", "wmx.genericGrantSubhd.ExtFl",
				FT_UINT16, BASE_DEC, NULL, GRANT_MGMT_SUBHEADER_EXT_FL_MASK,
				NULL, HFILL
			}
		}
	};

	/* ARQ Feedback Payload display */
	static hf_register_info hf_arq[] =
	{
		{
			&hf_mac_header_generic_arq_fb_ie_cid,
			{
				"CID", "wmx.genericArq.FbIeCid",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_last,
			{
				"Last IE", "wmx.genericArq.FbIeLast",
				FT_UINT16, BASE_DEC, VALS(last_ie_msgs), ARQ_FB_IE_LAST_BIT_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_ack_type,
			{
				"ACK Type", "wmx.genericArq.FbIeAckType",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_ACK_TYPE_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_bsn,
			{
				"BSN", "wmx.genericArq.FbIeBsn",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_BSN_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_num_maps,
			{
				"Number of ACK Maps", "wmx.genericArq.FbIeMaps",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_NUM_MAPS_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_ack_type_reserved,
			{
				"Reserved", "wmx.genericArq.FbIeRsvd", FT_UINT16, BASE_DEC, NULL, 0x03, NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_sel_ack_map,
			{
				"Selective ACK Map", "wmx.genericArq.FbIeSelAckMap",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_seq_format,
			{
				"Sequence Format", "wmx.genericArq.FbIeSeqFmt",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_SEQ_FORMAT_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_seq_ack_map,
			{
				"Sequence ACK Map", "wmx.genericArq.FbIeSeqAckMap",
				FT_UINT16, BASE_HEX, NULL, ARQ_FB_IE_SEQ_ACK_MAP_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_seq1_length,
			{
				"Sequence 1 Length", "wmx.genericArq.FbIeSeq1Len",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_SEQ1_LENGTH_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_seq2_length,
			{
				"Sequence 2 Length", "wmx.genericArq.FbIeSeq2Len",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_SEQ2_LENGTH_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_seq3_length,
			{
				"Sequence 3 Length", "wmx.genericArq.FbIeSeq3Len",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_SEQ3_LENGTH_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_seq_ack_map_2,
			{
				"Sequence ACK Map", "wmx.genericArq.FbIeSeqAckMap2",
				FT_UINT16, BASE_HEX, NULL, ARQ_FB_IE_SEQ_ACK_MAP_2_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_seq1_length_6,
			{
				"Sequence 1 Length", "wmx.genericArq.FbIeSeq1Len",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_SEQ1_LENGTH_6_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_seq2_length_6,
			{
				"Sequence 2 Length", "wmx.genericArq.FbIeSeq2Len",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_SEQ2_LENGTH_6_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_generic_arq_fb_ie_rsv,
			{
				"Reserved", "wmx.genericArq.FbIeRsv",
				FT_UINT16, BASE_DEC, NULL, ARQ_FB_IE_RSV_MASK,
				NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_header_generic_decoder,
			/* &ett_mac_subheader_decoder, */
			&ett_mac_mesh_subheader_decoder,
			&ett_mac_frag_subheader_decoder,
			&ett_mac_grant_mgmt_subheader_decoder,
			&ett_mac_pkt_subheader_decoder,
			&ett_mac_fast_fb_subheader_decoder,
			&ett_mac_ext_subheader_decoder,
			&ett_mac_ext_subheader_dl_decoder,
			&ett_mac_ext_subheader_ul_decoder,
			&ett_mac_arq_fb_payload_decoder,
			&ett_mac_data_pdu_decoder,
		};

	proto_mac_header_generic_decoder = proto_register_protocol (
		"WiMax Generic/Type1/Type2 MAC Header Messages", /* name       */
		"WiMax Generic/Type1/Type2 MAC Header (hdr)",    /* short name */
		"wmx.hdr"                                        /* abbrev     */
		);

	/* register the field display messages */
	proto_register_field_array(proto_mac_header_generic_decoder, hf,       array_length(hf));
	proto_register_field_array(proto_mac_header_generic_decoder, hf_ext,   array_length(hf_ext));
	proto_register_field_array(proto_mac_header_generic_decoder, hf_mesh,  array_length(hf_mesh));
	proto_register_field_array(proto_mac_header_generic_decoder, hf_frag,  array_length(hf_frag));
	proto_register_field_array(proto_mac_header_generic_decoder, hf_pack,  array_length(hf_pack));
	proto_register_field_array(proto_mac_header_generic_decoder, hf_fast,  array_length(hf_fast));
	proto_register_field_array(proto_mac_header_generic_decoder, hf_grant, array_length(hf_grant));
	proto_register_field_array(proto_mac_header_generic_decoder, hf_arq,   array_length(hf_arq));
	proto_register_subtree_array(ett, array_length(ett));

	/* register the generic mac header dissector */
	register_dissector("mac_header_generic_handler", dissect_mac_header_generic_decoder, proto_mac_header_generic_decoder);
	/* register the mac payload dissector */
	proto_register_mac_mgmt_msg();
	/* Register the payload fragment table init routine */
	register_init_routine(wimax_defragment_init);
}
