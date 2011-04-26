/* packet-bssgp.c
 * Routines for Base Station Subsystem GPRS Protocol dissection
 * Copyright 2000, Susanne Edlund <susanne.edlund@ericsson.com>
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

/* 3GPP TS 48.018 V 6.5.0 (2004-07) Release 6 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <prefs.h>
#include <epan/asn1.h>

#include "packet-bssgp.h"
#include "packet-e212.h"
#include "packet-gsm_a_common.h"
#include "packet-ranap.h"
#include "packet-rrc.h"
#include "packet-lte-rrc.h"
#include "packet-s1ap.h"

/* #define BSSGP_DEBUG */
/*
 * TS 48.018 V6.6.0 (2004-11) says, of information elements:
 *
 *    Refer to General Structure Of The Information Elements/3GPP TS 48.016.
 *
 * TS 48.016 V9.0.0 (2010-02), in that section, says, of information elements:
 *
 *    When a field extends over more than one octet, the order of bit
 *    values progressively decreases as the octet number increases.
 *    The least significant bit of the field is represented by the
 *    lowest numbered bit of the highest numbered octet of the field.
 *
 * which sure sounds little-endian.
 *
 * However, for some not-entirely-obvious reason, BSSGP_LITTLE_ENDIAN, which
 * was passed to proto_tree_add_item() as the byte-order argument, was
 * defined as FALSE - which meant big-endian.
 *
 * For now, we'll use ENC_BIG_ENDIAN, now that we have ENC_BIG_ENDIAN and
 * REP_LITTLE_ENDIAN definitions.
 */

#define BSSGP_SEP ", "
static int bssgp_decode_nri = 0;
static guint bssgp_nri_length = 4;

static packet_info *gpinfo;
static guint8 g_pdu_type, g_rim_application_identity;
static proto_tree *gparent_tree;
static dissector_handle_t llc_handle;
static dissector_handle_t rrlp_handle;
static dissector_handle_t data_handle;

static module_t *bssgp_module;
static dissector_table_t diameter_3gpp_avp_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_bssgp = -1;
static int hf_bssgp_msg_type = -1;
int hf_bssgp_elem_id = -1;
static int hf_bssgp_ci = -1;
static int hf_bssgp_flush_action = -1;
static int hf_bssgp_llc_frames_disc = -1;
static int hf_bssgp_ra_discriminator = -1;
static int hf_bssgp_rim_app_id = -1;
static int hf_bssgp_rim_seq_no = -1;
static int hf_bssgp_rat_discriminator = -1;
static int hf_bssgp_nacc_cause = -1;
static int hf_bssgp_s13_cause = -1;
static int hf_bssgp_mbms_data_ch_cause = -1;
static int hf_bssgp_utra_si_cause = -1;
static int hf_bssgp_num_si_psi = -1;
static int hf_bssgp_si_psi_type = -1;
static int hf_bssgp_ran_inf_req_pdu_t_ext_c = -1;
static int hf_bssgp_ran_inf_pdu_t_ext_c = -1;
static int hf_bssgp_rim_pdu_ind_ack = -1;
static int hf_bssgp_rim_proto_ver_no = -1;
static int hf_bssgp_bss_area_ind = -1;
static int hf_bssgp_bvci = -1;
static int hf_bssgp_bmax = -1;
static int hf_bssgp_r = -1;
static int hf_bssgp_r_pfc = -1;
static int hf_bssgp_bucket_size = -1;
static int hf_bssgp_bmax_pfc = -1;
static int hf_bssgp_omc_id = -1;
static int hf_bssgp_nsei = -1;
static int hf_bssgp_rrlp_flag1 = -1;

static int hf_bssgp_delay_val = -1;
static int hf_bssgp_cause = -1;
static int hf_bssgp_peak_rate_gran = -1;
static int hf_bssgp_cr_bit = -1;
static int hf_bssgp_t_bit = -1;
static int hf_bssgp_a_bit = -1;
static int hf_bssgp_ra_cause = -1;
static int hf_bssgp_ra_cap_upd_cause = -1;
static int hf_bssgp_r_default_ms = -1;
static int hf_bssgp_suspend_ref_no = -1;
static int hf_bssgp_tag = -1;
static int hf_bssgp_trace_ref = -1;
static int hf_bssgp_trigger_id = -1;
static int hf_bssgp_transaction_id = -1;
static int hf_bssgp_no_of_oct = -1;
static int hf_bssgp_unit_val = -1;
static int hf_bssgp_gprs_timer = -1;
static int hf_bssgp_mbms = -1;
static int hf_bssgp_EnhancedRadioStatus = -1;
static int hf_bssgp_pfcfc = -1;
static int hf_bssgp_rim = -1;
static int hf_bssgp_lcs = -1;
static int hf_bssgp_inr = -1;
static int hf_bssgp_cbl = -1;
static int hf_bssgp_pfc = -1;
static int hf_bssgp_bucket_full_ratio = -1;
static int hf_bssgp_b_pfc = -1;

static int hf_bssgp_precedence = -1;
static int hf_bssgp_serv_utran_cco = -1;
static int hf_bssgp_mbms_session_id = -1;
static int hf_bssgp_mbms_cause = -1;
static int hf_bssgp_mbms_stop_cause = -1;
static int hf_bssgp_mbms_num_ra_ids = -1;
static int hf_bssgp_session_inf = -1;
static int hf_bssgp_gb_if = -1;
static int hf_bssgp_ps_ho = -1;
static int hf_bssgp_src_to_trg_transp_cont = -1;
static int hf_bssgp_trg_to_src_transp_cont = -1;
static int hf_bssgp_rnc_id = -1;
static int hf_bssgp_page_mode = -1;
static int hf_bssgp_container_id = -1;
static int hf_bssgp_global_tfi = -1;
static int hf_bssgp_ul_tfi = -1;
static int hf_bssgp_dl_tfi = -1;
static int hf_bssgp_time_to_MBMS_data_tran = -1;
static int hf_bssgp_mbms_session_rep_no = -1;
static int hf_bssgp_ps_ho_cmd = -1;
static int hf_bssgp_sipsi = -1;
static int hf_bssgp_type = -1;
static int hf_bssgp_cs_indication = -1;
static int hf_bssgp_flow_control_gran = -1;
static int hf_bssgp_serv_eutran_cco = -1;
static int hf_bssgp_sub_prof_id_f_rat_freq_prio = -1;
static int hf_bssgp_eutran_irat_ho_inf_req = -1;
static int hf_bssgp_irat_ho_inf_req = -1;

static int hf_bssgp_rel_int_rat_ho_inf_ind = -1;
static int hf_bssgp_csg_id = -1;
static int hf_bssgp_cell_acc_mode = -1;
static int hf_bssgp_Global_ENB_ID_PDU = -1;
static int hf_bssgp_SONtransferRequestContainer_PDU = -1;

/* Initialize the subtree pointers */
static gint ett_bssgp = -1;
static gint ett_bssgp_new = -1;
static gint ett_bssgp_pfcs_to_be_set_up_list = -1;
static gint ett_bssgp_pfcs_to_be_set_up_list_pft = -1;
static gint ett_bssgp_pfcs_to_be_set_up_list_abqp = -1;
static gint ett_bssgp_pfcs_to_be_set_up_list_arp = -1;
static gint ett_bssgp_pfcs_to_be_set_up_list_t10 = -1;
static gint ett_bssgp_list_of_setup_pfcs = -1;
static gint ett_bssgp_pfc_flow_control_parameters_pfc = -1;
static gint ett_bssgp_ra_id = -1;

/* PDU type coding, v6.5.0, table 11.3.26, p 80 */
#define BSSGP_PDU_DL_UNITDATA                  0x00
#define BSSGP_PDU_UL_UNITDATA                  0x01
#define BSSGP_PDU_RA_CAPABILITY                0x02
#define BSSGP_PDU_PTM_UNITDATA                 0x03
#define BSSGP_PDU_DL_MBMS_UNITDATA             0x04
#define BSSGP_PDU_UL_MBMS_UNITDATA             0x05
#define BSSGP_PDU_PAGING_PS                    0x06
#define BSSGP_PDU_PAGING_CS                    0x07
#define BSSGP_PDU_RA_CAPABILITY_UPDATE         0x08
#define BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK     0x09
#define BSSGP_PDU_RADIO_STATUS                 0x0a
#define BSSGP_PDU_SUSPEND                      0x0b
#define BSSGP_PDU_SUSPEND_ACK                  0x0c
#define BSSGP_PDU_SUSPEND_NACK                 0x0d
#define BSSGP_PDU_RESUME                       0x0e
#define BSSGP_PDU_RESUME_ACK                   0x0f
#define BSSGP_PDU_RESUME_NACK                  0x10

#define BSSGP_PDU_RESERVED_0X11                0x11
#define BSSGP_PDU_RESERVED_0X12                0x12
#define BSSGP_PDU_RESERVED_0X13                0x13
#define BSSGP_PDU_RESERVED_0X14                0x14
#define BSSGP_PDU_RESERVED_0X15                0x15
#define BSSGP_PDU_RESERVED_0X16                0x16
#define BSSGP_PDU_RESERVED_0X17                0x17
#define BSSGP_PDU_RESERVED_0X18                0x18
#define BSSGP_PDU_RESERVED_0X19                0x19
#define BSSGP_PDU_RESERVED_0X1A                0x1a
#define BSSGP_PDU_RESERVED_0X1B                0x1b
#define BSSGP_PDU_RESERVED_0X1C                0x1c
#define BSSGP_PDU_RESERVED_0X1D                0x1d
#define BSSGP_PDU_RESERVED_0X1E                0x1e
#define BSSGP_PDU_RESERVED_0X1F                0x1f

#define BSSGP_PDU_BVC_BLOCK                    0x20
#define BSSGP_PDU_BVC_BLOCK_ACK                0x21
#define BSSGP_PDU_BVC_RESET                    0x22
#define BSSGP_PDU_BVC_RESET_ACK                0x23
#define BSSGP_PDU_BVC_UNBLOCK                  0x24
#define BSSGP_PDU_BVC_UNBLOCK_ACK              0x25
#define BSSGP_PDU_FLOW_CONTROL_BVC             0x26
#define BSSGP_PDU_FLOW_CONTROL_BVC_ACK         0x27
#define BSSGP_PDU_FLOW_CONTROL_MS              0x28
#define BSSGP_PDU_FLOW_CONTROL_MS_ACK          0x29
#define BSSGP_PDU_FLUSH_LL                     0x2a
#define BSSGP_PDU_FLUSH_LL_ACK                 0x2b
#define BSSGP_PDU_LLC_DISCARDED                0x2c
#define BSSGP_PDU_FLOW_CONTROL_PFC             0x2d
#define BSSGP_PDU_FLOW_CONTROL_PFC_ACK         0x2e

#define BSSGP_PDU_RESERVED_0X2F                0x2f
#define BSSGP_PDU_RESERVED_0X30                0x30
#define BSSGP_PDU_RESERVED_0X31                0x31
#define BSSGP_PDU_RESERVED_0X32                0x32
#define BSSGP_PDU_RESERVED_0X33                0x33
#define BSSGP_PDU_RESERVED_0X34                0x34
#define BSSGP_PDU_RESERVED_0X35                0x35
#define BSSGP_PDU_RESERVED_0X36                0x36
#define BSSGP_PDU_RESERVED_0X37                0x37
#define BSSGP_PDU_RESERVED_0X38                0x38
#define BSSGP_PDU_RESERVED_0X39                0x39
#define BSSGP_PDU_RESERVED_0X3A                0x3a
#define BSSGP_PDU_RESERVED_0X3B                0x3b
#define BSSGP_PDU_RESERVED_0X3C                0x3c
#define BSSGP_PDU_RESERVED_0X3D                0x3d
#define BSSGP_PDU_RESERVED_0X3E                0x3e
#define BSSGP_PDU_RESERVED_0X3F                0x3f

#define BSSGP_PDU_SGSN_INVOKE_TRACE            0x40
#define BSSGP_PDU_STATUS                       0x41

#define BSSGP_PDU_RESERVED_0X42                0x42
#define BSSGP_PDU_RESERVED_0X43                0x43
#define BSSGP_PDU_RESERVED_0X44                0x44
#define BSSGP_PDU_RESERVED_0X45                0x45
#define BSSGP_PDU_RESERVED_0X46                0x46
#define BSSGP_PDU_RESERVED_0X47                0x47
#define BSSGP_PDU_RESERVED_0X48                0x48
#define BSSGP_PDU_RESERVED_0X49                0x49
#define BSSGP_PDU_RESERVED_0X4A                0x4a
#define BSSGP_PDU_RESERVED_0X4B                0x4b
#define BSSGP_PDU_RESERVED_0X4C                0x4c
#define BSSGP_PDU_RESERVED_0X4D                0x4d
#define BSSGP_PDU_RESERVED_0X4E                0x4e
#define BSSGP_PDU_RESERVED_0X4F                0x4f

#define BSSGP_PDU_DOWNLOAD_BSS_PFC             0x50
#define BSSGP_PDU_CREATE_BSS_PFC               0x51
#define BSSGP_PDU_CREATE_BSS_PFC_ACK           0x52
#define BSSGP_PDU_CREATE_BSS_PFC_NACK          0x53
#define BSSGP_PDU_MODIFY_BSS_PFC               0x54
#define BSSGP_PDU_MODIFY_BSS_PFC_ACK           0x55
#define BSSGP_PDU_DELETE_BSS_PFC               0x56
#define BSSGP_PDU_DELETE_BSS_PFC_ACK           0x57
#define BSSGP_PDU_DELETE_BSS_PFC_REQ           0x58
#define BSSGP_PDU_PS_HANDOVER_REQUIRED         0x59
#define BSSGP_PDU_PS_HANDOVER_REQUIRED_ACK     0x5a
#define BSSGP_PDU_PS_HANDOVER_REQUIRED_NACK    0x5b
#define BSSGP_PDU_PS_HANDOVER_REQUEST          0x5c
#define BSSGP_PDU_PS_HANDOVER_REQUEST_ACK      0x5d
#define BSSGP_PDU_PS_HANDOVER_REQUEST_NACK     0x5e

#define BSSGP_PDU_RESERVED_0X5F                0x5f

#define BSSGP_PDU_PERFORM_LOCATION_REQUEST     0x60
#define BSSGP_PDU_PERFORM_LOCATION_RESPONSE    0x61
#define BSSGP_PDU_PERFORM_LOCATION_ABORT       0x62
#define BSSGP_PDU_POSITION_COMMAND             0x63
#define BSSGP_PDU_POSITION_RESPONSE            0x64

#define BSSGP_PDU_RESERVED_0X65                0x65
#define BSSGP_PDU_RESERVED_0X66                0x66
#define BSSGP_PDU_RESERVED_0X67                0x67
#define BSSGP_PDU_RESERVED_0X68                0x68
#define BSSGP_PDU_RESERVED_0X69                0x69
#define BSSGP_PDU_RESERVED_0X6A                0x6a
#define BSSGP_PDU_RESERVED_0X6B                0x6b
#define BSSGP_PDU_RESERVED_0X6C                0x6c
#define BSSGP_PDU_RESERVED_0X6D                0x6d
#define BSSGP_PDU_RESERVED_0X6E                0x6e
#define BSSGP_PDU_RESERVED_0X6F                0x6f

#define BSSGP_PDU_RAN_INFORMATION              0x70
#define BSSGP_PDU_RAN_INFORMATION_REQUEST      0x71
#define BSSGP_PDU_RAN_INFORMATION_ACK          0x72
#define BSSGP_PDU_RAN_INFORMATION_ERROR        0x73
#define BSSGP_PDU_RAN_INFORMATION_APP_ERROR    0x74

#define BSSGP_PDU_RESERVED_0X75                0x75
#define BSSGP_PDU_RESERVED_0X76                0x76
#define BSSGP_PDU_RESERVED_0X77                0x77
#define BSSGP_PDU_RESERVED_0X78                0x78
#define BSSGP_PDU_RESERVED_0X79                0x79
#define BSSGP_PDU_RESERVED_0X7A                0x7a
#define BSSGP_PDU_RESERVED_0X7B                0x7b
#define BSSGP_PDU_RESERVED_0X7C                0x7c
#define BSSGP_PDU_RESERVED_0X7D                0x7d
#define BSSGP_PDU_RESERVED_0X7E                0x7e
#define BSSGP_PDU_RESERVED_0X7F                0x7f

#define BSSGP_PDU_MBMS_SESSION_START_REQ       0x80
#define BSSGP_PDU_MBMS_SESSION_START_RESP      0x81
#define BSSGP_PDU_MBMS_SESSION_STOP_REQ        0x82
#define BSSGP_PDU_MBMS_SESSION_STOP_RESP       0x83
#define BSSGP_PDU_MBMS_SESSION_UPDATE_REQ      0x84
#define BSSGP_PDU_MBMS_SESSION_UPDATE_RESP     0x85

#define BSSGP_PDU_RESERVED_0X86                0x86
#define BSSGP_PDU_RESERVED_0X87                0x87
#define BSSGP_PDU_RESERVED_0X88                0x88
#define BSSGP_PDU_RESERVED_0X89                0x89
#define BSSGP_PDU_RESERVED_0X8A                0x8a
#define BSSGP_PDU_RESERVED_0X8B                0x8b
#define BSSGP_PDU_RESERVED_0X8C                0x8c
#define BSSGP_PDU_RESERVED_0X8D                0x8d
#define BSSGP_PDU_RESERVED_0X8E                0x8e
#define BSSGP_PDU_RESERVED_0X8F                0x8f

#define BSSGP_PDU_RESERVED_0X90                0x90
#define BSSGP_PDU_PS_HANDOVER_COMPLETE         0x91
#define BSSGP_PDU_PS_HANDOVER_CANCEL           0x92
#define BSSGP_PDU_PS_HANDOVER_COMPLETE_ACK     0x93

/*
0x91 PS-HANDOVER-COMPLETE
0x92 PS-HANDOVER-CANCEL
0x93 PS-HANDOVER-COMPLETE-ACK
*/

/* Information element coding, v 6.5.0, table 11.3, p 72 */
#define BSSGP_IEI_ALIGNMENT_OCTETS                         0x00
#define BSSGP_IEI_BMAX_DEFAULT_MS                          0x01
#define BSSGP_IEI_BSS_AREA_INDICATION                      0x02
#define BSSGP_IEI_BUCKET_LEAK_RATE                         0x03
#define BSSGP_IEI_BVCI                                     0x04
#define BSSGP_IEI_BVC_BUCKET_SIZE                          0x05
#define BSSGP_IEI_BVC_MEASUREMENT                          0x06
#define BSSGP_IEI_CAUSE                                    0x07
#define BSSGP_IEI_CELL_IDENTIFIER                          0x08
#define BSSGP_IEI_CHANNEL_NEEDED                           0x09
#define BSSGP_IEI_DRX_PARAMETERS                           0x0a
#define BSSGP_IEI_EMLPP_PRIORITY                           0x0b
#define BSSGP_IEI_FLUSH_ACTION                             0x0c
#define BSSGP_IEI_IMSI                                     0x0d
#define BSSGP_IEI_LLC_PDU                                  0x0e
#define BSSGP_IEI_LLC_FRAMES_DISCARDED                     0x0f
#define BSSGP_IEI_LOCATION_AREA                            0x10
#define BSSGP_IEI_MOBILE_ID                                0x11
#define BSSGP_IEI_MS_BUCKET_SIZE                           0x12
#define BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY               0x13
#define BSSGP_IEI_OMC_ID                                   0x14
#define BSSGP_IEI_PDU_IN_ERROR                             0x15
#define BSSGP_IEI_PDU_LIFETIME                             0x16
#define BSSGP_IEI_PRIORITY                                 0x17
#define BSSGP_IEI_QOS_PROFILE                              0x18
#define BSSGP_IEI_RADIO_CAUSE                              0x19
#define BSSGP_IEI_RA_CAP_UPD_CAUSE                         0x1a
#define BSSGP_IEI_ROUTING_AREA                             0x1b
#define BSSGP_IEI_R_DEFAULT_MS                             0x1c
#define BSSGP_IEI_SUSPEND_REFERENCE_NUMBER                 0x1d
#define BSSGP_IEI_TAG                                      0x1e
#define BSSGP_IEI_TLLI                                     0x1f
#define BSSGP_IEI_TMSI                                     0x20
#define BSSGP_IEI_TRACE_REFERENCE                          0x21
#define BSSGP_IEI_TRACE_TYPE                               0x22
#define BSSGP_IEI_TRANSACTION_ID                           0x23
#define BSSGP_IEI_TRIGGER_ID                               0x24
#define BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED                0x25
#define BSSGP_IEI_LSA_IDENTIFIER_LIST                      0x26
#define BSSGP_IEI_LSA_INFORMATION                          0x27
#define BSSGP_IEI_PFI                                      0x28
#define BSSGP_IEI_GPRS_TIMER                               0x29
#define BSSGP_IEI_ABQP                                     0x3a
#define BSSGP_IEI_FEATURE_BITMAP                           0x3b
#define BSSGP_IEI_BUCKET_FULL_RATIO                        0x3c
#define BSSGP_IEI_SERVICE_UTRAN_CCO                        0x3d
#define BSSGP_IEI_NSEI                                     0x3e
#define BSSGP_IEI_RRLP_APDU                                0x3f
#define BSSGP_IEI_LCS_QOS                                  0x40
#define BSSGP_IEI_LCS_CLIENT_TYPE                          0x41
#define BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA            0x42
#define BSSGP_IEI_LOCATION_TYPE                            0x43
#define BSSGP_IEI_LOCATION_ESTIMATE                        0x44
#define BSSGP_IEI_POSITIONING_DATA                         0x45
#define BSSGP_IEI_DECIPHERING_KEYS                         0x46
#define BSSGP_IEI_LCS_PRIORITY                             0x47
#define BSSGP_IEI_LCS_CAUSE                                0x48
#define BSSGP_IEI_LCS_CAPABILITY                           0x49
#define BSSGP_IEI_RRLP_FLAGS                               0x4a
#define BSSGP_IEI_RIM_APP_ID                               0x4b
#define BSSGP_IEI_RIM_SEQUENCE_NUMBER                      0x4c
#define BSSGP_IEI_RAN_INF_REQUEST_APP_CONTAINER            0x4d
#define BSSGP_IEI_RAN_INF_APP_CONTAINER                    0x4e
#define BSSGP_IEI_RIM_PDU_INDICATIONS					   0x4f
#define BSSGP_IEI_NUMBER_OF_CONTAINER_UNITS                0x50
#define BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS              0x52
#define BSSGP_IEI_GLOBAL_CN_ID                             0x53
#define BSSGP_IEI_RIM_ROUTING_INFORMATION				   0x54
#define BSSGP_IEI_RIM_PROTOCOL_VERSION					   0x55
#define BSSGP_IEI_APPLICATION_ERROR_CONTAINER			   0x56

#define BSSGP_IEI_RAN_INF_REQUEST_RIM_CONTAINER            0x57
#define BSSGP_IEI_RAN_INF_RIM_CONTAINER                    0x58

#define BSSGP_IEI_RAN_INF_APP_ERROR_RIM_CONTAINER          0x59
#define BSSGP_IEI_RAN_INF_ACK_RIM_CONTAINER                0x5a
#define BSSGP_IEI_RAN_INF_ERROR_RIM_CONTAINER              0x5b
/*
ETSI
3GPP TS 48.018 version 6.16.0 Release 6 108 ETSI TS 148 018 V6.16.0 (2006-12)
IEI coding
(hexadecimal)
IEI Types

x5c TMGI
x5d MBMS Session Identity
x5e MBMS Session Duration
x5f MBMS Service Area Identity List
x60 MBMS Response
x61 MBMS Routing Area List
x62 MBMS Session Information
x63 MBMS Stop Cause
x64 Source BSS to Target BSS Transparent Container
x65 Target BSS to Source BSS Transparent Container
x66 NAS container for PS Handover
x67 PFCs to be set-up list
x68 List of set-up PFCs
x69 Extended Feature Bitmap
x6a Source RNC to Target RNC Transparent Container
x6b Target RNC to Source RNC Transparent Container
x6c RNC Identifier
x6d Page Mode
x6e Container ID
x6f Global TFI
x70 IMEI
x71 Time to MBMS Data Transfer
x72 MBMS Session Repetition Number
x73 Inter RAT Handover Info
x74 PS Handover Command
x75 PS Handover Indications
x76 SI/PSI Container
x77 Active PFCs List
x78 Velocity Data
x79 DTM Handover Command
x7a CS Indication
x7b Requested GANSS Assistance Data
x7c GANSS Location Type
x7d GANSS Positioning Data
x7e Flow Control Granularity
x7f eNB Identifier
x80 E-UTRAN Inter RAT Handover Info
x81 Subscriber Profile ID for RAT/Frequency priority
x82 Request for Inter RAT Handover Info
x83 Reliable Inter RAT Handover Info
x84 SON Transfer Application Identity
x85 CSG Identifier
x86 TAC
*/

/* Macros */
/* Defined localy here without the check of curr_len wrapping, that will be taken care of when this IEI dissecton finishes */
#define ELEM_IN_ELEM_MAND_TELV(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition) \
{\
	if ((consumed = elem_telv(tvb, tree, pinfo, (guint8) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, curr_len, EMT_elem_name_addition)) > 0) \
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
			get_gsm_a_msg_string(EMT_pdu_type, EMT_elem_idx), \
			(EMT_elem_name_addition == NULL) ? "" : EMT_elem_name_addition \
			); \
	} \
}

#define ELEM_IN_ELEM_OPT_TELV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
	if (curr_len != 0){\
		if ((consumed = elem_telv(tvb, tree, pinfo, (guint8) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, curr_len, EOT_elem_name_addition)) > 0) \
		{ \
			curr_offset += consumed; \
			curr_len -= consumed; \
		} \
	} \
}

/* Forward declarations */
static guint16 de_bssgp_source_BSS_to_target_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);
static guint16 de_bssgp_target_BSS_to_source_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);
static guint16 de_bssgp_ran_inf_request_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);
static guint16 de_bssgp_ran_inf_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);
static guint16 de_bssgp_ran_inf_ack_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);
static guint16 de_bssgp_ran_inf_error_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);
static guint16 de_bssgp_ran_inf_app_error_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);


static const value_string tab_nacc_cause[]={
  { 0x00,			"Other unspecified error" },
  { 0x01,			"Syntax error in the Application Container" },
  { 0x02,			"Reporting Cell Identifier does not match with the Destination Cell Identifier or with the Source Cell Identifier" },
  { 0x03,			"SI/PSI type error" },
  { 0x04,			"Inconsistent length of a SI/PSI message" },
  { 0x05,			"Inconsistent set of messages" },
  { 0,				NULL },

};


/*
 * 11.3	Information Element Identifier (IEI)
 */

/*
 * 11.3.1	Alignment octets
 */
static guint16
de_bssgp_aligment_octets(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree, tvb, curr_offset, len, "%u Spare octet(s)",len);

	return(len);
}

/*
 * 11.3.2	Bmax default MS
 */
static guint16
de_bssgp_bmax_default_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_bmax, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.3	BSS Area Indication
 */
static guint16
de_bssgp_bss_area_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_bss_area_ind, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.4	Bucket Leak Rate (R)
 */
static guint16
de_bssgp_bucket_leak_rate(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_r, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.5	BVC Bucket Size
 */
static guint16
de_bssgp_bvc_bucket_size(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_bucket_size, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.6	BVCI (BSSGP Virtual Connection Identifier)
 */
static guint16
de_bssgp_bvci(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint16 bvci;

	curr_offset = offset;

	/* octet 3-4 Unstructured value */
	bvci = tvb_get_ntohs(tvb,curr_offset);
	proto_tree_add_item(tree, hf_bssgp_bvci, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	if (add_string)
		g_snprintf(add_string, string_len, " - 0x%x", bvci);


	return(curr_offset-offset);
}
/*
 * 11.3.7	BVC Measurement
 */
static guint16
de_bssgp_bvc_meas(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* 	The Delay Value field is coded as a 16-bit integer value in units of centi-seconds (one hundredth of a second). This
	 * coding provides a range of over 10 minutes in increments of 10 ms. As a special case, the hexadecimal value 0xFFFF
	 *(decimal 65 535) shall be interpreted as "infinite delay".
	 */
	proto_tree_add_item(tree, hf_bssgp_delay_val, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.8	Cause
 */
static const value_string bssgp_cause_vals[] = {
  { 0x00, "Processor overload" },
  { 0x01, "Equipment failure" },
  { 0x02, "Transit network service failure" },
  { 0x03, "Network service transmission capacity modified from zero kbps to greater than zero kbps" },
  { 0x04, "Unknown MS" },
  { 0x05, "BVCI unknown" },
  { 0x06, "Cell traffic congestion" },
  { 0x07, "SGSN congestion" },
  { 0x08, "O&M intervention" },
  { 0x09, "BVCI blocked" },
  { 0x0a, "PFC create failure" },
  { 0x0b, "PFC preempted" },
  { 0x0c, "ABQP no more supported" },

  { 0x0d, "Undefined - protocol error - unspecified" },
  { 0x0e, "Undefined - protocol error - unspecified" },
  { 0x0f, "Undefined - protocol error - unspecified" },
  { 0x10, "Undefined - protocol error - unspecified" },
  { 0x11, "Undefined - protocol error - unspecified" },
  { 0x12, "Undefined - protocol error - unspecified" },
  { 0x13, "Undefined - protocol error - unspecified" },
  { 0x14, "Undefined - protocol error - unspecified" },
  { 0x15, "Undefined - protocol error - unspecified" },
  { 0x16, "Undefined - protocol error - unspecified" },
  { 0x17, "Undefined - protocol error - unspecified" },
  { 0x18, "Undefined - protocol error - unspecified" },
  { 0x19, "Undefined - protocol error - unspecified" },
  { 0x1a, "Undefined - protocol error - unspecified" },
  { 0x1b, "Undefined - protocol error - unspecified" },
  { 0x1c, "Undefined - protocol error - unspecified" },
  { 0x1d, "Undefined - protocol error - unspecified" },
  { 0x1e, "Undefined - protocol error - unspecified" },
  { 0x1f, "Undefined - protocol error - unspecified" },

  { 0x20, "Semantically incorrect PDU" },
  { 0x21, "Invalid mandatory information" },
  { 0x22, "Missing mandatory IE" },
  { 0x23, "Missing conditional IE" },
  { 0x24, "Unexpected conditional IE" },
  { 0x25, "Conditional IE error" },
  { 0x26, "PDU not compatible with the protocol state" },
  { 0x27, "Protocol error - unspecified" },
  { 0x28, "PDU not compatible with the feature set" },
  { 0x29, "Requested information not available" },
  { 0x2a, "Unknown destination address" },
  { 0x2b, "Unknown RIM application identity" },
  { 0x2c, "Invalid container unit information" },
  { 0x2d, "PFC queuing" },
  { 0x2e, "PFC created successfully" },
  { 0x2f, "T12 expiry" },
  { 0x30, "MS under PS Handover treatment" },
  { 0x31, "Uplink quality" },
  { 0x32, "Uplink strength" },
  { 0x33, "Downlink quality" },
  { 0x34, "Downlink strength" },
  { 0x35, "Distance" },
  { 0x36, "Better cell" },
  { 0x37, "Traffic" },
  { 0x38, "Radio contact lost with MS" },
  { 0x39, "MS back on old channel" },
  { 0x3a, "T13 expiry" },
  { 0x3b, "T14 expiry" },
  { 0x3c, "Not all requested PFCs created" },
  { 0x3d, "CS cause" },
  { 0x3e, "Requested ciphering and/or integrity protection algorithms not supported" },
  { 0x3f, "Relocation failure in target system" },
  { 0x40, "Directed Retry" },
  { 0x41, "Time critical relocation" },
  { 0x42, "PS Handover Target not allowed" },
  { 0x43, "PS Handover not Supported in Target BSS or Target System" },
  { 0x44, "Incoming relocation not supported due to PUESBINE feature" },
  { 0x45, "DTM Handover - No CS resource" },
  { 0x46, "DTM Handover - PS Allocation failure" },
  { 0x47, "DTM Handover - T24 expiry" },
  { 0x48, "DTM Handover - Invalid CS Indication IE" },
  { 0x49, "DTM Handover - T23 expiry" },
  { 0x4a, "DTM Handover - MSC Error" },
  { 0x4b, "Invalid CSG cell" },
  { 0,    NULL },
};

value_string_ext bssgp_cause_vals_ext = VALUE_STRING_EXT_INIT(bssgp_cause_vals);

static guint16
de_bssgp_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* 	The Delay Value field is coded as a 16-bit integer value in units of centi-seconds (one hundredth of a second). This
	 * coding provides a range of over 10 minutes in increments of 10 ms. As a special case, the hexadecimal value 0xFFFF
	 *(decimal 65 535) shall be interpreted as "infinite delay".
	 */
	proto_tree_add_item(tree, hf_bssgp_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;

	return(curr_offset-offset);
}
/*
 * 11.3.9	Cell Identifier
 */
/*
 * octets 3-8 Octets 3 to 8 contain the value part (starting with octet 2) of the
 * Routing Area Identification IE defined in 3GPP TS 24.008, not
 * including 3GPP TS 24.008 IEI
 * Octets 9 and 10 contain the value part (starting with octet 2) of the
 * Cell Identity IE defined in 3GPP TS 24.008, not including
 * 3GPP TS 24.008 IEI (10.5.1.1)
 */

static guint16
de_bssgp_cell_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
	guint32	curr_offset;
	guint16 ci;

	curr_offset = offset;

	curr_offset = curr_offset + de_gmm_rai(tvb, tree, pinfo, curr_offset, 6, add_string, string_len);
	/*Why doesn't this work? ( add_string will not contain RAI + CI )
	 * curr_offset = curr_offset + de_cell_id(tvb, tree, curr_offset , 2, add_string, string_len);
	 */
	ci = tvb_get_ntohs(tvb, curr_offset);
	proto_tree_add_item(tree, hf_bssgp_ci, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;
	if (add_string)
		g_snprintf(add_string, string_len, "%s, CI %u", add_string, ci);


	return(curr_offset-offset);
}
/*
 * 11.3.10	Channel needed
 */
/* Rest of element coded as the value part of the Channel Needed
 * PDU defined in 3GPP TS 29.018, not including 3GPP TS 29.018
 * IEI and 3GPP TS 29.018 length indicator
 * TS 29.018
 * The rest of the information element is coded as the IEI part and the
 * value part of the Channel Needed IE defined in 3GPP TS 44.018.
 */
static guint16
de_bssgp_chnl_needed(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	curr_offset = de_rr_chnl_needed(tvb, tree, pinfo, curr_offset, len , NULL, 0);

	return(curr_offset-offset);
}

/*
 * 11.3.11	DRX Parameters
 */
/*
 * Rest of element coded as the value part defined in
 * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
 * 3GPP TS 24.008 octet length indicator
 */
/*
 * 11.3.12	eMLPP-Priority
 */
/*
 * Rest of element coded as the value part of the eMLPP-Priority IE
 * defined in 3GPP TS 48.008, not including 3GPP TS 48.008 IEI and
 * 3GPP TS 48.008 length indicator
 */
/*
 * 11.3.13	Flush Action
 */
static const value_string bssgp_flush_action_vals[] = {
    { 0x00, "LLC-PDU(s) deleted" },
    { 0x01, "LLC-PDU(s) transferred" },
    { 0,    NULL },
    /* Otherwise "Reserved" */
  };

static guint16
de_bssgp_flush_action(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8  oct;

	curr_offset = offset;

	/* Action value */
	oct = tvb_get_guint8(tvb,curr_offset);
	proto_tree_add_item(tree, hf_bssgp_flush_action, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;
	if (add_string)
		g_snprintf(add_string, string_len, " - %s", val_to_str_const(oct, bssgp_flush_action_vals, "Reserved"));


	return(curr_offset-offset);
}
/*
 * 11.3.14	IMSI
 */
/* Octets 3-n contain an IMSI coded as the value part of the Mobile
 * Identity IE defined in 3GPP TS 24.008
 * (NOTE 1)
 * NOTE 1: The Type of identity field in the Mobile Identity IE shall be ignored by
 * the receiver.
 */
/*
 * 11.3.15	LLC-PDU
 */

static guint16
de_bssgp_llc_pdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *next_tvb=NULL;
	guint32	curr_offset;

	curr_offset = offset;



	if(len > 0){
		next_tvb = tvb_new_subset_remaining(tvb, curr_offset);
		proto_tree_add_text(tree, tvb, curr_offset, len, "LLC Data");
	}

  if(next_tvb){
    if (llc_handle) {
      call_dissector(llc_handle, next_tvb, gpinfo, gparent_tree);
    }
    else if (data_handle) {
      call_dissector(data_handle, next_tvb, gpinfo, gparent_tree);
    }
  }

	return(len);
}
/*
 * 11.3.16	LLC Frames Discarded
 */
static guint16
de_bssgp_llc_frames_disc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct;

	curr_offset = offset;

	/* Action value */
	oct = tvb_get_guint8(tvb,curr_offset);
	proto_tree_add_item(tree, hf_bssgp_llc_frames_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;

	if (add_string)
		g_snprintf(add_string, string_len, " - %u Frames", oct);

	return(curr_offset-offset);
}
/*
 * 11.3.17	Location Area
 */
/* Octets 3 to 7 contain the value part (starting with octet 2) of the
 * Location Area Identification IE defined in 3GPP TS 24.008, not
 * including 3GPP TS 24.008 IEI
 */

/*
 * 11.3.18	LSA Identifier List
 */
/* Rest of element coded as in 3GPP TS 48.008, not including
 * 3GPP TS 48.008 IEI and 3GPP TS 48.008 length indicator
 */
/*
 * 11.3.19	LSA Information
 */
/* Rest of element coded as in 3GPP TS 48.008, not including
 * 3GPP TS 48.008 IEI and 3GPP TS 48.008 length indicator
 */
/*
 * 11.3.20	Mobile Id
 */
/* Octets 3-n contain either the IMSI, IMEISV or IMEI coded as the
 * value part (starting with octet 3) of the Mobile Identity IE defined in
 * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
 * 3GPP TS 24.008 length indcator
 */
/*
 * 11.3.21	MS Bucket Size
 */

static guint16
de_bssgp_ms_bucket_size(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* The Bmax field is coded as Bmax of BVC Bucket Size, see sub-clause 11.3.5. */
	proto_tree_add_item(tree, hf_bssgp_bucket_size, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.22	MS Radio Access Capability
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
 * 3GPP TS 24.008 octet length indicator.
 */
/*
 * 11.3.23	OMC Id
 */
static guint16
de_bssgp_omc_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* octet 3-22 For the OMC identity, see 3GPP TS 12.20 */
	proto_tree_add_item(tree, hf_bssgp_omc_id, tvb, curr_offset, len, ENC_BIG_ENDIAN);

	return len;
}
/*
 * 11.3.24	PDU In Error
 */
static guint16
de_bssgp_pdu_in_error(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* octet 3-? Erroneous BSSGP PDU */
	 proto_tree_add_item(tree, hf_bssgp_msg_type, tvb, 0, 1, ENC_BIG_ENDIAN);
	 curr_offset++;

	 proto_tree_add_text(tree, tvb, curr_offset, len-1, "PDU Data");

	return len;
}
/*
 * 11.3.25 PDU Lifetime
 */
static guint16
de_bssgp_pdu_lifetime(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_delay_val, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}

/*
The Delay Value field is coded as a 16-bit integer value in units of centi-seconds (one hundredth of a second). This
coding provides a range of over 10 minutes in increments of 10 ms. As a special case, the hexadecimal value 0xFFFF
(decimal 65 535) shall be interpreted as "infinite delay".
*/
/*
 * 11.3.26	PDU Type
 */
/*
 * 11.3.27	Priority
 */
/* Rest of element coded as the value part of the Priority IE defined in
 * 3GPP TS 48.008, not including 3GPP TS 48.008 IEI and
 * 3GPP TS 48.008 length indicator
 */
/*
 * 11.3.28	QoS Profile
 */
static const true_false_string  bssgp_a_bit_vals = {
    "Radio interface uses RLC/MAC-UNITDATA functionality",
    "Radio interface uses RLC/MAC ARQ functionality"
};

static const true_false_string  bssgp_t_bit_vals = {
    "The SDU contains data",
    "The SDU contains signalling"
};

static const true_false_string  bssgp_cr_bit_vals = {
    "The SDU does not contain a LLC ACK or SACK command/response frame type",
    "The SDU contains a LLC ACK or SACK command/response frame type"
};

const value_string bssgp_peak_rate_gran_vals[] = {
	{ 0x0, "100 bits/s increments" },
    { 0x1, "1000 bits/s increments" },
    { 0x2, "10000 bits/s increments" },
    { 0x3, "100000 bits/s increments" },
  { 0, NULL }
};
  static const value_string bssgp_precedence_ul[] = {
    { 0,   "High priority" },
    { 1,   "Normal priority" },
    { 2,   "Low priority" },
    { 0,   NULL },
  };

  static const value_string bssgp_precedence_dl[] = {
    { 0,   "Radio priority 1" },
    { 1,   "Radio priority 2" },
    { 2,   "Radio priority 3" },
    { 3,   "Radio priority 4" },
    { 4,   "Radio priority unknown" },
    { 0,   NULL },
  };

static guint16
de_bssgp_qos_profile(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_item *pi, *pre_item;
	guint32	curr_offset;
	guint16 peak_bit_rate;
	guint8  rate_gran, precedence;
	int     link_dir;

	curr_offset = offset;

	/* octet 3-4 Peak bit rate provided by the network (note)
	 * NOTE: The bit rate 0 (zero) shall mean "best effort" in this IE.
	 */
	link_dir = gpinfo->link_dir;

	peak_bit_rate = tvb_get_ntohs(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1, "Peak bit rate: ");
	if (peak_bit_rate == 0) {
		proto_item_append_text(pi, "Best effort");
	}else{
		rate_gran = tvb_get_guint8(tvb, curr_offset+2)&0xc0;
		switch(rate_gran){
			case 0:
				/* 100 bits/s increments */
				proto_item_append_text(pi, "%u bits/s", peak_bit_rate * 100);
				break;
			case 1:
				/* 1000 bits/s increments */
				proto_item_append_text(pi, "%u kbits/s", peak_bit_rate);
				break;
			case 2:
				/* 10000 bits/s increments */
				proto_item_append_text(pi, "%u kbits/s", peak_bit_rate * 10);
				break;
			case 3:
				/* 100000 bits/s increments */
				proto_item_append_text(pi, "%u kbits/s", peak_bit_rate * 100);
				break;
			default:
				break;
		}
	}
	curr_offset+=2;

	/* octet 5 Peak Bit Rate Granularity C/R T A Precedence */
	/* If the Gigabit Interface feature has not been negotiated, the "Peak bit rate"
	 * field is the binary encoding of the peak bit rate information expressed in 100 bits/s
	 * increments, starting from 0 x 100 bits/s until 65 535 x 100 bits/s (6 Mbps).
	 *
	 * If the Gigabit Interface feature has been negotiated, the "Peak bit rate" field is the
	 * binary encoding of the peak bit rate information expressed in increments as defined by
	 * the Peak Bit Rate Granularity field.
	 */
	proto_tree_add_item(tree, hf_bssgp_peak_rate_gran, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_cr_bit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_t_bit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_a_bit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	precedence = tvb_get_guint8(tvb, curr_offset) & 0x7;
	pre_item = proto_tree_add_item(tree, hf_bssgp_precedence, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	if(link_dir == P2P_DIR_DL){
		proto_item_append_text(pre_item, " %s", val_to_str_const((guint32)precedence, bssgp_precedence_dl, "Radio Priority Unknown(Radio priority 3)"));
	}else{
		proto_item_append_text(pre_item, " %s", val_to_str_const((guint32)precedence, bssgp_precedence_ul, "Priority Unknown(Low priority)"));
	}

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.29	Radio Cause
 */
  static const value_string bssgp_radio_cause_vals[] = {
    { 0x00, "Radio contact lost with the MS" },
    { 0x01, "Radio link quality insufficient to continue communication" },
    { 0x02, "Cell reselection ordered" },
    { 0x03, "Cell reselection prepare" },
    { 0x04, "Cell reselection failure" },
    { 0,    NULL },
    /* Otherwise "Reserved (Radio contact lost with the MS)" */
  };

static guint16
de_bssgp_ra_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_ra_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.30	RA-Cap-UPD-Cause
 */
  static const value_string bssgp_ra_cap_upd_cause_vals[] = {
    { 0x00, "OK, RA capability IE present" },
    { 0x01, "TLLI unknown in SGSN" },
    { 0x02, "No RA capabilities or IMSI available for this MS" },
    { 0,    NULL },
    /* Otherwise "Reserved (TLLI unknown in SGSN)" */
  };

static guint16
de_bssgp_ra_cap_upd_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_ra_cap_upd_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.31	Routeing Area
 */
/* Octets 3 to 8 contain the value part (starting with octet 2) of the
 * Routing Area Identification IE defined in 3GPP TS 24.008, not
 * including 3GPP TS 24.008 IEI
 */
/*
 * 11.3.32	R_default_MS
 */
static guint16
de_bssgp_r_default_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_r_default_ms, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}

/*
 * 11.3.33	Suspend Reference Number
 */
static guint16
de_bssgp_suspend_ref_no(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Unstructured value */
	proto_tree_add_item(tree, hf_bssgp_suspend_ref_no, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.34	Tag
 */

static guint16
de_bssgp_tag(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Unstructured value */
	proto_tree_add_item(tree, hf_bssgp_tag, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.35	Temporary logical link Identity (TLLI)
 * Rest of element coded as the value part of the TLLI information
 * element in 3GPP TS 44.018, not including 3GPP TS 44.018 IEI.
 */
/*
 * 11.3.36	Temporary Mobile Subscriber Identity (TMSI)
 */
/* Rest of element coded as the value part of the TMSI/P-TMSI
 * information element in 3GPP TS 24.008, not including
 * 3GPP TS 24.008 IEI.
 */
/*
 * 11.3.37	Trace Reference
 */
static guint16
de_bssgp_trace_ref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* octet 3-4 Trace Reference */
	proto_tree_add_item(tree, hf_bssgp_trace_ref, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

	curr_offset+=2;

	return(curr_offset-offset);
}

/*
 * 11.3.38	Trace Type
 */
/* This is coded as specified in Technical Specification
 * 3GPP TS 32.008
 * XXX: Coding unknown (Specification withdrawn) 3GPP TS 32.008
 */
static guint16
de_bssgp_trace_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, len, "Trace Type data ( Coding unknown (Specification withdrawn) 3GPP TS 32.008)");

	return(len);
}
/*
 * 11.3.39	Transaction Id
 */
static guint16
de_bssgp_transaction_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_transaction_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

	return(curr_offset-offset);
}
/*
 * 11.3.40	Trigger Id
 */
static guint16
de_bssgp_trigger_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_trigger_id, tvb, curr_offset, len, ENC_BIG_ENDIAN);

	return(len);
}
/*
 * 11.3.41	Number of octets affected
 */
static guint16
de_bssgp_no_of_oct_affected(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32 no_of_oct;

	curr_offset = offset;

	/* octet 3-5 number of octets transferred or deleted */
	no_of_oct = tvb_get_ntoh24(tvb,curr_offset);
	proto_tree_add_item(tree, hf_bssgp_no_of_oct, tvb, curr_offset, 3, ENC_BIG_ENDIAN);

	curr_offset+=3;

	if (add_string)
		g_snprintf(add_string, string_len, " - %u", no_of_oct);

	return(curr_offset-offset);
}
/*
 * 11.3.42	Packet Flow Identifier (PFI)
 */
/* Rest of element coded as the value part of the Packet Flow
 * Identifier information element in 3GPP TS 24.008, not including
 * 3GPP TS 24.008 IEI
 */
/*
 * 11.3.42a	(void)
 */
/*
 * 11.3.43	Aggregate BSS QoS Profile
 */
/* Rest of element coded as the value part of the QoS information
 * element in 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
 * length indicator. The shorter 3-byte form of QoS information is not
 * allowed in BSSGP PDUs.
 * 10.5.6.5
 */
/*
 * 11.3.44	GPRS Timer
 */
static const value_string bssgp_unit_vals[] = {
    { 0, "incremented in multiples of 2 s" },
    { 1, "incremented in multiples of 1 minute" },
    { 2, "incremented in multiples of decihours" },
    { 3, "incremented in multiples of 500 msec" },
    { 4, "incremented in multiples of 1 minute(Undefined)" },
	{ 5, "incremented in multiples of 1 minute(Undefined)" },
    { 6, "incremented in multiples of 1 minute(Undefined)" },
    { 7, "the timer does not expire" },
    { 0, NULL},
    /* Otherwise "incremented in multiples of 1 minute" */
  };

static guint16
de_bssgp_gprs_timer(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/*octet 3 Unit Value Timer value */
	proto_tree_add_item(tree, hf_bssgp_unit_val, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_gprs_timer, tvb, curr_offset, 3, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.45	Feature Bitmap
 */
static guint16
de_bssgp_feature_bitmap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	/* MBMS */
	proto_tree_add_item(tree, hf_bssgp_mbms, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* EnhancedRadioStatus */
	proto_tree_add_item(tree, hf_bssgp_EnhancedRadioStatus, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* PFCFC */
	proto_tree_add_item(tree, hf_bssgp_pfcfc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* RIM */
	proto_tree_add_item(tree, hf_bssgp_rim, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* LCS */
	proto_tree_add_item(tree, hf_bssgp_lcs, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* INR */
	proto_tree_add_item(tree, hf_bssgp_inr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* CBL */
	proto_tree_add_item(tree, hf_bssgp_cbl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* PFC */
	proto_tree_add_item(tree, hf_bssgp_pfc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.46	Bucket Full Ratio
 */
static guint16
de_bssgp_bucket_full_ratio(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Ratio of the bucket that is filled up with data */
	proto_tree_add_item(tree, hf_bssgp_bucket_full_ratio, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.47	Service UTRAN CCO
 */
static const value_string bssgp_service_utran_cco_vals[] = {
    { 0, "Network initiated cell change order procedure to UTRAN should be performed" },
    { 1, "Network initiated cell change order procedure to UTRAN should not be performed" },
    { 2, "Network initiated cell change order procedure to UTRAN shall not be performed" },
	{ 3, "If received, shall be interpreted as no information available (bits 4-5 valid)" },
	{ 0,    NULL },
    /* Otherwise "No information available" */
  };

static const value_string bssgp_service_eutran_cco_vals[] = {
    { 0, "If received, shall be interpreted as no information available" },
    { 1, "Network initiated cell change order to E-UTRAN or PS handover to E-UTRAN procedure should be performed" },
    { 2, "Network initiated cell change order to E-UTRAN or PS handover to E-UTRAN procedure should not be performed" },
	{ 3, "Network initiated cell change order to E-UTRAN or PS handover to E-UTRAN procedure shall not be performed" },
	{ 0,    NULL },
    /* Otherwise "No information available" */
  };

static guint16
de_bssgp_serv_utran_cco(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Service EUTRAN CCO Value part */
	proto_tree_add_item(tree, hf_bssgp_serv_eutran_cco, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* Service UTRAN CCO Value part */
	proto_tree_add_item(tree, hf_bssgp_serv_utran_cco, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.48	NSEI (Network Service Entity Identifier)
 */
static guint16
de_bssgp_nsei(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint16 nsei;

	curr_offset = offset;

	nsei = tvb_get_ntohs(tvb, curr_offset);
	proto_tree_add_item(tree, hf_bssgp_nsei, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	col_append_sep_fstr(gpinfo->cinfo, COL_INFO, BSSGP_SEP, "NSEI %u", nsei);


	return(curr_offset-offset);
}
/*
 * 11.3.49	RRLP APDU
 */
static guint16
de_bssgp_rrlp_apdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *next_tvb=NULL;
	guint32	curr_offset;

	curr_offset = offset;

	/* The rest of the information element contains an embedded RRLP
	 * message whose content and encoding are defined according to the
	 * 3GPP TS 44.031. The RRLP protocol is not octet aligned.
	 * Therefore, the unused bits in the last octet are padded with zeroes
	 */

	if(len > 0){
		next_tvb = tvb_new_subset_remaining(tvb, curr_offset);
		proto_tree_add_text(tree, tvb, curr_offset, len, "RRLP APDU");
	}

	if(next_tvb){
		if (rrlp_handle) {
			call_dissector(rrlp_handle, next_tvb, gpinfo, gparent_tree);
		}else if (data_handle) {
			call_dissector(data_handle, next_tvb, gpinfo, gparent_tree);
		}
    }
	return(len);
}

/*
 * 11.3.50	LCS QoS
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 48.008, not including 3GPP TS 48.008 IEI and
 * 3GPP TS 48.008 octet length indicator
 */
/*
 * 11.3.51	LCS Client Type
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.52	Requested GPS Assistance Data
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.53	Location Type
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.54	Location Estimate
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 48.008, not including 3GPP TS 48.008 IEI and
 * 3GPP TS 48.008 octet length indicator
 */
/*
 * 11.3.55	Positioning Data
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.56	Deciphering Keys
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.57	LCS Priority
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.58	LCS Cause
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.59	LCS Capability
 */
/* Rest of element coded as the value part of the PS LCS Capability
 * IE defined in 3GPP TS 24.008, not including 3GPP TS 24.008 IEI
 * and length indicator
 */
/*
 * 11.3.60	RRLP Flags
 */

static const true_false_string  bssgp_rrlp_flg1_vals = {
    "Not a Positioning Command or final response",
    "Position Command (BSS to SGSN) or final response (SGSN to BSS)"
};

static guint16
de_bssgp_rrlp_flags(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Flag 1 (Octet 3, bit 1): */
	proto_tree_add_item(tree, hf_bssgp_rrlp_flag1, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

	return(curr_offset-offset);
}

/*
 * 11.3.61	RIM Application Identity
 */

static const value_string bssgp_rim_appid_vals[] = {
    { 0, "Reserved" },
    { 1, "Network Assisted Cell Change (NACC)" },
    { 2, "System Information 3 (SI3)" },
	{ 3, "MBMS data channel" },
	{ 4, "SON Transfer" },
	{ 5, "UTRA System Information (UTRA SI)" },
	{ 0,    NULL },
  };

static guint16
de_bssgp_rim_app_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* RIM Application Identity */
	g_rim_application_identity = tvb_get_guint8(tvb, curr_offset);
	proto_tree_add_item(tree, hf_bssgp_rim_app_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.62	RIM Sequence Number
 */
static guint16
de_bssgp_rim_seq_no(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* RIM Sequence Number */
	proto_tree_add_item(tree, hf_bssgp_rim_seq_no, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
	curr_offset+=4;

	return(curr_offset-offset);
}
/*
 * 11.3.62a	RIM Container
 * 11.3.62a.0	General
 * 11.3.62a.1	RAN-INFORMATION-REQUEST RIM Container
 */
/* Dissection moved */
/*
 * 11.3.62a.2	RAN-INFORMATION RIM Container
 * 11.3.62a.3	RAN-INFORMATION-ACK RIM Container
 * 11.3.62a.4	RAN-INFORMATION-ERROR RIM Container
 * 11.3.62a.5	RAN-INFORMATION-APPLICATION-ERROR RIM Container
 */
/*
 * 11.3.63	Application Container
 * 11.3.63.1	RAN-INFORMATION-REQUEST Application Container
 * 11.3.63.1.0	General
 */



static guint16
de_bssgp_ran_information_request_app_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *new_tvb = NULL;
	guint32	curr_offset;

	curr_offset = offset;

	switch(g_rim_application_identity){
		case 1:
			/* 11.3.63.1.1	RAN-INFORMATION-REQUEST Application Container for the NACC Application */
			/* Reporting Cell Identifier */
			curr_offset = curr_offset + de_bssgp_cell_id(tvb, tree, pinfo,curr_offset, len, add_string, string_len);
			break;
		case 2:
			/* 11.3.63.1.2	RAN-INFORMATION-REQUEST Application Container for the SI3 Application */
			/* Reporting Cell Identifier */
			curr_offset = curr_offset + de_bssgp_cell_id(tvb, tree, pinfo, curr_offset, len, add_string, string_len);
			break;
		case 3:
			/* 11.3.63.1.3	RAN-INFORMATION-REQUEST Application Container for the MBMS data channel Application */
			/* Reporting Cell Identifier */
			curr_offset = curr_offset + de_bssgp_cell_id(tvb, tree, pinfo, curr_offset, len, add_string, string_len);
			break;
		case 4:
			{
			asn1_ctx_t asn1_ctx;

			asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, gpinfo);
			/* 11.3.63.1.4	RAN-INFORMATION-REQUEST Application Container for the SON Transfer Application */
			/* Reporting Cell Identifier */
			/* convert to bit offset */
			curr_offset = curr_offset<<3;
			curr_offset = dissect_s1ap_Global_ENB_ID(tvb, curr_offset<<3, &asn1_ctx, tree, hf_bssgp_Global_ENB_ID_PDU);
			curr_offset = dissect_s1ap_SONtransferRequestContainer(tvb, curr_offset, &asn1_ctx, tree, hf_bssgp_SONtransferRequestContainer_PDU);
			curr_offset += 7; curr_offset >>= 3;
			}
			break;
		case 5:
			/* 11.3.63.1.5 RAN-INFORMATION Application Container for the UTRA SI Application */
			/* Octet 3-m Reporting Cell Identifier
			 * This field is encoded as the Source Cell Identifier IE (UTRAN Source Cell ID) as defined in
			 * 3GPP TS 25.413
			 */
			new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
			curr_offset = curr_offset + dissect_ranap_SourceCellID_PDU(new_tvb, gpinfo, tree);
			break;
		default :
			proto_tree_add_text(tree, tvb, curr_offset, len, "Unknown RIM Application Identity");
			curr_offset+=len;
			break;
	}


	return(curr_offset-offset);
}

/*
 * 11.3.63.2	RAN-INFORMATION Application Container Unit
 * 11.3.63.2.0	General
 */
static const true_false_string  bssgp_si_psi_type_vals = {
    "PSI messages as specified for PBCCH (3GPP TS 44.060) follow",
    "SI messages as specified for BCCH (3GPP TS 44.018) follow"
};

static const value_string bssgp_rat_discriminator_vals[] = {
    { 0, "The reporting RAT is GERAN" },
    { 1, "The reporting RAT is UTRAN" },
    { 2, "The reporting RAT is E-UTRAN" },
	{ 0,    NULL },
  };
static guint16
de_bssgp_ran_information_app_cont_unit(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *new_tvb = NULL;
	guint32	curr_offset;
	guint8 type, num_items, rat_type, oct;
	int i;

	curr_offset = offset;

	switch(g_rim_application_identity){
		case 1:
			/* 11.3.63.2.1 RAN-INFORMATION Application Container for the NACC Application */
			/* Reporting Cell Identifier */
			curr_offset = curr_offset + de_bssgp_cell_id(tvb, tree, pinfo, curr_offset, len, add_string, string_len);
			/* Number of SI/PSI */
			num_items = tvb_get_guint8(tvb,curr_offset)>>1;
			proto_tree_add_item(tree, hf_bssgp_num_si_psi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			/* Type */
			type = tvb_get_guint8(tvb,curr_offset)&0x01;
			proto_tree_add_item(tree, hf_bssgp_si_psi_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
			/* Octet 12-n SI/PSI */
			if(type==1){
				/* If the Type field indicates that "PSI messages as specified for PBCCH (3GPP TS 44.060) follow" then the SI/PSI
				 * field contains Packet System Information message instances encoded for PBCCH as specified in
				 * 3GPP TS 44.060. Each Packet System Information message contains the MESSAGE_TYPE field followed by the
				 * PSI message content. Each message is 22 octets long.
				 */
				for (i=0; i < num_items; i++){
					proto_tree_add_text(tree, tvb, curr_offset, 22, "PSI item %u - not dissected yet",i+1);
					curr_offset+=22;
				}
			}else{
				/* If the Type field indicates that "SI messages as specified for BCCH (3GPP TS 44.018) follow" then the SI/PSI
				 * field contains System Information message instances encoded for BCCH as specified in 3GPP TS 44.018. Each
				 * System Information message contains the Message type octet followed by all the IEs composing the message
				 * payload. Each message is 21 octets long.
				 */
				void			(*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);
				gint			ett_tree;
				int				hf_idx;
				const gchar		*msg_str;
				proto_item		*si_item;
				proto_tree		*si_tree;

				for (i=0; i < num_items; i++){
					oct = tvb_get_guint8(tvb,curr_offset);
					get_rr_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);
					proto_tree_add_text(tree, tvb, curr_offset, 21, "SI item %u ",i+1);
					si_item = proto_tree_add_item(tree, hf_idx, tvb, curr_offset, 1, FALSE);
					si_tree = proto_item_add_subtree(si_item, ett_tree);
					if (msg_fcn_p == NULL){
						proto_tree_add_text(si_tree, tvb, curr_offset, 21, "Unknown SI message");
					}else{
						(*msg_fcn_p)(tvb, si_tree, gpinfo, curr_offset+1, 20);
					}
					curr_offset+=21;
				}
			}
			break;
		case 2:
			/* 11.3.63.2.2 RAN-INFORMATION Application Container for the SI3 Application */
			/* Octet 3-10 Reporting Cell Identifier */
			/* Reporting Cell Identifier: The parameter is encoded as the value part of the Cell Identifier IE
			 * defined in sub-clause 11.3.9, not including IEI and Length Indicator.
			 */
			curr_offset = curr_offset + de_bssgp_cell_id(tvb, tree, pinfo, curr_offset, len, add_string, string_len);
			/* Octet 11-31 SI3 */
			/* SI3: contains the SYSTEM INFORMATION type 3 message encoded for BCCH as specified in 3GPP TS 44.018 ch 9.1.35
			 * It contains the Message type octet followed by all the IEs composing the message payload.
			 * The message is 21 octets long.
			 * dtap_rr_sys_info_3(tvb, tree, curr_offset, len-7)
			 */
			proto_tree_add_text(tree, tvb, curr_offset, 1, "SYSTEM INFORMATION type 3 message");
			curr_offset++;
			break;
		case 3:
			/* 11.3.63.2.3 RAN-INFORMATION Application Container for the MBMS data channel Application */
			/* Octet 3-10 Reporting Cell Identifier */
			curr_offset = curr_offset + de_bssgp_cell_id(tvb, tree, pinfo, curr_offset, len, add_string, string_len);
			/* Octet 11-n MBMS data channel report */
			proto_tree_add_text(tree, tvb, curr_offset, len-6, "MBMS data channel report - not dissected yet");
			break;
		case 4:
			/* 11.3.63.2.4 RAN-INFORMATION Application Container for the SON Transfer Application */
			/* Octet 3 Spare RAT discriminator */
			rat_type = tvb_get_guint8(tvb,curr_offset) & 0x0f;
			proto_tree_add_item(tree, hf_bssgp_rat_discriminator, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
			/* Octet 4-m Reporting Cell Identifier */
			switch(rat_type){
				case 0:
					/* If the RAT discriminator field indicates GERAN, this field is encoded as the value part of the Cell Identifier IE
					 * defined in sub-clause 11.3.9, not including IEI and Length Indicator.
					 */
					curr_offset = curr_offset + de_bssgp_cell_id(tvb, tree, pinfo, curr_offset, len, add_string, string_len);
					break;
				case 1:
					/* If the RAT discriminator field indicates UTRAN, this field is encoded as the Source Cell Identifier IE (UTRAN
					 * Source Cell ID) as defined in 3GPP TS 25.413
					 */
					new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
					curr_offset = curr_offset + dissect_ranap_SourceCellID_PDU(new_tvb, gpinfo, tree);
					break;
				case 2:
					/* If the RAT discriminator field indicates E-UTRAN, this field is encoded as the E-UTRAN CGI IE as
					 * defined in 3GPP TS 36.413
					 */
					new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
					curr_offset = curr_offset + dissect_s1ap_Global_ENB_ID_PDU(new_tvb, gpinfo, tree);
					break;
				default:
					break;
			}

			break;
		case 5:
			/* 11.3.63.2.5 RAN-INFORMATION Application Container for the UTRA SI Application */
			/* Octet 3-m Reporting Cell Identifier
			 * Reporting Cell Identifier: This field is encoded as the Source Cell Identifier IE
			 * (UTRAN Source Cell ID) as defined in 3GPP TS 25.413
			 */
			new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
			curr_offset = curr_offset + dissect_ranap_SourceCellID_PDU(new_tvb, gpinfo, tree);
			/* Octet (m+1)-n UTRA SI Container
			 * UTRA SI Container: This field contains System Information Container valid for the reporting cell
			 * encoded as defined in TS 25.331
			 */
			proto_tree_add_text(tree, tvb, curr_offset, len-(curr_offset-offset), "UTRA SI Container - not dissected yet");
			break;

		default :
			proto_tree_add_text(tree, tvb, curr_offset, len, "Unknown RIM Application Identitys Data");
			curr_offset+=len;
			break;
	}


	return(curr_offset-offset);
}
/*
 * 11.3.64	Application Error Container
 */
static const value_string bssgp_nacc_cause_vals[] = {
    { 0, "Other unspecified error" },
    { 1, "Syntax error in the Application Container" },
    { 2, "Reporting Cell Identifier does not match with the Destination Cell Identifier or with the Source Cell Identifier" },
    { 3, "SI/PSI type error" },
    { 4, "Inconsistent length of a SI/PSI message" },
    { 5, "Inconsistent set of messages" },
	{ 0,    NULL },
  };

static const value_string bssgp_s13_cause_vals[] = {
    { 0, "Other unspecified error" },
    { 1, "Syntax error in the Application Container" },
    { 2, "Reporting Cell Identifier does not match with the Destination Cell Identifier or with the Source Cell Identifier" },
    { 3, "Inconsistent length of a SI3 message" },
    { 4, "Inconsistent set of messages" },
	{ 0,    NULL },
  };

static const value_string bssgp_mbms_data_ch_cause_vals[] = {
    { 0, "Other unspecified error" },
    { 1, "Syntax error in the Application Container" },
    { 2, "Reporting Cell Identifier does not match with the Destination Cell Identifier or with the Source Cell Identifier" },
    { 3, "RAN-INFORMATION/Initial Multiple Report or RANINFORMATION/Single Report PDU exceeds the maximum supported length" },
    { 4, "Inconsistent MBMS data channel description" },
	{ 0,    NULL },
  };

static const value_string bssgp_utra_si_cause_vals[] = {
    { 0, "Other unspecified error" },
    { 1, "Syntax error in the Application Container" },
    { 2, "Inconsistent Reporting Cell Identifier" },
	{ 0,    NULL },
  };

static guint16
de_bssgp_ran_app_error_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *new_tvb = NULL;
	guint32	curr_offset;

	curr_offset = offset;

	switch(g_rim_application_identity){
		case 1:
			/*
			 * 11.3.64.1	Application Error Container layout for the NACC application
			 */
			/* Octet 3 NACC Cause */
			proto_tree_add_item(tree, hf_bssgp_nacc_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
			/* Erroneous Application Container including IEI and LI */
			proto_tree_add_text(tree, tvb, curr_offset, len-(curr_offset-offset), "Erroneous Application Container including IEI and LI");
			break;
		case 2:
			/*
			 * 11.3.64.2	Application Error Container for the SI3 application
			 */
			/* Octet 3 SI3 Cause */
			proto_tree_add_item(tree, hf_bssgp_s13_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
			/* Erroneous Application Container including IEI and LI */
			proto_tree_add_text(tree, tvb, curr_offset, len-(curr_offset-offset), "Erroneous Application Container including IEI and LI");
			break;
		case 3:
			/*
			 * 11.3.64.3	Application Error Container for the MBMS data channel application
			 */
			/* Octet 3 MBMS data channel Cause */
			proto_tree_add_item(tree, hf_bssgp_mbms_data_ch_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
			/* Erroneous Application Container including IEI and LI */
			proto_tree_add_text(tree, tvb, curr_offset, len-(curr_offset-offset), "Erroneous Application Container including IEI and LI");
			break;
		case 4:
			/*
			 * 11.3.64.4	Application Error Container for the SON Transfer Application
			 */
			/* SON Transfer Cause: This field indicates the cause why the Application Error Container IE is sent.
			 * The "SON Transfer Cause" field is encoded as the SON Transfer Cause IE as defined in 3GPP TS 36.413
			 */
			new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
			curr_offset = curr_offset + dissect_s1ap_SONtransferCause_PDU(new_tvb, gpinfo, tree);
			/* Erroneous Application Container including IEI and LI */
			proto_tree_add_text(tree, tvb, curr_offset, len-(curr_offset-offset), "Erroneous Application Container including IEI and LI");
			break;
		case 5:
			/* 11.3.64.5 Application Error Container for the UTRA SI Application*/
			/* Octet 3 UTRA SI Cause */
			proto_tree_add_item(tree, hf_bssgp_utra_si_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			break;
		default :
			proto_tree_add_text(tree, tvb, curr_offset, len, "Unknown Application Error Container");
			curr_offset+=len;
			break;
	}
	return(len);
}

/*
 * 11.3.65	RIM PDU Indications
 */
static const value_string bssgp_ran_inf_req_pdu_t_ext_c_vals[] = {
    { 0, "RAN-INFORMATION-REQUEST/Stop PDU" },
    { 1, "RAN-INFORMATION-REQUEST/Single Report PDU" },
    { 2, "RAN-INFORMATION-REQUEST/Multiple Report PDU" },
	{ 3, "Reserved" },
	{ 4, "Reserved" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0,    NULL },
};

static const value_string bssgp_ran_inf_pdu_t_ext_c_vals[] = {
    { 0, "RAN-INFORMATION/Stop PDU" },
    { 1, "RAN-INFORMATION/Single Report PDU" },
    { 2, "RAN-INFORMATION/Initial Multiple Report PDU" },
	{ 3, "RAN-INFORMATION/Multiple Report PDU" },
	{ 4, "RAN-INFORMATION/End PDU" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0,    NULL },
};

static const true_false_string  bssgp_rim_pdu_ind_ack_vals = {
    "ACK requested",
    "No ACK requested"
};

static guint16
de_bssgp_rim_pdu_indications(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	switch(g_pdu_type){
		case BSSGP_PDU_RAN_INFORMATION_REQUEST:
			/* 11.3.65.1 RAN-INFORMATION-REQUEST RIM PDU Indications */
			/* Table 11.3.65.1: RAN-INFORMATION-REQUEST PDU Type Extension coding */
			proto_tree_add_item(tree, hf_bssgp_ran_inf_req_pdu_t_ext_c, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			/* The ACK field is not used and shall be considered as spare */
			curr_offset++;
			break;
		case BSSGP_PDU_RAN_INFORMATION:
			/* 11.3.65.2 RAN-INFORMATION RIM PDU Indications */
			/* Table 11.3.65.2: RAN-INFORMATION PDU Type Extension coding */
			proto_tree_add_item(tree, hf_bssgp_ran_inf_pdu_t_ext_c, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_bssgp_rim_pdu_ind_ack, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
			break;
		case BSSGP_PDU_RAN_INFORMATION_ERROR:
			/* 11.3.65.3 RAN-INFORMATION-APPLICATION-ERROR RIM PDU Indications */
			proto_tree_add_item(tree, hf_bssgp_rim_pdu_ind_ack, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			/* The PDU Type Extension field is not used and shall be considered as spare */
			curr_offset++;
			break;
		default:
			break;
	}

	return(curr_offset-offset);
}

/*
 * 11.3.65.0	General
 * 11.3.65.1	RAN-INFORMATION-REQUEST RIM PDU Indications
 * 11.3.65.2	RAN-INFORMATION RIM PDU Indications
 * 11.3.65.3	RAN-INFORMATION-APPLICATION-ERROR RIM PDU Indications
 * 11.3.66	(void)
 */
/*
 * 11.3.67	RIM Protocol Version Number
 */
static const value_string bssgp_rim_proto_ver_no_vals[] = {
    { 0, "Reserved" },
    { 1, "Version 1" },
	{ 0,    NULL },
};

static guint16
de_bssgp_rim_proto_ver_no(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Octet 3 RIM Protocol Version Number */
	proto_tree_add_item(tree, hf_bssgp_rim_proto_ver_no, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.68	PFC Flow Control parameters
 */

static guint16
de_bssgp_pfc_flow_ctrl(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree *pfc_tree;
	proto_item *pi, *ti2;

	guint32	curr_offset;
	guint8 num_pfc, i, pfc_len;
	gboolean b_pfc_included;

	curr_offset = offset;

	num_pfc = tvb_get_guint8(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of PFCs: ");

	if (num_pfc < 12) {
		proto_item_append_text(pi, "%u", num_pfc);
	}else {
		proto_item_append_text(pi, "Reserved");
		return (curr_offset-offset);
	}
	curr_offset++;
	if (num_pfc == 0)
		return (curr_offset-offset);

	pfc_len = (len - 1) / num_pfc;
	b_pfc_included = (pfc_len == 6);

	for (i = 0; i < num_pfc; i++) {
		ti2 = proto_tree_add_text(tree, tvb, curr_offset, pfc_len,
					  "PFC (%u)", i + 1);
		pfc_tree = proto_item_add_subtree(ti2, ett_bssgp_pfc_flow_control_parameters_pfc);

		/* PFI: Packet Flow Identifier.
		 * Coded as the value part of the Packet Flow Identifier information element in
		 * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI
		 */
		de_sm_pflow_id(tvb, pfc_tree, pinfo, curr_offset, 1, NULL, 0);
		curr_offset++;

		/* Bmax_PFC: Bucket size of the PFC. Coded like the value part of BVC Bucket Size, see sub-clause 11.3.5. */
		proto_tree_add_item(tree, hf_bssgp_bmax_pfc, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
		curr_offset += 2;

		/* R_PFC: Bucket Leak Rate of the PFC. Coded as the value part of Bucket Leak Rate (R), see sub-clause 11.3.4. */
		proto_tree_add_item(tree, hf_bssgp_r_pfc, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
		curr_offset += 2;

		if (b_pfc_included) {
			/* B_PFC: Bucket Full Ratio of the PFC. This field is only present if the Current Bucket Level (CBL) feature is
			 * negotiated. Otherwise, the flow control parameters for the next PFC, if any, are provided instead. This field if coded as
			 * the value part of the Bucket Full Ratio, see sub-clause 11.3.46.
			 */
			proto_tree_add_item(tree, hf_bssgp_b_pfc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
		}
	}
	return(curr_offset-offset);
}
/*
 * 11.3.69	Global CN-Id
 */
/* Coded as octets 3 to 7 of the Global CN-Id IE, defined in
 * 3GPP TS 29.018
 */
/*
 * 11.3.70	RIM Routing Information
 */
static const value_string bssgp_ra_discriminator_vals[] = {
  { 0, "A Cell Identifier is used to identify a GERAN cell" },
  { 1, "A Global RNC-ID is used to identify a UTRAN RNC" },
  { 2, "An eNB identifier is used to identify an E-UTRAN eNodeB or HeNB" },
  { 0, NULL },
};

static guint16
de_bssgp_rim_routing_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8 oct;
	guint16 rnc_id;
	tvbuff_t *new_tvb = NULL;
	guint32	curr_offset;

	curr_offset = offset;

	/* This information element uniquely identifies either a cell within a
	 * GERAN BSS, a UTRAN RNC or an E-UTRAN eNodeB.
	 */

	/* RIM Routing Address discriminator */
	oct  = tvb_get_guint8(tvb,curr_offset);
	proto_tree_add_item(tree, hf_bssgp_ra_discriminator, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;
	switch(oct){
		case 0:
			/* RIM Routing Address discriminator = 0000:
			 * The RIM Routing Address field contains a Cell Identifier
			 * and is coded as the value part (octet 3 to octet 10) of the
			 * Cell Identifier information element specified in sub-clause 11.3.9.
			 */
			curr_offset = curr_offset + de_bssgp_cell_id(tvb, tree, pinfo, curr_offset, len, add_string, string_len);
			break;
		case 1:
			/* RIM Routing Address discriminator = 0001:
			 * The RIM Routing Address field contains an RNC identifier and is coded as follows:
			 * Octets 4 to 9 contain the value part (starting with octet 2) of the Routing Area Identification IE
			 * defined in 3GPP TS 24.008, not including 3GPP TS 24.008 IEI
			 */
			curr_offset = curr_offset + de_gmm_rai(tvb, tree, pinfo, curr_offset , 6, add_string, string_len);
			/* Octet 10 - 11 RNC-ID (or Extended RNC-ID) */
			rnc_id = tvb_get_ntohs(tvb, curr_offset);
			proto_tree_add_item(tree, hf_bssgp_rnc_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
			curr_offset+=2;

			if (add_string)
				g_snprintf(add_string, string_len, " %s, RNC-ID %u", add_string, rnc_id);
			break;
		case 2:
			/* RIM Routing Address discriminator = 0010:
			 * The RIM Routing Address field contains an eNB identifier and is coded as follows:
			 * Octets 4 to 8 contain the value part (starting with octet 2) of the
			 * Tracking Area Identity IE defined in 3GPP TS 24.301 [37], not including 3GPP TS 24.301 IEI
			 */
			curr_offset = curr_offset+ de_emm_trac_area_id(tvb, tree, pinfo, curr_offset, 5, add_string, string_len);
			/* Octets 9-n contain the Global eNB ID (see 3GPP TS 36.413 [36]) of the eNodeB. */
			new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
			dissect_s1ap_Global_ENB_ID_PDU(new_tvb, gpinfo, tree);
			break;
		default:
			proto_tree_add_text(tree, tvb, curr_offset, 3, "Unknown RIM Routing Address discriminator");
			return len;
	}


	return len;
}

/*
 * 11.3.71	MBMS Session Identity
 */
/* MBMS-Session-Identity AVP encoded as in 3GPP TS 29.061 [31],
 * excluding AVP Header fields as defined in IETF RFC 3588 [33].
 * TS 29.061
 * 17.7.11 MBMS-Session-Identity AVP
 * The MBMS-Session-Identity AVP (AVP code 908) is of type OctetString. Its length is one octet. It is allocated by the
 * BM-SC. Together with TMGI it identifies a transmission of a specific MBMS session. The initial transmission and
 * subsequent retransmissions of the MBMS session will use the same values of these parameters. This AVP is optional
 * within the Gmb interface.
 */
static guint16
de_bssgp_mbms_session_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* MBMS Session Identity */
	proto_tree_add_item(tree, hf_bssgp_mbms_session_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.72	MBMS Session Duration
 */
static guint16
de_bssgp_mbms_session_dur(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	/* AVP Code: 904 MBMS-Session-Duration Registered by packet-gtp.c */
	new_tvb =tvb_new_subset(tvb, offset, len, len);
	dissector_try_uint(diameter_3gpp_avp_dissector_table, 904, new_tvb, gpinfo, tree);

	return(curr_offset-offset);
}
/*
 * 11.3.73	MBMS Service Area Identity List
 * octet 3 - 514
 * MBMS-Service-Area AVP encoded as in 3GPP TS 29.061,
 * excluding AVP Header fields (as defined in IETF RFC 3588 [33]).
 *
 */
static guint16
de_bssgp_mbms_sai_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	/* AVP Code: 903 MBMS-Service-Area Registered by packet-gtp.c */
	new_tvb =tvb_new_subset(tvb, offset, len, len);
	dissector_try_uint(diameter_3gpp_avp_dissector_table, 903, new_tvb, gpinfo, tree);

	return(curr_offset-offset);
}
/*
 * 11.3.74	MBMS Response
 */

static const value_string bssgp_mbms_cause_vals[] = {
  { 0, "Acknowledge" },
  { 1, "Acknowledge, initiate data transfer" },
  { 2, "Acknowledge, data transfer initiated from other SGSN" },
  { 3, "Reject - Congestion" },
  { 4, "Reject - None of the listed MBMS Service Areas are supported by BSS" },
  { 5, "Reject - MBMS Service Context is released due to interrupted data flow" },

  { 6, "Unspecified in this version of the protocol" },
  { 7, "Unspecified in this version of the protocol" },
  { 8, "Unspecified in this version of the protocol" },
  { 9, "Unspecified in this version of the protocol" },
  { 10, "Unspecified in this version of the protocol" },
  { 11, "Unspecified in this version of the protocol" },
  { 12, "Unspecified in this version of the protocol" },
  { 13, "Unspecified in this version of the protocol" },
  { 14, "Unspecified in this version of the protocol" },
  { 15, "Unspecified in this version of the protocol" },
  { 0, NULL },
};
static value_string_ext bssgp_mbms_cause_vals_ext = VALUE_STRING_EXT_INIT(bssgp_mbms_cause_vals);

static guint16
de_bssgp_mbms_response(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* MBMS Session Identity */
	proto_tree_add_item(tree, hf_bssgp_mbms_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.75	MBMS Routing Area List
 */
/* Number of Routing Areas (octet 3) */
static const value_string bssgp_mbms_num_ra_ids_vals[] = {
  { 0, "Notification shall not be sent to any Routing Areas in the BSS" },
  { 1, "'1' Routing Area Identities" },
  { 2, "'1' Routing Area Identities" },
  { 3, "'1' Routing Area Identities" },
  { 4, "'1' Routing Area Identities" },
  { 5, "'1' Routing Area Identities" },
  { 6, "'1' Routing Area Identities" },
  { 7, "'1' Routing Area Identities" },
  { 8, "'1' Routing Area Identities" },
  { 9, "'1' Routing Area Identities" },
  { 10, "'1' Routing Area Identities" },
  { 11, "'1' Routing Area Identities" },
  { 12, "'1' Routing Area Identities" },
  { 13, "'1' Routing Area Identities" },
  { 14, "'1' Routing Area Identities" },
  { 15, "Notification shall be sent in all Routing Areas in the BSS" },
  { 0, NULL },
};
static value_string_ext bssgp_mbms_num_ra_ids_vals_ext = VALUE_STRING_EXT_INIT(bssgp_mbms_num_ra_ids_vals);

static guint16
de_bssgp_mbms_ra_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_item *ti;
	proto_tree *rai_tree;
	guint32	curr_offset;
	guint8 num_ra_ids;
	int i;

	curr_offset = offset;

	/* octet 3 Number of Routing Area Identifications Spare Spare Spare Spare */
	num_ra_ids = tvb_get_guint8(tvb,curr_offset) >> 4;
	proto_tree_add_item(tree, hf_bssgp_mbms_num_ra_ids, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* octet 4 - 11 Routing Area Identification 1 (etc)*/
	for (i = 0; i < num_ra_ids; i++) {
		ti = proto_tree_add_text(tree, tvb, curr_offset, 8, "Routing Area Identification (%u)", i + 1);
		rai_tree = proto_item_add_subtree(ti, ett_bssgp_ra_id);

		/* The element is coded as the Routing Area Identification information element in
		 * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and 3GPP TS 24.008 length indicator.
		 */
		de_gmm_rai(tvb, rai_tree, pinfo, curr_offset , 6, NULL, 0);

		curr_offset+=8;
	}

	return(curr_offset-offset);
}

/*
 * 11.3.76	MBMS Session Information
 */

static const true_false_string  tfs_bssgp_bc_mc = {
    "Multicast Session",
    "Broadcast Session"
};
static guint16
de_bssgp_mbms_session_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* MBMS Session Identity */
	proto_tree_add_item(tree, hf_bssgp_session_inf, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.77	TMGI (Temporary Mobile Group Identity)
 */
/* Rest of element coded as in 3GPP TS 24.008, not including 3GPP
 * TS 24.008 IEI and 3GPP TS 24.008 length indicator.
 */
/*
 * 11.3.78	MBMS Stop Cause
 */
static const value_string bssgp_mbms_stop_cause_vals[] = {
  { 0, "MBMS Session terminated by upstream node" },
  { 1, "MBMS Session terminated by SGSN" },

  { 2, "Unspecified in this version of the protocol" },
  { 3, "Unspecified in this version of the protocol" },
  { 4, "Unspecified in this version of the protocol" },
  { 5, "Unspecified in this version of the protocol" },
  { 6, "Unspecified in this version of the protocol" },
  { 7, "Unspecified in this version of the protocol" },
  { 8, "Unspecified in this version of the protocol" },
  { 9, "Unspecified in this version of the protocol" },
  { 10, "Unspecified in this version of the protocol" },
  { 11, "Unspecified in this version of the protocol" },
  { 12, "Unspecified in this version of the protocol" },
  { 13, "Unspecified in this version of the protocol" },
  { 14, "Unspecified in this version of the protocol" },
  { 15, "Unspecified in this version of the protocol" },
  { 0, NULL },
};
static value_string_ext bssgp_mbms_stop_cause_vals_ext = VALUE_STRING_EXT_INIT(bssgp_mbms_stop_cause_vals);

static guint16
de_bssgp_mbms_stop_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* MBMS Session Identity */
	proto_tree_add_item(tree, hf_bssgp_mbms_stop_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.79	Source BSS to Target BSS Transparent Container
 */
/* The actual function moved to after defining the enums */

/*
 * 11.3.80	Target BSS to Source BSS Transparent Container
 */
/*
 * 11.3.81	NAS container for PS Handover
 */
/*
 * 11.3.82	PFCs to be set-up list
 */
static guint16
de_bssgp_pfcs_to_be_set_up_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree *pfc_tree, *pft_tree, *abqp_tree, *arp_tree, *t10_tree;
	proto_item *pi, *ti2;

	guint32	curr_offset;
	guint8 num_pfc, i, pfc_len;

	curr_offset = offset;

	num_pfc = tvb_get_guint8(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of PFCs: ");

	if (num_pfc < 12) {
		proto_item_append_text(pi, "%u", num_pfc);
	}else {
		proto_item_append_text(pi, "Reserved");
		return (len);
	}
	curr_offset++;
	if (num_pfc == 0)
		return (curr_offset-offset);

	pfc_len = (len - 1) / num_pfc;

	for (i = 0; i < num_pfc; i++) {
		ti2 = proto_tree_add_text(tree, tvb, curr_offset, pfc_len,
					  "PFC (%u)", i + 1);
		pfc_tree = proto_item_add_subtree(ti2, ett_bssgp_pfcs_to_be_set_up_list);

		de_sm_pflow_id(tvb, pfc_tree, pinfo, curr_offset, 1, NULL, 0);
		curr_offset++;

		/* PFT: Packet Flow Timer. Coded as the GPRS Timer information element,
		 * see sub-clause 11.3.44.
		 */
		proto_tree_add_text(pfc_tree, tvb, curr_offset, 3, "Packet Flow Timer(PFT)");
		pft_tree = proto_item_add_subtree(ti2, ett_bssgp_pfcs_to_be_set_up_list_pft);
		proto_tree_add_item(pft_tree, hf_bssgp_unit_val, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(pft_tree, hf_bssgp_gprs_timer, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
		curr_offset += 3;

		/* ABQP: Aggregate BSS QoS Profile.
		 * Coded as the Aggregate BSS QoS Profile information element, see sub-clause 11.3.43.
		 */
		proto_tree_add_text(pfc_tree, tvb, curr_offset, 3, "Aggregate BSS QoS Profile(ABQP)");
		abqp_tree = proto_item_add_subtree(ti2, ett_bssgp_pfcs_to_be_set_up_list_abqp);
		/* Unsure about length 16 */
		curr_offset = curr_offset + de_sm_qos(tvb, abqp_tree, pinfo, curr_offset, 16, NULL, 0);

		/* Allocation/Retention Priority: Allocation Retention Priority.
		 * Coded as the Priority information element, see subclause 11.3.27.
		 * This information element is optionally included.
		 */
		if(pfc_len>17){
			proto_tree_add_text(pfc_tree, tvb, curr_offset, 3, "Allocation/Retention Priority");
			arp_tree = proto_item_add_subtree(ti2, ett_bssgp_pfcs_to_be_set_up_list_arp);
			curr_offset = curr_offset + be_prio(tvb, arp_tree, pinfo, curr_offset, 1, NULL, 0);
		}
		/* T10: T10.
		 * Coded as the GPRS Timer information element, see sub-clause 11.3.44.
		 * This information element shall be present for a PFC if the Allocation/Retention Priority
		 * is present and if queuing is allowed for the PFC.
		 */
		if(pfc_len>18){
			proto_tree_add_text(pfc_tree, tvb, curr_offset, 3, "T10");
			t10_tree = proto_item_add_subtree(ti2, ett_bssgp_pfcs_to_be_set_up_list_t10);
			proto_tree_add_item(t10_tree, hf_bssgp_unit_val, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(t10_tree, hf_bssgp_gprs_timer, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
			curr_offset += 3;
		}
	}
	return(curr_offset-offset);
}
/*
 * 11.3.83	List of set-up PFCs
 */
static guint16
de_bssgp_list_of_setup_pfcs(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree *pfc_tree;
	proto_item *pi, *ti2;

	guint32	curr_offset;
	guint8 num_pfc, i;

	curr_offset = offset;

	num_pfc = tvb_get_guint8(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of PFCs: ");

	if (num_pfc < 12) {
		proto_item_append_text(pi, "%u", num_pfc);
	}else {
		proto_item_append_text(pi, "Reserved");
		return (curr_offset-offset);
	}
	curr_offset++;
	if (num_pfc == 0)
		return (curr_offset-offset);

	for (i = 0; i < num_pfc; i++) {
		ti2 = proto_tree_add_text(tree, tvb, curr_offset, 1,
					  "PFC (%u)", i + 1);
		pfc_tree = proto_item_add_subtree(ti2, ett_bssgp_list_of_setup_pfcs);

		de_sm_pflow_id(tvb, pfc_tree, pinfo, curr_offset, 1, NULL, 0);
		curr_offset++;

	}

	return(curr_offset-offset);
}
/*
 * 11.3.84	Extended Feature Bitmap
 */
static guint16
de_bssgp_ext_feature_bitmap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Gigabit Interface */
	proto_tree_add_item(tree, hf_bssgp_gb_if, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* PS Handover */
	proto_tree_add_item(tree, hf_bssgp_ps_ho, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.85	Source to Target Transparent Container
 */
static guint16
de_bssgp_src_to_trg_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Octets 3-? Source to Target Transparent Container content coded as
	 * specified in 3GPP TS 25.413 or 3GPP TS 36.413.
	 * In inter-RAT handovers ... RANAP specification 3GPP TS 25.413, excluding RANAP tag.
	 * In inter-RAT handover to E-UTRAN ... encoding is defined in 3GPP TS 36.413
	 */
	proto_tree_add_item(tree, hf_bssgp_src_to_trg_transp_cont, tvb, curr_offset, len, ENC_BIG_ENDIAN);

	return(len);
}

/*
 * 11.3.86	Target to Source Transparent Container
 */
static guint16
de_bssgp_trg_to_src_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Rest of element coded as either a complete Handover to UTRAN
	 * Command radio interface message (as defined in 3GPP TS
	 * 25.331) or a complete Radio Bearer Reconfiguration radio
	 * interface message (as defined in 3GPP TS 44.118) or a complete
	 * DL-DCCH-Message including a complete
	 * RRCConnectionReconfiguration radio interface message (as
	 * defined in 3GPP TS 36.331)
	 */
	proto_tree_add_item(tree, hf_bssgp_trg_to_src_transp_cont, tvb, curr_offset, len, ENC_BIG_ENDIAN);

	return(len);
}

/*
 * 11.3.87	RNC Identifier
 */
static guint16
de_bssgp_rnc_identifier(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint16 rnc_id;

	curr_offset = offset;
	/* Octets 3-8 Octets 3 to 8 contain the value part (starting with octet 2) of the
	 * Routing Area Identification IE defined in 3GPP TS 24.008, not including 3GPP TS 24.008 IEI
	 */
	curr_offset = curr_offset + de_gmm_rai(tvb, tree, pinfo, curr_offset, 6, add_string, string_len);
	/* Octet 9 - 10 RNC ID (or Extended RNC-ID or Corresponding RNC-ID) */
	rnc_id = tvb_get_ntohs(tvb, curr_offset);
	proto_tree_add_item(tree, hf_bssgp_rnc_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	if (add_string)
		g_snprintf(add_string, string_len, " %s, RNC-ID %u", add_string, rnc_id);

	return(curr_offset-offset);

}
/*
 * 11.3.88	Page Mode
 */
/* PAGE_MODE (2 bit field) */

static const value_string bssgp_page_mode_vals[] = {
    { 0, "Normal Paging" },
    { 1, "Extended Paging" },
    { 2, "Paging Reorganization" },
	{ 3, "Same as before" },
	{ 0,    NULL },
  };
static guint16
de_bssgp_page_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_page_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.89	Container ID
 */
static guint16
de_bssgp_container_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_container_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.90	Global TFI
 */
static const value_string bssgp_global_tfi_vals[] = {
    { 0, "UPLINK_TFI" },
    { 1, "DOWNLINK_TFI" },
	{ 0,    NULL },
  };

static guint16
de_bssgp_global_tfi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32 bit_offset;
	guint8  gtfi;

	curr_offset = offset;

	/* Bits 6 - 1 Global TFI coded as specified in 3GPP TS 44.060 */
	bit_offset = (curr_offset << 3) +3;
	gtfi = tvb_get_bits8(tvb,bit_offset,1);
	proto_tree_add_bits_item(tree, hf_bssgp_global_tfi, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	/* < Global TFI IE > ::=
	 *    { 0 < UPLINK_TFI : bit (5) >
	 *    | 1 < DOWNLINK_TFI : bit (5) > } ;
	 */
	if(gtfi == 0){
		/* UPLINK_TFI (5 bit field)
		 * This field identifies an uplink TBF. This field is coded the same as the
		 * TFI field defined in sub-clause 12.15.
		 * This field is encoded as a binary number. Range 0 to 31
		 */
		proto_tree_add_bits_item(tree, hf_bssgp_ul_tfi, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	}else{
		/* DOWNLINK_TFI (5 bit field)
		 * This field identifies an uplink TBF. This field is coded the same as the
		 * TFI field defined in sub-clause 12.15.
		 * This field is encoded as a binary number. Range 0 to 31
		 */
		proto_tree_add_bits_item(tree, hf_bssgp_dl_tfi, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	}
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.91	IMEI
 */
/* Octets 3-10 contain the IMEI coded as the value part of the Mobile
 * Identity IE defined in 3GPP TS 24.008
 * (NOTE 1)
 */
/*
 * 11.3.92	Time to MBMS Data Transfer
 */
static guint16
de_bssgp_time_to_MBMS_data_tran(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 value;

	curr_offset = offset;

	/* 0 = 1s etc */
	value = tvb_get_guint8(tvb,curr_offset) + 1;
	proto_tree_add_uint(tree, hf_bssgp_time_to_MBMS_data_tran, tvb, curr_offset, 1, value);

	return(len);
}
/*
 * 11.3.93	MBMS Session Repetition Number
 */
static guint16
de_bssgp_mbms_session_rep_no(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_mbms_session_rep_no, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(len);
}
/*
 * 11.3.94	Inter RAT Handover Info
 */
static guint16
de_bssgp_inter_rat_ho_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t	*new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
	/*
	 * Inter RAT Handover Information coded as specified in 3GPP
	 * Technical Specification 25.331
	 */
	dissect_rrc_InterRATHandoverInfo_PDU(new_tvb, gpinfo, tree);

	return(len);
}
/*
 * 11.3.95	PS Handover Command
 */
static guint16
de_bssgp_ps_ho_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Octet 3-? Rest of element coded as a complete PS Handover Command
	* radio interface message as defined in 3GPP TS 44.060 (carrying
	* the PS Handover to A/Gb Mode Payload)
	*/
	proto_tree_add_item(tree, hf_bssgp_ps_ho_cmd, tvb, curr_offset, len, ENC_BIG_ENDIAN);


	return(len);
}

/*
 * 11.3.95a	PS Handover Indications
 */
static guint16
de_bssgp_ps_ho_indications(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* SI/PSI */
	proto_tree_add_item(tree, hf_bssgp_sipsi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.95b	SI/PSI Container
 */

 static const value_string type_vals[] = {
    { 0, "SI messages as specified for BCCH (3GPP TS 44.018) follow" },
    { 1, "PSI messages as specified for PBCCH (3GPP TS 44.060) follow" },
	{ 0,    NULL },
  };
static guint16
de_bssgp_sipsi_container(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct,num, type, i;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	num = oct >>1;
	type = oct & 1;
	proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of SI/PSI: %u",num);

	/* Type */
	proto_tree_add_item(tree, hf_bssgp_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;
	if (type==0){
		/* BCCH (3GPP TS 44.018) */
		for (i = 0; i < num; i++) {
			proto_tree_add_text(tree, tvb, curr_offset, 21, "SI (%u)", i + 1);
			curr_offset+=21;
		}
	}else{
		/* PBCCH (3GPP TS 44.060) */
		for (i = 0; i < num; i++) {
			proto_tree_add_text(tree, tvb, curr_offset, 22, "PSI (%u)", i + 1);
			curr_offset+=22;
		}
	}

	return(curr_offset-offset);
}
/*
 * 11.3.95c	Active PFCs List
 */
static guint16
de_bssgp_active_pfcs_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree *pfc_tree;
	proto_item *pi, *ti2;

	guint32	curr_offset;
	guint8 num_pfc, i;

	curr_offset = offset;

	num_pfc = tvb_get_guint8(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of PFCs: ");

	if (num_pfc < 12) {
		proto_item_append_text(pi, "%u", num_pfc);
	}else {
		proto_item_append_text(pi, "Reserved");
		return (curr_offset-offset);
	}
	curr_offset++;
	if (num_pfc == 0)
		return (curr_offset-offset);

	for (i = 0; i < num_pfc; i++) {
		ti2 = proto_tree_add_text(tree, tvb, curr_offset, 1, "PFC (%u)", i + 1);
		pfc_tree = proto_item_add_subtree(ti2, ett_bssgp_pfc_flow_control_parameters_pfc);

		de_sm_pflow_id(tvb, pfc_tree, pinfo, curr_offset, 1, NULL, 0);
		curr_offset++;

	}

	return(curr_offset-offset);
}
/*
 * 11.3.96	Velocity Data
 */
static guint16
de_bssgp_velocity_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* The rest of the information element contains an octet sequence
	 * identical to that for Description of Velocity defined in 3GPP TS
	 * 23.032.
	 */
	curr_offset = dissect_description_of_velocity(tvb, tree, pinfo, curr_offset, len, add_string, string_len);

	return(curr_offset-offset);
}
/*
 * 11.3.97	DTM Handover Command
 */
static guint16
de_bssgp_dtm_ho_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Rest of element coded as a complete DTM Handover Command
	 * radio interface message as defined in 3GPP TS 44.060 (carrying
	 * the DTM Handover to A/Gb Mode Payload)
	 */
	proto_tree_add_text(tree, tvb, curr_offset, len, "DTM Handover Command data");

	return(len);
}
/*
 * 11.3.98	CS Indication
 */
static guint16
de_bssgp_cs_indication(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* CS Indication Contents
	 * CS Indication Contents: This identifies a particular handover attempt for this MS. This shall be identical to the PS
	 * Indication Contents value in the corresponding PS Indication IE included in the Old BSS to New BSS Information IE
	 * (see 3GPP TS 48.008). The choice of the value of this field is implementation specific, with the requirement that
	 * consecutive handover attempts for the same mobile station shall not have the same CS Indication Contents value.
	 */
	proto_tree_add_item(tree, hf_bssgp_cs_indication, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.99	Requested GANSS Assistance Data
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.100 	GANSS Location Type
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.101 	GANSS Positioning Data
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 49.031, not including 3GPP TS 49.031 IEI and
 * 3GPP TS 49.031 octet length indicator
 */
/*
 * 11.3.102 	Flow Control Granularity
 */
static const value_string bssgp_flow_control_gran_vals[] = {
    { 0, "100 octets or bits/s increments" },
    { 1, "1000 octets or bits/s increments" },
    { 2, "10000 octets or bits/s increments" },
	{ 3, "100000 octets or bits/s increments" },
	{ 0,    NULL },
  };


static guint16
de_bssgp_flow_control_gran(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Granularity */
	proto_tree_add_item(tree, hf_bssgp_flow_control_gran, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.103 	eNB Identifier
 */
static guint16
de_bssgp_enb_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
	tvbuff_t	*new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	/* Octets 3 to 7 contain the value part (starting with octet 2) of the
	 * Tracking Area Identity IE defined in 3GPP TS 24.301 [37], not
	 * including 3GPP TS 24.301 IEI [37]
	*/
	curr_offset = curr_offset+ de_emm_trac_area_id(tvb, tree, pinfo, curr_offset, 5, add_string, string_len);

	/* Octets 8-n contain the Global eNB ID (see 3GPP TS 36.413) of the eNodeB. */
	new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
	dissect_s1ap_Global_ENB_ID_PDU(new_tvb, gpinfo, tree);

	return(len);
}
/*
 * 11.3.104 	E-UTRAN Inter RAT Handover Info
 */
static guint16
de_bssgp_e_utran_inter_rat_ho_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t	*new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
	/*
	 * Formatted and coded according to the UE-EUTRA-Capability IE
	 * defined in 3GPP Technical Specification 36.331. The most
	 * significant bit of the first octet of the octet string contains bit 8 of
	 * the first octet of the IE.
	 */
	dissect_lte_rrc_UE_EUTRA_Capability_PDU(new_tvb, gpinfo, tree);

	return(len);
}
/*
 * 11.3.105 	Subscriber Profile ID for RAT/Frequency priority
 */

static guint16
de_bssgp_sub_prof_id_f_rat_freq_prio(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 value;

	curr_offset = offset;

	/* Octet 3 contains a number in binary representation ranging from 0 to 255.
	 * The Subscriber Profile ID for RAT/Frequency priority is given by
	 * the indicated value +1.
	 */
	value = tvb_get_guint8(tvb,curr_offset) + 1;
	proto_tree_add_uint(tree, hf_bssgp_sub_prof_id_f_rat_freq_prio, tvb, curr_offset, 1, value);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.106 	Request for Inter-RAT Handover Info
 */
static guint16
de_bssgp_req_for_inter_rat_ho_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/*octet 3 Spare E-UTRAN Inter RAT Handover Info Req Inter RAT Handover Info Req */
	proto_tree_add_item(tree, hf_bssgp_eutran_irat_ho_inf_req, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_irat_ho_inf_req, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.107 	Reliable Inter-RAT Handover Info
 */
static guint16
de_bssgp_reliable_inter_rat_ho_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Reliable Inter RAT Handover Info Indicator */
	proto_tree_add_item(tree, hf_bssgp_rel_int_rat_ho_inf_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.108 	SON Transfer Application Identity
 */
static guint16
de_bssgp_son_transfer_app_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset _U_, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	/* SON Transfer Application Identity: This field is encoded as the SON Transfer Application Identity IE
	 * as defined in 3GPP TS 36.413
	 */
	dissect_s1ap_SONtransferApplicationIdentity_PDU(tvb, gpinfo, tree);

	return(len);
}
/*
 * 11.3.109 	CSG Identifier
 */

/* Cell Access Mode (bit 1 of octet 7) */
static const value_string bssgp_cell_access_mode_vals[] = {
    { 0, "CSG cell" },
    { 1, "Hybrid cell" },
	{ 0,    NULL },
};

static guint16
de_bssgp_csg_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Octets 3 to 6 contain the CSG Identity (CSG-ID) of the cell (defined in
	 * 3GPP TS 23.003) as reported by the mobile station (see 3GPP TS
	 * 44.060). Bits 4 to 8 of octet 6 are spare and set to zero.
	 */
	proto_tree_add_item(tree, hf_bssgp_csg_id, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
	curr_offset+=4;
	/* Cell Access Mode */
	proto_tree_add_item(tree, hf_bssgp_cell_acc_mode, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.110 	Tracking Area Code
 */
/*
 * Octets 3 to 5 contain the value part (starting with octet 2) of the TAC
 * IE defined in 3GPP TS 24.301.
 */
/*
 * 11.3.111 	Redirect Attempt Flag
 * 11.3.112 	Redirection Indication
 * 11.3.113 	Redirection Completed
*/


const value_string bssgp_elem_strings[] = {
    { 0x00, "Alignment Octets" },                                 	/* 11.3.1	Alignment octets */
	{ 0x01, "Bmax default MS" },                                 	/* 11.3.2	Bmax default MS  */
	{ 0x02, "BSS Area Indication" },								/* 11.3.3	BSS Area Indication	 */
	{ 0x03, "Bucket Leak Rate (R)" },								/* 11.3.4	Bucket Leak Rate (R) */
	{ 0x04, "BVCI (BSSGP Virtual Connection Identifier)" },			/* 11.3.6	BVCI (BSSGP Virtual Connection Identifier)  */
	{ 0x05,	"BVC Bucket size" },									/* 11.3.5	BVC Bucket Size */
	{ 0x06, "BVC Measurement" },									/* 11.3.7	BVC Measurement */
	{ 0x07, "Cause" },												/* 11.3.8	Cause */
	{ 0x08, "Cell Identifier" },									/* 11.3.9	Cell Identifier */
	{ 0x09, "Channel needed" },										/* 11.3.10	Channel needed */
	{ 0x0a, "DRX Parameters" },										/* 11.3.11	DRX Parameters */
	{ 0x0b, "eMLPP-Priority" },										/* 11.3.12	eMLPP-Priority */
	{ 0x0c, "Flush Action" },										/* 11.3.13	Flush Action */
	{ 0x0d, "IMSI" },												/* 11.3.14	IMSI */
	{ 0x0e, "LLC-PDU" },											/* 11.3.15	LLC-PDU */
 	{ 0x0f, "LLC Frames Discarded" },								/* 11.3.16	LLC Frames Discarded  */
	{ 0x10, "Location Area" },										/* 11.3.17	Location Area  */
	{ 0x11, "Mobile Id" },											/* 11.3.20	Mobile Id */
	{ 0x12, "MS Bucket Size" },										/* 11.3.21	MS Bucket Size */
 	{ 0x13, "MS Radio Access Capability" },						    /* 11.3.22	MS Radio Access Capability GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP */
	{ 0x14, "OMC Id" },												/* 11.3.23	OMC Id */
	{ 0x15, "PDU In Error" },										/* 11.3.24	PDU In Error */
	{ 0x16, "PDU Lifetime" },										/* 11.3.25	PDU Lifetime */
	{ 0x17, "Priority" },											/* 11.3.27	Priority */
    { 0x18, "QoS Profile" },										/* 11.3.28	QoS Profile */
    { 0x19, "Radio Cause" },										/* 11.3.29	Radio Cause */
	{ 0x1a, "RA-Cap-UPD-Cause" },									/* 11.3.30	RA-Cap-UPD-Cause */
	{ 0x1b, "Routeing Area" },										/* 11.3.31	Routeing Area */
 	{ 0x1c, "R_default_MS" },										/* 11.3.32	R_default_MS */
	{ 0x1d, "Suspend Reference Number" },							/* 11.3.33	Suspend Reference Number */
    { 0x1e, "Tag" },												/* 11.3.34	Tag */
 	{ 0x1f, "Temporary logical link Identity (TLLI)" },				/* 11.3.35	Temporary logical link Identity (TLLI) GSM_A_PDU_TYPE_RR, DE_RR_TLLI*/
	{ 0x20, "Temporary Mobile Subscriber Identity (TMSI)" },		/* 11.3.36	Temporary Mobile Subscriber Identity (TMSI)GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI */
    { 0x21, "Trace Reference" },									/* 11.3.37	Trace Reference */
    { 0x22, "Trace Type" },											/* 11.3.38	Trace Type */
    { 0x23, "Transaction Id" },										/* 11.3.39	Transaction Id */
    { 0x24, "Trigger Id" },											/* 11.3.40	Trigger Id */
    { 0x25, "Number of octets affected" },							/* 11.3.41	Number of octets affected */
	{ 0x26, "LSA Identifier List" },								/* 11.3.18	LSA Identifier List */
	{ 0x27, "LSA Information" },									/* 11.3.19	LSA Information */
	{ 0x28, "Packet Flow Identifier (PFI)" },						/* 11.3.42	Packet Flow Identifier (PFI) GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID*/
																	/* 11.3.42a	(void) */
	{ 0x29, "GPRS Timer" },											/* 11.3.44	GPRS Timer */
	{ 0x3a, "Aggregate BSS QoS Profile" },							/* 11.3.43	Aggregate BSS QoS Profile GSM_A_PDU_TYPE_GM, DE_QOS*/
	{ 0x3b, "Feature Bitmap" },										/* 11.3.45	Feature Bitmap */
	{ 0x3c, "Bucket Full Ratio" },									/* 11.3.46	Bucket Full Ratio */
	{ 0x3d, "Service UTRAN CCO" },									/* 11.3.47	Service UTRAN CCO */
	{ 0x3e, "NSEI (Network Service Entity Identifier)" },			/* 11.3.48	NSEI (Network Service Entity Identifier) */
	{ 0x00, "RRLP APDU" },											/* 11.3.49 RRLP APDU */
																	/* 11.3.50	LCS QoS BSSGP_IEI_LCS_QOS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCSQOS*/
																	/* 11.3.51	LCS Client Type BSSGP_IEI_LCS_CLIENT_TYPE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CLIENT_TYPE*/
																	/* 11.3.52	Requested GPS Assistance Data BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_REQ_GPS_ASSIST_D*/
																	/* 11.3.53	Location Type 0x7c, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_LOC_TYPE*/
																	/* 11.3.54	Location Estimate BSSGP_IEI_LOCATION_ESTIMATE, GSM_A_PDU_TYPE_BSSMAP, BE_LOC_EST*/
																	/* 11.3.55	Positioning Data 0x7d, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_POS_DATA*/
																	/* 11.3.56	Deciphering Keys BSSGP_IEI_DECIPHERING_KEYS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_DECIPH_KEYS */
																	/* 11.3.57	LCS Priority BSSGP_IEI_LCS_PRIORITY, GSM_A_PDU_TYPE_BSSMAP, BE_LCS_PRIO;*/
																	/* 11.3.58	LCS Cause BSSGP_IEI_LCS_CAUSE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAUSE */
																	/* 11.3.59	LCS Capability 0x49 , GSM_A_PDU_TYPE_GM, DE_PS_LCS_CAP*/
	{ 0x00, "RRLP Flags" },											/* 11.3.60	RRLP Flags */
	{ 0x00, "RIM Application Identity" },							/* 11.3.61	RIM Application Identity */
	{ 0x00, "RIM Sequence Number" },								/* 11.3.62	RIM Sequence Number */
 /* 11.3.62a	RIM Container */
 /* 11.3.62a.0	General */
	{ 0x00, "RAN-INFORMATION-REQUEST RIM Container" },				/* 11.3.62a.1	RAN-INFORMATION-REQUEST RIM Container */
	{ 0x00, "RAN-INFORMATION RIM Container" },						/* 11.3.62a.2	RAN-INFORMATION RIM Container */
	{ 0x00, "RAN-INFORMATION-ACK RIM Container" },					/* 11.3.62a.3	RAN-INFORMATION-ACK RIM Container */
	{ 0x00, "RAN-INFORMATION-ERROR RIM Container" },				/* 11.3.62a.4	RAN-INFORMATION-ERROR RIM Container */
	{ 0x00, "RAN-INFORMATION-APPLICATION-ERROR RIM Container" },	/* 11.3.62a.5	RAN-INFORMATION-APPLICATION-ERROR RIM Container */
 /* 11.3.63	Application Container */
	{ 0x00, "RAN-INFORMATION-REQUEST Application Container" },		/* 11.3.63.1	RAN-INFORMATION-REQUEST Application Container */
 /* 11.3.63.1.0	General */
 /* 11.3.63.1.1	RAN-INFORMATION-REQUEST Application Container for the NACC Application */
 /* 11.3.63.1.2	RAN-INFORMATION-REQUEST Application Container for the SI3 Application */
 /* 11.3.63.1.3	RAN-INFORMATION-REQUEST Application Container for the MBMS data channel Application */
 /* 11.3.63.1.4	RAN-INFORMATION-REQUEST Application Container for the SON Transfer Application */
	{ 0x00, "RAN-INFORMATION Application Container Unit" },			/* 11.3.63.2	RAN-INFORMATION Application Container Unit */
 /* 11.3.63.2.0	General */
 /* 11.3.63.2.1	RAN-INFORMATION Application Container for the NACC Application */
 /* 11.3.63.2.2	RAN-INFORMATION Application Container for the SI3 Application */
 /* 11.3.63.2.3	RAN-INFORMATION Application Container for the MBMS data channel Application */
 /* 11.3.63.2.4	RAN-INFORMATION Application Container for the SON Transfer Application */
	{ 0x00, "Application Error Container" },						/* 11.3.64	Application Error Container */
 /* 11.3.64.1	Application Error Container layout for the NACC application */
 /* 11.3.64.2	Application Error Container for the SI3 application */
 /* 11.3.64.3	Application Error Container for the MBMS data channel application */
 /* 11.3.64.4	Application Error Container for the SON Transfer Application */
	{ 0x00, "RIM PDU Indications" },								/* 11.3.65	RIM PDU Indications */
 /* 11.3.65.0	General */
 /* 11.3.65.1	RAN-INFORMATION-REQUEST RIM PDU Indications */
 /* 11.3.65.2	RAN-INFORMATION RIM PDU Indications */
 /* 11.3.65.3	RAN-INFORMATION-APPLICATION-ERROR RIM PDU Indications */
 /* 11.3.66	(void) */
	{ 0x00, "RIM Protocol Version Number" },							/* 11.3.67	RIM Protocol Version Number */
	{ 0x00, "PFC Flow Control parameters" },						/* 11.3.68	PFC Flow Control parameters */
 /* 0x53, SGSAP_PDU_TYPE, DE_SGSAP_GLOBAL_CN_ID */					/* 11.3.69	Global CN-Id */
	{ 0x00, "RIM Routing Information" },							/* 11.3.70	RIM Routing Information */
	{ 0x00, "MBMS Session Identity" },								/* 11.3.71 MBMS Session Identity */
	{ 0x00, "MBMS Session Duration" },								/* 11.3.72	MBMS Session Duration */
	{ 0x00, "MBMS Service Area Identity List" },					/* 11.3.73	MBMS Service Area Identity List */
	{ 0x00, "MBMS Response" },										/* 11.3.74	MBMS Response */
	{ 0x00, "MBMS Routing Area List" },								/* 11.3.75	MBMS Routing Area List */
	{ 0x00, "MBMS Session Information" },							/* 11.3.76	MBMS Session Information */
 /* ELEM_MAND_TELV(GSM_A_PDU_TYPE_GM, DE_TMGI,  */					/* 11.3.77	TMGI (Temporary Mobile Group Identity) */
	{ 0x00, "MBMS Stop Cause" },									/* 11.3.78	MBMS Stop Cause */
	{ 0x00, "Source BSS to Target BSS Transparent Container" },		/* 11.3.79	Source BSS to Target BSS Transparent Container */
	{ 0x00, "Target BSS to Source BSS Transparent Container" },		/* 11.3.80	Target BSS to Source BSS Transparent Container */
 /* 11.3.81	NAS container for PS Handover */
	{ 0x00, "PFCs to be set-up list" },								/* 11.3.82	PFCs to be set-up list */
	{ 0x00, "List of set-up PFCs" },								/* 11.3.83	List of set-up PFCs */
	{ 0x00, "Extended Feature Bitmap" },							/* 11.3.84	Extended Feature Bitmap */
	{ 0x00, "Source to Target Transparent Container" },				/* 11.3.85	Source to Target Transparent Container */
	{ 0x00, "Target to Source Transparent Container" },				/* 11.3.86	Target to Source Transparent Container */
	{ 0x00, "RNC Identifier" },										/* 11.3.87	RNC Identifier */
	{ 0x00, "Page Mode" },											/* 11.3.88	Page Mode */
 	{ 0x00, "Container ID" },										/* 11.3.89	Container ID */
 	{ 0x00, "Global TFI" },											/* 11.3.90	Global TFI */
 /* 11.3.91	IMEI */
 	{ 0x00, "Time to MBMS Data Transfer" },							/* 11.3.92	Time to MBMS Data Transfer */
 	{ 0x00, "MBMS Session Repetition Number" },						/* 11.3.93	MBMS Session Repetition Number */
	{ 0x00, "Inter RAT Handover Info" },							/* 11.3.94	Inter RAT Handover Info */
	{ 0x00, "PS Handover Command" },								/* 11.3.95	PS Handover Command */
 	{ 0x00, "PS Handover Indications" },							/* 11.3.95a	PS Handover Indications */
 	{ 0x00, "SI/PSI Container" },									/* 11.3.95b	SI/PSI Container */
 	{ 0x00, "Active PFCs List" },									/* 11.3.95c	Active PFCs List */
 	{ 0x00, "Velocity Data" },										/* 11.3.96	Velocity Data */
 	{ 0x00, "DTM Handover Command" },								/* 11.3.97	DTM Handover Command */
	{ 0x00, "PS Handover Indications" },							/* 11.3.98	CS Indication */
																	/* 11.3.99	Requested GANSS Assistance Data 0x7b, GSM_A_PDU_TYPE_BSSMAP, BE_GANSS_ASS_DTA*/
																	/* 11.3.100 	GANSS Location Type 0x7c, GSM_A_PDU_TYPE_BSSMAP, BE_GANSS_LOC_TYP*/
																	/* 11.3.101 	GANSS Positioning Data ENC_BIG_ENDIAN);*/
	{ 0x00, "Flow Control Granularity" },							/* 11.3.102 	Flow Control Granularity */
	{ 0x00, "eNB Identifier" },										/* 11.3.103 	eNB Identifier */
 	{ 0x00, "E-UTRAN Inter RAT Handover Info" },					/* 11.3.104 	E-UTRAN Inter RAT Handover Info */
	{ 0x00, "Subscriber Profile ID for RAT/Frequency priority" },	/* 11.3.105 Subscriber Profile ID for RAT/Frequency priority */
	{ 0x00, "Request for Inter-RAT Handover Info" },				/* 11.3.106 Request for Inter-RAT Handover Info */
	{ 0x00, "Reliable Inter-RAT Handover Info" },					/* 11.3.107 Reliable Inter-RAT Handover Info */
	{ 0x00, "Reliable Inter-RAT Handover Info" },					/* 11.3.108 SON Transfer Application Identity */
	{ 0x00, "CSG Identifier" },										/* 11.3.109 CSG Identifier */
/* 11.3.110 Tracking Area Code */

	{ 0, NULL }
};

#define	NUM_BSSGP_ELEM (sizeof(bssgp_elem_strings)/sizeof(value_string))
gint ett_bssgp_elem[NUM_BSSGP_ELEM];


typedef enum
{
	DE_BSSGP_ALIGNMENT_OCTETS,									/* 11.3.1	0x00 Alignment octets */
	DE_BSSGP_BMAX_DEFAULT_MS,									/* 11.3.2	0x01 Bmax default MS  */
	DE_BSSGP_BSS_AREA_IND,										/* 11.3.3	0x02 BSS Area Indication */
	DE_BSSGP_BUCKET_LEAK_RATE,									/* 11.3.4	0x03 Bucket Leak Rate (R) */
	DE_BSSGP_BVCI,												/* 11.3.6	0x04 BVCI (BSSGP Virtual Connection Identifier)  */
	DE_BSSGP_BVC_BUCKET_SIZE,									/* 11.3.5	0x05 BVC Bucket Size */
	DE_BSSGP_BVC_MEAS,											/* 11.3.7	0x06 BVC Measurement */
	DE_BSSGP_CAUSE,												/* 11.3.8	0x07 Cause */
	DE_BSSGP_CELL_ID,											/* 11.3.9	0x08 Cell Identifier */
	DE_BSSGP_CHLN_NEEDED,										/* 11.3.10	0x09 Channel needed */
	DE_BBSGP_DRX_PARAM,											/* 11.3.11	0x0a DRX Parameters GSM_A_PDU_TYPE_GM, DE_DRX_PARAM */
	DE_BBSGP_EMLPP_PRIO,										/* 11.3.12	0x0b eMLPP-Priority GSM_A_PDU_TYPE_BSSMAP, BE_EMLPP_PRIO*/
	DE_BSSGP_FLUSH_ACTION,										/* 11.3.13	0x0c Flush Action */
	DE_BSSGP_IMSI,												/* 11.3.14	0x0d IMSI */
	DE_BSSGP_LLC_PDU,											/* 11.3.15	0x0e LLC-PDU */
 	DE_BSSGP_LLC_FRAMES_DISC,									/* 11.3.16	0x0f LLC Frames Discarded  */
	DE_BSSGP_LAI	,											/* 11.3.17	0x10 Location Area  GSM_A_PDU_TYPE_COMMON, DE_LAI*/
	DE_BSSGP_MID,												/* 11.3.20	0x11 Mobile Id GSM_A_PDU_TYPE_COMMON, DE_MID*/
	DE_BSSGP_MS_BUCKET_SIZE,									/* 11.3.21	0x12 MS Bucket Size */
	DE_BSSGP_MS_RAD_ACC_CAP,									/* 11.3.22	0x13 MS Radio Access Capability GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP*/
	DE_BSSGP_OMC_ID,											/* 11.3.23	0x14 OMC Id */
	DE_BSSGP_PDU_IN_ERROR,										/* 11.3.24	0x15 PDU In Error */
	DE_BSSGP_PDU_LIFETIME,										/* 11.3.25	0x16 PDU Lifetime */
	DE_BSSP_PRIORITY,											/* 11.3.27  0x17	Priority */
	DE_BSSGP_QOS_PROFILE,										/* 11.3.28	0x18 QoS Profile */
	DE_BSSGP_RA_CAUSE,											/* 11.3.29	0x19 Radio Cause */
	DE_BSSGP_RA_CAP_UPD_CAUSE,									/* 11.3.30	0x1a RA-Cap-UPD-Cause */
	DE_BSSGP_RAI,												/* 11.3.31	0x1b Routeing Area GSM_A_PDU_TYPE_GM, DE_RAI*/
	DE_BSSGP_R_DEFAULT_MS,										/* 11.3.32	0x1c R_default_MS */
	DE_BBSGP_SUSPEND_REF_NO,									/* 11.3.33	0x1d Suspend Reference Number */
	DE_BSSGP_TAG,												/* 11.3.34	0x1e Tag */
	DE_BSSGP_TLLI,												/* 11.3.35	0x1f Temporary logical link Identity (TLLI) GSM_A_PDU_TYPE_RR, DE_RR_TLLI*/
	DE_BSSGP_TMSI_PTMSI,										/* 11.3.36	0x20 Temporary Mobile Subscriber Identity (TMSI) GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI*/
	DE_BSSGP_TRACE_REF,											/* 11.3.37	0x21 Trace Reference */
	DE_BSSGP_TRACE_TYPE,										/* 11.3.38	0x22 Trace Type */
	DE_BSSGP_TRANSACTION_ID,									/* 11.3.39	0x23 Transaction Id */
	DE_BSSGP_TRIGGER_ID,										/* 11.3.40	0x24 Trigger Id */
	DE_BSSGP_NO_OF_OCT_AFFECTED,								/* 11.3.41	0x25 Number of octets affected */
	DE_BSSGP_LSA_ID_LIST,										/* 11.3.18	0x26 LSA Identifier List GSM_A_PDU_TYPE_BSSMAP, BE_LSA_ID_LIST*/
	DE_BSSGP_LSA_INFO,											/* 11.3.19	0x27 LSA Information GSM_A_PDU_TYPE_BSSMAP, BE_LSA_INFO */
	DE_BSSGP_ACKET_FLOW_ID,										/* 11.3.42	0x28 Packet Flow Identifier (PFI)  GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID*/
	DE_BSSGP_GPRS_TIMER,										/* 11.3.44	0x29 GPRS Timer */
	DE_BSSGP_QOS,												/* 11.3.43	0x3a Aggregate BSS QoS Profile GSM_A_PDU_TYPE_GM, DE_QOS*/
	DE_BSSGP_FEATURE_BITMAP,									/* 11.3.45	0x3b Feature Bitmap */
	DE_BSSGP_BUCKET_FULL_RATIO,									/* 11.3.46	0x3c Bucket Full Ratio */
	DE_BSSGP_SERV_UTRAN_CCO,									/* 11.3.47	0x3d Service UTRAN CCO */
	DE_BSSGP_NSEI,												/* 11.3.48	0x3e NSEI (Network Service Entity Identifier) */
	DE_BSSGP_RRLP_APDU,											/* 11.3.49 RRLP APDU */
	DE_BSSGP_RRLP_FLAGS,										/* 11.3.60	RRLP Flags */
	DE_BSSGP_RIM_APP_ID,										/* 11.3.61	RIM Application Identity */
	DE_BSSGP_RIM_SEQ_NO,										/* 11.3.62	RIM Sequence Number */
	DE_BSSGP_RAN_INF_REQUEST_RIM_CONT,							/* 11.3.62a.1	RAN-INFORMATION-REQUEST RIM Container */
	DE_BSSGP_RAN_INF_RIM_CONT,									/* 11.3.62a.2	RAN-INFORMATION RIM Container */
	DE_BSSGP_RAN_INFORMATION_ACK_RIM_CONT,						/* 11.3.62a.3	RAN-INFORMATION-ACK RIM Container */
	DE_BSSGP_RAN_INFORMATION_ERROR_RIM_CONT,					/* 11.3.62a.4	RAN-INFORMATION-ERROR RIM Container */
	DE_BSSGP_RAN_INF_APP_ERROR_RIM_CONT,						/* 11.3.62a.5	RAN-INFORMATION-APPLICATION-ERROR RIM Container */
	DE_BSSGP_RAN_INFORMATION_REQUEST_APP_CONT,					/* 11.3.63.1	RAN-INFORMATION-REQUEST Application Container */
	DE_BSSGP_RAN_INFORMATION_APP_CONT_UNIT,						/* 11.3.63.2	RAN-INFORMATION Application Container Unit */
	DE_BSSGP_RAN_APP_ERROR_CONT,								/* 11.3.64	Application Error Container */
	DE_BSSGP_RIM_PDU_INDICATIONS,								/* 11.3.65	RIM PDU Indications */
	DE_BSSGP_RIM_PROTO_VER_NO,									/* 11.3.67	RIM Protocol Version Number */

	DE_BSSGP_PFC_FLOW_CTRL,										/* 11.3.68	PFC Flow Control parameters */
	DE_BSSGP_RIM_ROUTING_INF,									/* 11.3.70	RIM Routing Information */

	DE_BSSGP_MBMS_SESSION_ID,									/* 11.3.71	MBMS Session Identity */
	DE_BSSGP_MBMS_SESSION_DUR,									/* 11.3.72	MBMS Session Duration */
	DE_BSSGP_MBMS_SAI_LIST,										/* 11.3.73	MBMS Service Area Identity List */
	DE_BSSGP_MBMS_RESPONSE,										/* 11.3.74	MBMS Response */
	DE_BSSGP_MBMS_RA_LIST,										/* 11.3.75	MBMS Routing Area List */
	DE_BSSGP_MBMS_SESSION_INF,									/* 11.3.76	MBMS Session Information */

	DE_BSSGP_TMGI,												/* 11.3.77	TMGI (Temporary Mobile Group Identity) GSM_A_PDU_TYPE_GM, DE_TMGI*/
	DE_BSSGP_MBMS_STOP_CAUSE,									/* 11.3.78	MBMS Stop Cause */
	DE_BSSGP_SOURCE_BSS_TO_TARGET_BSS_TRANSP_CONT,				/* 11.3.79	Source BSS to Target BSS Transparent Container */
	DE_BSSGP_TARGET_BSS_TO_SOURCE_BSS_TRANSP_CONT,				/* 11.3.80	Target BSS to Source BSS Transparent Container */
	DE_BSSGP_PFCS_TO_BE_SET_UP_LIST,							/* 11.3.82	PFCs to be set-up list */
	DE_BSSGP_LIST_OF_SETUP_PFCS,								/* 11.3.83	List of set-up PFCs */
	DE_BSSGP_EXT_FEATURE_BITMAP,								/* 11.3.84	Extended Feature Bitmap */
	DE_BSSGP_SRC_TO_TRG_TRANSP_CONT,							/* 11.3.85	Source to Target Transparent Container */
	DE_BSSGP_TRG_TO_SRC_TRANSP_CONT,							/* 11.3.86	Target to Source Transparent Container */
	BE_BSSGP_RNC_ID,											/* 11.3.87	RNC Identifier */
	DE_BSSGP_PAGE_MODE,											/* 11.3.88	Page Mode */
 	DE_BSSGP_CONTAINER_ID,										/* 11.3.89	Container ID */
	DE_BSSGP_GLOBAL_TFI,										/* 11.3.90	Global TFI */
 	DE_BSSGP_TIME_TO_MBMS_DATA_TRAN,							/* 11.3.92	Time to MBMS Data Transfer */
 	DE_BSSGP_MBMS_SESSION_REP_NO,								/* 11.3.93	MBMS Session Repetition Number */

	DE_BSSGP_INTER_RAT_HO_INFO,									/* 11.3.94	Inter RAT Handover Info */
	DE_BSSGP_PS_HO_CMD,											/* 11.3.95	PS Handover Command */
 	DE_BSSGP_PS_HO_INDICATIONS,									/* 11.3.95a	PS Handover Indications */
 	DE_BSSGP_SIPSI_CONTAINER,									/* 11.3.95b	SI/PSI Container */
 	DE_BSSGP_ACTIVE_PFCS_LIST,									/* 11.3.95c	Active PFCs List */
	DE_BSSGP_VELOCITY_DATA,										/* 11.3.96	Velocity Data */
 	DE_BBSGP_DTM_HO_CMD,										/* 11.3.97	DTM Handover Command */
	DE_BSSGP_CS_INDICATION,										/* 11.3.98	CS Indication */
	DE_BSSGP_FLOW_CONTROL_GRAN,									/* 11.3.102	Flow Control Granularity */
	DE_BSSGP_ENB_ID,											/* 11.3.103 	eNB Identifier */
	DE_BSSGP_E_UTRAN_INTER_RAT_HO_INFO,							/* 11.3.104	E-UTRAN Inter RAT Handover Info */
 	DE_BSSGP_SUB_PROF_ID_F_RAT_FRQ_PRIO,						/* 11.3.105 Subscriber Profile ID for RAT/Frequency priority */
	DE_BSSGP_REQ_FOR_INTER_RAT_HO_INFO,							/* 11.3.106 Request for Inter-RAT Handover Info */
	DE_BSSGP_RELIABLE_INTER_RAT_HO_INF,							/* 11.3.107 Reliable Inter-RAT Handover Info */
	DE_BSSGP_SON_TRANSFER_APP_ID,								/* 11.3.108 SON Transfer Application Identity */
	DE_BSSGP_CSG_ID,											/* 11.3.109 CSG Identifier */
	DE_BSSGP_NONE												/* NONE */
}
bssgp_elem_idx_t;

guint16 (*bssgp_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
	de_bssgp_aligment_octets,									/* 11.3.1	0x00 Alignment octets */
	de_bssgp_bmax_default_ms,									/* 11.3.2	0x01 Bmax default MS  */
	de_bssgp_bss_area_ind,										/* 11.3.3	0x02 BSS Area Indication */
	de_bssgp_bucket_leak_rate,									/* 11.3.4	0x03 Bucket Leak Rate (R) */
	de_bssgp_bvci,												/* 11.3.6	0x04 BVCI (BSSGP Virtual Connection Identifier)  */
	de_bssgp_bvc_bucket_size,									/* 11.3.5	0x05 BVC Bucket Size */
	de_bssgp_bvc_meas,											/* 11.3.7	0x06 BVC Measurement */
	de_bssgp_cause,												/* 11.3.8	0x07 Cause */
 	de_bssgp_cell_id,											/* 11.3.9	0x08 Cell Identifier */
	de_bssgp_chnl_needed,										/* 11.3.10	0x09 Channel needed */
	NULL,														/* 11.3.11	0x0a DRX Parameters */
	NULL,														/* 11.3.12	0x0b eMLPP-Priority */
	de_bssgp_flush_action,										/* 11.3.13	0x0c Flush Action */
	de_mid,														/* 11.3.14	0x0d IMSI */
	de_bssgp_llc_pdu,											/* 11.3.15	0x0e LLC-PDU */
 	de_bssgp_llc_frames_disc,									/* 11.3.16	0x0f LLC Frames Discarded  */
	NULL,														/* 11.3.17	0x10 Location Area  */
	NULL,														/* 11.3.20	0x11 Mobile Id */
	de_bssgp_ms_bucket_size,									/* 11.3.21	0x12 MS Bucket Size */
	NULL,														/* 11.3.22	0x13 MS Radio Access Capability */
	de_bssgp_omc_id,											/* 11.3.23	0x14 OMC Id */
	de_bssgp_pdu_in_error,										/* 11.3.24	0x15 PDU In Error */
	de_bssgp_pdu_lifetime,										/* 11.3.25	0x16 PDU Lifetime */
	NULL,														/* 11.3.27  0x17	Priority */
	de_bssgp_qos_profile,										/* 11.3.28	0x18 QoS Profile */
	de_bssgp_ra_cause,											/* 11.3.29	0x19 Radio Cause */
	de_bssgp_ra_cap_upd_cause,									/* 11.3.30	0x1a RA-Cap-UPD-Cause */
	NULL,														/* 11.3.31	0x1b Routeing Area */
	de_bssgp_r_default_ms,										/* 11.3.32	0x1c R_default_MS */
	de_bssgp_suspend_ref_no,									/* 11.3.33	0x1d Suspend Reference Number */
	de_bssgp_tag,												/* 11.3.34	0x1e Tag */
	NULL,														/* 11.3.35	0x1f Temporary logical link Identity (TLLI) */
	NULL,														/* 11.3.36	0x20 Temporary Mobile Subscriber Identity (TMSI) */
 	de_bssgp_trace_ref,											/* 11.3.37	0x21 Trace Reference */
 	de_bssgp_trace_type,										/* 11.3.38	0x22 Trace Type */
	de_bssgp_transaction_id,									/* 11.3.39	0x23 Transaction Id */
	de_bssgp_trigger_id,										/* 11.3.40	0x24 Trigger Id */
	de_bssgp_no_of_oct_affected,								/* 11.3.41	0x25 Number of octets affected */
	NULL,														/* 11.3.18	0x26 LSA Identifier List GSM_A_PDU_TYPE_BSSMAP, BE_LSA_ID_LIST*/
	NULL,														/* 11.3.19	0x27 LSA Information */
	NULL,														/* 11.3.42	0x28 Packet Flow Identifier (PFI) */
	de_bssgp_gprs_timer,										/* 11.3.44	0x29 GPRS Timer */
	NULL,														/* 11.3.43	0x3a Aggregate BSS QoS Profile */
	de_bssgp_feature_bitmap,									/* 11.3.45	0x3b Feature Bitmap */
	de_bssgp_bucket_full_ratio,									/* 11.3.46	0x3c Bucket Full Ratio */
	de_bssgp_serv_utran_cco,									/* 11.3.47	0x3d Service UTRAN CCO */
	de_bssgp_nsei,												/* 11.3.48	0x3e NSEI (Network Service Entity Identifier) */
	de_bssgp_rrlp_apdu,											/* 11.3.49 RRLP APDU */
	de_bssgp_rrlp_flags,										/* 11.3.60	RRLP Flags */
	de_bssgp_rim_app_id,										/* 11.3.61	RIM Application Identity */
	de_bssgp_rim_seq_no,										/* 11.3.62	RIM Sequence Number */
	de_bssgp_ran_inf_request_rim_cont,							/* 11.3.62a.1 RAN-INFORMATION-REQUEST RIM Container */
	de_bssgp_ran_inf_rim_cont,									/* 11.3.62a.2 RAN-INFORMATION RIM Container */
	de_bssgp_ran_inf_ack_rim_cont,								/* 11.3.62a.3	RAN-INFORMATION-ACK RIM Container */
	de_bssgp_ran_inf_error_rim_cont,							/* 11.3.62a.4	RAN-INFORMATION-ERROR RIM Container */
	de_bssgp_ran_inf_app_error_rim_cont,						/* 11.3.62a.5	RAN-INFORMATION-APPLICATION-ERROR RIM Container */

	de_bssgp_ran_information_request_app_cont,					/* 11.3.63.1 RAN-INFORMATION-REQUEST Application Container */
	de_bssgp_ran_information_app_cont_unit,						/* 11.3.63.2 RAN-INFORMATION Application Container Unit */
	de_bssgp_ran_app_error_cont,								/* 11.3.64	Application Error Container */
	de_bssgp_rim_pdu_indications,								/* 11.3.65	RIM PDU Indications */
	de_bssgp_rim_proto_ver_no,									/* 11.3.67	RIM Protocol Version Number */

    de_bssgp_pfc_flow_ctrl,										/* 11.3.68	PFC Flow Control parameters */
	de_bssgp_rim_routing_inf,									/* 11.3.70	RIM Routing Information */
	de_bssgp_mbms_session_id,									/* 11.3.71	MBMS Session Identity */
	de_bssgp_mbms_session_dur,									/* 11.3.72	MBMS Session Duration */
	de_bssgp_mbms_sai_list,										/* 11.3.73	MBMS Service Area Identity List */
	de_bssgp_mbms_response,										/* 11.3.74	MBMS Response */
	de_bssgp_mbms_ra_list,										/* 11.3.75	MBMS Routing Area List */
	de_bssgp_mbms_session_inf,									/* 11.3.76	MBMS Session Information */
	NULL,														/* 11.3.77	TMGI (Temporary Mobile Group Identity) */
	de_bssgp_mbms_stop_cause,									/* 11.3.78	MBMS Stop Cause */
	de_bssgp_source_BSS_to_target_BSS_transp_cont,				/* 11.3.79	Source BSS to Target BSS Transparent Container */
	de_bssgp_target_BSS_to_source_BSS_transp_cont,				/* 11.3.80	Target BSS to Source BSS Transparent Container */
	de_bssgp_pfcs_to_be_set_up_list,							/* 11.3.82	PFCs to be set-up list */
	de_bssgp_list_of_setup_pfcs,								/* 11.3.83	List of set-up PFCs */
	de_bssgp_ext_feature_bitmap,								/* 11.3.84	Extended Feature Bitmap */
	de_bssgp_src_to_trg_transp_cont,							/* 11.3.85	Source to Target Transparent Container */
	de_bssgp_trg_to_src_transp_cont,							/* 11.3.86	Target to Source Transparent Container */
	de_bssgp_rnc_identifier,									/* 11.3.87	RNC Identifier */
	de_bssgp_page_mode,											/* 11.3.88	Page Mode */
	de_bssgp_container_id,										/* 11.3.89	Container ID */
	de_bssgp_global_tfi,										/* 11.3.90	Global TFI */
 	de_bssgp_time_to_MBMS_data_tran,							/* 11.3.92	Time to MBMS Data Transfer */
 	de_bssgp_mbms_session_rep_no,								/* 11.3.93	MBMS Session Repetition Number */
	de_bssgp_inter_rat_ho_info,									/* 11.3.94	Inter RAT Handover Info */
	de_bssgp_ps_ho_cmd,											/* 11.3.95	PS Handover Command */
 	de_bssgp_ps_ho_indications,									/* 11.3.95a	PS Handover Indications */
 	de_bssgp_sipsi_container,									/* 11.3.95b	SI/PSI Container */
	de_bssgp_active_pfcs_list,									/* 11.3.95c	Active PFCs List */
	de_bssgp_velocity_data,										/* 11.3.96	Velocity Data */
 	de_bssgp_dtm_ho_cmd,										/* 11.3.97	DTM Handover Command */
	de_bssgp_cs_indication,										/* 11.3.98	CS Indication */
	de_bssgp_flow_control_gran,									/* 11.3.102	Flow Control Granularity */
	de_bssgp_enb_id,											/* 11.3.103 	eNB Identifier */
	de_bssgp_e_utran_inter_rat_ho_info,							/* 11.3.104	E-UTRAN Inter RAT Handover Info */
	de_bssgp_sub_prof_id_f_rat_freq_prio,						/* 11.3.105	Subscriber Profile ID for RAT/Frequency priority */
	de_bssgp_reliable_inter_rat_ho_inf,							/* 11.3.107 Reliable Inter-RAT Handover Info */
	de_bssgp_req_for_inter_rat_ho_inf,							/* 11.3.106 Request for Inter-RAT Handover Info */
	de_bssgp_son_transfer_app_id,								/* 11.3.108 SON Transfer Application Identity */
	de_bssgp_csg_id,											/* 11.3.109 CSG Identifier */

	NULL,	/* NONE */
};

/*
 * 11.3.62a	RIM Container
 * 11.3.62a.0	General
 * 11.3.62a.1	RAN-INFORMATION-REQUEST RIM Container
 */
static guint16
de_bssgp_ran_inf_request_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RAN-INFORMATION-REQUEST RIM Container Contents coded as
	 * defined in table 11.3.62a.1b
	 */
	/* RIM Application Identity RIM Application Identity/11.3.61 M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_APP_ID, BSSGP_PDU_TYPE, DE_BSSGP_RIM_APP_ID, NULL);
	/* RIM Sequence Number RIM Sequence Number/11.3.62 M TLV 6 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_SEQUENCE_NUMBER, BSSGP_PDU_TYPE, DE_BSSGP_RIM_SEQ_NO, NULL);
	/* RIM PDU Indications RIM PDU Indications/11.3.65 M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_PDU_INDICATIONS, BSSGP_PDU_TYPE, DE_BSSGP_RIM_PDU_INDICATIONS, NULL);
	/* RIM Protocol Version Number RIM Protocol Version Number/11.3.67 O TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(BSSGP_IEI_RIM_PROTOCOL_VERSION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_PROTO_VER_NO, NULL);
	/* Application Container (note 1) RAN-INFORMATION-REQUEST Application Container/11.3.63.1 C TLV 4-? */
	ELEM_IN_ELEM_OPT_TELV(BSSGP_IEI_RAN_INF_REQUEST_APP_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_INFORMATION_REQUEST_APP_CONT, NULL);
	/* SON Transfer Application Identity (note 2) SON Transfer Application Identity/11.3.108 C TLV 3-m */
	ELEM_IN_ELEM_OPT_TELV(0x84, BSSGP_PDU_TYPE, DE_BSSGP_SON_TRANSFER_APP_ID, NULL);

	return(curr_offset-offset);
}
/*
 * 11.3.62a.2	RAN-INFORMATION RIM Container
 */
static guint16
de_bssgp_ran_inf_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RAN-INFORMATION RIM Container Contents coded as
	 * defined in table 11.3.62a.2b
	 */
	/* RIM Application Identity RIM Application Identity /11.3.61 M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_APP_ID, BSSGP_PDU_TYPE, DE_BSSGP_RIM_APP_ID, NULL);
	/* RIM Sequence Number RIM Sequence Number /11.3.62 M TLV 6 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_SEQUENCE_NUMBER, BSSGP_PDU_TYPE, DE_BSSGP_RIM_SEQ_NO, NULL);
	/* RIM PDU Indications RIM PDU Indications /11.3.65. M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_PDU_INDICATIONS, BSSGP_PDU_TYPE, DE_BSSGP_RIM_PDU_INDICATIONS, NULL);
	/* RIM Protocol Version Number RIM Protocol Version Number/11.3.67 O TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(BSSGP_IEI_RIM_PROTOCOL_VERSION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_PROTO_VER_NO, NULL);
	/* Application Container (NOTE 1) RAN-INFORMATION Application Container /11.3.63.2 C (Note 1) TLV 4-? */
	ELEM_IN_ELEM_OPT_TELV(BSSGP_IEI_RAN_INF_APP_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_INFORMATION_APP_CONT_UNIT, NULL);
	/* Application Error Container (NOTE 1) Application Error Container/11.3.64 C (Note 1) TLV n */
	ELEM_IN_ELEM_OPT_TELV(BSSGP_IEI_APPLICATION_ERROR_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_APP_ERROR_CONT, NULL);
	/* SON Transfer Application Identity (note 2) SON Transfer Application Identity/11.3.108 C TLV 3-m */
	ELEM_IN_ELEM_OPT_TELV(0x84, BSSGP_PDU_TYPE, DE_BSSGP_SON_TRANSFER_APP_ID, NULL);

	return(curr_offset-offset);
}

/*
 * 11.3.62a.3	RAN-INFORMATION-ACK RIM Container
 */
static guint16
de_bssgp_ran_inf_ack_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RAN-INFORMATION-ACK RIM Container Contents coded as
	 * defined in table 11.3.62a.3b
	 */
	/* RIM Application Identity RIM Application Identity /11.3.61 M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_APP_ID, BSSGP_PDU_TYPE, DE_BSSGP_RIM_APP_ID, NULL);
	/* RIM Sequence Number RIM Sequence Number /11.3.62 M TLV 6 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_SEQUENCE_NUMBER, BSSGP_PDU_TYPE, DE_BSSGP_RIM_SEQ_NO, NULL);
	/* RIM Protocol Version Number RIM Protocol Version Number/11.3.67 O TLV 4 */
	ELEM_IN_ELEM_OPT_TELV(BSSGP_IEI_RIM_PROTOCOL_VERSION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_PROTO_VER_NO, NULL);
	/* SON Transfer Application Identity (note 1) SON Transfer Application Identity/11.3.108 C TLV 3-m */
	ELEM_IN_ELEM_OPT_TELV(0x84, BSSGP_PDU_TYPE, DE_BSSGP_SON_TRANSFER_APP_ID, NULL);

	return(curr_offset-offset);
}
/*
 * 11.3.62a.4	RAN-INFORMATION-ERROR RIM Container
 */
static guint16
de_bssgp_ran_inf_error_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RAN-INFORMATION-ERROR RIM Container Contents coded as
	 * defined in table 11.3.62a.4b
	 */
	/* RIM Application Identity RIM Application Identity /11.3.61 M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_APP_ID, BSSGP_PDU_TYPE, DE_BSSGP_RIM_APP_ID, NULL);
	/* RIM Cause Cause/11.3.8 M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, " - RIM");
	/* RIM Sequence Number RIM Sequence Number /11.3.62 M TLV 6 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_SEQUENCE_NUMBER, BSSGP_PDU_TYPE, DE_BSSGP_RIM_SEQ_NO, NULL);
	/* RIM Protocol Version Number RIM Protocol Version Number/11.3.67 O TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(BSSGP_IEI_RIM_PROTOCOL_VERSION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_PROTO_VER_NO, NULL);
	/* PDU in Error PDU in Error/11.3.24 M TLV 3-? */
	ELEM_IN_ELEM_OPT_TELV(0x15, BSSGP_PDU_TYPE, DE_BSSGP_PDU_IN_ERROR , NULL);
	/* SON Transfer Application Identity (note 1) SON Transfer Application Identity/11.3.108 C TLV 3-m */
	ELEM_IN_ELEM_OPT_TELV(0x84, BSSGP_PDU_TYPE, DE_BSSGP_SON_TRANSFER_APP_ID, NULL);

	return(curr_offset-offset);
}
/*
 * 11.3.62a.5	RAN-INFORMATION-APPLICATION-ERROR RIM Container
 */
static guint16
de_bssgp_ran_inf_app_error_rim_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RRAN-INFORMATION-APPLICATION-ERROR RIM Container
	 * Contents coded as defined in table 11.3.62a.5b
	 */
	/* RIM Application Identity RIM Application Identity /11.3.61 M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_APP_ID, BSSGP_PDU_TYPE, DE_BSSGP_RIM_APP_ID, NULL);
	/* RIM Sequence Number RIM Sequence Number /11.3.62 M TLV 6 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_SEQUENCE_NUMBER, BSSGP_PDU_TYPE, DE_BSSGP_RIM_SEQ_NO, NULL);
	/* RIM PDU Indications RIM PDU Indications /11.3.65. M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_RIM_PDU_INDICATIONS, BSSGP_PDU_TYPE, DE_BSSGP_RIM_PDU_INDICATIONS, NULL);
	/* RIM Protocol Version Number RIM Protocol Version Number/11.3.67 O TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(BSSGP_IEI_RIM_PROTOCOL_VERSION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_PROTO_VER_NO, NULL);
	/* Application Error Container Application Error Container/11.3.64 M TLV n */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_APPLICATION_ERROR_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_APP_ERROR_CONT, NULL);
	/* SON Transfer Application Identity (note 1) SON Transfer Application Identity/11.3.108 C TLV 3-m */
	ELEM_IN_ELEM_OPT_TELV(0x84, BSSGP_PDU_TYPE, DE_BSSGP_SON_TRANSFER_APP_ID, NULL);

	return(curr_offset-offset);
}

/*
 * 11.3.79	Source BSS to Target BSS Transparent Container
 */
static guint16
de_bssgp_source_BSS_to_target_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;


	/* Octet 3-? Source BSS to Target BSS Transparent Container Contents coded
	 * as defined in table 11.3.79.b
	 */
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 M TLV 7-? */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);
	/* Inter RAT Handover Info Inter RAT Handover Info/11.3.94 O (note 1) TLV 3-? */
	ELEM_IN_ELEM_OPT_TELV(0x73, BSSGP_PDU_TYPE, DE_BSSGP_INTER_RAT_HO_INFO, NULL);
	/* Page Mode Page Mode/11.3.88 O (note 2, note 3) TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(0x6d, BSSGP_PDU_TYPE, DE_BSSGP_PAGE_MODE, NULL);
	/* Container ID Container ID/11.3.89 O (note 2) TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(0x6e, BSSGP_PDU_TYPE, DE_BSSGP_CONTAINER_ID, NULL);
	/* Global TFI Global TFI/11.3.90 O (note 2, note 3) TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(0x6f, BSSGP_PDU_TYPE, DE_BSSGP_GLOBAL_TFI, NULL);
	/* PS Handover Indications PS Handover Indications/11.3.95a O TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(0x75, BSSGP_PDU_TYPE, DE_BSSGP_PS_HO_INDICATIONS, NULL);
	/* CS Indication CS Indication/11.3.98 O (note 3) TLV 3 */
	ELEM_IN_ELEM_OPT_TELV(0x7a, BSSGP_PDU_TYPE, DE_BSSGP_CS_INDICATION, NULL);
	/* E-UTRAN Inter RAT Handover Info E-UTRAN Inter RAT HandoverInfo/11.3.104 O (note 1) TLV 3-? */
	ELEM_IN_ELEM_OPT_TELV(0x80, BSSGP_PDU_TYPE, DE_BSSGP_E_UTRAN_INTER_RAT_HO_INFO, NULL);

	return(curr_offset-offset);
}

/*
 * 11.3.80 Target BSS to Source BSS Transparent Container
 */
static guint16
de_bssgp_target_BSS_to_source_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;


	/* Octet 3-? Target BSS to Source BSS Transparent Container Contents coded
	 * as defined in table 11.3.80.b
	 */

	/* PS Handover Command PS Handover Command/11.3.95 O (Note 2) TLV 4-? */
	ELEM_IN_ELEM_OPT_TELV(0x74, BSSGP_PDU_TYPE, DE_BSSGP_PS_HO_CMD, NULL);
	/* SI/PSI Container SI/PSI Container/11.3.95b O (Note 1) TLV 3-? */
	ELEM_IN_ELEM_OPT_TELV(0x76, BSSGP_PDU_TYPE, DE_BSSGP_SIPSI_CONTAINER, NULL);
	/* DTM Handover Command DTM Handover Command/11.3.97 O (Note 2) TLV 22-? */
	ELEM_IN_ELEM_OPT_TELV(0x79, BSSGP_PDU_TYPE, DE_BBSGP_DTM_HO_CMD, NULL);

	return(curr_offset-offset);
}

/* MESSAGE FUNCTIONS */

/*
 * 10.2	PDU functional definitions and contents at RL and BSSGP SAPs
 * 10.2.1 DL-UNITDATA
 */
static void
bssgp_dl_unitdata(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU is sent to the BSS to transfer an LLC-PDU across the radio interface to an MS. */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI (current) TLLI/11.3.35 M V 4 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TLLI, " - current");
	/* QoS Profile (note 1) QoS Profile/11.3.28 M V 3 */
	ELEM_MAND_V(BSSGP_PDU_TYPE, DE_BSSGP_QOS_PROFILE, NULL);

	/* PDU Lifetime PDU Lifetime/11.3.25 M TLV 4 */
	ELEM_MAND_TELV(0x16, BSSGP_PDU_TYPE, DE_BSSGP_PDU_LIFETIME, NULL);
	/* MS Radio Access Capability (note 2) MS Radio Access Capability/11.3.22 O TLV 7-? */
	ELEM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);
	/* Priority (note 3) Priority/11.3.27 O TLV 3 */
	ELEM_OPT_TELV(0x0b, GSM_A_PDU_TYPE_BSSMAP, BE_PRIO, NULL);
	/* DRX Parameters DRX Parameters/11.3.11 O TLV 4 */
	ELEM_OPT_TELV(0x0a , GSM_A_PDU_TYPE_GM, DE_DRX_PARAM , NULL);
	/* IMSI IMSI/11.3.14 O TLV 5-10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* TLLI (old) TLLI/11.3.35 O TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , " - old");
	/* PFI PFI/11.3.42 O TLV 3 */
	ELEM_OPT_TELV( BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* LSA Information LSA Information/11.3.19 O TLV 7-? */
	ELEM_OPT_TELV(0x27, GSM_A_PDU_TYPE_BSSMAP, BE_LSA_INFO, NULL);
	/* Service UTRAN CCO Service UTRAN CCO/11.3.47 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_SERVICE_UTRAN_CCO, BSSGP_PDU_TYPE, DE_BSSGP_SERV_UTRAN_CCO, NULL);

	/* Subscriber Profile ID for RAT/Frequency priority (note 5)
	 * Subscriber Profile ID for RAT/Frequency priority/11.3.105 O TLV 3
	 */
	ELEM_OPT_TELV(0x81, BSSGP_PDU_TYPE, DE_BSSGP_SUB_PROF_ID_F_RAT_FRQ_PRIO, NULL);
	/* Alignment octets Alignment octets/11.3.1 O TLV 2-5 */
	ELEM_OPT_TELV(0x00, BSSGP_PDU_TYPE, DE_BSSGP_ALIGNMENT_OCTETS, NULL);
	/* LLC-PDU (note 4) LLC-PDU/11.3.15 M TLV 2-? */
	ELEM_MAND_TELV(0x0e, BSSGP_PDU_TYPE, DE_BSSGP_LLC_PDU, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.2.2	UL-UNITDATA
 */
static void
bssgp_ul_unitdata(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU transfers an MS's LLC-PDU and its associated radio interface information across the Gb-interface.
	 * Direction: BSS to SGSN
	 */
	pinfo->link_dir = P2P_DIR_UL;
	/* TLLI TLLI/11.3.35 M V 4 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TLLI, NULL);
	/* QoS Profile QoS Profile/11.3.28 M V 3 */
	ELEM_MAND_V(BSSGP_PDU_TYPE, DE_BSSGP_QOS_PROFILE, NULL);
	/* Cell Identifier Cell Identifier/11.3.9 M TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , NULL);
	/* PFI PFI/11.3.42 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* LSA Identifier List LSA Identifier List/11.3.18 O TLV 3-?  */
	ELEM_OPT_TELV(0x26, GSM_A_PDU_TYPE_BSSMAP, BE_LSA_ID_LIST, NULL);
	/* Alignment octets Alignment octets/11.3.1 O TLV 2-5  */
	ELEM_OPT_TELV(0x00, BSSGP_PDU_TYPE, DE_BSSGP_ALIGNMENT_OCTETS, NULL);
	/* LLC-PDU (note) LLC-PDU/11.3.15 M TLV 2-?  */
	ELEM_MAND_TELV(0x0e, BSSGP_PDU_TYPE, DE_BSSGP_LLC_PDU, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.2.3	RA-CAPABILITY
 */
static void
bssgp_ra_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the BSS of the new Radio Access Capability of an MS. */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 M TLV 7-? */
	ELEM_MAND_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.2.4	(void)
 */
/*
 * 10.2.5	DL-MBMS-UNITDATA
 */
static void
bssgp_dl_mbms_unitdata(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU is sent to the BSS to transfer an LLC-PDU across the radio interface.
	 * Direction: SGSN to BSS
	 */
	pinfo->link_dir = P2P_DIR_DL;

	/* PDU Lifetime PDU Lifetime/11.3.25 M TLV 4  */
	ELEM_MAND_TELV(0x16, BSSGP_PDU_TYPE, DE_BSSGP_PDU_LIFETIME, NULL);
	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* Alignment octets Alignment octets/11.3.1 O TLV 2-5 */
	ELEM_OPT_TELV(0x00, BSSGP_PDU_TYPE, DE_BSSGP_ALIGNMENT_OCTETS, NULL);
	/* LLC-PDU LLC-PDU/11.3.15 M TLV 3-? */
	ELEM_MAND_TELV(0x0e, BSSGP_PDU_TYPE, DE_BSSGP_LLC_PDU, NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.2.6	UL-MBMS-UNITDATA
 */
static void
bssgp_ul_mbms_unitdata(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU transfers an LLC-PDU for an MBMS session across the Gb-interface.
	 * Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* Alignment octets Alignment octets/11.3.1 O TLV 2-5 */
	ELEM_OPT_TELV(0x00, BSSGP_PDU_TYPE, DE_BSSGP_ALIGNMENT_OCTETS, NULL);
	/* LLC-PDU (note 1) LLC-PDU/11.3.15 M TLV 2-? */
	ELEM_MAND_TELV(0x0e, BSSGP_PDU_TYPE, DE_BSSGP_LLC_PDU, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.3	PDU functional definitions and contents at GMM SAP
 * 10.3.1	PAGING PS
 */

static void
bssgp_paging_ps(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* This PDU indicates that a BSS shall initiate the packet paging procedure for an MS within a group of cells.
	 * Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* IMSI IMSI/11.3.14 M TLV 5 -10 */
	ELEM_MAND_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* DRX Parameters DRX Parameters/11.3.11 O TLV 4 */
	ELEM_OPT_TELV(0x0a , GSM_A_PDU_TYPE_GM, DE_DRX_PARAM , NULL);
	/* BVCI a) BVCI/11.3.6 C TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Location Area (note) Location Area/11.3.17 C TLV 7 */
	ELEM_OPT_TELV(0x10,GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);
	/* Routeing Area (note) Routeing Area/11.3.31 C TLV 8 */
	ELEM_OPT_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* BSS Area Indication (note) BSS Area Indication/11.3.3 C TLV 3 */
	ELEM_OPT_TELV(0x02,BSSGP_PDU_TYPE, DE_BSSGP_BSS_AREA_IND, NULL);
	/* PFI PFI/11.3.42 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* ABQP ABQP/11.3.43 O TLV 13-? */
	ELEM_OPT_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);
	/* QoS Profile QoS Profile/11.3.28 M TLV 5 */
	ELEM_MAND_TELV(0x18,BSSGP_PDU_TYPE, DE_BSSGP_QOS_PROFILE, NULL);
	/* P-TMSI TMSI/11.3.36 O TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TMSI,GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.3.2	PAGING CS
 */
static void
bssgp_paging_cs(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* This PDU indicates that a BSS shall initiate a circuit-switched paging procedure for an MS within a group of cells.
	 * Direction: SGSN to BSS
	 */
	pinfo->link_dir = P2P_DIR_DL;
	/* IMSI IMSI/11.3.14 M TLV 5 -10 */
	ELEM_MAND_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* DRX Parameters DRX Parameters/11.3.11 M TLV 4 */
	ELEM_MAND_TELV(0x0a , GSM_A_PDU_TYPE_GM, DE_DRX_PARAM , NULL);
	/* BVCI a) BVCI/11.3.6 C TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Location Area (note 1) Location Area/11.3.17 C TLV 7 */
	ELEM_OPT_TELV(0x10,GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);
	/* Routeing Area (note 1) Routeing Area/11.3.31 C TLV 8 */
	ELEM_OPT_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* BSS Area Indication (note 1) BSS Area Indication/11.3.3 C TLV 3 */
	ELEM_OPT_TELV(0x02,BSSGP_PDU_TYPE, DE_BSSGP_BSS_AREA_IND, NULL);
	/* TLLI TLLI/11.3.35 O TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Channel needed (note 2) Channel needed/11.3.10 O TLV 3 */
	ELEM_OPT_TELV(0x09, BSSGP_PDU_TYPE, DE_BSSGP_CHLN_NEEDED , NULL);
	/* eMLPP-Priority (note 2) eMLPP-Priority/11.3.12 O TLV 3 */
	ELEM_OPT_TELV(0x0b, GSM_A_PDU_TYPE_BSSMAP, BE_EMLPP_PRIO, NULL);
	/* TMSI (note 2) TMSI/11.3.36 O TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TMSI,GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, NULL);
	/* Global CN-Id (note 2) Global CN-Id/11.3.69 O TLV 7 */
	ELEM_OPT_TELV(0x53, SGSAP_PDU_TYPE, DE_SGSAP_GLOBAL_CN_ID, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.3.3	RA-CAPABILITY-UPDATE
 */
static void
bssgp_ra_cap_upd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* This PDU requests that the SGSN send an MS's current Radio Access capability or IMSI to the BSS. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* IMSI (note) IMSI/11.3.14 C TLV 5 -10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* RA-Cap-UPD-CAUSE RA-Cap-UPDCAUSE/11.3.30 M TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_RA_CAP_UPD_CAUSE, BSSGP_PDU_TYPE, DE_BSSGP_RA_CAP_UPD_CAUSE , NULL);
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 C TLV 7-? */
	ELEM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.3.4	RA-CAPABILITY-UPDATE-ACK
 */

static void
bssgp_ra_cap_upd_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* This PDU provides the BSS with an MS's current Radio Access capability and IMSI */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* IMSI (note) IMSI/11.3.14 C TLV 5 -10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* RA-Cap-UPD-CAUSE RA-Cap-UPDCAUSE/11.3.30 M TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_RA_CAP_UPD_CAUSE, BSSGP_PDU_TYPE, DE_BSSGP_RA_CAP_UPD_CAUSE , NULL);
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 C TLV 7-? */
	ELEM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.3.5	RADIO-STATUS
 */
static void
bssgp_ra_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that an exception condition related to the radio interface has occurred. */
	/* BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI (note) TLLI/11.3.35 C TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* TMSI (note) TMSI/11.3.36 C TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TMSI,GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, NULL);
	/* IMSI (note) IMSI/11.3.14 C TLV 5-10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* Radio Cause Radio Cause/11.3.29 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_RADIO_CAUSE, BSSGP_PDU_TYPE, DE_BSSGP_RA_CAUSE , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.3.6	SUSPEND
 */
static void
bssgp_suspend(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that an MS wishes to suspend its GPRS service. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.3.7	SUSPEND-ACK
 */
void
bssgp_suspend_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU positively acknowledges the reception of a SUSPEND PDU for an MS. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* Suspend Reference Number Suspend Reference Number/11.3.33 M TLV 3 */
	ELEM_MAND_TELV(0x1d,BSSGP_PDU_TYPE, DE_BBSGP_SUSPEND_REF_NO, NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.3.8	SUSPEND-NACK
 */
static void
bssgp_suspend_nack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;


	/* This PDU negatively acknowledges the reception of a SUSPEND PDU for an MS. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* Cause Cause/11.3.8 O TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.3.9	RESUME
 */
static void
bssgp_resume(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that an MS wishes to RESUME its GPRS service. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* Suspend Reference Number Suspend Reference Number/11.3.33 M TLV 3 */
	ELEM_MAND_TELV(0x1d,BSSGP_PDU_TYPE, DE_BBSGP_SUSPEND_REF_NO, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.3.10	RESUME-ACK
 */

static void
bssgp_resume_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU positively acknowledges the reception of a RESUME PDU for an MS. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.3.11	RESUME-NACK
 */

static void
bssgp_resume_nack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU negatively acknowledges the reception of a RESUME PDU for an MS. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* Cause Cause/11.3.8 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4	PDU functional definitions and contents at NM SAP
 * 10.4.1	FLUSH-LL
 */
static void
bssgp_flush_ll(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs a BSS that an MS has moved from one cell to another. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* BVCI (old) BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - Old");
	/* BVCI (new) BVCI/11.3.6 O TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - New");
	/* NSEI (new) NSEI/11.3.48 O (note) TLV 4 */
	ELEM_OPT_TELV(0x3e, GSM_A_PDU_TYPE_RR, DE_BSSGP_NSEI , " - New");

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.2	FLUSH-LL-ACK
 */
static void
bssgp_flush_ll_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that LLC-PDU(s) buffered for an MS in the old cell
	 * have been either deleted or transferred to the new cell within the routing area. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Flush Action Flush Action/11.3.13 M TLV 3 */
	ELEM_MAND_TELV(0x0c, BSSGP_PDU_TYPE, DE_BSSGP_FLUSH_ACTION , NULL);
	/* BVCI (new) BVCI/11.3.13 C (note 1) TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - New");
	/* Number of octets affected Number of octets affected/11.3.41 M TLV 5 */
	ELEM_MAND_TELV(BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED, BSSGP_PDU_TYPE, DE_BSSGP_NO_OF_OCT_AFFECTED , NULL);
	/* NSEI (new) NSEI/11.3.48 C (note 2) TLV 4 */
	ELEM_OPT_TELV(0x3e, GSM_A_PDU_TYPE_RR, DE_BSSGP_NSEI , " - New");


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.3	LLC-DISCARDED
 */
static void
bssgp_llc_discarded(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* LLC Frames Discarded LLC Frames Discarded/11.3.16 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_LLC_FRAMES_DISCARDED, BSSGP_PDU_TYPE, DE_BSSGP_LLC_FRAMES_DISC , NULL);
	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Number of octets deleted Number of octets affected/11.3.41 M TLV 5 */
	ELEM_MAND_TELV(BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED, BSSGP_PDU_TYPE, DE_BSSGP_NO_OF_OCT_AFFECTED , NULL);
	/* PFI (note) PFI/11.3.42 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.4	FLOW-CONTROL-BVC
 */
static void
bssgp_flow_control_bvc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at an SGSN of the status of a
	 * BVC's maximum acceptable SGSN to BSS throughput on the Gb interface.
	 */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* BVC Bucket Size BVC Bucket Size/11.3.5 M TLV 4 */
	ELEM_MAND_TELV(0x05, BSSGP_PDU_TYPE, DE_BSSGP_BVC_BUCKET_SIZE , NULL);
	/* Bucket Leak Rate Bucket Leak Rate/11.3.4 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BUCKET_LEAK_RATE, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_LEAK_RATE , NULL);
	/* Bmax default MS Bmax default MS/11.3.2 M TLV 4 */
	ELEM_MAND_TELV(0x01, BSSGP_PDU_TYPE, DE_BSSGP_BMAX_DEFAULT_MS , NULL);
	/* R_default_MS R_default_MS/11.3.32 M TLV 4 */
	ELEM_MAND_TELV(0x1c, BSSGP_PDU_TYPE, DE_BSSGP_R_DEFAULT_MS , NULL);
	/* Bucket_Full Ratio Bucket_Full Ratio/11.3.46 C TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_BUCKET_FULL_RATIO, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_FULL_RATIO , NULL);
	/* BVC Measurement BVC Measurement/11.3.7 O TLV 4  */
	ELEM_OPT_TELV(0x06, BSSGP_PDU_TYPE, DE_BSSGP_BVC_MEAS , NULL);
	/* Flow Control Granularity (note) Flow Control Granularity/11.3.102 O TLV 3 */
	ELEM_OPT_TELV(0x7e, BSSGP_PDU_TYPE, DE_BSSGP_FLOW_CONTROL_GRAN , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.5	FLOW-CONTROL-BVC-ACK
 */
static void
bssgp_flow_control_bvc_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at the BSS that the SGSN has received
	 * the FLOW-CONTROL-BVC PDU indicated by the Tag.
	 */

	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.6	FLOW-CONTROL-MS
 */
static void
bssgp_flow_control_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at an SGSN of the status of an MS's
	 * maximum acceptable SGSN to BSS throughput on the Gb interface.
	 */

	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* MS Bucket Size MS Bucket Size/11.3.21 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_MS_BUCKET_SIZE, BSSGP_PDU_TYPE, DE_BSSGP_MS_BUCKET_SIZE , NULL);
	/* Bucket Leak rate Bucket Leak rate/11.3.4 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BUCKET_LEAK_RATE, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_LEAK_RATE , NULL);
	/* Bucket_Full Ratio Bucket_Full Ratio/11.3.46 C TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_BUCKET_FULL_RATIO, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_FULL_RATIO , NULL);
	/* Flow Control Granularity (note) Flow Control Granularity/11.3.102 O TLV 3 */
	ELEM_OPT_TELV(0x7e, BSSGP_PDU_TYPE, DE_BSSGP_FLOW_CONTROL_GRAN , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.7	FLOW-CONTROL-MS-ACK
 */
static void
bssgp_flow_control_ms_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at the BSS that the SGSN has received
	 * the FLOW-CONTROL-MS PDU indicated by the TLLI and the Tag. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6  */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.8	BVC-BLOCK
 */

static void
bssgp_bvc_block(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that the contained BVC shall be blocked at the recipient entity. */
	/* BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.9	BVC-BLOCK-ACK
 */
static void
bssgp_bvc_block_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU acknowledges that a BVC has been blocked. */
	/* SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.10	BVC-UNBLOCK
 */
static void
bssgp_bvc_un_block(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that the identified BVC shall be unblocked at the recipient entity. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.11	BVC-UNBLOCK-ACK
 */

static void
bssgp_bvc_un_block_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU acknowledges that a BVC has been unblocked. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.12	BVC-RESET
 */

static void
bssgp_bvc_reset(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that BVC initialisation is required, e.g. because of a BVC failure. */
	/* Direction: SGSN to BSS, BSS to SGSN */

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);
	/* Cell Identifier (note 1) C TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , NULL);
	/* Feature bitmap (note 2) Feature bitmap/11.3.45 O TLV 3 */
	ELEM_OPT_TELV(0x3b, BSSGP_PDU_TYPE, DE_BSSGP_FEATURE_BITMAP , NULL);
	/* Extended Feature Bitmap (note 3) Extended Feature Bitmap/11.3.84 O TLV 3 */
	ELEM_OPT_TELV(0x69, BSSGP_PDU_TYPE, DE_BSSGP_EXT_FEATURE_BITMAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.13	BVC-RESET-ACK
 */

static void
bssgp_bvc_reset_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that BVC initialisation has been executed */
	/* BSS to SGSN, SGSN to BSS */

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Cell Identifier (note 1) C TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , NULL);
	/* Feature bitmap (note 2) Feature bitmap/11.3.45 O TLV 3 */
	ELEM_OPT_TELV(0x3b, BSSGP_PDU_TYPE, DE_BSSGP_FEATURE_BITMAP , NULL);
	/* Extended Feature Bitmap (note 3) Extended Feature Bitmap/11.3.84 O TLV 3 */
	ELEM_OPT_TELV(0x69, BSSGP_PDU_TYPE, DE_BSSGP_EXT_FEATURE_BITMAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.14	STATUS
 */
static void
bssgp_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that an exception condition occurred. */
	/* Direction: SGSN to BSS, BSS to SGSN */

	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);
	/* BVCI BVCI/11.3.6 C TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* PDU In Error (note) PDU In Error/11.3.24 O TLV 3-? */
	ELEM_MAND_TELV(0x15, BSSGP_PDU_TYPE, DE_BSSGP_PDU_IN_ERROR , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.15	SGSN-INVOKE-TRACE
 */
static void
bssgp_sgsn_invoke_trace(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that the BSS shall begin the production of a trace record for an MS. */
	/* Direction: SGSN to BSS */

	pinfo->link_dir = P2P_DIR_UL;

	/* Trace Type Trace Type/11.3.38 M TLV 3 */
	ELEM_MAND_TELV(0x22, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Trace Reference Trace Reference/11.3.37 M TLV 4 */
	ELEM_MAND_TELV(0x21, BSSGP_PDU_TYPE, DE_BSSGP_TRACE_REF , NULL);
	/* Trigger Id Trigger Id/11.3.40 O TLV 4-24 */
	ELEM_OPT_TELV(0x24, BSSGP_PDU_TYPE, DE_BSSGP_TRIGGER_ID , NULL);
	/* Mobile Id Mobile Id/11.3.20 O TLV 3-10 */
	ELEM_OPT_TELV(0x11,GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);
	/* OMC Id OMC Id/11.3.23 O TLV 4-24 */
	ELEM_OPT_TELV(0x14,GSM_A_PDU_TYPE_COMMON, DE_BSSGP_OMC_ID, NULL);
	/* TransactionId TransactionId/11.3.39 O TLV 4 */
	ELEM_OPT_TELV(0x23, BSSGP_PDU_TYPE, DE_BSSGP_TRANSACTION_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.16	DOWNLOAD-BSS-PFC
 */
static void
bssgp_download_bss_pfc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU requests a SGSN to initiate a CREATE-BSS-PFC procedure. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.17	CREATE-BSS-PFC
 */
static void
bssgp_create_bss_pfc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the SGSN to request that a BSS create or modify a BSS Packet Flow Context. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* IMSI IMSI/11.3.14 O (note 4) TLV 5 -10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* PFT GPRS Timer/11.3.44 M TLV 3 */
	ELEM_MAND_TELV(0x29, BSSGP_PDU_TYPE, DE_BSSGP_GPRS_TIMER , " - PFT");
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);
	/* Service UTRAN CCO Service UTRAN CCO/11.3.47 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_SERVICE_UTRAN_CCO, BSSGP_PDU_TYPE, DE_BSSGP_SERV_UTRAN_CCO, NULL);
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 O (note 1) TLV 7-? */
	ELEM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);
	/* Allocation/Retention Priority Priority/11.3.27 O TLV 3 */
	ELEM_OPT_TELV(0x0b, GSM_A_PDU_TYPE_BSSMAP, BE_PRIO, NULL);
	/* T10 GPRS Timer/11.3.44 C (note 2) TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_GPRS_TIMER, BSSGP_PDU_TYPE, DE_BSSGP_GPRS_TIMER , " - T10");
	/* Inter RAT Handover Info Inter RAT Handover Info/11.3.94 O (note 3) TLV 3-? */
	ELEM_OPT_TELV(0x73, BSSGP_PDU_TYPE, DE_BSSGP_INTER_RAT_HO_INFO, NULL);
	/* E-UTRAN Inter RAT Handover Info E-UTRAN Inter RAT Handover Info/11.3.104 O (note 3) TLV 3-? */
	ELEM_OPT_TELV(0x80, BSSGP_PDU_TYPE, DE_BSSGP_E_UTRAN_INTER_RAT_HO_INFO, NULL);
	/* Subscriber Profile ID for RAT/Frequency priority (note 5)
	 * Subscriber Profile ID for RAT/Frequency priority/11.3.105 O TLV 3
	 */
	ELEM_OPT_TELV(0x81, BSSGP_PDU_TYPE, DE_BSSGP_SUB_PROF_ID_F_RAT_FRQ_PRIO, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.18	CREATE-BSS-PFC-ACK
 */
static void
bssgp_create_bss_pfc_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to acknowledge a request from the SGSN for the creation
	 * or modification of a BSS Packet Flow Context.
	 */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);
	/* Cause Cause/11.3.8 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.19	CREATE-BSS-PFC-NACK
 */
static void
bssgp_create_bss_pfc_nack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to Nack a request from the SGSN for the
	 * creation of a BSS Packet Flow Context
	 */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.20	MODIFY-BSS-PFC
 */
static void
bssgp_modify_bss_pfc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to request a modification of a BSS Packet Flow Context. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.21	MODIFY-BSS-PFC-ACK
 */
static void
bssgp_modify_bss_pfc_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the SGSN to acknowledge a modification to a BSS Packet Flow Context. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* PFT GPRS Timer/11.3.44 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_GPRS_TIMER, BSSGP_PDU_TYPE, DE_BSSGP_GPRS_TIMER , " - PFT");
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.22	DELETE-BSS-PFC
 */
static void
bssgp_delete_bss_pfc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the SGSN to request that a BSS delete a BSS Packet Flow Context. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.23	DELETE-BSS-PFC-ACK
 */
static void
bssgp_delete_bss_pfc_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to acknowledge a request for the deletion of a BSS Packet Flow Context. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.24	FLOW-CONTROL-PFC
 */
static void
bssgp_flow_cntrl_pfc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU provides the SGSN with flow control information regarding one or more PFC(s) of a given Mobile Station. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* MS Bucket Size MS Bucket Size/11.3.21 O TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_MS_BUCKET_SIZE, BSSGP_PDU_TYPE, DE_BSSGP_MS_BUCKET_SIZE , NULL);
	/* Bucket Leak rate Bucket Leak rate/11.3.4 O TLV 4 */
	ELEM_OPT_TELV(0x3b, BSSGP_PDU_TYPE, DE_BSSGP_FEATURE_BITMAP , NULL);
	/* Bucket_Full Ratio Bucket_Full Ratio/11.3.46 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_BUCKET_FULL_RATIO, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_FULL_RATIO , NULL);
	/* PFC flow control parameters PFC flow control parameters/11.3.68 M TLV */
	ELEM_MAND_TELV(0x52, BSSGP_PDU_TYPE, DE_BSSGP_PFC_FLOW_CTRL , NULL);
	/* Flow Control Granularity (note) Flow Control Granularity/11.3.102 O TLV 3 */
	ELEM_OPT_TELV(0x7e, BSSGP_PDU_TYPE, DE_BSSGP_FLOW_CONTROL_GRAN , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.25	FLOW-CONTROL-PFC-ACK
 */
static void
bssgp_flow_cntrl_pfc_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at the BSS that the SGSN has received the FLOW-CONTROL-PFC
	 * PDU indicated by the TLLI and the Tag.
	 */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.26	DELETE-BSS-PFC-REQ
 */
static void
bssgp_delete_bss_pfc_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to inform the SGSN that the BSS Packet Flow Context cannot be supported anymore */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.27	PS-HANDOVER-REQUIRED
 */
static void
bssgp_ps_ho_required(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU initiates the allocation of resources in the target system for an MS. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);
	/* Source Cell Identifier Cell Identifier/11.3.9 M TLV 10 */
	ELEM_MAND_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Source");
	/* Target Cell Identifier (note 2) Cell Identifier/11.3.9 C TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Target");
	/* Source BSS to Target BSS Transparent Container (note 1)
	 * Source BSS to Target BSS Transparent Container/11.3.79 C TLV 10-?
	 */
	ELEM_OPT_TELV(0x64,BSSGP_PDU_TYPE, DE_BSSGP_SOURCE_BSS_TO_TARGET_BSS_TRANSP_CONT, NULL);
	/* Target RNC Identifier (note 2) (note 3) RNC Identifier/11.3.87 C TLV 10 */
	ELEM_OPT_TELV(0x6c,BSSGP_PDU_TYPE, BE_BSSGP_RNC_ID, " - Target");
	/* Source to Target Transparent Container (note 1)
	 * Source to Target Transparent Container/11.3.85 C TLV 3-?
	 */
	ELEM_OPT_TELV(0x6a,BSSGP_PDU_TYPE, DE_BSSGP_SRC_TO_TRG_TRANSP_CONT, NULL);
	/* Active PFCs List Active PFCs List/11.3.95c M TLV 3-? */
	ELEM_OPT_TELV(0x77,BSSGP_PDU_TYPE, DE_BSSGP_ACTIVE_PFCS_LIST, NULL);
	/* Target eNB identifier (note 2) (note 3) eNB Identifier/11.3.103 C TLV 3-n */
	ELEM_OPT_TELV(0x7f,BSSGP_PDU_TYPE, DE_BSSGP_ENB_ID, " - Target");
	/* Reliable Inter RAT Handover Info (note 4)
	 * Reliable Inter RAT Handover Info/11.3.107 C TLV 3
	 */
	ELEM_OPT_TELV(0x83,BSSGP_PDU_TYPE, DE_BSSGP_RELIABLE_INTER_RAT_HO_INF, NULL);
	/* CSG Identifier (note 5) CSG Identifier/11.3.109 C TLV 7 */
	ELEM_OPT_TELV(0x85,BSSGP_PDU_TYPE, DE_BSSGP_CSG_ID, NULL);
	/* TAC (note 6) Tracking Area Code/11.3.110 C TLV 5 */
	ELEM_OPT_TELV(0x86, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.28	PS-HANDOVER-REQUIRED-ACK
 */
static void
bssgp_ps_ho_required_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that resources have been allocated in the target system and
	 * that the BSS may initiate the channel change attempt for the corresponding MS.
	 */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* List of set-up PFCs List of set-up PFCs/11.3.83 M TLV 3-?S */
	ELEM_MAND_TELV(0x68,BSSGP_PDU_TYPE, DE_BSSGP_LIST_OF_SETUP_PFCS, NULL);
	/* Target BSS to Source BSS Transparent Container (note)
	 * Target BSS to Source BSS Transparent Container/11.3.80 C TLV 3-?
	 */
	ELEM_MAND_TELV(0x65,BSSGP_PDU_TYPE, DE_BSSGP_TARGET_BSS_TO_SOURCE_BSS_TRANSP_CONT, NULL);
	/* Target to Source Transparent Container (note)
	 * Target to Source Transparent Container/11.3.86 C TLV 3-?
	 */
	ELEM_MAND_TELV(0x6b,BSSGP_PDU_TYPE, DE_BSSGP_TRG_TO_SRC_TRANSP_CONT, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.29	PS-HANDOVER-REQUIRED-NACK
 */
static void
bssgp_ps_ho_required_nack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the source BSS about failed resource allocation in the target system. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.30	PS-HANDOVER-REQUEST
 */
static void
bssgp_ps_ho_request(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU initiates the allocation of resources for one or more PFCs in the target BSS for an MS. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* IMSI IMSI/11.3.14 M TLV 5-10 */
	ELEM_MAND_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);
	/* Source Cell Identifier (note 1) Cell Identifier/11.3.9 C TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Source");
	/* Source RNC Identifier (note 1) RNC Identifier/11.3.87 C TLV 10 */
	ELEM_OPT_TELV(0x6c,BSSGP_PDU_TYPE, BE_BSSGP_RNC_ID, " - Source");
	/* Target Cell Identifier Cell Identifier/11.3.9 M TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Target");
	/* Source BSS to Target BSS Transparent Container Source BSS to Target BSS Transparent Container/11.3.79 M TLV 7-? */
	ELEM_OPT_TELV(0x64,BSSGP_PDU_TYPE, DE_BSSGP_SOURCE_BSS_TO_TARGET_BSS_TRANSP_CONT, NULL);
	/* PFCs to be set-up list PFCs to be set-up list/11.3.82 M TLV 22-? */
	ELEM_OPT_TELV(0x67,BSSGP_PDU_TYPE, DE_BSSGP_PFCS_TO_BE_SET_UP_LIST, NULL);
	/* NAS container for PS Handover NAS container for PS Handover/11.3.81 O TLV 3-? */
	ELEM_OPT_TELV(0x66,GSM_A_PDU_TYPE_COMMON, DE_NAS_CONT_FOR_PS_HO, NULL);
	/* Service UTRAN CCO Service UTRAN CCO/11.3.47 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_SERVICE_UTRAN_CCO, BSSGP_PDU_TYPE, DE_BSSGP_SERV_UTRAN_CCO, NULL);
	/* Subscriber Profile ID for RAT/Frequency priority (note 2) Subscriber Profile ID for RAT/Frequency priority/11.3.105 O TLV 3 */
	ELEM_OPT_TELV(0x81, BSSGP_PDU_TYPE, DE_BSSGP_SUB_PROF_ID_F_RAT_FRQ_PRIO, NULL);
	/* Reliable Inter RAT Handover Info (note 3) Reliable Inter RAT Handover Info/11.3.107 C TLV 3 */
	ELEM_OPT_TELV(0x83,BSSGP_PDU_TYPE, DE_BSSGP_RELIABLE_INTER_RAT_HO_INF, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.31	PS-HANDOVER-REQUEST-ACK
 */
static void
bssgp_ps_ho_request_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU acknowledges the successful allocation of resources in the target BSS. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* List of set-up PFCs List of set-up PFCs/11.3.83 M TLV 3-? */
	ELEM_MAND_TELV(0x68,BSSGP_PDU_TYPE, DE_BSSGP_LIST_OF_SETUP_PFCS, NULL);
	/* Target BSS to Source BSS Transparent Container Target BSS to Source BSS Transparent Container/11.3.80 M TLV 3-? */
	ELEM_MAND_TELV(0x65,BSSGP_PDU_TYPE, DE_BSSGP_TARGET_BSS_TO_SOURCE_BSS_TRANSP_CONT, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.32	PS-HANDOVER-REQUEST-NACK
 */
static void
bssgp_ps_ho_request_nack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the SGSN about failed resource allocation in the target BSS. */
	/* BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.33	PS-HANDOVER-COMPLETE
 */
static void
bssgp_ps_ho_complete(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the SGSN about successful channel change for an MS. */
	/* BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* IMSI IMSI/11.3.14 M TLV 5-10 */
	ELEM_MAND_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* Target Cell Identifier (note 1) Cell Identifier/11.3.9 O TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Target");
	/* Request for Inter RAT Handover Info (note 2) Request for Inter RAT Handover Info/11.3.106 C TLV 3 */
	ELEM_OPT_TELV(0x82, BSSGP_PDU_TYPE, DE_BSSGP_REQ_FOR_INTER_RAT_HO_INFO , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.4.34	PS-HANDOVER-CANCEL
 */
static void
bssgp_ps_ho_cancel(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU cancels the handover for an MS. */
	/* BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_IN_ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);
	/* Source Cell Identifier Cell Identifier/11.3.9 M TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Source");
	/* Target Cell Identifier (note 1) Cell Identifier/11.3.9 O TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Target");
	/* Target RNC Identifier (note 1) (note 2) RNC Identifier/11.3.87 C TLV 10 */
	ELEM_OPT_TELV(0x6c,BSSGP_PDU_TYPE, BE_BSSGP_RNC_ID, " - Target");
	/* Target eNB Identifier (note 1) (note 2) eNB Identifier/11.3.103 C TLV 3-n */
	ELEM_OPT_TELV(0x7f,BSSGP_PDU_TYPE, DE_BSSGP_ENB_ID, " - Target");

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.4.35	PS-HANDOVER-COMPLETE-ACK
 */
static void
bssgp_ps_ho_complete_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU provides to the BSS the Inter RAT Handover Info IE or
	 * E-UTRAN Inter RAT Handover Info IE or both. It is sent only if
	 * requested by the BSS and it shall contain at least one of the
	 * inter-RAT capabilities.
	 */

	/* SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Inter RAT Handover Info Inter RAT Handover Info/11.3.94 C (note 1) TLV 3-? */
	ELEM_OPT_TELV(0x73, BSSGP_PDU_TYPE, DE_BSSGP_INTER_RAT_HO_INFO, NULL);
	/* E-UTRAN Inter RAT Handover Info E-UTRAN Inter RAT Handover Info/11.3.104 C (note 1) TLV 3-? */
	ELEM_OPT_TELV(0x80, BSSGP_PDU_TYPE, DE_BSSGP_E_UTRAN_INTER_RAT_HO_INFO, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.5	PDU functional definitions and contents at LCS SAP
 * 10.5.1	PERFORM-LOCATION-REQUEST
 */
static void
bssgp_perform_loc_request(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the SGSN about failed resource allocation in the target BSS. */
	/* BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* IMSI IMSI/11.3.14 M TLV 5-10 */
	ELEM_MAND_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* DRX Parameters (note 1) DRX Parameters/11.3.11 O TLV 4 */
	ELEM_OPT_TELV(0x86, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, NULL);
	/* BVCI (PCU-PTP) BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - (PCU-PTP)");
	/* NSEI (PCU-PTP) NSEI/11.3.48 M TLV 4-? */
	ELEM_OPT_TELV(0x3e, GSM_A_PDU_TYPE_RR, DE_BSSGP_NSEI , " - (PCU-PTP)");
	/* Location Type Location Type/11.3.53 M TLV 3-? */
	ELEM_OPT_TELV(0x7c, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_LOC_TYPE, NULL);
	/* Cell Identifier Cell Identifier/11.3.9 M TLV 10 */
	ELEM_OPT_TELV(BSSGP_IEI_CELL_IDENTIFIER, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , NULL);
	/* LCS Capability (note 2) LCS Capability/11.3.59 O TLV 3-? */
	ELEM_OPT_TELV( BSSGP_IEI_LCS_CAPABILITY , GSM_A_PDU_TYPE_GM, DE_PS_LCS_CAP , NULL);
	/* LCS Priority LCS Priority/11.3.57 O TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_LCS_PRIORITY, GSM_A_PDU_TYPE_BSSMAP, BE_LCS_PRIO, NULL);
	/* LCS QoS LCS QoS/11.3.50 O TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_LCS_QOS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCSQOS, NULL);
	/* LCS Client Type (note 3) LCS Client Type/11.3.51 C TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_LCS_CLIENT_TYPE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CLIENT_TYPE, NULL);
	/* Requested GPS Assistance Data (note 4) Requested GPS Assistance Data/11.3.52 O TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_REQ_GPS_ASSIST_D, NULL);
	/* IMEI (note 5) IMEI/11.3.91 O TLV 10 */
	ELEM_OPT_TELV(0x70,GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);
	/* GANSS Location Type GANSS Location Type / 11.3.100 C TLV 3 */
	ELEM_OPT_TELV(0x7c, GSM_A_PDU_TYPE_BSSMAP, BE_GANSS_LOC_TYP, NULL);
	/* Requested GANSS Assistance Data (note 6) Requested GANSS Assistance Data/11.3.99 O TLV 3-? */
	ELEM_OPT_TLV(0x7b, GSM_A_PDU_TYPE_BSSMAP, BE_GANSS_ASS_DTA, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.5.2	PERFORM-LOCATION-RESPONSE
 */
static void
bssgp_perform_loc_response(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/*This PDU allows the BSS to respond to the SGSN after the completion of the location procedure. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* BVCI (PCU-PTP) BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - (PCU-PTP)");
	/* Location Estimate (note 1) Location Estimate/11.3.54 C TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_LOCATION_ESTIMATE, GSM_A_PDU_TYPE_BSSMAP, BE_LOC_EST, NULL);
	/* Positioning Data Positioning Data/11.3.55 O TLV 3-? */
	ELEM_OPT_TELV(0x7d, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_POS_DATA, NULL);
	/* Deciphering Keys (note 2) Deciphering Keys/11.3.56 C TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_DECIPHERING_KEYS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_DECIPH_KEYS, NULL);
	/* LCS Cause (note 3) LCS Cause/11.3.58 O TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_LCS_CAUSE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAUSE, NULL);
	/* Velocity Data Velocity Data/11.3.96 O TLV 3-? */
	ELEM_MAND_TELV(0x78, BSSGP_PDU_TYPE, DE_BSSGP_VELOCITY_DATA , NULL);
	/* GANSS Positioning Data GANSS Positioning Data /11.3.101 O TLV 3-? */
	ELEM_OPT_TELV(0x7d, GSM_A_PDU_TYPE_BSSMAP, BE_GANSS_POS_DTA, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.5.3	PERFORM-LOCATION-ABORT
 */
static void
bssgp_perform_loc_response_abort(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/*This PDU allows the SGSN to request the BSS to ABORT the LCS procedure */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* BVCI (PCU-PTP) BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - (PCU-PTP)");
	/* LCS Cause LCS Cause/11.3.58 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_LCS_CAUSE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.5.4	POSITION-COMMAND
 */
static void
bssgp_pos_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to request the SGSN to perform the position command procedure. */
	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* BVCI (PCU-PTP) BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - (PCU-PTP)");
	/* RRLP Flags RRLP Flags/11.3.60 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_RRLP_FLAGS, BSSGP_PDU_TYPE, DE_BSSGP_RRLP_FLAGS , NULL);
	/* RRLP APDU RRLP APDU/11.3.49 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RRLP_APDU, BSSGP_PDU_TYPE, DE_BSSGP_RRLP_APDU , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.5.5	POSITION-RESPONSE
 */
static void
bssgp_pos_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the SGSN to respond to the position command request procedure. */
	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* BVCI (PCU-PTP) BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - (PCU-PTP)");
	/* RRLP Flags a) RRLP Flags/11.3.60 C TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_RRLP_FLAGS, BSSGP_PDU_TYPE, DE_BSSGP_RRLP_FLAGS , NULL);
	/* RRLP APDU a) RRLP APDU/11.3.49 C TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_RRLP_APDU, BSSGP_PDU_TYPE, DE_BSSGP_RRLP_APDU , NULL);
	/* LCS Cause b) LCS Cause/11.3.58 O TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_LCS_CAUSE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.6	PDU functional definitions and contents at RIM SAP
 * 10.6.1	RAN-INFORMATION-REQUEST
 */
static void
bssgp_ran_inf_request(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* The RAN-INFORMATION-REQUEST PDU allows a controlling BSS to request information from another BSS. */
	/* Direction: BSS to SGSN - SGSN to BSS */

	/* Destination Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Destination Cell Identifier");
	/* Source Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Source Cell Identifier");
	/* RIM Container RAN-INFORMATION-REQUEST RIM Container/11.3.62a.1 M TLV 3-? */
	ELEM_OPT_TELV(BSSGP_IEI_RAN_INF_REQUEST_RIM_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_INF_REQUEST_RIM_CONT, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.6.2	RAN-INFORMATION
 */
static void
bssgp_ran_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* The RAN-INFORMATION PDU allows a serving BSS to send information to a controlling BSS. */
	/* Direction: BSS to SGSN SGSN to BSS */

	/* Destination Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Destination Cell Identifier");
	/* Source Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Source Cell Identifier");
	/* RIM Container RAN-INFORMATION RIM Container/11.3.62a.2 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RAN_INF_RIM_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_INF_RIM_CONT , " - Source Cell Identifier");


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.6.3	RAN-INFORMATION-ACK
 */
static void
bssgp_ran_inf_request_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* The RAN-INFORMATION-ACK PDU allows a controlling BSS to acknowledge the reception of a RANINFORMATION
     * PDU and a serving BSS to acknowledge the reception of a RAN-INFORMATION-APPLICATIONERROR PDU.
	 */

	/* Direction: BSS to SGSN SGSN to BSS */

	/* Destination Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Destination Cell Identifier");
	/* Source Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Source Cell Identifier");
	/* RIM Container RAN-INFORMATION-ACK RIM Container/11.3.62a.3 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RAN_INF_ACK_RIM_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_INFORMATION_ACK_RIM_CONT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.6.4	RAN-INFORMATION-ERROR
 */

static void
bssgp_ran_inf_err(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* The RAN-INFORMATION-ERROR PDU allows a BSS to send an error PDU back to an originating BSS as a response
	 * to a RAN-INFORMATION, a RAN-INFORMATION-REQUEST, a RAN-INFORMATION-ACK or a RANINFORMATION-APPLICATION-ERROR PDU.
	 */

	/* Direction: BSS to SGSN SGSN to BSS */

	/* Destination Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Destination Cell Identifier");
	/* Source Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Source Cell Identifier");
	/* RIM Container RAN-INFORMATION-ERROR RIM Container/11.3.62a.4 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RAN_INF_ERROR_RIM_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_INFORMATION_ERROR_RIM_CONT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.6.5	RAN-INFORMATION-APPLICATION-ERROR
 */
static void
bssgp_ran_inf_app_err(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* The RAN-INFORMATION-APPLICATION-ERROR PDU allows a controlling BSS to inform the serving BSS about
	 * erroneous application information in a previously received RAN-INFORMATION PDU.
	 */

	/* Direction: BSS to SGSN SGSN to BSS */

	/* Destination Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Destination Cell Identifier");
	/* Source Cell Identifier RIM Routing Information/11.3.70 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RIM_ROUTING_INFORMATION, BSSGP_PDU_TYPE, DE_BSSGP_RIM_ROUTING_INF , " - Source Cell Identifier");
	/* RIM Container RAN-INFORMATION-APPLICATION ERROR RIM Container/11.3.62a.5 M TLV 3-? */
	ELEM_MAND_TELV(BSSGP_IEI_RAN_INF_APP_ERROR_RIM_CONTAINER, BSSGP_PDU_TYPE, DE_BSSGP_RAN_INF_APP_ERROR_RIM_CONT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.7	PDU functional definitions and contents at MBMS SAP
 * 10.7.1	MBMS-SESSION-START-REQUEST
 */
static void
bssgp_mbms_session_start_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows a SGSN to request BSS to start an MBMS session. */

	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TMGI TMGI/11.3.77 M TLV 3-8  */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);
	/* MBMS Service Area Identity List MBMS Service Area Identity List/11.3.73 M TLV 4-? */
	ELEM_MAND_TELV(0x5f, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SAI_LIST, NULL);
	/* MBMS Routing Area List MBMS Routing Area List/11.3.75 M TLV 3-? */
	ELEM_MAND_TELV(0x61, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_RA_LIST, NULL);
	/* MBMS Session Duration MBMS Session Duration/11.3.72 M TLV 3-? */
	ELEM_MAND_TELV(0x5e, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_DUR, NULL);
	/* MBMS Session Information MBMS Session Information/11.3.76 M TLV 3 */
	ELEM_MAND_TELV(0x62, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_INF, NULL);
	/* Time to MBMS Data Transfer Time to MBMS Data Transfer/11.3.92 M TLV 3 */
	ELEM_MAND_TELV(0x71, BSSGP_PDU_TYPE, DE_BSSGP_TIME_TO_MBMS_DATA_TRAN, NULL);
	/* Allocation/Retention Priority Priority/11.3.27 O TLV 3 */
	ELEM_OPT_TELV(0x0b, GSM_A_PDU_TYPE_BSSMAP, BE_PRIO, NULL);
	/* MBMS Session Repetition Number MBMS Session Repetition Number/11.3.93 O TLV 3 */
	ELEM_MAND_TELV(0x72, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_REP_NO, NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.7.2	MBMS-SESSION-START-RESPONSE
 */
static void
bssgp_mbms_session_start_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows a BSS to acknowledge to SGSN that it will start an MBMS session or to indicate to SGSN why the
	 * MBMS Service Context cannot be created or is released by the BSS.
	 */

	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* MBMS Response MBMS Response/ 11.3.74 M TLV 3 */
	ELEM_OPT_TELV(0x60, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_RESPONSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * 10.7.3	MBMS-SESSION-STOP-REQUEST
 */
static void
bssgp_mbms_session_stop_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows a SGSN to request BSS to stop an MBMS session. */

	/* Direction: SGSN to BSS */
	pinfo->link_dir = P2P_DIR_DL;

	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* MBMS Stop Cause MBMS Stop Cause/11.3.78 M TLV 3 */
	ELEM_OPT_TELV(0x63, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_STOP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.7.4	MBMS-SESSION-STOP-RESPONSE
 */
static void
bssgp_mbms_session_stop_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows a BSS to acknowledge to SGSN that it will stop an MBMS session. */

	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* MBMS Response MBMS Response/ 11.3.74 M TLV 3 */
	ELEM_OPT_TELV(0x60, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_RESPONSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.7.5	MBMS-SESSION-UPDATE-REQUEST
 */
static void
bssgp_mbms_session_update_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows an SGSN to request BSS to update the MBMS service area list
	 * of an ongoing MBMS broadcast service session.
	 */

	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);
	/* MBMS Service Area Identity List MBMS Service Area Identity List/11.3.73 M TLV 4-? */
	ELEM_MAND_TELV(0x5f, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SAI_LIST, NULL);
	/* MBMS Routing Area List MBMS Routing Area List/11.3.75 M TLV 3-? */
	ELEM_MAND_TELV(0x61, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_RA_LIST, NULL);
	/* MBMS Session Duration MBMS Session Duration/11.3.72 M TLV 3-? */
	ELEM_MAND_TELV(0x5e, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_DUR, NULL);
	/* MBMS Session Information MBMS Session Information/11.3.76 M TLV 3 */
	ELEM_MAND_TELV(0x62, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_INF, NULL);
	/* Time to MBMS Data Transfer Time to MBMS Data Transfer/11.3.92 M TLV 3 */
	ELEM_MAND_TELV(0x71, BSSGP_PDU_TYPE, DE_BSSGP_TIME_TO_MBMS_DATA_TRAN, NULL);
	/* Allocation/Retention Priority Priority/11.3.27 O TLV 3 */
	ELEM_OPT_TELV(0x0b, GSM_A_PDU_TYPE_BSSMAP, BE_PRIO, NULL);
	/* MBMS Session Repetition Number MBMS Session Repetition Number/11.3.93 O TLV 3 */
	ELEM_MAND_TELV(0x72, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_REP_NO, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}
/*
 * 10.7.6	MBMS-SESSION-UPDATE-RESPONSE
 */
static void
bssgp_mbms_session_uptate_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows a BSS to acknowledge to SGSN that it will update the MBMS service area list of an ongoing MBMS
	 * broadcast service session or to indicate to SGSN why the MBMS Service Context cannot be created or is released by the BSS.
	 */

	/* Direction: BSS to SGSN */
	pinfo->link_dir = P2P_DIR_UL;

	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* MBMS Response MBMS Response/ 11.3.74 M TLV 3 */
	ELEM_OPT_TELV(0x60, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_RESPONSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

static const value_string bssgp_msg_strings[] = {
/* 0x00 */  { BSSGP_PDU_DL_UNITDATA,                  "DL-UNITDATA" },					/* 10.2.1 DL-UNITDATA */
/* 0x01 */  { BSSGP_PDU_UL_UNITDATA,                  "UL-UNITDATA" },					/* 10.2.2 UL-UNITDATA */
/* 0x02 */  { BSSGP_PDU_RA_CAPABILITY,                "RA-CAPABILITY" },				/* 10.2.3 RA-CAPABILITY */
/* NOTE 1: This value was allocated in an earlier version of the protocol and shall	not be used */
/* 0x03 */  { BSSGP_PDU_PTM_UNITDATA,                 "Reserved" },						/* 10.2.4 (void) */
/* 0x04 */  { BSSGP_PDU_DL_MBMS_UNITDATA,             "DL-MBMS-UNITDATA" },				/* 10.2.5 DL-MBMS-UNITDATA */
/* 0x05 */  { BSSGP_PDU_UL_MBMS_UNITDATA,             "UL-MBMS-UNITDATA" },				/* 10.2.6 UL-MBMS-UNITDATA */
/* 0x06 */  { BSSGP_PDU_PAGING_PS,                    "PAGING-PS" },					/* 10.3.1 PAGING PS */
/* 0x07 */  { BSSGP_PDU_PAGING_CS,                    "PAGING-CS" },					/* 10.3.2 PAGING CS */
/* 0x08 */  { BSSGP_PDU_RA_CAPABILITY_UPDATE,         "RA-CAPABILITY-UPDATE" },			/* 10.3.3 RA-CAPABILITY-UPDATE */
/* 0x09 */  { BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK,     "RA-CAPABILITY-UPDATE-ACK" },		/* 10.3.4 RA-CAPABILITY-UPDATE-ACK */
/* 0x0a */  { BSSGP_PDU_RADIO_STATUS,                 "RADIO-STATUS" },					/* 10.3.5 RADIO-STATUS */
/* 0x0b */  { BSSGP_PDU_SUSPEND,                      "SUSPEND" },						/* 10.3.6 SUSPEND */
/* 0x0c */  { BSSGP_PDU_SUSPEND_ACK,                  "SUSPEND-ACK" },					/* 10.3.7 SUSPEND-ACK */
/* 0x0d */  { BSSGP_PDU_SUSPEND_NACK,                 "SUSPEND-NACK" },					/* 10.3.8 SUSPEND-NACK */
/* 0x0e */  { BSSGP_PDU_RESUME,                       "RESUME" },						/* 10.3.9 RESUME */
/* 0x0f */  { BSSGP_PDU_RESUME_ACK,                   "RESUME-ACK" },					/* 10.3.10 RESUME-ACK */
/* 0x10 */  { BSSGP_PDU_RESUME_NACK,                  "RESUME-NACK" },					/* 10.3.11 RESUME-NACK */
  /* 0x11 to 0x1f Reserved */
/* 0x11 */  { BSSGP_PDU_RESERVED_0X11,                 "Reserved" },					/*  */
/* 0x12 */  { BSSGP_PDU_RESERVED_0X12,                 "Reserved" },					/*  */
/* 0x13 */  { BSSGP_PDU_RESERVED_0X13,                 "Reserved" },					/*  */
/* 0x14 */  { BSSGP_PDU_RESERVED_0X14,                 "Reserved" },					/*  */
/* 0x15 */  { BSSGP_PDU_RESERVED_0X15,                 "Reserved" },					/*  */
/* 0x16 */  { BSSGP_PDU_RESERVED_0X16,                 "Reserved" },					/*  */
/* 0x17 */  { BSSGP_PDU_RESERVED_0X17,                 "Reserved" },					/*  */
/* 0x18 */  { BSSGP_PDU_RESERVED_0X18,                 "Reserved" },					/*  */
/* 0x19 */  { BSSGP_PDU_RESERVED_0X19,                 "Reserved" },					/*  */
/* 0x1a */  { BSSGP_PDU_RESERVED_0X1A,                 "Reserved" },					/*  */
/* 0x1b */  { BSSGP_PDU_RESERVED_0X1B,                 "Reserved" },					/*  */
/* 0x1c */  { BSSGP_PDU_RESERVED_0X1C,                 "Reserved" },					/*  */
/* 0x1d */  { BSSGP_PDU_RESERVED_0X1D,                 "Reserved" },					/*  */
/* 0x1e */  { BSSGP_PDU_RESERVED_0X1E,                 "Reserved" },					/*  */
/* 0x1f */  { BSSGP_PDU_RESERVED_0X1F,                 "Reserved" },					/*  */

/* 0x20 */  { BSSGP_PDU_BVC_BLOCK,                    "BVC-BLOCK" },					/* 10.4.8 BVC-BLOCK */
/* 0x21 */  { BSSGP_PDU_BVC_BLOCK_ACK,                "BVC-BLOCK-ACK" },				/* 10.4.9 BVC-BLOCK-ACK */
/* 0x22 */  { BSSGP_PDU_BVC_RESET,                    "BVC-RESET" },					/* 10.4.12 BVC-RESET */
/* 0x23 */  { BSSGP_PDU_BVC_RESET_ACK,                "BVC-RESET-ACK" },				/* 10.4.13 BVC-RESET-ACK */
/* 0x24 */  { BSSGP_PDU_BVC_UNBLOCK,                  "UNBLOCK" },						/* 10.4.10 BVC-UNBLOCK */
/* 0x25 */  { BSSGP_PDU_BVC_UNBLOCK_ACK,              "UNBLOCK-ACK" },					/* 10.4.11 BVC-UNBLOCK-ACK */
/* 0x26 */  { BSSGP_PDU_FLOW_CONTROL_BVC,             "FLOW-CONTROL-BVC" },				/* 10.4.4 FLOW-CONTROL-BVC */
/* 0x27 */  { BSSGP_PDU_FLOW_CONTROL_BVC_ACK,         "FLOW-CONTROL-BVC-ACK" },			/* 10.4.5 FLOW-CONTROL-BVC-ACK */
/* 0x28 */  { BSSGP_PDU_FLOW_CONTROL_MS,              "FLOW-CONTROL-MS" },				/* 10.4.6 FLOW-CONTROL-MS */
/* 0x29 */  { BSSGP_PDU_FLOW_CONTROL_MS_ACK,          "FLOW-CONTROL-MS-ACK" },			/* 10.4.7 FLOW-CONTROL-MS-ACK */
/* 0x2a */  { BSSGP_PDU_FLUSH_LL,                     "FLUSH-LL" },						/* 10.4.1 FLUSH-LL */
/* 0x2b */  { BSSGP_PDU_FLUSH_LL_ACK,                 "FLUSH_LL_ACK" },					/* 10.4.2 FLUSH-LL-ACK */
/* 0x2c */  { BSSGP_PDU_LLC_DISCARDED,                "LLC-DISCARDED" },				/* 10.4.3 LLC-DISCARDED */
/* 0x2d */  { BSSGP_PDU_FLOW_CONTROL_PFC,             "FLOW-CONTROL-PFC" },				/* 10.4.24 FLOW-CONTROL-PFC */
/* 0x2e */  { BSSGP_PDU_FLOW_CONTROL_PFC_ACK,         "FLOW-CONTROL-PFC-ACK" },			/* 10.4.25 FLOW-CONTROL-PFC-ACK */
  /* 0x2f to 0x3f Reserved */
/* 0x2f */  { BSSGP_PDU_RESERVED_0X2F,                 "Reserved" },					/*  */
/* 0x30 */  { BSSGP_PDU_RESERVED_0X30,                 "Reserved" },					/*  */
/* 0x31 */  { BSSGP_PDU_RESERVED_0X31,                 "Reserved" },					/*  */
/* 0x32 */  { BSSGP_PDU_RESERVED_0X32,                 "Reserved" },					/*  */
/* 0x33 */  { BSSGP_PDU_RESERVED_0X33,                 "Reserved" },					/*  */
/* 0x34 */  { BSSGP_PDU_RESERVED_0X34,                 "Reserved" },					/*  */
/* 0x35 */  { BSSGP_PDU_RESERVED_0X35,                 "Reserved" },					/*  */
/* 0x36 */  { BSSGP_PDU_RESERVED_0X36,                 "Reserved" },					/*  */
/* 0x37 */  { BSSGP_PDU_RESERVED_0X37,                 "Reserved" },					/*  */
/* 0x38 */  { BSSGP_PDU_RESERVED_0X38,                 "Reserved" },					/*  */
/* 0x39 */  { BSSGP_PDU_RESERVED_0X39,                 "Reserved" },					/*  */
/* 0x3a */  { BSSGP_PDU_RESERVED_0X3A,                 "Reserved" },					/*  */
/* 0x3b */  { BSSGP_PDU_RESERVED_0X3B,                 "Reserved" },					/*  */
/* 0x3c */  { BSSGP_PDU_RESERVED_0X3C,                 "Reserved" },					/*  */
/* 0x3d */  { BSSGP_PDU_RESERVED_0X3D,                 "Reserved" },					/*  */
/* 0x3e */  { BSSGP_PDU_RESERVED_0X3E,                 "Reserved" },					/*  */
/* 0x3f */  { BSSGP_PDU_RESERVED_0X3F,                 "Reserved" },					/*  */

/* 0x40 */  { BSSGP_PDU_SGSN_INVOKE_TRACE,            "SGSN-INVOKE-TRACE" },			/* 10.4.15 SGSN-INVOKE-TRACE */
/* 0x41 */  { BSSGP_PDU_STATUS,                       "STATUS" },						/* 10.4.14 STATUS */
  /* 0x42 to 0x4f Reserved */
/* 0x42 */  { BSSGP_PDU_RESERVED_0X42,                 "Reserved" },					/*  */
/* 0x43 */  { BSSGP_PDU_RESERVED_0X43,                 "Reserved" },					/*  */
/* 0x44 */  { BSSGP_PDU_RESERVED_0X44,                 "Reserved" },					/*  */
/* 0x45 */  { BSSGP_PDU_RESERVED_0X45,                 "Reserved" },					/*  */
/* 0x46 */  { BSSGP_PDU_RESERVED_0X46,                 "Reserved" },					/*  */
/* 0x47 */  { BSSGP_PDU_RESERVED_0X47,                 "Reserved" },					/*  */
/* 0x48 */  { BSSGP_PDU_RESERVED_0X48,                 "Reserved" },					/*  */
/* 0x49 */  { BSSGP_PDU_RESERVED_0X49,                 "Reserved" },					/*  */
/* 0x4a */  { BSSGP_PDU_RESERVED_0X4A,                 "Reserved" },					/*  */
/* 0x4b */  { BSSGP_PDU_RESERVED_0X4B,                 "Reserved" },					/*  */
/* 0x4c */  { BSSGP_PDU_RESERVED_0X4C,                 "Reserved" },					/*  */
/* 0x4d */  { BSSGP_PDU_RESERVED_0X4D,                 "Reserved" },					/*  */
/* 0x4e */  { BSSGP_PDU_RESERVED_0X4E,                 "Reserved" },					/*  */
/* 0x4f */  { BSSGP_PDU_RESERVED_0X4F,                 "Reserved" },					/*  */
/* 0x50 */  { BSSGP_PDU_DOWNLOAD_BSS_PFC,              "DOWNLOAD-BSS-PFC" },			/* 10.4.16	DOWNLOAD-BSS-PFC */
/* 0x51 */  { BSSGP_PDU_CREATE_BSS_PFC,                "CREATE-BSS-PFC" },				/* 10.4.17 CREATE-BSS-PFC */
/* 0x52 */  { BSSGP_PDU_CREATE_BSS_PFC_ACK,            "CREATE-BSS-PFC-ACK" },			/* 10.4.18 CREATE-BSS-PFC-ACK */
/* 0x53 */  { BSSGP_PDU_CREATE_BSS_PFC_NACK,           "CREATE-BSS-PFC-NACK" },			/* 10.4.19 CREATE-BSS-PFC-NACK */
/* 0x54 */  { BSSGP_PDU_MODIFY_BSS_PFC,                "MODIFY-BSS-PFC" },				/* 10.4.20 MODIFY-BSS-PFC */
/* 0x55 */  { BSSGP_PDU_MODIFY_BSS_PFC_ACK,            "MODIFY-BSS-PFC-ACK" },			/* 10.4.21 MODIFY-BSS-PFC-ACK */
/* 0x56 */  { BSSGP_PDU_DELETE_BSS_PFC,                "DELETE-BSS-PFC" },				/* 10.4.22 DELETE-BSS-PFC */
/* 0x57 */  { BSSGP_PDU_DELETE_BSS_PFC_ACK,            "DELETE-BSS-PFC-ACK" },			/* 10.4.23 DELETE-BSS-PFC-ACK */
/* 0x58 */  { BSSGP_PDU_DELETE_BSS_PFC_REQ,            "DELETE-BSS-PFC-REQ" },			/* 10.4.26 DELETE-BSS-PFC-REQ */
/* 0x59 */  { BSSGP_PDU_PS_HANDOVER_REQUIRED,          "PS-HANDOVER-REQUIRED" },		/* 10.4.27 PS-HANDOVER-REQUIRED */
/* 0x5a */  { BSSGP_PDU_PS_HANDOVER_REQUIRED_ACK,      "PS-HANDOVER-REQUIRED-ACK" },	/* 10.4.28 PS-HANDOVER-REQUIRED-ACK */
/* 0x5b */  { BSSGP_PDU_PS_HANDOVER_REQUIRED_NACK,     "PS-HANDOVER-REQUIRED-NACK" },	/* 10.4.29 PS-HANDOVER-REQUIRED-NACK */
/* 0x5c */  { BSSGP_PDU_PS_HANDOVER_REQUEST,           "PS-HANDOVER-REQUEST" },			/* 10.4.30 PS-HANDOVER-REQUEST */
/* 0x5d */  { BSSGP_PDU_PS_HANDOVER_REQUEST_ACK,       "PS-HANDOVER-REQUEST-ACK" },		/* 10.4.31 PS-HANDOVER-REQUEST-ACK */
/* 0x5e */  { BSSGP_PDU_PS_HANDOVER_REQUEST_NACK,      "PS-HANDOVER-REQUEST-NACK" },	/* 10.4.31 10.4.32 PS-HANDOVER-REQUEST-NACK */

/* 0x5f */  { BSSGP_PDU_RESERVED_0X5F,                 "Reserved" },					/*  */

/* 0x60 */  { BSSGP_PDU_PERFORM_LOCATION_REQUEST,     "PERFORM-LOCATION-REQUEST" },		/* 10.5.1 PERFORM-LOCATION-REQUEST */
/* 0x61 */  { BSSGP_PDU_PERFORM_LOCATION_RESPONSE,    "PERFORM-LOCATION-RESPONSE" },	/* 10.5.2 PERFORM-LOCATION-RESPONSE */
/* 0x62 */  { BSSGP_PDU_PERFORM_LOCATION_ABORT,       "PERFORM-LOCATION-ABORT" },		/* 10.5.3 PERFORM-LOCATION-ABORT */
/* 0x63 */  { BSSGP_PDU_POSITION_COMMAND,             "POSITION-COMMAND" },				/* 10.5.4 POSITION-COMMAND */
/* 0x64 */  { BSSGP_PDU_POSITION_RESPONSE,            "POSITION-RESPONSE" },			/* 10.5.5 POSITION-RESPONSE */

/* 0x65 */  { BSSGP_PDU_RESERVED_0X65,                 "Reserved" },					/*  */
/* 0x66 */  { BSSGP_PDU_RESERVED_0X66,                 "Reserved" },					/*  */
/* 0x67 */  { BSSGP_PDU_RESERVED_0X67,                 "Reserved" },					/*  */
/* 0x68 */  { BSSGP_PDU_RESERVED_0X68,                 "Reserved" },					/*  */
/* 0x69 */  { BSSGP_PDU_RESERVED_0X69,                 "Reserved" },					/*  */
/* 0x6a */  { BSSGP_PDU_RESERVED_0X6A,                 "Reserved" },					/*  */
/* 0x6b */  { BSSGP_PDU_RESERVED_0X6B,                 "Reserved" },					/*  */
/* 0x6b */  { BSSGP_PDU_RESERVED_0X6C,                 "Reserved" },					/*  */
/* 0x6d */  { BSSGP_PDU_RESERVED_0X6D,                 "Reserved" },					/*  */
/* 0x6e */  { BSSGP_PDU_RESERVED_0X6E,                 "Reserved" },					/*  */
/* 0x6f */  { BSSGP_PDU_RESERVED_0X6F,                 "Reserved" },					/*  */

/* 0x70 */  { BSSGP_PDU_RAN_INFORMATION,              "RAN-INFORMATION" },				/* 10.6.2 RAN-INFORMATION */
/* 0x71 */  { BSSGP_PDU_RAN_INFORMATION_REQUEST,      "RAN-INFORMATION-REQUEST" },		/* 10.6.1 RAN-INFORMATION-REQUEST */
/* 0x72 */  { BSSGP_PDU_RAN_INFORMATION_ACK,          "RAN-INFORMATION-ACK" },			/* 10.6.3 RAN-INFORMATION-ACK */
/* 0x73 */  { BSSGP_PDU_RAN_INFORMATION_ERROR,        "RAN-INFORMATION-ERROR" },		/* 10.6.4 RAN-INFORMATION-ERROR */
/* 0x74 */  { BSSGP_PDU_RAN_INFORMATION_APP_ERROR,    "RAN-INFORMATION-APPLICATION-ERROR" }, /* 10.6.5 RAN-INFORMATION-APPLICATION-ERROR */
/* 0x75 */  { BSSGP_PDU_RESERVED_0X75,                 "Reserved" },					/*  */
/* 0x76 */  { BSSGP_PDU_RESERVED_0X76,                 "Reserved" },					/*  */
/* 0x77 */  { BSSGP_PDU_RESERVED_0X77,                 "Reserved" },					/*  */
/* 0x78 */  { BSSGP_PDU_RESERVED_0X78,                 "Reserved" },					/*  */
/* 0x79 */  { BSSGP_PDU_RESERVED_0X79,                 "Reserved" },					/*  */
/* 0x7a */  { BSSGP_PDU_RESERVED_0X7A,                 "Reserved" },					/*  */
/* 0x7b */  { BSSGP_PDU_RESERVED_0X7B,                 "Reserved" },					/*  */
/* 0x7c */  { BSSGP_PDU_RESERVED_0X7C,                 "Reserved" },					/*  */
/* 0x7d */  { BSSGP_PDU_RESERVED_0X7D,                 "Reserved" },					/*  */
/* 0x7e */  { BSSGP_PDU_RESERVED_0X7E,                 "Reserved" },					/*  */
/* 0x7f */  { BSSGP_PDU_RESERVED_0X7F,                 "Reserved" },					/*  */
/* 0x80 */  { BSSGP_PDU_MBMS_SESSION_START_REQ,        "MBMS-SESSION-START-REQUEST" },	/* 10.7.1	MBMS-SESSION-START-REQUEST */
/* 0x81 */  { BSSGP_PDU_MBMS_SESSION_START_RESP,       "MBMS-SESSION-START-RESPONSE" }, /* 10.7.2	MBMS-SESSION-START-RESPONSE */
/* 0x82 */  { BSSGP_PDU_MBMS_SESSION_STOP_REQ,         "MBMS-SESSION-STOP-REQUEST" },	/* 10.7.3	MBMS-SESSION-STOP-REQUEST */
/* 0x83 */  { BSSGP_PDU_MBMS_SESSION_STOP_RESP,        "MBMS-SESSION-STOP-RESPONSE" },  /* 10.7.4	MBMS-SESSION-STOP-RESPONSE */
/* 0x84 */  { BSSGP_PDU_MBMS_SESSION_UPDATE_REQ,       "MBMS-SESSION-UPDATE-REQUEST" }, /* 10.7.5	MBMS-SESSION-UPDATE-REQUEST */
/* 0x85 */  { BSSGP_PDU_MBMS_SESSION_UPDATE_RESP,      "MBMS-SESSION-UPDATE-RESPONSE" },/* 10.7.6	MBMS-SESSION-UPDATE-RESPONSE */

/* 0x86 */  { BSSGP_PDU_RESERVED_0X86,                 "Reserved" },					/*  */
/* 0x87 */  { BSSGP_PDU_RESERVED_0X87,                 "Reserved" },					/*  */
/* 0x88 */  { BSSGP_PDU_RESERVED_0X88,                 "Reserved" },					/*  */
/* 0x89 */  { BSSGP_PDU_RESERVED_0X89,                 "Reserved" },					/*  */
/* 0x8a */  { BSSGP_PDU_RESERVED_0X8A,                 "Reserved" },					/*  */
/* 0x8b */  { BSSGP_PDU_RESERVED_0X8B,                 "Reserved" },					/*  */
/* 0x8c */  { BSSGP_PDU_RESERVED_0X8C,                 "Reserved" },					/*  */
/* 0x8d */  { BSSGP_PDU_RESERVED_0X8D,                 "Reserved" },					/*  */
/* 0x8e */  { BSSGP_PDU_RESERVED_0X8E,                 "Reserved" },					/*  */
/* 0x8f */  { BSSGP_PDU_RESERVED_0X8F,                 "Reserved" },					/*  */
/* 0x90 */  { BSSGP_PDU_RESERVED_0X90,                 "Reserved" },					/*  */

/* 0x91 */  {BSSGP_PDU_PS_HANDOVER_COMPLETE,           "PS-HANDOVER-COMPLETE" },        /* 10.4.33	PS-HANDOVER-COMPLETE */
/* 0x92 */  {BSSGP_PDU_PS_HANDOVER_CANCEL,             "PS-HANDOVER-CANCEL" },          /* 10.4.34	PS-HANDOVER-CANCEL */
/* 0x93 */  {BSSGP_PDU_PS_HANDOVER_COMPLETE_ACK,       "PS-HANDOVER-COMPLETE-ACK" },    /* 10.4.35	PS-HANDOVER-COMPLETE-ACK*/

	{ 0,	NULL }
};
static value_string_ext bssgp_msg_strings_ext = VALUE_STRING_EXT_INIT(bssgp_msg_strings);

#define	NUM_BSSGP_MSG (sizeof(bssgp_msg_strings)/sizeof(value_string))
static gint ett_bssgp_msg[NUM_BSSGP_MSG];
static void (*bssgp_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
/* 0x00 to 0x10 */
    bssgp_dl_unitdata,					/* 10.2.1 DL-UNITDATA */
    bssgp_ul_unitdata,					/* 10.2.2 UL-UNITDATA */
    bssgp_ra_cap,						/* 10.2.3 RA-CAPABILITY */
    NULL,								/* 10.2.4 (void) */
    bssgp_dl_mbms_unitdata,				/* 10.2.5 DL-MBMS-UNITDATA */
    bssgp_ul_mbms_unitdata,				/* 10.2.6 UL-MBMS-UNITDATA */
    bssgp_paging_ps,					/* 10.3.1 PAGING PS */
    bssgp_paging_cs,					/* 10.3.2 PAGING CS */
    bssgp_ra_cap_upd,					/* 10.3.3 RA-CAPABILITY-UPDATE */
    bssgp_ra_cap_upd_ack,				/* 10.3.3 RA-CAPABILITY-UPDATE */
    bssgp_ra_status,					/* 10.3.5 RADIO-STATUS */
    bssgp_suspend,						/* 10.3.6 SUSPEND */
    bssgp_suspend_ack,					/* 10.3.7 SUSPEND-ACK */
    bssgp_suspend_nack,					/* 10.3.8 SUSPEND-NACK */
    bssgp_resume,						/* 10.3.9 RESUME */
    bssgp_resume_ack,					/* 10.3.10 RESUME-ACK */
    bssgp_resume_nack,					/* 10.3.11 RESUME-NACK */

/* 0x11 to 0x1f Reserved */
    NULL,                            /* 0x11 */
    NULL,                            /* 0x12 */
    NULL,                            /* 0x13 */
    NULL,                            /* 0x14 */
    NULL,                            /* 0x15 */
    NULL,                            /* 0x16 */
    NULL,                            /* 0x17 */
    NULL,                            /* 0x18 */
    NULL,                            /* 0x19 */
    NULL,                            /* 0x1A */
    NULL,                            /* 0x1B */
    NULL,                            /* 0x1C */
    NULL,                            /* 0x1D */
    NULL,                            /* 0x1E */
    NULL,                            /* 0x1F */

/* 0x20 to 0x2e */
    bssgp_bvc_block,					/* 10.4.8 BVC-BLOCK */
    bssgp_bvc_block_ack,				/* 10.4.9 BVC-BLOCK-ACK */
    bssgp_bvc_reset,					/* 10.4.12 BVC-RESET */
    bssgp_bvc_reset_ack,				/* 10.4.13 BVC-RESET-ACK */
    bssgp_bvc_un_block,					/* 10.4.10 BVC-UNBLOCK */
    bssgp_bvc_un_block_ack,				/* 10.4.11 BVC-UNBLOCK-ACK */
    bssgp_flow_control_bvc,				/* 10.4.4 FLOW-CONTROL-BVC */
    bssgp_flow_control_bvc_ack,			/* 10.4.5 FLOW-CONTROL-BVC-ACK */
    bssgp_flow_control_ms,				/* 10.4.6 FLOW-CONTROL-MS */
    bssgp_flow_control_ms_ack,			/* 10.4.7 FLOW-CONTROL-MS-ACK */
    bssgp_flush_ll,						/* 10.4.1 FLUSH-LL */
    bssgp_flush_ll_ack,					/* 10.4.2 FLUSH-LL-ACK */
    bssgp_llc_discarded,				/* 10.4.3 LLC-DISCARDED */
    bssgp_flow_cntrl_pfc,				/* 10.4.24 FLOW-CONTROL-PFC */
    bssgp_flow_cntrl_pfc_ack,			/* 10.4.25 FLOW-CONTROL-PFC-ACK */

/* 0x2f to 0x3f Reserved */
    NULL,                              /* 0x2f */
    NULL,                              /* 0x30 */
    NULL,                              /* 0x31 */
    NULL,                              /* 0x32 */
    NULL,                              /* 0x33 */
    NULL,                              /* 0x34 */
    NULL,                              /* 0x35 */
    NULL,                              /* 0x36 */
    NULL,                              /* 0x37 */
    NULL,                              /* 0x38 */
    NULL,                              /* 0x39 */
    NULL,                              /* 0x3A */
    NULL,                              /* 0x3B */
    NULL,                              /* 0x3C */
    NULL,                              /* 0x3D */
    NULL,                              /* 0x3E */
    NULL,                              /* 0x3F */

/* 0x40 to 0x41 */
    bssgp_sgsn_invoke_trace,			/* 10.4.15 SGSN-INVOKE-TRACE */
    bssgp_status,						/* 10.4.14 STATUS */

/* 0x42 to 0x4f Reserved */
    NULL,                              /* 0x42 */
    NULL,                              /* 0x43 */
    NULL,                              /* 0x44 */
    NULL,                              /* 0x45 */
    NULL,                              /* 0x46 */
    NULL,                              /* 0x47 */
    NULL,                              /* 0x48 */
    NULL,                              /* 0x49 */
    NULL,                              /* 0x4A */
    NULL,                              /* 0x4B */
    NULL,                              /* 0x4C */
    NULL,                              /* 0x4D */
    NULL,                              /* 0x4E */
    NULL,                              /* 0x4F */

/* 0x50 to 0x5e */
    bssgp_download_bss_pfc,				/* 10.4.16    DOWNLOAD-BSS-PFC */
    bssgp_create_bss_pfc,				/* 10.4.17 CREATE-BSS-PFC */
    bssgp_create_bss_pfc_ack,			/* 10.4.18 CREATE-BSS-PFC-ACK */
    bssgp_create_bss_pfc_nack,			/* 10.4.19 CREATE-BSS-PFC-NACK */
    bssgp_modify_bss_pfc,				/* 10.4.20 MODIFY-BSS-PFC */
    bssgp_modify_bss_pfc_ack,			/* 10.4.21 MODIFY-BSS-PFC-ACK */
    bssgp_delete_bss_pfc,				/* 10.4.22 DELETE-BSS-PFC */
    bssgp_delete_bss_pfc_ack,			/* 10.4.23 DELETE-BSS-PFC-ACK */
    bssgp_delete_bss_pfc_req,			/* 10.4.26 DELETE-BSS-PFC-REQ */
    bssgp_ps_ho_required,				/* 10.4.27 PS-HANDOVER-REQUIRED */
    bssgp_ps_ho_required_ack,			/* 10.4.28 PS-HANDOVER-REQUIRED-ACK */
    bssgp_ps_ho_required_nack,			/* 10.4.29 PS-HANDOVER-REQUIRED-NACK */
    bssgp_ps_ho_request,				/* 10.4.30 PS-HANDOVER-REQUEST */
    bssgp_ps_ho_request_ack,			/* 10.4.31 PS-HANDOVER-REQUEST-ACK */
    bssgp_ps_ho_request_nack,			/* 10.4.31 10.4.32 PS-HANDOVER-REQUEST-NACK */

/* 0x5f Reserved */
    NULL,                              /* 0x5F */

/* 0x60 */
    bssgp_perform_loc_request,			/* 10.5.1 PERFORM-LOCATION-REQUEST */
	bssgp_perform_loc_response,			/* 10.5.2 PERFORM-LOCATION-RESPONSE */
	bssgp_perform_loc_response_abort,	/* 10.5.3 PERFORM-LOCATION-ABORT */
	bssgp_pos_cmd,						/* 10.5.4 POSITION-COMMAND */
	bssgp_pos_resp,						/* 10.5.5 POSITION-RESPONSE */

/* 0x65 to 0x6f Reserved */
    NULL,                              /* 0x65 */
    NULL,                              /* 0x66 */
    NULL,                              /* 0x67 */
    NULL,                              /* 0x68 */
    NULL,                              /* 0x69 */
    NULL,                              /* 0x6a */
    NULL,                              /* 0x6b */
    NULL,                              /* 0x6c */
    NULL,                              /* 0x6d */
    NULL,                              /* 0x6e */
    NULL,                              /* 0x6f */
	bssgp_ran_inf,                     /* 10.6.2 RAN-INFORMATION */
	bssgp_ran_inf_request,             /* 10.6.1 RAN-INFORMATION-REQUEST */
	bssgp_ran_inf_request_ack,         /* 10.6.3 RAN-INFORMATION-ACK */
	bssgp_ran_inf_err,                 /* 10.6.4 RAN-INFORMATION-ERROR */
    bssgp_ran_inf_app_err,             /* 10.6.5 RAN-INFORMATION-APPLICATION-ERROR */
    NULL,                              /* 0x75 */
    NULL,                              /* 0x76 */
    NULL,                              /* 0x77 */
    NULL,                              /* 0x78 */
    NULL,                              /* 0x79 */
    NULL,                              /* 0x7a */
    NULL,                              /* 0x7b */
    NULL,                              /* 0x7c */
    NULL,                              /* 0x7d */
    NULL,                              /* 0x7e */
    NULL,                              /* 0x7f */
	bssgp_mbms_session_start_req,      /* 10.7.1	MBMS-SESSION-START-REQUEST */
	bssgp_mbms_session_start_resp,     /* 10.7.2	MBMS-SESSION-START-RESPONSE */
	bssgp_mbms_session_stop_req,       /* 10.7.3	MBMS-SESSION-STOP-REQUEST */
	bssgp_mbms_session_stop_resp,      /* 10.7.4	MBMS-SESSION-STOP-RESPONSE */
	bssgp_mbms_session_update_req,     /* 10.7.5	MBMS-SESSION-UPDATE-REQUEST */
	bssgp_mbms_session_uptate_resp,    /* 10.7.6	MBMS-SESSION-UPDATE-RESPONSE */
    NULL,                              /* 0x86 */
    NULL,                              /* 0x87 */
    NULL,                              /* 0x88 */
    NULL,                              /* 0x89 */
    NULL,                              /* 0x8a */
    NULL,                              /* 0x8b */
    NULL,                              /* 0x8c */
    NULL,                              /* 0x8d */
    NULL,                              /* 0x8e */
    NULL,                              /* 0x8f */
    NULL,                              /* 0x90 */
    bssgp_ps_ho_complete,              /* 0x91 10.4.33	PS-HANDOVER-COMPLETE */
    bssgp_ps_ho_cancel,                /* 0x92 10.4.34	PS-HANDOVER-CANCEL */
    bssgp_ps_ho_complete_ack,          /* 0x93 10.4.35	PS-HANDOVER-COMPLETE-ACK*/
    NULL,    /* NONE */
};

void get_bssgp_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx_ext((guint32) (oct & 0xff), &bssgp_msg_strings_ext, &idx);
	*ett_tree = ett_bssgp_msg[idx];
	*hf_idx = hf_bssgp_msg_type;
	*msg_fcn = bssgp_msg_fcn[idx];

	return;
}

static void
dissect_bssgp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  proto_item *ti;
  proto_tree *bssgp_tree = NULL;
  int				offset = 0;
  guint32			len;
  const gchar		*msg_str = NULL;
  gint				ett_tree;
  int				hf_idx;
  void				(*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);

  /* Save pinfo */
  gpinfo = pinfo;
  g_rim_application_identity = 0;
  gparent_tree = tree;
  len = tvb_length(tvb);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BSSGP");

  col_clear(pinfo->cinfo, COL_INFO);


  g_pdu_type = tvb_get_guint8(tvb,offset);
  if (tree) {
    ti = proto_tree_add_item(tree, proto_bssgp, tvb, 0, -1, ENC_NA);
    bssgp_tree = proto_item_add_subtree(ti, ett_bssgp);
  }

  /* Messge type IE*/
  msg_fcn = NULL;
  ett_tree = -1;
  hf_idx = -1;
  msg_str = NULL;

  get_bssgp_msg_params(g_pdu_type, &msg_str, &ett_tree, &hf_idx, &msg_fcn);

  if(msg_str){
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s", msg_str);
  }else{
	proto_tree_add_text(bssgp_tree, tvb, offset, 1,"Unknown message 0x%x",g_pdu_type);
	return;
  }

	/*
	 * Add BSSGP message name
	 */
	proto_tree_add_item(bssgp_tree, hf_idx, tvb, offset, 1, FALSE);
	offset++;


	/*
	 * decode elements
	 */
	if (msg_fcn == NULL)
	{
		proto_tree_add_text(bssgp_tree, tvb, offset, len - offset, "Message Elements");
	}
	else
	{
		(*msg_fcn)(tvb, bssgp_tree, pinfo, offset, len - offset);
	}
}

void
proto_register_bssgp(void)
{
	guint		i;
	guint		last_offset;

  static hf_register_info hf[] = {
    { &hf_bssgp_msg_type,
       { "PDU Type", "bssgp.pdu_type",
         FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bssgp_msg_strings_ext, 0x0,
         NULL, HFILL }
     },
	{ &hf_bssgp_elem_id,
		{ "Element ID",	"bssgp.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		NULL, HFILL }
	},
	{ &hf_bssgp_bss_area_ind,
      { "BSS indicator", "bssgp.bss_ind",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_bvci,
      { "BVCI", "bssgp.bvci",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_bmax,
      { "Bmax(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.bmax",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_r,
      { "R(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.r",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_r_pfc,
      { "R_PFC(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.r_pfc",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_bucket_size,
      { "Bmax(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.bucket_size",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_bmax_pfc,
      { "Bmax_PFC(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.bmax_pfc",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_omc_id,
      { "OMC identity", "bssgp.omc_id",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_nsei,
      { "NSEI", "bssgp.nsei",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_rrlp_flag1,
      { "Flag 1", "bssgp.rrlp_flag1",
	FT_BOOLEAN, 8, TFS(&bssgp_rrlp_flg1_vals), 0x01,
	NULL, HFILL }
    },
    { &hf_bssgp_ci,
       { "CI", "bssgp.ci",
         FT_UINT16, BASE_HEX, NULL, 0x0,
         "Cell Identity", HFILL }
     },
	{ &hf_bssgp_flush_action,
      { "Action", "bssgp.ci",
	FT_UINT8, BASE_DEC, VALS(bssgp_flush_action_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_llc_frames_disc,
      { "Number of frames discarded", "bssgp.llc_frames_disc",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_ra_discriminator,
      { "Routing Address Discriminator", "bssgp.rad",
	FT_UINT8, BASE_DEC, VALS(bssgp_ra_discriminator_vals), 0x0f,
	NULL, HFILL }
    },
    { &hf_bssgp_rim_app_id,
      { "RIM Application Identity", "bssgp.rim_app_id",
	FT_UINT8, BASE_DEC, VALS(bssgp_rim_appid_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_rim_seq_no,
      { "RIM Sequence Number", "bssgp.rim_seq_no",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_rat_discriminator,
      { "RAT discriminator", "bssgp.rat_discriminator",
	FT_UINT8, BASE_DEC, VALS(bssgp_rat_discriminator_vals), 0x0f,
	NULL, HFILL }
    },
	{ &hf_bssgp_nacc_cause,
      { "NACC Cause", "bssgp.nacc_cause",
	FT_UINT8, BASE_DEC, VALS(bssgp_nacc_cause_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_s13_cause,
      { "SI3 Cause", "bssgp.s13_cause",
	FT_UINT8, BASE_DEC, VALS(bssgp_s13_cause_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_mbms_data_ch_cause,
      { "MBMS data channel Cause", "bssgp.mbms_data_ch_cause",
	FT_UINT8, BASE_DEC, VALS(bssgp_mbms_data_ch_cause_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_utra_si_cause,
      { "UTRA SI Cause", "bssgp.utra_si_cause",
	FT_UINT8, BASE_DEC, VALS(bssgp_utra_si_cause_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_num_si_psi,
      { "Number of SI/PSI", "bssgp.num_si_psi",
	FT_UINT8, BASE_DEC, NULL, 0xfe,
	NULL, HFILL }
    },
	{&hf_bssgp_si_psi_type,
      { "Type", "bssgp.si_psi_type",
	FT_BOOLEAN, 8, TFS(&bssgp_si_psi_type_vals), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_ran_inf_req_pdu_t_ext_c,
      { "PDU Type Extension", "bssgp.ran_inf_req_pdu_t_ext_c",
	FT_UINT8, BASE_DEC, VALS(bssgp_ran_inf_req_pdu_t_ext_c_vals), 0x0e,
	NULL, HFILL }
    },
	{ &hf_bssgp_ran_inf_pdu_t_ext_c,
      { "PDU Type Extension", "bssgp.ran_inf_pdu_t_ext_c",
	FT_UINT8, BASE_DEC, VALS(bssgp_ran_inf_pdu_t_ext_c_vals), 0x0e,
	NULL, HFILL }
    },
	{&hf_bssgp_rim_pdu_ind_ack,
      { "ACK", "bssgp.rim_pdu_ind_ack",
	FT_BOOLEAN, 8, TFS(&bssgp_rim_pdu_ind_ack_vals), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_rim_proto_ver_no,
      { "RIM Protocol Version Number", "bssgp.rim_proto_ver_no",
	FT_UINT8, BASE_DEC, VALS(bssgp_rim_proto_ver_no_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_delay_val,
      { "Delay Value (in centi-seconds)", "bssgp.delay_val",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_cause,
      { "Cause", "bssgp.cause",
	FT_UINT8, BASE_DEC|BASE_EXT_STRING, &bssgp_cause_vals_ext, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_peak_rate_gran,
      { "Peak Bit Rate Granularity", "bssgp.peak_rate_gran",
	FT_UINT8, BASE_DEC, NULL, 0xc0,
	NULL, HFILL }
    },
	{ &hf_bssgp_cr_bit,
      { "C/R", "bssgp.cr_bit",
	FT_BOOLEAN, 8, TFS(&bssgp_cr_bit_vals), 0x20,
	NULL, HFILL }
    },
	{ &hf_bssgp_t_bit,
      { "T", "bssgp.t_bit",
	FT_BOOLEAN, 8, TFS(&bssgp_t_bit_vals), 0x10,
	NULL, HFILL }
    },
	{ &hf_bssgp_a_bit,
      { "A", "bssgp.a_bit",
	FT_BOOLEAN, 8, TFS(&bssgp_a_bit_vals), 0x08,
	NULL, HFILL }
    },
	{ &hf_bssgp_ra_cause,
      { "Radio Cause", "bssgp.ra_cause",
	FT_UINT8, BASE_DEC, VALS(bssgp_radio_cause_vals), 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_ra_cap_upd_cause,
      { "RA-Cap-UPD Cause", "bssgp.ra_cap_upd_cause",
	FT_UINT8, BASE_DEC, VALS(bssgp_ra_cap_upd_cause_vals), 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_r_default_ms,
      { "R_default_MS(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.r",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },

	{ &hf_bssgp_suspend_ref_no,
      { "Suspend Reference Number", "bssgp.r_default_ms",
	FT_UINT8, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_tag,
      { "Tag", "bssgp.tag",
	FT_UINT8, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_trace_ref,
      { "Trace Reference", "bssgp.trace_ref",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_trigger_id,
      { "Entity Identity", "bssgp.entity_id",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_transaction_id,
      { "Transaction Id", "bssgp.transaction_id",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_no_of_oct,
      { "Number of octets transferred or deleted", "bssgp.no_of_oct",
	FT_UINT24, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_unit_val,
      { "Unit Value", "bssgp.unit_val",
	FT_UINT8, BASE_DEC, VALS(bssgp_unit_vals), 0xe0,
	NULL, HFILL }
    },
	{ &hf_bssgp_gprs_timer,
      { "Unit Value", "bssgp.gprs_timer",
	FT_UINT8, BASE_DEC, NULL, 0x1f,
	NULL, HFILL }
    },

	{ &hf_bssgp_mbms,
      { "MBMS Procedures", "bssgp.mbms",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
	NULL, HFILL }
    },
	{ &hf_bssgp_EnhancedRadioStatus,
      { "Enhanced Radio Status Procedures", "bssgp.enhancedradiostatus",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
	NULL, HFILL }
    },
	{ &hf_bssgp_pfcfc,
      { "PFC Flow Control Procedures", "bssgp.pfcfc",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
	NULL, HFILL }
    },
	{ &hf_bssgp_rim,
      { "RAN Information Management (RIM) procedures", "bssgp.rim",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
	NULL, HFILL }
    },
	{ &hf_bssgp_lcs,
      { "LCS Procedures", "bssgp.lcs",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
	NULL, HFILL }
    },
	{ &hf_bssgp_inr,
      { "Inter-NSE re-routing(INR)", "bssgp.inr",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
	NULL, HFILL }
    },
	{ &hf_bssgp_cbl,
      { "Current Bucket Level(CBL) Procedures", "bssgp.cbl",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
	NULL, HFILL }
    },
	{ &hf_bssgp_pfc,
      { "Packet Flow Context(PFC) Procedures", "bssgp.pfc",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_bucket_full_ratio,
     { "Ratio of the bucket that is filled up with data", "bssgp.bucket_full_ratio",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"B current x (100 / Bmax)", HFILL }
    },
	{ &hf_bssgp_b_pfc,
     { "B_PFC: Bucket Full Ratio of the PFC", "bssgp.b_pfc",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"B current x (100 / Bmax)", HFILL }
    },

	{ &hf_bssgp_precedence,
      { "Precedence", "bssgp.a_bit",
	FT_UINT8, BASE_DEC, NULL, 0x07,
	NULL, HFILL }
    },
	{ &hf_bssgp_serv_utran_cco,
      { "Service UTRAN CCO", "bssgp.serv_utran_cco",
	FT_UINT8, BASE_DEC, VALS(bssgp_service_utran_cco_vals), 0x07,
	NULL, HFILL }
    },
	{ &hf_bssgp_mbms_session_id,
		{ "MBMS Session ID", "bssgp.mbms_session_id",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_bssgp_mbms_cause,
		{ "Cause", "bssgp.mbms_cause",
		FT_UINT8, BASE_DEC|BASE_EXT_STRING, &bssgp_mbms_cause_vals_ext, 0x0f,
		NULL, HFILL }
	},
	{ &hf_bssgp_mbms_stop_cause,
		{ "Stop Cause", "bssgp.mbms_stop_cause",
		FT_UINT8, BASE_DEC|BASE_EXT_STRING, &bssgp_mbms_stop_cause_vals_ext, 0x0f,
		NULL, HFILL }
	},
	{ &hf_bssgp_session_inf,
		{ "BC/MC", "bssgp.session_inf",
		FT_BOOLEAN, 8, TFS(&tfs_bssgp_bc_mc), 0x01,
		NULL, HFILL }
    },
	{ &hf_bssgp_mbms_num_ra_ids,
		{ "Number of Routing Area Identifications", "bssgp.mbms_num_ra_ids",
		FT_UINT8, BASE_DEC|BASE_EXT_STRING, &bssgp_mbms_num_ra_ids_vals_ext, 0xf0,
		NULL, HFILL }
	},
	{ &hf_bssgp_gb_if,
      { "Gigabit Interface", "bssgp.gb_if",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
	NULL, HFILL }
    },
	{ &hf_bssgp_ps_ho,
      { "PS Handover", "bssgp.ps_ho",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_src_to_trg_transp_cont,
      { "Source to Target Transparent Container", "bssgp.src_to_trg_transp_cont",
	FT_BYTES, FT_NONE, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_trg_to_src_transp_cont,
      { "Target to Source Transparent Container", "bssgp.trg_to_src_transp_cont",
	FT_BYTES, FT_NONE, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_rnc_id,
      { "RNC ID", "bssgp.rnc_id",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_page_mode,
      { "PAGE_MODE", "bssgp.page_mode",
	FT_UINT8, BASE_DEC, VALS(bssgp_page_mode_vals), 0x03,
	NULL, HFILL }
    },
	{ &hf_bssgp_container_id,
      { "Container ID", "bssgp.container_id",
	FT_UINT8, BASE_DEC, NULL, 0x03,
	NULL, HFILL }
    },
	{ &hf_bssgp_global_tfi,
      { "Global TFI", "bssgp.global_tfi",
	FT_UINT8, BASE_DEC, VALS(bssgp_global_tfi_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_ul_tfi,
      { "UPLINK_TFI", "bssgp.global_tfi",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_dl_tfi,
      { "DOWNLINK_TFI", "bssgp.global_tfi",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_time_to_MBMS_data_tran,
      { "Time to MBMS Data Transfer", "bssgp.time_to_mbms_data_tran",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_mbms_session_rep_no,
      { "MBMS-Session-Repetition-Number", "bssgp.mbms_session_rep_no",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_ps_ho_cmd,
      { "PS Handover Command", "bssgp.ps_ho_cmd",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_sipsi,
      { "SI/PSI", "bssgp.sipsi",
	FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_type,
      { "Type", "bssgp.type",
	FT_UINT8, BASE_DEC, VALS(type_vals), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_cs_indication,
      { "CS Indication Contents", "bssgp.cs_indication",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },

	{ &hf_bssgp_flow_control_gran,
      { "Granularity", "bssgp.flow_control_gran",
	FT_UINT8, BASE_DEC, VALS(bssgp_flow_control_gran_vals), 0x03,
	NULL, HFILL }
    },
	{ &hf_bssgp_serv_eutran_cco,
      { "Service EUTRAN CCO", "bssgp.serv_eutran_cco",
	FT_UINT8, BASE_DEC, VALS(bssgp_service_eutran_cco_vals), 0x18,
	NULL, HFILL }
    },
	{ &hf_bssgp_sub_prof_id_f_rat_freq_prio,
      { "Subscriber Profile ID for RAT/Frequency priority", "bssgp.sub_prof_id_f_rat_freq_prio",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_eutran_irat_ho_inf_req,
      { "E-UTRAN Inter RAT Handover Info", "bssgp.eutran_irat_ho_inf_req",
	FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
	NULL, HFILL }
    },
	{ &hf_bssgp_irat_ho_inf_req,
      { "Inter RAT Handover Info", "bssgp.irat_ho_inf_req",
	FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
	NULL, HFILL }
    },

	{ &hf_bssgp_rel_int_rat_ho_inf_ind,
      { "Inter RAT Handover Info", "bssgp.rel_int_rat_ho_inf_ind",
	FT_BOOLEAN, 8, TFS(&tfs_reliable_not_reliable), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_csg_id,
      { "CSG Identity (CSG-ID)", "bssgp.csg_id",
	FT_UINT32, BASE_HEX, NULL, 0xffffff0f,
	NULL, HFILL }
    },
	{ &hf_bssgp_cell_acc_mode,
      { "Cell Access Mode", "bssgp.cell_acc_mode",
	FT_UINT8, BASE_DEC, VALS(bssgp_cell_access_mode_vals), 0x01,
	NULL, HFILL }
    },
    { &hf_bssgp_Global_ENB_ID_PDU,
      { "Global-ENB-ID", "bssgp.Global_ENB_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }
	},
    { &hf_bssgp_SONtransferRequestContainer_PDU,
      { "SONtransferRequestContainer", "bssgp.SONtransferRequestContainer",
        FT_UINT32, BASE_DEC, VALS(s1ap_SONtransferRequestContainer_vals), 0,
        NULL, HFILL }},

  };

  /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	10
	gint *ett[NUM_INDIVIDUAL_ELEMS +
		  NUM_BSSGP_ELEM +
		  NUM_BSSGP_MSG];
	ett[0] = &ett_bssgp;
    ett[1] = &ett_bssgp_list_of_setup_pfcs;
    ett[2] = &ett_bssgp_pfcs_to_be_set_up_list_t10;
    ett[3] = &ett_bssgp_pfcs_to_be_set_up_list_arp;
    ett[4] = &ett_bssgp_pfcs_to_be_set_up_list_abqp;
    ett[5] = &ett_bssgp_pfcs_to_be_set_up_list_pft;
    ett[6] = &ett_bssgp_pfcs_to_be_set_up_list;
    ett[7] = &ett_bssgp_new;
    ett[8] = &ett_bssgp_pfc_flow_control_parameters_pfc;
	ett[9] = &ett_bssgp_ra_id,

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_BSSGP_ELEM; i++, last_offset++)
	{
		ett_bssgp_elem[i] = -1;
		ett[last_offset] = &ett_bssgp_elem[i];
	}

	for (i=0; i < NUM_BSSGP_MSG; i++, last_offset++)
	{
		ett_bssgp_msg[i] = -1;
		ett[last_offset] = &ett_bssgp_msg[i];
	}

  /* Register the protocol name and description */
  proto_bssgp = proto_register_protocol("Base Station Subsystem GPRS Protocol", "BSSGP", "bssgp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_bssgp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("bssgp", dissect_bssgp, proto_bssgp);

  /* Register configuration options */
  bssgp_module = prefs_register_protocol(proto_bssgp, NULL);
  prefs_register_bool_preference(bssgp_module, "decode_nri",
				 "Decode NRI",
				 "Decode NRI (for use with SGSN in Pool)",
				 &bssgp_decode_nri);
  prefs_register_uint_preference(bssgp_module, "nri_length", "NRI length",
				 "NRI length, in bits",
				 10, &bssgp_nri_length);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 */
void
proto_reg_handoff_bssgp(void)
{
  llc_handle = find_dissector("llcgprs");
  rrlp_handle = find_dissector("rrlp");
  data_handle = find_dissector("data");

  diameter_3gpp_avp_dissector_table = find_dissector_table("diameter.3gpp");
}
