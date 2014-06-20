/* packet-sprt.h
 *
 * Routines for SPRT dissection
 * SPRT = Simple Packet Relay Transport
 *
 * Written by Jamison Adcock <jamison.adcock@cobham.com>
 * for Sparta Inc., dba Cobham Analytic Solutions
 * This code is largely based on the RTP parsing code
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

/* TODO:
 *    - work on conversations
 *
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#include "packet-sprt.h"

void proto_register_sprt(void);
void proto_reg_handoff_sprt(void);

/* for some "range_string"s, there's only one value in the range  */
#define SPRT_VALUE_RANGE(a) a,a

/* TODO - conversation states */
#define SPRT_STATE_XXX_TODO 0

#define SPRT_CONV_MAX_SETUP_METHOD_SIZE 12

/* is DLCI field present in I_OCTET message?  See "DLCI enabled" in CONNECT message */
typedef enum {
    DLCI_UNKNOWN,
    DLCI_PRESENT,
    DLCI_ABSENT
} i_octet_dlci_status_t;


 /* Keep conversation info for one side of an SPRT conversation
  * TODO - this needs to be bidirectional
  */
struct _sprt_conversation_info
{
    gchar    method[SPRT_CONV_MAX_SETUP_METHOD_SIZE + 1];
    gboolean stream_started;
    guint32  frame_number;         /* the frame where this conversation is started */

    /* sequence numbers for each channel: */
    guint32 seqnum[4];

    /* are we using the DLCI field in I_OCTET messages?  See CONNECT message ("DLCI enabled") */
    i_octet_dlci_status_t i_octet_dlci_status;
    guint32 connect_frame_number; /* the CONNECT frame that tells us if the DLCI is enabled */

    /* TODO - maintain state */

};

/* SPRT Message IDs: */
#define SPRT_MODEM_RELAY_MSG_ID_NULL              0
#define SPRT_MODEM_RELAY_MSG_ID_INIT              1
#define SPRT_MODEM_RELAY_MSG_ID_XID_XCHG          2
#define SPRT_MODEM_RELAY_MSG_ID_JM_INFO           3
#define SPRT_MODEM_RELAY_MSG_ID_START_JM          4
#define SPRT_MODEM_RELAY_MSG_ID_CONNECT           5
#define SPRT_MODEM_RELAY_MSG_ID_BREAK             6
#define SPRT_MODEM_RELAY_MSG_ID_BREAK_ACK         7
#define SPRT_MODEM_RELAY_MSG_ID_MR_EVENT          8
#define SPRT_MODEM_RELAY_MSG_ID_CLEARDOWN         9
#define SPRT_MODEM_RELAY_MSG_ID_PROF_XCHG        10
/* 11 -15 Reserved */
#define SPRT_MODEM_RELAY_MSG_ID_RESERVED1_START  11
#define SPRT_MODEM_RELAY_MSG_ID_RESERVED1_END    15
/* Data */
#define SPRT_MODEM_RELAY_MSG_ID_I_RAW_OCTET      16
#define SPRT_MODEM_RELAY_MSG_ID_I_RAW_BIT        17
#define SPRT_MODEM_RELAY_MSG_ID_I_OCTET          18
#define SPRT_MODEM_RELAY_MSG_ID_I_CHAR_STAT      19
#define SPRT_MODEM_RELAY_MSG_ID_I_CHAR_DYN       20
#define SPRT_MODEM_RELAY_MSG_ID_I_FRAME          21
#define SPRT_MODEM_RELAY_MSG_ID_I_OCTET_CS       22
#define SPRT_MODEM_RELAY_MSG_ID_I_CHAR_STAT_CS   23
#define SPRT_MODEM_RELAY_MSG_ID_I_CHAR_DYN_CS    24
/* 25 - 99 Reserved */
#define SPRT_MODEM_RELAY_MSG_ID_RESERVED2_START  25
#define SPRT_MODEM_RELAY_MSG_ID_RESERVED2_END    99
/* 100 - 127 Vendor-specific */
#define SPRT_MODEM_RELAY_MSG_ID_VENDOR_START    100
#define SPRT_MODEM_RELAY_MSG_ID_VENDOR_END      127


/* error correcting protocol in XID_XCHG message: */
#define SPRT_ECP_NO_LINK_LAYER_PROTO     0
#define SPRT_ECP_V42_LAPM                1
#define SPRT_ECP_ANNEX_AV42_1996         2
/* 3 - 25 Reserved for ITU-T */
#define SPRT_ECP_RESERVED_START          3
#define SPRT_ECP_RESERVED_END           25


/* category ID used in JM_INFO message: */
#define SPRT_JM_INFO_CAT_ID_CALL_FUNCT          0x8
#define SPRT_JM_INFO_CAT_ID_MOD_MODES           0xA
#define SPRT_JM_INFO_CAT_ID_PROTOCOLS           0x5
#define SPRT_JM_INFO_CAT_ID_PSTN_ACCESS         0xB
#define SPRT_JM_INFO_CAT_ID_PCM_MODEM_AVAIL     0xE
#define SPRT_JM_INFO_CAT_ID_CATEGORY_EXTENSION  0x0


#define SPRT_JMINFO_TBC_CALL_FUNCT_PSTN_MULTIMEDIA_TERM     0x4
#define SPRT_JMINFO_TBC_CALL_FUNCT_TEXTPHONE_ITU_T_REC_V18  0x2
#define SPRT_JMINFO_TBC_CALL_FUNCT_VIDEOTEXT_ITU_T_REC_T101 0x6
#define SPRT_JMINFO_TBC_CALL_FUNCT_TRANS_FAX_ITU_T_REC_T30  0x1
#define SPRT_JMINFO_TBC_CALL_FUNCT_RECV_FAX_ITU_T_REC_T30   0x5
#define SPRT_JMINFO_TBC_CALL_FUNCT_DATA_V_SERIES_MODEM_REC  0x3


#define SPRT_JMINFO_TBC_PROTOCOL_LAPM_ITU_T_REC_V42     0x4


/* selected modulations in CONNECT message: */
#define SPRT_SELMOD_NULL             0
#define SPRT_SELMOD_V92              1
#define SPRT_SELMOD_V91              2
#define SPRT_SELMOD_V90              3
#define SPRT_SELMOD_V34              4
#define SPRT_SELMOD_V32_BIS          5
#define SPRT_SELMOD_V32              6
#define SPRT_SELMOD_V22_BIS          7
#define SPRT_SELMOD_V22              8
#define SPRT_SELMOD_V17              9
#define SPRT_SELMOD_V29             10
#define SPRT_SELMOD_V27_TER         11
#define SPRT_SELMOD_V26_TER         12
#define SPRT_SELMOD_V26_BIS         13
#define SPRT_SELMOD_V23             14
#define SPRT_SELMOD_V21             15
#define SPRT_SELMOD_BELL_212        16
#define SPRT_SELMOD_BELL_103        17
/* 18 - 30 Vendor-specific modulations */
#define SPRT_SELMOD_VENDOR_START    18
#define SPRT_SELMOD_VENDOR_END      30
/* 31 - 63 Reserved for ITU-T */
#define SPRT_SELMOD_RESERVED_START  31
#define SPRT_SELMOD_RESERVED_END    63


/* Compression direction in CONNECT message: */
#define SPRT_COMPR_DIR_NO_COMPRESSION   0
#define SPRT_COMPR_DIR_TRANSMIT         1
#define SPRT_COMPR_DIR_RECEIVE          2
#define SPRT_COMPR_DIR_BIDIRECTIONAL    3


/* Selected compression modes in CONNECT message: */
#define SPRT_SELECTED_COMPR_NONE             0
#define SPRT_SELECTED_COMPR_V42_BIS          1
#define SPRT_SELECTED_COMPR_V44              2
#define SPRT_SELECTED_COMPR_MNP5             3
/* 4 - 15 Reserved by ITU-T */
#define SPRT_SELECTED_COMPR_RESERVED_START   4
#define SPRT_SELECTED_COMPR_RESERVED_END    15


/* Selected error correction modes in CONNECT message: */
#define SPRT_SELECTED_ERR_CORR_V14_OR_NONE       0
#define SPRT_SELECTED_ERR_CORR_V42_LAPM          1
#define SPRT_SELECTED_ERR_CORR_ANNEX_AV42        2
/* 3 - 15 Reserved for ITU-T */
#define SPRT_SELECTED_ERR_CORR_RESERVED_START    3
#define SPRT_SELECTED_ERR_CORR_RESERVED_END     15


/* Break source protocol in BREAK message: */
#define SPRT_BREAK_SRC_PROTO_V42_LAPM            0
#define SPRT_BREAK_SRC_PROTO_ANNEX_AV42_1996     1
#define SPRT_BREAK_SRC_PROTO_V14                 2
/* 3 - 15 Reserved for ITU-T */
#define SPRT_BREAK_SRC_PROTO_RESERVED_START      3
#define SPRT_BREAK_SRC_PROTO_RESERVED_END       15


#define SPRT_BREAK_TYPE_NOT_APPLICABLE                   0
#define SPRT_BREAK_TYPE_DESTRUCTIVE_AND_EXPEDITED        1
#define SPRT_BREAK_TYPE_NONDESTRUCTIVE_AND_EXPEDITED     2
#define SPRT_BREAK_TYPE_NONDESTRUCTIVE_AND_NONEXPEDITED  3
/* 4 - 15 Reserved for ITU-T */
#define SPRT_BREAK_TYPE_RESERVED_START                   4
#define SPRT_BREAK_TYPE_RESERVED_END                    15


/* Modem relay info in MR_EVENT messages: */
#define SPRT_MREVT_EVENT_ID_NULL                  0
#define SPRT_MREVT_EVENT_ID_RATE_RENEGOTIATION    1
#define SPRT_MREVT_EVENT_ID_RETRAIN               2
#define SPRT_MREVT_EVENT_ID_PHYSUP                3
/* 4 - 255 Reserved for ITU-T */
#define SPRT_MREVT_EVENT_ID_RESERVED_START        4
#define SPRT_MREVT_EVENT_ID_RESERVED_END        255


#define SPRT_MREVT_REASON_CODE_NULL               0
#define SPRT_MREVT_REASON_CODE_INIT               1
#define SPRT_MREVT_REASON_CODE_RESPONDING         2
/* 3 - 255 Undefined */
#define SPRT_MREVT_REASON_CODE_RESERVED_START     3
#define SPRT_MREVT_REASON_CODE_RESERVED_END     255


#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_NULL                0
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_600                 1
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_1200                2
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_1600                3
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_2400                4
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_2743                5
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3000                6
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3200                7
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3429                8
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_8000                9
/* 10 - 254 Reserved for ITU-T */
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_RESERVED_START     10
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_RESERVED_END      254
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_UNSPECIFIED       255


/* Cleardown reason codes: */
#define SPRT_CLEARDOWN_RIC_UNKNOWN                     0
#define SPRT_CLEARDOWN_RIC_PHYSICAL_LAYER_RELEASE      1
#define SPRT_CLEARDOWN_RIC_LINK_LAYER_DISCONNECT       2
#define SPRT_CLEARDOWN_RIC_DATA_COMPRESSION_DISCONNECT 3
#define SPRT_CLEARDOWN_RIC_ABORT                       4
#define SPRT_CLEARDOWN_RIC_ON_HOOK                     5
#define SPRT_CLEARDOWN_RIC_NETWORK_LAYER_TERMINATION   6
#define SPRT_CLEARDOWN_RIC_ADMINISTRATIVE              7


/* PROF_XCHG messages (XID profile exchange for MR1): */
#define SPRT_PROF_XCHG_SUPPORT_NO       0
#define SPRT_PROF_XCHG_SUPPORT_YES      1
#define SPRT_PROF_XCHG_SUPPORT_UNKNOWN  2


/* DLCI field in I_OCTET: */
#define SPRT_PAYLOAD_DLCI1_DTE2DTE                0
#define SPRT_PAYLOAD_DLCI1_RESERVED_START         1
#define SPRT_PAYLOAD_DLCI1_RESERVED_END          31
#define SPRT_PAYLOAD_DLCI1_NOT_RESERVED_START    32
#define SPRT_PAYLOAD_DLCI1_NOT_RESERVED_END      62
#define SPRT_PAYLOAD_DLCI1_CTRLFN2CTRLFN         63

#define SPRT_PAYLOAD_DLCI2_START                  0
#define SPRT_PAYLOAD_DLCI2_END                  127

/* Payload fields for I_CHAR_STAT_CS, etc.: */
/* # of data bits */
#define SPRT_PAYLOAD_D_0        0
#define SPRT_PAYLOAD_D_1        1
#define SPRT_PAYLOAD_D_2        2
#define SPRT_PAYLOAD_D_3        3


/* parity */
#define SPRT_PAYLOAD_P_0    0
#define SPRT_PAYLOAD_P_1    1
#define SPRT_PAYLOAD_P_2    2
#define SPRT_PAYLOAD_P_3    3
#define SPRT_PAYLOAD_P_4    4
#define SPRT_PAYLOAD_P_5    5
#define SPRT_PAYLOAD_P_6    6
#define SPRT_PAYLOAD_P_7    7


/* # of stop bits */
#define SPRT_PAYLOAD_S_0    0
#define SPRT_PAYLOAD_S_1    1
#define SPRT_PAYLOAD_S_2    2
#define SPRT_PAYLOAD_S_3    3


/* data frame state */
#define SPRT_PAYLOAD_FR_0   0
#define SPRT_PAYLOAD_FR_1   1
#define SPRT_PAYLOAD_FR_2   2
#define SPRT_PAYLOAD_FR_3   3


/* Initialize the protocol & registered fields */
static int proto_sprt =                         -1;

static int hf_sprt_setup =                      -1;
static int hf_sprt_setup_frame =                -1;
static int hf_sprt_setup_method =               -1;

static int hf_sprt_header_extension_bit =       -1;
static int hf_sprt_subsession_id =              -1;
static int hf_sprt_reserved_bit =               -1;
static int hf_sprt_payload_type =               -1;
static int hf_sprt_transport_channel_id =       -1;
static int hf_sprt_sequence_number =            -1;
static int hf_sprt_number_of_ack_fields =       -1;
static int hf_sprt_base_sequence_number =       -1;
static int hf_sprt_ack_field_items =            -1;
static int hf_sprt_transport_channel_item =     -1;
static int hf_sprt_sequence_item =              -1;

static int hf_sprt_payload =                    -1;
static int hf_sprt_payload_no_data =            -1;
static int hf_sprt_payload_reserved_bit =       -1;
static int hf_sprt_payload_message_id =         -1;

static int hf_sprt_payload_data =               -1; /* stuff after msgid */
/* INIT msg: */
static int hf_sprt_payload_msg_init_all_fields =                    -1;
static int hf_sprt_payload_msg_init_necrxch =                       -1;
static int hf_sprt_payload_msg_init_ecrxch =                        -1;
static int hf_sprt_payload_msg_init_xid_prof_exch =                 -1;
static int hf_sprt_payload_msg_init_assym_data_types =              -1;
static int hf_sprt_payload_msg_init_opt_moip_types_i_raw_bit =      -1;
static int hf_sprt_payload_msg_init_opt_moip_types_i_frame =        -1;
static int hf_sprt_payload_msg_init_opt_moip_types_i_char_stat =    -1;
static int hf_sprt_payload_msg_init_opt_moip_types_i_char_dyn =     -1;
static int hf_sprt_payload_msg_init_opt_moip_types_i_octet_cs =     -1;
static int hf_sprt_payload_msg_init_opt_moip_types_i_char_stat_cs = -1;
static int hf_sprt_payload_msg_init_opt_moip_types_i_char_dyn_cs =  -1;
static int hf_sprt_payload_msg_init_opt_moip_types_reserved =       -1;
/* XID_XCHG message: */
static int hf_sprt_payload_msg_xidxchg_ecp =                                    -1;
static int hf_sprt_payload_msg_xidxchg_xidlr1_v42bis =                          -1;
static int hf_sprt_payload_msg_xidxchg_xidlr1_v44 =                             -1;
static int hf_sprt_payload_msg_xidxchg_xidlr1_mnp5 =                            -1;
static int hf_sprt_payload_msg_xidxchg_xidlr1_reserved =                        -1;
static int hf_sprt_payload_msg_xidxchg_xidlr2_v42bis_compr_req =                -1;
static int hf_sprt_payload_msg_xidxchg_xidlr3and4_v42bis_num_codewords =        -1;
static int hf_sprt_payload_msg_xidxchg_xidlr5_v42bis_max_strlen =               -1;
static int hf_sprt_payload_msg_xidxchg_xidlr6_v44_capability =                  -1;
static int hf_sprt_payload_msg_xidxchg_xidlr7_v44_compr_req =                   -1;
static int hf_sprt_payload_msg_xidxchg_xidlr8and9_v44_num_codewords_trans =     -1;
static int hf_sprt_payload_msg_xidxchg_xidlr10and11_v44_num_codewords_recv =    -1;
static int hf_sprt_payload_msg_xidxchg_xidlr12_v44_max_strlen_trans =           -1;
static int hf_sprt_payload_msg_xidxchg_xidlr13_v44_max_strlen_recv =            -1;
static int hf_sprt_payload_msg_xidxchg_xidlr14and15_v44_history_len_trans =     -1;
static int hf_sprt_payload_msg_xidxchg_xidlr16and17_v44_history_len_recv =      -1;
/* V.8 JM_INFO msg: */
static int hf_sprt_payload_msg_jminfo_category_data =           -1;
static int hf_sprt_payload_msg_jminfo_category_id =             -1;
static int hf_sprt_payload_msg_jminfo_category_ext_info =       -1;
static int hf_sprt_payload_msg_jminfo_unk_category_info =       -1;
static int hf_sprt_payload_msg_jminfo_category_leftover_bits =  -1;
static int hf_sprt_payload_msg_jminfo_call_function =           -1;
static int hf_sprt_payload_msg_jminfo_mod_v34_duplex =          -1;
static int hf_sprt_payload_msg_jminfo_mod_v34_half_duplex =     -1;
static int hf_sprt_payload_msg_jminfo_mod_v32bis_v32 =          -1;
static int hf_sprt_payload_msg_jminfo_mod_v22bis_v22 =          -1;
static int hf_sprt_payload_msg_jminfo_mod_v17 =                 -1;
static int hf_sprt_payload_msg_jminfo_mod_v29_half_duplex =     -1;
static int hf_sprt_payload_msg_jminfo_mod_v27ter =              -1;
static int hf_sprt_payload_msg_jminfo_mod_v26ter =              -1;
static int hf_sprt_payload_msg_jminfo_mod_v26bis =              -1;
static int hf_sprt_payload_msg_jminfo_mod_v23_duplex =          -1;
static int hf_sprt_payload_msg_jminfo_mod_v23_half_duplex =     -1;
static int hf_sprt_payload_msg_jminfo_mod_v21 =                 -1;
static int hf_sprt_payload_msg_jminfo_protocols =               -1;
static int hf_sprt_payload_msg_jminfo_pstn_access_call_dce_cell =       -1;
static int hf_sprt_payload_msg_jminfo_pstn_access_answ_dce_cell =       -1;
static int hf_sprt_payload_msg_jminfo_pstn_access_dce_on_digital_net =  -1;
static int hf_sprt_payload_msg_jminfo_pcm_modem_avail_v90_v92_analog =  -1;
static int hf_sprt_payload_msg_jminfo_pcm_modem_avail_v90_v92_digital = -1;
static int hf_sprt_payload_msg_jminfo_pcm_modem_avail_v91 =             -1;
/* CONNECT msg: */
static int hf_sprt_payload_msg_connect_selmod =                         -1;
static int hf_sprt_payload_msg_connect_compr_dir =                      -1;
static int hf_sprt_payload_msg_connect_selected_compr =                 -1;
static int hf_sprt_payload_msg_connect_selected_err_corr =              -1;
static int hf_sprt_payload_msg_connect_tdsr =                           -1;
static int hf_sprt_payload_msg_connect_rdsr =                           -1;
static int hf_sprt_payload_msg_connect_dlci_enabled =                   -1;
static int hf_sprt_payload_msg_connect_avail_data_types =               -1;
static int hf_sprt_payload_msg_connect_adt_octet_no_format_no_dlci =    -1;
static int hf_sprt_payload_msg_connect_adt_i_raw_bit =                  -1;
static int hf_sprt_payload_msg_connect_adt_i_frame =                    -1;
static int hf_sprt_payload_msg_connect_adt_i_char_stat =                -1;
static int hf_sprt_payload_msg_connect_adt_i_char_dyn =                 -1;
static int hf_sprt_payload_msg_connect_adt_i_octet_cs =                 -1;
static int hf_sprt_payload_msg_connect_adt_i_char_stat_cs =             -1;
static int hf_sprt_payload_msg_connect_adt_i_char_dyn_cs =              -1;
static int hf_sprt_payload_msg_connect_adt_reserved =                   -1;
static int hf_sprt_payload_msg_connect_compr_trans_dict_sz =            -1;
static int hf_sprt_payload_msg_connect_compr_recv_dict_sz =             -1;
static int hf_sprt_payload_msg_connect_compr_trans_str_len =            -1;
static int hf_sprt_payload_msg_connect_compr_recv_str_len =             -1;
static int hf_sprt_payload_msg_connect_compr_trans_hist_sz =            -1;
static int hf_sprt_payload_msg_connect_compr_recv_hist_sz =             -1;
/* BREAK msg: */
static int hf_sprt_payload_msg_break_source_proto =     -1;
static int hf_sprt_payload_msg_break_type =             -1;
static int hf_sprt_payload_msg_break_length =           -1;
/* MR_EVENT msg: */
static int hf_sprt_payload_msg_mr_event_id =            -1;
static int hf_sprt_payload_msg_mr_evt_reason_code =     -1;
static int hf_sprt_payload_msg_mr_evt_selmod =          -1;
static int hf_sprt_payload_msg_mr_evt_txsen =           -1;
static int hf_sprt_payload_msg_mr_evt_rxsen =           -1;
static int hf_sprt_payload_msg_mr_evt_tdsr =            -1;
static int hf_sprt_payload_msg_mr_evt_rdsr =            -1;
static int hf_sprt_payload_msg_mr_evt_txsr =            -1;
static int hf_sprt_payload_msg_mr_evt_rxsr =            -1;
/* CLEARDOWN msg: */
static int hf_sprt_payload_msg_cleardown_reason_code =  -1;
static int hf_sprt_payload_msg_cleardown_vendor_tag =   -1;
static int hf_sprt_payload_msg_cleardown_vendor_info =  -1;
/* PROF_XCHG msg: */
static int hf_sprt_payload_msg_profxchg_v42_lapm =                              -1;
static int hf_sprt_payload_msg_profxchg_annex_av42 =                            -1;
static int hf_sprt_payload_msg_profxchg_v44_compr =                             -1;
static int hf_sprt_payload_msg_profxchg_v42bis_compr =                          -1;
static int hf_sprt_payload_msg_profxchg_mnp5_compr =                            -1;
static int hf_sprt_payload_msg_profxchg_reserved =                              -1;
static int hf_sprt_payload_msg_profxchg_xidlr2_v42bis_compr_req =               -1;
static int hf_sprt_payload_msg_profxchg_xidlr3and4_v42bis_num_codewords =       -1;
static int hf_sprt_payload_msg_profxchg_xidlr5_v42bis_max_strlen =              -1;
static int hf_sprt_payload_msg_profxchg_xidlr6_v44_capability =                 -1;
static int hf_sprt_payload_msg_profxchg_xidlr7_v44_compr_req =                  -1;
static int hf_sprt_payload_msg_profxchg_xidlr8and9_v44_num_codewords_trans =    -1;
static int hf_sprt_payload_msg_profxchg_xidlr10and11_v44_num_codewords_recv =   -1;
static int hf_sprt_payload_msg_profxchg_xidlr12_v44_max_strlen_trans =          -1;
static int hf_sprt_payload_msg_profxchg_xidlr13_v44_max_strlen_recv =           -1;
static int hf_sprt_payload_msg_profxchg_xidlr14and15_v44_history_len_trans =    -1;
static int hf_sprt_payload_msg_profxchg_xidlr16and17_v44_history_len_recv =     -1;
/* I_OCTET */
static int hf_sprt_payload_i_octet_no_dlci =                                    -1;
static int hf_sprt_payload_i_octet_dlci_presence_unknown =                      -1;
static int hf_sprt_payload_i_octet_dlci1 =                                      -1;
static int hf_sprt_payload_i_octet_cr =                                         -1;
static int hf_sprt_payload_i_octet_ea =                                         -1;
static int hf_sprt_payload_i_octet_dlci2 =                                      -1;
static int hf_sprt_payload_i_octet_dlci_setup_by_connect_frame =                -1;

/* I_OCTET_CS, I_CHAR_STAT_CS, I_CHAR_DYN_CS msgs: */
static int hf_sprt_payload_data_cs =                                            -1;
static int hf_sprt_payload_data_reserved_bit =                                  -1;
static int hf_sprt_payload_data_num_data_bits =                                 -1;
static int hf_sprt_payload_data_parity_type =                                   -1;
static int hf_sprt_payload_num_stop_bits =                                      -1;
static int hf_sprt_payload_frame_reserved_bits =                                -1;
static int hf_sprt_payload_frame_state =                                        -1;
static int hf_sprt_payload_rawoctet_n_field_present =                           -1;
static int hf_sprt_payload_rawoctet_l =                                         -1;
static int hf_sprt_payload_rawoctet_n =                                         -1;
static int hf_sprt_payload_rawbit_included_fields_l =                           -1;
static int hf_sprt_payload_rawbit_included_fields_lp =                          -1;
static int hf_sprt_payload_rawbit_included_fields_lpn =                         -1;
static int hf_sprt_payload_rawbit_len_a =                                       -1;
static int hf_sprt_payload_rawbit_len_b =                                       -1;
static int hf_sprt_payload_rawbit_len_c =                                       -1;
static int hf_sprt_payload_rawbit_p =                                           -1;
static int hf_sprt_payload_rawbit_n =                                           -1;

/* Preferences  */
static gboolean global_sprt_show_setup_info = TRUE; /* show how this SPRT stream got started */
static gboolean global_sprt_show_dlci_info  = TRUE; /* show DLCI in I_OCTET messages, including setup frame (if we can) */


/* dissector handle */
static dissector_handle_t sprt_handle;


/* initialize the subtree pointers */
static gint ett_sprt =                  -1;
static gint ett_sprt_setup =            -1;
static gint ett_sprt_ack_fields =       -1;
static gint ett_payload =               -1;
static gint ett_init_msg_all_fields =   -1;
static gint ett_jminfo_msg_cat_data =   -1;
static gint ett_connect_msg_adt =       -1;

static expert_field ei_sprt_sequence_number_0 = EI_INIT;

/* value strings & range strings */
static const value_string sprt_transport_channel_characteristics[] = {
    { 0, "Unreliable, unsequenced" },
    { 1, "Reliable, sequenced" },
    { 2, "Expedited, reliable, sequenced" },
    { 3, "Unreliable, sequenced" },
    { 0, NULL}
};

static const range_string sprt_modem_relay_msg_id_name[] = {
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_NULL),                                 "NULL reserved for ITU-T" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_INIT),                                 "INIT" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_XID_XCHG),                             "XID_XCHG" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_JM_INFO),                              "JM_INFO" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_START_JM),                             "START_JM" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_CONNECT),                              "CONNECT" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_BREAK),                                "BREAK" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_BREAK_ACK),                            "BREAK_ACK" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_MR_EVENT),                             "MR_EVENT" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_CLEARDOWN),                            "CLEARDOWN" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_PROF_XCHG),                            "PROF_XCHG" },
    { SPRT_MODEM_RELAY_MSG_ID_RESERVED1_START, SPRT_MODEM_RELAY_MSG_ID_RESERVED1_END, "Reserved for ITU-T" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_RAW_OCTET),                          "I_RAW-OCTET" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_RAW_BIT),                            "I_RAW-BIT" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_OCTET),                              "I_OCTET" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_CHAR_STAT),                          "I_CHAR-STAT" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_CHAR_DYN),                           "I_CHAR-DYN" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_FRAME),                              "I_FRAME" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_OCTET_CS),                           "I_OCTET-CS" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_CHAR_STAT_CS),                       "I_CHAR-STAT-CS" },
    { SPRT_VALUE_RANGE(SPRT_MODEM_RELAY_MSG_ID_I_CHAR_DYN_CS),                        "I_CHAR-DYN-CS" },
    { SPRT_MODEM_RELAY_MSG_ID_RESERVED2_START, SPRT_MODEM_RELAY_MSG_ID_RESERVED2_END, "Reserved for ITU-T" },
    { SPRT_MODEM_RELAY_MSG_ID_VENDOR_START, SPRT_MODEM_RELAY_MSG_ID_VENDOR_END,       "Vendor-specific message" },
    { 0, 0, NULL }
};

static const range_string sprt_ecp_name[] = {
    { SPRT_VALUE_RANGE(SPRT_ECP_NO_LINK_LAYER_PROTO),   "No link layer protocol" },
    { SPRT_VALUE_RANGE(SPRT_ECP_V42_LAPM),              "V.42/LAPM" },
    { SPRT_VALUE_RANGE(SPRT_ECP_ANNEX_AV42_1996),       "Annex A/V.42(1996)" },
    { SPRT_ECP_RESERVED_START, SPRT_ECP_RESERVED_END,   "Reserved for ITU-T" },
    { 0, 0, NULL }
};

static const value_string sprt_jm_info_cat_id_name[] = {
    { SPRT_JM_INFO_CAT_ID_CALL_FUNCT,           "Call function" },
    { SPRT_JM_INFO_CAT_ID_MOD_MODES,            "Modulation modes" },
    { SPRT_JM_INFO_CAT_ID_PROTOCOLS,            "Protocols" },
    { SPRT_JM_INFO_CAT_ID_PSTN_ACCESS,          "PSTN access" },
    { SPRT_JM_INFO_CAT_ID_PCM_MODEM_AVAIL,      "PCM modem availability" },
    { SPRT_JM_INFO_CAT_ID_CATEGORY_EXTENSION,   "Extension of current category" },
    { 0, NULL }
};

static const value_string sprt_jminfo_tbc_call_funct_name[] = {
    { SPRT_JMINFO_TBC_CALL_FUNCT_PSTN_MULTIMEDIA_TERM,      "PSTN Multimedia terminal (ITU-T Rec. H.324)" },
    { SPRT_JMINFO_TBC_CALL_FUNCT_TEXTPHONE_ITU_T_REC_V18,   "Textphone (ITU-T Rec. V.18)" },
    { SPRT_JMINFO_TBC_CALL_FUNCT_VIDEOTEXT_ITU_T_REC_T101,  "Videotext (ITU-T Rec. T.101)" },
    { SPRT_JMINFO_TBC_CALL_FUNCT_TRANS_FAX_ITU_T_REC_T30,   "Transmit facsimilie from call terminal (ITU-T Rec. T.30)" },
    { SPRT_JMINFO_TBC_CALL_FUNCT_RECV_FAX_ITU_T_REC_T30,    "Receive facsimilie at call terminal (ITU-T Rec. T.30)" },
    { SPRT_JMINFO_TBC_CALL_FUNCT_DATA_V_SERIES_MODEM_REC,   "Data (V-series modem Recommendations)" },
    { 0, NULL }
};

static const range_string sprt_jminfo_tbc_protocol_name[] = {
    { SPRT_VALUE_RANGE(SPRT_JMINFO_TBC_PROTOCOL_LAPM_ITU_T_REC_V42),    "LAPM protocol according to ITU-T Rec. V.42" },
    { 0, 0, NULL }
};

static const range_string sprt_selmod_name[] = {
    { SPRT_VALUE_RANGE(SPRT_SELMOD_NULL),                   "NULL" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V92),                    "V.92" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V91),                    "V.91" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V90),                    "V.90" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V34),                    "V.34" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V32_BIS),                "V.32bis" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V32),                    "V.32" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V22_BIS),                "V.22bis" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V22),                    "V.22" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V17),                    "V.17" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V29),                    "V.29" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V27_TER),                "V.27ter" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V26_TER),                "V.26ter" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V26_BIS),                "V.26bis" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V23),                    "V.23" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_V21),                    "V.21" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_BELL_212),               "Bell 212" },
    { SPRT_VALUE_RANGE(SPRT_SELMOD_BELL_103),               "Bell 103" },
    { SPRT_SELMOD_VENDOR_START, SPRT_SELMOD_VENDOR_END,     "Vendor-specific modulation" },
    { SPRT_SELMOD_RESERVED_START, SPRT_SELMOD_RESERVED_END, "Reserved for ITU-T" },
    { 0, 0, NULL }
};

static const value_string sprt_comp_direction[] = {
    { SPRT_COMPR_DIR_NO_COMPRESSION,    "None" },
    { SPRT_COMPR_DIR_TRANSMIT,          "Transmit" },
    { SPRT_COMPR_DIR_RECEIVE,           "Receive" },
    { SPRT_COMPR_DIR_BIDIRECTIONAL,     "Bidirectional" },
    { 0, NULL }
};

static const range_string sprt_selected_compr_name[] = {
    { SPRT_VALUE_RANGE(SPRT_SELECTED_COMPR_NONE),       "None" },
    { SPRT_VALUE_RANGE(SPRT_SELECTED_COMPR_V42_BIS),    "V.42bis" },
    { SPRT_VALUE_RANGE(SPRT_SELECTED_COMPR_V44),        "V.44" },
    { SPRT_VALUE_RANGE(SPRT_SELECTED_COMPR_MNP5),       "MNP5" },
    { SPRT_SELECTED_COMPR_RESERVED_START, SPRT_SELECTED_COMPR_RESERVED_END, "Reserved by ITU-T" },
    { 0, 0, NULL }
};

static const range_string sprt_selected_err_corr_name[] = {
    { SPRT_VALUE_RANGE(SPRT_SELECTED_ERR_CORR_V14_OR_NONE),     "V.14 or no error correction protocol" },
    { SPRT_VALUE_RANGE(SPRT_SELECTED_ERR_CORR_V42_LAPM),        "V.42/LAPM" },
    { SPRT_VALUE_RANGE(SPRT_SELECTED_ERR_CORR_ANNEX_AV42),      "Annex A/V.42" },
    { SPRT_SELECTED_ERR_CORR_RESERVED_START, SPRT_SELECTED_ERR_CORR_RESERVED_END,   "Reserved for ITU-T" },
    { 0, 0, NULL }
};

static const range_string sprt_break_src_proto_name[] = {
    { SPRT_VALUE_RANGE(SPRT_BREAK_SRC_PROTO_V42_LAPM),          "V.42/LAPM" },
    { SPRT_VALUE_RANGE(SPRT_BREAK_SRC_PROTO_ANNEX_AV42_1996),   "Annex A/V.42(1996)" },
    { SPRT_VALUE_RANGE(SPRT_BREAK_SRC_PROTO_V14),               "V.14" },
    { SPRT_BREAK_SRC_PROTO_RESERVED_START, SPRT_BREAK_SRC_PROTO_RESERVED_END,   "Reserved for ITU-T" },
    { 0, 0, NULL }
};

static const range_string sprt_break_type_name[] = {
    { SPRT_VALUE_RANGE(SPRT_BREAK_TYPE_NOT_APPLICABLE),                     "Not applicable" },
    { SPRT_VALUE_RANGE(SPRT_BREAK_TYPE_DESTRUCTIVE_AND_EXPEDITED),          "Destructive and expedited" },
    { SPRT_VALUE_RANGE(SPRT_BREAK_TYPE_NONDESTRUCTIVE_AND_EXPEDITED),       "Non-destructive and expedited" },
    { SPRT_VALUE_RANGE(SPRT_BREAK_TYPE_NONDESTRUCTIVE_AND_NONEXPEDITED),    "Non-destructive and non-expedited" },
    { SPRT_BREAK_TYPE_RESERVED_START, SPRT_BREAK_TYPE_RESERVED_END,         "Reserved for ITU-T" },
    { 0, 0, NULL }
};

static const range_string sprt_mrevent_id_name[] = {
    { SPRT_VALUE_RANGE(SPRT_MREVT_EVENT_ID_NULL),               "NULL" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_EVENT_ID_RATE_RENEGOTIATION), "Rate renegotiation" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_EVENT_ID_RETRAIN),            "Retrain" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_EVENT_ID_PHYSUP),             "Physical layer ready" }, /* reason code should be 0 */
    { SPRT_MREVT_EVENT_ID_RESERVED_START, SPRT_MREVT_EVENT_ID_RESERVED_END, "Reserved for ITU-T" },
    { 0, 0, NULL }
};

static const range_string sprt_mrevent_reason_code_name[] = {
    { SPRT_VALUE_RANGE(SPRT_MREVT_REASON_CODE_NULL),                "Null/not applicable" }, /* for eventid = PHYSUP */
    { SPRT_VALUE_RANGE(SPRT_MREVT_REASON_CODE_INIT),                "Initiation" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_REASON_CODE_RESPONDING),          "Responding" },
    { SPRT_MREVT_REASON_CODE_RESERVED_START, SPRT_MREVT_REASON_CODE_RESERVED_END,   "Reserved for ITU-T" },
    { 0, 0, NULL }
};

static const range_string sprt_mrevent_phys_layer_symbol_rate[] = {
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_NULL),             "Null/not applicable" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_600),              "600" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_1200),             "1200" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_1600),             "1600" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_2400),             "2400" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_2743),             "2743" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3000),             "3000" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3200),             "3200" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3429),             "3249" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_8000),             "8000" },
    { SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_RESERVED_START, SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_RESERVED_END, "Reserved for ITU-T" },
    { SPRT_VALUE_RANGE(SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_UNSPECIFIED),  "Unspecified" },
    { 0, 0, NULL }
};

static const value_string sprt_cleardown_reason[] = {
    { SPRT_CLEARDOWN_RIC_UNKNOWN,                     "Unknown/unspecified" },
    { SPRT_CLEARDOWN_RIC_PHYSICAL_LAYER_RELEASE,      "Physical layer release" },
    { SPRT_CLEARDOWN_RIC_LINK_LAYER_DISCONNECT,       "Link layer disconnect" },
    { SPRT_CLEARDOWN_RIC_DATA_COMPRESSION_DISCONNECT, "Data compression disconnect" },
    { SPRT_CLEARDOWN_RIC_ABORT,                       "Abort" },
    { SPRT_CLEARDOWN_RIC_ON_HOOK,                     "On hook" },
    { SPRT_CLEARDOWN_RIC_NETWORK_LAYER_TERMINATION,   "Network layer termination" },
    { SPRT_CLEARDOWN_RIC_ADMINISTRATIVE,              "Administrative" },
    { 0, NULL }
};

static const value_string sprt_prof_xchg_support[] = {
    { SPRT_PROF_XCHG_SUPPORT_NO,        "No" },
    { SPRT_PROF_XCHG_SUPPORT_YES,       "Yes" },
    { SPRT_PROF_XCHG_SUPPORT_UNKNOWN,   "Unknown" },
    { 0, NULL }
};

static const range_string sprt_payload_dlci1[] = {
    { SPRT_VALUE_RANGE(SPRT_PAYLOAD_DLCI1_DTE2DTE),                               "DTE-to-DTE (V.24 interfaces) data" },
    { SPRT_PAYLOAD_DLCI1_RESERVED_START,     SPRT_PAYLOAD_DLCI1_RESERVED_END,     "Reserved for for ITU-T" },
    { SPRT_PAYLOAD_DLCI1_NOT_RESERVED_START, SPRT_PAYLOAD_DLCI1_NOT_RESERVED_END, "Not reserved for for ITU-T" },
    { SPRT_VALUE_RANGE(SPRT_PAYLOAD_DLCI1_CTRLFN2CTRLFN),                         "Control-function to control-function information" },
    { 0, 0, NULL }
};

static const true_false_string sprt_payload_ea_bit[] = {
    { "Last octet of address field", "Another octet of address field follows" }
};

static const range_string sprt_payload_dlci2[] = {
    { SPRT_PAYLOAD_DLCI2_START, SPRT_PAYLOAD_DLCI2_END,     "Reserved by ITU-T for further study" },
    { 0, 0, NULL }
};

static const value_string sprt_payload_data_bits[] = {
    { SPRT_PAYLOAD_D_0,     "5 bits" },
    { SPRT_PAYLOAD_D_1,     "6 bits" },
    { SPRT_PAYLOAD_D_2,     "7 bits" },
    { SPRT_PAYLOAD_D_3,     "8 bits" },
    { 0, NULL }
};

static const value_string sprt_payload_parity[] = {
    { SPRT_PAYLOAD_P_0,     "Unknown" },
    { SPRT_PAYLOAD_P_1,     "None" },
    { SPRT_PAYLOAD_P_2,     "Even parity" },
    { SPRT_PAYLOAD_P_3,     "Odd parity" },
    { SPRT_PAYLOAD_P_4,     "Space parity" },
    { SPRT_PAYLOAD_P_5,     "Mark parity" },
    { SPRT_PAYLOAD_P_6,     "Reserved" },
    { SPRT_PAYLOAD_P_7,     "Reserved" },
    { 0, NULL }
};

static const value_string sprt_payload_stop_bits[] = {
    { SPRT_PAYLOAD_S_0,     "1 stop bit" },
    { SPRT_PAYLOAD_S_1,     "2 stop bits" },
    { SPRT_PAYLOAD_S_2,     "Reserved" },
    { SPRT_PAYLOAD_S_3,     "Reserved" },
    { 0, NULL }
};

static const value_string sprt_payload_frame_state[] = {
    { SPRT_PAYLOAD_FR_0,    "Data frame without termination" },
    { SPRT_PAYLOAD_FR_1,    "Data frame with termination" },
    { SPRT_PAYLOAD_FR_2,    "Data frame with abort termination" },
    { SPRT_PAYLOAD_FR_3,    "Undefined" },
    { 0, NULL }
};



/* look for a conversation & return the associated data */
static struct _sprt_conversation_info* find_sprt_conversation_data(packet_info *pinfo)
{
    conversation_t *p_conv = NULL;
    struct _sprt_conversation_info *p_conv_data = NULL;
    /* Use existing packet info if available */
    p_conv = find_conversation(pinfo->fd->num,
                                &pinfo->src,
                                &pinfo->dst,
                                pinfo->ptype,
                                pinfo->srcport,
                                pinfo->destport,
                                NO_ADDR_B|NO_PORT_B);
    if (p_conv)
    {
        p_conv_data = (struct _sprt_conversation_info*)conversation_get_proto_data(p_conv, proto_sprt);
    }
    return p_conv_data;
}



/* set up SPRT conversation */
void sprt_add_address(packet_info *pinfo,
                      address *addr, int port,
                      int other_port,
                      const gchar *setup_method,
                      guint32 setup_frame_number)
{
    address null_addr;
    conversation_t* p_conv;
    struct _sprt_conversation_info *p_conv_data = NULL;

    /*
     * If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again.
     */
    if (pinfo->fd->flags.visited)
    {
        return;
    }

    SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

    /*
     * Check if the ip address and port combination is not
     * already registered as a conversation.
     */
    p_conv = find_conversation(setup_frame_number, addr, &null_addr, PT_UDP, port, other_port,
                                NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

    /*
     * If not, create a new conversation.
     */
    if (!p_conv || p_conv->setup_frame != setup_frame_number) {
        p_conv = conversation_new(setup_frame_number, addr, &null_addr, PT_UDP,
                                    (guint32)port, (guint32)other_port,
                                    NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
    }

    /* Set dissector */
    conversation_set_dissector(p_conv, sprt_handle);

    /*
     * Check if the conversation has data associated with it.
     */
    p_conv_data = (struct _sprt_conversation_info *)conversation_get_proto_data(p_conv, proto_sprt);

    /*
     * If not, add a new data item.
     */
    if (!p_conv_data) {
        /* Create conversation data */
        p_conv_data = wmem_new(wmem_file_scope(), struct _sprt_conversation_info);
        p_conv_data->stream_started = FALSE;
        p_conv_data->seqnum[0] = 0;
        p_conv_data->seqnum[1] = 0;
        p_conv_data->seqnum[2] = 0;
        p_conv_data->seqnum[3] = 0;
        p_conv_data->i_octet_dlci_status = DLCI_UNKNOWN;
        p_conv_data->connect_frame_number = 0;
        conversation_add_proto_data(p_conv, proto_sprt, p_conv_data);
    }

    /* Update the conversation data. */
    g_strlcpy(p_conv_data->method, setup_method, SPRT_CONV_MAX_SETUP_METHOD_SIZE);
    p_conv_data->frame_number = setup_frame_number;
}



/* Display setup info */
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    struct _sprt_conversation_info *p_conv_data;
    proto_tree *sprt_setup_tree;
    proto_item *ti;

    /* look up the conversation & get the data */
    p_conv_data = find_sprt_conversation_data(pinfo);

    if (!p_conv_data)
    {
        proto_tree_add_string_format(tree, hf_sprt_setup, tvb, 0, 0, "", "No setup info found");
        return;
    }

    /* Create setup info subtree with summary info. */
    ti =  proto_tree_add_string_format(tree, hf_sprt_setup, tvb, 0, 0,
                                        "",
                                        "Stream setup by %s (frame %u)",
                                        p_conv_data->method,
                                        p_conv_data->frame_number);
    PROTO_ITEM_SET_GENERATED(ti);
    sprt_setup_tree = proto_item_add_subtree(ti, ett_sprt_setup);
    if (sprt_setup_tree)
    {
        /* Add details into subtree */
        proto_item* item = proto_tree_add_uint(sprt_setup_tree, hf_sprt_setup_frame,
                                                tvb, 0, 0, p_conv_data->frame_number);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_string(sprt_setup_tree, hf_sprt_setup_method,
                                        tvb, 0, 0, p_conv_data->method);
        PROTO_ITEM_SET_GENERATED(item);
    }
}


/* code to actually dissect the packet payload data */
static int
dissect_sprt_data(tvbuff_t *tvb,
                  packet_info *pinfo,
                  struct _sprt_conversation_info *p_conv_data,
                  proto_tree *sprt_tree,
                  unsigned int offset,
                  guint payload_length)
{
    proto_item *ti;
    proto_tree *sprt_payload_tree, *field_subtree;
    guint8 octet, payload_msgid, category_id;
    guint8 selcompr, mr_event_id;
    guint16 word, category_count;

    if (payload_length > 0)
    {
        ti = proto_tree_add_uint(sprt_tree, hf_sprt_payload, tvb, offset, 1, payload_length);
        proto_item_set_len(ti, payload_length);

        sprt_payload_tree = proto_item_add_subtree(ti, ett_payload);

        payload_msgid = tvb_get_guint8(tvb, offset) & 0x7F;

        proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_reserved_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_message_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        payload_length--;

        /* what kind of message is this? */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s(%d)", rval_to_str(payload_msgid, sprt_modem_relay_msg_id_name, "Unknown"), payload_msgid);

        /* now parse payload stuff after ext. bit & msgid */
        switch(payload_msgid)
        {
        case SPRT_MODEM_RELAY_MSG_ID_INIT:
            /* make subtree */
            ti = proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_init_all_fields, tvb, offset, 2, ENC_BIG_ENDIAN);
            field_subtree = proto_item_add_subtree(ti, ett_init_msg_all_fields);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_necrxch, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_ecrxch, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_xid_prof_exch, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_assym_data_types, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_opt_moip_types_i_raw_bit, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_opt_moip_types_i_frame, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_opt_moip_types_i_char_stat, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_opt_moip_types_i_char_dyn, tvb, offset, 2, ENC_BIG_ENDIAN);
            /* from V.150.1 amendment 2 (5-2006): */
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_opt_moip_types_i_octet_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_opt_moip_types_i_char_stat_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_opt_moip_types_i_char_dyn_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_init_opt_moip_types_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case SPRT_MODEM_RELAY_MSG_ID_XID_XCHG:
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_ecp, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr1_v42bis, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr1_v44, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr1_mnp5, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr1_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr2_v42bis_compr_req, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr3and4_v42bis_num_codewords, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr5_v42bis_max_strlen, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr6_v44_capability, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr7_v44_compr_req, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr8and9_v44_num_codewords_trans, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr10and11_v44_num_codewords_recv, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr12_v44_max_strlen_trans, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr13_v44_max_strlen_recv, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr14and15_v44_history_len_trans, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_xidxchg_xidlr16and17_v44_history_len_recv, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case SPRT_MODEM_RELAY_MSG_ID_JM_INFO:
            category_count = 1;
            do /* there may be multiple categories */
            {
                word = tvb_get_ntohs(tvb, offset);
                category_id = (word >> 12);

                ti = proto_tree_add_uint_format_value(sprt_payload_tree, hf_sprt_payload_msg_jminfo_category_data, tvb, offset, 2, word,
                    "Item #%d: %s (0x%04x)", category_count, val_to_str_const(category_id, sprt_jm_info_cat_id_name, "Unknown"), category_id);
                category_count++;
                field_subtree = proto_item_add_subtree(ti, ett_jminfo_msg_cat_data);
                proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_category_id, tvb, offset, 2, ENC_BIG_ENDIAN);

                switch(category_id)
                {
                case SPRT_JM_INFO_CAT_ID_CALL_FUNCT: /* 0x8 */
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_call_function, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_category_leftover_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                    break;
                case SPRT_JM_INFO_CAT_ID_MOD_MODES: /* 0xA */
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v34_duplex, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v34_half_duplex, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v32bis_v32, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v22bis_v22, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v17, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v29_half_duplex, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v27ter, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v26ter, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v26bis, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v23_duplex, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v23_half_duplex, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_mod_v21, tvb, offset, 2, ENC_BIG_ENDIAN);
                    break;
                case SPRT_JM_INFO_CAT_ID_PROTOCOLS: /* 0x5 */
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_protocols, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_category_leftover_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                    break;
                case SPRT_JM_INFO_CAT_ID_PSTN_ACCESS: /* 0xB */
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_pstn_access_call_dce_cell, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_pstn_access_answ_dce_cell, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_pstn_access_dce_on_digital_net, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_category_leftover_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                    break;
                case SPRT_JM_INFO_CAT_ID_PCM_MODEM_AVAIL: /* 0xE */
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_pcm_modem_avail_v90_v92_analog, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_pcm_modem_avail_v90_v92_digital, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_pcm_modem_avail_v91, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_category_leftover_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                    break;
                case SPRT_JM_INFO_CAT_ID_CATEGORY_EXTENSION: /* 0x0 */
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_category_ext_info, tvb, offset, 2, ENC_BIG_ENDIAN);
                    break;
                default: /* unknown category ID */
                    proto_tree_add_item(field_subtree, hf_sprt_payload_msg_jminfo_unk_category_info, tvb, offset, 2, ENC_BIG_ENDIAN);
                    break;
                }
                offset += 2;
            } while (tvb_length_remaining(tvb, offset) >= 2);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_START_JM:
            /* No additional content */
            break;
        case SPRT_MODEM_RELAY_MSG_ID_CONNECT: /***/
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_selmod, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_compr_dir, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            selcompr = (tvb_get_guint8(tvb, offset) & 0xF0) >> 4;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_selected_compr, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_selected_err_corr, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_tdsr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_rdsr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            word = tvb_get_ntohs(tvb, offset);
            /* is DLCI enabled (used w/I_OCTET messages)? */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_dlci_enabled, tvb, offset, 2, ENC_BIG_ENDIAN);
            /* have we previously seen a CONNECT msg in this conversation (i.e., do we know if DLCI is used w/I_OCTET?) */
            if (p_conv_data->connect_frame_number == 0)
            {
                p_conv_data->connect_frame_number = pinfo->fd->num;
                if (word & 0x8000)
                {
                    p_conv_data->i_octet_dlci_status = DLCI_PRESENT;
                } else {
                    p_conv_data->i_octet_dlci_status = DLCI_ABSENT;
                }
            }

            /* do subtree for available data types */
            ti = proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_avail_data_types, tvb, offset, 2, ENC_BIG_ENDIAN);
            field_subtree = proto_item_add_subtree(ti, ett_connect_msg_adt);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_octet_no_format_no_dlci, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_i_raw_bit, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_i_frame, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_i_char_stat, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_i_char_dyn, tvb, offset, 2, ENC_BIG_ENDIAN);
            /* from V.150.1 amendment 2 (5-2006): */
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_i_octet_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_i_char_stat_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_i_char_dyn_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(field_subtree, hf_sprt_payload_msg_connect_adt_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (selcompr != SPRT_SELECTED_COMPR_NONE &&
               selcompr != SPRT_SELECTED_COMPR_MNP5)
            {
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_compr_trans_dict_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_compr_recv_dict_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_compr_trans_str_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_compr_recv_str_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
            if (selcompr != SPRT_SELECTED_COMPR_NONE &&
               selcompr != SPRT_SELECTED_COMPR_MNP5 &&
               selcompr != SPRT_SELECTED_COMPR_V42_BIS)
            {
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_compr_trans_hist_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_connect_compr_recv_hist_sz, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            break;
        case SPRT_MODEM_RELAY_MSG_ID_BREAK: /* no additional info */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_break_source_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_break_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_break_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case SPRT_MODEM_RELAY_MSG_ID_BREAK_ACK:
            /* No additional content */
            break;
        case SPRT_MODEM_RELAY_MSG_ID_MR_EVENT:
            mr_event_id = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_event_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_evt_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (mr_event_id == SPRT_MREVT_EVENT_ID_PHYSUP)
            {
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_evt_selmod, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_evt_txsen, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_evt_rxsen, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_evt_tdsr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_evt_rdsr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* The next two fields are "optional"
                 * they should only appear w/PHYSUP (MR_EVENT id = 3) messages, when TxSR and RxSR are true
                 */
                if (tvb_reported_length_remaining(tvb, offset) >= 2)
                {
                    proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_evt_txsr, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_mr_evt_rxsr, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
            }
            break;
        case SPRT_MODEM_RELAY_MSG_ID_CLEARDOWN:
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_cleardown_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_cleardown_vendor_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_cleardown_vendor_info, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case SPRT_MODEM_RELAY_MSG_ID_PROF_XCHG:
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_v42_lapm, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_annex_av42, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_v44_compr, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_v42bis_compr, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_mnp5_compr, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr2_v42bis_compr_req, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr3and4_v42bis_num_codewords, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr5_v42bis_max_strlen, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr6_v44_capability, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr7_v44_compr_req, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr8and9_v44_num_codewords_trans, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr10and11_v44_num_codewords_recv, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr12_v44_max_strlen_trans, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr13_v44_max_strlen_recv, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr14and15_v44_history_len_trans, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_msg_profxchg_xidlr16and17_v44_history_len_recv, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_RAW_OCTET: /* data */
            octet = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawoctet_n_field_present, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawoctet_l, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (octet & 0x80) /* is N field present? */
            {
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawoctet_n, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            offset++;
            payload_length--;
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_RAW_BIT: /* data */
            /*
             * L, P, N fields need to be parsed
             */
            switch((tvb_get_guint8(tvb, offset) & 0xC0) >> 6)
            {
            case 0x0: /* 00: get L (6 bits) */
                /* display leading "00" bits, followed by L */
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_included_fields_l, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_len_a, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                payload_length--;
                break;
            case 0x1: /* 01: get L (3 bits) & P (3 bits) */
                /* display leading "01" bits, followed by L,P */
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_included_fields_lp, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_len_b, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_p, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                payload_length--;
                break;
            default: /* 10, 11: get L (4 bits), P (3 bits), N (8 bits) */
                /* display leading "1" bit, followed by L,P,N */
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_included_fields_lpn, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_len_c, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_p, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                payload_length--;
                proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_rawbit_n, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                payload_length--;
                break;
            }
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_OCTET: /* data */
            if (global_sprt_show_dlci_info)
            {
                /* DLCI field may be 0, 1, or 2 bytes, depending on CONNECT message (see "DLCI enabled")...
                 * or UNKNOWN if we don't see the CONNECT message
                 */
                switch(p_conv_data->i_octet_dlci_status)
                {
                case DLCI_PRESENT:
                    octet = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_i_octet_dlci1, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_i_octet_cr, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_i_octet_ea, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    payload_length--;
                    /* check address extension... if ea bit == 0, then DLCI has another octet (see ITU-T V42 spec for more info) */
                    if (!(octet & 0x01))
                    {
                        proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_i_octet_dlci2, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_i_octet_ea, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        payload_length--;
                    }
                    ti = proto_tree_add_uint(sprt_payload_tree, hf_sprt_payload_i_octet_dlci_setup_by_connect_frame, tvb, 0, 0, p_conv_data->connect_frame_number);
                    PROTO_ITEM_SET_GENERATED(ti);
                    break;
                case DLCI_ABSENT:
                    ti = proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_i_octet_no_dlci, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_GENERATED(ti);
                    ti = proto_tree_add_uint(sprt_payload_tree, hf_sprt_payload_i_octet_dlci_setup_by_connect_frame, tvb, 0, 0, p_conv_data->connect_frame_number);
                    PROTO_ITEM_SET_GENERATED(ti);
                    break;
                case DLCI_UNKNOWN: /* e.g., we didn't see the CONNECT msg so we don't know if there is a DLCI */
                default:
                    ti = proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_i_octet_dlci_presence_unknown, tvb, 0, 0, ENC_NA);
                    PROTO_ITEM_SET_GENERATED(ti);
                    break;
                }
            }
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_CHAR_STAT: /* data */
            /* r: 1-bit reserved */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_reserved_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* D: 2-bit field indicating # of data bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_num_data_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* P: 3-bit field for parity type */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_parity_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* S: 2-bit field indicating # of stop bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_num_stop_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            payload_length--;
            /* octets */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_CHAR_DYN: /* data */
            /* r: 1-bit reserved */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_reserved_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* D: 2-bit field indicating # of data bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_num_data_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* P: 3-bit field for parity type */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_parity_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* S: 2-bit field indicating # of stop bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_num_stop_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            payload_length--;
            /* octets */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_FRAME: /* data */
            /* R: 6 reserved bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_frame_reserved_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Fr: data frame state */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_frame_state, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            payload_length--;
            /* octets */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_OCTET_CS: /* data */
            /* CS: 2-byte character sequence number */
            /* TODO - does this msg type ever have a DLCI? */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            payload_length -= 2;
            /* octets */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_CHAR_STAT_CS: /* data */
            /* r: 1-bit reserved */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_reserved_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* D: 2-bit field indicating # of data bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_num_data_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* P: 3-bit field for parity type */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_parity_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* S: 2-bit field indicating # of stop bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_num_stop_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            payload_length--;
            /* CS: 2-byte character sequence number */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            payload_length -= 2;
            /* octets */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        case SPRT_MODEM_RELAY_MSG_ID_I_CHAR_DYN_CS: /* data */
            /* r: 1-bit reserved */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_reserved_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* D: 2-bit field indicating # of data bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_num_data_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* P: 3-bit field for parity type */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_parity_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* S: 2-bit field indicating # of stop bits */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_num_stop_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            payload_length--;
            /* CS: 2-byte character sequence number */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            payload_length -= 2;
            /* octets */
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        default:
            proto_tree_add_item(sprt_payload_tree, hf_sprt_payload_data, tvb, offset, payload_length, ENC_NA);
            break;
        }
    } else {
        proto_tree_add_item(sprt_tree, hf_sprt_payload_no_data, tvb, offset, 0, ENC_NA);
        col_append_str(pinfo->cinfo, COL_INFO, ", No Payload");
    }

    return offset;
}

static int
dissect_sprt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *sprt_tree = NULL;
    proto_tree *sprt_ack_field_tree;
    guint16 word1;
    unsigned int offset = 0;
    guint payload_length;
    struct _sprt_conversation_info *p_conv_data = NULL;
    int i;

    guint16 tc;
    guint16 seqnum; /* 0 if TC = 0 or if no payload */
    guint16 noa;
    /* ack fields */
    /*guint16 tcn;*/
    /*guint16 sqn;*/

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPRT");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree)
    {
        /* create the trees */
        ti = proto_tree_add_item(tree, proto_sprt, tvb, 0, -1, ENC_NA);
        sprt_tree = proto_item_add_subtree(ti, ett_sprt);

        /* show conversation setup info */
        if (global_sprt_show_setup_info)
        {
            show_setup_info(tvb, pinfo, sprt_tree);
        }
    }

    /*SPRT header packet format
    +------+-------+-------+-------+-------+-------+---------+-------+
    |0     |1      |2      |3      |4      |5      |6          |7    |
    +------+-------+-------+-------+-------+-------+---------+-------+
    | X    |             SSID                                        |
    +----------------------------------------------------------------+
    | R    |             PT                                          |
    +--------------+-------------------------------------------------+
    | TC           |   Sequence Number                               |
    +--------------+-------------------------------------------------+
    |            Sequence Number                                     |
    +----------------------------------------------------------------+
    | NOA          |   Base Sequence Number                          |
    +--------------+-------------------------------------------------+
    |            Base Sequence Number                                |
    +----------------------------------------------------------------+
    | TCN          |   SQN                                           |
    +--------------+-------------------------------------------------+
    |            SQN                                                 |
    +----------------------------------------------------------------+
    | TCN          |   SQN                                           |
    +--------------+-------------------------------------------------+
    |            SQN                                                 |
    +----------------------------------------------------------------+
    | TCN          |   SQN                                           |
    +--------------+-------------------------------------------------+
    |            SQN                                                 |
    +----------------------------------------------------------------+
    */

    /* Get fields needed for further dissection */
    word1 = tvb_get_ntohs(tvb, offset + 2);
    tc = (word1 & 0xC000) >> 14;
    seqnum = word1 & 0x3FFF;

    noa = (tvb_get_ntohs(tvb, offset + 4) & 0xC000) >> 14;

    /* Get conversation data, or create it if not found */
    p_conv_data = find_sprt_conversation_data(pinfo);
    if (!p_conv_data)
    {
        sprt_add_address(pinfo,
            &pinfo->src, pinfo->srcport,
            0,
            "SPRT stream",
            pinfo->fd->num);
        p_conv_data = find_sprt_conversation_data(pinfo);
    }

    proto_tree_add_item(sprt_tree, hf_sprt_header_extension_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sprt_tree, hf_sprt_subsession_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(sprt_tree, hf_sprt_reserved_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sprt_tree, hf_sprt_payload_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(sprt_tree, hf_sprt_transport_channel_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(sprt_tree, hf_sprt_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (tc == 0 && seqnum != 0)
        expert_add_info(pinfo, ti, &ei_sprt_sequence_number_0);

    p_conv_data->seqnum[tc] = seqnum; /* keep track of seqnum values */
    offset+=2;

    proto_tree_add_item(sprt_tree, hf_sprt_number_of_ack_fields, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sprt_tree, hf_sprt_base_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    if (noa) /* parse ack fields? There can be 0 - 3 */
    {
        ti = proto_tree_add_item(sprt_tree, hf_sprt_ack_field_items, tvb, offset, 2, ENC_BIG_ENDIAN);
        sprt_ack_field_tree = proto_item_add_subtree(ti, ett_sprt_ack_fields);

        for(i = 0; i < noa; i++)
        {
            proto_tree_add_item(sprt_ack_field_tree, hf_sprt_transport_channel_item, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(sprt_ack_field_tree, hf_sprt_sequence_item, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    /* put details in the info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, "TC=%u", tc);
    if (tc != 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Seq=%u", seqnum);

    /* dissect the payload, if any */
    payload_length = tvb_length(tvb) - (6 + noa * 2); /* total sprt length - header stuff */
    dissect_sprt_data(tvb, pinfo, p_conv_data, sprt_tree, offset, payload_length);

    if (noa)
        col_append_str(pinfo->cinfo, COL_INFO, " (ACK fields present)");

    return tvb_length(tvb);
}

/* heuristic dissector */
static gboolean
dissect_sprt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 octet, extension_bit, reserved_bit, payload_type;
    guint16 word, tc, seqnum;
    unsigned int offset = 0;

    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (tvb_length(tvb) < 6)
        return FALSE; /* packet is waay to short */

    /* Get the fields in the first two octets */
    extension_bit = tvb_get_guint8(tvb, offset) & 0x7F;
    if (extension_bit != 0) /* must be 0 */
        return FALSE;

    octet = tvb_get_guint8(tvb, offset + 1);
    reserved_bit = octet & 80;
    payload_type = octet & 0x7F;
    if (reserved_bit != 0) /* must be 0 */
        return FALSE;
    if (payload_type < 96 || payload_type > 128) /* value within RTP dynamic payload type range */
        return FALSE;

    word = tvb_get_ntohs(tvb, offset + 2);
    tc = word >> 14;
    seqnum = word & 0x3F;
    if ((tc == 0 || tc == 3) && (seqnum != 0)) /* seqnum only applies if tc is 1 or 2 */
        return FALSE;

    dissect_sprt(tvb, pinfo, tree, NULL);
    return TRUE;
}

/* register the protocol with Wireshark */
void
proto_register_sprt(void)
{
    module_t *sprt_module;
    expert_module_t* expert_sprt;

    static hf_register_info hf[] =
    {
        /* set up fields */
        {
            &hf_sprt_setup,
            {
                "Stream setup",
                "sprt.setup",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Stream setup, method and frame number", HFILL
            }
        },
        {
            &hf_sprt_setup_frame,
            {
                "Setup frame",
                "sprt.setup-frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                "Frame that set up this stream", HFILL
            }
        },
        {
            &hf_sprt_setup_method,
            {
                "Setup Method",
                "sprt.setup-method",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Method used to set up this stream", HFILL
            }
        },
        /* SPRT header fields: */
        {
            &hf_sprt_header_extension_bit,
            {
                "Header extension bit",
                "sprt.x",
                FT_BOOLEAN,
                8,
                TFS(&tfs_set_notset),
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_subsession_id,
            {
                "Sub session ID",
                "sprt.ssid",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7F,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_reserved_bit,
            {
                "Reserved bit",
                "sprt.reserved",
                FT_BOOLEAN,
                8,
                TFS(&tfs_set_notset),
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_type,
            {
                "Payload type",
                "sprt.pt",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7F,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_transport_channel_id,
            {
                "Transport channel ID",
                "sprt.tc",
                FT_UINT16,
                BASE_DEC,
                VALS(sprt_transport_channel_characteristics),
                0xC000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_sequence_number,
            {
                "Sequence number",
                "sprt.seq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x3FFF,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_number_of_ack_fields,
            {
                "Number of ACK fields",
                "sprt.noa",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0xC000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_base_sequence_number,
            {
                "Base sequence number",
                "sprt.bsqn",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x3FFF,
                NULL, HFILL
            }
        },
        /* ACK fields, if any: */
        {
            &hf_sprt_ack_field_items, /* 0 to 3 items (TCN + SQN) */
            {
                "ACK fields",
                "sprt.ack.field",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0xC000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_transport_channel_item,
            {
                "Transport control channel",
                "sprt.tcn",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0xC000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_sequence_item,
            {
                "Sequence number",
                "sprt.sqn",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x3FFF,
                NULL, HFILL
            }
        },
        /* SPRT payload, if any: */
        {
            &hf_sprt_payload,
            {
                "Payload (in bytes)",
                "sprt.payload",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_no_data,
            {
                "No payload",
                "sprt.payload",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_reserved_bit,
            {
                "Reserved bit",
                "sprt.payload.reserved_bit",
                FT_BOOLEAN,
                8,
                TFS(&tfs_set_notset),
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_message_id,
            {
                "Payload message ID",
                "sprt.payload.msgid",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_modem_relay_msg_id_name),
                0x7F,
                NULL, HFILL
            }
        },
        /* SPRT payload fields, if any (depend on payload msgid): */
        /* INIT message */
        {
            &hf_sprt_payload_msg_init_all_fields,
            {
                "Init message fields",
                "sprt.payload.msg_init.all_fields",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0xFFFF, /* 0x0 */
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_necrxch,
            {
                "NECRxCH",
                "sprt.payload.msg_init.NECRxCH",
                FT_BOOLEAN,
                16,
                NULL,
                0x8000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_ecrxch,
            {
                "ECRxCH",
                "sprt.payload.msg_init.ECRxCH",
                FT_BOOLEAN,
                16,
                NULL,
                0x4000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_xid_prof_exch,
            {
                "XID profile exchange",
                "sprt.payload.msg_init.XID_profile_exch",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x2000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_assym_data_types,
            {
                "Assymetrical data types",
                "sprt.payload.msg_init.assym_data_types",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x1000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_opt_moip_types_i_raw_bit,
            {
                "I_RAW-BIT",
                "sprt.payload.msg_init.opt_moip_types_i_raw_bit",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x0800,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_opt_moip_types_i_frame,
            {
                "I_FRAME",
                "sprt.payload.msg_init.opt_moip_types_i_frame",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x0400,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_opt_moip_types_i_char_stat,
            {
                "I_CHAR-STAT",
                "sprt.payload.msg_init.opt_moip_types_i_char_stat",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x0200,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_opt_moip_types_i_char_dyn,
            {
                "I_CHAR-DYN",
                "sprt.payload.msg_init.opt_moip_types_i_char_dyn",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x0100,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_opt_moip_types_i_octet_cs,
            {
                "I_OCTET-CS",
                "sprt.payload.msg_init.opt_moip_types_i_octet_cs",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x0080,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_opt_moip_types_i_char_stat_cs,
            {
                "I_CHAR-STAT-CS",
                "sprt.payload.msg_init.opt_moip_types_i_char_stat_cs",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x0040,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_opt_moip_types_i_char_dyn_cs,
            {
                "I_CHAR-DYN-CS",
                "sprt.payload.msg_init.opt_moip_types_i_char_dyn_cs",
                FT_BOOLEAN,
                16,
                TFS(&tfs_supported_not_supported),
                0x0020,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_init_opt_moip_types_reserved,
            {
                "Reserved for ITU-T",
                "sprt.payload.msg_init.opt_moip_types_reserved",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x001F,
                NULL, HFILL
            }
        },
        /* XID_XCHG message */
        {
            &hf_sprt_payload_msg_xidxchg_ecp,
            {
                "Error correcting protocol",
                "sprt.payload.msg_xidxchg.ecp",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_ecp_name),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr1_v42bis,
            {
                "V.42 bis",
                "sprt.payload.msg_xidxchg.xidlr1_v42bis",
                FT_BOOLEAN,
                8,
                TFS(&tfs_supported_not_supported),
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr1_v44,
            {
                "V.44",
                "sprt.payload.msg_xidxchg.xidlr1_v44",
                FT_BOOLEAN,
                8,
                TFS(&tfs_supported_not_supported),
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr1_mnp5,
            {
                "MNP5",
                "sprt.payload.msg_xidxchg.xidlr1_mnp5",
                FT_BOOLEAN,
                8,
                TFS(&tfs_supported_not_supported),
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr1_reserved,
            {
                "Reserved for ITU-T",
                "sprt.payload.msg_xidxchg.xidlr1_reserved",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x1F,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr2_v42bis_compr_req,
            {
                "V.42bis data compression request",
                "sprt.payload.msg_xidxchg.xidlr2_v42bis_compr_req",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr3and4_v42bis_num_codewords,
            {
                "V.42bis number of codewords",
                "sprt.payload.msg_xidxchg.xidlr3and4_v42bis_num_codewords",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr5_v42bis_max_strlen,
            {
                "V.42bis maximum string length",
                "sprt.payload.msg_xidxchg.xidlr5_v42bis_max_strlen",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr6_v44_capability,
            {
                "V.44 capability",
                "sprt.payload.msg_xidxchg.xidlr6_v44_capability",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr7_v44_compr_req,
            {
                "V.44 data compression request",
                "sprt.payload.msg_xidxchg.xidlr7_v44_compr_req",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr8and9_v44_num_codewords_trans,
            {
                "V.44 number of codewords in transmit direction",
                "sprt.payload.msg_xidxchg.xidlr8and9_v44_num_codewords_trans",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr10and11_v44_num_codewords_recv,
            {
                "V.44 number of codewords in receive direction",
                "sprt.payload.msg_xidxchg.xidlr10and11_v44_num_codewords_recv",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr12_v44_max_strlen_trans,
            {
                "V.44 maximum string length in transmit direction",
                "sprt.payload.msg_xidxchg.xidlr12_v44_max_strlen_trans",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr13_v44_max_strlen_recv,
            {
                "V.44 maximum string length in receive direction",
                "sprt.payload.msg_xidxchg.xidlr13_v44_max_strlen_recv",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr14and15_v44_history_len_trans,
            {
                "V.44 length of history in transmit direction",
                "sprt.payload.msg_xidxchg.xidlr14and15_v44_history_len_trans",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_xidxchg_xidlr16and17_v44_history_len_recv,
            {
                "V.44 length of history in receive direction",
                "sprt.payload.msg_xidxchg.xidlr16and17_v44_history_len_recv",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* JM_INFO message */
        {
            &hf_sprt_payload_msg_jminfo_category_data,
            {
                "Category data",
                "sprt.payload.msg_jminfo.category_data",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0xFFFF,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_category_id,
            {
                "Category ID",
                "sprt.payload.msg_jminfo.category_id",
                FT_UINT16,
                BASE_HEX,
                VALS(sprt_jm_info_cat_id_name),
                0xF000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_category_ext_info,
            {
                "Unrecognized category data",
                "sprt.payload.msg_jminfo.category_ext_info",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0FFF,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_unk_category_info,
            {
                "Category extension data",
                "sprt.payload.msg_jminfo.unk_category_info",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0FFF,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_category_leftover_bits,
            {
                "Leftover bits", /* "Category info leftover bits", */
                "sprt.payload.msg_jminfo.category_leftover_bits",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x01FF,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_call_function,
            {
                "Call function",
                "sprt.payload.msg_jminfo.call_function",
                FT_UINT16,
                BASE_DEC,
                VALS(sprt_jminfo_tbc_call_funct_name),
                0x0E00,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v34_duplex,
            {
                "V.34 duplex",
                "sprt.payload.msg_jminfo.mod_v34_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0800,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v34_half_duplex,
            {
                "V.34 half-duplex",
                "sprt.payload.msg_jminfo.mod_v34_half_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0400,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v32bis_v32,
            {
                "V.32bis/V.32",
                "sprt.payload.msg_jminfo.mod_v32bis_v32",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0200,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v22bis_v22,
            {
                "V.22bis/V.22",
                "sprt.payload.msg_jminfo.mod_v22bis_v22",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0100,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v17,
            {
                "V.17",
                "sprt.payload.msg_jminfo.mod_v17",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0080,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v29_half_duplex,
            {
                "V.29 half-duplex",
                "sprt.payload.msg_jminfo.mod_v29_half_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0040,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v27ter,
            {
                "V.27ter",
                "sprt.payload.msg_jminfo.mod_v27ter",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0020,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v26ter,
            {
                "V.26ter",
                "sprt.payload.msg_jminfo.mod_v26ter",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0010,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v26bis,
            {
                "V.26bis",
                "sprt.payload.msg_jminfo.mod_v16bis",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0008,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v23_duplex,
            {
                "V.23 duplex",
                "sprt.payload.msg_jminfo.mod_v23_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0004,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v23_half_duplex,
            {
                "V.23 half-duplex",
                "sprt.payload.msg_jminfo.mod_v23_half_duplex",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0002,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_mod_v21,
            {
                "V.21",
                "sprt.payload.msg_jminfo.mod_v21",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0001,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_protocols,
            {
                "Protocols",
                "sprt.payload.msg_jminfo.protocols",
                FT_UINT16,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_jminfo_tbc_protocol_name),
                0x0E00,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_pstn_access_call_dce_cell,
            {
                "Call DCE is on a cellular connection",
                "sprt.payload.msg_jminfo.pstn_access_call_dce_cell",
                FT_BOOLEAN,
                16,
                NULL,
                0x0800,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_pstn_access_answ_dce_cell,
            {
                "Answer DCE is on a cellular connection",
                "sprt.payload.msg_jminfo.pstn_access_answ_dce_cell",
                FT_BOOLEAN,
                16,
                NULL,
                0x0400,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_pstn_access_dce_on_digital_net,
            {
                "DCE is on a digital network connection",
                "sprt.payload.msg_jminfo.pstn_access_dce_on_digital_net",
                FT_BOOLEAN,
                16,
                NULL,
                0x0200,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_pcm_modem_avail_v90_v92_analog,
            {
                "V.90 or V.92 analog modem availability",
                "sprt.payload.msg_jminfo.pcm_modem_avail_v90_v92_analog",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0800,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_pcm_modem_avail_v90_v92_digital,
            {
                "V.90 or V.92 digital modem availability",
                "sprt.payload.msg_jminfo.pcm_modem_avail_v90_v92_digital",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0400,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_jminfo_pcm_modem_avail_v91,
            {
                "V.91 modem availability",
                "sprt.payload.msg_jminfo.pcm_modem_avail_v91",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0200,
                NULL, HFILL
            }
        },
        /* START_JM message has no additional fields */
        /* CONNECT message */
        {
            &hf_sprt_payload_msg_connect_selmod,
            {
                "Selected modulation",
                "sprt.payload.msg_connect.selmod",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_selmod_name),
                0xFC,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_compr_dir,
            {
                "Compression direction",
                "sprt.payload.msg_connect.compr_dir",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_comp_direction),
                0x03,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_selected_compr,
            {
                "Selected compression",
                "sprt.payload.msg_connect.selected_compr",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_selected_compr_name),
                0xF0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_selected_err_corr,
            {
                "Selected error correction",
                "sprt.payload.msg_connect.selected_err_corr",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_selected_err_corr_name),
                0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_tdsr,
            {
                "Transmit data signalling rate (bits/sec)",
                "sprt.payload.msg_connect.tdsr",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_rdsr,
            {
                "Receive data signalling rate (bits/sec)",
                "sprt.payload.msg_connect.rdsr",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_dlci_enabled,
            {
                "DLCI",
                "sprt.payload.msg_connect.dlci_enabled",
                FT_BOOLEAN,
                16,
                TFS(&tfs_enabled_disabled),
                0x8000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_avail_data_types,
            {
                "Available data types",
                "sprt.payload.msg_connect.avail_data_types",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x7FFF,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_adt_octet_no_format_no_dlci,
            {
                "Octet w/o formatting with no DLCI",
                "sprt.payload.msg_connect.adt_octet_no_format_no_dlci",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x4000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_adt_i_raw_bit,
            {
                "I_RAW-BIT",
                "sprt.payload.msg_connect.adt_i_raw_bit",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x2000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_adt_i_frame,
            {
                "I_FRAME",
                "sprt.payload.msg_connect.adt_i_frame",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x1000,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_adt_i_char_stat,
            {
                "I_CHAR-STAT",
                "sprt.payload.msg_connect.adt_i_char_stat",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0800,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_adt_i_char_dyn,
            {
                "I_CHAR-DYN",
                "sprt.payload.msg_connect.adt_i_char_dyn",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0400,
                NULL, HFILL
            }
        },
        { /* from V.150.1 amendment 2 (5-2006): */
            &hf_sprt_payload_msg_connect_adt_i_octet_cs,
            {
                "I_OCTET-CS",
                "sprt.payload.msg_connect.adt_i_octet_cs",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0200,
                NULL, HFILL
            }
        },
        { /* from V.150.1 amendment 2 (5-2006): */
            &hf_sprt_payload_msg_connect_adt_i_char_stat_cs,
            {
                "I_CHAR-STAT-CS",
                "sprt.payload.msg_connect.adt_i_char_stat_cs",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0100,
                NULL, HFILL
            }
        },
        { /* from V.150.1 amendment 2 (5-2006): */
            &hf_sprt_payload_msg_connect_adt_i_char_dyn_cs,
            {
                "I_CHAR-DYN-CS",
                "sprt.payload.msg_connect.adt_i_char_dyn_cs",
                FT_BOOLEAN,
                16,
                TFS(&tfs_available_not_available),
                0x0080,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_adt_reserved,
            {
                "Reserved for ITU-T",
                "sprt.payload.msg_connect.adt_reserved",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x007F,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_compr_trans_dict_sz,
            {
                "Compression transmit dictionary size",
                "sprt.payload.msg_connect.compr_trans_dict_sz",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_compr_recv_dict_sz,
            {
                "Compression receive dictionary size",
                "sprt.payload.msg_connect.compr_recv_dict_sz",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_compr_trans_str_len,
            {
                "Compression transmit string length",
                "sprt.payload.msg_connect.compr_trans_str_len",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_compr_recv_str_len,
            {
                "Compression receive string length",
                "sprt.payload.msg_connect.compr_recv_str_len",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_compr_trans_hist_sz,
            {
                "Compression transmit history size",
                "sprt.payload.msg_connect.compr_trans_hist_sz",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_connect_compr_recv_hist_sz,
            {
                "Compression receive history size",
                "sprt.payload.msg_connect.compr_recv_hist_sz",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* BREAK message */
        {
            &hf_sprt_payload_msg_break_source_proto,
            {
                "Break source protocol",
                "sprt.payload.msg_break.source_proto",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_break_src_proto_name),
                0xF0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_break_type,
            {
                "Break type",
                "sprt.payload.msg_break.type",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_break_type_name),
                0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_break_length,
            {
                "Break length (x10 msec)",
                "sprt.payload.msg_break.length",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* BREAK_ACK message has no additional fields */
        /* MR_EVENT message */
        {
            &hf_sprt_payload_msg_mr_event_id,
            {
                "Modem relay event ID",
                "sprt.payload.msg_mr_event.id",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_mrevent_id_name),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_mr_evt_reason_code,
            {
                "Reason code",
                "sprt.payload.msg_mr_event.reason_code",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_mrevent_reason_code_name),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_mr_evt_selmod,
            {
                "Selected modulation",
                "sprt.payload.msg_mr_event.selmod",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_selmod_name),
                0xFC,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_mr_evt_txsen,
            {
                "TxSEN",
                "sprt.payload.msg_mr_event.txsen",
                FT_BOOLEAN,
                8,
                TFS(&tfs_enabled_disabled),
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_mr_evt_rxsen,
            {
                "RxSEN",
                "sprt.payload.msg_mr_event.rxsen",
                FT_BOOLEAN,
                8,
                TFS(&tfs_enabled_disabled),
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_mr_evt_tdsr,
            {
                "Transmit data signalling rate (bits/sec)",
                "sprt.payload.msg_mr_event.tdsr",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_mr_evt_rdsr,
            {
                "Receive data signalling rate (bits/sec)",
                "sprt.payload.msg_mr_event.rdsr",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_mr_evt_txsr,
            {
                "Physical layer transmitter symbol rate (TxSR)",
                "sprt.payload.msg_mr_event.txsr",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_mrevent_phys_layer_symbol_rate),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_mr_evt_rxsr,
            {
                "Physical layer receiver symbol rate (RxSR)",
                "sprt.payload.msg_mr_event.rxsr",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_mrevent_phys_layer_symbol_rate),
                0x0,
                NULL, HFILL
            }
        },
        /* CLEARDOWN message */
        {
            &hf_sprt_payload_msg_cleardown_reason_code,
            {
                "Reason code",
                "sprt.payload.msg_cleardown.reason_code",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_cleardown_reason),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_cleardown_vendor_tag,
            {
                "Vendor tag",
                "sprt.payload.msg_cleardown.vendor_tag",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_cleardown_vendor_info,
            {
                "Vendor info",
                "sprt.payload.msg_cleardown.vendor_info",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* PROF_XCHG message */
        {
            &hf_sprt_payload_msg_profxchg_v42_lapm,
            {
                "V.42/LAPM protocol support",
                "sprt.payload.msg_profxchg.v42_lapm",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_prof_xchg_support),
                0xC0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_annex_av42,
            {
                "Annex A/V.42(1996) protocol support",
                "sprt.payload.msg_profxchg.annex_av42",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_prof_xchg_support),
                0x30,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_v44_compr,
            {
                "V.44 compression support",
                "sprt.payload.msg_profxchg.v44_compr",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_prof_xchg_support),
                0x0C,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_v42bis_compr,
            {
                "V.42bis compression support",
                "sprt.payload.msg_profxchg.v42bis_compr",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_prof_xchg_support),
                0x03,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_mnp5_compr,
            {
                "MNP5 compression support",
                "sprt.payload.msg_profxchg.mnp5_compr",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_prof_xchg_support),
                0xC0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_reserved,
            {
                "Reserved for ITU-T",
                "sprt.payload.msg_profxchg.reserved",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x3F,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr2_v42bis_compr_req,
            {
                "V.42bis data compression request",
                "sprt.payload.msg_profxchg.xidlr2_v42bis_compr_req",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr3and4_v42bis_num_codewords,
            {
                "V.42bis number of codewords",
                "sprt.payload.msg_profxchg.xidlr3and4_v42bis_num_codewords",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr5_v42bis_max_strlen,
            {
                "V.42bis maximum string length",
                "sprt.payload.msg_profxchg.xidlr5_v42bis_max_strlen",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr6_v44_capability,
            {
                "V.44 capability",
                "sprt.payload.msg_profxchg.xidlr6_v44_capability",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr7_v44_compr_req,
            {
                "V.44 data compression request",
                "sprt.payload.msg_profxchg.xidlr7_v44_compr_req",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr8and9_v44_num_codewords_trans,
            {
                "V.44 number of codewords in transmit direction",
                "sprt.payload.msg_profxchg.xidlr8and9_v44_num_codewords_trans",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr10and11_v44_num_codewords_recv,
            {
                "V.44 number of codewords in receive direction",
                "sprt.payload.msg_profxchg.xidlr10and11_v44_num_codewords_recv",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr12_v44_max_strlen_trans,
            {
                "V.44 maximum string length in transmit direction",
                "sprt.payload.msg_profxchg.xidlr12_v44_max_strlen_trans",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr13_v44_max_strlen_recv,
            {
                "V.44 maximum string length in receive direction",
                "sprt.payload.msg_profxchg.xidlr13_v44_max_strlen_recv",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr14and15_v44_history_len_trans,
            {
                "V.44 length of history in transmit direction",
                "sprt.payload.msg_profxchg.xidlr14and15_v44_history_len_trans",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_msg_profxchg_xidlr16and17_v44_history_len_recv,
            {
                "V.44 length of history in receive direction",
                "sprt.payload.msg_profxchg.xidlr16and17_v44_history_len_recv",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* User data messages... */
        /* I_OCTET message: need to use DLCI field (8 or 16 bits) if indicated by CONNECT message */
        {
            &hf_sprt_payload_i_octet_no_dlci,
            {
                "No DLCI field",
                "sprt.payload.i_octet_no_dlci",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_i_octet_dlci_presence_unknown,
            {
                "Not known if DLCI field is present",
                "sprt.payload.i_octet_dlci_presence_unknown",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_i_octet_dlci1,
            {
                "DLCI #1",
                "sprt.payload.i_octet_dlci1",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_payload_dlci1),
                0xFC,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_i_octet_cr,
            {
                "Command/response bit",
                "sprt.payload.i_octet_cr",
                FT_BOOLEAN,
                8,
                NULL,
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_i_octet_ea,
            {
                "Address field extension bit",
                "sprt.payload.i_octet_ea",
                FT_BOOLEAN,
                8,
                TFS(&sprt_payload_ea_bit),
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_i_octet_dlci2,
            {
                "DLCI #2",
                "sprt.payload.i_octet_dlci2",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(sprt_payload_dlci2),
                0xFE,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_i_octet_dlci_setup_by_connect_frame,
            {
                "DLCI setup by CONNECT message at frame",
                "sprt.payload.i_octet_dlci_setup_by_connect_frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* fields for I_RAW_OCTET message (L; L,N) */
        {
            &hf_sprt_payload_rawoctet_n_field_present,
            {
                "N field",
                "sprt.payload.rawoctet_n_field_present",
                FT_BOOLEAN,
                8,
                TFS(&tfs_present_absent),
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawoctet_l,
            {
                "L: # of octets in segment minus one",
                "sprt.payload.rawoctet_l",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7F,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawoctet_n,
            {
                "N: # of times octets appear in data minus 2",
                "sprt.payload.rawoctet_n",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xFF,
                NULL, HFILL
            }
        },
        /* fields for I_RAW_BIT (L; L,P; L,P,N) */
        {
            &hf_sprt_payload_rawbit_included_fields_l,
            {
                "Include field L only",
                "sprt.payload.rawbit_included_fields_l",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xC0, /* top two bits: 00 */
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawbit_included_fields_lp,
            {
                "Include fields L, P",
                "sprt.payload.rawbit_field_format_lp",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xC0, /* top two bits: 01 */
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawbit_included_fields_lpn,
            {
                "Include fields L, P, N",
                "sprt.payload.rawbit_included_fields_lpn",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x80, /* top bit: 1 */
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawbit_len_a,
            {
                "L: # of octets in segment",
                "sprt.payload.rawbit_len_a",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x3F, /* six bits */
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawbit_len_b,
            {
                "L: # of octets in segment",
                "sprt.payload.rawbit_len_b",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x38, /* three bits */
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawbit_len_c,
            {
                "L: # of octets in segment",
                "sprt.payload.rawbit_len_c",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x78, /* four bits */
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawbit_p,
            {
                "P: # of low-order bits in last octet that are not in segment",
                "sprt.payload.rawbit_p",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7, /* three bits */
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_rawbit_n,
            {
                "N: # of times octets appear in data minus 2",
                "sprt.payload.rawbit_n",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xFF, /* eight bits */
                NULL, HFILL
            }
        },
        /* fields in I_CHAR_STAT & I_CHAR_DYN messages */
        {
            &hf_sprt_payload_data_reserved_bit,
            {
                "Reserved bit",
                "sprt.payload.reserved_bit",
                FT_BOOLEAN,
                8,
                TFS(&tfs_set_notset),
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_data_num_data_bits,
            {
                "D: Number of data bits",
                "sprt.payload.num_data_bits",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_payload_data_bits),
                0x60,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_data_parity_type,
            {
                "P: Parity type",
                "sprt.payload.parity_type",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_payload_parity),
                0x1C,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_num_stop_bits,
            {
                "S: Number stop bits",
                "sprt.payload.num_stop_bits",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_payload_stop_bits),
                0x03,
                NULL, HFILL
            }
        },
        /* sequence field in I_OCTET_CS, I_CHAR_STAT_CS, & I_CHAR_DYN_CS messages */
        {
            &hf_sprt_payload_data_cs,
            {
                "Character sequence number",
                "sprt.payload.cs",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* fields for I_FRAME: */
        {
            &hf_sprt_payload_frame_reserved_bits,
            {
                "Reserved bits",
                "sprt.payload.frame_reserved_bits",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0xFC,
                NULL, HFILL
            }
        },
        {
            &hf_sprt_payload_frame_state,
            {
                "Frame state",
                "sprt.payload.frame_state",
                FT_UINT8,
                BASE_DEC,
                VALS(sprt_payload_frame_state),
                0x03,
                NULL, HFILL
            }
        },
        /* just dump remaining payload data: */
        {
            &hf_sprt_payload_data,
            {
                "Payload data",
                "sprt.payload.data",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    }; /* hf_register_info hf[] */

    /* setup protocol subtree array */
    static gint *ett[] = {
        &ett_sprt,
        &ett_sprt_setup,
        &ett_sprt_ack_fields,
        &ett_payload,
        &ett_init_msg_all_fields,
        &ett_jminfo_msg_cat_data,
        &ett_connect_msg_adt
    };

    static ei_register_info ei[] = {
        { &ei_sprt_sequence_number_0, { "sprt.sequence_number_0", PI_PROTOCOL, PI_WARN, "Should be 0 for transport channel 0", EXPFILL }},
    };

    /* register protocol name & description */
    proto_sprt = proto_register_protocol("Simple Packet Relay Transport", "SPRT", "sprt");

    /* required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_sprt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_sprt = expert_register_protocol(proto_sprt);
    expert_register_field_array(expert_sprt, ei, array_length(ei));

    /* register the dissector */
    new_register_dissector("sprt", dissect_sprt, proto_sprt);

    sprt_module = prefs_register_protocol(proto_sprt, NULL);

    /* preferences */
    prefs_register_bool_preference(sprt_module, "show_setup_info",
                                    "Show stream setup information",
                                    "Where available, show which protocol and frame caused "
                                    "this SPRT stream to be created",
                                    &global_sprt_show_setup_info);
    prefs_register_bool_preference(sprt_module, "show_dlci_info",
                                    "Show DLCI in I_OCTET messages",
                                    "Show the DLCI field in I_OCTET messages as well as the frame that "
                                    "enabled/disabled the DLCI",
                                    &global_sprt_show_dlci_info);

}

void
proto_reg_handoff_sprt(void)
{
    sprt_handle = find_dissector("sprt");
    dissector_add_for_decode_as("udp.port", sprt_handle);

    heur_dissector_add( "udp", dissect_sprt_heur, proto_sprt);
}
