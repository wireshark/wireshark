/* packet-bssgp.c
 * Routines for BSSGP (BSS GPRS Protocol ETSI GSM 08.18 version 6.7.1 TS 101 343 ) dissection
 * Copyright 2000, Josef Korelus <jkor@quick.cz>
 *
 * $Id: packet-bssgp.c,v 1.8 2003/12/28 12:43:38 ulfl Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
/*#include "packet-bssgp.h"*/


/*PDU Type GSM 08.18 version 6.7.1 table 11.27 page 53*/
#define DL_UNITDATA                     0x0
#define UL_UNITDATA                     0x1
#define RA_CAPABILITY                   0X2
#define PTM_UNITDAT                     0X3
#define PAGING_PS                       0X6
#define PAGING_CS                       0x7
#define RA_CAPABILITY_UPDATE            0X8
#define RA_CAPABILITY_UPDATE_ACK        0X9
#define RADIO_STATUS                    0xa
#define SUSPEND                         0xb
#define SUSPEND_ACK                     0xc
#define SUSPEND_NACK                    0xd
#define RESUME                          0xe
#define RESUME_ACK                      0xf
#define RESUME_NACK                     0x10
#define BVC_BLOCK                       0x20
#define BVC_BLOCK_ACK                   0x21
#define BVC_RESET                       0X22
#define BVC_RESET_ACK                   0X23
#define BVC_UNBLOCK                     0x24
#define BVC_UNBLOCK_ACK                 0x25
#define FLOW_CONTROL_BVC                0x26
#define FLOW_CONTROL_BVC_ACK            0x27
#define FLOW_CONTROL_MS                 0x28
#define FLOW_CONTROL_MS_ACK             0x29
#define FLUSH_LL                        0x2a
#define FLUSH_LL_ACK                    0x2b
#define LLC_DISCARDED                   0x2c
#define SGSN_INVOKE_TRACE               0x40
#define STATUS                          0x41


#define BSSGP_M 1
#define BSSGP_O 2
#define BSSGP_C 3

#define QOSO5CR				0x20
#define QOSO5T				0x10
#define QOSO5A				0x08
#define LOW3B				0x07
#define ODD_EVEN_INDIC			0x08
/*GSM 08.18 version 6.7.1 table 11.27*/

static const value_string tab_bssgp_pdu_type[] = {
        { DL_UNITDATA,              "DL-UNITDATA" },    
        { UL_UNITDATA,              "UL-UNITDATA" },                    
        { RA_CAPABILITY,            "RA_CAPABILITY" },                  
        { PTM_UNITDAT,              "PTM-UNITDATA" },   
        { PAGING_PS,                "PAGING PS" },      
        { PAGING_CS,                "PAGING CS" },      
        { RA_CAPABILITY_UPDATE,     "RA-CAPABILITY-UPDATE" },   
        { RA_CAPABILITY_UPDATE_ACK, "RA-CAPABILITY-UPDATE-ACK" },       
        { RADIO_STATUS,             "RADIO-STATUS" },           
        { SUSPEND,                  "SUSPEND" },                        
        { SUSPEND_ACK,              "SUSPEND-ACK" },    
        { SUSPEND_NACK,             "SUSPEND-NACK" },                   
        { RESUME,                   "RESUME" },                         
        { RESUME_ACK,               "RESUME-ACK" },                     
        { RESUME_NACK,              "RESUME-NACK" },                    
        { BVC_BLOCK,                "BVC-BLOCK" },      
        { BVC_BLOCK_ACK,            "BVC-BLOCK-ACK" },
        { BVC_RESET,                "BVC-RESET" },      
        { BVC_RESET_ACK,            "BVC-RESET-ACK" },                  
        { BVC_UNBLOCK,              "BVC-UNBLOCK" },                    
        { BVC_UNBLOCK_ACK,          "BVC_UNBLOCK_ACK" },                        
        { FLOW_CONTROL_BVC,         "FLOW-CONTROL-BVC" },               
        { FLOW_CONTROL_BVC_ACK,     "FLOW-CONTROL-BVC-ACK" },           
        { FLOW_CONTROL_MS,          "FLOW-CONTROL-MS" },                        
        { FLOW_CONTROL_MS_ACK,      "FLOW-CONTROL-MS-ACK" },            
        { FLUSH_LL,                 "FLUSH-LL" },               
        { FLUSH_LL_ACK,             "FLUSH-LL-ACK" },   
        { LLC_DISCARDED,            "LLC-DISCARDED" },                  
        { SGSN_INVOKE_TRACE,        "SGSN_INVOKE_TRACE" },      
        { STATUS,                   "STATUS" },
        { 0,                        NULL },
};
        
static const value_string bssgp_iei[] = {
        { 0x0,   "Alignment Octets" },
	{ 0x1,   "Bmax default MS" },
	{ 0x2,   "BSS Area Indication" },
	{ 0x3,   "Bucket Leak Rate" },
	{ 0x4,   "BVCI" },
	{ 0x5,   "BVC Bucket Size" },
	{ 0x6,   "BVC Measurment" },
	{ 0x7,   "Cause" },
	{ 0x8,   "Cell Identifier" },
	{ 0x9,   "Channel needed" },
	{ 0xa,   "DRX Parameters" },
	{ 0xb,   "eMLPP-Priority" },
	{ 0xc,   "Flush Action" },
	{ 0xd,   "IMSI" },
	{ 0xe,   "LLC-PDU"},
	{ 0xf,   "LLC Frames Discarded" },
	{ 0x10,  "Location Area" },
	{ 0x11,  "Mobile Id" },
	{ 0x12,  "MS Bucket Size" },
	{ 0x13,  "MS Radio Access Capability" },
	{ 0x14,  "OMC Id" },
	{ 0x15,  "PDU In Error" },
	{ 0x16,  "PDU Lifetime" },
	{ 0x17,  "Priority" },
	{ 0x18,  "QoS Profile" },
	{ 0x19,  "Radio Cause" },
	{ 0x1a,  "RA-Cap-UPD-Cause" },
	{ 0x1b,  "Routeing Area" },
	{ 0x1c,  "R_default_MS" },
	{ 0x1d,  "Suspend Reference Number" },
	{ 0x1e,  "Tag" },
	{ 0x1f,  "TLLI" },
	{ 0x20,  "TMSI" },
	{ 0x21,  "Trace Reference" },
	{ 0x22,  "Trace Type" },
	{ 0x23,  "Transaction Id" },
	{ 0x24,  "Trigger Id" },
	{ 0x25,  "Number of octets affected" },
	{ 0, NULL },
};

static const value_string bssgp_cause[] = {
        { 0x0,  "Processor overload" },
	{ 0x1,  "Equipment failure"  },
	{ 0x2,  "Transit network service failure" },
	{ 0x3,  "Network service transmission capacity modified from zero kbps to greater than zero" },
	{ 0x4,  "Unknown MS" },
	{ 0x5,  "BVCI unknown" },
	{ 0x6,  "Cell traffic congestion" },
	{ 0x7,  "SGSN congestion" },
	{ 0x8,  "O&M intervention" },
	{ 0x9,  "BVCI-blocked" },
	{ 0x20, "Semantically incorect PDU" },
	{ 0x21, "Invalid mandatory information" },
	{ 0x22, "Missing mandatory information" },
	{ 0x23, "Missing conditional IE" },
	{ 0x24, "Unexpected conditional IE" },
	{ 0x25, "Conditional IE error" },
	{ 0x26, "PDU not compatible with protocol state" },
	{ 0x27, "Protocol error-unspecified" },
	{ 0,   NULL },
};

#define TOI_IMSI	0x01
#define TOI_IMEI	0x02
#define TOI_IMEISV	0x03
#define TOI_TMSI_P_TMSI	0x04
#define TOI_NO_IDENTITY	0x00

static const value_string type_of_identity[] = {
	{ TOI_IMSI,        "IMSI" },
	{ TOI_IMEI,        "IMEI" },
     	{ TOI_IMEISV,      "IMEISV" },
	{ TOI_TMSI_P_TMSI, "TMSI/P-TMSI" },
	{ TOI_NO_IDENTITY, "No identity" },
	{ 0,	NULL },	
};
static const value_string radio_cause[] = {
	{ 0x0, "Radio contact lost with the MS" },
	{ 0x1, "Radio link quality insufficient to continue communication" },
	{ 0x2, "cell-reselction ordered" },
	{ 0, NULL },
};
static const true_false_string cr_string = {
	"The SDU does not contain a LLC ACK or SACK command/response frame type",
	"The SDU contains a LLC ACK or SACK command/response frame type",
};
static const true_false_string t_string = {
	"The SDU contains data",
	"The SDU contains signalling "
};
static const true_false_string a_string = {
	"Radio interface uses RLC/MAC-UNITDATA functionality",
	"Radio interface uses RLC/MAC ARQ functionality"
};
static const true_false_string imsi_odd_even = {
	"even number of identity digits and also when the TMSI/P-TMSI is used",
	"odd number of identity digits"
};
static const value_string prec_dl[] = {
	{ 0, "High priority"},
	{ 1, "Normal priority"},
	{ 2, "Low priority"},
	{ 3, "Reserved:Taken like Low priority"},
	{ 4, "Reserved:Taken like Low priority"},
	{ 0, NULL},
};	
static const value_string prec[] = {
	{ 0, "Radio priority 1" },
	{ 1, "Radio priority 2" },
	{ 2, "Radio priority 3" },
	{ 3, "Radio priority 4" },
	{ 4, "Radio priority Unknown" },
	{ 0, NULL },
};
static const value_string prec_both[] = {
	{ 0, "High priority/Radio priority 1"},
	{ 1, "Normal priority/Radio priority 2"},
	{ 2, "Low priority/Radio priority 3"},
	{ 3, "Reserved/Radio priority 4"},
	{ 4, "Reserved/Radio priority Unknown"},
	{ 0, NULL},
};

/* Initialize the protocol and registered fields */
static int proto_bssgp = -1;
static int hf_bssgp_pdu_type= -1;
static int hf_bssgp_cause = -1;
static int hf_bssgp_cid = -1;
static int hf_bssgp_imsi = -1;
static int hf_bssgp_imsi_toi = -1;
static int hf_bssgp_imsi_even_odd_indic = -1;
static int hf_bssgp_imsi_lsix = -1;
static int hf_bssgp_tlli = -1;
/*static int hf_bssgp_tag = -1;
static int hf_bssgp_tlli_old = -1;
static int hf_bssgp_aligment = -1;
static int hf_bssgp_drx_param = -1;
static int hf_bssgp_ms_radio_cap = -1;
*/
static int hf_bssgp_qos = -1;
static int hf_bssgp_pbr = -1;
static int hf_bssgp_pdu_lifetime = -1;
/*static int hf_bssgp_priority = -1;
static int hf_bssgp_llc_pdu = -1;
static int hf_bssgp_ptmsi = -1;
*/
static int hf_bssgp_bvci = -1;
/*static int hf_bssgp_la = -1;
*/
static int hf_bssgp_ra_mccmnc = -1;
static int hf_bssgp_ra_lac = -1;
static int hf_bssgp_ra_rac = -1;
/*static int hf_bssgp_bss_area = -1;
static int hf_bssgp_channel_needed = -1;
static int hf_bssgp_emlpp_priority = -1;
static int hf_bssgp_ra_cap_upd_cause = -1;
*/
static int hf_bssgp_radio_cause = -1;
/*static int hf_bssgp_sus_ref_num = -1;
*/
static int hf_bssgp_bvci_new = -1;
/*static int hf_bssgp_flush_action = -1;
static int hf_bssgp_num_oct_affect = -1;
static int hf_bssgp_llc_disc = -1;
*/
static int hf_bssgp_bvc_buck_size = -1;
static int hf_bssgp_buck_leak_rate = -1;
static int hf_bssgp_bmax_def_ms = -1;
static int hf_bssgp_r_defau_ms = -1;
/*static int hf_bssgp_bvc_measur = -1;
static int hf_bssgp_ms_buck_size = -1;
static int hf_bssgp_trace_type = -1;
static int hf_bssgp_trace_ref = -1;
static int hf_bssgp_trigg_id = -1;
static int hf_bssgp_mobile_id = -1;
static int hf_bssgp_omc_id = -1;
static int hf_bssgp_transactionid = -1;
*/
static int hf_bssgp_ietype = -1;
static int hf_bssgp_qos_cr = -1;
static int hf_bssgp_qos_t = -1;
static int hf_bssgp_qos_a = -1;
static int hf_bssgp_qos_prec = -1;
static int hf_bssgp_frdsc = -1;
static int hf_bssgp_noaff = -1;
/*static int hf_bssgp_FIELDABBREV = -1;*/

static dissector_handle_t data_handle;
/*static dissector_handle_t llcgprs_handle;
*/
/* Initialize the subtree pointers */
static gint ett_bssgp = -1;
static gint ett_bssgp_tlli = -1;
static gint ett_bssgp_qos = -1;
static gint ett_bssgp_o5 = -1;
static gint ett_bssgp_lft = -1;
static gint ett_bssgp_racc = -1;
static gint ett_prio_tree = -1;
static gint ett_drx_tree = -1;
static gint ett_bssgp_imsi = -1;
static gint ett_bssgp_imsi_stru_tree = -1;
static gint ett_algn_tree = -1;
static gint ett_b_llc_tree = -1;
static gint ett_celid_tree = -1;
static gint ett_tag_tree = -1;
static gint ett_bsize_tree = -1;
static gint ett_bucklr_tree = -1;
static gint ett_bmaxms_tree = -1;
static gint ett_rdefms_tree = -1;
static gint ett_bvci_tree = -1;
static gint ett_bvcin_tree = -1;
static gint ett_cause_tree = -1;
static gint ett_frdsc_tree = -1;
static gint ett_noaff_tree = -1;
static gint ett_racaus_tree = -1;
static gint ett_ra_tree = -1;
/*Functions for decoding IEs of BSSGP V6.7.1 */
typedef struct {
	int type;
	packet_info *pinfo;
	proto_tree *tree;
	int k;
} dec_fu_param_stru_t;	
static int dcd_bssgp_algn	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_bmaxms	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_bss_aind	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_bucklr	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_bvci	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_bvci_n	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_bvc_bsize	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_bvc_meas	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_cause	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_cellid	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_chan_need	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_drx	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_emlpp_prio	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_flush_act	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_imsi	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_llc_pdu	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_llc_frdsc	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_la		( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_mid	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_ms_buck	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_radio_acc	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_omc_id	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
/*static int dcd_bssgp_pdu_err	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_pdu_life	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_prio	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_qos	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_radio_caus	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_racap_upd	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_ra		( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_r_def_ms	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_sus_ref_num( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_tag	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_tlli	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
/*static int dcd_bssgp_tlli_o	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
/*static int dcd_bssgp_tmsi	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
/*static int dcd_bssgp_trace_ref	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
/*static int dcd_bssgp_trace_type	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
/*static int dcd_bssgp_trans_id	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
/*static int dcd_bssgp_trig_id	( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
*/
static int dcd_bssgp_num_oct_aff( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static int dcd_bssgp_not_yet_dcd( tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm );
static void mccmnc(guint32 mcmn, char buf[]);
/*---------------------------------------------------------*/
typedef struct _bssgp_ie {
	guint8 	code;
	guint8 presence;
	guint8 type;
/*	int (*decode)(tvbuff_t *, int, int, packet_info *, proto_tree *);
*/
	int (*decode)(tvbuff_t *, int, dec_fu_param_stru_t *);
	} bssgp_ie_t;
typedef struct _bssgp_pdu {
	guint8 pdu;
	bssgp_ie_t infe[12];
} _bssgp_pdu_t;
/*------------------------------------------------------------*/
static _bssgp_pdu_t bssgp_pdu[] = {
	{
		DL_UNITDATA, {
			{ 0x1f, BSSGP_M, 3, dcd_bssgp_tlli },
			{ 0x18, BSSGP_M, 3, dcd_bssgp_qos },
			{ 0x16, BSSGP_M, 4, dcd_bssgp_pdu_life },
			{ 0x13, BSSGP_O, 4, dcd_bssgp_radio_acc },
			{ 0x17, BSSGP_O, 4, dcd_bssgp_prio },
			{ 0x0a, BSSGP_O, 4, dcd_bssgp_drx },
			{ 0x0d, BSSGP_O, 4, dcd_bssgp_imsi },
/*			{ 0x1f, BSSGP_O, 4, dcd_bssgp_tlli_o },
*/			
			{ 0x1f, BSSGP_O, 4, dcd_bssgp_not_yet_dcd},
			{ 0x00, BSSGP_O, 4, dcd_bssgp_algn },
			{ 0x0e, BSSGP_M, 4, dcd_bssgp_llc_pdu },
			{ 0,0,0,NULL }
		}	
		
	},
	{
		UL_UNITDATA, {
			{ 0x1f, BSSGP_M, 3, dcd_bssgp_tlli },
			{ 0x18, BSSGP_M, 3, dcd_bssgp_qos },
			{ 0x08, BSSGP_M, 4, dcd_bssgp_cellid },
			{ 0x00, BSSGP_O, 4, dcd_bssgp_algn },
			{ 0x0e, BSSGP_M, 4, dcd_bssgp_llc_pdu },
			{ 0,0,0,NULL }
		}
	},
	{
		RA_CAPABILITY, {
			{ 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x13, BSSGP_M, 4, dcd_bssgp_radio_acc },
			{ 0,0,0,NULL }
		}
	},
	{
		PAGING_PS, {
			{ 0x0d, BSSGP_M, 4, dcd_bssgp_imsi },
			{ 0x0a, BSSGP_O, 4, dcd_bssgp_drx },
			{ 0x04, BSSGP_C, 4, dcd_bssgp_bvci },
/*		        { 0x10, BSSGP_C, 4, dcd_bssgp_la },
*/			
		        { 0x10, BSSGP_C, 4, dcd_bssgp_not_yet_dcd},
			{ 0x1b, BSSGP_C, 4, dcd_bssgp_ra },
/*			{ 0x02, BSSGP_C, 4, dcd_bssgp_bss_aind },
*/			
			{ 0x02, BSSGP_C, 4, dcd_bssgp_not_yet_dcd},
			{ 0x18, BSSGP_M, 4, dcd_bssgp_qos },
/*			{ 0x20, BSSGP_O, 4, dcd_bssgp_tmsi },
*/			
			{ 0x20, BSSGP_O, 4, dcd_bssgp_not_yet_dcd},
			{ 0,0,0,NULL }
		}
	},
	{
		PAGING_CS, {
			{ 0x0d, BSSGP_M, 4, dcd_bssgp_imsi },
			{ 0x0a, BSSGP_M, 4, dcd_bssgp_drx },
			{ 0x04, BSSGP_C, 4, dcd_bssgp_bvci },
/*		        { 0x10, BSSGP_C, 4, dcd_bssgp_la },
*/			
		        { 0x10, BSSGP_C, 4, dcd_bssgp_not_yet_dcd},
			{ 0x1b, BSSGP_C, 4, dcd_bssgp_ra },
/*			{ 0x02, BSSGP_C, 4, dcd_bssgp_bss_aind },
*/			
			{ 0x02, BSSGP_C, 4, dcd_bssgp_not_yet_dcd},
			{ 0x1f, BSSGP_O, 4, dcd_bssgp_tlli },
/*			{ 0x09, BSSGP_O, 4, dcd_bssgp_chan_need },
*/			
			{ 0x09, BSSGP_O, 4, dcd_bssgp_not_yet_dcd},
/*			{ 0x0b, BSSGP_O, 4, dcd_bssgp_emlpp_prio },
*/			
			{ 0x0b, BSSGP_O, 4, dcd_bssgp_not_yet_dcd},
/*			{ 0x20, BSSGP_O, 4, dcd_bssgp_tmsi },
*/			
			{ 0x20, BSSGP_O, 4, dcd_bssgp_not_yet_dcd},
			{ 0,0,0,NULL }
		}
	},
	{
		RA_CAPABILITY_UPDATE, {
			{ 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1e, BSSGP_M, 4, dcd_bssgp_tag },
			{ 0,0,0,NULL }
		}
		
	},
	{
		 RA_CAPABILITY_UPDATE_ACK, {
			{ 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1e, BSSGP_M, 4, dcd_bssgp_tag },
			{ 0x0d, BSSGP_O, 4, dcd_bssgp_imsi },
/*			{ 0x1a, BSSGP_M, 4, dcd_bssgp_racap_upd },
*/			
			{ 0x1a, BSSGP_M, 4, dcd_bssgp_not_yet_dcd},
			{ 0x13, BSSGP_C, 4, dcd_bssgp_radio_acc },
			{ 0,0,0,NULL }
		 }
	},
	{
		RADIO_STATUS, {
			{ 0x1f, BSSGP_C, 4, dcd_bssgp_tlli },
/*			{ 0x20, BSSGP_C, 4, dcd_bssgp_tmsi },
*/			
			{ 0x20, BSSGP_C, 4, dcd_bssgp_not_yet_dcd},
			{ 0x0d, BSSGP_C, 4, dcd_bssgp_imsi },
			{ 0x19, BSSGP_M, 4, dcd_bssgp_radio_caus },
			{ 0,0,0,NULL }
		}
	},
	{
		SUSPEND, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1b, BSSGP_M, 4, dcd_bssgp_ra },
			{ 0,0,0,NULL }
		}
	},
	{
		 SUSPEND_ACK, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1b, BSSGP_M, 4, dcd_bssgp_ra },
/*			{ 0x1d, BSSGP_M, 4, dcd_bssgp_sus_ref_num },
*/			
			{ 0x1d, BSSGP_M, 4, dcd_bssgp_not_yet_dcd},
			{ 0,0,0,NULL }
		 }
	},
	{
		 SUSPEND_NACK, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1b, BSSGP_M, 4, dcd_bssgp_ra },
			{ 0x07, BSSGP_O, 4, dcd_bssgp_cause },
			{ 0,0,0,NULL }
		 }
	},
	{
		RESUME, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1b, BSSGP_M, 4, dcd_bssgp_ra },
/*			{ 0x1d, BSSGP_M, 4, dcd_bssgp_sus_ref_num },
*/			
			{ 0x1d, BSSGP_M, 4, dcd_bssgp_not_yet_dcd},
			{ 0,0,0,NULL }
		}
	},
	{
		RESUME_ACK, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1b, BSSGP_M, 4, dcd_bssgp_ra },
			{ 0,0,0,NULL }
		}
	},
	{
		 RESUME_NACK, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1b, BSSGP_M, 4, dcd_bssgp_ra },
			{ 0x07, BSSGP_O, 4, dcd_bssgp_cause },
			{ 0,0,0,NULL }
		 }
	},
	{
		BVC_BLOCK, {
			{ 0x04, BSSGP_M, 4, dcd_bssgp_bvci },
			{ 0x07, BSSGP_M, 4, dcd_bssgp_cause },
			{ 0,0,0,NULL }
		}
	},
	{
		BVC_BLOCK_ACK, {
			{ 0x04, BSSGP_M, 4, dcd_bssgp_bvci },
			{ 0,0,0,NULL }
		}
	},
	{
		BVC_RESET, {
			{ 0x04, BSSGP_M, 4, dcd_bssgp_bvci },
			{ 0x07, BSSGP_M, 4, dcd_bssgp_cause },
			{ 0x08, BSSGP_C, 4, dcd_bssgp_cellid },
			{ 0,0,0,NULL }
		}
	},
	{
		BVC_RESET_ACK, {
			{ 0x04, BSSGP_M, 4, dcd_bssgp_bvci },
			{ 0x08, BSSGP_C, 4, dcd_bssgp_cellid },
			{ 0,0,0,NULL }
		}
	},
	{
		 BVC_UNBLOCK, {
			{ 0x04, BSSGP_M, 4, dcd_bssgp_bvci },
			{ 0,0,0,NULL }
		 }
	},
	{
		 BVC_UNBLOCK_ACK, {
			{ 0x04, BSSGP_M, 4, dcd_bssgp_bvci },
			{ 0,0,0,NULL }
		 }
	},
	{
		FLOW_CONTROL_BVC, {
			{ 0x1e, BSSGP_M, 4, dcd_bssgp_tag },
			{ 0x05, BSSGP_M, 4, dcd_bssgp_bvc_bsize },
			{ 0x03, BSSGP_M, 4, dcd_bssgp_bucklr },
			{ 0x01, BSSGP_M, 4, dcd_bssgp_bmaxms },
			{ 0x1c, BSSGP_M, 4, dcd_bssgp_r_def_ms },
/*			{ 0x06, BSSGP_O, 4, dcd_bssgp_bvc_meas }, */
			{ 0x06, BSSGP_O, 4, dcd_bssgp_not_yet_dcd },
			{ 0,0,0,NULL }
		}
	},
	{
		 FLOW_CONTROL_BVC_ACK, {
			{ 0x1e, BSSGP_M, 4, dcd_bssgp_tag },
			{ 0,0,0,NULL }
		 }
	},
	{
		 FLOW_CONTROL_MS, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1e, BSSGP_M, 4, dcd_bssgp_tag },
/*			{ 0x12, BSSGP_M, 4, dcd_bssgp_ms_buck},
*/			
			{ 0x12, BSSGP_M, 4, dcd_bssgp_not_yet_dcd},
			{ 0x03, BSSGP_M, 4, dcd_bssgp_bucklr },
			{ 0,0,0,NULL }
		 }
	},
	{
		FLOW_CONTROL_MS_ACK, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x1e, BSSGP_M, 4, dcd_bssgp_tag },
			{ 0,0,0,NULL }
		}
	},
	{
		FLUSH_LL, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x04, BSSGP_M, 4, dcd_bssgp_bvci },
			{ 0x04, BSSGP_O, 4, dcd_bssgp_bvci_n },
			{ 0,0,0,NULL }
		}
	},
	{
		FLUSH_LL_ACK, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
/*			{ 0x0c, BSSGP_M, 4, dcd_bssgp_flush_act },
*/			
			{ 0x0c, BSSGP_M, 4, dcd_bssgp_not_yet_dcd },
			{ 0x04, BSSGP_C, 4, dcd_bssgp_bvci_n },
			{ 0x25, BSSGP_M, 4, dcd_bssgp_num_oct_aff }, 
			{ 0,0,0,NULL }
		}
	},
	{
		LLC_DISCARDED, {
		        { 0x1f, BSSGP_M, 4, dcd_bssgp_tlli },
			{ 0x0f, BSSGP_M, 4, dcd_bssgp_llc_frdsc },
			{ 0x04, BSSGP_M, 4, dcd_bssgp_bvci },
			{ 0x25, BSSGP_M, 4, dcd_bssgp_num_oct_aff }, 
			{ 0,0,0,NULL }
		}
	},
	{
		SGSN_INVOKE_TRACE, {
/*			{ 0x22, BSSGP_M, 4, dcd_bssgp_trace_type },
			{ 0x21, BSSGP_M, 4, dcd_bssgp_trace_ref },
			{ 0x24, BSSGP_O, 4, dcd_bssgp_trig_id },
			{ 0x11, BSSGP_O, 4, dcd_bssgp_mid },
			{ 0x14, BSSGP_O, 4, dcd_bssgp_omc_id },
			{ 0x23, BSSGP_O, 4, dcd_bssgp_trans_id },
*/			
			{ 0x22, BSSGP_M, 4, dcd_bssgp_not_yet_dcd },
			{ 0x21, BSSGP_M, 4, dcd_bssgp_not_yet_dcd },
			{ 0x24, BSSGP_O, 4, dcd_bssgp_not_yet_dcd },
			{ 0x11, BSSGP_O, 4, dcd_bssgp_not_yet_dcd },
			{ 0x14, BSSGP_O, 4, dcd_bssgp_not_yet_dcd },
			{ 0x23, BSSGP_O, 4, dcd_bssgp_not_yet_dcd },
			{ 0,0,0,NULL }
		}
	},
	{
		STATUS, {
			{ 0x07, BSSGP_M, 4, dcd_bssgp_cause },
			{ 0x04, BSSGP_C, 4, dcd_bssgp_bvci },
/*			{ 0x15, BSSGP_O, 4, dcd_bssgp_pdu_err },
*/			
			{ 0x15, BSSGP_O, 4, dcd_bssgp_not_yet_dcd },
			{ 0,0,0,NULL }
		}
	},
	{
		0, {
			{ 0,0,0,NULL }
		}
	}
};
/*-----------------------------------------------------------------------------------------------------------------*/
static void mccmnc(guint32 mcmn, char buf[]){
       typedef struct {
		guint32 mnc1 : 4 ;
   	 	guint32 mnc2 : 4 ;
     		guint32 mcc3 : 4 ;
		guint32	mnc3 : 4 ;
		guint32 mcc1 : 4 ;
		guint32 mcc2 : 4 ;		
	} stru_mncmcc;
	typedef union {
		guint32 i;
		stru_mncmcc s;
	} u_mncmcc;
	u_mncmcc  *r_mncmcc;
	guint8 pom =0,i=0 ;
		r_mncmcc = (u_mncmcc *)&mcmn;
		for (i=0;i<8;i++){
		  switch (i) {
			  case 0 :
				  pom = r_mncmcc->s.mcc1;
			  	break;
			  case 1 :	
				  pom = r_mncmcc->s.mcc2;
				break;
			  case 2 :
				  pom = r_mncmcc->s.mcc3;
				break;
			  case 3 :
			  	  pom = 0x61;/* 0x61 because i need space " " (0x61-1)^0x40*/	
				break;
			  case 4 :
				  pom = r_mncmcc->s.mnc1;
				break;
			  case 5 :
				  pom = r_mncmcc->s.mnc2;
				break;
			  case 6 :
				  pom = r_mncmcc->s.mnc3;	  
			  	  pom = (pom == 0xf)?0x41: pom;/* 0x41 because i need null on the end of string (0x41-1)^0x40*/
				break;
			  case 7 :
				 pom = 0x41;
		       		break;		 
					  
		  }
				  pom = (pom > 9)?(pom-1) ^ 0x40: pom ^ 0x30;
				  buf[i] = pom;
		}
}
static int dcd_bssgp_not_yet_dcd(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){
	guint8 code=0, pom=0,k=2;
	guint16 llen=0;
	
	pom = tvb_get_guint8(tvb,offset+1);
	if ( pom >= 128 ){
		llen = pom & 0x7f;
		k = 2;
	}
	else{ 
		llen = tvb_get_ntohs( tvb, offset+1);
		k=3;	
	}
 	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		proto_tree_add_uint_format(dprm_p->tree,hf_bssgp_ietype,tvb,offset,llen+k,code,"IE type: %s  (%#.2x) ....Not yet decoded",match_strval(code,bssgp_iei),code);
	}
return llen+k;
}
static int dcd_bssgp_algn(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0;
	proto_item *ti=NULL;
	proto_tree *algn_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
 	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "%u Aligment octets", len+2 );
		algn_tree = proto_item_add_subtree(ti, ett_algn_tree);
		proto_tree_add_uint_format(algn_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_text(algn_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}
static int dcd_bssgp_bmaxms(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){  	
	guint8 code=0, len=0;
	guint16 bucket=0;
	proto_item *ti=NULL;
	proto_tree *bmaxms_tree=NULL;
	
 	if (dprm_p->tree){
		len = tvb_get_guint8(tvb,offset+1) & 0x7f;
		code = tvb_get_guint8(tvb,offset);
		bucket = tvb_get_ntohs(tvb,offset+2);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "%s: %u bytes", match_strval(code,bssgp_iei),100*bucket);
		bmaxms_tree = proto_item_add_subtree(ti, ett_bmaxms_tree);
		proto_tree_add_uint_format(bmaxms_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(bmaxms_tree, hf_bssgp_bmax_def_ms,tvb,offset+2,len,bucket,"%s in 100 octet increments: %u (%#.2x)",match_strval(code,bssgp_iei),bucket,bucket);
		proto_tree_add_text(bmaxms_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}
/*static int dcd_bssgp_bss_aind(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/
static int dcd_bssgp_bucklr(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0;
	guint16 bucket=0;
	proto_item *ti=NULL;
	proto_tree *bucklr_tree=NULL;
	
	bucket = tvb_get_ntohs(tvb,offset+2);
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	code = tvb_get_guint8(tvb,offset);
	
	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO, ", %s: %u bits/sec",match_strval(code,bssgp_iei),bucket*100 );
		}	
 	if (dprm_p->tree){
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "Bucket Leak Rate(R): %u bits/sec", 100*bucket);
		bucklr_tree = proto_item_add_subtree(ti, ett_bucklr_tree);
		proto_tree_add_uint_format(bucklr_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(bucklr_tree, hf_bssgp_buck_leak_rate,tvb,offset+2,len,bucket,"%s in 100 bits/sec increments: %u (%#.2x)",match_strval(code,bssgp_iei),bucket,bucket);
		proto_tree_add_text(bucklr_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}
static int dcd_bssgp_bvci(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0;
	guint16 bucket=0;
	proto_item *ti=NULL;
	proto_tree *bvci_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	code = tvb_get_guint8(tvb,offset);
	bucket = tvb_get_ntohs(tvb,offset+2);
	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO, ", %s: %u",match_strval(code,bssgp_iei),bucket );
		}	
 	if (dprm_p->tree){
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "%s: %u", match_strval(code,bssgp_iei), bucket);
		bvci_tree = proto_item_add_subtree(ti, ett_bvci_tree);
		proto_tree_add_uint_format(bvci_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(bvci_tree, hf_bssgp_bvci,tvb,offset+2,len,bucket,"%s: %u (%#.2x)",match_strval(code,bssgp_iei),bucket,bucket);
		proto_tree_add_text(bvci_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}
static int dcd_bssgp_bvci_n(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0;
	guint16 bucket=0;
	proto_item *ti=NULL;
	proto_tree *bvcin_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	code = tvb_get_guint8(tvb,offset);
	bucket = tvb_get_ntohs(tvb,offset+2);
	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO, " New %s: %u",match_strval(code,bssgp_iei),bucket );
		}	
 	if (dprm_p->tree){
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "New %s: %u", match_strval(code,bssgp_iei), bucket);
		bvcin_tree = proto_item_add_subtree(ti, ett_bvcin_tree);
		proto_tree_add_uint_format(bvcin_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s(New) %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(bvcin_tree, hf_bssgp_bvci_new,tvb,offset+2,len,bucket,"New %s: %u (%#.2x)",match_strval(code,bssgp_iei),bucket,bucket);
		proto_tree_add_text(bvcin_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}
static int dcd_bssgp_bvc_bsize(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0;
	guint16 bucket=0;
	proto_item *ti=NULL;
	proto_tree *bsize_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	code = tvb_get_guint8(tvb,offset);
	bucket = tvb_get_ntohs(tvb,offset+2);
	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO, ", %s: %u bytes",match_strval(code,bssgp_iei),bucket*100 );
		}	
 	if (dprm_p->tree){
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "BVC Bucket Size: %u bytes", 100*bucket);
		bsize_tree = proto_item_add_subtree(ti, ett_bsize_tree);
		proto_tree_add_uint_format(bsize_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(bsize_tree, hf_bssgp_bvc_buck_size,tvb,offset+2,len,bucket,"%s in 100 octet increments: %u (%#.2x)",match_strval(code,bssgp_iei),bucket,bucket);
		proto_tree_add_text(bsize_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}
/*static int dcd_bssgp_bvc_meas(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
return 4;
};
*/
static int dcd_bssgp_cause(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0,cause=0;
	proto_item *ti=NULL;
	proto_tree *cause_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	code = tvb_get_guint8(tvb,offset);
	cause = tvb_get_guint8(tvb,offset+2);
	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO, ", %s: %s",match_strval(code,bssgp_iei),match_strval(cause,bssgp_cause));
		}	
 	if (dprm_p->tree){
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "%s: %s", match_strval(code,bssgp_iei),match_strval(cause,bssgp_cause));
		cause_tree = proto_item_add_subtree(ti, ett_cause_tree);
		proto_tree_add_uint_format(cause_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(cause_tree, hf_bssgp_cause,tvb,offset+2,len,cause,"%s: %s (%#.2x)",match_strval(code,bssgp_iei),match_strval(cause,bssgp_cause),cause);
		proto_tree_add_text(cause_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}

static int dcd_bssgp_cellid(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	char mccmnc_str[8];
	guint32 mnccc;
	guint16 lac,cid;
	guint8 len=8, code=0,rac;
	proto_item *ti = NULL;
	proto_tree *celid_tree = NULL;
	
	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		mnccc = tvb_get_ntoh24(tvb,offset+2);
		lac = tvb_get_ntohs(tvb,offset+5);
		rac = tvb_get_guint8(tvb,offset+7);
		cid = tvb_get_ntohs(tvb,offset+8);
                mccmnc(mnccc, mccmnc_str);

		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "Cell Identifier: %s %u %u %u",mccmnc_str,lac,rac,cid);
		celid_tree = proto_item_add_subtree(ti, ett_celid_tree);
		proto_tree_add_uint_format(celid_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_string_format(celid_tree,hf_bssgp_ra_mccmnc,tvb,offset+2,3,mccmnc_str,"MCC MNC: %s",mccmnc_str);
		proto_tree_add_uint_format(celid_tree,hf_bssgp_ra_lac,tvb,offset+5,2,lac,"LAC: %u",lac);
		proto_tree_add_uint_format(celid_tree,hf_bssgp_ra_rac,tvb,offset+7,1,rac,"RAC: %u",rac);
		proto_tree_add_uint_format(celid_tree,hf_bssgp_cid,tvb,offset+8,2,cid,"Cell Id: %u",cid);
		proto_tree_add_text(celid_tree,tvb,offset+1,1,"Length:%u",len);
		
	}
	 
	return len+2;
}

/*static int dcd_bssgp_chan_need(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/
static int dcd_bssgp_drx(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0;
	proto_item *ti=NULL;
	proto_tree *drx_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
 	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, 4,"DRX Parameters");
		drx_tree = proto_item_add_subtree(ti, ett_drx_tree);
		proto_tree_add_uint_format(drx_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_text(drx_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
	
}

/*static int dcd_bssgp_emlpp_prio(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/

/*static int dcd_bssgp_flush_act(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/

static int dcd_bssgp_imsi(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){
        guint8  nextb=0, first_b=0, toi=0, i, k;
	guint8  num=0,code=0,len=0;
	char buf[17],imsi_mccn[6],imsi_val[11], toibuf[9];
	proto_item *ti=NULL, *ti2=NULL;
	proto_tree *imsi_tree = NULL, *imsi_stru_tree = NULL;

	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	first_b = tvb_get_guint8(tvb,offset+2);
	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		decode_bitfield_value(toibuf,toi,LOW3B,8);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset,len+2 ,"IMSI");
		imsi_tree = proto_item_add_subtree(ti, ett_bssgp_imsi);
		proto_tree_add_uint_format(imsi_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_text(imsi_tree,tvb,offset+1,1,"Length:%u",len);
	}
	toi = first_b & LOW3B;
	switch (toi) {

	case TOI_IMSI:
	case TOI_IMEI:
	case TOI_IMEISV:
		num = first_b >> 4;
		buf[0] = num + '0';
		for (i=1,k=1;i<len;i++){
			nextb = tvb_get_guint8(tvb, offset+2+i);
			num = nextb & 0x0f;
			buf[k] = num + '0';
			k++;
			if (i < len - 1 || (first_b & ODD_EVEN_INDIC)) {
				/*
				 * Either this isn't the last octet
				 * of the number, or it is, but there's
				 * an odd number of digits, so the last
				 * nibble is part of the number.
				 */
				num = nextb >> 4;
				buf[k] = num + '0';
				k++;
			}
			buf[k] = '\0';
			switch (i*2){
				case 4:
					memcpy(&imsi_mccn,&buf,6);
					break;
				case 14:
					memcpy(&imsi_val, &buf[5],11);	
					break;
			}
	
		}
		if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
			col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO,
			    ", %s: %s %s",
			    val_to_str(toi,type_of_identity,"Unknown TOI (0x%x)"),
				imsi_mccn, imsi_val );
		}
	
		if (dprm_p->tree){
			proto_item_append_text(ti, ": %s", buf);
			ti2 = proto_tree_add_text(imsi_tree,tvb,offset+2,len,"Mobile identity: %s",buf);
			imsi_stru_tree = proto_item_add_subtree( ti2, ett_bssgp_imsi_stru_tree);
			proto_tree_add_uint(imsi_stru_tree,hf_bssgp_imsi_toi,tvb,offset+2,1,first_b);
			proto_tree_add_boolean(imsi_stru_tree,hf_bssgp_imsi_even_odd_indic,tvb,offset+2,1,first_b);
			proto_tree_add_string(imsi_stru_tree,hf_bssgp_imsi,tvb,offset+2,len,buf);
			proto_tree_add_string_hidden(imsi_stru_tree,hf_bssgp_imsi_lsix,tvb,offset+2,len,imsi_val);
		}
		break;
	}
return len+2;	
}

static int dcd_bssgp_llc_pdu(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, pom=0,k=0;
	guint16 llen=0;
	proto_item *ti=NULL;
	proto_tree *b_llc_tree=NULL;

	pom = tvb_get_guint8(tvb,offset+1);
	if ( pom >= 128 ){
		llen = pom & 0x7f;
		k = 2;
	}
	else{ 
		llen = tvb_get_ntohs( tvb, offset+1);
		k=3;	
	}

	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO, ", LLC PDU length %u bytes", llen );
		}	
 	
	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset,llen ,"LLC PDU %u bytes", llen);
		b_llc_tree = proto_item_add_subtree(ti, ett_b_llc_tree);
		proto_tree_add_uint_format(b_llc_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_text(b_llc_tree,tvb,offset+1,k-1,"Length:%u",llen);
	}
	
dprm_p->k=offset+k;	
return llen+k;	
}

static int dcd_bssgp_llc_frdsc(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0,frdsc=0;
	proto_item *ti=NULL;
	proto_tree *frdsc_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	frdsc = tvb_get_guint8(tvb,offset+2);
	code = tvb_get_guint8(tvb,offset);
	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO, ", %s: %u",match_strval(code,bssgp_iei), frdsc);
		}	
 	if (dprm_p->tree){
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "%s: %u", match_strval(code,bssgp_iei), frdsc);
		frdsc_tree = proto_item_add_subtree(ti, ett_frdsc_tree);
		proto_tree_add_uint_format(frdsc_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(frdsc_tree, hf_bssgp_frdsc,tvb,offset+2,len,frdsc,"%s: %u",match_strval(code,bssgp_iei),frdsc);
		proto_tree_add_text(frdsc_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}

/*static int dcd_bssgp_la(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){		
};
*/

/*static int dcd_bssgp_mid(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/

/*static int dcd_bssgp_ms_buck(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/

static int dcd_bssgp_radio_acc(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
        guint8 code=0,len=0;
	proto_item *ti=NULL;
	proto_tree *racc_tree = NULL;

	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset,len+2 ,"MS Radio Access Capability: ");
		racc_tree = proto_item_add_subtree(ti, ett_bssgp_racc);
		proto_tree_add_uint_format(racc_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_text(racc_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}

/*static int dcd_bssgp_omc_id(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/

/*static int dcd_bssgp_pdu_err(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/

static int dcd_bssgp_pdu_life(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){
	gfloat ms_lifetime;
	guint16 lifetime;
	guint8 code=0, len=0;
	proto_item *ti=NULL;
	proto_tree *lft_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
 	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		lifetime = tvb_get_ntohs(tvb,offset+2);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, 4,"PDU Lifetime (s): ");
		lft_tree = proto_item_add_subtree(ti, ett_bssgp_lft);
		proto_tree_add_uint_format(lft_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_text(lft_tree,tvb,offset+1,1,"Length:%u",len);
		if (lifetime == 0xFFFF){
			proto_item_append_text(ti,"infinite delay");
			proto_tree_add_uint_format(lft_tree,hf_bssgp_pdu_lifetime,tvb,offset+2,2,lifetime,"PDU Life time: infinite delay (%#.4x centi seconds)", lifetime);
		}
		else{
		        ms_lifetime = (gfloat) (lifetime/100);
			proto_item_append_text(ti,"%f",ms_lifetime);
			proto_tree_add_uint_format(lft_tree,hf_bssgp_pdu_lifetime,tvb,offset+2,2,lifetime,"PDU Life time: %fs (%#.4x centi seconds)", ms_lifetime, lifetime);
		}	
	}
return 4;
}

static int dcd_bssgp_prio(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0;
	proto_item *ti=NULL;
	proto_tree *prio_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
 	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, 4,"Priority");
		prio_tree = proto_item_add_subtree(ti, ett_prio_tree);
		proto_tree_add_uint_format(prio_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_text(prio_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}

static int dcd_bssgp_qos(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint16 blr=0;
	guint32 bps=0;
	char buf[16];
	gint8 disp=0, opet=0, code=0,len=0,start=0,pre=0;
	proto_item *ti=NULL, *ti2=NULL;
	proto_tree *qos_tree=NULL,*o5_tree;
	switch (dprm_p->type){
		case 3:
		break;	
		case 4:
		       code = tvb_get_guint8(tvb,offset);
		       disp++;
		       len = tvb_get_guint8(tvb,offset+disp);
		       disp++;
		       len = len & 0x7f;
		break;
	}
	start=disp;	
	blr = tvb_get_ntohs(tvb, offset+disp);
	disp = disp+2;
	opet = tvb_get_guint8(tvb,offset+disp);
	disp++;
	if (dprm_p->tree){
		bps = 100*blr/8;
		decode_bitfield_value(buf,opet,LOW3B,8);
		pre = opet & LOW3B;
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset,len+disp,"QoS Profile IE");
		qos_tree = proto_item_add_subtree(ti,ett_bssgp_qos);
		switch (dprm_p->type){
			case 4:
				proto_tree_add_uint_format(qos_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
				proto_tree_add_text(qos_tree,tvb,offset+1,1,"Length:%u",len);
			case 3:
				if (blr){
				proto_tree_add_uint_format(qos_tree,hf_bssgp_pbr,tvb,offset+start,2,blr,"Peak bit rate: %u bytes/s, (%#.4x)in 100bits/sec increments",bps,blr);
				}
				else{
				proto_tree_add_uint_format(qos_tree,hf_bssgp_pbr,tvb,offset+start,2,blr,"Peak bit rate: best effort (%#.4x)in  100bits/sec increments",blr);
				}
				ti2 = proto_tree_add_item(qos_tree,hf_bssgp_qos,tvb,offset+(disp-1),1,FALSE);
				o5_tree = proto_item_add_subtree(ti2, ett_bssgp_o5);
				proto_tree_add_boolean(o5_tree,hf_bssgp_qos_cr,tvb,offset+(disp-1),1,opet);
				proto_tree_add_boolean(o5_tree,hf_bssgp_qos_t,tvb,offset+(disp-1),1,opet);
				proto_tree_add_boolean(o5_tree,hf_bssgp_qos_a,tvb,offset+(disp-1),1,opet);
				if(tvb_get_guint8(tvb,0)){
				proto_tree_add_uint_format(o5_tree,hf_bssgp_qos_prec,tvb,offset+(disp-1),1,pre,"%s %s", buf,match_strval(pre,prec));

				}
				else{
				proto_tree_add_uint_format(o5_tree,hf_bssgp_qos_prec,tvb,offset+(disp-1),1,pre,"%s %s", buf,match_strval(pre,prec_dl));
				}
		}
				
	}
	return disp;
}

static int dcd_bssgp_radio_caus(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0,racaus=0;
	proto_item *ti=NULL;
	proto_tree *racaus_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	racaus = tvb_get_guint8(tvb,offset+2);
	code = tvb_get_guint8(tvb,offset);
	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO, ", %s: %s",match_strval(code,bssgp_iei), val_to_str(racaus,radio_cause,"%u reserved value"));
		}	
 	if (dprm_p->tree){
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "%s: %s", match_strval(code,bssgp_iei), val_to_str(racaus,radio_cause,"%u  reserved value, if received , it shall be handled as ""radio contact lost with MS"""));
		racaus_tree = proto_item_add_subtree(ti, ett_racaus_tree);
		proto_tree_add_uint_format(racaus_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(racaus_tree, hf_bssgp_radio_cause,tvb,offset+2,len,racaus,"%s: %#.2x",match_strval(code,bssgp_iei),racaus);
		proto_tree_add_text(racaus_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}

/*static int dcd_bssgp_racap_upd(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/

static int dcd_bssgp_ra(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){		
       guint16 lac;
	guint32 mnccc;
	guint8 rac, len = 0,code=0 ;
	char st_mccn[8];
	proto_item *ti=NULL;
	proto_tree *ra_tree = NULL;
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		mnccc = tvb_get_ntoh24(tvb,offset+2);
		lac = tvb_get_ntohs(tvb,offset+5);
		rac = tvb_get_guint8(tvb,offset+7);
                mccmnc(mnccc, st_mccn);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset,len+2, "Routing area: %s %u %u",st_mccn,lac,rac);
		ra_tree = proto_item_add_subtree(ti, ett_ra_tree);
		proto_tree_add_uint_format(ra_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_string_format(ra_tree,hf_bssgp_ra_mccmnc,tvb,offset+2,3,st_mccn,"MCC MNC: %s",st_mccn);
		proto_tree_add_uint_format(ra_tree,hf_bssgp_ra_lac,tvb,offset+5,2,lac,"LAC: %u",lac);
		proto_tree_add_uint_format(ra_tree,hf_bssgp_ra_rac,tvb,offset+7,1,rac,"RAC: %u",rac);
		proto_tree_add_text(ra_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}

static int dcd_bssgp_r_def_ms(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0;
	guint16 bucket=0;
	proto_item *ti=NULL;
	proto_tree *rdefms_tree=NULL;
	
 	if (dprm_p->tree){
		len = tvb_get_guint8(tvb,offset+1) & 0x7f;
		code = tvb_get_guint8(tvb,offset);
		bucket = tvb_get_ntohs(tvb,offset+2);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "%s: %u bits/sec", match_strval(code,bssgp_iei),100*bucket);
		rdefms_tree = proto_item_add_subtree(ti, ett_rdefms_tree);
		proto_tree_add_uint_format(rdefms_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(rdefms_tree, hf_bssgp_r_defau_ms,tvb,offset+2,len,bucket,"%s in 100 bits/sec increments: %u (%#.2x)",match_strval(code,bssgp_iei),bucket,bucket);
		proto_tree_add_text(rdefms_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}

/*static int dcd_bssgp_sus_ref_num(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){
};
*/

static int dcd_bssgp_tag(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint8 code=0, len=0,tag=0;
	proto_item *ti=NULL;
	proto_tree *tag_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
 	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		tag = tvb_get_guint8(tvb,offset+2);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2,"Tag: %u", tag);
		tag_tree = proto_item_add_subtree(ti, ett_tag_tree);
		proto_tree_add_uint_format(tag_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_text(tag_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}

static int dcd_bssgp_tlli(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
	guint32 tlli;
	guint8 len=0, code=0, disp=0;
	proto_item *ti=NULL;
	proto_tree *tlli_tree=NULL;
	switch (dprm_p->type){
          case 3:
		 disp = 0;
		 break; 
	  case 4:
		 code = tvb_get_guint8(tvb, offset);
		 disp++;
		 len = tvb_get_guint8(tvb,offset+disp);
		 len = len & 0x7f;
		 disp++;
		 break;
	}
	tlli = tvb_get_ntohl(tvb, offset+disp);
	if (check_col((dprm_p->pinfo)->cinfo, COL_INFO)){
		col_append_fstr( (dprm_p->pinfo)->cinfo, COL_INFO,", TLLI: %X", tlli);
	}
	if (dprm_p->tree){
		switch (dprm_p->type){
			case 3:
				proto_tree_add_uint_format(dprm_p->tree,hf_bssgp_tlli,tvb,offset,4,tlli,"TLLI: %#.4x", tlli ); 
			break;
			case 4:
				ti = proto_tree_add_text(dprm_p->tree,tvb,offset,len+disp,"TLLI: %#.4x",tlli);
				tlli_tree =proto_item_add_subtree(ti,ett_bssgp_tlli);
				proto_tree_add_uint_format(tlli_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);

				proto_tree_add_text(tlli_tree,tvb,offset+1,1,"Length:%u",len);
				proto_tree_add_uint_format(tlli_tree,hf_bssgp_tlli,tvb,offset+disp,len,tlli,"TLLI: %#.4x", tlli ); 
				
		}
	}	  
		  return 4 + disp;
}
/*static int dcd_bssgp_tlli_o(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){
	return 6;
};	
*/

/*static int dcd_bssgp_tmsi(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/
/*static int dcd_bssgp_trace_ref(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/
/*static int dcd_bssgp_trace_type(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/
/*static int dcd_bssgp_trans_id(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/
/*static int dcd_bssgp_trig_id(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){	
};
*/
static int dcd_bssgp_num_oct_aff(tvbuff_t *tvb, int offset, dec_fu_param_stru_t *dprm_p){
	guint8 code=0, len=0;
	guint32 bucket=0;
	proto_item *ti=NULL;
	proto_tree *noaff_tree=NULL;
	
	len = tvb_get_guint8(tvb,offset+1) & 0x7f;
 	if (dprm_p->tree){
		code = tvb_get_guint8(tvb,offset);
		bucket = tvb_get_ntoh24(tvb,offset+2);
		ti = proto_tree_add_text(dprm_p->tree,tvb,offset, len+2, "%s: %u", match_strval(code,bssgp_iei), bucket);
		noaff_tree = proto_item_add_subtree(ti, ett_noaff_tree);
		proto_tree_add_uint_format(noaff_tree,hf_bssgp_ietype,tvb,offset,1,code,"IE type: %s %#.2x",match_strval(code,bssgp_iei),code);
		proto_tree_add_uint_format(noaff_tree, hf_bssgp_noaff,tvb,offset+2,len,bucket,"%s: %u (%#.2x)",match_strval(code,bssgp_iei),bucket,bucket);
		proto_tree_add_text(noaff_tree,tvb,offset+1,1,"Length:%u",len);
	}
return len+2;
}


/* Code to actually dissect the packets */
static void
dissect_bssgp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
static dec_fu_param_stru_t decp , *decodeparam=&decp;
guint8 pdutype, i, j , iele , stay;
guint16 offset=1;
tvbuff_t *next_tvb;

/* Set up structures needed to add the protocol subtree and manage it */
        proto_item *ti=NULL;
        proto_tree *bssgp_tree=NULL;

	pdutype=tvb_get_guint8(tvb,0);
/* Make entries in Protocol column and Info column on summary display */
        if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "BSSGP");
    
/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. See section 1.5
   for more information.

   If you are setting it to a constant string, use "col_set_str()", as
   it's more efficient than the other "col_set_XXX()" calls.

   If you're setting it to a string you've constructed, or will be
   appending to the column later, use "col_add_str()".

   "col_add_fstr()" can be used instead of "col_add_str()"; it takes
   "printf()"-like arguments.  Don't use "col_add_fstr()" with a format
   string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
   more efficient than "col_add_fstr()".

   If you will be fetching any data from the packet before filling in
   the Info column, clear that column first, in case the calls to fetch
   data from the packet throw an exception because they're fetching data
   past the end of the packet, so that the Info column doesn't have data
   left over from the previous dissector; do
*/
        if (check_col(pinfo->cinfo, COL_INFO)) {
                col_clear(pinfo->cinfo, COL_INFO);
		col_add_str(pinfo->cinfo, COL_INFO,match_strval(pdutype,tab_bssgp_pdu_type));
	}
/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
/*        if (tree) { */

/* NOTE: The offset and length values in the call to
   "proto_tree_add_item()" define what data bytes to highlight in the hex
   display window when the line in the protocol tree display
   corresponding to that item is selected.

   tvb_length(tvb) is a handy way to highlight all data from the offset to
   the end of the packet. */

/* create display subtree for the protocol */
/*                ti = proto_tree_add_item(tree, proto_bssgp, tvb, 0, tvb_length(tvb), FALSE );

                bssgp_tree = proto_item_add_subtree(ti, ett_bssgp);
*/
	decodeparam->pinfo=pinfo;
	decodeparam->tree=tree;
		i = 0;
		stay = 1;
	 	while (bssgp_pdu[i].infe[0].presence && stay){ 
	            if (bssgp_pdu[i].pdu == pdutype) { 
			 j = 0;   
			 stay = 0;
			 if (tree){
                		ti = proto_tree_add_protocol_format(tree, proto_bssgp, tvb, 0, tvb_length(tvb),"BSS GPRS protocol PDU type: %s (%#.2x)", match_strval(pdutype,tab_bssgp_pdu_type), pdutype);
                		bssgp_tree = proto_item_add_subtree(ti, ett_bssgp);
                         	proto_tree_add_uint_format(bssgp_tree, hf_bssgp_pdu_type, tvb, 0, offset, pdutype, "PDU type: %s  (%#.2x)",match_strval(pdutype,tab_bssgp_pdu_type), pdutype );
			decodeparam->tree=bssgp_tree;	
			 }
			 while (bssgp_pdu[i].infe[j].presence){
		             switch(bssgp_pdu[i].infe[j].type){
		               case 3:
				     decodeparam->type=3; 
			             offset=offset+( *bssgp_pdu[i].infe[j].decode)(tvb, offset, decodeparam );     
				     j++;
	                       break;
			       case 4:
				  decodeparam->type=4; 
		                  if (offset >= tvb_length(tvb)) {
				      j++;
				      break;
				  }  
			          iele = tvb_get_guint8( tvb, offset);
				  while ((bssgp_pdu[i].infe[j].code != iele) && bssgp_pdu[i].infe[j].presence ) {
				     if (bssgp_pdu[i].infe[j].presence > 1) j++;
				     else break;
				  }
			          if (bssgp_pdu[i].infe[j].presence){
				      offset=offset+( *bssgp_pdu[i].infe[j].decode)(tvb, offset, decodeparam );     
				      if (iele == 0x0e ){
					      next_tvb = tvb_new_subset(tvb, decodeparam->k, -1, -1);
/*					      call_dissector(llcgprs_handle, next_tvb, pinfo, tree);
*/
					      call_dissector(data_handle, next_tvb, pinfo, tree);
				      }
				      j++;
				  }
				break;  
			     }
			 }    
		    }	   
                    i++;		    
		  };
		        
/* add an item to the subtree, see section 1.6 for more information */
/*
                proto_tree_add_uint(tree, hf_bssgp_FIELDABBREV, tvb, offset, len, value);
*/		
/*                proto_tree_add_uint_format(bssgp_tree, hf_bssgp_pdu_type, tvb, 0, 1, pdutype, "PDU type: %s  (%#.2x)",match_strval(pdutype,tab_bssgp_pdu_type), pdutype );
*/

/* Continue adding tree items to process the packet here */


/*        }*/

/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_bssgp(void)
{                 
        static hf_register_info hf[] = {
                { &hf_bssgp_pdu_type,
                        { "PDU", "bssgp.pdu",
                        FT_UINT8, BASE_HEX, VALS(tab_bssgp_pdu_type), 0x0,          
                        "BSSGP PDU", HFILL }},
		{&hf_bssgp_tlli,
			{ "TLLI","bssgp.tlli",FT_UINT32, BASE_HEX, NULL,0x0,"Current TLLI",HFILL}},
		{&hf_bssgp_ietype,
			{"IE Type", "bssgp.ietype", FT_UINT8, BASE_HEX, VALS(bssgp_iei),0x0,"Information element", HFILL }},
		{&hf_bssgp_pbr,
			 {"QoS_Profile","bssgp.pbr",FT_UINT16, BASE_HEX, NULL, 0x0, "Peak bit rate",HFILL }},
		{&hf_bssgp_qos,
			{"Last byte QoS Profile","bssgp.qos",FT_UINT8, BASE_HEX, NULL, 0x0,"5th byte of QoS profile(contains Precedence..)",HFILL}},
		{&hf_bssgp_qos_cr,
			{"C/R bit","bssgp.qos.cr",FT_BOOLEAN,8, TFS(&cr_string),QOSO5CR,"The SDU contains LLC ACK/SACK command/responce frame type",HFILL }},
		{&hf_bssgp_qos_t,
			{"T bit", "bssgp.qos.t", FT_BOOLEAN, 8, TFS( &t_string) , QOSO5T, "The SDU contains signaling/data" , HFILL}},
		{&hf_bssgp_qos_a,
			{"A bit" , "bssgp.qos.a" , FT_BOOLEAN,8, TFS( &a_string), QOSO5A, "Radio interface uses ARQ/UNITDATA functionality",HFILL}},
		{&hf_bssgp_qos_prec,
			{"Precedence", "bssgp.qos.prec", FT_UINT8,BASE_HEX ,VALS(prec_both), 0x0,"Precedence coding", HFILL }},
		{&hf_bssgp_pdu_lifetime,
			{"PDU Lifetime","bssgp.lft", FT_UINT16, BASE_HEX, NULL, 0x0, "PDU Lifetime for PDU inside the BSS",HFILL}},
		{&hf_bssgp_imsi,
			{"IMSI","bssgp.imsi", FT_STRING, BASE_DEC, NULL, 0x0, "International Mobile Subscriber Identity",HFILL}},
		{&hf_bssgp_imsi_toi,
			{ "Type of Mobile identity", "bssgp.mobid", FT_UINT8, BASE_HEX, VALS(type_of_identity), LOW3B, "Type of mobile identity",HFILL }},
		{&hf_bssgp_imsi_even_odd_indic,
			{ "Odd/even indication", "bssgp.oei", FT_BOOLEAN, 8, TFS(&imsi_odd_even), ODD_EVEN_INDIC, "Odd/even indication",HFILL }},
		{&hf_bssgp_imsi_lsix,
			{"IMSI last ten numbers","bssgp.imsi.last10num",FT_STRING, BASE_NONE, NULL, 0x0, "Last ten numbers of IMSI",HFILL}},
		{&hf_bssgp_bvc_buck_size,
			{"Bmax(in 100 oct incr)","bssgp.bmax", FT_UINT16, BASE_HEX, NULL, 0x0, "BVC Bucket Size in 100 octet increments",HFILL}},
		{&hf_bssgp_buck_leak_rate,
			{"Bucket Leak Rate","bssgp.R", FT_UINT16, BASE_HEX, NULL, 0x0, "Bucket Leak Rate in 100 bits/sec increments",HFILL}},
		{&hf_bssgp_bmax_def_ms,
			{"Bmax default MS","bssgp.bmaxms", FT_UINT16, BASE_HEX, NULL, 0x0, "Default bucket size in 100 octetsincrement for an MS",HFILL}},
		{&hf_bssgp_r_defau_ms,
			{"R default MS","bssgp.Rms", FT_UINT16, BASE_HEX,NULL, 0x0, "Dfeault bucket leak rate to be applied to a flow control bucket for an MS", HFILL}},
		{&hf_bssgp_bvci,
			{"BVCI","bssgp.bvci",FT_UINT16, BASE_HEX, NULL, 0x0, "BSSGP Virtual Connection Identifier", HFILL}},
		{&hf_bssgp_cause,
			{"Cause","bssgp.cause", FT_UINT8, BASE_HEX, NULL,0x0, " Cause information element  indicates the reason for an exception condition",HFILL }},
		{&hf_bssgp_bvci_new,{"BVCI(New)","bssgp.bvci.new",FT_UINT16, BASE_HEX, NULL, 0x0, "BSSGP Virtual Connection Identifier", HFILL}},
		{&hf_bssgp_frdsc,
			{"LLC frames discarded","bssgp.llcdisc.frames", FT_UINT8, BASE_HEX, NULL, 0x0,"LLC frames that have been discarded inside BSS", HFILL}},
		{&hf_bssgp_noaff,
			{"Number of octets affected","bssgp.noaff", FT_UINT24, BASE_HEX,NULL,0x0,"It indicates,for MS,the number of octets transferred or deleted by BSS",HFILL}},
		{&hf_bssgp_radio_cause,
			{"Radio Cause","bssgp.racase", FT_UINT8, BASE_HEX, NULL, 0x0, "Reason for an exception condition on the radio interface",HFILL}},
		{&hf_bssgp_ra_mccmnc,
			{"MCC and MNC","bssgp.ra.mccmnc", FT_STRING, BASE_DEC, NULL, 0x0, "Mobile country code and Mobile network code", HFILL}},
		{&hf_bssgp_ra_lac,
			{"LAC","bssgp.ra.lac",FT_UINT16, BASE_HEX, NULL, 0x0, "Location area code",HFILL }},
		{&hf_bssgp_ra_rac,
			{"RAC","bssgp.ra.rac",FT_UINT8, BASE_HEX, NULL, 0x0, "Routing area code", HFILL }},
		{&hf_bssgp_cid,
			{"Cell id","bssgp.cid",FT_UINT16, BASE_HEX, NULL, 0x0, "Cell identity", HFILL }},
        };

/* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_bssgp,
		&ett_bssgp_tlli,
		&ett_bssgp_qos,
		&ett_bssgp_o5,
		&ett_bssgp_lft,
		&ett_bssgp_racc,
		&ett_prio_tree,
		&ett_drx_tree,
		&ett_bssgp_imsi,
		&ett_bssgp_imsi_stru_tree,
		&ett_algn_tree,
		&ett_b_llc_tree,
		&ett_celid_tree,
		&ett_tag_tree,
		&ett_bsize_tree,
		&ett_bucklr_tree,
		&ett_bmaxms_tree,
		&ett_rdefms_tree,
		&ett_bvci_tree,
		&ett_bvcin_tree,
		&ett_cause_tree,
		&ett_frdsc_tree,
		&ett_noaff_tree,
		&ett_racaus_tree,
		&ett_ra_tree
        };

/* Register the protocol name and description */
        proto_bssgp = proto_register_protocol("BSS GPRS Protocol",
            "BSSGP", "bssgp");

/* Required function calls to register the header fields and subtrees used */
        proto_register_field_array(proto_bssgp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
	register_dissector("bssgp", dissect_bssgp, proto_bssgp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_bssgp(void)
{
/*        dissector_handle_t bssgp_handle;

        bssgp_handle = create_dissector_handle(dissect_bssgp,
            proto_bssgp);
*/
/*        dissector_add("fr.nspduname", NS_UNITDATA, bssgp_handle);*/
/*        dissector_add("fr.nspduname", 0x0, bssgp_handle);
*/	
/*        dissector_add("fr.ietf", 0x0, bssgp_handle);
*/	  
        data_handle = find_dissector("data");

/*
    	  llcgprs_handle = find_dissector ("llcgprs");
*/	  
}
