/* packet-rrc.c
 * Routines for Universal Mobile Telecommunications System (UMTS);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 25.331  packet dissection)
 * Copyright 2006-2010, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: 3GPP TS 25.331 V17.1.0 (2022-06)
 */

/**
 *
 * TODO:
 * - Fix ciphering information for circuit switched stuff
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-rrc.h"
#include "packet-gsm_a_common.h"
#include "packet-nbap.h"
#include "packet-umts_fp.h"
#include "packet-umts_mac.h"
#include "packet-umts_rlc.h"

#ifdef _MSC_VER
/* disable: "warning C4049: compiler limit : terminating line number emission" */
#pragma warning(disable:4049)
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "Radio Resource Control (RRC) protocol"
#define PSNAME "RRC"
#define PFNAME "rrc"

extern int proto_fp;       /*Handler to FP*/
extern int proto_umts_mac; /*Handler to MAC*/
extern int proto_umts_rlc; /*Handler to RLC*/

GTree * hsdsch_muxed_flows = NULL;
GTree * rrc_ciph_info_tree = NULL;
wmem_tree_t* rrc_global_urnti_crnti_map = NULL;
static int msg_type _U_;
static gboolean rrc_nas_in_root_tree;

enum rrc_sib_segment_type {
  RRC_SIB_SEG_NO_SEGMENT = 0,
  RRC_SIB_SEG_FIRST = 1,
  RRC_SIB_SEG_SUBSEQUENT = 2,
  RRC_SIB_SEG_LAST_SHORT = 3,
  RRC_SIB_SEG_LAST_AND_FIRST = 4,
  RRC_SIB_SEG_LAST_AND_COMP = 5,
  RRC_SIB_SEG_LAST_AND_COMP_AND_FIRST = 6,
  RRC_SIB_SEG_COMP_LIST = 7,
  RRC_SIB_SEG_COMP_AND_FIRST = 8,
  RRC_SIB_SEG_COMP = 10,
};

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all access to actx->private_data should be made       */
/* through this API, which ensures that they will not overwrite each other!! */
/*****************************************************************************/

typedef struct umts_rrc_private_data_t
{
  guint32 s_rnc_id; /* The S-RNC ID part of a U-RNTI */
  guint32 s_rnti; /* The S-RNTI part of a U-RNTI */
  guint32 new_u_rnti;
  guint32 current_u_rnti;
  guint32 scrambling_code;
  enum nas_sys_info_gsm_map cn_domain;
  wmem_strbuf_t* digits_strbuf; /* A collection of digits in a string. Used for reconstructing IMSIs or MCC-MNC pairs */
  wmem_strbuf_t* last_mcc_strbuf; /* Last seen MCC digits string */
  gboolean digits_strbuf_parsing_failed_flag; /* Whether an error occurred when creating the IMSI/MCC-MNC pair string */
  guint32 rbid;
  guint32 rlc_ciphering_sqn; /* Sequence number where ciphering starts in a given bearer */
  rrc_ciphering_info* ciphering_info;
  enum rrc_ue_state rrc_state_indicator;
  enum rrc_sib_segment_type curr_sib_segment_type;
  guint32 curr_sib_type;
} umts_rrc_private_data_t;


/* Helper function to get or create a struct that will be actx->private_data */
static umts_rrc_private_data_t* umts_rrc_get_private_data(asn1_ctx_t *actx)
{
  if (actx->private_data == NULL) {
    actx->private_data = wmem_new0(actx->pinfo->pool, umts_rrc_private_data_t);
  }
  return (umts_rrc_private_data_t*)actx->private_data;
}

static guint32 private_data_get_s_rnc_id(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->s_rnc_id;
}

static void private_data_set_s_rnc_id(asn1_ctx_t *actx, guint32 s_rnc_id)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->s_rnc_id = s_rnc_id;
}

static guint32 private_data_get_s_rnti(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->s_rnti;
}

static void private_data_set_s_rnti(asn1_ctx_t *actx, guint32 s_rnti)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->s_rnti = s_rnti;
}

static guint32 private_data_get_new_u_rnti(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->new_u_rnti;
}

static void private_data_set_new_u_rnti(asn1_ctx_t *actx, guint32 new_u_rnti)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->new_u_rnti = new_u_rnti;
}

static guint32 private_data_get_current_u_rnti(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->current_u_rnti;
}

static void private_data_set_current_u_rnti(asn1_ctx_t *actx, guint32 current_u_rnti)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->current_u_rnti = current_u_rnti;
}

static guint32 private_data_get_scrambling_code(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->scrambling_code;
}

static void private_data_set_scrambling_code(asn1_ctx_t *actx, guint32 scrambling_code)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->scrambling_code = scrambling_code;
}

static enum nas_sys_info_gsm_map private_data_get_cn_domain(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->cn_domain;
}

static void private_data_set_cn_domain(asn1_ctx_t *actx, enum nas_sys_info_gsm_map cn_domain)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->cn_domain = cn_domain;
}

static wmem_strbuf_t* private_data_get_digits_strbuf(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->digits_strbuf;
}

static void private_data_set_digits_strbuf(asn1_ctx_t *actx, wmem_strbuf_t* digits_strbuf)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->digits_strbuf = digits_strbuf;
}

static gboolean private_data_get_digits_strbuf_parsing_failed_flag(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->digits_strbuf_parsing_failed_flag;
}

static void private_data_set_digits_strbuf_parsing_failed_flag(asn1_ctx_t *actx, gboolean digits_strbuf_parsing_failed_flag)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->digits_strbuf_parsing_failed_flag = digits_strbuf_parsing_failed_flag;
}

static wmem_strbuf_t* private_data_get_last_mcc_strbuf(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->last_mcc_strbuf;
}

static void private_data_set_last_mcc_strbuf(asn1_ctx_t *actx, wmem_strbuf_t* last_mcc_strbuf)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->last_mcc_strbuf = last_mcc_strbuf;
}

static guint32 private_data_get_rbid(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->rbid;
}

static void private_data_set_rbid(asn1_ctx_t *actx, guint32 rbid)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->rbid = rbid;
}

static guint32 private_data_get_rlc_ciphering_sqn(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->rlc_ciphering_sqn;
}

static void private_data_set_rlc_ciphering_sqn(asn1_ctx_t *actx, guint32 rlc_ciphering_sqn)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->rlc_ciphering_sqn = rlc_ciphering_sqn;
}

static rrc_ciphering_info* private_data_get_ciphering_info(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->ciphering_info;
}

static void private_data_set_ciphering_info(asn1_ctx_t *actx, rrc_ciphering_info* ciphering_info)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->ciphering_info = ciphering_info;
}

static enum rrc_ue_state private_data_get_rrc_state_indicator(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->rrc_state_indicator;
}

static void private_data_set_rrc_state_indicator(asn1_ctx_t *actx, enum rrc_ue_state rrc_state_indicator)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->rrc_state_indicator = rrc_state_indicator;
}

static enum rrc_sib_segment_type private_data_get_curr_sib_segment_type(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->curr_sib_segment_type;
}

static void private_data_set_curr_sib_segment_type(asn1_ctx_t *actx, enum rrc_sib_segment_type curr_sib_segment_type)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->curr_sib_segment_type = curr_sib_segment_type;
}

static guint32 private_data_get_curr_sib_type(asn1_ctx_t *actx)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  return private_data->curr_sib_type;
}

static void private_data_set_curr_sib_type(asn1_ctx_t *actx, guint32 curr_sib_type)
{
  umts_rrc_private_data_t *private_data = (umts_rrc_private_data_t*)umts_rrc_get_private_data(actx);
  private_data->curr_sib_type = curr_sib_type;
}

/*****************************************************************************/

static dissector_handle_t gsm_a_dtap_handle;
static dissector_handle_t rrc_ue_radio_access_cap_info_handle=NULL;
static dissector_handle_t rrc_pcch_handle=NULL;
static dissector_handle_t rrc_ul_ccch_handle=NULL;
static dissector_handle_t rrc_dl_ccch_handle=NULL;
static dissector_handle_t rrc_ul_dcch_handle=NULL;
static dissector_handle_t rrc_dl_dcch_handle=NULL;
static dissector_handle_t rrc_bcch_fach_handle=NULL;
static dissector_handle_t lte_rrc_ue_eutra_cap_handle=NULL;
static dissector_handle_t lte_rrc_dl_dcch_handle=NULL;
static dissector_handle_t gsm_rlcmac_dl_handle=NULL;

/* Forward declarations */
void proto_register_rrc(void);
void proto_reg_handoff_rrc(void);
static int dissect_UE_RadioAccessCapabilityInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoType11bis_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoType11ter_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoType22_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

/* Include constants */
#include "packet-rrc-val.h"

/* Initialize the protocol and registered fields */
int proto_rrc = -1;
static int hf_test;
static int hf_urnti;
static int hf_urnti_new;
static int hf_urnti_current;
#include "packet-rrc-hf.c"

/* Initialize the subtree pointers */
static int ett_rrc = -1;

#include "packet-rrc-ett.c"

static gint ett_rrc_eutraFeatureGroupIndicators = -1;
static gint ett_rrc_cn_CommonGSM_MAP_NAS_SysInfo = -1;
static gint ett_rrc_ims_info = -1;
static gint ett_rrc_cellIdentity = -1;
static gint ett_rrc_sib_data_var = -1;

static expert_field ei_rrc_no_hrnti = EI_INIT;

/* Global variables */
static proto_tree *top_tree;

static int hf_rrc_eutra_feat_group_ind_1 = -1;
static int hf_rrc_eutra_feat_group_ind_2 = -1;
static int hf_rrc_eutra_feat_group_ind_3 = -1;
static int hf_rrc_eutra_feat_group_ind_4 = -1;
static int hf_rrc_ims_info_atgw_trans_det_cont_type = -1;
static int hf_rrc_ims_info_atgw_udp_port = -1;
static int hf_rrc_ims_info_atgw_ipv4 = -1;
static int hf_rrc_ims_info_atgw_ipv6 = -1;
static int hf_rrc_cellIdentity_rnc_id = -1;
static int hf_rrc_cellIdentity_c_id = -1;

static const true_false_string rrc_eutra_feat_group_ind_1_val = {
  "UTRA CELL_PCH to EUTRA RRC_IDLE cell reselection - Supported",
  "UTRA CELL_PCH to EUTRA RRC_IDLE cell reselection - Not supported"
};
static const true_false_string rrc_eutra_feat_group_ind_2_val = {
  "EUTRAN measurements and reporting in connected mode - Supported",
  "EUTRAN measurements and reporting in connected mode - Not supported"
};
static const true_false_string rrc_eutra_feat_group_ind_3_val = {
  "UTRA CELL_FACH absolute priority cell reselection for high priority layers - Supported",
  "UTRA CELL_FACH absolute priority cell reselection for high priority layers - Not supported"
};
static const true_false_string rrc_eutra_feat_group_ind_4_val = {
  "UTRA CELL_FACH absolute priority cell reselection for all layers - Supported",
  "UTRA CELL_FACH absolute priority cell reselection for all layers - Not supported"
};
static const value_string rrc_ims_info_atgw_trans_det_cont_type[] = {
  {0, "ATGW-IPv4-address-and-port"},
  {1, "ATGW-IPv6-address-and-port"},
  {2, "ATGW-not-available"},
  {0, NULL}
};
static int flowd,type;

/*Stores how many channels we have detected for a HS-DSCH MAC-flow*/
#define    RRC_MAX_NUM_HSDHSCH_MACDFLOW 8
static guint8 num_chans_per_flow[RRC_MAX_NUM_HSDHSCH_MACDFLOW];

/**
 * Return the maximum counter, useful for initiating counters
 */
#if 0
static int get_max_counter(int com_context){
    int i;
    guint32 max = 0;
    rrc_ciphering_info * ciphering_info;

    if( (ciphering_info = g_tree_lookup(rrc_ciph_info_tree, GINT_TO_POINTER((gint)com_context))) == NULL ){
        return 0;
    }
    for(i = 0; i<31; i++){
        max = MAX(ciphering_info->ps_conf_counters[i][0], max);
        max = MAX(ciphering_info->ps_conf_counters[i][1], max);
    }
    return max;
}
#endif
/** Utility functions used for various comparisons/cleanups in tree **/
static gint rrc_key_cmp(gconstpointer b_ptr, gconstpointer a_ptr, gpointer ignore _U_){
    if( GPOINTER_TO_INT(a_ptr) > GPOINTER_TO_INT(b_ptr) ){
        return  -1;
    }
    return GPOINTER_TO_INT(a_ptr) < GPOINTER_TO_INT(b_ptr);
}

static void rrc_free_value(gpointer value ){
            g_free(value);
}

static rrc_ciphering_info*
get_or_create_cipher_info(fp_info *fpinf, rlc_info *rlcinf) {
  rrc_ciphering_info *cipher_info = NULL;
  guint32 ueid;
  int i;

  if (!fpinf || !rlcinf)
    return NULL;

  ueid = rlcinf->ueid[fpinf->cur_tb];
  cipher_info = (rrc_ciphering_info *)g_tree_lookup(rrc_ciph_info_tree, GINT_TO_POINTER((gint)ueid));

  if( cipher_info == NULL ){
    cipher_info = g_new0(rrc_ciphering_info,1);

    /*Initiate tree with START_PS values.*/
    if(!cipher_info->start_ps)
      cipher_info->start_ps = g_tree_new_full(rrc_key_cmp,
                                        NULL,NULL,rrc_free_value);

    /*Clear and initialize seq_no matrix*/
    for(i = 0; i< 31; i++){
      cipher_info->seq_no[i][0] = -1;
      cipher_info->seq_no[i][1] = -1;
    }

    /* Set algorithms to 'unknown' since 0s are valid values */
    cipher_info->ciphering_algorithm = -1;
    cipher_info->integrity_algorithm = -1;

    g_tree_insert(rrc_ciph_info_tree, GINT_TO_POINTER((gint)rlcinf->ueid[fpinf->cur_tb]), cipher_info);
  }
  return cipher_info;
}

/* Try to find the NBAP C-RNC Context and, if found, pair it with a given U-RNTI */
static void
rrc_try_map_urnti_to_crncc(guint32 u_rnti, asn1_ctx_t *actx)
{
  guint32 scrambling_code, crnc_context;
  /* Getting the user's Uplink Scrambling Code*/
  scrambling_code = private_data_get_scrambling_code(actx);
  if (u_rnti != 0 && scrambling_code != 0) {
    /* Looking for the C-RNC Context mapped to this Scrambling Code */
    crnc_context = GPOINTER_TO_UINT(wmem_tree_lookup32(nbap_scrambling_code_crncc_map,scrambling_code));
    if (crnc_context != 0) {
      /* Mapping the U-RNTI to the C-RNC context*/
      wmem_tree_insert32(nbap_crncc_urnti_map,crnc_context,GUINT_TO_POINTER(u_rnti));
    }
  }
}

#include "packet-rrc-fn.c"


static int
dissect_rrc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* FIX ME Currently don't know the 'starting point' of this protocol
     * exported DL-DCCH-Message is the entry point.
     */
    proto_item    *rrc_item = NULL;
    proto_tree    *rrc_tree = NULL;
    struct rrc_info *rrcinf;

    top_tree = tree;
    rrcinf = (struct rrc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rrc, 0);

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RRC");

    /*Clear memory*/
    memset(num_chans_per_flow,0,sizeof(guint8)*RRC_MAX_NUM_HSDHSCH_MACDFLOW);

    /* create the rrc protocol tree */
    rrc_item = proto_tree_add_item(tree, proto_rrc, tvb, 0, -1, ENC_NA);
    rrc_tree = proto_item_add_subtree(rrc_item, ett_rrc);

    if (rrcinf) {
        switch (rrcinf->msgtype[pinfo->fd->subnum]) {
            case RRC_MESSAGE_TYPE_PCCH:
                call_dissector(rrc_pcch_handle, tvb, pinfo, rrc_tree);
                break;
            case RRC_MESSAGE_TYPE_UL_CCCH:
                call_dissector(rrc_ul_ccch_handle, tvb, pinfo, rrc_tree);
                break;
            case RRC_MESSAGE_TYPE_DL_CCCH:
                call_dissector(rrc_dl_ccch_handle, tvb, pinfo, rrc_tree);
                break;
            case RRC_MESSAGE_TYPE_UL_DCCH:
                call_dissector(rrc_ul_dcch_handle, tvb, pinfo, rrc_tree);
                break;
            case RRC_MESSAGE_TYPE_DL_DCCH:
                call_dissector(rrc_dl_dcch_handle, tvb, pinfo, rrc_tree);
                break;
            case RRC_MESSAGE_TYPE_BCCH_FACH:
                call_dissector(rrc_bcch_fach_handle, tvb, pinfo, rrc_tree);
                break;
            default:
                ;
        }
    }
    return tvb_captured_length(tvb);
}

static void
rrc_init(void) {
    /*Initialize structure for muxed flow indication*/
    hsdsch_muxed_flows = g_tree_new_full(rrc_key_cmp,
                       NULL,      /* data pointer, optional */
                       NULL,
                       rrc_free_value);

    rrc_ciph_info_tree = g_tree_new_full(rrc_key_cmp,
                       NULL,      /* data pointer, optional */
                       NULL,
                       rrc_free_value);

    /* Global U-RNTI / C-RNTI map to be used in RACH channels */
    rrc_global_urnti_crnti_map = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

static void
rrc_cleanup(void) {
    /*Cleanup*/
    g_tree_destroy(hsdsch_muxed_flows);
    g_tree_destroy(rrc_ciph_info_tree);
}

/*--- proto_register_rrc -------------------------------------------*/
void proto_register_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-rrc-hfarr.c"
    { &hf_test,
      { "RAB Test", "rrc.RAB.test",
        FT_UINT8, BASE_DEC, NULL, 0,
        "rrc.RAB_Info_r6", HFILL }},
    { &hf_urnti,
      { "U-RNTI", "rrc.urnti",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_urnti_new,
      { "New U-RNTI", "rrc.urnti_new",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_urnti_current,
      { "Current U-RNTI", "rrc.urnti_current",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_rrc_eutra_feat_group_ind_1,
      { "Indicator 1", "rrc.eutra_feat_group_ind_1",
        FT_BOOLEAN, BASE_NONE, TFS(&rrc_eutra_feat_group_ind_1_val), 0,
        "EUTRA Feature Group Indicator 1", HFILL }},
    { &hf_rrc_eutra_feat_group_ind_2,
      { "Indicator 2", "rrc.eutra_feat_group_ind_2",
        FT_BOOLEAN, BASE_NONE, TFS(&rrc_eutra_feat_group_ind_2_val), 0,
        "EUTRA Feature Group Indicator 2", HFILL }},
    { &hf_rrc_eutra_feat_group_ind_3,
      { "Indicator 3", "rrc.eutra_feat_group_ind_3",
        FT_BOOLEAN, BASE_NONE, TFS(&rrc_eutra_feat_group_ind_3_val), 0,
        "EUTRA Feature Group Indicator 3", HFILL }},
    { &hf_rrc_eutra_feat_group_ind_4,
      { "Indicator 4", "rrc.eutra_feat_group_ind_4",
        FT_BOOLEAN, BASE_NONE, TFS(&rrc_eutra_feat_group_ind_4_val), 0,
        "EUTRA Feature Group Indicator 4", HFILL }},
    { &hf_rrc_ims_info_atgw_trans_det_cont_type,
      { "ATGW transfer details content type", "rrc.rsrvcc_info.ims_info_atgw_trans_det_cont",
        FT_UINT8, BASE_DEC, VALS(rrc_ims_info_atgw_trans_det_cont_type), 0x3,
        "rSR-VCC IMS information ATGW transfer details content type", HFILL }},
    {&hf_rrc_ims_info_atgw_udp_port,
        {"ATGW UDP port","rrc.rsrvcc_info.ims_info_atgw_udp_port",
        FT_UINT16,BASE_DEC, NULL, 0x0,
        "rSR-VCC IMS information ATGW UDP port", HFILL }},
    { &hf_rrc_ims_info_atgw_ipv4,
        {"ATGW IPv4", "rrc.rsrvcc_info.ims_info_atgw_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "rSR-VCC IMS information ATGW IPv4", HFILL}},
    { &hf_rrc_ims_info_atgw_ipv6,
        {"ATGW IPv6", "rrc.rsrvcc_info.ims_info_atgw_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "rSR-VCC IMS information ATGW IPv6", HFILL}},
    { &hf_rrc_cellIdentity_rnc_id,
        {"RNC Identifier", "rrc.cellIdentity.rnc_id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "The RNC Identifier (RNC-Id) part of the Cell Identity", HFILL }},
    { &hf_rrc_cellIdentity_c_id,
        {"Cell Identifier", "rrc.cellIdentity.c_id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "The Cell Identifier (C-Id) part of the Cell Identity", HFILL }}
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_rrc,
#include "packet-rrc-ettarr.c"
    &ett_rrc_eutraFeatureGroupIndicators,
    &ett_rrc_cn_CommonGSM_MAP_NAS_SysInfo,
    &ett_rrc_ims_info,
    &ett_rrc_cellIdentity,
    &ett_rrc_sib_data_var,
  };

  static ei_register_info ei[] = {
     { &ei_rrc_no_hrnti, { "rrc.no_hrnti", PI_SEQUENCE, PI_NOTE, "Did not detect any H-RNTI", EXPFILL }},
  };

  expert_module_t* expert_rrc;
  module_t *rrc_module;

  /* Register protocol */
  proto_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_rrc = expert_register_protocol(proto_rrc);
  expert_register_field_array(expert_rrc, ei, array_length(ei));

  register_dissector("rrc", dissect_rrc, proto_rrc);

#include "packet-rrc-dis-reg.c"

  register_init_routine(rrc_init);
  register_cleanup_routine(rrc_cleanup);

  /* Register configuration preferences */
  rrc_module = prefs_register_protocol(proto_rrc, NULL);
  prefs_register_bool_preference(rrc_module, "nas_in_root_tree",
                                 "Show NAS PDU in root packet details",
                                 "Whether the NAS PDU should be shown in the root packet details tree",
                                 &rrc_nas_in_root_tree);
}


/*--- proto_reg_handoff_rrc ---------------------------------------*/
void
proto_reg_handoff_rrc(void)
{
  gsm_a_dtap_handle = find_dissector_add_dependency("gsm_a_dtap", proto_rrc);
  rrc_pcch_handle = find_dissector("rrc.pcch");
  rrc_ul_ccch_handle = find_dissector("rrc.ul.ccch");
  rrc_dl_ccch_handle = find_dissector("rrc.dl.ccch");
  rrc_ul_dcch_handle = find_dissector("rrc.ul.dcch");
  rrc_dl_dcch_handle = find_dissector("rrc.dl.dcch");
  rrc_ue_radio_access_cap_info_handle = find_dissector("rrc.ue_radio_access_cap_info");
  rrc_dl_dcch_handle = find_dissector("rrc.dl.dcch");
  lte_rrc_ue_eutra_cap_handle = find_dissector_add_dependency("lte-rrc.ue_eutra_cap", proto_rrc);
  lte_rrc_dl_dcch_handle = find_dissector_add_dependency("lte-rrc.dl.dcch", proto_rrc);
  rrc_bcch_fach_handle = find_dissector("rrc.bcch.fach");
  gsm_rlcmac_dl_handle = find_dissector_add_dependency("gsm_rlcmac_dl", proto_rrc);
}


