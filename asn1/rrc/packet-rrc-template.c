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
 *
 * Ref: 3GPP TS 25.331 V11.8.0 (2013-12)
 */

/**
 *
 * TODO:
 * - Fix ciphering information for circuit switched stuff
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-rrc.h"
#include "packet-gsm_a_common.h"
#include "packet-umts_fp.h"

#ifdef _MSC_VER
/* disable: "warning C4049: compiler limit : terminating line number emission" */
#pragma warning(disable:4049)
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "Radio Resource Control (RRC) protocol"
#define PSNAME "RRC"
#define PFNAME "rrc"

extern int proto_fp;    /*Handler to FP*/

GTree * hsdsch_muxed_flows = NULL;
GTree * rrc_ciph_inf = NULL;
static int msg_type _U_;

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

enum nas_sys_info_gsm_map {
  RRC_NAS_SYS_INFO_CS,
  RRC_NAS_SYS_INFO_PS,
  RRC_NAS_SYS_INFO_CN_COMMON
};

/* Forward declarations */
void proto_register_rrc(void);
void proto_reg_handoff_rrc(void);
static int dissect_UE_RadioAccessCapabilityInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoTypeSB1_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoTypeSB2_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoType5_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoType11_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoType11bis_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SysInfoType22_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

/* Include constants */
#include "packet-rrc-val.h"

/* Initialize the protocol and registered fields */
int proto_rrc = -1;
static int hf_test;
#include "packet-rrc-hf.c"

/* Initialize the subtree pointers */
static int ett_rrc = -1;

#include "packet-rrc-ett.c"

static gint ett_rrc_eutraFeatureGroupIndicators = -1;
static gint ett_rrc_cn_CommonGSM_MAP_NAS_SysInfo = -1;

static expert_field ei_rrc_no_hrnti = EI_INIT;

/* Global variables */
static proto_tree *top_tree;

static int hf_rrc_eutra_feat_group_ind_1 = -1;
static int hf_rrc_eutra_feat_group_ind_2 = -1;
static int hf_rrc_eutra_feat_group_ind_3 = -1;
static int hf_rrc_eutra_feat_group_ind_4 = -1;

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
static int flowd,type;

static int cipher_start_val[2] _U_;

/*Stores how many channels we have detected for a HS-DSCH MAC-flow*/
#define    RRC_MAX_NUM_HSDHSCH_MACDFLOW 8
static guint8 num_chans_per_flow[RRC_MAX_NUM_HSDHSCH_MACDFLOW];
static int rbid;
static int activation_frame;


/**
 * Return the maximum counter, useful for initiating counters
 */
#if 0
static int get_max_counter(int com_context){
    int i;
    guint32 max = 0;
    rrc_ciphering_info * c_inf;

    if( (c_inf = g_tree_lookup(rrc_ciph_inf, GINT_TO_POINTER((gint)com_context))) == NULL ){
        return 0;
    }
    for(i = 0; i<31; i++){
        max = MAX(c_inf->ps_conf_counters[i][0], max);
        max = MAX(c_inf->ps_conf_counters[i][1], max);
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

static void rrc_free_key(gpointer key _U_){
            /*Keys should be de allocated elsewhere.*/

}

static void rrc_free_value(gpointer value ){
            g_free(value);
}
#include "packet-rrc-fn.c"

#include "packet-rrc.h"


static void
dissect_rrc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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
}

static void rrc_init(void){
    /*Cleanup*/
    if(hsdsch_muxed_flows){
        g_tree_destroy(hsdsch_muxed_flows);
    }
    if(rrc_ciph_inf){
        g_tree_destroy(rrc_ciph_inf);
    }
    /*Initialize structure for muxed flow indication*/
    hsdsch_muxed_flows = g_tree_new_full(rrc_key_cmp,
                       NULL,      /* data pointer, optional */
                       rrc_free_key,
                       rrc_free_value);

    /*Initialize structure for muxed flow indication*/
    rrc_ciph_inf = g_tree_new_full(rrc_key_cmp,
                       NULL,      /* data pointer, optional */
                       NULL,
                       rrc_free_value);
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
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_rrc,
#include "packet-rrc-ettarr.c"
    &ett_rrc_eutraFeatureGroupIndicators,
    &ett_rrc_cn_CommonGSM_MAP_NAS_SysInfo,
  };

  static ei_register_info ei[] = {
     { &ei_rrc_no_hrnti, { "rrc.no_hrnti", PI_SEQUENCE, PI_NOTE, "Did not detect any H-RNTI", EXPFILL }},
  };

  expert_module_t* expert_rrc;

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
}


/*--- proto_reg_handoff_rrc ---------------------------------------*/
void
proto_reg_handoff_rrc(void)
{
  gsm_a_dtap_handle = find_dissector("gsm_a_dtap");
  rrc_pcch_handle = find_dissector("rrc.pcch");
  rrc_ul_ccch_handle = find_dissector("rrc.ul.ccch");
  rrc_dl_ccch_handle = find_dissector("rrc.dl.ccch");
  rrc_ul_dcch_handle = find_dissector("rrc.ul.dcch");
  rrc_dl_dcch_handle = find_dissector("rrc.dl.dcch");
  rrc_ue_radio_access_cap_info_handle = find_dissector("rrc.ue_radio_access_cap_info");
  rrc_dl_dcch_handle = find_dissector("rrc.dl.dcch");
  lte_rrc_ue_eutra_cap_handle = find_dissector("lte-rrc.ue_eutra_cap");
  lte_rrc_dl_dcch_handle = find_dissector("lte-rrc.dl.dcch");
  rrc_bcch_fach_handle = find_dissector("rrc.bcch.fach");
  gsm_rlcmac_dl_handle = find_dissector("gsm_rlcmac_dl");
}


