/* packet-nvme.c
 * Routines for NVM Express dissection
 * Copyright 2016
 * Code by Parav Pandit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This file dissects NVMe packets received from the underlying
 * fabric such as RDMA, FC.
 * This is fabric agnostic dissector and depends on cmd_ctx and q_ctx
 * It currently aligns to below specification.
 * http://www.nvmexpress.org/wp-content/uploads/NVM-Express-1_2a.pdf
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>

#include "packet-nvme.h"

void proto_register_nvme(void);

static int proto_nvme = -1;
/* Windows compiler does not support designated Initializers */
#define NEG_LST_2 -1, -1
#define NEG_LST_3 -1, -1, -1
#define NEG_LST_4 NEG_LST_2, NEG_LST_2
#define NEG_LST_5 NEG_LST_2, NEG_LST_3
#define NEG_LST_6 NEG_LST_3, NEG_LST_3
#define NEG_LST_7 NEG_LST_3, NEG_LST_4
#define NEG_LST_8 NEG_LST_4, NEG_LST_4
#define NEG_LST_9 NEG_LST_4, NEG_LST_5
#define NEG_LST_10 NEG_LST_5, NEG_LST_5
#define NEG_LST_11 NEG_LST_5, NEG_LST_6
#define NEG_LST_12 NEG_LST_6, NEG_LST_6
#define NEG_LST_13 NEG_LST_6, NEG_LST_7
#define NEG_LST_14 NEG_LST_7, NEG_LST_7
#define NEG_LST_15 NEG_LST_7, NEG_LST_8
#define NEG_LST_16 NEG_LST_8, NEG_LST_8
#define NEG_LST_17 NEG_LST_8, NEG_LST_9
#define NEG_LST_18 NEG_LST_9, NEG_LST_9
#define NEG_LST_19 NEG_LST_10, NEG_LST_9
#define NEG_LST_20 NEG_LST_10, NEG_LST_10
#define NEG_LST_32 NEG_LST_16, NEG_LST_16



/* NVMeOF fields */
/* NVMe Fabric Cmd */
static int hf_nvmeof_cmd = -1;
static int hf_nvmeof_cmd_opc = -1;
static int hf_nvmeof_cmd_rsvd = -1;
static int hf_nvmeof_cmd_cid = -1;
static int hf_nvmeof_cmd_fctype = -1;
static int hf_nvmeof_cmd_connect_rsvd1 = -1;
static int hf_nvmeof_cmd_connect_sgl1 = -1;
static int hf_nvmeof_cmd_connect_recfmt = -1;
static int hf_nvmeof_cmd_connect_qid = -1;
static int hf_nvmeof_cmd_connect_sqsize = -1;
static int hf_nvmeof_cmd_connect_cattr[5] =  { NEG_LST_5 };
static int hf_nvmeof_cmd_connect_rsvd2 = -1;
static int hf_nvmeof_cmd_connect_kato = -1;
static int hf_nvmeof_cmd_connect_rsvd3 = -1;
static int hf_nvmeof_cmd_connect_data_hostid = -1;
static int hf_nvmeof_cmd_connect_data_cntlid = -1;
static int hf_nvmeof_cmd_connect_data_rsvd0 = -1;
static int hf_nvmeof_cmd_connect_data_subnqn = -1;
static int hf_nvmeof_cmd_connect_data_hostnqn = -1;
static int hf_nvmeof_cmd_connect_data_rsvd1 = -1;

static int hf_nvmeof_cmd_auth_rsdv1 = -1;
static int hf_nvmeof_cmd_auth_sgl1 = -1;
static int hf_nvmeof_cmd_auth_rsdv2 = -1;
static int hf_nvmeof_cmd_auth_spsp0 = -1;
static int hf_nvmeof_cmd_auth_spsp1 = -1;
static int hf_nvmeof_cmd_auth_secp = -1;
static int hf_nvmeof_cmd_auth_al = -1;
static int hf_nvmeof_cmd_auth_rsdv3 = -1;

static int hf_nvmeof_cmd_disconnect_rsvd0 = -1;
static int hf_nvmeof_cmd_disconnect_recfmt = -1;
static int hf_nvmeof_cmd_disconnect_rsvd1 = -1;

static int hf_nvmeof_cmd_prop_get_set_rsvd0 = -1;
static int hf_nvmeof_cmd_prop_get_set_attrib[3] =  { NEG_LST_3 };
static int hf_nvmeof_cmd_prop_get_set_rsvd1 = -1;
static int hf_nvmeof_cmd_prop_get_set_offset = -1;
static int hf_nvmeof_cmd_prop_get_rsvd2 = -1;

static int hf_nvmeof_cmd_prop_set_rsvd = -1;

static int hf_nvmeof_cmd_generic_rsvd1 = -1;
static int hf_nvmeof_cmd_generic_field = -1;

static int hf_nvmeof_prop_get_set_data = -1;
static int hf_nvmeof_prop_get_set_data_4B = -1;
static int hf_nvmeof_prop_get_set_data_4B_rsvd = -1;
static int hf_nvmeof_prop_get_set_data_8B= -1;
static int hf_nvmeof_prop_get_set_cc[10] = { NEG_LST_10 };
static int hf_nvmeof_prop_get_set_csts[7] = { NEG_LST_7 };
static int hf_nvmeof_prop_get_set_nssr[2] = { NEG_LST_2 };
static int hf_nvmeof_prop_get_vs[4] = { NEG_LST_4 };
static int hf_nvmeof_prop_get_ccap[17] = { NEG_LST_17 };


/* NVMe Fabric CQE */
static int hf_nvmeof_cqe = -1;
static int hf_nvmeof_cqe_sts = -1;

static int hf_nvmeof_cqe_connect_cntlid = -1;
static int hf_nvmeof_cqe_connect_authreq = -1;
static int hf_nvmeof_cqe_connect_rsvd = -1;
static int hf_nvmeof_cqe_prop_set_rsvd = -1;

/* tracking Cmd and its respective CQE */
int hf_nvmeof_cmd_pkt = -1;
int hf_nvmeof_data_req = -1;
static int hf_nvmeof_data_tr[NVME_CMD_MAX_TRS] = {NEG_LST_16};
static int hf_nvmeof_cqe_pkt = -1;
static int hf_nvmeof_cmd_latency = -1;

static const value_string fctype_tbl[] = {
    { NVME_FCTYPE_PROP_SET,      "Property Set" },
    { NVME_FCTYPE_CONNECT,       "Connect" },
    { NVME_FCTYPE_PROP_GET,      "Property Get" },
    { NVME_FCTYPE_AUTH_SEND,     "Authentication Send" },
    { NVME_FCTYPE_AUTH_RECV,     "Authentication Recv" },
    { NVME_FCTYPE_DISCONNECT,     "Disconnect" },
    { 0, NULL}
};

static const value_string pclass_tbl[] = {
    { 0x0, "Urgent" },
    { 0x1, "High" },
    { 0x2, "Medium" },
    { 0x3, "Low", },
    { 0, NULL}
};

static const value_string prop_offset_tbl[] = {
    { 0x0,      "Controller Capabilities"},
    { 0x8,      "Version"},
    { 0xc,      "Reserved"},
    { 0x10,     "Reserved"},
    { 0x14,     "Controller Configuration"},
    { 0x18,     "Reserved"},
    { 0x1c,     "Controller Status"},
    { 0x20,     "NVM Subsystem Reset"},
    { 0x24,     "Reserved"},
    { 0x28,     "Reserved"},
    { 0x30,     "Reserved"},
    { 0x38,     "Reserved"},
    { 0x3c,     "Reserved"},
    { 0x40,     "Reserved"},
    { 0, NULL}
};

static const value_string attr_size_tbl[] = {
    { 0,       "4 bytes"},
    { 1,       "8 bytes"},
    { 0, NULL}
};

static const value_string css_table[] = {
     { 0x0, "NVM IO Command Set"},
     { 0x1, "Admin Command Set Only"},
     { 0x0, NULL}
};
static const value_string sn_table[] = {
    { 0x0, "No Shutdown"},
    { 0x1, "Normal Shutdown"},
    { 0x2, "Abrupt Shutdown"},
    { 0x3, "Reserved"},
    { 0x0, NULL}
};
static const value_string ams_table[] = {
    { 0x0, "Round Robin"},
    { 0x1, "Weighted Round Robin with Urgent Priority Class"},
    { 0x2, "Reserved"},
    { 0x3, "Reserved"},
    { 0x4, "Reserved"},
    { 0x5, "Reserved"},
    { 0x6, "Reserved"},
    { 0x7, "Vendor Specific"},
    { 0x0, NULL}
};

static const value_string shst_table[] = {
    { 0x0, "No Shutdown"},
    { 0x1, "Shutdown in Process"},
    { 0x2, "Shutdown Complete"},
    { 0x3, "Reserved"},
    { 0x0, NULL}
};

/* NVMe Cmd fields */
static int hf_nvme_cmd_opc = -1;
static int hf_nvme_cmd_rsvd = -1;
static int hf_nvme_cmd_cid = -1;
static int hf_nvme_cmd_fuse_op = -1;
static int hf_nvme_cmd_psdt = -1;
static int hf_nvme_cmd_nsid = -1;
static int hf_nvme_cmd_rsvd1 = -1;
static int hf_nvme_cmd_mptr = -1;
static int hf_nvme_cmd_sgl = -1;
static int hf_nvme_cmd_sgl_desc_type = -1;
static int hf_nvme_cmd_sgl_desc_sub_type = -1;
static int hf_nvme_cmd_sgl_desc_addr = -1;
static int hf_nvme_cmd_sgl_desc_addr_rsvd = -1;
static int hf_nvme_cmd_sgl_desc_len = -1;
static int hf_nvme_cmd_sgl_desc_rsvd = -1;
static int hf_nvme_cmd_sgl_desc_key = -1;
static int hf_nvme_cmd_dword10 = -1;
static int hf_nvme_cmd_dword11 = -1;
static int hf_nvme_cmd_dword12 = -1;
static int hf_nvme_cmd_dword13 = -1;
static int hf_nvme_cmd_dword14 = -1;
static int hf_nvme_cmd_dword15 = -1;
static int hf_nvme_cmd_slba = -1;
static int hf_nvme_cmd_nlb = -1;
static int hf_nvme_cmd_rsvd2 = -1;
static int hf_nvme_cmd_prinfo = -1;
static int hf_nvme_cmd_prinfo_prchk_lbrtag = -1;
static int hf_nvme_cmd_prinfo_prchk_apptag = -1;
static int hf_nvme_cmd_prinfo_prchk_guard = -1;
static int hf_nvme_cmd_prinfo_pract = -1;
static int hf_nvme_cmd_fua = -1;
static int hf_nvme_cmd_lr = -1;
static int hf_nvme_cmd_eilbrt = -1;
static int hf_nvme_cmd_elbat = -1;
static int hf_nvme_cmd_elbatm = -1;
static int hf_nvme_cmd_dsm = -1;
static int hf_nvme_cmd_dsm_access_freq = -1;
static int hf_nvme_cmd_dsm_access_lat = -1;
static int hf_nvme_cmd_dsm_seq_req = -1;
static int hf_nvme_cmd_dsm_incompressible = -1;
static int hf_nvme_cmd_rsvd3 = -1;
static int hf_nvme_identify_dword10[4] = { NEG_LST_4 };
static int hf_nvme_identify_dword11[3] = { NEG_LST_3 };
static int hf_nvme_identify_dword14[3] = { NEG_LST_3 };

static int hf_nvme_get_logpage_dword10[6] = { NEG_LST_6 };
static int hf_nvme_get_logpage_numd = -1;
static int hf_nvme_get_logpage_dword11[3] = { NEG_LST_3 };
static int hf_nvme_get_logpage_lpo = -1;
static int hf_nvme_get_logpage_dword14[3] = { NEG_LST_3 };
static int hf_nvme_set_features_dword10[4] = { NEG_LST_4 };
static int hf_nvme_set_features_dword14[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_arb[6] = { NEG_LST_6 };
static int hf_nvme_cmd_set_features_dword11_pm[4] = { NEG_LST_4 };
static int hf_nvme_cmd_set_features_dword11_lbart[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_tt[5] = { NEG_LST_5 };
static int hf_nvme_cmd_set_features_dword11_erec[4] = { NEG_LST_4 };
static int hf_nvme_cmd_set_features_dword11_vwce[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_nq[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_irqc[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_irqv[4] = { NEG_LST_4 };
static int hf_nvme_cmd_set_features_dword11_wan[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_aec[11] = { NEG_LST_11 };
static int hf_nvme_cmd_set_features_dword11_apst[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_kat[2] = { NEG_LST_2 };
static int hf_nvme_cmd_set_features_dword11_hctm[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_nops[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_rrl[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword12_rrl[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_plmc[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword12_plmc[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_plmw[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword12_plmw[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_lbasi[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_san[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_eg[4] = { NEG_LST_4 };
static int hf_nvme_cmd_set_features_dword11_swp[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_hid[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_rsrvn[6] = { NEG_LST_6 };
static int hf_nvme_cmd_set_features_dword11_rsrvp[3] = { NEG_LST_3 };
static int hf_nvme_cmd_set_features_dword11_nswp[3] = { NEG_LST_3 };
static int hf_nvme_set_features_tr_lbart = -1;
static int hf_nvme_set_features_tr_lbart_type = -1;
static int hf_nvme_set_features_tr_lbart_attr[4] = { NEG_LST_4 };
static int hf_nvme_set_features_tr_lbart_rsvd0 = -1;
static int hf_nvme_set_features_tr_lbart_slba = -1;
static int hf_nvme_set_features_tr_lbart_nlb = -1;
static int hf_nvme_set_features_tr_lbart_guid = -1;
static int hf_nvme_set_features_tr_lbart_rsvd1 = -1;
static int hf_nvme_set_features_tr_apst[5] = { NEG_LST_5 };
static int hf_nvme_set_features_tr_tst[3] = { NEG_LST_3 };
static int hf_nvme_set_features_tr_plmc = - 1;
static int hf_nvme_set_features_tr_plmc_ee[7] = { NEG_LST_7 };
static int hf_nvme_set_features_tr_plmc_rsvd0 = - 1;
static int hf_nvme_set_features_tr_plmc_dtwinrt = -1;
static int hf_nvme_set_features_tr_plmc_dtwinwt = -1;
static int hf_nvme_set_features_tr_plmc_dtwintt = -1;
static int hf_nvme_set_features_tr_plmc_rsvd1 = -1;
static int hf_nvme_set_features_tr_hbs = -1;
static int hf_nvme_set_features_tr_hbs_acre = -1;
static int hf_nvme_set_features_tr_hbs_rsvd = -1;
static int hf_nvme_get_features_dword10[4] = { NEG_LST_4 };
static int hf_nvme_get_features_dword14[3] = { NEG_LST_3 };
static int hf_nvme_cmd_get_features_dword11_rrl[3] = { NEG_LST_3 };
static int hf_nvme_cmd_get_features_dword11_plmc[3] = { NEG_LST_3 };
static int hf_nvme_cmd_get_features_dword11_plmw[3] = { NEG_LST_3 };
static int hf_nvme_identify_ns_nsze = -1;
static int hf_nvme_identify_ns_ncap = -1;
static int hf_nvme_identify_ns_nuse = -1;
static int hf_nvme_identify_ns_nsfeat = -1;
static int hf_nvme_identify_ns_nlbaf = -1;
static int hf_nvme_identify_ns_flbas = -1;
static int hf_nvme_identify_ns_mc = -1;
static int hf_nvme_identify_ns_dpc = -1;
static int hf_nvme_identify_ns_dps = -1;
static int hf_nvme_identify_ns_nmic = -1;
static int hf_nvme_identify_ns_nguid = -1;
static int hf_nvme_identify_ns_eui64 = -1;
static int hf_nvme_identify_ns_lbafs = -1;
static int hf_nvme_identify_ns_lbaf = -1;
static int hf_nvme_identify_ns_rsvd = -1;
static int hf_nvme_identify_ns_vs = -1;
static int hf_nvme_identify_ctrl_vid = -1;
static int hf_nvme_identify_ctrl_ssvid = -1;
static int hf_nvme_identify_ctrl_sn = -1;
static int hf_nvme_identify_ctrl_mn = -1;
static int hf_nvme_identify_ctrl_fr = -1;
static int hf_nvme_identify_ctrl_rab = -1;
static int hf_nvme_identify_ctrl_ieee = -1;
static int hf_nvme_identify_ctrl_cmic[6] = { NEG_LST_6 };
static int hf_nvme_identify_ctrl_mdts = -1;
static int hf_nvme_identify_ctrl_cntlid = -1;
static int hf_nvme_identify_ctrl_ver = -1;
static int hf_nvme_identify_ctrl_ver_min = -1;
static int hf_nvme_identify_ctrl_ver_mjr = -1;
static int hf_nvme_identify_ctrl_ver_ter = -1;
static int hf_nvme_identify_ctrl_rtd3r = -1;
static int hf_nvme_identify_ctrl_rtd3e = -1;
static int hf_nvme_identify_ctrl_oaes[10] = { NEG_LST_10 };
static int hf_nvme_identify_ctrl_ctratt[12] = { NEG_LST_12 };
static int hf_nvme_identify_ctrl_rrls[17] = { NEG_LST_17 };
static int hf_nvme_identify_ctrl_rsvd0 = -1;
static int hf_nvme_identify_ctrl_cntrltype = -1;
static int hf_nvme_identify_ctrl_fguid = -1;
static int hf_nvme_identify_ctrl_fguid_vse = -1;
static int hf_nvme_identify_ctrl_fguid_oui = -1;
static int hf_nvme_identify_ctrl_fguid_ei = -1;
static int hf_nvme_identify_ctrl_crdt1 = -1;
static int hf_nvme_identify_ctrl_crdt2 = -1;
static int hf_nvme_identify_ctrl_crdt3 = -1;
static int hf_nvme_identify_ctrl_rsvd1 = -1;
static int hf_nvme_identify_ctrl_mi = -1;
static int hf_nvme_identify_ctrl_mi_rsvd = -1;
static int hf_nvme_identify_ctrl_mi_nvmsr[4] = { NEG_LST_4 };
static int hf_nvme_identify_ctrl_mi_vwci[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_mi_mec[4] =  { NEG_LST_4 };
static int hf_nvme_identify_ctrl_oacs[12] = { NEG_LST_12 };
static int hf_nvme_identify_ctrl_acl = -1;
static int hf_nvme_identify_ctrl_aerl = -1;
static int hf_nvme_identify_ctrl_frmw[5] = { NEG_LST_5 };
static int hf_nvme_identify_ctrl_lpa[7] = { NEG_LST_7 };
static int hf_nvme_identify_ctrl_elpe = -1;
static int hf_nvme_identify_ctrl_npss = -1;
static int hf_nvme_identify_ctrl_avscc[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_apsta[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_wctemp = -1;
static int hf_nvme_identify_ctrl_cctemp = -1;
static int hf_nvme_identify_ctrl_mtfa = -1;
static int hf_nvme_identify_ctrl_hmpre = -1;
static int hf_nvme_identify_ctrl_hmmin = -1;
static int hf_nvme_identify_ctrl_tnvmcap = -1;
static int  hf_nvme_identify_ctrl_unvmcap = -1;
static int hf_nvme_identify_ctrl_rpmbs[6] = { NEG_LST_5 };
static int hf_nvme_identify_ctrl_edstt = -1;
static int hf_nvme_identify_ctrl_dsto[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_fwug = -1;
static int hf_nvme_identify_ctrl_kas = -1;
static int hf_nvme_identify_ctrl_hctma[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_mntmt = -1;
static int hf_nvme_identify_ctrl_mxtmt = -1;
static int hf_nvme_identify_ctrl_sanicap[7] = { NEG_LST_7 };
static int hf_nvme_identify_ctrl_hmmminds = -1;
static int hf_nvme_identify_ctrl_hmmaxd = -1;
static int hf_nvme_identify_ctrl_nsetidmax = -1;
static int hf_nvme_identify_ctrl_endgidmax = -1;
static int hf_nvme_identify_ctrl_anatt = -1;
static int hf_nvme_identify_ctrl_anacap[9] = { NEG_LST_9 };
static int hf_nvme_identify_ctrl_anagrpmax = -1;
static int hf_nvme_identify_ctrl_nanagrpid = -1;
static int hf_nvme_identify_ctrl_pels = -1;
static int hf_nvme_identify_ctrl_rsvd2 = -1;
static int hf_nvme_identify_ctrl_sqes[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_cqes[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_maxcmd = -1;
static int hf_nvme_identify_ctrl_nn = -1;
static int hf_nvme_identify_ctrl_oncs[10] = { NEG_LST_10 };
static int hf_nvme_identify_ctrl_fuses[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_fna[5] = { NEG_LST_5 };
static int hf_nvme_identify_ctrl_vwc[4] = { NEG_LST_4 };
static int hf_nvme_identify_ctrl_awun = -1;
static int hf_nvme_identify_ctrl_awupf = -1;
static int hf_nvme_identify_ctrl_nvscc[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_nwpc[5] = { NEG_LST_5 };
static int hf_nvme_identify_ctrl_acwu = -1;
static int hf_nvme_identify_ctrl_rsvd3 = -1;
static int hf_nvme_identify_ctrl_sgls[11] = { NEG_LST_11 };
static int hf_nvme_identify_ctrl_mnan = -1;
static int hf_nvme_identify_ctrl_rsvd4 = -1;
static int hf_nvme_identify_ctrl_subnqn = -1;
static int hf_nvme_identify_ctrl_rsvd5 = -1;
static int hf_nvme_identify_ctrl_nvmeof = -1;
static int hf_nvme_identify_ctrl_nvmeof_ioccsz = -1;
static int hf_nvme_identify_ctrl_nvmeof_iorcsz = -1;
static int hf_nvme_identify_ctrl_nvmeof_icdoff = -1;
static int hf_nvme_identify_ctrl_nvmeof_fcatt[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_nvmeof_msdbd = -1;
static int hf_nvme_identify_ctrl_nvmeof_ofcs[3] = { NEG_LST_3 };
static int hf_nvme_identify_ctrl_nvmeof_rsvd = -1;
static int hf_nvme_identify_ctrl_psds = -1;
static int hf_nvme_identify_ctrl_psd = -1;
static int hf_nvme_identify_ctrl_psd_mp = -1;
static int hf_nvme_identify_ctrl_psd_rsvd0 = -1;
static int hf_nvme_identify_ctrl_psd_mxps = -1;
static int hf_nvme_identify_ctrl_psd_nops = -1;
static int hf_nvme_identify_ctrl_psd_rsvd1 = -1;
static int hf_nvme_identify_ctrl_psd_enlat = -1;
static int hf_nvme_identify_ctrl_psd_exlat = -1;
static int hf_nvme_identify_ctrl_psd_rrt = -1;
static int hf_nvme_identify_ctrl_psd_rsvd2 = -1;
static int hf_nvme_identify_ctrl_psd_rrl = -1;
static int hf_nvme_identify_ctrl_psd_rsvd3 = -1;
static int hf_nvme_identify_ctrl_psd_rwt = -1;
static int hf_nvme_identify_ctrl_psd_rsvd4 = -1;
static int hf_nvme_identify_ctrl_psd_rwl = -1;
static int hf_nvme_identify_ctrl_psd_rsvd5 = -1;
static int hf_nvme_identify_ctrl_psd_idlp = -1;
static int hf_nvme_identify_ctrl_psd_rsvd6 = -1;
static int hf_nvme_identify_ctrl_psd_ips = -1;
static int hf_nvme_identify_ctrl_psd_rsvd7 = -1;
static int hf_nvme_identify_ctrl_psd_actp = -1;
static int hf_nvme_identify_ctrl_psd_apw = -1;
static int hf_nvme_identify_ctrl_psd_rsvd8 = -1;
static int hf_nvme_identify_ctrl_psd_aps = -1;
static int hf_nvme_identify_ctrl_psd_rsvd9 = -1;
static int hf_nvme_identify_ctrl_vs = - 1;

static int hf_nvme_identify_nslist_nsid = -1;

/* get logpage response */
static int hf_nvme_get_logpage_ify_genctr = -1;
static int hf_nvme_get_logpage_ify_numrec = -1;
static int hf_nvme_get_logpage_ify_recfmt = -1;
static int hf_nvme_get_logpage_ify_rsvd = -1;
static int hf_nvme_get_logpage_ify_rcrd = -1;
static int hf_nvme_get_logpage_ify_rcrd_trtype = -1;
static int hf_nvme_get_logpage_ify_rcrd_adrfam = - 1;
static int hf_nvme_get_logpage_ify_rcrd_subtype = -1;
static int hf_nvme_get_logpage_ify_rcrd_treq[4] = { NEG_LST_4 };
static int hf_nvme_get_logpage_ify_rcrd_portid = -1;
static int hf_nvme_get_logpage_ify_rcrd_cntlid = -1;
static int hf_nvme_get_logpage_ify_rcrd_asqsz = -1;
static int hf_nvme_get_logpage_ify_rcrd_rsvd0 = -1;
static int hf_nvme_get_logpage_ify_rcrd_trsvcid = -1;
static int hf_nvme_get_logpage_ify_rcrd_rsvd1 = -1;
static int hf_nvme_get_logpage_ify_rcrd_subnqn = -1;
static int hf_nvme_get_logpage_ify_rcrd_traddr = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_qptype = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_prtype = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_cms = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_rsvd0 = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_pkey = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_rsvd1 = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_tcp_sectype = -1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_tcp_rsvd = -1;
static int hf_nvme_get_logpage_errinf_errcnt = -1;
static int hf_nvme_get_logpage_errinf_sqid = -1;
static int hf_nvme_get_logpage_errinf_cid = -1;
static int hf_nvme_get_logpage_errinf_sf[3] = { NEG_LST_3};
static int hf_nvme_get_logpage_errinf_pel[4] = { NEG_LST_4};
static int hf_nvme_get_logpage_errinf_lba = -1;
static int hf_nvme_get_logpage_errinf_ns = -1;
static int hf_nvme_get_logpage_errinf_vsi = -1;
static int hf_nvme_get_logpage_errinf_trtype = -1;
static int hf_nvme_get_logpage_errinf_rsvd0 = -1;
static int hf_nvme_get_logpage_errinf_csi = -1;
static int hf_nvme_get_logpage_errinf_tsi = -1;
static int hf_nvme_get_logpage_errinf_rsvd1 = -1;
static int hf_nvme_get_logpage_smart_cw[8] = { NEG_LST_8};
static int hf_nvme_get_logpage_smart_ct = -1;
static int hf_nvme_get_logpage_smart_asc = -1;
static int hf_nvme_get_logpage_smart_ast = -1;
static int hf_nvme_get_logpage_smart_lpu = -1;
static int hf_nvme_get_logpage_smart_egcws[6] = { NEG_LST_6};
static int hf_nvme_get_logpage_smart_rsvd0 = -1;
static int hf_nvme_get_logpage_smart_dur = -1;
static int hf_nvme_get_logpage_smart_duw = -1;
static int hf_nvme_get_logpage_smart_hrc = -1;
static int hf_nvme_get_logpage_smart_hwc = -1;
static int hf_nvme_get_logpage_smart_cbt = -1;
static int hf_nvme_get_logpage_smart_pc = -1;
static int hf_nvme_get_logpage_smart_poh = -1;
static int hf_nvme_get_logpage_smart_us = -1;
static int hf_nvme_get_logpage_smart_mie = -1;
static int hf_nvme_get_logpage_smart_ele = -1;
static int hf_nvme_get_logpage_smart_wctt = -1;
static int hf_nvme_get_logpage_smart_cctt = -1;
static int hf_nvme_get_logpage_smart_ts[9] = { NEG_LST_9 };
static int hf_nvme_get_logpage_smart_tmt1c = -1;
static int hf_nvme_get_logpage_smart_tmt2c = -1;
static int hf_nvme_get_logpage_smart_tmt1t = -1;
static int hf_nvme_get_logpage_smart_tmt2t = -1;
static int hf_nvme_get_logpage_smart_rsvd1 = -1;
static int hf_nvme_get_logpage_fw_slot_afi[5] = { NEG_LST_5 };
static int hf_nvme_get_logpage_fw_slot_rsvd0 = -1;
static int hf_nvme_get_logpage_fw_slot_frs[8] = { NEG_LST_8 };
static int hf_nvme_get_logpage_fw_slot_rsvd1 = -1;
static int hf_nvme_get_logpage_changed_nslist = -1;
static int hf_nvme_get_logpage_cmd_and_eff_cs = -1;
static int hf_nvme_get_logpage_cmd_and_eff_cseds[10] = { NEG_LST_10 };
static int hf_nvme_get_logpage_selftest_csto[3] = { NEG_LST_3 };
static int hf_nvme_get_logpage_selftest_cstc[3] = { NEG_LST_3 };
static int hf_nvme_get_logpage_selftest_rsvd = -1;
static int hf_nvme_get_logpage_selftest_res = -1;
static int hf_nvme_get_logpage_selftest_res_status[3] = { NEG_LST_3 };
static int hf_nvme_get_logpage_selftest_res_sn = -1;
static int hf_nvme_get_logpage_selftest_res_vdi[6] = { NEG_LST_6 };
static int hf_nvme_get_logpage_selftest_res_rsvd = -1;
static int hf_nvme_get_logpage_selftest_res_poh = -1;
static int hf_nvme_get_logpage_selftest_res_nsid = -1;
static int hf_nvme_get_logpage_selftest_res_flba = -1;
static int hf_nvme_get_logpage_selftest_res_sct[3] = { NEG_LST_3 };
static int hf_nvme_get_logpage_selftest_res_sc = -1;
static int hf_nvme_get_logpage_selftest_res_vs = -1;
static int hf_nvme_get_logpage_telemetry_li = -1;
static int hf_nvme_get_logpage_telemetry_rsvd0 = -1;
static int hf_nvme_get_logpage_telemetry_ieee = -1;
static int hf_nvme_get_logpage_telemetry_da1lb = -1;
static int hf_nvme_get_logpage_telemetry_da2lb = -1;
static int hf_nvme_get_logpage_telemetry_da3lb = -1;
static int hf_nvme_get_logpage_telemetry_rsvd1 = -1;
static int hf_nvme_get_logpage_telemetry_da = -1;
static int hf_nvme_get_logpage_telemetry_dgn = -1;
static int hf_nvme_get_logpage_telemetry_ri = -1;
static int hf_nvme_get_logpage_telemetry_db = -1;
static int hf_nvme_get_logpage_egroup_cw[6] = { NEG_LST_6 };
static int hf_nvme_get_logpage_egroup_rsvd0 = -1;
static int hf_nvme_get_logpage_egroup_as = -1;
static int hf_nvme_get_logpage_egroup_ast = -1;
static int hf_nvme_get_logpage_egroup_pu = -1;
static int hf_nvme_get_logpage_egroup_rsvd1 = -1;
static int hf_nvme_get_logpage_egroup_ee = -1;
static int hf_nvme_get_logpage_egroup_dur = -1;
static int hf_nvme_get_logpage_egroup_duw = -1;
static int hf_nvme_get_logpage_egroup_muw = -1;
static int hf_nvme_get_logpage_egroup_hrc = -1;
static int hf_nvme_get_logpage_egroup_hwc = -1;
static int hf_nvme_get_logpage_egroup_mdie = -1;
static int hf_nvme_get_logpage_egroup_ele = -1;
static int hf_nvme_get_logpage_egroup_rsvd2 = -1;
static int hf_nvme_get_logpage_pred_lat_status[3] = { NEG_LST_3 };
static int hf_nvme_get_logpage_pred_lat_rsvd0 = -1;
static int hf_nvme_get_logpage_pred_lat_etype[7] = { NEG_LST_7 };
static int hf_nvme_get_logpage_pred_lat_rsvd1 = -1;
static int hf_nvme_get_logpage_pred_lat_dtwin_rt = -1;
static int hf_nvme_get_logpage_pred_lat_dtwin_wt = -1;
static int hf_nvme_get_logpage_pred_lat_dtwin_tm = -1;
static int hf_nvme_get_logpage_pred_lat_ndwin_tmh = -1;
static int hf_nvme_get_logpage_pred_lat_ndwin_tml = -1;
static int hf_nvme_get_logpage_pred_lat_rsvd2 = -1;
static int hf_nvme_get_logpage_pred_lat_dtwin_re = -1;
static int hf_nvme_get_logpage_pred_lat_dtwin_we = -1;
static int hf_nvme_get_logpage_pred_lat_dtwin_te = -1;
static int hf_nvme_get_logpage_pred_lat_rsvd3 = -1;
static int hf_nvme_get_logpage_pred_lat_aggreg_ne = -1;
static int hf_nvme_get_logpage_pred_lat_aggreg_nset = -1;
static int hf_nvme_get_logpage_ana_chcnt = -1;
static int hf_nvme_get_logpage_ana_ngd = -1;
static int hf_nvme_get_logpage_ana_rsvd = -1;
static int hf_nvme_get_logpage_ana_grp = -1;
static int hf_nvme_get_logpage_ana_grp_id = -1;
static int hf_nvme_get_logpage_ana_grp_nns = -1;
static int hf_nvme_get_logpage_ana_grp_chcnt = -1;
static int hf_nvme_get_logpage_ana_grp_anas[3] = { NEG_LST_3 };
static int hf_nvme_get_logpage_ana_grp_rsvd = -1;
static int hf_nvme_get_logpage_ana_grp_nsid = -1;
static int hf_nvme_get_logpage_lba_status_lslplen = -1;
static int hf_nvme_get_logpage_lba_status_nlslne = -1;
static int hf_nvme_get_logpage_lba_status_estulb = -1;
static int hf_nvme_get_logpage_lba_status_rsvd = -1;
static int hf_nvme_get_logpage_lba_status_lsgc = -1;
static int hf_nvme_get_logpage_lba_status_nel = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne_neid = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne_nlrd = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne_ratype = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne_rsvd = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne_rd = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne_rd_rslba = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne_rd_rnlb = -1;
static int hf_nvme_get_logpage_lba_status_nel_ne_rd_rsvd = -1;
static int hf_nvme_get_logpage_egroup_aggreg_ne = -1;
static int hf_nvme_get_logpage_egroup_aggreg_eg = -1;
static int hf_nvme_get_logpage_reserv_notif_lpc = -1;
static int hf_nvme_get_logpage_reserv_notif_lpt = -1;
static int hf_nvme_get_logpage_reserv_notif_nalp = -1;
static int hf_nvme_get_logpage_reserv_notif_rsvd0 = -1;
static int hf_nvme_get_logpage_reserv_notif_nsid = -1;
static int hf_nvme_get_logpage_reserv_notif_rsvd1 = -1;
static int hf_nvme_get_logpage_sanitize_sprog = -1;
static int hf_nvme_get_logpage_sanitize_sstat[5] = { NEG_LST_5 };
static int hf_nvme_get_logpage_sanitize_scdw10 = -1;
static int hf_nvme_get_logpage_sanitize_eto = -1;
static int hf_nvme_get_logpage_sanitize_etbe = -1;
static int hf_nvme_get_logpage_sanitize_etce = -1;
static int hf_nvme_get_logpage_sanitize_etond = -1;
static int hf_nvme_get_logpage_sanitize_etbend = -1;
static int hf_nvme_get_logpage_sanitize_etcend = -1;
static int hf_nvme_get_logpage_sanitize_rsvd = -1;

/* NVMe CQE fields */
static int hf_nvme_cqe_dword0 = -1;
static int hf_nvme_cqe_aev_dword0[6] = { NEG_LST_6 };
static int hf_nvme_cqe_dword0_sf_nq[3] = { NEG_LST_3 };
static int hf_nvme_cqe_dword0_sf_err = -1;

static int hf_nvme_cqe_get_features_dword0_arb[6] = { NEG_LST_6 };
static int hf_nvme_cqe_get_features_dword0_pm[4] = { NEG_LST_4 };
static int hf_nvme_cqe_get_features_dword0_lbart[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_tt[5] = { NEG_LST_5 };
static int hf_nvme_cqe_get_features_dword0_erec[4] = { NEG_LST_4 };
static int hf_nvme_cqe_get_features_dword0_vwce[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_nq[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_irqc[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_irqv[4] = { NEG_LST_4 };
static int hf_nvme_cqe_get_features_dword0_wan[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_aec[11] = { NEG_LST_11 };
static int hf_nvme_cqe_get_features_dword0_apst[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_kat[2] = { NEG_LST_2 };
static int hf_nvme_cqe_get_features_dword0_hctm[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_nops[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_rrl[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_plmc[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_plmw[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_lbasi[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_san[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_eg[4] = { NEG_LST_4 };
static int hf_nvme_cqe_get_features_dword0_swp[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_hid[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_rsrvn[6] = { NEG_LST_6 };
static int hf_nvme_cqe_get_features_dword0_rsrvp[3] = { NEG_LST_3 };
static int hf_nvme_cqe_get_features_dword0_nswp[3] = { NEG_LST_3 };

static int hf_nvme_cqe_dword1 = -1;
static int hf_nvme_cqe_sqhd = -1;
static int hf_nvme_cqe_sqid = -1;
static int hf_nvme_cqe_cid = -1;
static int hf_nvme_cqe_status[7] = { NEG_LST_7 };
static int hf_nvme_cqe_status_rsvd = -1;

/* tracking Cmd and its respective CQE */
static int hf_nvme_cmd_pkt = -1;
static int hf_nvme_data_req = -1;
static int hf_nvme_data_tr[NVME_CMD_MAX_TRS] = {NEG_LST_16};
static int hf_nvme_cqe_pkt = -1;
static int hf_nvme_cmd_latency = -1;

/* Data response fields */
static int hf_nvme_gen_data = -1;
/* Initialize the subtree pointers */
static gint ett_data = -1;

#define NVME_AQ_OPC_DELETE_SQ           0x0
#define NVME_AQ_OPC_CREATE_SQ           0x1
#define NVME_AQ_OPC_GET_LOG_PAGE        0x2
#define NVME_AQ_OPC_DELETE_CQ           0x4
#define NVME_AQ_OPC_CREATE_CQ           0x5
#define NVME_AQ_OPC_IDENTIFY            0x6
#define NVME_AQ_OPC_ABORT               0x8
#define NVME_AQ_OPC_SET_FEATURES        0x9
#define NVME_AQ_OPC_GET_FEATURES        0xa
#define NVME_AQ_OPC_ASYNC_EVE_REQ       0xc
#define NVME_AQ_OPC_NS_MGMT             0xd
#define NVME_AQ_OPC_FW_COMMIT           0x10
#define NVME_AQ_OPC_FW_IMG_DOWNLOAD     0x11
#define NVME_AQ_OPC_NS_ATTACH           0x15
#define NVME_AQ_OPC_KEEP_ALIVE          0x18

#define NVME_IOQ_OPC_FLUSH                  0x0
#define NVME_IOQ_OPC_WRITE                  0x1
#define NVME_IOQ_OPC_READ                   0x2
#define NVME_IOQ_OPC_WRITE_UNCORRECTABLE    0x4
#define NVME_IOQ_OPC_COMPARE                0x5
#define NVME_IOQ_OPC_WRITE_ZEROS            0x8
#define NVME_IOQ_OPC_DATASET_MGMT           0x9
#define NVME_IOQ_OPC_RESV_REG               0xd
#define NVME_IOQ_OPC_RESV_REPORT            0xe
#define NVME_IOQ_OPC_RESV_ACQUIRE           0x11
#define NVME_IOQ_OPC_RESV_RELEASE           0x15

#define NVME_IDENTIFY_CNS_IDENTIFY_NS       0x0
#define NVME_IDENTIFY_CNS_IDENTIFY_CTRL     0x1
#define NVME_IDENTIFY_CNS_IDENTIFY_NSLIST   0x2

typedef enum {
    NVME_CQE_SCT_GENERIC = 0x0,
    NVME_CQE_SCT_COMMAND = 0x1,
    NVME_CQE_SCT_MEDIA = 0x2,
    NVME_CQE_SCT_PATH = 0x3,
    NVME_CQE_SCT_VENDOR = 0x7,
} nvme_cqe_sct_t;

typedef enum {
    NVME_CQE_SC_GEN_CMD_OK = 0x00,
    NVME_CQE_SC_CMD_INVALID_OPCODE = 0x01,
    NVME_CQE_SC_GEN_CMD_INVALID_FIELD = 0x02,
    NVME_CQE_SC_GEN_CMD_CID_CONFLICT = 0x03,
    NVME_CQE_SC_GEN_DATA_TRANSFER_ERR = 0x04,
    NVME_CQE_SC_GEN_ABORT_DUE_TO_POWER_LOSS = 0x05,
    NVME_CQE_SC_GEN_INTERNAL_ERROR = 0x06,
    NVME_CQE_SC_GEN_ABORT_REQUESTED = 0x07,
    NVME_CQE_SC_GEN_ABORT_DUE_TO_SQ_DELETE = 0x08,
    NVME_CQE_SC_GEN_ABORT_DUE_TO_FAILED_FUSE = 0x09,
    NVME_CQE_SC_GEN_ABORT_DUE_TO_MISSED_FUSE = 0x0A,
    NVME_CQE_SC_GEN_INVALID_NAMESPACE_OR_FMT = 0x0B,
    NVME_CQE_SC_GEN_COMMAND_SEQUENCE_ERR = 0x0C,
    NVME_CQE_SC_GEN_INVALID_SGL_SD = 0x0D,
    NVME_CQE_SC_GEN_INVALID_SGL_SD_NUM = 0x0E,
    NVME_CQE_SC_GEN_INVALID_SGL_LEN = 0x0F,
    NVME_CQE_SC_GEN_INVALID_MDATA_SGL_LEN = 0x10,
    NVME_CQE_SC_GEN_INVALID_SGL_SD_TYPE = 0x11,
    NVME_CQE_SC_GEN_INVALID_USE_OF_MC_BUF = 0x12,
    NVME_CQE_SC_GEN_INVALID_PRP_OFFSET = 0x13,
    NVME_CQE_SC_GEN_ATOMIC_WRITE_UNIT_EXCEED = 0x14,
    NVME_CQE_SC_GEN_OPERATION_DENIED = 0x15,
    NVME_CQE_SC_GEN_INVALID_SGL_OFFSET = 0x16,
    NVME_CQE_SC_GEN_RESERVED_17H = 0x17,
    NVME_CQE_SC_GEN_HOST_ID_INVALID_FMT = 0x18,
    NVME_CQE_SC_GEN_KEEP_ALLIVE_EXPIRED = 0x19,
    NVME_CQE_SC_GEN_KEEP_ALIVE_INVALID = 0x1A,
    NVME_CQE_SC_GEN_ABORT_DUE_TO_PREEMPT_ABRT = 0x1B,
    NVME_CQE_SC_GEN_SANITIZE_FAILED = 0x1C,
    NVME_CQE_SC_GEN_SANITZE_IN_PROGRESS = 0x1D,
    NVME_CQE_SC_GEN_SGL_BLOCK_GRAN_INVALID = 0x1E,
    NVME_CQE_SC_GEN_CMD_NOT_SUPP_IN_CMB = 0x1F,
    NVME_CQE_SC_GEN_NAMESPACE_IS_WP = 0x20,
    NVME_CQE_SC_GEN_COMMAND_INTERRUPTED = 0x21,
    NVME_CQE_SC_GEN_TRANSIENT_TRASPORT_ERROR = 0x22,
    NVME_CQE_SC_GEN_LBA_OUT_OF_RANGE = 0x80,
    NVME_CQE_SC_GEN_CAPACITY_EXCEED = 0x81,
    NVME_CQE_SC_GEN_NAMESPACE_NOT_ERADY = 0x82,
    NVME_CQE_SC_GEN_RESERVATION_CONFLICT = 0x83,
    NVME_CQE_SC_GEN_FMT_IN_PROGRESS = 0x84,
} nvme_cqe_sc_gen_t;

typedef enum {
    NVME_CQE_SC_CMD_INVALID_CQ = 0x00,
    NVME_CQE_SC_CMD_INVALID_QID = 0x01,
    NVME_CQE_SC_CMD_INVALID_QUEUE_SIZE = 0x02,
    NVME_CQE_SC_CMD_ABORT_LIMIT_EXCEED = 0x03,
    NVME_CQE_SC_CMD_RESERVED_4H = 0x04,
    NVME_CQE_SC_CMD_ASYNC_REQ_LIMIT_EXCEED = 0x05,
    NVME_CQE_SC_CMD_INVALID_FW_SLOT = 0x06,
    NVME_CQE_SC_CMD_INVALID_FW_IMAGE = 0x07,
    NVME_CQE_SC_CMD_INVALID_IRQ_VECTOR = 0x08,
    NVME_CQE_SC_CMD_INVALID_LOG_PAGE = 0x09,
    NVME_CQE_SC_CMD_INVALID_FMT = 0x0A,
    NVME_CQE_SC_CMD_FW_ACTIVATION_NEEDS_RESET = 0x0B,
    NVME_CQE_SC_CMD_INVALID_QUEUE_DELETE = 0x0C,
    NVME_CQE_SC_CMD_FEATURE_ID_NOT_SAVEABLE = 0x0D,
    NVME_CQE_SC_CMD_FEATURE_NOT_CHANGEABLE = 0x0E,
    NVME_CQE_SC_CMD_FEATURE_NOT_NAMESPACE = 0x0F,
    NVME_CQE_SC_CMD_FEATURE_ACTIVATION_NEEDS_NVM_RESET = 0x10,
    NVME_CQE_SC_CMD_FEATURE_ACTIVATION_NEEDS_CNTRL_RESET = 0x11,
    NVME_CQE_SC_CMD_FW_ACTIVATION_NEED_MAX_TIME = 0x12,
    NVME_CQE_SC_CMD_FW_ACTIVATION_PROHIBITED = 0x13,
    NVME_CQE_SC_CMD_OVERLAPPING_RANGE = 0x14,
    NVME_CQE_SC_CMD_NAMESPACE_INSUF_CAPACITY = 0x15,
    NVME_CQE_SC_CMD_NAMESPACE_ID_NOT_AVAILABLE = 0x16,
    NVME_CQE_SC_CMD_RESERVED_17H = 0x17,
    NVME_CQE_SC_CMD_NAMESPACE_ALREADY_ATATCHED = 0x18,
    NVME_CQE_SC_CMD_NAMESPACE_IS_PRIVATE = 0x19,
    NVME_CQE_SC_CMD_NAMESPACE_NOT_ATTACHED = 0x1A,
    NVME_CQE_SC_CMD_THIN_PROVISION_NOT_SUPP = 0x1B,
    NVME_CQE_SC_CMD_INVALID_CNTRL_LIST = 0x1C,
    NVME_CQE_SC_CMD_SELF_TEST_IN_PROGRESS = 0x1D,
    NVME_CQE_SC_CMD_BOOT_PART_WRITE_PROHIBIT = 0x1E,
    NVME_CQE_SC_CMD_INVALID_CNTRL_ID = 0x1F,
    NVME_CQE_SC_CMD_INVALID_SECOND_CNTRL_STATE = 0x20,
    NVME_CQE_SC_CMD_IBVALID_CNRL_RES_NUM = 0x21,
    NVME_CQE_SC_CMD_INVALID_RESOURSE_ID = 0x22,
    NVME_CQE_SC_CMD_SANITIZE_PROHIBIT_WITH_PMR = 0x23,
    NVME_CQE_SC_CMD_INVALID_ANA_GROUP_ID = 0x24,
    NVME_CQE_SC_CMD_ANA_ATTACH_FAILED = 0x25,
    NVME_CQE_SC_CMD_CONFLICTING_ATTRS = 0x80,
    NVME_CQE_SC_CMD_INVALID_PROTECTION_INF = 0x81,
    NVME_CQE_SC_CMD_WRITE_TO_RO_REGION = 0x82,
} nvme_cqe_sc_cmd_t;

typedef enum {
    NVMEOF_CQE_SC_CMD_INCOMPAT_FORMAT = 0x80,
    NVMEOF_CQE_SC_CMD_CONT_BUSY = 0x81,
    NVMEOF_CQE_SC_CMD_CNCT_INV_PARAMS = 0x82,
    NVMEOF_CQE_SC_CMD_CNCT_RESTART_DISC = 0x83,
    NVMEOF_CQE_SC_CMD_CNCT_INV_HOST = 0x84,
    NVMEOF_CQE_SC_CMD_INV_QUEUE_TYPE = 0x85,
    NVMEOF_CQE_SC_CMD_DISC_RESTART = 0x90,
    NVMEOF_CQE_SC_CMD_AUTH_REQ = 0x91,
} nvmeof_cqe_sc_cmd_t;

typedef enum {
    NVME_CQE_SC_MEDIA_WRITE_FAULT = 0x80,
    NVME_CQE_SC_MEDIA_READ_FAULT = 0x81,
    NVME_CQE_SC_MEDIA_ETE_GUARD_CHECK_ERR = 0x82,
    NVME_CQE_SC_MEDIA_ETE_APPTAG_CHECK_ERR = 0x83,
    NVME_CQE_SC_MEDIA_ETE_REFTAG_CHECK_ERR = 0x84,
    NVME_CQE_SC_MEDIA_COMPARE_FAILURE = 0x85,
    NVME_CQE_SC_MEDIA_ACCESS_DENIED = 0x86,
    NVME_CQE_SC_MEDIA_DEALLOCATED_LBA = 0x87,
} nvme_cqe_sc_media_t;

typedef enum {
    NVME_CQE_SC_PATH_INTERNAL_PATH_ERROR = 0x00,
    NVME_CQE_SC_PATH_ANA_PERSISTENT_LOSS = 0x01,
    NVME_CQE_SC_PATH_ANA_INACCESSIBLE = 0x02,
    NVME_CQE_SC_PATH_ANA_TRANSIENT = 0x03,
    NVME_CQE_SC_PATH_CNTRL_PATH_ERROR = 0x60,
    NVME_CQE_SC_PATH_HOST_PATH_ERROR = 0x70,
    NVME_CQE_SC_PATH_CMD_ABORT = 0x71,
} nvme_cqe_sc_path_t;

static const value_string nvme_cqe_sct_tbl[] = {
    { NVME_CQE_SCT_GENERIC, "Generic Command Status" },
    { NVME_CQE_SCT_COMMAND, "Command Specific Status" },
    { NVME_CQE_SCT_MEDIA, "Media and Data Integrity Errors" },
    { NVME_CQE_SCT_PATH, "Path Related Status" },
    { NVME_CQE_SCT_VENDOR, "Vendor Specific" },
    { 0, NULL },
};

static const value_string nvme_cqe_sc_gen_tbl[] = {
    { NVME_CQE_SC_GEN_CMD_OK, "Successful Completion" },
    { NVME_CQE_SC_CMD_INVALID_OPCODE, "Invalid opcode field" },
    { NVME_CQE_SC_GEN_CMD_INVALID_FIELD, "Invalid Field in Command" },
    { NVME_CQE_SC_GEN_CMD_CID_CONFLICT, "Command ID Conflict" },
    { NVME_CQE_SC_GEN_DATA_TRANSFER_ERR, "Data Transfer Error" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_POWER_LOSS, "Commands Aborted due to Power Loss Notification" },
    { NVME_CQE_SC_GEN_INTERNAL_ERROR, "Internal Error" },
    { NVME_CQE_SC_GEN_ABORT_REQUESTED, "Command Abort Requested" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_SQ_DELETE, "Command Aborted due to SQ Deletion" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_FAILED_FUSE, "Command Aborted due to Failed Fused Command" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_MISSED_FUSE, "Command Aborted due to Missing Fused Command" },
    { NVME_CQE_SC_GEN_INVALID_NAMESPACE_OR_FMT, "Invalid Namespace or Format" },
    { NVME_CQE_SC_GEN_COMMAND_SEQUENCE_ERR, "Command Sequence Error" },
    { NVME_CQE_SC_GEN_INVALID_SGL_SD, "Invalid SGL Segment Descriptor" },
    { NVME_CQE_SC_GEN_INVALID_SGL_SD_NUM, "Invalid Number of SGL Descriptors" },
    { NVME_CQE_SC_GEN_INVALID_SGL_LEN, "Data SGL Length Invalid" },
    { NVME_CQE_SC_GEN_INVALID_MDATA_SGL_LEN, "Metadata SGL Length Invalid" },
    { NVME_CQE_SC_GEN_INVALID_SGL_SD_TYPE, "SGL Descriptor Type Invalid" },
    { NVME_CQE_SC_GEN_INVALID_USE_OF_MC_BUF, "Invalid Use of Controller Memory Buffer" },
    { NVME_CQE_SC_GEN_INVALID_PRP_OFFSET, "PRP Offset Invalid" },
    { NVME_CQE_SC_GEN_ATOMIC_WRITE_UNIT_EXCEED, "Atomic Write Unit Exceeded" },
    { NVME_CQE_SC_GEN_OPERATION_DENIED, "Operation Denied" },
    { NVME_CQE_SC_GEN_INVALID_SGL_OFFSET, "SGL Offset Invalid" },
    { NVME_CQE_SC_GEN_RESERVED_17H, "Reserved" },
    { NVME_CQE_SC_GEN_HOST_ID_INVALID_FMT, "Host Identifier Inconsistent Format" },
    { NVME_CQE_SC_GEN_KEEP_ALLIVE_EXPIRED, "Keep Alive Timer Expired" },
    { NVME_CQE_SC_GEN_KEEP_ALIVE_INVALID, "Keep Alive Timeout Invalid" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_PREEMPT_ABRT, "Command Aborted due to Preempt and Abort" },
    { NVME_CQE_SC_GEN_SANITIZE_FAILED, "Sanitize Failed" },
    { NVME_CQE_SC_GEN_SANITZE_IN_PROGRESS,"Sanitize In Progress"  },
    { NVME_CQE_SC_GEN_SGL_BLOCK_GRAN_INVALID, "SGL Data Block Granularity Invalid" },
    { NVME_CQE_SC_GEN_CMD_NOT_SUPP_IN_CMB, "Command Not Supported for Queue in CMB" },
    { NVME_CQE_SC_GEN_NAMESPACE_IS_WP, "Namespace is Write Protected" },
    { NVME_CQE_SC_GEN_COMMAND_INTERRUPTED,"Command Interrupted" },
    { NVME_CQE_SC_GEN_TRANSIENT_TRASPORT_ERROR, "Transient Transport Error"},
    { NVME_CQE_SC_GEN_LBA_OUT_OF_RANGE, "LBA Out of Range" },
    { NVME_CQE_SC_GEN_CAPACITY_EXCEED, "Capacity Exceeded" },
    { NVME_CQE_SC_GEN_NAMESPACE_NOT_ERADY, "Namespace Not Ready" },
    { NVME_CQE_SC_GEN_RESERVATION_CONFLICT, "Reservation Conflict" },
    { NVME_CQE_SC_GEN_FMT_IN_PROGRESS, "Format In Progress"},
    { 0, NULL },
};

static const value_string nvme_cqe_sc_cmd_tbl[] = {
    { NVME_CQE_SC_CMD_INVALID_CQ, "Completion Queue Invalid" },
    { NVME_CQE_SC_CMD_INVALID_QID, "Invalid Queue Identifier" },
    { NVME_CQE_SC_CMD_INVALID_QUEUE_SIZE, "Invalid Queue Size" },
    { NVME_CQE_SC_CMD_ABORT_LIMIT_EXCEED, "Abort Command Limit Exceeded" },
    { NVME_CQE_SC_CMD_RESERVED_4H, "Reserved" },
    { NVME_CQE_SC_CMD_ASYNC_REQ_LIMIT_EXCEED, "Asynchronous Event Request Limit Exceeded" },
    { NVME_CQE_SC_CMD_INVALID_FW_SLOT, "Invalid Firmware Slot" },
    { NVME_CQE_SC_CMD_INVALID_FW_IMAGE, "Invalid Firmware Image" },
    { NVME_CQE_SC_CMD_INVALID_IRQ_VECTOR, "Invalid Interrupt Vector" },
    { NVME_CQE_SC_CMD_INVALID_LOG_PAGE, "Invalid Log Page" },
    { NVME_CQE_SC_CMD_INVALID_FMT, "Invalid Format" },
    { NVME_CQE_SC_CMD_FW_ACTIVATION_NEEDS_RESET, "Firmware Activation Requires Conventional Reset" },
    { NVME_CQE_SC_CMD_INVALID_QUEUE_DELETE, "Invalid Queue Deletion" },
    { NVME_CQE_SC_CMD_FEATURE_ID_NOT_SAVEABLE, "Feature Identifier Not Saveable" },
    { NVME_CQE_SC_CMD_FEATURE_NOT_CHANGEABLE, "Feature Not Changeable" },
    { NVME_CQE_SC_CMD_FEATURE_NOT_NAMESPACE, "Feature Not Namespace Specific" },
    { NVME_CQE_SC_CMD_FEATURE_ACTIVATION_NEEDS_NVM_RESET, "Firmware Activation Requires NVM Subsystem Reset" },
    { NVME_CQE_SC_CMD_FEATURE_ACTIVATION_NEEDS_CNTRL_RESET, "Firmware Activation Requires Controller Level Reset" },
    { NVME_CQE_SC_CMD_FW_ACTIVATION_NEED_MAX_TIME, "Firmware Activation Requires Maximum Time Violation" },
    { NVME_CQE_SC_CMD_FW_ACTIVATION_PROHIBITED, "Firmware Activation Prohibited" },
    { NVME_CQE_SC_CMD_OVERLAPPING_RANGE, "Overlapping Range" },
    { NVME_CQE_SC_CMD_NAMESPACE_INSUF_CAPACITY, "Namespace Insufficient Capacity" },
    { NVME_CQE_SC_CMD_NAMESPACE_ID_NOT_AVAILABLE, "Namespace Identifier Unavailable" },
    { NVME_CQE_SC_CMD_RESERVED_17H, "Reserved" },
    { NVME_CQE_SC_CMD_NAMESPACE_ALREADY_ATATCHED, "Namespace Already Attached" },
    { NVME_CQE_SC_CMD_NAMESPACE_IS_PRIVATE, "Namespace Is Private" },
    { NVME_CQE_SC_CMD_NAMESPACE_NOT_ATTACHED, "Namespace Not Attached" },
    { NVME_CQE_SC_CMD_THIN_PROVISION_NOT_SUPP, "Thin Provisioning Not Supported" },
    { NVME_CQE_SC_CMD_INVALID_CNTRL_LIST, "Controller List Invalid" },
    { NVME_CQE_SC_CMD_SELF_TEST_IN_PROGRESS, "Device Self-test In Progress" },
    { NVME_CQE_SC_CMD_BOOT_PART_WRITE_PROHIBIT, "Boot Partition Write Prohibited" },
    { NVME_CQE_SC_CMD_INVALID_CNTRL_ID, "Invalid Controller Identifier" },
    { NVME_CQE_SC_CMD_INVALID_SECOND_CNTRL_STATE, "Invalid Secondary Controller State" },
    { NVME_CQE_SC_CMD_IBVALID_CNRL_RES_NUM, "Invalid Number of Controller Resources" },
    { NVME_CQE_SC_CMD_INVALID_RESOURSE_ID, "Invalid Resource Identifier" },
    { NVME_CQE_SC_CMD_SANITIZE_PROHIBIT_WITH_PMR, "Sanitize Prohibited While Persistent Memory Region  is Enabled" },
    { NVME_CQE_SC_CMD_INVALID_ANA_GROUP_ID, "ANA Group Identifier Invalid" },
    { NVME_CQE_SC_CMD_ANA_ATTACH_FAILED, "ANA Attach Failed" },
    { NVME_CQE_SC_CMD_CONFLICTING_ATTRS, "Conflicting Attributes" },
    { NVME_CQE_SC_CMD_INVALID_PROTECTION_INF, "Invalid Protection Information" },
    { NVME_CQE_SC_CMD_WRITE_TO_RO_REGION, "Attempted Write to Read Only Range" },
    { 0, NULL },
};

static const value_string nvmeof_cqe_sc_cmd_tbl[] = {
    { NVMEOF_CQE_SC_CMD_INCOMPAT_FORMAT, "Incompatible Format" },
    { NVMEOF_CQE_SC_CMD_CONT_BUSY, "Controller Busy" },
    { NVMEOF_CQE_SC_CMD_CNCT_INV_PARAMS, "Connect Invalid Parameters" },
    { NVMEOF_CQE_SC_CMD_CNCT_RESTART_DISC, "Connect Restart Discovery" },
    { NVMEOF_CQE_SC_CMD_CNCT_INV_HOST, "Connect Invalid Host" },
    { NVMEOF_CQE_SC_CMD_INV_QUEUE_TYPE, "Invalid Queue Type" },
    { NVMEOF_CQE_SC_CMD_DISC_RESTART, "Discover Restart" },
    { NVMEOF_CQE_SC_CMD_AUTH_REQ, "Authentication Required" },
    { 0, NULL },
};

static const value_string nvme_cqe_sc_media_tbl[] = {
    { NVME_CQE_SC_MEDIA_WRITE_FAULT, "Write Fault" },
    { NVME_CQE_SC_MEDIA_READ_FAULT, "Unrecovered Read Error" },
    { NVME_CQE_SC_MEDIA_ETE_GUARD_CHECK_ERR, "End-to-end Guard Check Error" },
    { NVME_CQE_SC_MEDIA_ETE_APPTAG_CHECK_ERR, "End-to-end Application Tag Check Error" },
    { NVME_CQE_SC_MEDIA_ETE_REFTAG_CHECK_ERR, "End-to-end Reference Tag Check Error" },
    { NVME_CQE_SC_MEDIA_COMPARE_FAILURE, "Compare Failure" },
    { NVME_CQE_SC_MEDIA_ACCESS_DENIED, "Access Denied" },
    { NVME_CQE_SC_MEDIA_DEALLOCATED_LBA, "Deallocated or Unwritten Logical Block" },
    { 0, NULL },
};

static const value_string nvme_cqe_sc_path_tbl[] = {
    { NVME_CQE_SC_PATH_INTERNAL_PATH_ERROR, "Internal Path Error" },
    { NVME_CQE_SC_PATH_ANA_PERSISTENT_LOSS, "Asymmetric Access Persistent Loss" },
    { NVME_CQE_SC_PATH_ANA_INACCESSIBLE, "Asymmetric Access Inaccessible" },
    { NVME_CQE_SC_PATH_ANA_TRANSIENT, "Asymmetric Access Transition" },
    { NVME_CQE_SC_PATH_CNTRL_PATH_ERROR, "Controller Pathing Error" },
    { NVME_CQE_SC_PATH_HOST_PATH_ERROR, "Host Pathing Error" },
    { NVME_CQE_SC_PATH_CMD_ABORT, "Command Aborted By Host" },
    { 0, NULL },
};

static const value_string aq_opc_tbl[] = {
    { NVME_AQ_OPC_DELETE_SQ,     "Delete SQ"},
    { NVME_AQ_OPC_CREATE_SQ,     "Create SQ"},
    { NVME_AQ_OPC_GET_LOG_PAGE,  "Get Log Page"},
    { NVME_AQ_OPC_DELETE_CQ,     "Delete CQ"},
    { NVME_AQ_OPC_CREATE_CQ,     "Create CQ"},
    { NVME_AQ_OPC_IDENTIFY,      "Identify"},
    { NVME_AQ_OPC_ABORT,         "Abort"},
    { NVME_AQ_OPC_SET_FEATURES,  "Set Features"},
    { NVME_AQ_OPC_GET_FEATURES,  "Get Features"},
    { NVME_AQ_OPC_ASYNC_EVE_REQ, "Async Event Request"},
    { NVME_AQ_OPC_NS_MGMT,       "Namespace Management"},
    { NVME_AQ_OPC_FW_COMMIT,     "Firmware Commit"},
    { NVME_AQ_OPC_FW_IMG_DOWNLOAD, "Firmware Image Download"},
    { NVME_AQ_OPC_NS_ATTACH,     "Namespace attach"},
    { NVME_AQ_OPC_KEEP_ALIVE,    "Keep Alive"},
    { 0, NULL}
};

static const value_string ioq_opc_tbl[] = {
    { NVME_IOQ_OPC_FLUSH,         "Flush"},
    { NVME_IOQ_OPC_WRITE,         "Write"},
    { NVME_IOQ_OPC_READ,          "Read"},
    { NVME_IOQ_OPC_WRITE_UNCORRECTABLE, "Write Uncorrectable"},
    { NVME_IOQ_OPC_COMPARE,       "Compare"},
    { NVME_IOQ_OPC_WRITE_ZEROS,   "Write Zero"},
    { NVME_IOQ_OPC_DATASET_MGMT,  "Dataset Management"},
    { NVME_IOQ_OPC_RESV_REG,      "Reserve Register"},
    { NVME_IOQ_OPC_RESV_REPORT,   "Reserve Report"},
    { NVME_IOQ_OPC_RESV_ACQUIRE,  "Reserve Acquire"},
    { NVME_IOQ_OPC_RESV_RELEASE,  "Reserve Release"},
    { 0, NULL}
};

#define NVME_CMD_SGL_DATA_DESC          0x0
#define NVME_CMD_SGL_BIT_BUCKET_DESC    0x1
#define NVME_CMD_SGL_SEGMENT_DESC       0x2
#define NVME_CMD_SGL_LAST_SEGMENT_DESC  0x3
#define NVME_CMD_SGL_KEYED_DATA_DESC    0x4
#define NVME_CMD_SGL_VENDOR_DESC        0xf

static const value_string sgl_type_tbl[] = {
    { NVME_CMD_SGL_DATA_DESC,         "Data Block"},
    { NVME_CMD_SGL_BIT_BUCKET_DESC,   "Bit Bucket"},
    { NVME_CMD_SGL_SEGMENT_DESC,      "Segment"},
    { NVME_CMD_SGL_LAST_SEGMENT_DESC, "Last Segment"},
    { NVME_CMD_SGL_KEYED_DATA_DESC,   "Keyed Data Block"},
    { NVME_CMD_SGL_VENDOR_DESC,       "Vendor Specific"},
    { 0, NULL}
};

#define NVME_CMD_SGL_SUB_DESC_ADDR      0x0
#define NVME_CMD_SGL_SUB_DESC_OFFSET    0x1
#define NVME_CMD_SGL_SUB_DESC_TRANSPORT 0xf

static const value_string sgl_sub_type_tbl[] = {
    { NVME_CMD_SGL_SUB_DESC_ADDR,      "Address"},
    { NVME_CMD_SGL_SUB_DESC_OFFSET,    "Offset"},
    { NVME_CMD_SGL_SUB_DESC_TRANSPORT, "Transport specific"},
    { 0, NULL}
};


static const value_string cns_table[] = {
    { 0, "Namespace"},
    { 1, "Controller"},
    { 2, "Active Namespace List"},
    { 3, "Namespace Identification Descriptor"},
    {4, "NVM Set List"},
    {0x10, "Allocated Namespace ID List"},
    {0x11, "Namespace Data Structure"},
    {0x12, "Controller List Attached to NSID"},
    {0x13, "Existing Controllers List"},
    {0x14, "Primary Controller Capabilities"},
    {0x15, "Secondary Controller List"},
    {0x16, "Namespace Granularity List"},
    {0x17, "UUID List"},
    {0, NULL}
};

static const value_string dsm_acc_freq_tbl[] = {
    { 0, "No frequency"},
    { 1, "Typical"},
    { 2, "Infrequent Read/Write"},
    { 3, "Infrequent Writes, Frequent Reads"},
    { 4, "Frequent Writes, Infrequent Reads"},
    { 5, "Frequent Read/Write"},
    { 6, "One time read"},
    { 7, "Speculative read"},
    { 8, "Likely tobe overwritten"},
    { 0, NULL}
};

static const value_string dsm_acc_lat_tbl[] = {
    { 0, "None"},
    { 1, "Idle (Longer)"},
    { 2, "Normal (Typical)"},
    { 3, "Low (Smallest)"},
    { 0, NULL}
};


void
nvme_publish_qid(proto_tree *tree, int field_index, guint16 qid)
{
    proto_item *cmd_ref_item;

    cmd_ref_item = proto_tree_add_uint_format_value(tree, field_index, NULL,
                       0, 0, qid,
                     qid ? "%d (IOQ)" : "%d (AQ)",
                                     qid);

    proto_item_set_generated(cmd_ref_item);
}

static void nvme_build_pending_cmd_key(wmem_tree_key_t *cmd_key, guint32 *key)
{
    cmd_key[0].length = 1;
    cmd_key[0].key = key;
    cmd_key[1].length = 0;
    cmd_key[1].key = NULL;
}

static void
nvme_build_done_frame_key(wmem_tree_key_t *cmd_key, guint32 *key, guint32 *frame)
{
    guint idx = 0;
    if (key) {
        cmd_key[0].length = 1;
        cmd_key[0].key = key;
        idx = 1;
    }
    cmd_key[idx].length = 1;
    cmd_key[idx].key = frame;
    idx++;

    cmd_key[idx].length = 0;
    cmd_key[idx].key = NULL;
}

void
nvme_add_cmd_to_pending_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             struct nvme_cmd_ctx *cmd_ctx,
                             void *ctx, guint16 cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = cmd_id;

    cmd_ctx->cmd_pkt_num = pinfo->num;
    cmd_ctx->cqe_pkt_num = 0;
    cmd_ctx->cmd_start_time = pinfo->abs_ts;
    nstime_set_zero(&cmd_ctx->cmd_end_time);

    /* this is a new cmd, create a new command context and map it to the
       unmatched table
     */
    nvme_build_pending_cmd_key(cmd_key, &key);
    wmem_tree_insert32_array(q_ctx->pending_cmds, cmd_key, (void *)ctx);
}

void* nvme_lookup_cmd_in_pending_list(struct nvme_q_ctx *q_ctx, guint16 cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = cmd_id;

    nvme_build_pending_cmd_key(cmd_key, &key);
    return wmem_tree_lookup32_array(q_ctx->pending_cmds, cmd_key);
}


static void nvme_build_pending_transfer_key(wmem_tree_key_t *key, struct keyed_data_req *req)
{
    key[0].length = 2;
    key[0].key = (guint32 *)&req->addr;
    key[1].length = 1;
    key[1].key = &req->key;
    key[2].length = 1;
    key[2].key = &req->size;
    key[3].length = 0;
    key[3].key = NULL;
}

void nvme_add_data_request(struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx,
                                        struct keyed_data_req *req)
{
    wmem_tree_key_t tr_key[4];

    memset(cmd_ctx->data_tr_pkt_num, 0, sizeof(cmd_ctx->data_tr_pkt_num));
    nvme_build_pending_transfer_key(tr_key, req);
    wmem_tree_insert32_array(q_ctx->data_requests, tr_key, (void *)cmd_ctx);
}

struct nvme_cmd_ctx* nvme_lookup_data_request(struct nvme_q_ctx *q_ctx,
                                        struct keyed_data_req *req)
{
    wmem_tree_key_t tr_key[4];

    nvme_build_pending_transfer_key(tr_key, req);
    return (struct nvme_cmd_ctx*)wmem_tree_lookup32_array(q_ctx->data_requests, tr_key);
}

void
nvme_add_data_tr_pkt(struct nvme_q_ctx *q_ctx,
                       struct nvme_cmd_ctx *cmd_ctx, guint32 rkey, guint32 frame_num)
{
    wmem_tree_key_t cmd_key[3];

    nvme_build_done_frame_key(cmd_key, rkey ? &rkey : NULL, &frame_num);
    wmem_tree_insert32_array(q_ctx->data_responses, cmd_key, (void*)cmd_ctx);
}

struct nvme_cmd_ctx*
nvme_lookup_data_tr_pkt(struct nvme_q_ctx *q_ctx,
                          guint32 rkey, guint32 frame_num)
{
    wmem_tree_key_t cmd_key[3];

    nvme_build_done_frame_key(cmd_key, rkey ? &rkey : NULL, &frame_num);
    return (struct nvme_cmd_ctx*)wmem_tree_lookup32_array(q_ctx->data_responses, cmd_key);
}

void
nvme_add_data_tr_off(struct nvme_q_ctx *q_ctx, guint32 off, guint32 frame_num)
{
    wmem_tree_key_t cmd_key[2];

    nvme_build_done_frame_key(cmd_key, NULL, &frame_num);
    wmem_tree_insert32_array(q_ctx->data_offsets, cmd_key, GUINT_TO_POINTER(off));
}

guint32
nvme_lookup_data_tr_off(struct nvme_q_ctx *q_ctx, guint32 frame_num)
{
    wmem_tree_key_t cmd_key[2];

    nvme_build_done_frame_key(cmd_key, NULL, &frame_num);
    return GPOINTER_TO_UINT(wmem_tree_lookup32_array(q_ctx->data_offsets, cmd_key));
}

void
nvme_add_cmd_cqe_to_done_list(struct nvme_q_ctx *q_ctx,
                              struct nvme_cmd_ctx *cmd_ctx, guint16 cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = cmd_id;
    guint32 frame_num;

    nvme_build_done_frame_key(cmd_key, &key, &frame_num);

    /* found matchng entry. Add entries to the matched table for both cmd and cqe.
     */
    frame_num = cmd_ctx->cqe_pkt_num;
    wmem_tree_insert32_array(q_ctx->done_cmds, cmd_key, (void*)cmd_ctx);

    frame_num = cmd_ctx->cmd_pkt_num;
    wmem_tree_insert32_array(q_ctx->done_cmds, cmd_key, (void*)cmd_ctx);
}

void*
nvme_lookup_cmd_in_done_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             guint16 cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = cmd_id;
    guint32 frame_num = pinfo->num;

    nvme_build_done_frame_key(cmd_key, &key, &frame_num);

    return wmem_tree_lookup32_array(q_ctx->done_cmds, cmd_key);
}

void
nvme_publish_cmd_latency(proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx,
                         int field_index)
{
    proto_item *cmd_ref_item;
    nstime_t ns;
    double cmd_latency;

    nstime_delta(&ns, &cmd_ctx->cmd_end_time, &cmd_ctx->cmd_start_time);
    cmd_latency = nstime_to_msec(&ns);
    cmd_ref_item = proto_tree_add_double_format_value(tree, field_index,
                            NULL, 0, 0, cmd_latency,
                            "%.3f ms", cmd_latency);
    proto_item_set_generated(cmd_ref_item);
}

void nvme_update_cmd_end_info(packet_info *pinfo, struct nvme_cmd_ctx *cmd_ctx)
{
    cmd_ctx->cmd_end_time = pinfo->abs_ts;
    cmd_ctx->cqe_pkt_num = pinfo->num;
}

void
nvme_publish_link(proto_tree *tree, tvbuff_t *tvb, int hf_index,
                                       guint32 pkt_no, gboolean zero_ok)
{
    proto_item *ref_item;

    if (pkt_no || zero_ok) {
        ref_item = proto_tree_add_uint(tree, hf_index,
                                 tvb, 0, 0, pkt_no);
        proto_item_set_generated(ref_item);
    }
}

void
nvme_publish_to_cmd_link(proto_tree *tree, tvbuff_t *tvb,
                          int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->cmd_pkt_num, TRUE);
}

void
nvme_publish_to_cqe_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->cqe_pkt_num, FALSE);
}

void
nvme_publish_to_data_req_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->data_req_pkt_num, FALSE);
}

static void
nvme_publish_to_data_tr_links(proto_tree *tree, tvbuff_t *tvb,
                             int *index_arr, struct nvme_cmd_ctx *cmd_ctx)
{
    guint i;
    for (i = 0; i < NVME_CMD_MAX_TRS; i++)
        nvme_publish_link(tree, tvb, index_arr[i], cmd_ctx->data_tr_pkt_num[i], FALSE);
}

void nvme_publish_to_data_resp_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->data_tr_pkt_num[0], FALSE);
}

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                          int field_index, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, guint cmd_off, gboolean visited)
{
    proto_item *ti, *sgl_tree, *type_item, *sub_type_item;
    guint8 sgl_identifier, desc_type, desc_sub_type;
    int offset = 24 + cmd_off;

    ti = proto_tree_add_item(cmd_tree, field_index, cmd_tvb, offset,
                             16, ENC_NA);
    sgl_tree = proto_item_add_subtree(ti, ett_data);

    sgl_identifier = tvb_get_guint8(cmd_tvb, offset + 15);
    desc_type = (sgl_identifier & 0xff) >> 4;
    desc_sub_type = sgl_identifier & 0x0f;

    type_item = proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_type,
                                    cmd_tvb, offset + 15, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(type_item, " %s",
                           val_to_str_const(desc_type, sgl_type_tbl, "Reserved"));

    sub_type_item = proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_sub_type,
                                        cmd_tvb,
                                        offset + 15, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(sub_type_item, " %s",
                           val_to_str_const(desc_sub_type, sgl_sub_type_tbl, "Reserved"));

    switch (desc_type) {
    case NVME_CMD_SGL_DATA_DESC:
    case NVME_CMD_SGL_LAST_SEGMENT_DESC:
    case NVME_CMD_SGL_SEGMENT_DESC:
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_addr, cmd_tvb,
                            offset, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_len, cmd_tvb,
                            offset + 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_rsvd, cmd_tvb,
                            offset + 12, 3, ENC_NA);
        break;
    case NVME_CMD_SGL_BIT_BUCKET_DESC:
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_addr_rsvd, cmd_tvb,
                            offset, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_len, cmd_tvb,
                            offset + 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_rsvd, cmd_tvb,
                            offset + 12, 3, ENC_NA);
        break;
    case NVME_CMD_SGL_KEYED_DATA_DESC:
    {
        struct keyed_data_req req;
        proto_tree_add_item_ret_uint64(sgl_tree, hf_nvme_cmd_sgl_desc_addr, cmd_tvb,
                            offset, 8, ENC_LITTLE_ENDIAN, &req.addr);
        proto_tree_add_item_ret_uint(sgl_tree, hf_nvme_cmd_sgl_desc_len, cmd_tvb,
                            offset + 8, 3, ENC_LITTLE_ENDIAN, &req.size);
        proto_tree_add_item_ret_uint(sgl_tree, hf_nvme_cmd_sgl_desc_key, cmd_tvb,
                            offset + 11, 4, ENC_LITTLE_ENDIAN, &req.key);
        if (!visited && cmd_ctx && q_ctx && q_ctx->data_requests)
            nvme_add_data_request(q_ctx, cmd_ctx, &req);
        break;
    }
    case NVME_CMD_SGL_VENDOR_DESC:
    default:
        break;
    }
}

static void
dissect_nvme_rwc_common_word_10_11_12_14_15(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti, *prinfo_tree;
    guint16 num_lba;

    /* word 10, 11 */
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_slba, cmd_tvb,
                        40, 8, ENC_LITTLE_ENDIAN);
    /* add 1 for readability, as its zero based value */
    num_lba = tvb_get_guint16(cmd_tvb, 48, ENC_LITTLE_ENDIAN) + 1;

    /* word 12 */
    proto_tree_add_uint(cmd_tree, hf_nvme_cmd_nlb,
                        cmd_tvb, 48, 2, num_lba);

    proto_tree_add_item(cmd_tree, hf_nvme_cmd_rsvd2, cmd_tvb,
                        50, 2, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(cmd_tree, hf_nvme_cmd_prinfo, cmd_tvb, 50,
                             1, ENC_NA);
    prinfo_tree = proto_item_add_subtree(ti, ett_data);

    proto_tree_add_item(prinfo_tree, hf_nvme_cmd_prinfo_prchk_lbrtag, cmd_tvb,
                        50, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(prinfo_tree, hf_nvme_cmd_prinfo_prchk_apptag, cmd_tvb,
                        50, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(prinfo_tree, hf_nvme_cmd_prinfo_prchk_guard, cmd_tvb,
                        50, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(prinfo_tree, hf_nvme_cmd_prinfo_pract, cmd_tvb,
                        50, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_cmd_fua, cmd_tvb,
                        50, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_lr, cmd_tvb,
                        50, 2, ENC_LITTLE_ENDIAN);

    /* word 14, 15 */
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_eilbrt, cmd_tvb,
                        56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_elbat, cmd_tvb,
                        60, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_elbatm, cmd_tvb,
                        62, 2, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_identify_ns_lbafs(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti, *lbafs_tree, *item;
    int lbaf_off, i;
    guint8 nlbaf, lbads;
    guint16 ms;
    guint32 lbaf_raw;

    nlbaf = tvb_get_guint8(cmd_tvb, 25) + 1; // +1 for zero-base value

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_lbafs, cmd_tvb,
                             128, 64, ENC_NA);
    lbafs_tree = proto_item_add_subtree(ti, ett_data);

    for (i = 0; i < nlbaf; i++) {
        lbaf_off = 128 + i * 4;

        lbaf_raw = tvb_get_guint32(cmd_tvb, lbaf_off, ENC_LITTLE_ENDIAN);
        ms = lbaf_raw & 0xFF;
        lbads = (lbaf_raw >> 16) & 0xF;
        item = proto_tree_add_item(lbafs_tree, hf_nvme_identify_ns_lbaf,
                                   cmd_tvb, lbaf_off, 4, ENC_LITTLE_ENDIAN);
        proto_item_set_text(item, "LBAF%d: lbads %d ms %d", i, lbads, ms);
    }
}

static void dissect_nvme_identify_ns_resp(tvbuff_t *cmd_tvb,
                                            proto_tree *cmd_tree, guint off, guint len)
{
    proto_item *ti;
    guint start;
    if (!off) {
        /* minimal MTU fits this block */
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_nsze, cmd_tvb,
                        0, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_ncap, cmd_tvb,
                        8, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_nuse, cmd_tvb,
                        16, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_nsfeat, cmd_tvb,
                        24, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_nlbaf, cmd_tvb,
                        25, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_flbas, cmd_tvb,
                        26, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_mc, cmd_tvb,
                        27, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_dpc, cmd_tvb,
                        28, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_dps, cmd_tvb,
                        29, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_nmic, cmd_tvb,
                        30, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_nguid, cmd_tvb,
                        104, 16, ENC_NA);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_eui64, cmd_tvb,
                        120, 8, ENC_NA);

        dissect_nvme_identify_ns_lbafs(cmd_tvb, cmd_tree);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_rsvd, cmd_tvb,
                        192, 192, ENC_NA);
    }
    if (off >= 384)
        start = 0;
    else
        start = 384 - off;
    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_vs, cmd_tvb,
                        start, len - start, ENC_NA);
    proto_item_append_text(ti, " (offset %u)", (off <= 384) ? 0 : off-384);
}

static void dissect_nvme_identify_nslist_resp(tvbuff_t *cmd_tvb,
                                              proto_tree *cmd_tree, guint off, guint len)
{
    guint32 nsid;
    proto_item *item;
    guint done = 0;

    for (; off < 4096 && (done + 4) <= len; off += 4) {
        nsid = tvb_get_guint32(cmd_tvb, done, ENC_LITTLE_ENDIAN);
        if (nsid == 0)
            break;

        item = proto_tree_add_item(cmd_tree, hf_nvme_identify_nslist_nsid,
                                   cmd_tvb, done, 4, ENC_LITTLE_ENDIAN);
        proto_item_set_text(item, "nsid[%u]: %u", off / 4, nsid);
        done += 4;
    }
}

#define ASPEC(_x_) _x_, array_length(_x_)

static void add_group_mask_entry(tvbuff_t *tvb, proto_tree *tree, guint offset, guint bytes, int *array, guint array_len)
{
    proto_item *ti;
    proto_tree *grp;
    guint i;

    ti = proto_tree_add_item(tree, array[0], tvb, offset, bytes, ENC_LITTLE_ENDIAN);
    grp =  proto_item_add_subtree(ti, ett_data);

    for (i = 1; i < array_len; i++)
        proto_tree_add_item(grp, array[i], tvb, offset, bytes, ENC_LITTLE_ENDIAN);
}

static void add_ctrl_x16_bytes( gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%x (%u bytes)", val, val * 16);
}

static void dissect_nvme_identify_ctrl_resp_nvmeof(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, guint32 off)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nvmeof, cmd_tvb, 1792-off, 256, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_ioccsz, cmd_tvb, 1792-off, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_iorcsz, cmd_tvb, 1796-off, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_icdoff, cmd_tvb, 1800-off, 2, ENC_LITTLE_ENDIAN);

    add_group_mask_entry(cmd_tvb, grp, 1802-off, 1, ASPEC(hf_nvme_identify_ctrl_nvmeof_fcatt));
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_msdbd, cmd_tvb, 1803-off, 1, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, grp, 1804-off, 2, ASPEC(hf_nvme_identify_ctrl_nvmeof_ofcs));
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_rsvd, cmd_tvb, 1806-off, 242, ENC_NA);
}


static const true_false_string units_watts = {
    "1 (0.0001 Watt units)",
    "0 (0.01 Watt units)"
};


static const value_string power_scale_tbl[] = {
    { 0, "not reported for this power state" },
    { 1, "0.0001 Watt units" },
    { 2, "0.01 Watt units" },
    { 3,  "reserved value" },
    { 0, NULL}
};

static void dissect_nvme_identify_ctrl_resp_power_state_descriptor(tvbuff_t *cmd_tvb, proto_tree *tree, guint8 idx, guint32 off)
{
    proto_item *ti;
    proto_tree *grp;

    off = 2048 - off + idx *32;
    ti = proto_tree_add_bytes_format(tree, hf_nvme_identify_ctrl_psd, cmd_tvb, off, 32, NULL,
                                           "Power State %u Descriptor (PSD%u)", idx, idx);
    grp =  proto_item_add_subtree(ti, ett_data);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_mp, cmd_tvb, off, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd0, cmd_tvb, off+2, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_mxps, cmd_tvb, off+3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_nops, cmd_tvb, off+3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd1, cmd_tvb, off+3, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_enlat, cmd_tvb, off+4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_exlat, cmd_tvb, off+8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rrt, cmd_tvb, off+12, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd2, cmd_tvb, off+12, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rrl, cmd_tvb, off+13, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd3, cmd_tvb, off+13, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rwt, cmd_tvb, off+14, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd4, cmd_tvb, off+14, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rwl, cmd_tvb, off+15, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd5, cmd_tvb, off+15, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_idlp, cmd_tvb, off+16, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd6, cmd_tvb, off+18, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_ips, cmd_tvb, off+18, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd7, cmd_tvb, off+19, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_actp, cmd_tvb, off+20, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_apw, cmd_tvb, off+22, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd8, cmd_tvb, off+22, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_aps, cmd_tvb, off+22, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd9, cmd_tvb, off+23, 9, ENC_NA);
}

static void dissect_nvme_identify_ctrl_resp_power_state_descriptors(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, guint32 off)
{
    proto_item *ti;
    proto_tree *grp;
    guint i;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_psds, cmd_tvb, 2048-off, 1024, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    for (i = 0; i < 32; i++)
        dissect_nvme_identify_ctrl_resp_power_state_descriptor(cmd_tvb, grp, i, off);
}


static void add_ctrl_rab(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"PRIu64" command%s)", val, ((guint64)1) << val, val ? "s" : "");
}

static void add_ctrl_mdts(gchar *result, guint32 val)
{
    if (val)
        snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"PRIu64" pages)", val, ((guint64)1) << val);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "0x%x (unlimited)", val);
}

static void add_ctrl_rtd3(gchar *result, guint32 val)
{
    if (!val)
        snprintf(result, ITEM_LABEL_LENGTH, "0 (not reported)");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u (%u microsecond%s)", val, val, (val > 1) ? "%s" : "");
}

static const value_string ctrl_type_tbl[] = {
    { 0,  "Reserved (not reported)" },
    { 1,  "I/O Controller" },
    { 2,  "Discovery Controller" },
    { 3,  "Administrative Controller" },
    { 0, NULL}
};

static void add_ctrl_ms(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u (%u ms)", val, val * 100);
}

static void dissect_nvme_identify_ctrl_resp_ver(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, guint32 off)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ver, cmd_tvb,  80-off, 4, ENC_LITTLE_ENDIAN);
    grp =  proto_item_add_subtree(ti, ett_data);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_mjr, cmd_tvb, 82-off, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_min, cmd_tvb, 81-off, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_ter, cmd_tvb, 80-off, 1, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_identify_ctrl_resp_fguid(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, guint32 off)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_fguid, cmd_tvb, 112-off, 16, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_vse, cmd_tvb, 112-off, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_oui, cmd_tvb, 120-off, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_ei, cmd_tvb, 123-off, 5, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_identify_ctrl_resp_mi(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, guint32 off)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mi, cmd_tvb, 240-off, 16, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_mi_rsvd, cmd_tvb, 240-off, 13, ENC_NA);
    add_group_mask_entry(cmd_tvb, grp, 253-off, 1, ASPEC(hf_nvme_identify_ctrl_mi_nvmsr));
    add_group_mask_entry(cmd_tvb, grp, 254-off, 1, ASPEC(hf_nvme_identify_ctrl_mi_vwci));
    add_group_mask_entry(cmd_tvb, grp, 255-off, 1, ASPEC(hf_nvme_identify_ctrl_mi_mec));
}

static void add_ctrl_commands(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u command%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_events(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u event%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_entries(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u entr%s)", val, val+1, val ? "ies" : "y");
}

static void add_ctrl_states(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u state%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_hmpre(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"PRIu64" bytes)", val, ((guint64)(val)) * 4096);
}

static void post_add_bytes_from_16bytes(proto_item *ti, tvbuff_t *tvb, guint off, guint8 shiftl)
{
    guint64 lo = tvb_get_guint64(tvb, off, 0);
    guint64 hi = tvb_get_guint64(tvb, off, 8);

    if (shiftl) {
        hi = hi << shiftl;
        hi |= (lo >> (64-shiftl));
        lo = lo << shiftl;
    }
    if (hi) {
        if (!(hi >> 10))
            proto_item_append_text(ti, " (%" PRIu64 " KiB)", (hi << 54) | (lo >> 10));
        else if (!(hi >> 20))
            proto_item_append_text(ti, " (%" PRIu64 " MiB)", (hi << 44) | (lo >> 20));
        else if (!(hi >> 30))
            proto_item_append_text(ti, " (%" PRIu64 " GiB)", (hi << 34) | (lo >> 30));
        else if (!(hi >> 40))
            proto_item_append_text(ti, " (%" PRIu64 " TiB)", (hi << 24) | (lo >> 40));
        else if (!(hi >> 50))
            proto_item_append_text(ti, " (%" PRIu64 " PiB)", (hi << 14) | (lo >> 50));
        else if (!(hi >> 60))
            proto_item_append_text(ti, " (%" PRIu64 " EiB)", (hi << 4) | (lo >> 60));
        else
            proto_item_append_text(ti, " (%" PRIu64 " ZiB)", hi >> 6);
    } else {
        proto_item_append_text(ti, " (%" PRIu64 " bytes)", lo);
    }
}

static void add_ctrl_tmt(gchar *result, guint32 val)
{
    if (!val)
        snprintf(result, ITEM_LABEL_LENGTH, "0 (not supported)");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u degrees K", val);
}

static const value_string mmas_type_tbl[] = {
    { 0,  "modification not defined" },
    { 1,  "no modification after sanitize completion" },
    { 2,  "additional modification after sanitize completion" },
    { 0, NULL}
};

static void add_ctrl_pow2_bytes(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%" PRIu64" bytes)", val, ((guint64)1) << val);
}

static void add_ctrl_pow2_page_size(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%" PRIu64" bytes)", val, ((guint64)1) << (12+val));
}

static void add_ctrl_pow2_dstrd_size(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%" PRIu64" bytes)", val, ((guint64)1) << (2+val));
}


static const value_string fcb_type_tbl[] = {
    { 0, "support for the NSID field set to FFFFFFFFh is not indicated" },
    { 1, "reserved value" },
    { 2, "Flush command does not support the NSID field set to FFFFFFFFh" },
    { 3, "Flush command supports the NSID field set to FFFFFFFFh" },
    { 0, NULL}
};


static void add_ctrl_lblocks(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u logical block%s", val + 1, val ? "%s" : "");
}

static const value_string sgls_ify_type_tbl[] = {
    { 0,  "SGLs are not supported." },
    { 1, "SGLs are supported without alignment or granularity limitations" },
    { 2, "SGLs are supported with DWORD alignment and granularity limitation" },
    { 3,  "reserved value" },
    { 0, NULL}
};

#define CHECK_STOP_PARSE(__field_off__, __field_len__) \
do { \
    if ((__field_off__ - off + __field_len__) > len) \
        return; \
} while(0)

static void dissect_nvme_identify_ctrl_resp(tvbuff_t *cmd_tvb,
                                            proto_tree *cmd_tree, guint off, guint len)
{
    proto_item *ti;

    if (!off) {
        CHECK_STOP_PARSE(0, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_vid, cmd_tvb, 0, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 2) {
        CHECK_STOP_PARSE(2, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ssvid, cmd_tvb, 2-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 4) {
        CHECK_STOP_PARSE(4, 20);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_sn, cmd_tvb, 4-off, 20, ENC_ASCII);
    }
    if (off <= 24) {
        CHECK_STOP_PARSE(24, 40);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mn, cmd_tvb, 24-off, 40, ENC_ASCII);
    }
    if (off <= 64) {
        CHECK_STOP_PARSE(64, 8);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_fr, cmd_tvb, 64-off, 8, ENC_NA);
    }
    if (off <= 72) {
        CHECK_STOP_PARSE(72, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rab, cmd_tvb, 72-off, 1, ENC_LITTLE_ENDIAN);
    }
    if (off <= 73) {
        CHECK_STOP_PARSE(73, 3);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ieee, cmd_tvb, 73-off, 3, ENC_LITTLE_ENDIAN);
    }
    if (off <= 76) {
        CHECK_STOP_PARSE(76, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 76-off, 1, ASPEC(hf_nvme_identify_ctrl_cmic));
    }
    if (off <= 77) {
        CHECK_STOP_PARSE(77, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mdts, cmd_tvb, 77-off, 1, ENC_LITTLE_ENDIAN);
    }

    if (off <= 78) {
        CHECK_STOP_PARSE(78, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_cntlid, cmd_tvb, 78-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 80) {
        CHECK_STOP_PARSE(80, 4);
        dissect_nvme_identify_ctrl_resp_ver(cmd_tvb, cmd_tree, off);
    }
    if (off <= 84) {
        CHECK_STOP_PARSE(84, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rtd3r, cmd_tvb, 84-off, 4, ENC_LITTLE_ENDIAN);
    }

    if (off <= 88) {
        CHECK_STOP_PARSE(88, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rtd3e, cmd_tvb, 88-off, 4, ENC_LITTLE_ENDIAN);
    }
    if (off <= 92) {
        CHECK_STOP_PARSE(92, 4);
        add_group_mask_entry(cmd_tvb, cmd_tree, 92-off, 4, ASPEC(hf_nvme_identify_ctrl_oaes));
    }
    if (off <= 96) {
        CHECK_STOP_PARSE(96, 4);
        add_group_mask_entry(cmd_tvb, cmd_tree, 96-off, 4, ASPEC(hf_nvme_identify_ctrl_ctratt));
    }

    if (off <= 100) {
        CHECK_STOP_PARSE(100, 2);
        add_group_mask_entry(cmd_tvb, cmd_tree, 100-off, 2, ASPEC(hf_nvme_identify_ctrl_rrls));
    }
    if (off <= 102) {
        CHECK_STOP_PARSE(102, 9);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd0, cmd_tvb, 102-off, 9, ENC_NA);
    }
    if (off <= 111) {
        CHECK_STOP_PARSE(111, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_cntrltype, cmd_tvb, 111-off, 1, ENC_LITTLE_ENDIAN);
    }
    if (off <= 112) {
        CHECK_STOP_PARSE(112, 16);
        dissect_nvme_identify_ctrl_resp_fguid(cmd_tvb, cmd_tree, off);
    }

    if (off <= 128) {
        CHECK_STOP_PARSE(128, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_crdt1, cmd_tvb, 128-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 130) {
        CHECK_STOP_PARSE(130, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_crdt2, cmd_tvb, 130-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 132)  {
        CHECK_STOP_PARSE(132, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_crdt3, cmd_tvb, 132-off, 2, ENC_LITTLE_ENDIAN);
    }

    if (off <= 132)  {
        CHECK_STOP_PARSE(134, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd1, cmd_tvb, 134-off, 106, ENC_NA);
    }
    if (off <= 240)  {
        CHECK_STOP_PARSE(240, 16);
        dissect_nvme_identify_ctrl_resp_mi(cmd_tvb, cmd_tree, off);
    }
    if (off <= 256)  {
        CHECK_STOP_PARSE(256, 2);
        add_group_mask_entry(cmd_tvb, cmd_tree, 256-off, 2, ASPEC(hf_nvme_identify_ctrl_oacs));
    }

    if (off <= 258)  {
        CHECK_STOP_PARSE(258, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_acl, cmd_tvb,  258-off, 1, ENC_LITTLE_ENDIAN);
    }
    if (off <= 259)  {
        CHECK_STOP_PARSE(259, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_aerl, cmd_tvb, 259-off, 1, ENC_LITTLE_ENDIAN);
    }
    if (off <= 260)  {
        CHECK_STOP_PARSE(260, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 260, 1, ASPEC(hf_nvme_identify_ctrl_frmw));
    }

    if (off <= 261)  {
        CHECK_STOP_PARSE(261, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 261-off, 1, ASPEC(hf_nvme_identify_ctrl_lpa));
    }
    if (off <= 262)  {
        CHECK_STOP_PARSE(262, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_elpe, cmd_tvb, 262-off, 1, ENC_LITTLE_ENDIAN);
    }
    if (off <= 263)  {
        CHECK_STOP_PARSE(263, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_npss, cmd_tvb, 263-off, 1, ENC_LITTLE_ENDIAN);
    }

    if (off <= 264)  {
        CHECK_STOP_PARSE(264, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 264-off, 1, ASPEC(hf_nvme_identify_ctrl_avscc));
    }
    if (off <= 265)  {
        CHECK_STOP_PARSE(265, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 265-off, 1, ASPEC(hf_nvme_identify_ctrl_apsta));
    }
    if (off <= 266)  {
        CHECK_STOP_PARSE(266, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_wctemp, cmd_tvb, 266-off, 2, ENC_LITTLE_ENDIAN);

    }
    if (off <= 268)  {
        CHECK_STOP_PARSE(268, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_cctemp, cmd_tvb, 268-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 270)  {
        CHECK_STOP_PARSE(270, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mtfa, cmd_tvb, 270-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 272)  {
        CHECK_STOP_PARSE(272, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_hmpre, cmd_tvb, 272-off, 4, ENC_LITTLE_ENDIAN);
    }
    if (off <= 276)  {
        CHECK_STOP_PARSE(276, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_hmmin, cmd_tvb, 276-off, 4, ENC_LITTLE_ENDIAN);
    }

    if (off <= 280)  {
        CHECK_STOP_PARSE(280, 16);
        ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_tnvmcap, cmd_tvb, 280-off, 16, ENC_NA);
        post_add_bytes_from_16bytes(ti, cmd_tvb, 280-off, 0);
    }
    if (off <= 296)  {
        CHECK_STOP_PARSE(296, 16);
        ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_unvmcap, cmd_tvb, 296-off, 16, ENC_NA);
        post_add_bytes_from_16bytes(ti, cmd_tvb, 296-off, 0);
    }

    if (off <= 312)  {
        CHECK_STOP_PARSE(312, 4);
        add_group_mask_entry(cmd_tvb, cmd_tree, 312-off, 4, ASPEC(hf_nvme_identify_ctrl_rpmbs));
    }
    if (off <= 316)  {
        CHECK_STOP_PARSE(316, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_edstt, cmd_tvb, 316-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 318)  {
        CHECK_STOP_PARSE(318, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 318-off, 1, ASPEC(hf_nvme_identify_ctrl_dsto));
    }

    if (off <= 319)  {
        CHECK_STOP_PARSE(319, 1);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_fwug, cmd_tvb, 319-off, 1, ENC_LITTLE_ENDIAN);
    }
    if (off <= 320)  {
        CHECK_STOP_PARSE(320, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_kas, cmd_tvb, 320-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 322)  {
        CHECK_STOP_PARSE(322, 2);
        add_group_mask_entry(cmd_tvb, cmd_tree, 322-off, 2, ASPEC(hf_nvme_identify_ctrl_hctma));
    }

    if (off <= 324)  {
        CHECK_STOP_PARSE(324, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mntmt, cmd_tvb, 324-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 326)  {
        CHECK_STOP_PARSE(326, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mxtmt, cmd_tvb, 326-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 328)  {
        CHECK_STOP_PARSE(328, 2);
        add_group_mask_entry(cmd_tvb, cmd_tree, 328-off, 2, ASPEC(hf_nvme_identify_ctrl_sanicap));
    }

    if (off <= 332)  {
        CHECK_STOP_PARSE(332, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_hmmminds, cmd_tvb, 332-off, 4, ENC_LITTLE_ENDIAN);
    }
    if (off <= 336)  {
        CHECK_STOP_PARSE(336, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_hmmaxd, cmd_tvb, 336-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 338)  {
        CHECK_STOP_PARSE(338, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nsetidmax, cmd_tvb, 338-off, 2, ENC_LITTLE_ENDIAN);
    }

    if (off <= 340)  {
        CHECK_STOP_PARSE(340, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_endgidmax, cmd_tvb, 340-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 342)  {
        CHECK_STOP_PARSE(342, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_anatt, cmd_tvb, 342-off, 1, ENC_LITTLE_ENDIAN);
    }
    if (off <= 343)  {
        CHECK_STOP_PARSE(343, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 343-off, 1, ASPEC(hf_nvme_identify_ctrl_anacap));
    }

    if (off <= 344)  {
        CHECK_STOP_PARSE(344, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_anagrpmax, cmd_tvb, 344-off, 4, ENC_LITTLE_ENDIAN);
    }
    if (off <= 348)  {
        CHECK_STOP_PARSE(348, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nanagrpid, cmd_tvb, 348-off, 4, ENC_LITTLE_ENDIAN);
    }
    if (off <= 352)  {
        CHECK_STOP_PARSE(352, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_pels, cmd_tvb, 352-off, 4, ENC_LITTLE_ENDIAN);
    }

    if (off <= 356)  {
        CHECK_STOP_PARSE(356, 156);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd2, cmd_tvb, 356-off, 156, ENC_NA);
    }
    if (off <= 512)  {
        CHECK_STOP_PARSE(512, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 512-off, 1, ASPEC(hf_nvme_identify_ctrl_sqes));
    }
    if (off <= 513)  {
        CHECK_STOP_PARSE(513, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 513-off, 1, ASPEC(hf_nvme_identify_ctrl_cqes));
    }

    if (off <= 514)  {
        CHECK_STOP_PARSE(514, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_maxcmd, cmd_tvb, 514-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 516)  {
        CHECK_STOP_PARSE(516, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nn, cmd_tvb, 516-off, 4, ENC_LITTLE_ENDIAN);
    }
    if (off <= 520)  {
        CHECK_STOP_PARSE(520, 2);
        add_group_mask_entry(cmd_tvb, cmd_tree, 520-off, 2, ASPEC(hf_nvme_identify_ctrl_oncs));
    }

    if (off <= 522)  {
        CHECK_STOP_PARSE(522, 2);
        add_group_mask_entry(cmd_tvb, cmd_tree, 522-off, 2, ASPEC(hf_nvme_identify_ctrl_fuses));
    }
    if (off <= 524)  {
        CHECK_STOP_PARSE(524, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 524-off, 1, ASPEC(hf_nvme_identify_ctrl_fna));
    }
    if (off <= 525)  {
        CHECK_STOP_PARSE(525, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 525-off, 1, ASPEC(hf_nvme_identify_ctrl_vwc));
    }

    if (off <= 526)  {
        CHECK_STOP_PARSE(526, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_awun, cmd_tvb, 526-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 528)  {
        CHECK_STOP_PARSE(528, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_awupf, cmd_tvb, 528-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 530)  {
        CHECK_STOP_PARSE(530, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 530-off, 1, ASPEC(hf_nvme_identify_ctrl_nvscc));
    }

    if (off <= 531)  {
        CHECK_STOP_PARSE(531, 1);
        add_group_mask_entry(cmd_tvb, cmd_tree, 531-off, 1, ASPEC(hf_nvme_identify_ctrl_nwpc));
    }
    if (off <= 532)  {
        CHECK_STOP_PARSE(532, 3);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_acwu, cmd_tvb, 532-off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 534)  {
        CHECK_STOP_PARSE(534, 2);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd3, cmd_tvb, 534-off, 2, ENC_NA);
    }

    if (off <= 536)  {
        CHECK_STOP_PARSE(536, 4);
        add_group_mask_entry(cmd_tvb, cmd_tree, 536-off, 4, ASPEC(hf_nvme_identify_ctrl_sgls));
    }
    if (off <= 540)  {
        CHECK_STOP_PARSE(540, 4);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mnan, cmd_tvb, 540-off, 4, ENC_LITTLE_ENDIAN);
    }
    if (off <= 544)  {
        CHECK_STOP_PARSE(544, 224);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd4, cmd_tvb, 544-off, 224, ENC_NA);
    }

    if (off <= 768)  {
        CHECK_STOP_PARSE(768, 256);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_subnqn, cmd_tvb, 768-off, 256, ENC_ASCII);
    }
    if (off <= 1024)  {
        CHECK_STOP_PARSE(1024, 768);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd5, cmd_tvb, 1024-off, 768, ENC_NA);
    }
    if (off <= 1792)  {
        CHECK_STOP_PARSE(1792, 256);
        dissect_nvme_identify_ctrl_resp_nvmeof(cmd_tvb, cmd_tree, off);
    }

    if (off <= 2048)  {
        CHECK_STOP_PARSE(2048, 1024);
        dissect_nvme_identify_ctrl_resp_power_state_descriptors(cmd_tvb, cmd_tree, off);
    }

    if (off <= 3072)  {
        CHECK_STOP_PARSE(3072, 1024);
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_vs, cmd_tvb, 3072-off, 1024, ENC_NA);
    }
}

static void dissect_nvme_identify_resp(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                       struct nvme_cmd_ctx *cmd_ctx, guint off, guint len)
{
    switch(cmd_ctx->cmd_ctx.cmd_identify.cns) {
    case NVME_IDENTIFY_CNS_IDENTIFY_NS:
        dissect_nvme_identify_ns_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_IDENTIFY_CTRL:
        dissect_nvme_identify_ctrl_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_IDENTIFY_NSLIST:
        dissect_nvme_identify_nslist_resp(cmd_tvb, cmd_tree, off, len);
        break;
    default:
        break;
    }
}

static void dissect_nvme_identify_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_identify_dword10));
    add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_identify_dword11));

    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);

    add_group_mask_entry(cmd_tvb, cmd_tree, 56, 4, ASPEC(hf_nvme_identify_dword14));

    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

static const value_string logpage_tbl[] = {
    { 0, "Unspecified" },
    { 1, "Error Information" },
    { 2, "SMART/Health Information" },
    { 3, "Firmware Slot Information" },
    { 4, "Changed Namespace List" },
    { 5, "Commands Supported and Effects" },
    { 6, "Device Self-test" },
    { 7, "Telemetry Host-Initiated" },
    { 8, "Telemetry Controller-Initiated" },
    { 9, "Endurance Group Information" },
    { 10, "Predictable Latency Per NVM Set" },
    { 11, "Predictable Latency Event Aggregate" },
    { 12, "Asymmetric Namespace Access" },
    { 13, "Persistent Event Log" },
    { 14, "LBA Status Information" },
    { 15, "Endurance Group Event Aggregate" },
    { 0x70, "NVMeOF Discovery" },
    { 0x80, "Reservation Notification" },
    { 0x81, "Sanitize Status" },
    { 0, NULL }
};

static const char *get_logpage_name(guint lid)
{
    if (lid > 0x70 && lid < 0x80)
        return "NVMeoF Reserved Page name";
    else if (lid > 0x81 && lid < 0xc0)
        return "IO Command Set Specific Page";
    else if (lid >= 0xc0)
        return "Vendor Specific Page";
    else
        return val_to_str_const(lid, logpage_tbl, "Reserved Page Name");
}

static void add_logpage_lid(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%s (0x%x)", get_logpage_name(val), val);
}

static const value_string sec_type_tbl[] = {
    { 0, "No security" },
    { 1, "Transport Layer Security (TLS) version >= 1.2" },
    { 0, NULL }
};

static void dissect_nvme_get_logpage_ify_rcrd_tsas_tcp(tvbuff_t *cmd_tvb, proto_item *ti, guint off)
{
    proto_tree *grp =  proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas_tcp_sectype, cmd_tvb, off, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas_tcp_rsvd, cmd_tvb, off+1, 255, ENC_NA);
}

static const value_string qp_type_tbl[] = {
    { 1, "Reliable Connected" },
    { 2, "Reliable Datagram" },
    { 0, NULL }
};

static const value_string pr_type_tbl[] = {
    { 1, "No provider specified" },
    { 2, "InfiniBand" },
    { 3, "RoCE (v1)" },
    { 4, "RoCE (v2)" },
    { 5, "iWARP" },
    { 0, NULL }
};

static const value_string cms_type_tbl[] = {
    { 1, "RDMA_IP_CM" },
    { 0, NULL }
};

static void dissect_nvme_get_logpage_ify_rcrd_tsas_rdma(tvbuff_t *cmd_tvb, proto_item *ti, guint off)
{
    proto_tree *grp;

    grp =  proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas_rdma_qptype, cmd_tvb, off, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas_rdma_prtype, cmd_tvb, off+1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas_rdma_cms, cmd_tvb, off+2, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas_rdma_rsvd0, cmd_tvb, off+3, 5, ENC_NA);
    proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas_rdma_pkey, cmd_tvb, off+8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas_rdma_rsvd1, cmd_tvb, off+10, 246, ENC_NA);
}

static const value_string trt_type_tbl[] = {
    { 0, "Reserved" },
    { 1, "RDMA Transport" },
    { 2, "Fibre Channel Transport" },
    { 3, "TCP Transport" },
    { 254, "Itra-host Transport" },
    { 0, NULL }
};

static const value_string adrfam_type_tbl[] = {
    { 0, "Reserved" },
    { 1, "AF_INET" },
    { 2, "AF_INET6" },
    { 3, "AF_IB" },
    { 4, "Fibre Channel" },
    { 254, "Intra-Host" },
    { 0, NULL }
};

static const value_string sub_type_tbl[] = {
    { 0, "Reserved" },
    { 1, "Referreal to another Discovery Service" },
    { 2, "NVM System with IO controllers" },
    { 0, NULL }
};

static void dissect_nvme_get_logpage_ify_rcrd_resp(tvbuff_t *cmd_tvb, proto_tree *tree, guint64 rcrd, guint roff, gint off, guint len)
{
    proto_item *ti;
    proto_tree *grp;
    guint tr_type;

    ti = proto_tree_add_bytes_format(tree, hf_nvme_get_logpage_ify_rcrd, cmd_tvb, off,
        (len < 1024) ? len : 1024, NULL, "Discovery Log Entry %"PRIu64" (DLE%"PRIu64")", rcrd, rcrd);
    grp =  proto_item_add_subtree(ti, ett_data);

    if (!roff)
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ify_rcrd_trtype, cmd_tvb, off, 1, ENC_LITTLE_ENDIAN, &tr_type);

    if (roff <= 1 && (2-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_adrfam, cmd_tvb, off-roff+1, 1, ENC_LITTLE_ENDIAN);

    if (roff <= 2 && (3-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_subtype, cmd_tvb, off-roff+2, 1, ENC_LITTLE_ENDIAN);

    if (roff <= 3 && (4-roff) <= len)
        add_group_mask_entry(cmd_tvb, grp, off-roff+3, 1, ASPEC(hf_nvme_get_logpage_ify_rcrd_treq));

    if (roff <= 4 && (6-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_portid, cmd_tvb, off-roff+4, 2, ENC_LITTLE_ENDIAN);

    if (roff <= 6 && (8-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_cntlid, cmd_tvb, off-roff+6, 2, ENC_LITTLE_ENDIAN);

    if (roff <= 8 && (10-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_asqsz, cmd_tvb, off-roff+8, 2, ENC_LITTLE_ENDIAN);

    if (roff <= 10 && (32-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_rsvd0, cmd_tvb, off-roff+10, 22, ENC_NA);

    if (roff <= 32 && (62-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_trsvcid, cmd_tvb, off-roff+32, 32, ENC_ASCII);

    if (roff <= 64 && (256-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_rsvd1, cmd_tvb, off-roff+64, 192, ENC_NA);

    if (roff <= 256 && (512-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_subnqn, cmd_tvb, off-roff+256, 256, ENC_ASCII);

    if (roff <= 512 && (768-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_traddr, cmd_tvb, off-roff+512, 256, ENC_ASCII);

    if (roff <= 768 && (1024-roff) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas, cmd_tvb, off-roff+768, 256, ENC_NA);
        if (tr_type == 1)
            dissect_nvme_get_logpage_ify_rcrd_tsas_rdma(cmd_tvb, ti, off-roff+768);
        else if (tr_type == 3)
            dissect_nvme_get_logpage_ify_rcrd_tsas_tcp(cmd_tvb, ti, off-roff+768);
    }
}

static void dissect_nvme_get_logpage_ify_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint tr_off, guint len)
{
    guint64 off = cmd_ctx->cmd_ctx.get_logpage.off + tr_off;
    proto_tree *grp;
    guint poff;
    guint roff;
    guint max_bytes;
    guint64 rcrd;
    guint64 recnum = 0;

    grp =  proto_item_add_subtree(ti, ett_data);

    if (!off && len >= 8)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_genctr, cmd_tvb, 0, 8, ENC_LITTLE_ENDIAN);

    /* guint casts are to silence clang-11 compile errors */
    if (off <= 8 && (16 - (guint)off) <= len)
        proto_tree_add_item_ret_uint64(grp, hf_nvme_get_logpage_ify_numrec, cmd_tvb, (guint)(8-off), 8, ENC_LITTLE_ENDIAN, &recnum);

    if (off <= 16 && (18 - (guint)off) <= len) {
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_recfmt, cmd_tvb, (guint)(16-off), 2, ENC_LITTLE_ENDIAN);
        cmd_ctx->cmd_ctx.get_logpage.records = (recnum & 0xffffffff);
    } else if (tr_off) {
        recnum = cmd_ctx->cmd_ctx.get_logpage.records;
    }

    if (off <= 18 && (1024 - (guint)off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rsvd, cmd_tvb, (guint)(18-off), 1006, ENC_NA);

    if (off <= 1024) {
        poff = (1024 - (guint)off); /* clang-11 is so strange, hence the cast */
        if (poff >= len)
            return;
        max_bytes = 1024;
        rcrd = 0;
        roff = 0;
        len -= poff;
    } else {
        poff = 0;
        roff = (off & 1023);
        max_bytes = 1024 - (roff);
        rcrd = (off - roff) / 1024 - 1;
    }

    max_bytes = (max_bytes <= len) ? max_bytes : len;
    dissect_nvme_get_logpage_ify_rcrd_resp(cmd_tvb, grp, rcrd, roff, poff, len);
    poff += max_bytes;
    len -= max_bytes;
    rcrd++;

    if (!recnum)
        recnum = (len  + 1023) / 1024;

    while (len && rcrd < recnum) {
        max_bytes = (len >= 1024) ? 1024 : len;
        dissect_nvme_get_logpage_ify_rcrd_resp(cmd_tvb, grp, rcrd, 0, poff, len);
        poff += max_bytes;
        len -= max_bytes;
        rcrd++;
    }
}

static void dissect_nvme_get_logpage_err_inf_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;

    grp =  proto_item_add_subtree(ti, ett_data);

    if (cmd_ctx->cmd_ctx.get_logpage.off > 42)
        return; /* max allowed offset is 42, so we do not loose bits by casting to guint type */

    if (!off && len >= 8)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_errcnt, cmd_tvb, 0, 8, ENC_LITTLE_ENDIAN);
    if (off <= 8 && (10-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_sqid, cmd_tvb, 8-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 10 && (12-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_cid, cmd_tvb, 10-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 12 && (14-off) <= len)
        add_group_mask_entry(cmd_tvb, grp, 12-off, 2, ASPEC(hf_nvme_get_logpage_errinf_sf));
    if (off <= 14 && (16-off) <= len)
        add_group_mask_entry(cmd_tvb, grp, 14-off, 2, ASPEC(hf_nvme_get_logpage_errinf_pel));
    if (off <= 16 && (24-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_lba, cmd_tvb, 16-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 24 && (28-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_ns, cmd_tvb, 24-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 28 && (29-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_vsi, cmd_tvb, 28-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 29 && (30-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_trtype, cmd_tvb, 29-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 30 && (32-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_rsvd0, cmd_tvb, 30-off, 2, ENC_NA);
    if (off <= 32 && (40-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_csi, cmd_tvb, 32-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 40 && (42-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_tsi, cmd_tvb, 40-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 42 && (64-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_rsvd1, cmd_tvb, 42-off, 24, ENC_NA);
}

static void post_add_intval_from_16bytes(proto_item *ti, tvbuff_t *tvb, guint off)
{
    guint64 lo = tvb_get_guint64(tvb, off, 0);
    guint64 hi = tvb_get_guint64(tvb, off, 8);
    double res;

    res = (double)hi;
    res *= (((guint64)1) << 63);
    res *= 2;
    res += lo;
    if (res > 99999999)
        proto_item_append_text(ti, " (%.8le)", res);
    else
        proto_item_append_text(ti, " (%.0lf)", res);
}

static void decode_smart_resp_temps(proto_tree *grp, tvbuff_t *cmd_tvb, guint off, guint len)
{
    proto_item *ti;
    guint bytes;
    guint poff;
    guint max_bytes;
    guint i;


    poff = (off < 200) ? 200-off : off;

    if (off > 214 || (poff + 2) > len)
        return;

    bytes = len - poff;
    max_bytes = (off <= 200) ? 16 : (216 - off);

    if (bytes > max_bytes)
        bytes = max_bytes;

    ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ts[0],  cmd_tvb, poff, bytes, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    for (i = 0; i < 8; i++) {
        guint pos = 200 + i * 2;
        if (off <= pos && (off + pos + 2) <= len)
            proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ts[i+1],  cmd_tvb, pos - off, 2, ENC_LITTLE_ENDIAN);
    }
}

static void dissect_nvme_get_logpage_smart_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;

    if (cmd_ctx->cmd_ctx.get_logpage.off >= 512)
        return; /* max allowed offset is < 512, so we do not loose bits by casting to guint type */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (!off && len >= 1)
        add_group_mask_entry(cmd_tvb, grp, 0, 1, ASPEC(hf_nvme_get_logpage_smart_cw));
    if (off <= 1 && (3 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ct,  cmd_tvb, 1-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 3 && (4 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_asc,  cmd_tvb, 3-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 4 && (5 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ast,  cmd_tvb, 4-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 5 && (6 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_lpu,  cmd_tvb, 5-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 6 && (7 -off) <= len)
        add_group_mask_entry(cmd_tvb, grp, 6-off, 1, ASPEC(hf_nvme_get_logpage_smart_egcws));
    if (off <= 7 && (32 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_rsvd0,  cmd_tvb, 7-off, 25, ENC_NA);
    if (off <= 32 && (48 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_dur,  cmd_tvb, 32-off, 16, ENC_NA);
        post_add_bytes_from_16bytes(ti, cmd_tvb, 32-off, 16);
    }
    if (off <= 48 && (64 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_duw,  cmd_tvb, 48-off, 16, ENC_NA);
        post_add_bytes_from_16bytes(ti, cmd_tvb, 48-off, 16);
    }
    if (off <= 64 && (80 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_hrc,  cmd_tvb, 64-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 64-off);
    }
    if (off <= 80 && (96 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_hwc,  cmd_tvb, 80-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 80-off);
    }
    if (off <= 96 && (112 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_cbt,  cmd_tvb, 96-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 96-off);
    }
    if (off <= 112 && (128 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_pc,  cmd_tvb, 112-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 112-off);
    }
    if (off <= 128 && (144 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_poh,  cmd_tvb, 128-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 128-off);
    }
    if (off <= 144 && (160 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_us,  cmd_tvb, 144-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 144-off);
    }
    if (off <= 160 && (176 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_mie,  cmd_tvb, 160-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 160-off);
    }
    if (off <= 176 && (192 -off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ele,  cmd_tvb, 176-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 176-off);
    }
    if (off <= 192 && (196 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_wctt,  cmd_tvb, 192-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 196 && (200 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_cctt,  cmd_tvb, 196-off, 4, ENC_LITTLE_ENDIAN);

    decode_smart_resp_temps(grp, cmd_tvb, off, len);

    if (off <= 216 && (220 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_tmt1c,  cmd_tvb, 216-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 220 && (224 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_tmt2c,  cmd_tvb, 220-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 224 && (228 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_tmt1t,  cmd_tvb, 224-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 228 && (232 -off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_tmt2t,  cmd_tvb, 228-off, 4, ENC_LITTLE_ENDIAN);
    if (off < 512) {
        guint poff = (off < 232) ? 232 : off;
        guint max_len = (off <= 232) ? 280 : 512 - off;
        len -= poff;
        if (len > max_len)
            len = max_len;
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_rsvd1,  cmd_tvb, poff, len, ENC_NA);
    }
}

static void decode_fw_slot_frs(proto_tree *grp, tvbuff_t *cmd_tvb, guint32 off, guint len)
{
    proto_item *ti;
    guint bytes;
    guint poff;
    guint max_bytes;
    guint i;


    poff = (off < 8) ? 8-off : off;

    if (off > 56 || (poff + 8) > len)
        return;

    bytes = len - poff;
    max_bytes = (off <= 8) ? 56 : (64 - off);

    if (bytes > max_bytes)
        bytes = max_bytes;

    ti = proto_tree_add_item(grp, hf_nvme_get_logpage_fw_slot_frs[0],  cmd_tvb, poff, bytes, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    for (i = 0; i < 7; i++) {
        guint pos = 8 + i * 8;
        if (off <= pos && (pos + 8 - off) <= len)
            proto_tree_add_item(grp, hf_nvme_get_logpage_fw_slot_frs[i+1],  cmd_tvb, pos - off, 8, ENC_LITTLE_ENDIAN);
    }
}

static void dissect_nvme_get_logpage_fw_slot_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;

    if (cmd_ctx->cmd_ctx.get_logpage.off >= 512)
        return;  /* max allowed offset is < 512, so we do not loose bits by casting to guint type */

    grp =  proto_item_add_subtree(ti, ett_data);

    if (!off && len > 1)
        add_group_mask_entry(cmd_tvb, grp, 0, 1, ASPEC(hf_nvme_get_logpage_fw_slot_afi));
    if (off <= 1 && (8-off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_fw_slot_rsvd0,  cmd_tvb, 1-off, 7, ENC_NA);

    decode_fw_slot_frs(grp, cmd_tvb, off, len);

    if (off < 512) {
        guint poff = (off < 64) ? 64 : off;
        guint max_len = (off <= 64) ? 448 : 512 - off;
        len -= poff;
        if (len > max_len)
            len = max_len;
        proto_tree_add_item(grp, hf_nvme_get_logpage_fw_slot_rsvd1,  cmd_tvb, poff, len, ENC_NA);
    }
}

static void dissect_nvme_get_logpage_changed_nslist_resp(proto_item *ti, tvbuff_t *cmd_tvb, guint len)
{
    proto_tree *grp;
    guint off = 0;

    grp =  proto_item_add_subtree(ti, ett_data);
    while (len >= 4) {
        proto_tree_add_item(grp, hf_nvme_get_logpage_changed_nslist,  cmd_tvb, off, 4, ENC_LITTLE_ENDIAN);
        len -= 4;
        off += 4;
    }
}

static const value_string cmd_eff_cse_tbl[] = {
    { 0, "No command submission or execution restriction" },
    { 1, "One concurrent command per namespace" },
    { 2, "One concurrent command per system" },
    { 0, NULL}
};

static void dissect_nvme_get_logpage_cmd_sup_and_eff_grp(proto_tree *grp, tvbuff_t *cmd_tvb, guint poff, guint nrec, guint fidx, gboolean acs)
{
    guint i;
    proto_item *ti;
    for (i = 0; i < nrec; i++) {
        if (acs)
            ti = proto_tree_add_bytes_format(grp, hf_nvme_get_logpage_cmd_and_eff_cs, cmd_tvb, poff, 4, NULL, "Admin Command Supported %u (ACS%u)", fidx+i, fidx+1);
        else
            ti = proto_tree_add_bytes_format(grp, hf_nvme_get_logpage_cmd_and_eff_cs, cmd_tvb, poff, 4, NULL, "I/0 Command Supported %u (IOCS%u)", fidx+i, fidx+1);
        grp =  proto_item_add_subtree(ti, ett_data);
        add_group_mask_entry(cmd_tvb, grp, poff, 4, ASPEC(hf_nvme_get_logpage_cmd_and_eff_cseds));
        poff += 4;
    }
}


static void dissect_nvme_get_logpage_cmd_sup_and_eff_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint tr_off, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;
    guint nrec = 0;
    guint fidx;

    off += tr_off;
    if (cmd_ctx->cmd_ctx.get_logpage.off >= 4096)
        return; /* max allowed offset is < 4096, so we do not loose bits by casting to guint type */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (off <= 1024 && len >= 4) {
        fidx = off / 4;
        nrec = (1024-off) / 4;
        if (nrec > (len / 4))
            nrec = len / 4;
        dissect_nvme_get_logpage_cmd_sup_and_eff_grp(grp, cmd_tvb, 0, nrec, fidx, TRUE);
    }

    nrec = len / 4 - nrec;
    if (!nrec)
        return;
    if (nrec > 256)
        nrec = 256;

    fidx = (off > 1028) ? (off - 1028) / 4 : 0;
    off = (off < 1028) ? (1028 - off) : 0;

    dissect_nvme_get_logpage_cmd_sup_and_eff_grp(grp, cmd_tvb, off, nrec, fidx, FALSE);
}

static const value_string stest_type_active_tbl[] = {
    { 0,  "No device self-test operation in progress" },
    { 1,  "Short device self-test operation in progress" },
    { 2,  "Extended device self-test operation in progress" },
    { 0xE,  "Vendor Specific" },
    { 0, NULL}
};

static const value_string stest_result_tbl[] = {
    { 0, "Operation completed without error" },
    { 1, "Operation was aborted by a Device Self-test command" },
    { 2, "Operation was aborted by a Controller Level Reset" },
    { 3, "Operation was aborted due to a removal of a namespace from the namespace inventory" },
    { 4, "Operation was aborted due to the processing of a Format NVM command" },
    { 5, "A fatal error or unknown test error occurred while the controller was executing the device self-test operation and the operation did not complete" },
    { 6, "Operation completed with a segment that failed and the segment that failed is not known" },
    { 7, "Operation completed with one or more failed segments and the first segment that failed is indicated in the Segment Number field" },
    { 8, "Operation was aborted for unknown reason" },
    { 9, "Operation was aborted due to a sanitize operation" },
    { 0xF, "Entry not used (does not contain a test result)" },
    {  0, NULL}
};

static const value_string stest_type_done_tbl[] = {
    { 1,  "Short device self-test operation in progress" },
    { 2,  "Extended device self-test operation in progress" },
    { 0xE,  "Vendor Specific" },
    { 0, NULL}
};

static void dissect_nvme_get_logpage_selftest_result(proto_tree *grp, tvbuff_t *cmd_tvb, guint32 off, guint tst_idx)
{
    proto_item *ti;

    ti = proto_tree_add_bytes_format(grp, hf_nvme_get_logpage_selftest_res, cmd_tvb, off, 24, NULL,
                                "Latest Self-test Result Data Structure (latest %u)", tst_idx);
    grp =  proto_item_add_subtree(ti, ett_data);
    add_group_mask_entry(cmd_tvb, grp, off, 1, ASPEC(hf_nvme_get_logpage_selftest_res_status));
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_sn, cmd_tvb, off+1, 1, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, grp, off+2, 1, ASPEC(hf_nvme_get_logpage_selftest_res_vdi));
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_rsvd, cmd_tvb, off+3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_poh, cmd_tvb, off+4, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_nsid, cmd_tvb, off+12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_flba, cmd_tvb, off+16, 8, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, grp, off+24, 1, ASPEC(hf_nvme_get_logpage_selftest_res_sct));
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_sc, cmd_tvb, off+25, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_vs, cmd_tvb, off+26, 2, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_get_logpage_selftest_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint tr_off, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;
    guint tst_idx;

    off += tr_off;
    if (cmd_ctx->cmd_ctx.get_logpage.off > 536)
        return; /* max offset is <= 536, so we do not loose bits by casting to guint type */

    grp =  proto_item_add_subtree(ti, ett_data);

    if (!off && len >= 1)
        add_group_mask_entry(cmd_tvb, grp, 0, 1, ASPEC(hf_nvme_get_logpage_selftest_csto));
    if (off <= 1 && (2 - off) <= len)
        add_group_mask_entry(cmd_tvb, grp, 1-off, 1, ASPEC(hf_nvme_get_logpage_selftest_cstc));
    if (off <= 2 && (4 - off) <= len)
         proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_rsvd, cmd_tvb, 2-off, 2, ENC_LITTLE_ENDIAN);

    if (off <= 4) {
        len -= (4-off);
        tst_idx = 0;
        off = 4;
    } else {
        tst_idx = (off - 4 + 27) / 28;
        len -= (tst_idx * 28 - (off - 4));
        off = 4 + (tst_idx * 8);
    }
    while (len >= 28) {
        dissect_nvme_get_logpage_selftest_result(grp, cmd_tvb, off, tst_idx);
        off += 28;
        len -= 28;
    }
}

static void dissect_nvme_get_logpage_telemetry_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint tr_off, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off  & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;
    guint64 next_block;
    guint32 poff;
    const char *pfx = (cmd_ctx->cmd_ctx.get_logpage.lid == 0x7) ? "Host-Initiated" : "Controller-Initiated";

    off += tr_off;
    poff = 512 - (off & 0x1ff);
    next_block = (off + poff) / 512;

    grp =  proto_item_add_subtree(ti, ett_data);


    if (poff >= len && cmd_ctx->cmd_ctx.get_logpage.off >= 384)
        return;

    if (!off && len >= 1)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_li, cmd_tvb, 0, 1, ENC_LITTLE_ENDIAN);
    if (off <= 1 && (5 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_rsvd0, cmd_tvb, 1-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 5 && (8 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_ieee, cmd_tvb, 5-off, 3, ENC_LITTLE_ENDIAN);
    if (off <= 8 && (10 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da1lb, cmd_tvb, 8-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 10 && (12 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da2lb, cmd_tvb, 10-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 12 && (14 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da3lb, cmd_tvb, 12-off, 3, ENC_LITTLE_ENDIAN);
    if (off <= 14 && (372 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_rsvd1, cmd_tvb, 14-off, 368, ENC_NA);
    if (off <= 382 && (383 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da, cmd_tvb, 382-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 383 && (384 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_dgn, cmd_tvb, 383-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 384 && (512 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_ri, cmd_tvb, 384-off, 128, ENC_NA);

    len -= poff;
    while (len >= 512) {
         proto_tree_add_bytes_format_value(grp, hf_nvme_get_logpage_telemetry_db, cmd_tvb, poff, 512, NULL,
                                           "Telemetry %s data block %"PRIu64, pfx, next_block);
        len -= 512;
        next_block++;
        poff += 512;
    }
}

static void dissect_nvme_get_logpage_egroup_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;

    if (cmd_ctx->cmd_ctx.get_logpage.off >= 512)
        return; /* max allowed offset is < 512, so we do not loose bits by casting to guint type */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (!off && len >= 1)
        add_group_mask_entry(cmd_tvb, grp, 0, 1, ASPEC(hf_nvme_get_logpage_egroup_cw));
    if (off <= 1 && (3 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_rsvd0,  cmd_tvb, 1-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 3 && (4 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_as,  cmd_tvb, 3-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 4 && (5 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_ast,  cmd_tvb, 4-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 5 && (6 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_pu,  cmd_tvb, 5-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 6 && (32 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_rsvd1,  cmd_tvb, 6-off, 26, ENC_NA);
    if (off <= 32 && (48 - off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_ee,  cmd_tvb, 32-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 32-off);
    }
    if (off <= 48 && (64 - off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_dur,  cmd_tvb, 48-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 48-off);
    }
    if (off <= 64 && (80 - off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_duw,  cmd_tvb, 64-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 64-off);
    }
    if (off <= 80 && (96 - off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_muw,  cmd_tvb, 80-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 80-off);
    }
    if (off <= 96 && (112 - off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_hrc,  cmd_tvb, 96-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 96-off);
    }
    if (off <= 112 && (128 - off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_hwc,  cmd_tvb, 112-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 112-off);
    }
    if (off <= 128 && (144 - off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_mdie,  cmd_tvb, 128-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 128-off);
    }
    if (off <= 144 && (160 - off) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_ele,  cmd_tvb, 144-off, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, 144-off);
    }
    if (off <= 508 && (512 - off) <= len) {
        guint poff = (off <= 160) ? (160 - off) : (off - 160);
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_rsvd2,  cmd_tvb, poff, len - poff, ENC_NA);
    }
}
static const value_string plat_status_tbl[] = {
    { 0,  "Predictable Latency Mode not Enabled" },
    { 1,  "Deterministic Window (DTWIN)" },
    { 2,  "Non-Deterministic Window (NDWIN)" },
    { 0, NULL}
};

static void dissect_nvme_get_logpage_pred_lat_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;
    guint poff;

    if (cmd_ctx->cmd_ctx.get_logpage.off > 508)
        return; /* max allowed offset is < 508, so we do not loose bits by casting to guint type */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (!off && len >= 1)
        add_group_mask_entry(cmd_tvb, grp, 0, 1, ASPEC(hf_nvme_get_logpage_pred_lat_status));
    if (off <= 1 && (2 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_rsvd0,  cmd_tvb, 1-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 2 && (4 - off) <= len)
        add_group_mask_entry(cmd_tvb, grp, 2-off, 2, ASPEC(hf_nvme_get_logpage_pred_lat_etype));
    if (off <= 4 && (32 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_rsvd1,  cmd_tvb, 4-off, 28, ENC_NA);
    if (off <= 32 && (40 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_rt,  cmd_tvb, 32-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 40 && (48 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_wt,  cmd_tvb, 40-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 48 && (56 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_tm,  cmd_tvb, 48-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 56 && (64 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_ndwin_tmh,  cmd_tvb, 56-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 64 && (72 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_ndwin_tml,  cmd_tvb, 64-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 72 && (128 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_rsvd2,  cmd_tvb, 72-off, 56, ENC_NA);
    if (off <= 128 && (136 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_re,  cmd_tvb, 128-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 136 && (144 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_we,  cmd_tvb, 136-off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 144 && (152 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_te,  cmd_tvb, 144-off, 152, ENC_LITTLE_ENDIAN);
    poff = (off <= 152) ? (152 - off) : 0;
    if (poff > len)
        return;
    proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_rsvd3,  cmd_tvb, poff, len - poff, ENC_NA);
}

static void dissect_nvme_get_logpage_pred_lat_aggreg_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint tr_off, guint len)
{
    guint64 off = cmd_ctx->cmd_ctx.get_logpage.off;
    proto_tree *grp;
    guint poff;

    off += tr_off;
    if (off < 8) {
        poff = (cmd_ctx->cmd_ctx.get_logpage.off & 0x7);
        poff = 8 - poff;
    } else {
        poff = 0;
    }
    if (len < (poff + 2) && off)
        return; /* nothing to display */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (!off && len >= 8)
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_aggreg_ne,  cmd_tvb, 0, 8, ENC_LITTLE_ENDIAN);
    len -= poff;
    while (len >= 2) {
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_aggreg_nset,  cmd_tvb, poff, 2, ENC_LITTLE_ENDIAN);
        poff += 2;
        len -= 2;
    }
}

static const value_string ana_state_tbl[] = {
    { 0x1,  "ANA Optimized State" },
    { 0x2,  "ANA Non-Optimized State" },
    { 0x3,  "ANA Inaccessible State" },
    { 0x4,  "ANA Persistent Loss State" },
    { 0xF,  "ANA Change Sate" },
    { 0, NULL}
};

static guint dissect_nvme_get_logpage_ana_resp_grp(proto_tree *grp, tvbuff_t *cmd_tvb,  struct nvme_cmd_ctx *cmd_ctx, guint len, guint32 poff)
{
    guint done = 0;
    guint bytes;
    proto_item *ti;
    guint group_id;
    guint nns;
    guint prev_off = cmd_ctx->cmd_ctx.get_logpage.tr_off;

    if (len < 4) {
        if (prev_off)
            cmd_ctx->cmd_ctx.get_logpage.tr_off += len;
        return 0;
    }

    if (prev_off <= 4) {
        nns = tvb_get_guint32(cmd_tvb, poff+4-prev_off, ENC_LITTLE_ENDIAN);
        bytes = 32 + 4 * nns;
        cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = nns;
    } else if (prev_off ) {
        nns = cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries;
        bytes = (prev_off > 32) ? 4 * nns : ((32-prev_off) + 4 * nns);
    } else {
        bytes = len;
    }

    if (bytes > len)
            bytes = len;

    ti = proto_tree_add_bytes_format_value(grp, hf_nvme_get_logpage_ana_grp, cmd_tvb, poff, bytes, NULL,
            "ANA Group Descriptor");
    grp =  proto_item_add_subtree(ti, ett_data);

    if (prev_off) {
        group_id = cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id;
        proto_item_append_text(ti, " %u (continued)", group_id);
    } else {
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ana_grp_id,  cmd_tvb, poff, 4, ENC_LITTLE_ENDIAN, &group_id);
        done += 4;
        proto_item_append_text(ti, " %u", group_id);
        cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id = group_id;
    }

    if (prev_off <= 4) {
        if ((len - done) < 4) {
            cmd_ctx->cmd_ctx.get_logpage.tr_off += done;
            return done;
        }
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_grp_nns,  cmd_tvb, poff+4-prev_off, 4, ENC_LITTLE_ENDIAN);
        done += 4;
    }
    if (prev_off <= 8) {
        if ((len - done) < 8) {
            cmd_ctx->cmd_ctx.get_logpage.tr_off += done;
            return done;
        }
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_grp_chcnt,  cmd_tvb, poff+8-prev_off, 8, ENC_LITTLE_ENDIAN);
        done += 8;
    }

    if (prev_off <= 16) {
        if ((len - done) < 1) {
            cmd_ctx->cmd_ctx.get_logpage.tr_off += done;
            return done;
        }
        add_group_mask_entry(cmd_tvb, grp, poff+16-prev_off, 1, ASPEC(hf_nvme_get_logpage_ana_grp_anas));
        done += 1;
    }

    if (prev_off <= 17) {
        if ((len - done) < 15) {
            cmd_ctx->cmd_ctx.get_logpage.tr_off += done;
            return done;
        }
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_grp_rsvd,  cmd_tvb, poff+17-prev_off, 15, ENC_NA);
        done += 15;
    }

    poff += done;
    while ((len - done) >= 4 && nns) {
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_grp_nsid,  cmd_tvb, poff, 4, ENC_LITTLE_ENDIAN);
        poff += 4;
        done += 4;
        nns--;
    }
    if (nns) {
        cmd_ctx->cmd_ctx.get_logpage.tr_off += done;
        cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = nns;
    } else {
        cmd_ctx->cmd_ctx.get_logpage.tr_off = 0;
        cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = 0;
        cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id = 0;
        cmd_ctx->cmd_ctx.get_logpage.records--;
    }
    return done;
}

static guint dissect_nvme_get_logpage_ana_resp_header(proto_tree *grp, tvbuff_t *cmd_tvb, guint len, guint32 off)
{
    guint groups=1;
    if (!off && len >= 8)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_chcnt,  cmd_tvb, off, 8, ENC_LITTLE_ENDIAN);
    if (off <= 8 && (10 - off) <= len)
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ana_ngd,  cmd_tvb, 8-off, 2, ENC_LITTLE_ENDIAN, &groups);
    if (off <= 10 && (16 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_rsvd,  cmd_tvb, 10-off, 6, ENC_LITTLE_ENDIAN);
    return groups;
}

static void dissect_nvme_get_logpage_ana_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint tr_off, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;
    guint poff = 0;
    guint groups = 1;

    grp =  proto_item_add_subtree(ti, ett_data);
    if (cmd_ctx->cmd_ctx.get_logpage.off < 16 && !tr_off) {
        groups = dissect_nvme_get_logpage_ana_resp_header(grp, cmd_tvb, len, off);
        cmd_ctx->cmd_ctx.get_logpage.records = groups;
        poff = 16 - off;
    } else if (tr_off) {
        groups = cmd_ctx->cmd_ctx.get_logpage.records;
    }
    len -= poff;
    while (len >= 4 && groups) {
        guint done = dissect_nvme_get_logpage_ana_resp_grp(grp, cmd_tvb, cmd_ctx, len, poff);
        poff += done;
        len -= done;
        groups--;
    }
}

static void dissect_nvme_get_logpage_lba_status_resp_header(proto_tree *grp, tvbuff_t *cmd_tvb, guint len, guint32 off)
{
    if (!off && len >= 4)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_lslplen,  cmd_tvb, off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 4 && (8 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nlslne,  cmd_tvb, 4-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 8 && (12 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_estulb,  cmd_tvb, 8-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 12 && (14 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_rsvd,  cmd_tvb, 12-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 14 && (16 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_lsgc,  cmd_tvb, 14-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 16 && (20 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel,  cmd_tvb, 16-off, len - (16-off), ENC_NA);
}

static guint dissect_nvme_get_logpage_lba_status_lba_range(proto_tree *grp, tvbuff_t *cmd_tvb, guint len, guint32 poff)
{
    guint32 slen;
    proto_item *ti;
    guint done;

    if (len >= 16) {
        slen = tvb_get_guint8(cmd_tvb, 4);
        if (!slen || slen == 0xffffffff)
            slen = 16;
        else
            slen = 16 * (slen + 1);
        if (slen > len)
            slen = len;
    } else {
        slen = len;
    }
    ti = proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne,  cmd_tvb, poff, slen, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);

    if (len >= 4)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_neid,  cmd_tvb, poff, 4, ENC_LITTLE_ENDIAN);
    if (len >= 8)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_nlrd,  cmd_tvb, poff+4, 4, ENC_LITTLE_ENDIAN);
    if (len >= 9)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_ratype,  cmd_tvb, poff+8, 1, ENC_LITTLE_ENDIAN);
    if (len >= 16)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_rsvd,  cmd_tvb, poff+9, 7, ENC_NA);

    if (len <= 16)
        return len;

    len -= 16;
    poff += 16;
    done = 16;
    while (len >= 8) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_rd,  cmd_tvb, poff, len >= 16 ? 16 : len, ENC_NA);
        grp =  proto_item_add_subtree(ti, ett_data);
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_rd_rslba, cmd_tvb, poff, 8, ENC_LITTLE_ENDIAN);
        if (len >= 12)
            proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_rd_rnlb, cmd_tvb, poff+8, 4, ENC_LITTLE_ENDIAN);
        if (len >= 16)
            proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_rd_rsvd, cmd_tvb, poff+12, 4, ENC_LITTLE_ENDIAN);
        if (len >= 16) {
            done += 16;
            poff += 16;
        } else {
            done += len;
            len = 0;
        }
    }
    return done;
}

static void dissect_nvme_get_logpage_lba_status_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint tr_off, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp = NULL;
    guint poff = 0;

    off += tr_off;
    if (off < 16) {
        grp =  proto_item_add_subtree(ti, ett_data);
        dissect_nvme_get_logpage_lba_status_resp_header(grp, cmd_tvb, len, off);
        poff = 16 - off;
    } else if (off & 15) {
        poff = 16 - (off & 15);
    }

    if (len < (poff + 8))
        return;

    if (off >= 16)
        grp =  proto_item_add_subtree(ti, ett_data);

    len -= poff;
    ti = proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel,  cmd_tvb, poff, len, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);

    while (len >= 8) {
        guint done = dissect_nvme_get_logpage_lba_status_lba_range(grp, cmd_tvb, len, poff);
        poff += done;
        len -= done;
    }
}

static void dissect_nvme_get_logpage_egroup_aggreg_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint tr_off, guint len)
{
    proto_tree *grp;
    guint poff = 0;

    if (!tr_off) {
        if (cmd_ctx->cmd_ctx.get_logpage.off < 8) {
            poff = 8 - (guint)cmd_ctx->cmd_ctx.get_logpage.off;
            if (poff > len || (cmd_ctx->cmd_ctx.get_logpage.off && poff == len))
                return;
        } else if (len < 2) {
            return;
        }
    }

    len -= poff;
    grp =  proto_item_add_subtree(ti, ett_data);
    if (!(cmd_ctx->cmd_ctx.get_logpage.off + tr_off))
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_aggreg_ne, cmd_tvb, 0, 8, ENC_LITTLE_ENDIAN);
    while (len >= 2) {
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_aggreg_eg, cmd_tvb, poff, 2, ENC_LITTLE_ENDIAN);
        len -= 2;
        poff += 2;
    }
}

static const value_string rnlpt_tbl[] = {
    { 0,  "Empty Log Page" },
    { 1,  "Registration Preempted" },
    { 2,  "Reservation Released" },
    { 3,  "Reservation Preempted" },
    { 0, NULL}
};

static void dissect_nvme_get_logpage_reserv_notif_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;
    guint poff = 0;

    if (cmd_ctx->cmd_ctx.get_logpage.off > 60)
        return; /* max allowed offset is < 60, so we do not loose bits by casting to guint type */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (!off && len >= 8)
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_lpc,  cmd_tvb, 0, 8, ENC_LITTLE_ENDIAN);
    if (off <= 8 && (9 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_lpt,  cmd_tvb, 8-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 9 && (10 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_nalp,  cmd_tvb, 9-off, 1, ENC_LITTLE_ENDIAN);
    if (off <= 10 && (12 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_rsvd0,  cmd_tvb, 10-off, 2, ENC_LITTLE_ENDIAN);
    if (off <= 12 && (16 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_nsid,  cmd_tvb, 12-off, 4, ENC_LITTLE_ENDIAN);
    if (off < 16) {
        poff = 16 - off;
        if (len <= poff)
            return;
        len -= poff;
        if (len > 48)
            len = 48; /* max padding size is 48 */
    } else {
        if (len > (64 - off))
            len = 64 - off; /* max padding size is 48 */
    }
    proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_rsvd1, cmd_tvb, poff, len, ENC_NA);
}


static const value_string san_mrst_tbl[] = {
    { 0, "The NVM subsystem has never been sanitized" },
    { 1, "The most recent sanitize operation completed successfully" },
    { 2, "A sanitize operation is currently in progress" },
    { 3, "The most recent sanitize operation failed" },
    { 4, "The most recent sanitize operation with No-Deallocate has completed successfully with deallocation of all logical blocks"},
    { 0, NULL}
};

static void dissect_nvme_get_logpage_sanitize_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, guint len)
{
    guint32 off = cmd_ctx->cmd_ctx.get_logpage.off & 0xffffffff; /* need guint type to silence clang-11 errors */
    proto_tree *grp;
    guint poff = 0;

    if (cmd_ctx->cmd_ctx.get_logpage.off > 508)
        return; /* max allowed offset is < 508, so we do not loose bits by casting to guint type */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (!off && len >= 2)
         proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_sprog,  cmd_tvb, 0, 2, ENC_LITTLE_ENDIAN);
    if (off <= 2 && (4 - off) <= len)
        add_group_mask_entry(cmd_tvb, grp, 2 - off, 2, ASPEC(hf_nvme_get_logpage_sanitize_sstat));
    if (off <= 4 && (8 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_scdw10,  cmd_tvb, 4-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 8 && (12 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_eto,  cmd_tvb, 8-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 12 && (16 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etbe,  cmd_tvb, 12-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 16 && (20 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etce,  cmd_tvb, 16-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 20 && (24 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etond,  cmd_tvb, 20-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 24 && (28 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etbend,  cmd_tvb, 24-off, 4, ENC_LITTLE_ENDIAN);
    if (off <= 28 && (32 - off) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etcend,  cmd_tvb, 28-off, 4, ENC_LITTLE_ENDIAN);
    if (off < 32) {
        poff = 32 - off;
        if (poff <= len)
            return;
        len -= poff;
        if (len > (512 - poff))
            len = 512 - poff;
    } else {
        if (len > (512 - off))
            len = 512 - off;
    }
    proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_rsvd,  cmd_tvb, poff, len, ENC_NA);
}

static void dissect_nvme_get_logpage_resp(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, struct nvme_cmd_ctx *cmd_ctx, guint off, guint len)
{
    proto_item *ti = proto_tree_add_bytes_format_value(cmd_tree, hf_nvme_gen_data, cmd_tvb, 0, len, NULL,
                            "NVMe Get Log Page (%s)", get_logpage_name(cmd_ctx->cmd_ctx.get_logpage.lid));
    switch(cmd_ctx->cmd_ctx.get_logpage.lid) {
        case 0x70:
            dissect_nvme_get_logpage_ify_resp(ti, cmd_tvb, cmd_ctx, off, len); break;
        case 0x1:
            /* fits smallest mtu */
            dissect_nvme_get_logpage_err_inf_resp(ti, cmd_tvb, cmd_ctx, len); break;
        case 0x2:
            /* fits smallest mtu */
            dissect_nvme_get_logpage_smart_resp(ti, cmd_tvb, cmd_ctx, len); break;
        case 0x3:
            /* fits smallest mtu */
            dissect_nvme_get_logpage_fw_slot_resp(ti, cmd_tvb, cmd_ctx, len); break;
        case 0x4:
            /* decodes array of integers, does need to know packet offset */
            dissect_nvme_get_logpage_changed_nslist_resp(ti, cmd_tvb, len); break;
        case 0x5:
            dissect_nvme_get_logpage_cmd_sup_and_eff_resp(ti, cmd_tvb, cmd_ctx, off, len); break;
        case 0x6:
            dissect_nvme_get_logpage_selftest_resp(ti, cmd_tvb, cmd_ctx, off, len); break;
        case 0x7:
        case 0x8:
            dissect_nvme_get_logpage_telemetry_resp(ti, cmd_tvb, cmd_ctx, off, len); break;
        case 0x9:
            /* fits smallest mtu */
            dissect_nvme_get_logpage_egroup_resp(ti, cmd_tvb, cmd_ctx, len); break;
        case 0xA:
            /* fits smallest mtu */
            dissect_nvme_get_logpage_pred_lat_resp(ti, cmd_tvb, cmd_ctx, len); break;
        case 0xB:
            dissect_nvme_get_logpage_pred_lat_aggreg_resp(ti, cmd_tvb, cmd_ctx, off, len); break;
        case 0xC:
            dissect_nvme_get_logpage_ana_resp(ti, cmd_tvb, cmd_ctx, off, len); break;
        case 0xE:
            dissect_nvme_get_logpage_lba_status_resp(ti, cmd_tvb, cmd_ctx, off, len); break;
        case 0xF:
            dissect_nvme_get_logpage_egroup_aggreg_resp(ti, cmd_tvb, cmd_ctx, off, len); break;
        case 0x80:
            /* fits smallest mtu */
            dissect_nvme_get_logpage_reserv_notif_resp(ti, cmd_tvb, cmd_ctx, len); break;
        case 0x81:
            /* fits smallest mtu */
            dissect_nvme_get_logpage_sanitize_resp(ti, cmd_tvb, cmd_ctx, len); break;
        default:
            return;
    }
}

static void dissect_nvme_get_logpage_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                      struct nvme_cmd_ctx *cmd_ctx)
{
    proto_item *ti;
    guint val;

    cmd_ctx->cmd_ctx.get_logpage.lid = tvb_get_guint8(cmd_tvb, 40);
    cmd_ctx->cmd_ctx.get_logpage.lsp = tvb_get_guint8(cmd_tvb, 41) & 0xf;
    cmd_ctx->cmd_ctx.get_logpage.lsi = tvb_get_guint16(cmd_tvb, 46, ENC_LITTLE_ENDIAN);
    cmd_ctx->cmd_ctx.get_logpage.uid_idx = tvb_get_guint8(cmd_tvb, 56) & 0x7f;

    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_get_logpage_dword10));
    ti = proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_get_logpage_numd, cmd_tvb, 42, 4, ENC_LITTLE_ENDIAN, &val);
    proto_item_append_text(ti, " (%"PRIu64" bytes)", ((guint64)(val+1)) * 4);

    add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_get_logpage_dword11));

    proto_tree_add_item_ret_uint64(cmd_tree, hf_nvme_get_logpage_lpo, cmd_tvb, 48, 8, ENC_LITTLE_ENDIAN, &cmd_ctx->cmd_ctx.get_logpage.off);
    cmd_ctx->cmd_ctx.get_logpage.off &= (~((guint64)3)); /* clear two low bits, the target shall either deny the command or clear the bits */

    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);

    add_group_mask_entry(cmd_tvb, cmd_tree, 56, 4, ASPEC(hf_nvme_get_logpage_dword14));

    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

typedef enum {
    F_ARBITRATION = 0x01,
    F_POWER_MGMT = 0x02,
    F_LBA_RANGE_TYPE = 0x03,
    F_TEMP_THRESHOLD = 0x04,
    F_ERROR_RECOVERY = 0x05,
    F_VOLATILE_WC = 0x06,
    F_NUM_OF_QUEUES = 0x07,
    F_IRQ_COALESCING = 0x08,
    F_IRQ_VECTOR_CONF = 0x09,
    F_WRITE_ATOM_NORM = 0x0A,
    F_ASYNC_EVENT_CONF = 0x0B,
    F_AUTO_PS_TRANSITION = 0x0C,
    F_HOST_MEM_BUF = 0x0D,
    F_TIMESTAMP = 0x0E,
    F_KA_TIMER = 0x0F,
    F_HOST_CNTL_THERM_MGMT = 0x10,
    F_NO_POWER_STATE_CONF = 0x11,
    F_READ_REC_LEVEL_CONF = 0x12,
    F_PRED_LAT_MODE_CONF = 0x13,
    F_PRED_LAT_MODE_WIND = 0x14,
    F_LBA_ST_INF_REP_INT = 0x15,
    F_HOST_BEHV_SUPPORT = 0x16,
    F_SANITIZE_CON = 0x17,
    F_END_GROUP_EV_CONF = 0x18,
    F_SW_PR_MARKER = 0x80,
    F_HOST_ID = 0x81,
    F_RSRV_NOT_MASK = 0x82,
    F_RSRV_PRST = 0x83,
    F_NS_WRITE_CONF = 0x84,
} nvme_setf_t;


static const value_string fid_table[] = {
    { F_ARBITRATION, "Arbitration" },
    { F_POWER_MGMT, "Power Management" },
    { F_LBA_RANGE_TYPE, "LBA Range Type" },
    { F_TEMP_THRESHOLD, "Temperature Threshold" },
    { F_ERROR_RECOVERY, "Error Recovery" },
    { F_VOLATILE_WC, "Volatile Write Cache" },
    { F_NUM_OF_QUEUES, "Number of Queues" },
    { F_IRQ_COALESCING, "Interrupt Coalescing" },
    { F_IRQ_VECTOR_CONF, "Interrupt Vector Configuration" },
    { F_WRITE_ATOM_NORM, "Write Atomicity Normal" },
    { F_ASYNC_EVENT_CONF, "Asynchronous Event Configuration" },
    { F_AUTO_PS_TRANSITION, "Autonomous Power State Transition" },
    { F_HOST_MEM_BUF, "Host Memory Buffer" },
    { F_TIMESTAMP, "Timestamp" },
    { F_KA_TIMER, "Keep Alive Timer" },
    { F_HOST_CNTL_THERM_MGMT, "Host Controlled Thermal Management" },
    { F_NO_POWER_STATE_CONF, "Non-Operational Power State Config" },
    { F_READ_REC_LEVEL_CONF, "Read Recovery Level Config" },
    { F_PRED_LAT_MODE_CONF, "Predictable Latency Mode Config" },
    { F_PRED_LAT_MODE_WIND, "Predictable Latency Mode Window" },
    { F_LBA_ST_INF_REP_INT, "LBA Status Information Report Interval" },
    { F_HOST_BEHV_SUPPORT, "Host Behavior Support" },
    { F_SANITIZE_CON, "Sanitize Config" },
    { F_END_GROUP_EV_CONF, "Endurance Group Event Configuration" },
    { F_SW_PR_MARKER, "Software Progress Marker" },
    { F_HOST_ID, "Host Identifier" },
    { F_RSRV_NOT_MASK, "Reservation Notification Mask" },
    { F_RSRV_PRST, "Reservation Persistence" },
    { F_NS_WRITE_CONF, "Namespace Write Protection Config" },
    { 0, NULL },
};

static const value_string sel_table[] = {
    { 0, "Current" },
    { 1, "Default" },
    { 2, "Saved" },
    { 3, "Supported Capabilities" },
    { 0, NULL },
};

static const value_string sf_tmpsel_table[] = {
    { 0x0, "Composite Temperature" },
    { 0x1, "Temperature Sensor 1" },
    { 0x2, "Temperature Sensor 2" },
    { 0x3, "Temperature Sensor 3" },
    { 0x4, "Temperature Sensor 4" },
    { 0x5, "Temperature Sensor 5" },
    { 0x6, "Temperature Sensor 6" },
    { 0x7, "Temperature Sensor 7" },
    { 0x8, "Temperature Sensor 8" },
    { 0xF, "All Temperature Sensors" },
    { 0, NULL },
};

static const value_string sf_thpsel_table[] = {
    { 0x0, "Over Temperature Threshold" },
    { 0x1, "Under Temperature Threshold" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

static const value_string sf_ws_table[] = {
    { 0x0, "Reserved" },
    { 0x1, "Deterministic Window" },
    { 0x2, "Non-Deterministic Window" },
    { 0x3, "Reserved" },
    { 0x4, "Reserved" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0, NULL },
};

static const value_string sf_wps[] = {
    { 0x0, "No Write Protect" },
    { 0x1, "Write Protect" },
    { 0x2, "Write Protect Until Power Cycle" },
    { 0x3, "Permanent Write Protect" },
    { 0x4, "Reserved" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0, NULL },
};

static void add_nvme_queues(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%x (%u)", val, val+1);
}

static void dissect_nvme_set_features_dword11(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, guint fid)
{
    switch (fid) {
        case F_ARBITRATION: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_arb)); break;
        case F_POWER_MGMT: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_pm)); break;
        case F_LBA_RANGE_TYPE: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_lbart)); break;
        case F_TEMP_THRESHOLD: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_tt)); break;
        case F_ERROR_RECOVERY: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_erec)); break;
        case F_VOLATILE_WC: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_vwce)); break;
        case F_NUM_OF_QUEUES: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_nq)); break;
        case F_IRQ_COALESCING: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_irqc)); break;
        case F_IRQ_VECTOR_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_irqv)); break;
        case F_WRITE_ATOM_NORM: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_wan)); break;
        case F_ASYNC_EVENT_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_aec)); break;
        case F_AUTO_PS_TRANSITION: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_apst)); break;
        case F_KA_TIMER: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_kat)); break;
        case F_HOST_CNTL_THERM_MGMT: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_hctm)); break;
        case F_NO_POWER_STATE_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_nops)); break;
        case F_READ_REC_LEVEL_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_rrl)); break;
        case F_PRED_LAT_MODE_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_plmc)); break;
        case F_PRED_LAT_MODE_WIND: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_plmw)); break;
        case F_LBA_ST_INF_REP_INT: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_lbasi)); break;
        case F_SANITIZE_CON: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_san)); break;
        case F_END_GROUP_EV_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_eg)); break;
        case F_SW_PR_MARKER: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_swp)); break;
        case F_HOST_ID: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_hid)); break;
        case F_RSRV_NOT_MASK: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_rsrvn)); break;
        case F_RSRV_PRST: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_rsrvp)); break;
        case F_NS_WRITE_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_nswp)); break;
        default: proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword11, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    }
}

static void dissect_nvme_set_features_dword12(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, guint fid)
{
    switch (fid) {
        case F_READ_REC_LEVEL_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 48, 4, ASPEC(hf_nvme_cmd_set_features_dword12_rrl)); break;
        case F_PRED_LAT_MODE_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 48, 4, ASPEC(hf_nvme_cmd_set_features_dword12_plmc)); break;
        case F_PRED_LAT_MODE_WIND: add_group_mask_entry(cmd_tvb, cmd_tree, 48, 4, ASPEC(hf_nvme_cmd_set_features_dword12_plmw)); break;
        default: proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    }
}

static void dissect_nvme_set_features_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                      struct nvme_cmd_ctx *cmd_ctx)
{
    cmd_ctx->cmd_ctx.set_features.fid = tvb_get_guint8(cmd_tvb, 40);
    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_set_features_dword10));
    dissect_nvme_set_features_dword11(cmd_tvb, cmd_tree, cmd_ctx->cmd_ctx.set_features.fid);
    dissect_nvme_set_features_dword12(cmd_tvb, cmd_tree, cmd_ctx->cmd_ctx.set_features.fid);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 56, 4, ASPEC(hf_nvme_set_features_dword14));
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_get_features_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                      struct nvme_cmd_ctx *cmd_ctx)
{
    cmd_ctx->cmd_ctx.set_features.fid = tvb_get_guint8(cmd_tvb, 40);
    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_get_features_dword10));
    switch(cmd_ctx->cmd_ctx.set_features.fid) {
        case F_READ_REC_LEVEL_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_get_features_dword11_rrl)); break;
        case F_PRED_LAT_MODE_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_get_features_dword11_plmc)); break;
        case F_PRED_LAT_MODE_WIND: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_get_features_dword11_plmw)); break;
        default: proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword11, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN); break;
    }
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 56, 4, ASPEC(hf_nvme_get_features_dword14));
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_rw_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti, *dsm_tree, *item;
    guint8 val;

    dissect_nvme_rwc_common_word_10_11_12_14_15(cmd_tvb, cmd_tree);

    ti = proto_tree_add_item(cmd_tree, hf_nvme_cmd_dsm, cmd_tvb, 52,
                             1, ENC_NA);
    dsm_tree = proto_item_add_subtree(ti, ett_data);

    val = tvb_get_guint8(cmd_tvb, 52) & 0x0f;
    item = proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_access_freq, cmd_tvb,
                               52, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(item, " %s",
                           val_to_str_const(val, dsm_acc_freq_tbl, "Reserved"));

    val = (tvb_get_guint8(cmd_tvb, 52) & 0x30) >> 4;
    item = proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_access_lat, cmd_tvb,
                               52, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(item, " %s",
                           val_to_str_const(val, dsm_acc_lat_tbl, "Reserved"));

    proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_seq_req, cmd_tvb,
                        52, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_incompressible, cmd_tvb,
                        52, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_rsvd3, cmd_tvb,
                        53, 3, ENC_NA);
}

static const value_string sf_lbart_type_table[] = {
    { 0x0, "General Purpose" },
    { 0x1, "Filesystem" },
    { 0x2, "RAID" },
    { 0x3, "Cache" },
    { 0x4, "Swap" },
    { 0, NULL },
};

static void dissect_nvme_set_features_transfer_lbart(tvbuff_t *tvb, proto_tree *tree, guint off, guint len)
{
    proto_tree *grp;
    proto_item *ti;
    guint done = 0;
    while (len >= 64) {
        ti =  proto_tree_add_bytes_format_value(tree, hf_nvme_set_features_tr_lbart, tvb, 0, 64, NULL, "LBA Range Structure %u", (done + off) / 64);
        grp =  proto_item_add_subtree(ti, ett_data);
        proto_tree_add_item(grp, hf_nvme_set_features_tr_lbart_type, tvb, done, 1, ENC_LITTLE_ENDIAN);
        add_group_mask_entry(tvb, grp, done+1, 1, ASPEC(hf_nvme_set_features_tr_lbart_attr));
        proto_tree_add_item(grp, hf_nvme_set_features_tr_lbart_rsvd0, tvb, done+2, 14, ENC_NA);
        proto_tree_add_item(grp, hf_nvme_set_features_tr_lbart_slba, tvb, done+16, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(grp, hf_nvme_set_features_tr_lbart_nlb, tvb, done+24, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(grp, hf_nvme_set_features_tr_lbart_guid, tvb, done+32, 16, ENC_NA);
        proto_tree_add_item(grp, hf_nvme_set_features_tr_lbart_rsvd1, tvb, done+48, 16, ENC_NA);
        len -= 64;
        done += 64;
    }
}

static void dissect_nvme_set_features_transfer_apst(tvbuff_t *tvb, proto_tree *tree, guint len)
{
    guint off = 0;
    while (len >= 8) {
        add_group_mask_entry(tvb, tree, off, 8, ASPEC(hf_nvme_set_features_tr_apst));
        len -= 8;
        off += 8;
    }
}

static void dissect_nvme_set_features_transfer_tst(tvbuff_t *tvb, proto_tree *tree)
{
    add_group_mask_entry(tvb, tree, 0, 8, ASPEC(hf_nvme_set_features_tr_tst));
}


static void dissect_nvme_set_features_transfer_plmc(tvbuff_t *tvb, proto_tree *tree, guint len)
{
    proto_tree *grp;
    proto_item *ti;

    ti = proto_tree_add_item(tree, hf_nvme_set_features_tr_plmc, tvb, 0, len, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    add_group_mask_entry(tvb, grp, 0, 2, ASPEC(hf_nvme_set_features_tr_plmc_ee));
    proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_rsvd0, tvb, 2, 30, ENC_NA);
    proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_dtwinrt, tvb, 32, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_dtwinwt, tvb, 40, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_dtwintt, tvb, 48, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_rsvd1, tvb, 56, len-56, ENC_NA);
}

static void dissect_nvme_set_features_transfer_hbs(tvbuff_t *tvb, proto_tree *tree, guint len)
{
    proto_tree *grp;
    proto_item *ti;

    ti = proto_tree_add_item(tree, hf_nvme_set_features_tr_hbs, tvb, 0, len, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item(grp, hf_nvme_set_features_tr_hbs_acre, tvb, 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_set_features_tr_hbs_rsvd, tvb, 1, len-1, ENC_NA);
}

static void dissect_nvme_set_features_transfer(tvbuff_t *tvb, proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx, guint off, guint len)
{
    switch(cmd_ctx->cmd_ctx.set_features.fid) {
        case F_LBA_RANGE_TYPE:
            dissect_nvme_set_features_transfer_lbart(tvb, tree, off, len);
            break;
        case F_AUTO_PS_TRANSITION:
            dissect_nvme_set_features_transfer_apst(tvb, tree, len);
            break;
        case F_TIMESTAMP:
            dissect_nvme_set_features_transfer_tst(tvb, tree);
            break;
        case F_PRED_LAT_MODE_CONF:
            dissect_nvme_set_features_transfer_plmc(tvb, tree, len);
            break;
        case F_HOST_BEHV_SUPPORT:
            dissect_nvme_set_features_transfer_hbs(tvb, tree, len);
            break;
        default:
            proto_tree_add_bytes_format_value(tree, hf_nvme_gen_data, tvb, 0, len, NULL,
                (cmd_ctx->opcode == NVME_AQ_OPC_SET_FEATURES) ? "Unhandled Set Features Transfer" : "Unhandled Get Features Transfer");
            break;
    }
}


void nvme_update_transfer_request(packet_info *pinfo, struct nvme_cmd_ctx *cmd, struct nvme_q_ctx *q_ctx)
{
    if (cmd->fabric) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF Data Request for %s",
            val_to_str_const(cmd->cmd_ctx.fabric_cmd.fctype, fctype_tbl, "Unknown Command"));
        return;
    }
    if (!q_ctx->qid) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF Data Request for %s", val_to_str_const(cmd->opcode, aq_opc_tbl, "Unknown Command"));
        if (cmd->opcode == NVME_AQ_OPC_IDENTIFY)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", val_to_str_const(cmd->cmd_ctx.cmd_identify.cns, cns_table, "Unknown"));
        else if (cmd->opcode == NVME_AQ_OPC_GET_LOG_PAGE)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", get_logpage_name(cmd->cmd_ctx.get_logpage.lid));
    } else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF Data Request for %s", val_to_str_const(cmd->opcode, ioq_opc_tbl, "Unknown Command"));
    }
}

void
dissect_nvme_data_response(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, guint len, gboolean is_inline)
{
    proto_tree *cmd_tree;
    proto_item *ti;
    const guint8 *str_opcode;
    guint32 off;

    off = (PINFO_FD_VISITED(pinfo)) ? nvme_lookup_data_tr_off(q_ctx, pinfo->num) : cmd_ctx->tr_bytes;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
    ti = proto_tree_add_item(root_tree, proto_nvme, nvme_tvb, 0,
                             len, ENC_NA);
    cmd_tree = proto_item_add_subtree(ti, ett_data);
    if (q_ctx->qid) { //IOQ
        str_opcode = val_to_str_const(cmd_ctx->opcode, ioq_opc_tbl,
                                      "Unknown Command");
      } else { //AQ
        str_opcode = val_to_str_const(cmd_ctx->opcode, aq_opc_tbl,
                                      "Unknown Command");
        switch (cmd_ctx->opcode) {
        case NVME_AQ_OPC_IDENTIFY:
            dissect_nvme_identify_resp(nvme_tvb, cmd_tree, cmd_ctx, off, len);
            break;
        case NVME_AQ_OPC_GET_LOG_PAGE:
                dissect_nvme_get_logpage_resp(nvme_tvb, cmd_tree, cmd_ctx, off, len);
            break;

        case NVME_AQ_OPC_SET_FEATURES:
        case NVME_AQ_OPC_GET_FEATURES:
                dissect_nvme_set_features_transfer(nvme_tvb, cmd_tree, cmd_ctx, off, len);
            break;

        default:
            proto_tree_add_bytes_format_value(cmd_tree, hf_nvme_gen_data,
                                              nvme_tvb, 0, len, NULL,
                                              "%s, offset %u", str_opcode, off);
            break;
        }
    }
    if (is_inline)
        return;
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF Data for %s", str_opcode);
    if (!q_ctx->qid) {
        if (cmd_ctx->opcode == NVME_AQ_OPC_IDENTIFY)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s, offset %u", val_to_str_const(cmd_ctx->cmd_ctx.cmd_identify.cns, cns_table, "Unknown"), off);
        else if (cmd_ctx->opcode == NVME_AQ_OPC_GET_LOG_PAGE)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s, offset %u", get_logpage_name(cmd_ctx->cmd_ctx.get_logpage.lid), off);
    } else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "offset %u", off);
    }
}

static void add_nvme_qid(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%x (%s)", val, val ? "IOQ" : "AQ");
}

static void add_zero_base(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u", val+1);
}

static
void dissect_nvmeof_fabric_connect_cmd(proto_tree *cmd_tree, packet_info *pinfo, tvbuff_t *cmd_tvb,
        struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, guint off)
{
    guint32 qid;

    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_connect_rsvd1, cmd_tvb,
                        5+off, 19, ENC_NA);
    dissect_nvme_cmd_sgl(cmd_tvb, cmd_tree, hf_nvmeof_cmd_connect_sgl1,
        q_ctx, cmd, off, PINFO_FD_VISITED(pinfo));
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_connect_recfmt, cmd_tvb,
                        40+off, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(cmd_tree, hf_nvmeof_cmd_connect_qid, cmd_tvb,
                        42+off, 2, ENC_LITTLE_ENDIAN, &qid);
    cmd->cmd_ctx.fabric_cmd.cnct.qid = qid;
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_connect_sqsize, cmd_tvb,
                        44+off, 2, ENC_LITTLE_ENDIAN);

    add_group_mask_entry(cmd_tvb, cmd_tree, 46+off, 1, ASPEC(hf_nvmeof_cmd_connect_cattr));
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_connect_rsvd2, cmd_tvb,
                        47+off, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_connect_kato, cmd_tvb,
                        48+off, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_connect_rsvd3, cmd_tvb,
                        52+off, 12, ENC_NA);
}

static
void dissect_nvmeof_fabric_auth_cmd(proto_tree *cmd_tree, packet_info *pinfo, tvbuff_t *cmd_tvb,
        struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, guint off)
{
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_auth_rsdv1, cmd_tvb,
                        5+off, 19, ENC_NA);
    dissect_nvme_cmd_sgl(cmd_tvb, cmd_tree, hf_nvmeof_cmd_auth_sgl1,
        q_ctx, cmd, off, PINFO_FD_VISITED(pinfo));
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_auth_rsdv2, cmd_tvb,
                        40+off, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_auth_spsp0, cmd_tvb,
                        41+off, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_auth_spsp1, cmd_tvb,
                        42+off, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_auth_secp, cmd_tvb,
                        43+off, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_auth_al, cmd_tvb,
                        44+off, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_auth_rsdv3, cmd_tvb,
                        48+off, 16, ENC_NA);
}

static void dissect_nvme_fabric_disconnect_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb,  guint off)
{
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_disconnect_rsvd0, cmd_tvb,
                        5+off, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_disconnect_recfmt, cmd_tvb,
                        40+off, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_disconnect_rsvd1, cmd_tvb,
                        42+off, 22, ENC_NA);
}

static void dissect_nvme_fabric_prop_cmd_common(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, guint off)
{
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_get_set_rsvd0, cmd_tvb,
                        5+off, 35, ENC_NA);

    add_group_mask_entry(cmd_tvb, cmd_tree, 40+off, 1, ASPEC(hf_nvmeof_cmd_prop_get_set_attrib));

    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_get_set_rsvd1, cmd_tvb,
                        41+off, 3, ENC_NA);

    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_get_set_offset, cmd_tvb,
                        44+off, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_nvmeof_fabric_prop_get_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd, guint off)
{
    cmd->cmd_ctx.fabric_cmd.prop_get.offset = tvb_get_guint8(cmd_tvb, 44+off);
    dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb, off);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_get_rsvd2, cmd_tvb,
                        48+off, 16, ENC_NA);
}

static void add_500ms_units(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%x (%u ms)", val, val * 500);
}

static void add_ccap_css(gchar *result, guint32 val)
{
    if (val & 0x1)
        snprintf(result, ITEM_LABEL_LENGTH, "%x (NVM IO Command Set)", val);
    else if (val & 0x80)
        snprintf(result, ITEM_LABEL_LENGTH, "%x (Admin Command Set Only)", val);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%x (Reserved)", val);
}

static void dissect_nvmeof_fabric_prop_data(proto_tree *tree, tvbuff_t *tvb, guint off, guint prop_off, guint8 attr)
{
    proto_item *ti, *grp;
    ti = proto_tree_add_item(tree, hf_nvmeof_prop_get_set_data, tvb, off, 8, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    switch(prop_off) {
        case 0x0:  add_group_mask_entry(tvb, grp, off, 8, ASPEC(hf_nvmeof_prop_get_ccap)); attr=1; break;
        case 0x8:  add_group_mask_entry(tvb, grp, off, 4, ASPEC(hf_nvmeof_prop_get_vs)); attr=0; break;
        case 0x14: add_group_mask_entry(tvb, grp, off, 4, ASPEC(hf_nvmeof_prop_get_set_cc)); attr=0; break;
        case 0x1c: add_group_mask_entry(tvb, grp, off, 4, ASPEC(hf_nvmeof_prop_get_set_csts)); attr=0; break;
        case 0x20: add_group_mask_entry(tvb, grp, off, 4, ASPEC(hf_nvmeof_prop_get_set_nssr)); attr=0; break;
        default:
        {
            if (attr == 0)
            proto_tree_add_item(grp, hf_nvmeof_prop_get_set_data_4B, tvb,
                            off, 4, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(grp, hf_nvmeof_prop_get_set_data_8B, tvb,
                            off, 8, ENC_LITTLE_ENDIAN);
            break;
        }
    }
    if (attr == 0)
        proto_tree_add_item(grp, hf_nvmeof_prop_get_set_data_4B_rsvd, tvb,
                        off+4, 4, ENC_LITTLE_ENDIAN);
}
static void dissect_nvmeof_fabric_prop_set_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd, guint off)
{
    guint8 attr;
    guint32 prop_off;

    dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb, off);
    attr = tvb_get_guint8(cmd_tvb, 40+off) & 0x7;
    prop_off = tvb_get_guint32(cmd_tvb, 44+off, ENC_LITTLE_ENDIAN);
    cmd->cmd_ctx.fabric_cmd.prop_get.offset = prop_off;
    dissect_nvmeof_fabric_prop_data(cmd_tree, cmd_tvb, 48+off, prop_off, attr);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_set_rsvd, cmd_tvb,
                        56+off, 8, ENC_NA);
}

static void dissect_nvmeof_fabric_generic_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, guint off)
{
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_generic_rsvd1, cmd_tvb,
                        5+off, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_generic_field, cmd_tvb,
                        40+off, 24, ENC_NA);
}

void dissect_nvmeof_fabric_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *nvme_tree,
        struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, guint off, gboolean link_data_req)
{
    proto_tree *cmd_tree;
    proto_item *ti;
    guint8 fctype;
    guint32 prop_off;

    fctype = tvb_get_guint8(nvme_tvb, 4+off);
    cmd->cmd_ctx.fabric_cmd.fctype = fctype;

    ti = proto_tree_add_item(nvme_tree, hf_nvmeof_cmd, nvme_tvb, off,
                             NVME_CMD_SIZE, ENC_NA);
    cmd_tree = proto_item_add_subtree(ti, ett_data);

    proto_tree_add_bytes_format(cmd_tree, hf_nvmeof_cmd_opc, nvme_tvb, off, 1, NULL, "Opcode: 0x%x (Fabric Command)",
                                NVME_FABRIC_OPC);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF %s", val_to_str_const(fctype, fctype_tbl, "Unknown Command"));
    prop_off = tvb_get_guint32(nvme_tvb, 44+off, ENC_LITTLE_ENDIAN);

    cmd->opcode = NVME_FABRIC_OPC;
    if (link_data_req)
        nvme_publish_to_data_req_link(cmd_tree, nvme_tvb, hf_nvmeof_data_req, cmd);
    nvme_publish_to_data_tr_links(cmd_tree, nvme_tvb, hf_nvmeof_data_tr, cmd);
    nvme_publish_to_cqe_link(cmd_tree, nvme_tvb, hf_nvmeof_cqe_pkt, cmd);

    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_rsvd, nvme_tvb,
                        1+off, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_cid, nvme_tvb,
                        2+off, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_fctype, nvme_tvb,
                        4+off, 1, ENC_LITTLE_ENDIAN);
    switch(fctype) {
    case NVME_FCTYPE_CONNECT:
        dissect_nvmeof_fabric_connect_cmd(cmd_tree, pinfo, nvme_tvb, q_ctx, cmd, off);
        break;
    case NVME_FCTYPE_PROP_GET:
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", val_to_str_const(prop_off, prop_offset_tbl, "Unknown Property"));
        dissect_nvmeof_fabric_prop_get_cmd(cmd_tree, nvme_tvb, cmd, off);
        break;
    case NVME_FCTYPE_PROP_SET:
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", val_to_str_const(prop_off, prop_offset_tbl, "Unknown Property"));
        dissect_nvmeof_fabric_prop_set_cmd(cmd_tree, nvme_tvb, cmd, off);
        break;
    case NVME_FCTYPE_DISCONNECT:
        dissect_nvme_fabric_disconnect_cmd(cmd_tree, nvme_tvb, off);
        break;
    case NVME_FCTYPE_AUTH_RECV:
    case NVME_FCTYPE_AUTH_SEND:
        dissect_nvmeof_fabric_auth_cmd(cmd_tree, pinfo, nvme_tvb, q_ctx, cmd, off);
        break;
    default:
        dissect_nvmeof_fabric_generic_cmd(cmd_tree, nvme_tvb, off);
        break;
    }
}

static void
dissect_nvmeof_fabric_connect_cmd_data(tvbuff_t *data_tvb, proto_tree *data_tree,
                                     guint pkt_off, guint off, guint len)
{
    if (!off) {
        CHECK_STOP_PARSE(0, 16);
        proto_tree_add_item(data_tree, hf_nvmeof_cmd_connect_data_hostid, data_tvb,
                            pkt_off, 16, ENC_NA);
    }
    if (off <= 16) {
        CHECK_STOP_PARSE(16, 2);
        proto_tree_add_item(data_tree, hf_nvmeof_cmd_connect_data_cntlid, data_tvb,
                            pkt_off + 16 - off, 2, ENC_LITTLE_ENDIAN);
    }
    if (off <= 18) {
        CHECK_STOP_PARSE(18, 238);
        proto_tree_add_item(data_tree, hf_nvmeof_cmd_connect_data_rsvd0, data_tvb,
                            pkt_off + 18 - off, 238, ENC_NA);
    }
    if (off <= 256) {
        CHECK_STOP_PARSE(256, 256);
        proto_tree_add_item(data_tree, hf_nvmeof_cmd_connect_data_subnqn, data_tvb,
                            pkt_off + 256 - off, 256, ENC_ASCII | ENC_NA);
    }
    if (off <= 512) {
        CHECK_STOP_PARSE(512, 256);
        proto_tree_add_item(data_tree, hf_nvmeof_cmd_connect_data_hostnqn, data_tvb,
                            pkt_off + 512 - off, 256, ENC_ASCII | ENC_NA);
    }
    if (off <= 768) {
        CHECK_STOP_PARSE(768, 256);
        proto_tree_add_item(data_tree, hf_nvmeof_cmd_connect_data_rsvd1, data_tvb,
                            pkt_off + 768 - off, 256, ENC_NA);
    }
}

void
dissect_nvmeof_cmd_data(tvbuff_t *data_tvb, packet_info *pinfo, proto_tree *data_tree,
                                 guint pkt_off, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, guint len)
{
    guint32 tr_off = (PINFO_FD_VISITED(pinfo)) ? nvme_lookup_data_tr_off(q_ctx, pinfo->num) : cmd->tr_bytes;

    if (!pkt_off) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeoF Data for %s, offset %u",
            val_to_str_const(cmd->cmd_ctx.fabric_cmd.fctype, fctype_tbl, "Unknown Command"), tr_off);
    }
    if (cmd->cmd_ctx.fabric_cmd.fctype == NVME_FCTYPE_CONNECT && len >= 768)
        dissect_nvmeof_fabric_connect_cmd_data(data_tvb, data_tree, pkt_off, tr_off, len);
}

static void
dissect_nvmeof_status_prop_get(proto_tree *cqe_tree, tvbuff_t *cqe_tvb, struct nvme_cmd_ctx *cmd, guint off)
{
    dissect_nvmeof_fabric_prop_data(cqe_tree, cqe_tvb, off, cmd->cmd_ctx.fabric_cmd.prop_get.offset, 1);
}

static void
dissect_nvmeof_cqe_status_8B(proto_tree *cqe_tree, tvbuff_t *cqe_tvb,
                                  struct nvme_cmd_ctx *cmd, guint off)
{
    switch (cmd->cmd_ctx.fabric_cmd.fctype) {
    case NVME_FCTYPE_CONNECT:
        proto_tree_add_item(cqe_tree, hf_nvmeof_cqe_connect_cntlid, cqe_tvb,
                            0+off, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cqe_tree, hf_nvmeof_cqe_connect_authreq, cqe_tvb,
                            2+off, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cqe_tree, hf_nvmeof_cqe_connect_rsvd, cqe_tvb,
                            4+off, 4, ENC_NA);
        break;
    case NVME_FCTYPE_PROP_GET:
        dissect_nvmeof_status_prop_get(cqe_tree, cqe_tvb, cmd, off);
        break;
    case NVME_FCTYPE_PROP_SET:
        proto_tree_add_item(cqe_tree, hf_nvmeof_cqe_prop_set_rsvd, cqe_tvb,
                            0+off, 8, ENC_NA);
        break;
    default:
        proto_tree_add_item(cqe_tree, hf_nvmeof_cqe_sts, cqe_tvb,
                            0+off, 8, ENC_LITTLE_ENDIAN);
        break;
    };
}


const gchar *get_nvmeof_cmd_string(guint8 fctype)
{
    return val_to_str(fctype, fctype_tbl, "Unknown Fabric Command");
}

static void dissect_nvme_cqe_common(tvbuff_t *nvme_tvb, proto_tree *cqe_tree, guint off, gboolean nvmeof);

void
dissect_nvmeof_fabric_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo,
                        proto_tree *nvme_tree,
                        struct nvme_cmd_ctx *cmd, guint off)
{
    proto_tree *cqe_tree;
    proto_item *ti;
    guint8 fctype = cmd->cmd_ctx.fabric_cmd.fctype;

    ti = proto_tree_add_item(nvme_tree, hf_nvmeof_cqe, nvme_tvb,
                             0+off, NVME_CQE_SIZE, ENC_NA);

    if (fctype != NVME_FCTYPE_PROP_GET && fctype != NVME_FCTYPE_PROP_SET)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF CQE for %s", val_to_str_const(fctype, fctype_tbl, "Unknown Command"));
    else
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF CQE for Property %s %s",
                            (fctype == NVME_FCTYPE_PROP_GET) ? "Get" : "Set",
                            val_to_str_const(cmd->cmd_ctx.fabric_cmd.prop_get.offset, prop_offset_tbl, "Unknown Property"));

    proto_item_append_text(ti, " (For Cmd: %s)", val_to_str(fctype, fctype_tbl, "Unknown Cmd"));

    cqe_tree = proto_item_add_subtree(ti, ett_data);

    nvme_publish_to_cmd_link(cqe_tree, nvme_tvb, hf_nvmeof_cmd_pkt,
                                 cmd);
    nvme_publish_cmd_latency(cqe_tree, cmd, hf_nvmeof_cmd_latency);

    dissect_nvmeof_cqe_status_8B(cqe_tree, nvme_tvb, cmd, off);

    dissect_nvme_cqe_common(nvme_tvb, cqe_tree, off, TRUE);
}

static void dissect_nvme_unhandled_cmd(tvbuff_t *nvme_tvb, proto_tree *cmd_tree)
{
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword10, nvme_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword11, nvme_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, nvme_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, nvme_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword14, nvme_tvb, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, nvme_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

void
dissect_nvme_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx)
{
    proto_tree *cmd_tree;
    proto_item *ti, *opc_item;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
    ti = proto_tree_add_item(root_tree, proto_nvme, nvme_tvb, 0,
                             NVME_CMD_SIZE, ENC_NA);
    proto_item_append_text(ti, " (Cmd)");
    cmd_tree = proto_item_add_subtree(ti, ett_data);

    cmd_ctx->opcode = tvb_get_guint8(nvme_tvb, 0);
    opc_item = proto_tree_add_item(cmd_tree, hf_nvme_cmd_opc, nvme_tvb,
                        0, 1, ENC_LITTLE_ENDIAN);
    if (q_ctx->qid) {
        proto_item_append_text(opc_item, " %s",
                               val_to_str_const(cmd_ctx->opcode, ioq_opc_tbl, "Unknown"));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMe %s", val_to_str_const(cmd_ctx->opcode, ioq_opc_tbl, "Unknown Command"));
    } else {
        proto_item_append_text(opc_item, " %s",
                               val_to_str_const(cmd_ctx->opcode, aq_opc_tbl, "Unknown"));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMe %s", val_to_str_const(cmd_ctx->opcode, aq_opc_tbl, "Unknown Command"));
    }

    nvme_publish_to_data_req_link(cmd_tree, nvme_tvb, hf_nvme_data_req, cmd_ctx);
    nvme_publish_to_data_tr_links(cmd_tree, nvme_tvb, hf_nvme_data_tr, cmd_ctx);
    nvme_publish_to_cqe_link(cmd_tree, nvme_tvb, hf_nvme_cqe_pkt, cmd_ctx);

    proto_tree_add_item(cmd_tree, hf_nvme_cmd_fuse_op, nvme_tvb,
                        1, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_rsvd, nvme_tvb,
                        1, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_psdt, nvme_tvb,
                        1, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_cid, nvme_tvb,
                        2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_nsid, nvme_tvb,
                        4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_rsvd1, nvme_tvb,
                        8, 8, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_mptr, nvme_tvb,
                        16, 8, ENC_LITTLE_ENDIAN);

    dissect_nvme_cmd_sgl(nvme_tvb, cmd_tree, hf_nvme_cmd_sgl, q_ctx, cmd_ctx, 0, PINFO_FD_VISITED(pinfo));

    if (q_ctx->qid) { //IOQ
        switch (cmd_ctx->opcode) {
        case NVME_IOQ_OPC_READ:
        case NVME_IOQ_OPC_WRITE:
            dissect_nvme_rw_cmd(nvme_tvb, cmd_tree);
            break;
        default:
            dissect_nvme_unhandled_cmd(nvme_tvb, cmd_tree);
            break;
        }
    } else { //AQ
        switch (cmd_ctx->opcode) {
        case NVME_AQ_OPC_IDENTIFY:
            cmd_ctx->cmd_ctx.cmd_identify.cns = tvb_get_guint16(nvme_tvb, 40, ENC_LITTLE_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", val_to_str_const(cmd_ctx->cmd_ctx.cmd_identify.cns, cns_table, "Unknown"));
            dissect_nvme_identify_cmd(nvme_tvb, cmd_tree);
            break;
        case NVME_AQ_OPC_GET_LOG_PAGE:
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", get_logpage_name(tvb_get_guint8(nvme_tvb, 40)));
            dissect_nvme_get_logpage_cmd(nvme_tvb, cmd_tree, cmd_ctx);
            break;
        case NVME_AQ_OPC_SET_FEATURES:
            dissect_nvme_set_features_cmd(nvme_tvb, cmd_tree, cmd_ctx);
            break;
        case NVME_AQ_OPC_GET_FEATURES:
            dissect_nvme_get_features_cmd(nvme_tvb, cmd_tree, cmd_ctx);
            break;
        default:
            dissect_nvme_unhandled_cmd(nvme_tvb, cmd_tree);
            break;
        }
    }
}

const gchar *nvme_get_opcode_string(guint8  opcode, guint16 qid)
{
    if (qid)
        return val_to_str_const(opcode, ioq_opc_tbl, "Reserved");
    else
        return val_to_str_const(opcode, aq_opc_tbl, "Reserved");
}

int
nvme_is_io_queue_opcode(guint8  opcode)
{
    return ((opcode == NVME_IOQ_OPC_FLUSH) ||
            (opcode == NVME_IOQ_OPC_WRITE) ||
            (opcode == NVME_IOQ_OPC_READ) ||
            (opcode == NVME_IOQ_OPC_WRITE_UNCORRECTABLE) ||
            (opcode == NVME_IOQ_OPC_COMPARE) ||
            (opcode == NVME_IOQ_OPC_WRITE_ZEROS) ||
            (opcode == NVME_IOQ_OPC_DATASET_MGMT) ||
            (opcode == NVME_IOQ_OPC_RESV_REG) ||
            (opcode == NVME_IOQ_OPC_RESV_REPORT) ||
            (opcode == NVME_IOQ_OPC_RESV_ACQUIRE) ||
            (opcode == NVME_IOQ_OPC_RESV_RELEASE));
}

static const char *get_cqe_sc_string(guint sct, guint sc, gboolean nvmeof)
{
    switch (sct) {
        case NVME_CQE_SCT_GENERIC: return val_to_str_const(sc, nvme_cqe_sc_gen_tbl, "Unknown Status Code");
        case NVME_CQE_SCT_COMMAND: return (nvmeof) ? val_to_str_const(sc, nvmeof_cqe_sc_cmd_tbl, "Unknown Fabrics Status Code") :
            val_to_str_const(sc, nvme_cqe_sc_cmd_tbl, "Unknown Status Code");
        case NVME_CQE_SCT_MEDIA: return val_to_str_const(sc, nvme_cqe_sc_media_tbl, "Unknown Status Code");
        case NVME_CQE_SCT_PATH: return val_to_str_const(sc, nvme_cqe_sc_path_tbl, "Unknown Status Code");
        case NVME_CQE_SCT_VENDOR: return "Vendor Error";
        default: return "Unknown Status Code";
    }
}

static const value_string nvme_cqe_sc_sf_err_dword0_tbl[] = {
    { 0xD, "Feature Identifier Not Saveable" },
    { 0xE, "Feature Not Changeable" },
    { 0xF, "Feature Not Namespace Specific" },
    { 0x14, "Overlapping Range" },
    { 0, NULL },
};

static const value_string nvme_cqe_aev_aet_dword0_tbl[] = {
    { 0x0, "Error status" },
    { 0x1, "SMART / Health status" },
    { 0x2, "Notice" },
    { 0x6, "IO Command Set specific status" },
    { 0x7, "Vendor specific" },
    { 0, NULL },
};

static const value_string nvme_cqe_aev_status_error_tbl[] = {
    { 0x0, "Write to Invalid Doorbell Register" },
    { 0x1, "Invalid Doorbell Write Value" },
    { 0x2, "Diagnostic Failure" },
    { 0x3, "Persistent Internal Error"},
    { 0x3, "Transient Internal Error"},
    { 0x4, "Persistent Internal Error"},
    { 0x5, "Firmware Image Load Error"},
    { 0, NULL },
};

static const value_string nvme_cqe_aev_status_smart_tbl[] = {
    { 0x0, "NVM subsystem Reliability" },
    { 0x1, "Temperature Threshold" },
    { 0x2, "Spare Below Threshold" },
    { 0, NULL },
};

static const value_string nvme_cqe_aev_status_notice_tbl[] = {
    { 0x0, "Namespace Attribute Changed" },
    { 0x1, "Firmware Activation Starting" },
    { 0x2, "Telemetry Log Changed" },
    { 0x3, "Asymmetric Namespace Access Change" },
    { 0x4, "Predictable Latency Event Aggregate Log Change" },
    { 0x5, "LBA Status Information Alert" },
    { 0x6, "Endurance Group Event Aggregate Log Page Change" },
    { 0, NULL },
};

static const value_string nvme_cqe_aev_status_nvm_tbl[] = {
    { 0x0, "Reservation Log Page Available" },
    { 0x1, "Sanitize Operation Completed" },
    { 0x2, "Sanitize Operation Completed With Unexpected Deallocation" },
    { 0, NULL },
};

static void decode_dword0_cqe(tvbuff_t *nvme_tvb, proto_tree *cqe_tree, struct nvme_cmd_ctx *cmd_ctx)
{
    switch (cmd_ctx->opcode) {
        case NVME_AQ_OPC_SET_FEATURES:
        {
            guint16 sc = tvb_get_guint16(nvme_tvb, 14, ENC_LITTLE_ENDIAN);
            sc = ((sc & 0x1fe) >> 9);
            if (sc) {
                proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0_sf_err, nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            } else {
                if (cmd_ctx->cmd_ctx.set_features.fid == F_NUM_OF_QUEUES)
                    add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_dword0_sf_nq));
                else
                    proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            }
            break;
        }
        case NVME_AQ_OPC_GET_FEATURES:
            switch (cmd_ctx->cmd_ctx.set_features.fid) {
                case F_ARBITRATION: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_arb)); break;
                case F_POWER_MGMT: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_pm)); break;
                case F_LBA_RANGE_TYPE: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_lbart)); break;
                case F_TEMP_THRESHOLD: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_tt)); break;
                case F_ERROR_RECOVERY: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_erec)); break;
                case F_VOLATILE_WC: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_vwce)); break;
                case F_NUM_OF_QUEUES: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_nq)); break;
                case F_IRQ_COALESCING: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_irqc)); break;
                case F_IRQ_VECTOR_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_irqv)); break;
                case F_WRITE_ATOM_NORM: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_wan)); break;
                case F_ASYNC_EVENT_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_aec)); break;
                case F_AUTO_PS_TRANSITION: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_apst)); break;
                case F_KA_TIMER: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_kat)); break;
                case F_HOST_CNTL_THERM_MGMT: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_hctm)); break;
                case F_NO_POWER_STATE_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_nops)); break;
                case F_READ_REC_LEVEL_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_rrl)); break;
                case F_PRED_LAT_MODE_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_plmc)); break;
                case F_PRED_LAT_MODE_WIND: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_plmw)); break;
                case F_LBA_ST_INF_REP_INT: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_lbasi)); break;
                case F_SANITIZE_CON: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_san)); break;
                case F_END_GROUP_EV_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_eg)); break;
                case F_SW_PR_MARKER: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_swp)); break;
                case F_HOST_ID: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_hid)); break;
                case F_RSRV_NOT_MASK: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_rsrvn)); break;
                case F_RSRV_PRST: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_rsrvp)); break;
                case F_NS_WRITE_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, 0, 4, ASPEC(hf_nvme_cqe_get_features_dword0_nswp)); break;
                default: proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN); break;
            }
            break;
        case NVME_AQ_OPC_ASYNC_EVE_REQ:
        {
            proto_item *ti;
            proto_tree *grp;
            guint i;
            guint8 aet;
            guint8 aei;
            ti = proto_tree_add_item(cqe_tree, hf_nvme_cqe_aev_dword0[0], nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            grp =  proto_item_add_subtree(ti, ett_data);
            for (i = 1; i < 4; i++)
                ti = proto_tree_add_item(grp, hf_nvme_cqe_aev_dword0[i], nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            aet = tvb_get_guint8(nvme_tvb, 0) & 0x7;
            aei = tvb_get_guint8(nvme_tvb, 2);
            switch (aet) {
                case 0: proto_item_append_text(ti, " (%s)", val_to_str_const(aei, nvme_cqe_aev_status_error_tbl, "Unknown")); break;
                case 1: proto_item_append_text(ti, " (%s)", val_to_str_const(aei, nvme_cqe_aev_status_smart_tbl, "Unknown")); break;
                case 2: proto_item_append_text(ti, " (%s)", val_to_str_const(aei, nvme_cqe_aev_status_notice_tbl, "Unknown")); break;
                case 6: proto_item_append_text(ti, " (%s)", val_to_str_const(aei, nvme_cqe_aev_status_nvm_tbl, "Unknown")); break;
            }
            proto_tree_add_item(grp, hf_nvme_cqe_aev_dword0[4], nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(grp, hf_nvme_cqe_aev_dword0[5], nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            break;
        }
        default:
            proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            break;
    }
}

static void dissect_nvme_cqe_common(tvbuff_t *nvme_tvb, proto_tree *cqe_tree, guint off, gboolean nvmeof)
{
    proto_item *ti;
    proto_tree *grp;
    guint16 val;
    guint i;

    val = tvb_get_guint16(nvme_tvb, off+14, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_sqhd, nvme_tvb, off+8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_sqid, nvme_tvb, off+10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_cid, nvme_tvb, off+12, 2, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(cqe_tree, hf_nvme_cqe_status[0], nvme_tvb, off+14, 2, ENC_LITTLE_ENDIAN);
    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvmeof)
        proto_tree_add_item(grp, hf_nvme_cqe_status_rsvd, nvme_tvb, off+14, 2, ENC_LITTLE_ENDIAN);
    else
        proto_tree_add_item(grp, hf_nvme_cqe_status[1], nvme_tvb, off+14, 2, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(grp, hf_nvme_cqe_status[2], nvme_tvb, off+14, 2, ENC_LITTLE_ENDIAN);
    proto_item_append_text(ti, " (%s)", get_cqe_sc_string((val & 0xE00) >> 9, (val & 0x1FE) >> 1, nvmeof));

    for (i = 3; i < array_length(hf_nvme_cqe_status); i++)
        proto_tree_add_item(grp, hf_nvme_cqe_status[i], nvme_tvb, off+14, 2, ENC_LITTLE_ENDIAN);
}

void dissect_nvme_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx)
{
    proto_tree *cqe_tree;
    proto_item *ti;

    if (q_ctx->qid)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMe CQE for %s", val_to_str_const(cmd_ctx->opcode, ioq_opc_tbl, "Unknown Command"));
    else
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMe CQE for %s", val_to_str_const(cmd_ctx->opcode, aq_opc_tbl, "Unknown Command"));

    if (!q_ctx->qid) {
        if (cmd_ctx->opcode == NVME_AQ_OPC_IDENTIFY)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", val_to_str_const(cmd_ctx->cmd_ctx.cmd_identify.cns, cns_table, "Unknown"));
        else if (cmd_ctx->opcode == NVME_AQ_OPC_GET_LOG_PAGE)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", get_logpage_name(cmd_ctx->cmd_ctx.get_logpage.lid));
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
    ti = proto_tree_add_item(root_tree, proto_nvme, nvme_tvb, 0,
                             NVME_CQE_SIZE, ENC_NA);
    proto_item_append_text(ti, " (Cqe)");
    cqe_tree = proto_item_add_subtree(ti, ett_data);

    nvme_publish_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_cmd_pkt, cmd_ctx);
    nvme_publish_cmd_latency(cqe_tree, cmd_ctx, hf_nvme_cmd_latency);

    decode_dword0_cqe(nvme_tvb, cqe_tree, cmd_ctx);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword1, nvme_tvb, 4, 4, ENC_LITTLE_ENDIAN);
    dissect_nvme_cqe_common(nvme_tvb, cqe_tree, 0, FALSE);
}

void
proto_register_nvme(void)
{
    static hf_register_info hf[] = {
        /* NVMeOF Fabric Command Fileds */
        { &hf_nvmeof_cmd,
            { "Cmd", "nvme.fabrics.cmd",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_opc,
            { "Opcode", "nvme.fabrics.cmd.opc",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_rsvd,
            { "Reserved", "nvme.fabrics.cmd.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_cid,
            { "Command Identifier", "nvme.fabrics.cmd.cid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_fctype,
            { "Fabric Command Type", "nvme.fabrics.cmd.fctype",
               FT_UINT8, BASE_HEX, VALS(fctype_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_rsvd1,
            { "Reserved", "nvme.fabrics.cmd.connect.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_sgl1,
            { "SGL1", "nvme.fabrics.cmd.connect.sgl1",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_recfmt,
            { "Record Format", "nvme.fabrics.cmd.connect.recfmt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_qid,
            { "Queue ID", "nvme.fabrics.cmd.connect.qid",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_qid), 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_sqsize,
            { "Submission Queue Size", "nvme.fabrics.cmd.connect.sqsize",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_zero_base), 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_cattr[0],
            { "Connect Attributes", "nvme.fabrics.cmd.connect.cattr",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_cattr[1],
            { "Priority Class", "nvme.fabrics.cmd.connect.cattr.pc",
               FT_UINT8, BASE_HEX, VALS(pclass_tbl), 0x3, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_cattr[2],
            { "Disable SQ Flow Control", "nvme.fabrics.cmd.connect.cattr.dfc",
               FT_UINT8, BASE_HEX, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_cattr[3],
            { "Support Deletion of IO Queues", "nvme.fabrics.cmd.connect.cattr.dioq",
               FT_UINT8, BASE_HEX, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_cattr[4],
            { "Reserved", "nvme.fabrics.cmd.connect.cattr.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_rsvd2,
            { "Reserved", "nvme.fabrics.cmd.connect.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_kato,
            { "Keep Alive Timeout", "nvme.fabrics.cmd.connect.kato",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_rsvd3,
            { "Reserved", "nvme.fabrics.cmd.connect.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_data_hostid,
            { "Host Identifier", "nvme.fabrics.cmd.connect.data.hostid",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_data_cntlid,
            { "Controller ID", "nvme.fabrics.cmd.connect.data.cntrlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_data_rsvd0,
            { "Reserved", "nvme.fabrics.cmd.connect.data.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_data_subnqn,
            { "Subsystem NQN", "nvme.fabrics.cmd.connect.data.subnqn",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_data_hostnqn,
            { "Host NQN", "nvme.fabrics.cmd.connect.data.hostnqn",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_data_rsvd1,
            { "Reserved", "nvme.fabrics.cmd.connect.data.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_auth_rsdv1,
            { "Reserved", "nvme.fabrics.cmd.auth.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_auth_sgl1,
            { "SGL1", "nvme.fabrics.cmd.auth.sgl1",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_auth_rsdv2,
            { "Reserved", "nvme.fabrics.cmd.auth.rsvd2",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_auth_spsp0,
            { "SP Specific 0", "nvme.fabrics.cmd.auth.spsp0",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_auth_spsp1,
            { "SP Specific 1", "nvme.fabrics.cmd.auth.spsp1",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_auth_secp,
            { "Security Protocol", "nvme.fabrics.cmd.auth.secp",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_auth_al,
            { "Allocation Length", "nvme.fabrics.cmd.auth.al",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_auth_rsdv3,
            { "Reserved", "nvme.fabrics.cmd.auth.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_disconnect_rsvd0,
            { "Reserved", "nvme.fabrics.cmd.disconnect.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_disconnect_recfmt,
            { "Record Format", "nvme.fabrics.cmd.disconnect.recfmt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_disconnect_rsvd1,
            { "Reserved", "nvme.fabrics.cmd.disconnect.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_prop_get_set_rsvd0,
            { "Reserved", "nvme.fabrics.cmd.prop_get_set.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_prop_get_set_attrib[0],
            { "Attributes", "nvme.fabrics.cmd.prop_get_set.attrib",
               FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_prop_get_set_attrib[1],
            { "Property Size", "nvme.fabrics.cmd.prop_get_set.attrib.size",
               FT_UINT8, BASE_HEX, VALS(attr_size_tbl), 0x7, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_prop_get_set_attrib[2],
            { "Reserved", "nvme.fabrics.cmd.prop_get_set.attrib.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_prop_get_set_rsvd1,
            { "Reserved", "nvme.fabrics.cmd.prop_get_set.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_prop_get_set_offset,
            { "Offset", "nvme.fabrics.cmd.prop_get_set.offset",
               FT_UINT32, BASE_HEX, VALS(prop_offset_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_prop_get_rsvd2,
            { "Reserved", "nvme.fabrics.cmd.prop_get.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_data,
            { "Property Data", "nvme.fabrics.prop_get_set.data",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_data_4B,
            { "Value", "nvme.fabrics.prop_get_set.data.4B",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_data_4B_rsvd,
            { "Reserved", "nvme.fabrics.prop_get_set.data.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_data_8B,
            { "Value", "nvme.fabrics.prop_get_set.data.8B",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[0],
            { "Controller Configuration", "nvme.fabrics.prop_get_set.cc",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[1],
            { "Enable", "nvme.fabrics.prop_get_set.cc.en",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[2],
            { "Reserved", "nvme.fabrics.prop_get_set.cc.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0xE, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[3],
            { "IO Command Set Selected", "nvme.fabrics.prop_get_set.cc.css",
               FT_UINT32, BASE_HEX, VALS(css_table), 0x70, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[4],
            { "Memory Page Size", "nvme.fabrics.prop_get_set.cc.mps",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_page_size), 0x780, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[5],
            { "Arbitration Mechanism Selected", "nvme.fabrics.prop_get_set.cc.ams",
               FT_UINT32, BASE_HEX, VALS(ams_table), 0x3800, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[6],
            { "Shutdown Notification", "nvme.fabrics.prop_get_set.cc.shn",
               FT_UINT32, BASE_HEX, VALS(sn_table), 0xc000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[7],
            { "IO Submission Queue Entry Size", "nvme.fabrics.prop_get_set.cc.iosqes",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_bytes), 0xF0000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[8],
            { "IO Completion Queue Entry Size", "nvme.fabrics.prop_get_set.cc.iocqes",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_bytes), 0xF00000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_cc[9],
            { "Reserved", "nvme.fabrics.prop_get_set.cc.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_csts[0],
            { "Controller Status", "nvme.fabrics.prop_get_set.csts",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_csts[1],
            { "Ready", "nvme.fabrics.prop_get_set.csts.rdy",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_csts[2],
            { "Controller Fatal Status", "nvme.fabrics.prop_get_set.csts.cfs",
               FT_UINT32, BASE_HEX, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_csts[3],
            { "Shutdown Status", "nvme.fabrics.prop_get_set.csts.shst",
               FT_UINT32, BASE_HEX, VALS(shst_table), 0xC, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_csts[4],
            { "NVM Subsystem Reset Occurred", "nvme.fabrics.prop_get_set.csts.nssro",
               FT_UINT32, BASE_HEX, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_csts[5],
            { "Processing Paused", "nvme.fabrics.prop_get_set.csts.pp",
               FT_UINT32, BASE_HEX, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_csts[6],
            { "Reserved", "nvme.fabrics.prop_get_set.csts.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffffC0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_nssr[0],
            { "NVM Subsystem Reset", "nvme.fabrics.cmd.prop_attr.set.nssr",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_set_nssr[1],
            { "NVM Subsystem Reset Control", "nvme.fabrics.cmd.prop_attr.set.nssr.nssrc",
               FT_UINT32, BASE_HEX, NULL, 0xffffffff, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_prop_set_rsvd,
            { "Reserved", "nvme.fabrics.cmd.prop_set.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_generic_rsvd1,
            { "Reserved", "nvme.fabrics.cmd.generic.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_generic_field,
            { "Fabric Cmd specific field", "nvme.fabrics.cmd.generic.field",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* NVMeOF Fabric Commands CQE fields */
        { &hf_nvmeof_cqe,
            { "Cqe", "nvme.fabrics.cqe",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cqe_sts,
            { "Cmd specific Status", "nvme.fabrics.cqe.sts",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[0],
            { "Controller Capabilities", "nvme.fabrics.prop_get.ccap",
               FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[1],
            { "Maximum Queue Entries Supported", "nvme.fabrics.prop_get.ccap.mqes",
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_zero_base), 0xffff, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[2],
            { "Contiguous Queues Required", "nvme.fabrics.prop_get.ccap.cqr",
               FT_BOOLEAN, 64, NULL, 0x10000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[3],
            { "Supports Arbitration Mechanism with Weighted Round Robin and Urgent Priority Class", "nvme.fabrics.prop_get.ccap.ams.wrr",
               FT_BOOLEAN, 64, NULL, 0x20000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[4],
            { "Supports Arbitration Mechanism Vendor Specific", "nvme.fabrics.prop_get.ccap.ams.vs",
               FT_BOOLEAN, 64, NULL, 0x40000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[5],
            { "Reserved", "nvme.fabrics.prop_get.ccap.rsvd0",
               FT_UINT64, BASE_HEX, NULL, 0xF80000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[6],
            { "Timeout (to ready status)", "nvme.fabrics.prop_get.ccap.to",
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_500ms_units), 0xFF000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[7],
            { "Doorbell Stride", "nvme.fabrics.prop_get.ccap.dstrd",
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_dstrd_size), 0xF00000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[8],
            { "NVM Subsystem Reset Supported", "nvme.fabrics.prop_get.ccap.nssrs",
               FT_BOOLEAN, 64, NULL, 0x1000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[9],
            { "Command Sets Supported", "nvme.fabrics.prop_get.ccap.css",
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_ccap_css), 0x1FE000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[10],
            { "Boot Partition Support", "nvme.fabrics.prop_get.ccap.bps",
               FT_BOOLEAN, 64, NULL, 0x200000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[11],
            { "Reserved", "nvme.fabrics.prop_get.ccap.rsdv1",
               FT_UINT64, BASE_HEX, NULL, 0xC00000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[12],
            { "Memory Page Size Minimum", "nvme.fabrics.prop_get.ccap.mpsmin",
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_page_size), 0xF000000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[13],
            { "Memory Page Size Maximum", "nvme.fabrics.prop_get.ccap.mpsmax",
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_page_size), 0xF0000000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[14],
            { "Persistent Memory Region Supported", "nvme.fabrics.prop_get.ccap.pmrs",
               FT_BOOLEAN, 64, NULL, 0x100000000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[15],
            { "Controller Memory Buffer Supported", "nvme.fabrics.prop_get.ccap.cmbs",
               FT_BOOLEAN, 64, NULL, 0x200000000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[16],
            { "Reserved", "nvme.fabrics.prop_get.ccap.rsvd2",
               FT_UINT64, BASE_HEX, NULL, 0xFC00000000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_vs[0],
            { "Version", "nvme.fabrics.prop_get.vs",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_vs[1],
            { "Tertiary Version", "nvme.fabrics.prop_get.vs.ter",
               FT_UINT32, BASE_DEC, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_vs[2],
            { "Minor Version", "nvme.fabrics.prop_get.vs.mnr",
               FT_UINT32, BASE_DEC, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_vs[3],
            { "Major Version", "nvme.fabrics.prop_get.vs.mjr",
               FT_UINT32, BASE_DEC, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvmeof_cqe_connect_cntlid,
            { "Controller ID", "nvme.fabrics.cqe.connect.cntrlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cqe_connect_authreq,
            { "Authentication Required", "nvme.fabrics.cqe.connect.authreq",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cqe_connect_rsvd,
            { "Reserved", "nvme.fabrics.cqe.connect.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cqe_prop_set_rsvd,
            { "Reserved", "nvme.fabrics.cqe.prop_set.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Tracking commands, completions and transfers */
                { &hf_nvmeof_cmd_pkt,
            { "Fabric Cmd in", "nvme.fabrics.cmd_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cmd for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_cqe_pkt,
            { "Fabric Cqe in", "nvme.fabrics.cqe_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cqe for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_req,
            { "DATA Transfer Request", "nvme.fabrics.data_req",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer request for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[0],
            { "DATA Transfer 0", "nvme.fabrics.data.tr0",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 0 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[1],
            { "DATA Transfer 1", "nvme.fabrics.data_tr1",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 1 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[2],
            { "DATA Transfer 2", "nvme.fabrics.data_tr2",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 2 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[3],
            { "DATA Transfer 3", "nvme.fabrics.data_tr3",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 3 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[4],
            { "DATA Transfer 4", "nvme.fabrics.data_tr4",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 4 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[5],
            { "DATA Transfer 5", "nvme.fabrics.data_tr5",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 5 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[6],
            { "DATA Transfer 6", "nvme.fabrics.data_tr6",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 6 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[7],
            { "DATA Transfer 7", "nvme.fabrics.data_tr7",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 7 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[8],
            { "DATA Transfer 8", "nvme.fabrics.data_tr8",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 8 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[9],
            { "DATA Transfer 9", "nvme.fabrics.data_tr9",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 9 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[10],
            { "DATA Transfer 10", "nvme.fabrics.data_tr10",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 10 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[11],
            { "DATA Transfer 11", "nvme.fabrics.data_tr11",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 11 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[12],
            { "DATA Transfer 12", "nvme.fabrics.data_tr12",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 12 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[13],
            { "DATA Transfer 13", "nvme.fabrics.data_tr13",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 13 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[14],
            { "DATA Transfer 14", "nvme.fabrics.data_tr14",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 14 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_data_tr[15],
            { "DATA Transfer 15", "nvme.fabrics.data_tr15",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 15 for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_cmd_latency,
            { "Cmd Latency", "nvme.fabrics.cmd_latency",
              FT_DOUBLE, BASE_NONE, NULL, 0x0,
              "The time between the command and completion, in usec", HFILL }
        },
        /* NVMe Command fields */
        { &hf_nvme_cmd_opc,
            { "Opcode", "nvme.cmd.opc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cmd_fuse_op,
            { "Fuse Operation", "nvme.cmd.fuse_op",
               FT_UINT8, BASE_HEX, NULL, 0x3, NULL, HFILL}
        },
        { &hf_nvme_cmd_rsvd,
            { "Reserved", "nvme.cmd.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0x3c, NULL, HFILL}
        },
        { &hf_nvme_cmd_psdt,
            { "PRP Or SGL", "nvme.cmd.psdt",
               FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL}
        },
        { &hf_nvme_cmd_cid,
            { "Command ID", "nvme.cmd.cid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cmd_nsid,
            { "Namespace Id", "nvme.cmd.nsid",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_rsvd1,
            { "Reserved", "nvme.cmd.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_mptr,
            { "Metadata Pointer", "nvme.cmd.mptr",
               FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_sgl,
            { "SGL1", "nvme.cmd.sgl1",
               FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_sgl_desc_sub_type,
            { "Descriptor Sub Type", "nvme.cmd.sgl.subtype",
               FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL}
        },
        { &hf_nvme_cmd_sgl_desc_type,
            { "Descriptor Type", "nvme.cmd.sgl.type",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_cmd_sgl_desc_addr,
            { "Address", "nvme.cmd.sgl1.addr",
               FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_sgl_desc_addr_rsvd,
            { "Reserved", "nvme.cmd.sgl1.addr_rsvd",
               FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_sgl_desc_len,
            { "Length", "nvme.cmd.sgl1.len",
               FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_sgl_desc_key,
            { "Key", "nvme.cmd.sgl1.key",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_sgl_desc_rsvd,
            { "Reserved", "nvme.cmd.sgl1.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dword10,
            { "DWORD10", "nvme.cmd.dword10",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dword11,
            { "DWORD11", "nvme.cmd.dword11",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dword12,
            { "DWORD12", "nvme.cmd.dword12",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dword13,
            { "DWORD13", "nvme.cmd.dword13",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dword14,
            { "DWORD14", "nvme.cmd.dword14",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dword15,
            { "DWORD15", "nvme.cmd.dword15",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_slba,
            { "Start LBA", "nvme.cmd.slba",
               FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_nlb,
            { "Absolute Number of Logical Blocks", "nvme.cmd.nlb",
               FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_rsvd2,
            { "Reserved", "nvme.cmd.rsvd2",
               FT_UINT16, BASE_HEX, NULL, 0x03ff, NULL, HFILL}
        },
        { &hf_nvme_cmd_prinfo,
            { "Protection info fields",
              "nvme.cmd.prinfo",
               FT_UINT16, BASE_HEX, NULL, 0x0400, NULL, HFILL}
        },
        { &hf_nvme_cmd_prinfo_prchk_lbrtag,
            { "check Logical block reference tag",
              "nvme.cmd.prinfo.lbrtag",
               FT_UINT16, BASE_HEX, NULL, 0x0400, NULL, HFILL}
        },
        { &hf_nvme_cmd_prinfo_prchk_apptag,
            { "check application tag field",
              "nvme.cmd.prinfo.apptag",
               FT_UINT16, BASE_HEX, NULL, 0x0800, NULL, HFILL}
        },
        { &hf_nvme_cmd_prinfo_prchk_guard,
            { "check guard field",
              "nvme.cmd.prinfo.guard",
               FT_UINT16, BASE_HEX, NULL, 0x1000, NULL, HFILL}
        },
        { &hf_nvme_cmd_prinfo_pract,
            { "action",
              "nvme.cmd.prinfo.action",
               FT_UINT16, BASE_HEX, NULL, 0x2000, NULL, HFILL}
        },
        { &hf_nvme_cmd_fua,
            { "Force Unit Access", "nvme.cmd.fua",
               FT_UINT16, BASE_HEX, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_cmd_lr,
            { "Limited Retry", "nvme.cmd.lr",
               FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_cmd_eilbrt,
            { "Expected Initial Logical Block Reference Tag", "nvme.cmd.eilbrt",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cmd_elbat,
            { "Expected Logical Block Application Tag Mask", "nvme.cmd.elbat",
               FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_elbatm,
            { "Expected Logical Block Application Tag", "nvme.cmd.elbatm",
               FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dsm,
            { "DSM Flags", "nvme.cmd.dsm",
               FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dsm_access_freq,
            { "Access frequency", "nvme.cmd.dsm.access_freq",
               FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL}
        },
        { &hf_nvme_cmd_dsm_access_lat,
            { "Access latency", "nvme.cmd.dsm.access_lat",
               FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL}
        },
        { &hf_nvme_cmd_dsm_seq_req,
            { "Sequential Request", "nvme.cmd.dsm.seq_req",
               FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_cmd_dsm_incompressible,
            { "Incompressible", "nvme.cmd.dsm.incompressible",
               FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_cmd_rsvd3 ,
            { "Reserved", "nvme.cmd.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_dword10[0],
            { "DWORD10", "nvme.cmd.identify.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_dword10[1],
            { "Controller or Namespace Structure (CNS)", "nvme.cmd.identify.dword10.cns",
               FT_UINT32, BASE_HEX, VALS(cns_table), 0xff, NULL, HFILL}
        },
        { &hf_nvme_identify_dword10[2],
            { "Reserved", "nvme.cmd.identify.dword10.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvme_identify_dword10[3],
            { "Controller Identifier (CNTID)", "nvme.cmd.identify.dword10.cntid",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_identify_dword11[0],
            { "DWORD11", "nvme.cmd.identify.dword11",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_dword11[1],
            { "NVM Set Identifier (NVMSETID)", "nvme.cmd.identify.dwrod11.nvmesetid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_identify_dword11[2],
            { "Reserved", "nvme.cmd.identify.dword11.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_identify_dword14[0],
            { "DWORD14", "nvme.cmd.identify.dword14",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_dword14[1],
            { "UUID Index", "nvme.cmd.identify.dword14.uuid_index",
               FT_UINT32, BASE_HEX, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_identify_dword14[2],
            { "UUID Index", "nvme.cmd.identify.dword14.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffff80, NULL, HFILL}
        },
        /* get log page */
        { &hf_nvme_get_logpage_dword10[0],
            { "DWORD 10", "nvme.cmd.get_logpage.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10[1],
            { "Log Page Identifier (LID)", "nvme.cmd.get_logpage.dword10.id",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_logpage_lid), 0xff, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10[2],
            { "Log Specific Field (LSP)", "nvme.cmd.get_logpage.dword10.lsp",
               FT_UINT32, BASE_HEX, NULL, 0x1f00, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10[3],
            { "Reserved", "nvme.cmd.get_logpage.dword10.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x6000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10[4],
            { "Retain Asynchronous Event (RAE)", "nvme.cmd.get_logpage.dword10.rae",
               FT_BOOLEAN, 32, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10[5],
            { "Number of Dwords Lower (NUMDL)", "nvme.cmd.get_logpage.dword10.numdl",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_numd,
            { "Number of Dwords", "nvme.cmd.get_logpage.numd",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword11[0],
            { "DWORD 11", "nvme.cmd.get_logpage.dword11",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword11[1],
            { "Number of Dwords Upper (NUMDU)", "nvme.cmd.get_logpage.dword11.numdu",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword11[2],
            { "Log Specific Identifier", "nvme.cmd.get_logpage.dword11.lsi",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lpo,
            { "Log Page Offset (DWORD 12 and DWORD 13)", "nvme.cmd.get_logpage.lpo",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword14[0],
            { "DWORD 14", "nvme.cmd.get_logpage.dword14",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword14[1],
            { "UUID Index", "nvme.cmd.identify.get_logpage.dword14.uuid_index",
               FT_UINT32, BASE_HEX, NULL, 0x3f, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword14[2],
            { "Reserved", "nvme.cmd.identify.get_logpage.dword14.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffffc0, NULL, HFILL}
        },
        /* Set Features */
        { &hf_nvme_set_features_dword10[0],
            { "DWORD 10", "nvme.cmd.set_features.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_dword10[1],
            { "Feature Identifier", "nvme.cmd.set_features.dword10.fid",
               FT_UINT32, BASE_HEX, VALS(fid_table), 0xff, NULL, HFILL}
        },
        { &hf_nvme_set_features_dword10[2],
            { "Reserved", "nvme.cmd.set_features.dword10.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x7fffff00, NULL, HFILL}
        },
        { &hf_nvme_set_features_dword10[3],
            { "Save", "nvme.cmd.set_features.dword10.sv",
               FT_UINT32, BASE_HEX, NULL, 0x80000000, NULL, HFILL}
        },
        { &hf_nvme_set_features_dword14[0],
            { "DWORD 14", "nvme.cmd.set_features.dword14",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_dword14[1],
            { "UUID Index", "nvme.cmd.set_features.dword14.uuid",
               FT_UINT32, BASE_HEX, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_set_features_dword14[2],
            { "Reserved", "nvme.cmd.set_features.dword14.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffff80, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.arb",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[1],
            { "Arbitration Burst", "nvme.cmd.set_features.dword11.arb.ab",
               FT_UINT32, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[3],
            { "Low Priority Weight", "nvme.cmd.set_features.dword11.arb.lpw",
               FT_UINT32, BASE_HEX, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[4],
            { "Medium Priority Weight", "nvme.cmd.set_features.dword11.arb.mpw",
               FT_UINT32, BASE_HEX, NULL, 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[5],
            { "High Priority Weight", "nvme.cmd.set_features.dword11.arb.hpw",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_pm[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.pm",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_pm[1],
            { "Power State", "nvme.cmd.set_features.dword11.pm.ps",
               FT_UINT32, BASE_HEX, NULL, 0x1f, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_pm[2],
            { "Work Hint", "nvme.cmd.set_features.dword11.pm.wh",
               FT_UINT32, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_pm[3],
            { "Work Hint", "nvme.cmd.set_features.dword11.pm.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbart[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.lbart",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbart[1],
            { "DWORD11", "nvme.cmd.set_features.dword11.lbart.lbarn",
               FT_UINT32, BASE_HEX, NULL, 0x3f, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbart[2],
            { "DWORD11", "nvme.cmd.set_features.dword11.lbart.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffffc0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_tt[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.tt",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_tt[1],
            { "Temperature Threshold", "nvme.cmd.set_features.dword11.tt.tmpth",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_tt[2],
            { "Threshold Temperature Select", "nvme.cmd.set_features.dword11.tt.tmpsel",
               FT_UINT32, BASE_HEX, VALS(sf_tmpsel_table), 0xf0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_tt[3],
            { "Threshold Type Select", "nvme.cmd.set_features.dword11.tt.thpsel",
               FT_UINT32, BASE_HEX, VALS(sf_thpsel_table), 0x300000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_tt[4],
            { "Reserved", "nvme.cmd.set_features.dword11.tt.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xc00000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_erec[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.erec",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_erec[1],
            { "Time Limited Error Recovery (100 ms units)", "nvme.cmd.set_features.dword11.erec.tler",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_erec[2],
            { "Deallocated or Unwritten Logical Block Error Enable", "nvme.cmd.set_features.dword11.erec.dulbe",
               FT_BOOLEAN, 32, NULL, 0x10000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_erec[3],
            { "Reserved", "nvme.cmd.set_features.dword11.erec.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfe0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_vwce[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.vwce",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_vwce[1],
            { "Volatile Write Cache Enable", "nvme.cmd.set_features.dword11.vwce.wce",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_vwce[2],
            { "Volatile Write Cache Enable", "nvme.cmd.set_features.dword11.vwce.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nq[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.nq",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nq[1],
            { "Number of IO Submission Queues Requested", "nvme.cmd.set_features.dword11.nq.nsqr",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_queues), 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nq[2],
            { "Number of IO Completion Queues Requested", "nvme.cmd.set_features.dword11.nq.ncqr",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_queues), 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqc[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.irqc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqc[1],
            { "Aggregation Threshold", "nvme.cmd.set_features.dword11.irqc.thr",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqc[2],
            { "Aggregation Time (100 us units)", "nvme.cmd.set_features.dword11.irqc.time",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqv[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.irqv",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqv[1],
            { "IRQ Vector", "nvme.cmd.set_features.dword11.irqv.iv",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqv[2],
            { "Coalescing Disable", "nvme.cmd.set_features.dword11.irqv.cd",
               FT_BOOLEAN, 32, NULL, 0x1ffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqv[3],
            { "Reserved", "nvme.cmd.set_features.dword11.irqv.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffe0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_wan[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.wan",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_wan[1],
            { "Disable Normal", "nvme.cmd.set_features.dword11.wan.dn",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_wan[2],
            { "Reserved", "nvme.cmd.set_features.dword11.wan.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.aec",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[1],
            { "SMART and Health Critical Warnings Bitmask", "nvme.cmd.set_features.dword11.aec.smart",
               FT_UINT32, BASE_HEX, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[2],
            { "Namespace Attribute Notices", "nvme.cmd.set_features.dword11.aec.ns",
               FT_BOOLEAN, 32, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[3],
            { "Firmware Activation Notices", "nvme.cmd.set_features.dword11.aec.fwa",
               FT_BOOLEAN, 32, NULL, 0x200, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[4],
            { "Telemetry Log Notices", "nvme.cmd.set_features.dword11.aec.tel",
               FT_BOOLEAN, 32, NULL, 0x400, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[5],
            { "ANA Change Notices", "nvme.cmd.set_features.dword11.aec.ana",
               FT_BOOLEAN, 32, NULL, 0x800, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[6],
            { "Predictable Latency Event Aggregate Log Change Notices", "nvme.cmd.set_features.dword11.aec.plat",
               FT_BOOLEAN, 32, NULL, 0x1000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[7],
            { "LBA Status Information Notices", "nvme.cmd.set_features.dword11.aec.lba",
               FT_BOOLEAN, 32, NULL, 0x2000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[8],
            { "Endurance Group Event Aggregate Log Change Notices", "nvme.cmd.set_features.dword11.aec.eg",
               FT_BOOLEAN, 32, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[9],
            { "Reserved", "nvme.cmd.set_features.dword11.aec.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x7fff8000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[10],
            { "Discovery Log Page Change Notification", "nvme.cmd.set_features.dword11.aec.disc",
               FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_apst[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.apst",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_apst[1],
            { "Autonomous Power State Transition Enable", "nvme.cmd.set_features.dword11.apst.apste",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_apst[2],
            { "Reserved", "nvme.cmd.set_features.dword11.apst.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_kat[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.kat",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_kat[1],
            { "Keep Alive Timeout", "nvme.cmd.set_features.dword11.kat.kato",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hctm[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.hctm",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hctm[1],
            { "Thermal Management Temperature 2 (K)", "nvme.cmd.set_features.dword11.hctm.tmt2",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hctm[2],
            { "Thermal Management Temperature 1 (K)", "nvme.cmd.set_features.dword11.hctm.tmt1",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nops[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.nops",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nops[1],
            { "Non-Operational Power State Permissive Mode Enable", "nvme.cmd.set_features.dword11.nops.noppme",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nops[2],
            { "Reserved", "nvme.cmd.set_features.dword11.nops.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rrl[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.rrl",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rrl[1],
            { "NVM Set Identifier", "nvme.cmd.set_features.dword11.rrl.nvmsetid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rrl[2],
            { "Reserved", "nvme.cmd.set_features.dword11.rrl.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_rrl[0],
            { "DWORD12", "nvme.cmd.set_features.dword12.rrl",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_rrl[1],
            { "Read Recovery Level", "nvme.cmd.set_features.dword12.rrl.rrl",
               FT_UINT32, BASE_HEX, NULL, 0xf, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_rrl[2],
            { "Reserved", "nvme.cmd.set_features.dword12.rrl.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plmc[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.plmc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plmc[1],
            { "NVM Set Identifier", "nvme.cmd.set_features.dword11.plmc.nvmsetid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plmc[2],
            { "Reserved", "nvme.cmd.set_features.dword11.plmc.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_plmc[0],
            { "DWORD12", "nvme.cmd.set_features.dword12.plmc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_plmc[1],
            { "Predictable Latency Enable", "nvme.cmd.set_features.dword12.plmc.ple",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_plmc[2],
            { "Reserved", "nvme.cmd.set_features.dword12.plmc.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plmw[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.plmw",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plmw[1],
            { "NVM Set Identifier", "nvme.cmd.set_features.dword11.plmw.nvmsetid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plmw[2],
            { "Reserved", "nvme.cmd.set_features.dword11.plmw.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_plmw[0],
            { "DWORD12", "nvme.cmd.set_features.dword12.plmw",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_plmw[1],
            { "DWORD12", "nvme.cmd.set_features.dword12.plmw.ws",
               FT_UINT32, BASE_HEX, VALS(sf_ws_table), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword12_plmw[2],
            { "Reserved", "nvme.cmd.set_features.dword12.plmw.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff8, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbasi[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.lbasi",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbasi[1],
            { "LBA Status Information Report Interval (100 ms)", "nvme.cmd.set_features.dword11.lbasi.lsiri",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbasi[2],
            { "LBA Status Information Poll Interval (100 ms)", "nvme.cmd.set_features.dword11.lbasi.lsipi",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_san[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.san",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_san[1],
            { "No-Deallocate Response Mode", "nvme.cmd.set_features.dword11.san.nodrm",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_san[2],
            { "Reserved", "nvme.cmd.set_features.dword11.san.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_eg[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.eg",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_eg[1],
            { "Endurance Group Identifier", "nvme.cmd.set_features.dword11.eg.endgid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_eg[2],
            { "Endurance Group Critical Warnings Bitmask", "nvme.cmd.set_features.dword11.eg.egcw",
               FT_UINT32, BASE_HEX, NULL, 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_eg[3],
            { "Reserved", "nvme.cmd.set_features.dword11.eg.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_swp[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.swp",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_swp[1],
            { "Pre-boot Software Load Count", "nvme.cmd.set_features.dword11.swp.pbslc",
               FT_UINT32, BASE_HEX, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_swp[2],
            { "Reserved", "nvme.cmd.set_features.dword11.swp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffff00, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hid[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.hid",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hid[1],
            { "Enable Extended Host Identifier", "nvme.cmd.set_features.dword11.hid.exhid",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hid[2],
            { "Reserved", "nvme.cmd.set_features.dword11.hid.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvn[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.rsrvn",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvn[1],
            { "Reserved", "nvme.cmd.set_features.dword11.rsrvn.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvn[2],
            { "Mask Registration Preempted Notification" , "nvme.cmd.set_features.dword11.rsrvn.regpre",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvn[3],
            { "Mask Reservation Released Notification", "nvme.cmd.set_features.dword11.rsrvn.resrel",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvn[4],
            { "Mask Reservation Preempted Notification", "nvme.cmd.set_features.dword11.rsrvn.resrpe",
               FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvn[5],
            { "Reserved", "nvme.cmd.set_features.dword11.rsrvn.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xfffff0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvp[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.rsrvp",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvp[1],
            { "Persist Through Power Loss", "nvme.cmd.set_features.dword11.rsrvp.ptpl",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_rsrvp[2],
            { "Reserved", "nvme.cmd.set_features.dword11.rsrvp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nswp[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.nswp",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nswp[1],
            { "DWORD11", "nvme.cmd.set_features.dword11.nswp.wps",
               FT_UINT32, BASE_HEX, VALS(sf_wps), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nswp[2],
            { "DWORD11", "nvme.cmd.set_features.dword11.nswp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff8, NULL, HFILL}
        },
        /* Set Features Transfers */
        { &hf_nvme_set_features_tr_lbart,
            { "LBA Range Structure", "nvme.set_features.lbart",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_type,
            { "Type", "nvme.set_features.lbart.type",
               FT_UINT8, BASE_HEX, VALS(sf_lbart_type_table), 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_attr[0],
            { "Attributes", "nvme.set_features.lbart.attr",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_attr[1],
            { "LBA Range may be overwritten", "nvme.set_features.lbart.attr.ovw",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_attr[2],
            { "LBA Range shall be hidden from OS/EFI/BIOS", "nvme.set_features.lbart.attr.hid",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_attr[3],
            { "Reserved", "nvme.set_features.lbart.attr.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_rsvd0,
            { "Reserved", "nvme.set_features.lbart.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_slba,
            { "Starting LBA", "nvme.set_features.lbart.slba",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_nlb,
            { "Number of Logical Blocks", "nvme.set_features.lbart.nlb",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_guid,
            { "Unique Identifier", "nvme.set_features.lbart.guid",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_rsvd1,
            { "Reserved", "nvme.set_features.lbart.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_apst[0],
            { "Autonomous Power State Transition Structure", "nvme.set_features.lbart.apst",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_apst[1],
            { "Reserved", "nvme.set_features.lbart.apst.rsvd0",
               FT_UINT64, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_apst[2],
            { "Idle Transition Power State", "nvme.set_features.lbart.apst.itps",
               FT_UINT64, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_apst[3],
            { "Idle Time Prior to Transition (us)", "nvme.set_features.lbart.apst.itpt",
               FT_UINT64, BASE_HEX, NULL, 0xfffff00, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_apst[4],
            { "Reserved", "nvme.set_features.lbart.apst.rsvd1",
               FT_UINT64, BASE_HEX, NULL, 0xffffffff00000000, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_tst[0],
            { "Timestamp Structure", "nvme.set_features.tst",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_tst[1],
            { "Timestamp (milliseconds since 01-Jan-1970)", "nvme.set_features.tst.ms",
               FT_UINT64, BASE_HEX, NULL, 0xffffffffffff, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_tst[2],
            { "Reserved", "nvme.set_features.tst.rsvd",
               FT_UINT64, BASE_HEX, NULL, 0xffff000000000000, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc,
            { "Reserved", "nvme.set_features.plmc",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_ee[0],
            { "Enable Event", "nvme.set_features.plmc.ee",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_ee[1],
            { "DTWIN Reads Warning", "nvme.set_features.plmc.ee.dtwinr",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_ee[2],
            { "DTWIN Writes Warning", "nvme.set_features.plmc.ee.dtwinw",
               FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_ee[3],
            { "DTWIN Time Warning", "nvme.set_features.plmc.ee.dtwint",
               FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_ee[4],
            { "Reserved", "nvme.set_features.plmc.ee.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x3ff8, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_ee[5],
            { "DTWIN to NDWIN transition due to typical or maximum value exceeded", "nvme.set_features.plmc.ee.ndtwindv",
               FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_ee[6],
            { "DTWIN to NDWIN transition due to Deterministic Excursion", "nvme.set_features.plmc.ee.ndtwindde",
               FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_rsvd0,
            { "Reserved", "nvme.set_features.plmc.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_dtwinrt,
            { "DTWIN Reads Threshold", "nvme.set_features.plmc.dtwinrt",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_dtwinwt,
            { "DTWIN Writes Threshold", "nvme.set_features.plmc.dtwinwt",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_dtwintt,
            { "DTWIN Time Threshold", "nvme.set_features.plmc.dtwintt",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc_rsvd1,
            { "Reserved", "nvme.set_features.plmc.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs,
            { "Host Behavior Support Structure", "nvme.set_features.hbs",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_acre,
            { "Advanced Command Retry Enable", "nvme.set_features.hbs.acre",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_rsvd,
            { "Reserved", "nvme.set_features.hbs.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Get Features */
        { &hf_nvme_get_features_dword10[0],
            { "DWORD 10", "nvme.cmd.get_features.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_features_dword10[1],
            { "Feature Identifier", "nvme.cmd.get_features.dword10.fid",
               FT_UINT32, BASE_HEX, VALS(fid_table), 0xff, NULL, HFILL}
        },
        { &hf_nvme_get_features_dword10[2],
            { "Select", "nvme.cmd.set_features.dword10.sel",
               FT_UINT32, BASE_HEX, VALS(sel_table), 0x700, NULL, HFILL}
        },
        { &hf_nvme_get_features_dword10[3],
            { "Reserved", "nvme.cmd.get_features.dword10.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffff800, NULL, HFILL}
        },
        { &hf_nvme_get_features_dword14[0],
            { "DWORD 14", "nvme.cmd.get_features.dword14",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_features_dword14[1],
            { "UUID Index", "nvme.cmd.get_features.dword14.uuid",
               FT_UINT32, BASE_HEX, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_get_features_dword14[2],
            { "Reserved", "nvme.cmd.get_features.dword14.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffff80, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_rrl[0],
            { "DWORD11", "nvme.cmd.get_features.dword11.rrl",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_rrl[1],
            { "NVM Set Identifier", "nvme.cmd_get_features.dword11.rrl.nvmsetid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_rrl[2],
            { "Reserved", "nvme.cmd.get_features.dword11.rrl.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_plmc[0],
            { "DWORD11", "nvme.cmd.get_features.dword11.plmc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_plmc[1],
            { "NVM Set Identifier", "nvme.cmd.get_features.dword11.plmc.nvmsetid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_plmc[2],
            { "Reserved", "nvme.cmd.get_features.dword11.plmc.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_plmw[0],
            { "DWORD11", "nvme.cmd.get_features.dword11.plmw",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_plmw[1],
            { "NVM Set Identifier", "nvme.cmd.get_features.dword11.plmw.nvmsetid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_plmw[2],
            { "Reserved", "nvme.cmd.get_features.dword11.plmw.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        /* Identify NS response */
        { &hf_nvme_identify_ns_nsze,
            { "Namespace Size (NSZE)", "nvme.cmd.identify.ns.nsze",
               FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_ncap,
            { "Namespace Capacity (NCAP)", "nvme.cmd.identify.ns.ncap",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nuse,
            { "Namespace Utilization (NUSE)", "nvme.cmd.identify.ns.nuse",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsfeat,
            { "Namespace Features (NSFEAT)", "nvme.cmd.identify.ns.nsfeat",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nlbaf,
            { "Number of LBA Formats (NLBAF)", "nvme.cmd.identify.ns.nlbaf",
               FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_flbas,
            { "Formatted LBA Size (FLBAS)", "nvme.cmd.identify.ns.flbas",
               FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_mc,
            { "Metadata Capabilities (MC)", "nvme.cmd.identify.ns.mc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dpc,
            { "End-to-end Data Protection Capabilities (DPC)", "nvme.cmd.identify.ns.dpc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dps,
            { "End-to-end Data Protection Type Settings (DPS)", "nvme.cmd.identify.ns.dps",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nmic,
            { "Namespace Multi-path I/O and Namespace Sharing Capabilities (NMIC)",
              "nvme.cmd.identify.ns.nmic", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nguid,
            { "Namespace Globally Unique Identifier (NGUID)", "nvme.cmd.identify.ns.nguid",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_eui64,
            { "IEEE Extended Unique Identifier (EUI64)", "nvme.cmd.identify.ns.eui64",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_lbafs,
            { "LBA Formats", "nvme.cmd.identify.ns.lbafs",
               FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_lbaf,
            { "LBA Format", "nvme.cmd.identify.ns.lbaf",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rsvd,
            { "Reserved", "nvme.cmd.identify.ns.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_vs,
            { "Vendor Specific", "nvme.cmd.identify.ns.vs",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Identify Ctrl response */
        { &hf_nvme_identify_ctrl_vid,
            { "PCI Vendor ID (VID)", "nvme.cmd.identify.ctrl.vid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ssvid,
            { "PCI Subsystem Vendor ID (SSVID)", "nvme.cmd.identify.ctrl.ssvid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sn,
            { "Serial Number (SN)", "nvme.cmd.identify.ctrl.sn",
               FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mn,
            { "Model Number (MN)", "nvme.cmd.identify.ctrl.mn",
               FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fr,
            { "Firmware Revision (FR)", "nvme.cmd.identify.ctrl.fr",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rab,
            { "Recommended Arbitration Burst (RAB)", "nvme.cmd.identify.ctrl.rab",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_rab), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ieee,
            { "IEEE OUI Identifier (IEEE)", "nvme.cmd.identify.ctrl.ieee",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[0],
            { "Controller Multi-Path I/O and Namespace Sharing Capabilities (CMIC)", "nvme.cmd.identify.ctrl.cmic",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[1],
            { "Multiple Ports Support", "nvme.cmd.identify.ctrl.cmic.mp",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[2],
            { "Multiple Controllers Support", "nvme.cmd.identify.ctrl.cmic.mc",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[3],
            { "SRIOV Association", "nvme.cmd.identify.ctrl.cmic.sriov",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[4],
            { "ANA Reporting Support", "nvme.cmd.identify.ctrl.cmic.ana",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[5],
            { "Reserved", "nvme.cmd.identify.ctrl.cmic.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mdts,
            { "Maximum Data Transfer Size (MDTS)", "nvme.cmd.identify.ctrl.mdts",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_mdts), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cntlid,
            { "Controller ID (CNTLID)", "nvme.cmd.identify.ctrl.cntlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ver,
            { "Version (VER)", "nvme.cmd.identify.ctrl.ver",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ver_ter,
            { "Tertiary Version Number (TER)", "nvme.cmd.identify.ctrl.ver.ter",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ver_min,
            { "Minor Version Number (MNR)", "nvme.cmd.identify.ctrl.ver.min",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ver_mjr,
            { "Major Version Number (MJR)", "nvme.cmd.identify.ctrl.ver.mjr",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rtd3r,
            { "RTD3 Resume Latency (RTD3R)", "nvme.cmd.identify.ctrl.rtd3r",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_rtd3), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rtd3e,
            { "RTD3 Entry Latency (RTD3E)", "nvme.cmd.identify.ctrl.rtd3e",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_rtd3), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[0],
            { "Optional Asynchronous Events Supported (OAES)", "nvme.cmd.identify.ctrl.oaes",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[1],
            { "Reserved", "nvme.cmd.identify.ctrl.oaes.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[2],
            { "Namespace Attribute Notices Supported", "nvme.cmd.identify.ctrl.oaes.nan",
               FT_BOOLEAN, 32, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[3],
            { "Firmware Activation Supported", "nvme.cmd.identify.ctrl.oaes.fan",
               FT_BOOLEAN, 32, NULL, 0x200, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[4],
            { "Reserved", "nvme.cmd.identify.ctrl.oaes.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0x400, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[5],
            { "Asymmetric Namespace Access Change Notices Supported", "nvme.cmd.identify.ctrl.oaes.ana",
               FT_BOOLEAN, 32, NULL, 0x800, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[6],
            { "Predictable Latency Event Aggregate Log Change Notices Supported", "nvme.cmd.identify.ctrl.oaes.ple",
               FT_BOOLEAN, 32, NULL, 0x1000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[7],
            { "LBA Status Information Notices Supported", "nvme.cmd.identify.ctrl.oaes.lba",
               FT_BOOLEAN, 32, NULL, 0x2000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[8],
            { "Endurance Group Event Aggregate Log Page Change Notices Supported", "nvme.cmd.identify.ctrl.oaes.ege",
               FT_BOOLEAN, 32, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[9],
            { "Reserved", "nvme.cmd.identify.ctrl.oaes.rsvd2",
               FT_UINT32, BASE_HEX, NULL, 0xffff8000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[0],
            { "Controller Attributes (CTRATT)", "nvme.cmd.identify.ctrl.ctratt",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[1],
            { "128-bit Host Identifier Support", "nvme.cmd.identify.ctrl.ctratt.hi_128",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[2],
            { "Non-Operational Power State Permissive Mode Supported", "nvme.cmd.identify.ctrl.ctratt.nopspm",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[3],
            { "NVM Sets Supported", "nvme.cmd.identify.ctrl.ctratt.nvmset",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[4],
            { "Read Recovery Levels Supported", "nvme.cmd.identify.ctrl.ctratt.rrl",
               FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[5],
            { "Endurance Groups Supported", "nvme.cmd.identify.ctrl.ctratt.eg",
               FT_BOOLEAN, 32, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[6],
            { "Predictable Latency Mode Supported", "nvme.cmd.identify.ctrl.ctratt.plm",
               FT_BOOLEAN, 32, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[7],
            { "Traffic Based Keep Alive Support (TBKAS)", "nvme.cmd.identify.ctrl.ctratt.tbkas",
               FT_BOOLEAN, 32, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[8],
            { "Namespace Granularity", "nvme.cmd.identify.ctrl.ctratt.ng",
               FT_BOOLEAN, 32, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[9],
            { "SQ Associations Support", "nvme.cmd.identify.ctrl.ctratt.sqa",
               FT_BOOLEAN, 32, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[10],
            { "UUID List Support", "nvme.cmd.identify.ctrl.ctratt.uuidl",
               FT_BOOLEAN, 32, NULL, 0x200, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[11],
            { "Reserved", "nvme.cmd.identify.ctrl.ctratt.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffc00, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[0],
            { "Read Recovery Levels Support (RRLS)", "nvme.cmd.identify.ctrl.rrls",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[1],
            { "Read Recovery Level 0 Support", "nvme.cmd.identify.ctrl.rrls.rrls0",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[2],
            { "Read Recovery Level 1 Support", "nvme.cmd.identify.ctrl.rrls.rrls1",
               FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[3],
            { "Read Recovery Level 2 Support", "nvme.cmd.identify.ctrl.rrls.rrls2",
               FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[4],
            { "Read Recovery Level 3 Support", "nvme.cmd.identify.ctrl.rrls.rrls3",
               FT_BOOLEAN, 16, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[5],
            { "Read Recovery Level 4 (Default) Support", "nvme.cmd.identify.ctrl.rrls.rrls4",
               FT_BOOLEAN, 16, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[6],
            { "Read Recovery Level 5 Support", "nvme.cmd.identify.ctrl.rrls.rrls5",
               FT_BOOLEAN, 16, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[7],
            { "Read Recovery Level 6 Support", "nvme.cmd.identify.ctrl.rrls.rrls6",
               FT_BOOLEAN, 16, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[8],
            { "Read Recovery Level 7 Support", "nvme.cmd.identify.ctrl.rrls.rrls7",
               FT_BOOLEAN, 16, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[9],
            { "Read Recovery Level 8 Support", "nvme.cmd.identify.ctrl.rrls.rrls8",
               FT_BOOLEAN, 16, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[10],
            { "Read Recovery Level 9 Support", "nvme.cmd.identify.ctrl.rrls.rrls9",
               FT_BOOLEAN, 16, NULL, 0x200, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[11],
            { "Read Recovery Level 10 Support", "nvme.cmd.identify.ctrl.rrls.rrls10",
               FT_BOOLEAN, 16, NULL, 0x400, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[12],
            { "Read Recovery Level 11 Support", "nvme.cmd.identify.ctrl.rrls.rrls11",
               FT_BOOLEAN, 16, NULL, 0x800, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[13],
            { "Read Recovery Level 12 Support", "nvme.cmd.identify.ctrl.rrls.rrls12",
               FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[14],
            { "Read Recovery Level 13 Support", "nvme.cmd.identify.ctrl.rrls.rrls13",
               FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[15],
            { "Read Recovery Level 14 Support", "nvme.cmd.identify.ctrl.rrls.rrls14",
               FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rrls[16],
            { "Read Recovery Level 15 (Fast Fail) Support", "nvme.cmd.identify.ctrl.rrls.rrls15",
               FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd0,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cntrltype,
            { "Controller Type (CNTRLTYPE)", "nvme.cmd.identify.ctrl.cntrltype",
               FT_UINT8, BASE_HEX, VALS(ctrl_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fguid,
            { "FRU Globally Unique Identifier (FGUID)", "nvme.cmd.identify.ctrl.fguid",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fguid_vse,
            { "Vendor Specific Extension Identifier", "nvme.cmd.identify.ctrl.fguid.vse",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fguid_oui,
            { "Organizationally Unique Identifier", "nvme.cmd.identify.ctrl.fguid.oui",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fguid_ei,
            { "Extension Identifier", "nvme.cmd.identify.ctrl.fguid.ei",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_crdt1,
            { "Command Retry Delay Time 1", "nvme.cmd.identify.ctrl.crdt1",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_ms), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_crdt2,
            { "Command Retry Delay Time 2", "nvme.cmd.identify.ctrl.crdt2",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_ms), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_crdt3,
            { "Command Retry Delay Time 3", "nvme.cmd.identify.ctrl.crdt3",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_ms), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd1,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi,
            { "NVMe Management Interface", "nvme.cmd.identify.ctrl.mi",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_rsvd,
            { "Reserved", "nvme.cmd.identify.ctrl.mi.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_nvmsr[0],
            { "NVM Subsystem Report (NVMSR)", "nvme.cmd.identify.ctrl.mi.nvmsr",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_nvmsr[1],
            { "NVMe Storage Device (NVMESD)", "nvme.cmd.identify.ctrl.mi.nvmsr.nvmesd",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_nvmsr[2],
            { "NVMe Enclosure (NVMEE)", "nvme.cmd.identify.ctrl.mi.nvmsr.nvmee",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_nvmsr[3],
            { "Reserved", "nvme.cmd.identify.ctrl.mi.nvmsr.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_vwci[0],
            { "VPD Write Cycle Information (VWCI)", "nvme.cmd.identify.ctrl.mi.vwci",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_vwci[1],
            { "VPD Write Cycles Remaining (VWCR)", "nvme.cmd.identify.ctrl.mi.vwci.vwcr",
               FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_vwci[2],
            { "VPD Write Cycle Remaining Valid (VWCRV)", "nvme.cmd.identify.ctrl.mi.vwci.vwcrv",
               FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_mec[0],
            { "Management Endpoint Capabilities (MEC)", "nvme.cmd.identify.ctrl.mi.mec",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_mec[1],
            { "SMBus/I2C Port Management Endpoint (SMBUSME)", "nvme.cmd.identify.ctrl.mi.mec.smbusme",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_mec[2],
            { "PCIe Port Management Endpoint (PCIEME)", "nvme.cmd.identify.ctrl.mi.mec.pcieme",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mi_mec[3],
            { "Reserved", "nvme.cmd.identify.ctrl.mi.mec.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[0],
            { "Optional Admin Command Support (OACS)", "nvme.cmd.identify.ctrl.oacs",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[1],
            { "Security Send and Security Receive Support", "nvme.cmd.identify.ctrl.oacs.sec",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[2],
            { "Format NVM Support", "nvme.cmd.identify.ctrl.oacs.fmt",
               FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[3],
            { "Firmware Download and Commit Support", "nvme.cmd.identify.ctrl.oacs.fw",
               FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[4],
            { "Namespace Management Support", "nvme.cmd.identify.ctrl.oacs.nsmgmt",
               FT_BOOLEAN, 16, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[5],
            { "Device Self-Test Support", "nvme.cmd.identify.ctrl.oacs.stst",
               FT_BOOLEAN, 16, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[6],
            { "Directive Send and Directive Receive Support", "nvme.cmd.identify.ctrl.oacs.dtv",
               FT_BOOLEAN, 16, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[7],
            { "NVMe-MI Send and NVMe Receive Support", "nvme.cmd.identify.ctrl.oacs.mi",
               FT_BOOLEAN, 16, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[8],
            { "Virtualization Management Support", "nvme.cmd.identify.ctrl.oacs.vm",
               FT_BOOLEAN, 16, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[9],
            { "Dorbell Buffer Config Support", "nvme.cmd.identify.ctrl.oacs.db",
               FT_BOOLEAN, 16, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[10],
            { "Get LBA Status Support", "nvme.cmd.identify.ctrl.oacs.sec.lba",
               FT_BOOLEAN, 16, NULL, 0x200, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[11],
            { "Reserved", "nvme.cmd.identify.ctrl.oacs.sec.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xfc00, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_acl,
            { "Abort Command Limit (ACL)", "nvme.cmd.identify.ctrl.acl",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_commands), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_aerl,
            { "Asynchronous Event Request Limit (AERL)", "nvme.cmd.identify.ctrl.aerl",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_events), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_frmw[0],
            { "Firmware Updates (FRMW)", "nvme.cmd.identify.ctrl.frmw",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_frmw[1],
            { "First Firmware Slot Read-Only", "nvme.cmd.identify.ctrl.frmw.fro",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_frmw[2],
            { "Number of Firmware Slots", "nvme.cmd.identify.ctrl.frmw.fsn",
               FT_UINT8, BASE_HEX, NULL, 0xe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_frmw[3],
            { "Supports Activation Without Reset", "nvme.cmd.identify.ctrl.frmw.anr",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_frmw[4],
            { "Reserved", "nvme.cmd.identify.ctrl.frmw.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[0],
            { "Log Page Attributes (LPA)", "nvme.cmd.identify.ctrl.lpa",
               FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[1],
            { "Smart Log Page per Namespace Support", "nvme.cmd.identify.ctrl.lpa.smrt",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[2],
            { "Commands Supported and Effects Log Page Support", "nvme.cmd.identify.ctrl.lpa.cmds",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[3],
            { "Extended Data Get Log Page Support", "nvme.cmd.identify.ctrl.lpa.elp",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[4],
            { "Telemetry Log Page and Notices Support", "nvme.cmd.identify.ctrl.lpa.tel",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[5],
            { "Persistent Event Log Support", "nvme.cmd.identify.ctrl.lpa.ple",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[6],
            { "Reserved", "nvme.cmd.identify.ctrl.lpa.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_elpe,
            { "Error Log Page Entries (ELPE)", "nvme.cmd.identify.ctrl.elpe",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_entries), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_npss,
            { "Number of Power States Supported (NPSS)", "nvme.cmd.identify.ctrl.npss",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_states), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_avscc[0],
            { "Admin Vendor Specific Command Configuration (AVSCC)", "nvme.cmd.identify.ctrl.avscc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_avscc[1],
            { "Standard Command Format", "nvme.cmd.identify.ctrl.avscc.std",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_avscc[2],
            { "Reserved", "nvme.cmd.identify.ctrl.avscc.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_apsta[0],
            { "Autonomous Power State Transition Attributes (APSTA)", "nvme.cmd.identify.ctrl.apsta",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_apsta[1],
            { "Autonomous Power State Transitions Supported", "nvme.cmd.identify.ctrl.apsta.aut",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_apsta[2],
            { "Reserved", "nvme.cmd.identify.ctrl.apsta.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_wctemp,
            { "Warning Composite Temperature Threshold (WCTEMP)", "nvme.cmd.identify.ctrl.wctemp",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cctemp,
            { "Critical Composite Temperature Threshold (CCTEMP)", "nvme.cmd.identify.ctrl.cctemp",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mtfa,
            { "Maximum Time for Firmware Activation (MTFA)", "nvme.cmd.identify.ctrl.mtfa",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_ms), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hmpre,
            { "Host Memory Buffer Preferred Size (HMPRE)", "nvme.cmd.identify.ctrl.hmpre",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_hmpre), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hmmin,
            { "Host Memory Buffer Minimum Size (HMMIN)", "nvme.cmd.identify.ctrl.hmmin",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_hmpre), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_tnvmcap,
            { "Total NVM Capacity (TNVMCAP)", "nvme.cmd.identify.ctrl.tnvmcap",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_unvmcap,
            { "Unallocated NVM Capacity (UNVMCAP)", "nvme.cmd.identify.ctrl.unvmcap",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rpmbs[0],
            { "Replay Protected Memory Block Support (RPMBS)", "nvme.cmd.identify.ctrl.rpmbs",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rpmbs[1],
            { "Number of RPMB Units", "nvme.cmd.identify.ctrl.rpmbs.nu",
               FT_UINT32, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rpmbs[2],
            { "Authentication Method", "nvme.cmd.identify.ctrl.rpmbs.au",
               FT_UINT32, BASE_HEX, NULL, 0x38, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rpmbs[3],
            { "Reserved", "nvme.cmd.identify.ctrl.rpmbs.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffc0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rpmbs[4],
            { "Total RPMB Unit Size (128 KiB blocks, zero based)", "nvme.cmd.identify.ctrl.rpmbs.ts",
               FT_UINT32, BASE_HEX, NULL, 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rpmbs[5],
            { "Access Size (512-byte blocks, zero based)", "nvme.cmd.identify.ctrl.rpmbs.as",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
            { &hf_nvme_identify_ctrl_edstt,
            { "Extended Device Self-test Time (EDSTT) (in minutes)", "nvme.cmd.identify.ctrl.edstt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_dsto[0],
            { "Device Self-test Options (DSTO)", "nvme.cmd.identify.ctrl.dsto",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_dsto[1],
            { "Concurrent Self-Tests for Multiple Devices Support", "nvme.cmd.identify.ctrl.dsto.mds",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_dsto[2],
            { "Reserved", "nvme.cmd.identify.ctrl.dsto.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fwug,
            { "Firmware Update Granularity in 4 KiB Units (FWUG)", "nvme.cmd.identify.ctrl.fwug",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_kas,
            { "Keep Alive Support - Timer Value (KAS)", "nvme.cmd.identify.ctrl.kas",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_ms), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hctma[0],
            { "Host Controlled Thermal Management Attributes (HCTMA)", "nvme.cmd.identify.ctrl.hctma",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hctma[1],
            { "Controller Supports Thermal Management", "nvme.cmd.identify.ctrl.hctma.sup",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hctma[2],
            { "Reserved", "nvme.cmd.identify.ctrl.hctma.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mntmt,
            { "Minimum Thermal Management Temperature (MNTMT)", "nvme.cmd.identify.ctrl.mntmt",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_tmt), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mxtmt,
            { "Maximum Thermal Management Temperature (MXTMT)", "nvme.cmd.identify.ctrl.mxtmt",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_tmt), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[0],
            { "Sanitize Capabilities (SANICAP)", "nvme.cmd.identify.ctrl.sanicap",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[1],
            { "Crypto Erase Support (CES)", "nvme.cmd.identify.ctrl.sanicap.ces",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[2],
            { "Block Erase Support (BES)", "nvme.cmd.identify.ctrl.sanicap.bes",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[3],
            { "Overwrite Support (OWS)", "nvme.cmd.identify.ctrl.sanicap.ows",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[4],
            { "Reserved", "nvme.cmd.identify.ctrl.sanicap.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x1ffffff8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[5],
            { "No-Deallocate Inhibited (NDI)", "nvme.cmd.identify.ctrl.sanicap.ndi",
               FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[6],
            { "No-Deallocate Modifies Media After Sanitize (NODMMAS)", "nvme.cmd.identify.ctrl.sanicap.nodmmas",
               FT_UINT32, BASE_HEX, VALS(mmas_type_tbl), 0xc0000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hmmminds,
            { "Host Memory Buffer Minimum Descriptor Entry Size in 4 KiB Units (HMMINDS)", "nvme.cmd.identify.ctrl.hmmminds",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hmmaxd,
            { "Host Memory Maximum Descriptors Entries (HMMAXD)", "nvme.cmd.identify.ctrl.hmmaxd",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nsetidmax,
            { "NVM Set Identifier Maximum (NSETIDMAX)", "nvme.cmd.identify.ctrl.nsetidmax",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_endgidmax,
            { "Endurance Group Identifier Maximum (ENDGIDMAX)", "nvme.cmd.identify.ctrl.endgidmax",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anatt,
            { "ANA Transition Time in Seconds (ANATT)", "nvme.cmd.identify.ctrl.anatt",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[0],
            { "Asymmetric Namespace Access Capabilities (ANACAP)", "nvme.cmd.identify.ctrl.anacap",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[1],
            { "Reports ANA Optimized State", "nvme.cmd.identify.ctrl.anacap.osr",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[2],
            { "Reports ANA Non-Optimized State", "nvme.cmd.identify.ctrl.anacap.nosr",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[3],
            { "Reports Innaccessible State", "nvme.cmd.identify.ctrl.anacap.isr",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[4],
            { "Reports ANA Persistent Loss State", "nvme.cmd.identify.ctrl.anacap.plsr",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[5],
            { "Reports ANA Change Sate", "nvme.cmd.identify.ctrl.anacap.csr",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[6],
            { "Reserved", "nvme.cmd.identify.ctrl.anacap.rsvd",
               FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[7],
            { "ANAGRPID field in the Identify Namespace does not change", "nvme.cmd.identify.ctrl.anacap.panagrpid",
               FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[8],
            { "Supports non-zero value in the ANAGRPID field", "nvme.cmd.identify.ctrl.anacap.nzpanagrpid",
               FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anagrpmax,
            { "ANA Group Identifier Maximum (ANAGRPMAX)", "nvme.cmd.identify.ctrl.anagrpmax",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nanagrpid,
            { "Number of ANA Group Identifiers (NANAGRPID)", "nvme.cmd.identify.ctrl.nanagrpid",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_pels,
            { "Persistent Event Log Size in 64 KiB Units (PELS)", "nvme.cmd.identify.ctrl.pels",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd2,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sqes[0],
            { "Submission Queue Entry Size (SQES)", "nvme.cmd.identify.ctrl.sqes",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sqes[1],
            { "Minimum (required) Size", "nvme.cmd.identify.ctrl.sqes.mins",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_bytes), 0xf, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sqes[2],
            { "Maximum (allowed) Size", "nvme.cmd.identify.ctrl.sqes.maxs",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_bytes), 0xf0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cqes[0],
            { "Completion Queue Entry Size (CQES)", "nvme.cmd.identify.ctrl.cqes",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cqes[1],
            { "Minimum (required) Size", "nvme.cmd.identify.ctrl.cqes.mins",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_bytes), 0xf, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cqes[2],
            { "Maximum (allowed) Size", "nvme.cmd.identify.ctrl.cqes.maxs",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_bytes), 0xf0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_maxcmd,
            { "Maximum Outstanding Commands (MAXCMD)", "nvme.cmd.identify.ctrl.maxcmd",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nn,
            { "Number of Namespaces (NN)", "nvme.cmd.identify.ctrl.nn",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[0],
            { "Optional NVM Command Support (ONCS)", "nvme.cmd.identify.ctrl.oncs",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[1],
            { "Supports Compare Command", "nvme.cmd.identify.ctrl.oncs.ccs",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[2],
            { "Supports Write Uncorrectable Command", "nvme.cmd.identify.ctrl.oncs.wus",
               FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[3],
            { "Supports Dataset Management Command", "nvme.cmd.identify.ctrl.oncs.dsms",
               FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[4],
            { "Support Write Zeroes Command", "nvme.cmd.identify.ctrl.oncs.wzs",
               FT_BOOLEAN, 16, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[5],
            { "Supports non-zero Save Filed in Set/Get Features", "nvme.cmd.identify.ctrl.oncs.nzfs",
               FT_BOOLEAN, 16, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[6],
            { "Supports Reservations", "nvme.cmd.identify.ctrl.oncs.ress",
               FT_BOOLEAN, 16, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[7],
            { "Supports Timestamps", "nvme.cmd.identify.ctrl.oncs.tstmps",
               FT_BOOLEAN, 16, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[8],
            { "Supports Verify Command", "nvme.cmd.identify.ctrl.oncs.vers",
               FT_BOOLEAN, 16, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[9],
            { "Reserved", "nvme.cmd.identify.ctrl.oncs.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fuses[0],
            { "Fused Operation Support (FUSES)", "nvme.cmd.identify.ctrl.fuses",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fuses[1],
            { "Compare and Write Fused Operation Support", "nvme.cmd.identify.ctrl.fuses.cws",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fuses[2],
            { "Reserved", "nvme.cmd.identify.ctrl.fuses.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fna[0],
            { "Format NVM Attributes (FNA)", "nvme.cmd.identify.ctrl.fna",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fna[1],
            { "Format Operation Applies to all Namespaces", "nvme.cmd.identify.ctrl.fna.fall",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fna[2],
            { "Secure Erase Operation Applies to all Namespaces", "nvme.cmd.identify.ctrl.fna.seall",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fna[3],
            { "Cryptographic Erase Supported", "nvme.cmd.identify.ctrl.fna.ces",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fna[4],
            { "Reserved", "nvme.cmd.identify.ctrl.fna.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vwc[0],
            { "Volatile Write Cache (VWC)", "nvme.cmd.identify.ctrl.vwc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vwc[1],
            { "Volatile Write Cache Present", "nvme.cmd.identify.ctrl.vwc.cp",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vwc[2],
            { "Flush Command Behavior", "nvme.cmd.identify.ctrl.vwc.cfb",
               FT_UINT8, BASE_HEX, VALS(fcb_type_tbl), 0x6, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vwc[3],
            { "Reserved", "nvme.cmd.identify.ctrl.vwc.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_awun,
            { "Atomic Write Unit Normal (AWUN)", "nvme.cmd.identify.ctrl.awun",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_lblocks), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_awupf,
            { "Atomic Write Unit Power Fail (AWUPF)", "nvme.cmd.identify.ctrl.awupf",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_lblocks), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvscc[0],
            { "NVM Vendor Specific Command Configuration (NVSCC)", "nvme.cmd.identify.ctrl.nvscc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvscc[1],
            { "Standard Format Used for Vendor Specific Commands", "nvme.cmd.identify.ctrl.nvscc.std",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvscc[2],
            { "Reserved", "nvme.cmd.identify.ctrl.nvscc.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nwpc[0],
            { "Namespace Write Protection Capabilities (NWPC)", "nvme.cmd.identify.ctrl.nwpc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nwpc[1],
            { "No Write Protect and Write Protect namespace write protection states Support", "nvme.cmd.identify.ctrl.nwpc.wpss",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nwpc[2],
            { "Write Protect Until Power Cycle state Support", "nvme.cmd.identify.ctrl.nwpc.wppcs",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nwpc[3],
            { "Permanent Write Protect state Support", "nvme.cmd.identify.ctrl.nwpc.pwpss",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nwpc[4],
            { "Reserved", "nvme.cmd.identify.ctrl.nwpc.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_acwu,
            { "Atomic Compare & Write Unit (ACWU)", "nvme.cmd.identify.ctrl.acwu",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_hmpre), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd3,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[0],
            { "SGL Support (SGLS)", "nvme.cmd.identify.ctrl.sgls",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[1],
            { "SGL Supported", "nvme.cmd.identify.ctrl.sgls.sgls",
               FT_UINT32, BASE_HEX, VALS(sgls_ify_type_tbl), 0x3, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[2],
            { "Supports Keyed SGL Data Block Descriptor", "nvme.cmd.identify.ctrl.sgls.kdbs",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[3],
            { "Reserved", "nvme.cmd.identify.ctrl.sgls.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0xfff8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[4],
            { "Supports SGL Bit Bucket Descriptor", "nvme.cmd.identify.ctrl.sgls.bbd",
               FT_BOOLEAN, 32, NULL, 0x10000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[5],
            { "Supports byte aligned contiguous buffer in MPTR Field", "nvme.cmd.identify.ctrl.sgls.bufmptr",
               FT_BOOLEAN, 32, NULL, 0x20000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[6],
            { "Supports Larger SGL List than Command Requires", "nvme.cmd.identify.ctrl.sgls.lsgl",
               FT_BOOLEAN, 32, NULL, 0x40000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[7],
            { "Supports SGL Segment in MPTR Field", "nvme.cmd.identify.ctrl.sgls.kmptr",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[8],
            { "Supports Address Field as offset in Data Block, Segment and Last Segment SGLs", "nvme.cmd.identify.ctrl.sgls.offs",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[9],
            { "Supports Transport SGL Data Block Descriptor", "nvme.cmd.identify.ctrl.sgls.tdbd",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[10],
            { "Reserved", "nvme.cmd.identify.ctrl.sgls.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xffc00000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mnan,
            { "Maximum Number of Allowed Namespaces (MNAN)", "nvme.cmd.identify.ctrl.mnan",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd4,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd4",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_subnqn,
            { "NVM Subsystem NVMe Qualified Name (SUBNQN)", "nvme.cmd.identify.ctrl.subnqn",
               FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd5,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd5",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof,
            { "NVMeOF Attributes", "nvme.cmd.identify.ctrl.nvmeof",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_ioccsz,
            { "I/O Queue Command Capsule Supported Size (IOCCSZ)", "nvme.cmd.identify.ctrl.nvmeof.ioccsz",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_x16_bytes), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_iorcsz,
            { "I/O Queue Response Capsule Supported Size (IORCSZ)", "nvme.cmd.identify.ctrl.nvmeof.iorcsz",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_x16_bytes), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_icdoff,
            { "In Capsule Data Offset (ICDOFF)", "nvme.cmd.identify.ctrl.nvmeof.icdoff",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_x16_bytes), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_fcatt[0],
            { "Fabrics Controller Attributes (FCATT)", "nvme.cmd.identify.ctrl.nvmeof.fcatt",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_fcatt[1],
            { "Dynamic Controller Model", "nvme.cmd.identify.ctrl.nvmeof.fcatt.dcm",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_fcatt[2],
            { "Reserved", "nvme.cmd.identify.ctrl.nvmeof.fcatt.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_msdbd,
            { "Maximum SGL Data Block Descriptors (MSDBD)", "nvme.cmd.identify.ctrl.nvmeof.msdbd",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_ofcs[0],
            { "Optional Fabric Commands Support (OFCS)", "nvme.cmd.identify.ctrl.nvmeof.ofcs",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_ofcs[1],
            { "Supports Disconnect Command", "nvme.cmd.identify.ctrl.nvmeof.ofcs.dcs",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_ofcs[2],
            { "Reserved", "nvme.cmd.identify.ctrl.nvmeof.ofcs.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_rsvd,
            { "Reserved", "nvme.cmd.identify.ctrl.nvmeof.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psds,
            { "Power State Attributes", "nvme.cmd.identify.ctrl.psds",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd,
            { "Power State 0 Descriptor (PSD0)", "nvme.cmd.identify.ctrl.psds.psd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_mp,
            { "Maximum Power (MP)", "nvme.cmd.identify.ctrl.psds.psd.mp",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd0,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd0",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_mxps,
            { "Max Power Scale (MXPS)", "nvme.cmd.identify.ctrl.psds.psd.mxps",
               FT_BOOLEAN, 8, TFS(&units_watts), 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_nops,
            { "Non-Operational State (NOPS)", "nvme.cmd.identify.ctrl.psds.psd.nops",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd1,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd1",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_enlat,
            { "Entry Latency (ENLAT)", "nvme.cmd.identify.ctrl.psds.psd.enlat",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_exlat,
            { "Exit Latency (EXLAT)", "nvme.cmd.identify.ctrl.psds.psd.exlat",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rrt,
            { "Relative Read Throughput (RRT)", "nvme.cmd.identify.ctrl.psds.psd.rrt",
               FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd2,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd2",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rrl,
            { "Relative Read Latency (RRL)", "nvme.cmd.identify.ctrl.psds.psd.rrl",
               FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd3,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd3",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rwt,
            { "Relative Write Throughput (RWT)", "nvme.cmd.identify.ctrl.psds.psd.rwt",
               FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd4,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd4",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rwl,
            { "Relative Write Latency (RWL)", "nvme.cmd.identify.ctrl.psds.psd.rwl",
               FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd5,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd5",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_idlp,
            { "Idle Power (IDLP)", "nvme.cmd.identify.ctrl.psds.psd.idlp",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd6,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd6",
               FT_UINT8, BASE_HEX, NULL, 0x3f, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_ips,
            { "Idle Power Scale (IPS)", "nvme.cmd.identify.ctrl.psds.psd.ips",
               FT_UINT8, BASE_HEX, VALS(power_scale_tbl), 0xc0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd7,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd7",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_actp,
            { "Active Power (ACTP)", "nvme.cmd.identify.ctrl.psds.psd.actp",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_apw,
            { "Active Power Workload (APW)", "nvme.cmd.identify.ctrl.psds.psd.apw",
               FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd8,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd8",
               FT_UINT8, BASE_HEX, NULL, 0x38, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_aps,
            { "Active Power Scale (APS)", "nvme.cmd.identify.ctrl.psds.psd.aps",
               FT_UINT8, BASE_HEX, VALS(power_scale_tbl), 0xc0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd9,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd9",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vs,
            { "Vendor Specific", "nvme.cmd.identify.ctrl.vs",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },

        /* Identify nslist response */
        { &hf_nvme_identify_nslist_nsid,
            { "Namespace list element", "nvme.cmd.identify.nslist.nsid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* get logpage response */
        /* Identify Response */
        { &hf_nvme_get_logpage_ify_genctr,
            { "Generation Counter (GENCTR)", "nvme.cmd.get_logpage.identify.genctr",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_numrec,
            { "Number of Records (NUMREC)", "nvme.cmd.get_logpage.identify.numrec",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_recfmt,
            { "Record Format (RECFMT)", "nvme.cmd.get_logpage.identify.recfmt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.identify.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd,
            { "Discovery Log Entry", "nvme.cmd.get_logpage.identify.rcrd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_trtype,
            { "Transport Type (TRTYPE)", "nvme.cmd.get_logpage.identify.rcrd.trtype",
               FT_UINT8, BASE_HEX, VALS(trt_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_adrfam,
            { "Address Family (ADRFAM)", "nvme.cmd.get_logpage.identify.rcrd.adrfam",
               FT_UINT8, BASE_HEX, VALS(adrfam_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_subtype,
            { "Subsystem Type (SUBTYPE)", "nvme.cmd.get_logpage.identify.rcrd.subtype",
               FT_UINT8, BASE_HEX, VALS(sub_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[0],
            { "Transport Requirements (TREQ)", "nvme.cmd.get_logpage.identify.rcrd.treq",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[1],
            { "Secure Channel Connection Requirement", "nvme.cmd.get_logpage.identify.rcrd.treq.secch",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[2],
            { "Disable SQ Flow Control Support", "nvme.cmd.get_logpage.identify.rcrd.treq.sqfc",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[3],
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.treq.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_portid,
            { "Port ID (PORTID)", "nvme.cmd.get_logpage.identify.rcrd.portid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_cntlid,
            { "Controller ID (CNTLID)", "nvme.cmd.get_logpage.identify.rcrd.cntlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_asqsz,
            { "Admin Max SQ Size (ASQSZ)", "nvme.cmd.get_logpage.identify.rcrd.asqsz",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_trsvcid,
            { "Transport Service Identifier (TRSVCID)", "nvme.cmd.get_logpage.identify.rcrd.trsvcid",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_subnqn,
            { "NVM Subsystem Qualified Name (SUBNQN)", "nvme.cmd.get_logpage.identify.rcrd.subnqn",
               FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_traddr,
            { "Transport Address (TRADDR)", "nvme.cmd.get_logpage.identify.rcrd.traddr",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas,
            { "Transport Specific Address Subtype (TSAS)", "nvme.cmd.get_logpage.identify.rcrd.tsas",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_rdma_qptype,
            { "RDMA QP Service Type (RDMA_QPTYPE)", "nvme.cmd.get_logpage.identify.rcrd.tsas.rdma_qptype",
               FT_UINT8, BASE_HEX, VALS(qp_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_rdma_prtype,
            { "RDMA Provider Type (RDMA_PRTYPE)", "nvme.cmd.get_logpage.identify.rcrd.tsas.rdma_prtype",
               FT_UINT8, BASE_HEX, VALS(pr_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_rdma_cms,
            { "RDMA Connection Management Service (RDMA_CMS)", "nvme.cmd.get_logpage.identify.rcrd.tsas.rdma_cms",
               FT_UINT8, BASE_HEX, VALS(cms_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_rdma_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.tsas.rdma_rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_rdma_pkey,
            { "RDMA Partition Key (RDMA_PKEY)", "nvme.cmd.get_logpage.identify.rcrd.tsas.rdma_pkey",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_rdma_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.tsas.rdma_rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_tcp_sectype,
            { "Security Type (SECTYPE)", "nvme.cmd.get_logpage.identify.rcrd.tsas.tcp_sectype",
               FT_UINT8, BASE_HEX, VALS(sec_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_tcp_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.tsas.tcp_rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Error Information Response */
        { &hf_nvme_get_logpage_errinf_errcnt,
            { "Error Count", "nvme.cmd.get_logpage.errinf.errcnt",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_sqid,
            { "Submission Queue ID", "nvme.cmd.get_logpage.errinf.sqid",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_cid,
            { "Command ID", "nvme.cmd.get_logpage.errinf.cid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_sf[0],
            { "Status Field", "nvme.cmd.get_logpage.errinf.sf",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_sf[1],
            { "Status Field Value", "nvme.cmd.get_logpage.errinf.sf.val",
               FT_UINT16, BASE_HEX, NULL, 0x7fff, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_sf[2],
            { "Status Field Phase Tag", "nvme.cmd.get_logpage.errinf.sf.ptag",
               FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_pel[0],
            { "Parameter Error Location", "nvme.cmd.get_logpage.errinf.pel",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_pel[1],
            { "Byte in command that contained the error", "nvme.cmd.get_logpage.errinf.pel.bytee",
               FT_UINT16, BASE_DEC, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_pel[2],
            { "Bit in command that contained the error", "nvme.cmd.get_logpage.errinf.pel.bite",
               FT_UINT16, BASE_DEC, NULL, 0x7ff, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_pel[3],
            { "Reserved", "nvme.cmd.get_logpage.errinf.pel.rsvd",
               FT_UINT16, BASE_DEC, NULL, 0xf8ff, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_lba,
            { "LBA", "nvme.cmd.get_logpage.errinf.lba",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_ns,
            { "Namespace ID", "nvme.cmd.get_logpage.errinf.nsid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_vsi,
            { "Namespace ID", "nvme.cmd.get_logpage.errinf.vsi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_trtype,
            { "Namespace ID", "nvme.cmd.get_logpage.errinf.trype",
               FT_UINT8, BASE_HEX, VALS(trt_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.errinf.rsvd0",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_csi,
            { "Command Specific Information", "nvme.cmd.get_logpage.errinf.csi",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_tsi,
            { "Namespace ID", "nvme.cmd.get_logpage.errinf.tsi",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_rsvd1,
            { "Namespace ID", "nvme.cmd.get_logpage.errinf.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Get LogPage SMART response */
        { &hf_nvme_get_logpage_smart_cw[0],
            { "Critical Warning", "nvme.cmd.get_logpage.smart.cw",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cw[1],
            { "Spare Capacity Below Threshold", "nvme.cmd.get_logpage.smart.cw.sc",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cw[2],
            { "Temperature Crossed Threshold", "nvme.cmd.get_logpage.smart.cw.temp",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cw[3],
            { "Reliability Degraded due to Significant Media Errors", "nvme.cmd.get_logpage.smart.cw.sme",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cw[4],
            { "Media Placed in RO State", "nvme.cmd.get_logpage.smart.cw.ro",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cw[5],
            { "Volatile Memory Backup Device Has Failed", "nvme.cmd.get_logpage.smart.cw.bdf",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cw[6],
            { "Persistent Memory Region Placed in RO State", "nvme.cmd.get_logpage.smart.cw.mrro",
               FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cw[7],
            { "Reserved", "nvme.cmd.get_logpage.smart.cw.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ct,
            { "Composite Temperature (degrees K)", "nvme.cmd.get_logpage.smart.ct",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_asc,
            { "Available Spare Capacity (%)", "nvme.cmd.get_logpage.smart.asc",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ast,
            { "Available Spare Capacity Threshold (%)", "nvme.cmd.get_logpage.smart.ast",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_lpu,
            { "Life Age Estimate (%)", "nvme.cmd.get_logpage.smart.lae",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_egcws[0],
            { "Endurance Group Critical Warning Summary", "nvme.cmd.get_logpage.smart.egcws",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_egcws[1],
            { "Spare Capacity of Endurance Group Below Threshold", "nvme.cmd.get_logpage.smart.egcws.sc",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_egcws[2],
            { "Reserved", "nvme.cmd.get_logpage.smart.egcws.rsvd0",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_egcws[3],
            { "Reliability of Endurance Group Degraded due to Media Errors", "nvme.cmd.get_logpage.smart.egcws.me",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_egcws[4],
            { "A Namespace in Endurance Group Placed in RO State", "nvme.cmd.get_logpage.smart.egcws.ro",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_egcws[5],
            { "Reserved", "nvme.cmd.get_logpage.smart.egcws.rsvd1",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.smart.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_dur,
            { "Data Units Read", "nvme.cmd.get_logpage.smart.dur",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_duw,
            { "Data Units Written", "nvme.cmd.get_logpage.smart.duw",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_hrc,
            { "Host Read Commands", "nvme.cmd.get_logpage.smart.hrc",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_hwc,
            { "Host Write Commands", "nvme.cmd.get_logpage.smart.hwc",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cbt,
            { "Controller Busy Time (minutes)", "nvme.cmd.get_logpage.smart.cbt",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_pc,
            { "Power Cycles", "nvme.cmd.get_logpage.smart.pc",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_poh,
            { "Power On Hours", "nvme.cmd.get_logpage.smart.poh",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_mie,
            { "Media Integrity Errors", "nvme.cmd.get_logpage.smart.mie",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_us,
            { "Unsafe Shutdowns", "nvme.cmd.get_logpage.smart.us",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ele,
            { "Number of Error Information Log Entries", "nvme.cmd.get_logpage.smart.ele",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_wctt,
            { "Warning Composite Temperature Time (minutes)", "nvme.cmd.get_logpage.smart.wctt",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cctt,
            { "Critical Composite Temperature Time (minutes)", "nvme.cmd.get_logpage.smart.cctt",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[0],
            { "Temperature Sensors", "nvme.cmd.get_logpage.smart.ts",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[1],
            { "Temperature Sensor 1 (degrees K)", "nvme.cmd.get_logpage.smart.ts.s1",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[2],
            { "Temperature Sensor 2 (degrees K)", "nvme.cmd.get_logpage.smart.ts.s2",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[3],
            { "Temperature Sensor 3 (degrees K)", "nvme.cmd.get_logpage.smart.ts.s3",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[4],
            { "Temperature Sensor 4 (degrees K)", "nvme.cmd.get_logpage.smart.ts.s4",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[5],
            { "Temperature Sensor 5 (degrees K)", "nvme.cmd.get_logpage.smart.ts.s5",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[6],
            { "Temperature Sensor 6 (degrees K)", "nvme.cmd.get_logpage.smart.ts.s6",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[7],
            { "Temperature Sensor 7 (degrees K)", "nvme.cmd.get_logpage.smart.ts.s7",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ts[8],
            { "Temperature Sensor 8 (degrees K)", "nvme.cmd.get_logpage.smart.ts.s8",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_tmt1c,
            { "Thermal Management Temperature 1 Transition Count", "nvme.cmd.get_logpage.smart.tmt1c",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_tmt2c,
            { "Thermal Management Temperature 2 Transition Count", "nvme.cmd.get_logpage.smart.tmt2c",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_tmt1t,
            { "Total Time For Thermal Management Temperature 1 (seconds)", "nvme.cmd.get_logpage.smart.tmt1t",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_tmt2t,
            { "Total Time For Thermal Management Temperature 2 (seconds)", "nvme.cmd.get_logpage.smart.tmt2t",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.smart.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* FW Slot Information Response */
        { &hf_nvme_get_logpage_fw_slot_afi[0],
            { "Active Firmware Info (AFI)", "nvme.cmd.get_logpage.fw_slot.afi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_afi[1],
            { "Active Firmware Slot", "nvme.cmd.get_logpage.fw_slot.afi.afs",
               FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_afi[2],
            { "Reserved", "nvme.cmd.get_logpage.fw_slot.afi.rsvd0",
               FT_UINT8, BASE_HEX, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_afi[3],
            { "Next Reset Firmware Slot", "nvme.cmd.get_logpage.fw_slot.afi.nfs",
               FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_afi[4],
            { "Reserved", "nvme.cmd.get_logpage.fw_slot.afi.rsvd1",
               FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.fw_slot.rsvd0",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs[0],
            { "Firmware Slot Revisions", "nvme.cmd.get_logpage.fw_slot.frs",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs[1],
            { "Firmware Revision for Slot 1", "nvme.cmd.get_logpage.fw_slot.frs.s1",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs[2],
            { "Firmware Revision for Slot 2", "nvme.cmd.get_logpage.fw_slot.frs.s2",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs[3],
            { "Firmware Revision for Slot 3", "nvme.cmd.get_logpage.fw_slot.frs.s3",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs[4],
            { "Firmware Revision for Slot 4", "nvme.cmd.get_logpage.fw_slot.frs.s4",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs[5],
            { "Firmware Revision for Slot 5", "nvme.cmd.get_logpage.fw_slot.frs.s5",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs[6],
            { "Firmware Revision for Slot 6", "nvme.cmd.get_logpage.fw_slot.frs.s6",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs[7],
            { "Firmware Revision for Slot 7", "nvme.cmd.get_logpage.fw_slot.frs.s7",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.fw_slot.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Changed NameSpace List Response */
        { &hf_nvme_get_logpage_changed_nslist,
            { "Changed Namespace", "nvme.cmd.get_logpage.changed_nslist",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* Commands Supported and Effects Response */
        { &hf_nvme_get_logpage_cmd_and_eff_cs,
            { "Command Supported Entry", "nvme.cmd.get_logpage.cmd_and_eff.cs",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[0],
            { "Commands Supported and Effects Data Structure", "nvme.cmd.get_logpage.cmd_and_eff.cseds",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[1],
            { "Command Supported (CSUPP)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csupp",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[2],
            { "Logical Block Content Change (LBCC)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.lbcc",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[3],
            { "Namespace Capability Change (NCC)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.ncc",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[4],
            { "Namespace Inventory Change (NIC)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.nic",
               FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[5],
            { "Controller Capability Change (CCC)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.ccc",
               FT_BOOLEAN, 32, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[6],
            { "Reserved", "nvme.cmd.get_logpage.cmd_and_eff.cseds.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0xffe0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[7],
            { "Command Submission and Execution (CSE)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.cse",
               FT_UINT32, BASE_HEX, VALS(cmd_eff_cse_tbl), 0x70000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[8],
            { "UUID Selection Supported", "nvme.cmd.get_logpage.cmd_and_eff.cseds.uss",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[9],
            { "Reserved", "nvme.cmd.get_logpage.cmd_and_eff.cseds.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xfff00000, NULL, HFILL}
        },
        /* Device Self-Test Response */
                { &hf_nvme_get_logpage_selftest_csto[0],
            { "Current Device Self-Test Operation", "nvme.cmd.get_logpage.selftest.csto",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_csto[1],
            { "Current Self-Test Operation Status", "nvme.cmd.get_logpage.selftest.csto.st",
               FT_UINT8, BASE_HEX, VALS(stest_type_active_tbl), 0xf, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_csto[2],
            { "Reserved", "nvme.cmd.get_logpage.selftest.csto.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_cstc[0],
            { "Current Device Self-Test Completion", "nvme.cmd.get_logpage.selftest.cstc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_cstc[1],
            { "Self-Test Completion Percent", "nvme.cmd.get_logpage.selftest.cstc.pcnt",
               FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_cstc[2],
            { "Reserved", "nvme.cmd.get_logpage.selftest.cstc.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_rsvd,
            { "Self-Test Completion Percent", "nvme.cmd.get_logpage.selftest.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res,
            { "Latest Self-test Result Data Structure", "nvme.cmd.get_logpage.selftest.res",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_status[0],
            { "Device Self-test Status", "nvme.cmd.get_logpage.selftest.res.status",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_status[1],
            { "Device Self-test Result", "nvme.cmd.get_logpage.selftest.res.status.result",
               FT_UINT8, BASE_HEX, VALS(stest_result_tbl), 0xf, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_status[2],
            { "Device Self-test Type", "nvme.cmd.get_logpage.selftest.res.status.type",
               FT_UINT8, BASE_HEX, VALS(stest_type_done_tbl), 0xf0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_sn,
            { "Segment Number", "nvme.cmd.get_logpage.selftest.res.sn",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vdi[0],
            { "Valid Diagnostic Information", "nvme.cmd.get_logpage.selftest.res.vdi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vdi[1],
            { "Namespace Identifier (NSID) Field Valid", "nvme.cmd.get_logpage.selftest.res.vdi.nsid",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vdi[2],
            { "Failing LBA (FLBA) Field Valid", "nvme.cmd.get_logpage.selftest.res.vdi.flba",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vdi[3],
            { "Status Code Type (SCT) Filed Valid", "nvme.cmd.get_logpage.selftest.res.vdi.sct",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vdi[4],
            { "Status Code (SC) Field Valid", "nvme.cmd.get_logpage.selftest.res.vdi.sc",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vdi[5],
            { "Reserved", "nvme.cmd.get_logpage.selftest.res.vdi.rsvd",
               FT_BOOLEAN, 8, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.selftest.res.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_poh,
            { "Power On Hours (POH)", "nvme.cmd.get_logpage.selftest.res.poh",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_nsid,
            { "Namespace Identifier (NSID)", "nvme.cmd.get_logpage.selftest.res.nsid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_flba,
            { "Failing LBA", "nvme.cmd.get_logpage.selftest.res.flba",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_sct[0],
            { "Status Code Type", "nvme.cmd.get_logpage.selftest.res.sct",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_sct[1],
            { "Additional Information", "nvme.cmd.get_logpage.selftest.res.sct.ai",
               FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_sct[2],
            { "Reserved", "nvme.cmd.get_logpage.selftest.res.sct.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_sc,
            { "Status Code", "nvme.cmd.get_logpage.selftest.res.sc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vs,
            { "Vendor Specific", "nvme.cmd.get_logpage.selftest.res.vs",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* Telemetry Log Response */
        { &hf_nvme_get_logpage_telemetry_li,
            { "Log Identifier", "nvme.cmd.get_logpage.telemetry.li",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.telemetry.rsvd0",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_ieee,
            { "IEEE OUI Identifier (IEEE)", "nvme.cmd.get_logpage.telemetry.ieee",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_da1lb,
            { "Telemetry Data Area 1 Last Block", "nvme.cmd.get_logpage.telemetry.da1b",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_da2lb,
            { "Telemetry Data Area 2 Last Block", "nvme.cmd.get_logpage.telemetry.da2b",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_da3lb,
            { "Telemetry Data Area 3 Last Block", "nvme.cmd.get_logpage.telemetry.da3b",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.telemetry.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_da,
            { "Telemetry Data Available", "nvme.cmd.get_logpage.telemetry.da",
               FT_BOOLEAN, 8, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_dgn,
            { "Telemetry Data Generation Number", "nvme.cmd.get_logpage.telemetry.dgn",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_ri,
            { "Reason Identifier", "nvme.cmd.get_logpage.telemetry.ri",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_db,
            { "Telemetry Data Block", "nvme.cmd.get_logpage.telemetry.db",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Endurance Group Response */
        { &hf_nvme_get_logpage_egroup_cw[0],
            { "Critical Warning", "nvme.cmd.get_logpage.egroup.cw",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_cw[1],
            { "Available Spare Capacity Below Threshold", "nvme.cmd.get_logpage.egroup.cw.asc",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_cw[2],
            { "Reserved", "nvme.cmd.get_logpage.egroup.cw.rsvd0",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_cw[3],
            { "Reliability of Endurance Group Degraded due to Media Errors", "nvme.cmd.get_logpage.egroup.cw.rd",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_cw[4],
            { "All Namespaces in Endurance Group Placed in RO State", "nvme.cmd.get_logpage.egroup.cw.ro",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_cw[5],
            { "Reserved", "nvme.cmd.get_logpage.egroup.cw.rsvd1",
               FT_BOOLEAN, 8, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.egroup.rsvd0",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_as,
            { "Available Spare Capacity %", "nvme.cmd.get_logpage.egroup.as",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_ast,
            { "Available Spare Threshold %", "nvme.cmd.get_logpage.egroup.ast",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_pu,
            { "Life Age (Percentage Used) %", "nvme.cmd.get_logpage.egroup.pu",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.egroup.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_ee,
            { "Endurance Estimate (GB that may be written)", "nvme.cmd.get_logpage.egroup.ee",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_dur,
            { "Data Units Read (GB)", "nvme.cmd.get_logpage.egroup.dur",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_duw,
            { "Data Units Written (GB)", "nvme.cmd.get_logpage.egroup.duw",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_muw,
            { "Media Units Written (GB)", "nvme.cmd.get_logpage.egroup.muw",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_hrc,
            { "Host Read Commands", "nvme.cmd.get_logpage.egroup.hrc",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_hwc,
            { "Host Write Commands", "nvme.cmd.get_logpage.egroup.hwc",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_mdie,
            { "Media and Data Integrity Errors", "nvme.cmd.get_logpage.egroup.mdie",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_ele,
            { "Media and Data Integrity Errors", "nvme.cmd.get_logpage.egroup.ele",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_rsvd2,
            { "Reserved", "nvme.cmd.get_logpage.egroup.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Predictable Latency NVMSet Response */
        { &hf_nvme_get_logpage_pred_lat_status[0],
            { "Predictable Latency NVM Set Status", "nvme.cmd.get_logpage.pred_lat.status",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_status[1],
            { "Enabled Window Setting", "nvme.cmd.get_logpage.pred_lat.status.ws",
               FT_UINT8, BASE_HEX, VALS(plat_status_tbl), 0x7, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_status[2],
            { "Reserved", "nvme.cmd.get_logpage.pred_lat.status.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.pred_lat.rsvd0",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_etype[0],
            { "Event Type", "nvme.cmd.get_logpage.pred_lat.etype",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_etype[1],
            { "DTWIN Reads Warning", "nvme.cmd.get_logpage.pred_lat.etype.rw",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_etype[2],
            { "DTWIN Writes Warning", "nvme.cmd.get_logpage.pred_lat.etype.ww",
               FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_etype[3],
            { "DTWIN Time Warning", "nvme.cmd.get_logpage.pred_lat.etype.tw",
               FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_etype[4],
            { "Reserved", "nvme.cmd.get_logpage.pred_lat.etype.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x3ff8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_etype[5],
            { "Autonomous transition from DTWIN to NDWIN due to typical or maximum value exceeded", "nvme.cmd.get_logpage.pred_lat.etype.atve",
               FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_etype[6],
            { "Autonomous transition from DTWIN to NDWIN due to Deterministic Excursion", "nvme.cmd.get_logpage.pred_lat.etype.atde",
               FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.pred_lat.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_dtwin_rt,
            { "DTWIN Reads Typical (4 KiB blocks)", "nvme.cmd.get_logpage.pred_lat.dtwin_rt",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_dtwin_wt,
            { "DTWIN Writes Typical (optimal block size)", "nvme.cmd.get_logpage.pred_lat.dtwin_wt",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_dtwin_tm,
            { "DTWIN Time Maximum (ms)", "nvme.cmd.get_logpage.pred_lat.dtwin_tm",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_ndwin_tmh,
            { "NDWIN Time Minimum High (ms)", "nvme.cmd.get_logpage.pred_lat.ndwin_tmh",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_ndwin_tml,
            { "NDWIN Time Minimum Low (ms)", "nvme.cmd.get_logpage.pred_lat.ndwin_tml",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_rsvd2,
            { "Reserved", "nvme.cmd.get_logpage.pred_lat.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_dtwin_re,
            { "DTWIN Reads Estimate (4 KiB blocks)", "nvme.cmd.get_logpage.pred_lat.dtwin_re",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_dtwin_we,
            { "DTWIN Writes Estimate (optimal block size)", "nvme.cmd.get_logpage.pred_lat.dtwin_we",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_dtwin_te,
            { "DTWIN Time Estimate (ms)", "nvme.cmd.get_logpage.pred_lat.dtwin_te",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_rsvd3,
            { "Reserved", "nvme.cmd.get_logpage.pred_lat.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Predictable Latency NVMSet Aggregate Response */
        { &hf_nvme_get_logpage_pred_lat_aggreg_ne,
            { "Number of Entries", "nvme.cmd.get_logpage.pred_lat_aggreg.ne",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_pred_lat_aggreg_nset,
            { "NVM Set with Pending Predictable Latency Event", "nvme.cmd.get_logpage.pred_lat_aggreg.nset",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* ANA Response */
        { &hf_nvme_get_logpage_ana_chcnt,
            { "Change Count", "nvme.cmd.get_logpage.ana.chcnt",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_ngd,
            { "Number of ANA Group Descriptors", "nvme.cmd.get_logpage.ana.ngd",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.ana.rsvd",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp,
            { "ANA Group Descriptor", "nvme.cmd.get_logpage.ana.grp",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_id,
            { "ANA Group ID", "nvme.cmd.get_logpage.ana.grp.id",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_nns,
            { "Number of NSID Values", "nvme.cmd.get_logpage.ana.grp.nns",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_chcnt,
            { "Change Count", "nvme.cmd.get_logpage.ana.grp.chcnt",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_anas[0],
            { "ANA State", "nvme.cmd.get_logpage.ana.grp.anas",
               FT_UINT8, BASE_HEX, NULL, 0xf, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_anas[1],
            { "Asymmetric Namespace Access State", "nvme.cmd.get_logpage.ana.grp.anas.state",
               FT_UINT8, BASE_HEX, VALS(ana_state_tbl), 0xf, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_anas[2],
            { "Reserved", "nvme.cmd.get_logpage.ana.grp.anas.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.ana.grp.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_nsid,
            { "Namespace Identifier", "nvme.cmd.get_logpage.ana.grp.nsid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* LBA Status Information Response */
        { &hf_nvme_get_logpage_lba_status_lslplen,
            { "LBA Status Log Page Length (LSLPLEN)", "nvme.cmd.get_logpage.lba_status.lslplen",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nlslne,
            { "Number of LBA Status Log Namespace Elements (NLSLNE)", "nvme.cmd.get_logpage.lba_status.nlslne",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_estulb,
            { "Estimate of Unrecoverable Logical Blocks (ESTULB)", "nvme.cmd.get_logpage.lba_status.estulb",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.lba_status.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_lsgc,
            { "LBA Status Generation Counter (LSGC)", "nvme.cmd.get_logpage.lba_status.lsgc",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel,
            { "LBA Status Log Namespace Element List", "nvme.cmd.get_logpage.lba_status.nel",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne,
            { "LBA Status Log Namespace Element", "nvme.cmd.get_logpage.lba_status.nel.ne",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne_neid,
            { "Namespace Element Identifier (NEID)", "nvme.cmd.get_logpage.lba_status.nel.ne.neid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne_nlrd,
            { "Number of LBA Range Descriptors (NLRD)", "nvme.cmd.get_logpage.lba_status.nel.ne.nlrd",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne_ratype,
            { "Number of LBA Range Descriptors (NLRD)", "nvme.cmd.get_logpage.lba_status.nel.ne.ratype",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.lba_status.nel.ne.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne_rd,
            { "LBA Range Descriptor", "nvme.cmd.get_logpage.lba_status.nel.ne.rd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne_rd_rslba,
            { "LBA Range Descriptor", "nvme.cmd.get_logpage.lba_status.nel.ne.rd.rslba",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne_rd_rnlb,
            { "Range Number of Logical Blocks (RNLB)", "nvme.cmd.get_logpage.lba_status.nel.ne.rd.rnlb",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_lba_status_nel_ne_rd_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.lba_status.nel.ne.rd.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* Get LogPage Endurance Group Aggregate Response */
        { &hf_nvme_get_logpage_egroup_aggreg_ne,
            { "Number of Entries", "nvme.cmd.get_logpage.egroup_agreg.ne",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_aggreg_eg,
            { "Endurance Group", "nvme.cmd.get_logpage.egroup_agreg.eg",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* Get LogPage Reservation Notification Response */
        { &hf_nvme_get_logpage_reserv_notif_lpc,
            { "Log Page Count", "nvme.cmd.get_logpage.reserv_notif.lpc",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_reserv_notif_lpt,
            { "Reservation Notification Log Page Type", "nvme.cmd.get_logpage.reserv_notif.lpt",
               FT_UINT8, BASE_HEX, VALS(rnlpt_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_reserv_notif_nalp,
            { "Number of Available Log Pages", "nvme.cmd.get_logpage.reserv_notif.nalp",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_reserv_notif_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.reserv_notif.rsvd0",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_reserv_notif_nsid,
            { "Namespace ID", "nvme.cmd.get_logpage.reserv_notif.nsid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_reserv_notif_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.reserv_notif.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Get LogPage Sanitize Response */
        { &hf_nvme_get_logpage_sanitize_sprog,
            { "Sanitize Progress (SPROG)", "nvme.cmd.get_logpage.sanitize.sprog",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[0],
            { "Sanitize Status (SSTAT)", "nvme.cmd.get_logpage.sanitize.sstat",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[1],
            { "Status of the most resent Sanitize Operation", "nvme.cmd.get_logpage.sanitize.sstat.mrst",
               FT_UINT16, BASE_HEX, VALS(san_mrst_tbl), 0x7, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[2],
            { "Number of Completed Overwrite Passes", "nvme.cmd.get_logpage.sanitize.sstat.cop",
               FT_UINT16, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[3],
            { "Global Data Erased", "nvme.cmd.get_logpage.sanitize.sstat.gde",
               FT_BOOLEAN, 16, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[4],
            { "Reserved", "nvme.cmd.get_logpage.sanitize.sstat.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xfe00, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_scdw10,
            { "Sanitize Command Dword 10 Information (SCDW10)", "nvme.cmd.get_logpage.sanitize.scdw10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_eto,
            { "Estimated Time For Overwrite (seconds)", "nvme.cmd.get_logpage.sanitize.eto",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etbe,
            { "Estimated Time For Block Erase (seconds)", "nvme.cmd.get_logpage.sanitize.etbe",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etce,
            { "Estimated Time For Crypto Erase (seconds)", "nvme.cmd.get_logpage.sanitize.etce",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etond,
            { "Estimated Time For Overwrite (seconds) with No-Deallocate", "nvme.cmd.get_logpage.sanitize.etond",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etbend,
            { "Estimated Time For Block Erase (seconds) with No-Deallocate", "nvme.cmd.get_logpage.sanitize.etbend",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etcend,
            { "Estimated Time For Crypto Erase (seconds) with No-Deallocate", "nvme.cmd.get_logpage.sanitize.etcend",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.sanitize.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* NVMe Response fields */
        { &hf_nvme_cqe_dword0,
            { "DWORD0", "nvme.cqe.dword0",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_dword0_sf_err,
            { "Set Features Error Specific Code", "nvme.cqe.dword0.set_features.err",
               FT_UINT32, BASE_HEX, VALS(nvme_cqe_sc_sf_err_dword0_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_aev_dword0[0],
            { "DWORD0", "nvme.cqe.dword0.aev",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_aev_dword0[1],
            { "Asynchronous Event Type", "nvme.cqe.dword0.aev.aet",
               FT_UINT32, BASE_HEX, VALS(nvme_cqe_aev_aet_dword0_tbl), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cqe_aev_dword0[2],
            { "Reserved", "nvme.cqe.dword0.aev.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_cqe_aev_dword0[3],
            { "Asynchronous Event Information", "nvme.cqe.dword0.aev.aei",
               FT_UINT32, BASE_HEX, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvme_cqe_aev_dword0[4],
            { "Log Page Identifier", "nvme.cqe.dword0.aev.lpi",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_logpage_lid), 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_aev_dword0[5],
            { "Reserved", "nvme.cqe.dword0.aev.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        /* Set Feature Responses */
        { &hf_nvme_cqe_dword0_sf_nq[0],
            { "DWORD0: Set Feature Number of Queues Result", "nvme.cqe.dword0.set_features.nq",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_dword0_sf_nq[1],
            { "Number of IO Submission Queues Allocated", "nvme.cqe.dword0.set_features.nq.nsqa",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_queues), 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_dword0_sf_nq[2],
            { "Number of IO Completion Queues Allocated", "nvme.cqe.dword0.set_features.ncqa",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_queues), 0xffff0000, NULL, HFILL}
        },
        /* Get Feature Responses */
        { &hf_nvme_cqe_get_features_dword0_arb[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.arb",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[1],
            { "Arbitration Burst", "nvme.cqe.dword0.get_features.arb.ab",
               FT_UINT32, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[3],
            { "Low Priority Weight", "nvme.cqe.dword0.get_features.arb.lpw",
               FT_UINT32, BASE_HEX, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[4],
            { "Medium Priority Weight", "nvme.cqe.dword0.get_features.arb.mpw",
               FT_UINT32, BASE_HEX, NULL, 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[5],
            { "High Priority Weight", "nvme.cqe.dword0.get_features.arb.hpw",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_pm[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.pm",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_pm[1],
            { "Power State", "nvme.cqe.dword0.get_features.pm.ps",
               FT_UINT32, BASE_HEX, NULL, 0x1f, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_pm[2],
            { "Work Hint", "nvme.cqe.dword0.get_features.pm.wh",
               FT_UINT32, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_pm[3],
            { "Work Hint", "nvme.cqe.dword0.get_features.pm.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbart[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.lbart",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbart[1],
            { "DWORD0", "nvme.cqe.dword0.get_features.lbart.lbarn",
               FT_UINT32, BASE_HEX, NULL, 0x3f, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbart[2],
            { "DWORD0", "nvme.cqe.dword0.get_features.lbart.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffffc0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_tt[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.tt",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_tt[1],
            { "Temperature Threshold", "nvme.cqe.dword0.get_features.tt.tmpth",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_tt[2],
            { "Threshold Temperature Select", "nvme.cqe.dword0.get_features.tt.tmpsel",
               FT_UINT32, BASE_HEX, VALS(sf_tmpsel_table), 0xf0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_tt[3],
            { "Threshold Type Select", "nvme.cqe.dword0.get_features.tt.thpsel",
               FT_UINT32, BASE_HEX, VALS(sf_thpsel_table), 0x300000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_tt[4],
            { "Reserved", "nvme.cqe.dword0.get_features.tt.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xc00000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_erec[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.erec",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_erec[1],
            { "Time Limited Error Recovery (100 ms units)", "nvme.cqe.dword0.get_features.erec.tler",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_erec[2],
            { "Deallocated or Unwritten Logical Block Error Enable", "nvme.cqe.dword0.get_features.erec.dulbe",
               FT_BOOLEAN, 32, NULL, 0x10000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_erec[3],
            { "Reserved", "nvme.cqe.dword0.get_features.erec.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfe0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_vwce[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.vwce",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_vwce[1],
            { "Volatile Write Cache Enable", "nvme.cqe.dword0.get_features.vwce.wce",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_vwce[2],
            { "Volatile Write Cache Enable", "nvme.cqe.dword0.get_features.vwce.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nq[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.nq",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nq[1],
            { "Number of IO Submission Queues Allocated", "nvme.cqe.dword0.get_features.nq.nsqa",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_queues), 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nq[2],
            { "Number of IO Completion Queues Allocated", "nvme.cqe.dword0.get_features.nq.ncqa",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_queues), 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqc[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.irqc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqc[1],
            { "Aggregation Threshold", "nvme.cqe.dword0.get_features.irqc.thr",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqc[2],
            { "Aggregation Time (100 us units)", "nvme.cqe.dword0.get_features.irqc.time",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqv[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.irqv",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqv[1],
            { "IRQ Vector", "nvme.cqe.dword0.get_features.irqv.iv",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqv[2],
            { "Coalescing Disable", "nvme.cqe.dword0.get_features.irqv.cd",
               FT_BOOLEAN, 32, NULL, 0x1ffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqv[3],
            { "Reserved", "nvme.cqe.dword0.get_features.irqv.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffe0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_wan[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.wan",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_wan[1],
            { "Disable Normal", "nvme.cqe.dword0.get_features.wan.dn",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_wan[2],
            { "Reserved", "nvme.cqe.dword0.get_features.wan.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.aec",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[1],
            { "SMART and Health Critical Warnings Bitmask", "nvme.cqe.dword0.get_features.aec.smart",
               FT_UINT32, BASE_HEX, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[2],
            { "Namespace Attribute Notices", "nvme.cqe.dword0.get_features.aec.ns",
               FT_BOOLEAN, 32, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[3],
            { "Firmware Activation Notices", "nvme.cqe.dword0.get_features.aec.fwa",
               FT_BOOLEAN, 32, NULL, 0x200, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[4],
            { "Telemetry Log Notices", "nvme.cqe.dword0.get_features.aec.tel",
               FT_BOOLEAN, 32, NULL, 0x400, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[5],
            { "ANA Change Notices", "nvme.cqe.dword0.get_features.aec.ana",
               FT_BOOLEAN, 32, NULL, 0x800, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[6],
            { "Predictable Latency Event Aggregate Log Change Notices", "nvme.cqe.dword0.get_features.aec.plat",
               FT_BOOLEAN, 32, NULL, 0x1000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[7],
            { "LBA Status Information Notices", "nvme.cqe.dword0.get_features.aec.lba",
               FT_BOOLEAN, 32, NULL, 0x2000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[8],
            { "Endurance Group Event Aggregate Log Change Notices", "nvme.cqe.dword0.get_features.aec.eg",
               FT_BOOLEAN, 32, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[9],
            { "Reserved", "nvme.cqe.dword0.get_features.aec.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x7fff8000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[10],
            { "Discovery Log Page Change Notification", "nvme.cqe.dword0.get_features.aec.disc",
               FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_apst[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.apst",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_apst[1],
            { "Autonomous Power State Transition Enable", "nvme.cqe.dword0.get_features.apst.apste",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_apst[2],
            { "Reserved", "nvme.cqe.dword0.get_features.apst.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_kat[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.kat",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_kat[1],
            { "Keep Alive Timeout", "nvme.cqe.dword0.get_features.kat.kato",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hctm[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.hctm",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hctm[1],
            { "Thermal Management Temperature 2 (K)", "nvme.cqe.dword0.get_features.hctm.tmt2",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hctm[2],
            { "Thermal Management Temperature 1 (K)", "nvme.cqe.dword0.get_features.hctm.tmt1",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nops[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.nops",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nops[1],
            { "Non-Operational Power State Permissive Mode Enable", "nvme.cqe.dword0.get_features.nops.noppme",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nops[2],
            { "Reserved", "nvme.cqe.dword0.get_features.nops.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rrl[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.rrl",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rrl[1],
            { "Read Recovery Level", "nvme.cqe.dword0.get_features.rrl.rrl",
               FT_UINT32, BASE_HEX, NULL, 0xf, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rrl[2],
            { "Reserved", "nvme.cqe.dword0.get_features.rrl.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_plmc[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.plmc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_plmc[1],
            { "Predictable Latency Enable", "nvme.cqe.dword0.get_features.plmc.ple",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_plmc[2],
            { "Reserved", "nvme.cqe.dword0.get_features.plmc.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_plmw[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.plmw",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_plmw[1],
            { "NVM Set Identifier", "nvme.cqe.dword0.get_features.plmw.nvmsetid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_plmw[2],
            { "Reserved", "nvme.cqe.dword0.get_features.plmw.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbasi[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.lbasi",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbasi[1],
            { "LBA Status Information Report Interval (100 ms)", "nvme.cqe.dword0.get_features.lbasi.lsiri",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbasi[2],
            { "LBA Status Information Poll Interval (100 ms)", "nvme.cqe.dword0.get_features.lbasi.lsipi",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_san[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.san",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_san[1],
            { "No-Deallocate Response Mode", "nvme.cqe.dword0.get_features.san.nodrm",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_san[2],
            { "Reserved", "nvme.cqe.dword0.get_features.san.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_eg[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.eg",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_eg[1],
            { "Endurance Group Identifier", "nvme.cqe.dword0.get_features.eg.endgid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_eg[2],
            { "Endurance Group Critical Warnings Bitmask", "nvme.cqe.dword0.get_features.eg.egcw",
               FT_UINT32, BASE_HEX, NULL, 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_eg[3],
            { "Reserved", "nvme.cqe.dword0.get_features.eg.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_swp[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.swp",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_swp[1],
            { "Pre-boot Software Load Count", "nvme.cqe.dword0.get_features.swp.pbslc",
               FT_UINT32, BASE_HEX, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_swp[2],
            { "Reserved", "nvme.cqe.dword0.get_features.swp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffff00, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hid[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.hid",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hid[1],
            { "Enable Extended Host Identifier", "nvme.cqe.dword0.get_features.hid.exhid",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hid[2],
            { "Reserved", "nvme.cqe.dword0.get_features.hid.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvn[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.rsrvn",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvn[1],
            { "Reserved", "nvme.cqe.dword0.get_features.rsrvn.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvn[2],
            { "Mask Registration Preempted Notification" , "nvme.cqe.dword0.get_features.rsrvn.regpre",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvn[3],
            { "Mask Reservation Released Notification", "nvme.cqe.dword0.get_features.rsrvn.resrel",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvn[4],
            { "Mask Reservation Preempted Notification", "nvme.cqe.dword0.get_features.rsrvn.resrpe",
               FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvn[5],
            { "Reserved", "nvme.cqe.dword0.get_features.rsrvn.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xfffff0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvp[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.rsrvp",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvp[1],
            { "Persist Through Power Loss", "nvme.cqe.dword0.get_features.rsrvp.ptpl",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_rsrvp[2],
            { "Reserved", "nvme.cqe.dword0.get_features.rsrvp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nswp[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.nswp",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nswp[1],
            { "DWORD0", "nvme.cqe.dword0.get_features.nswp.wps",
               FT_UINT32, BASE_HEX, VALS(sf_wps), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nswp[2],
            { "DWORD0", "nvme.cqe.dword0.get_features.nswp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff8, NULL, HFILL}
        },
        /* Generic Response Fields */
        { &hf_nvme_cqe_dword1,
            { "DWORD1", "nvme.cqe.dword1",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_sqhd,
            { "SQ Head Pointer", "nvme.cqe.sqhd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_sqid,
            { "SQ Identifier", "nvme.cqe.sqid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_cid,
            { "Command Identifier", "nvme.cqe.cid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[0],
            { "Status Field", "nvme.cqe.status",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[1],
            { "Phase Tag", "nvme.cqe.status.p",
               FT_UINT16, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_status_rsvd,
            { "Reserved", "nvme.cqe.status.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[2],
            { "Status Code", "nvme.cqe.status.sc",
               FT_UINT16, BASE_HEX, NULL, 0x1fe, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[3],
            { "Status Code Type", "nvme.cqe.status.sct",
               FT_UINT16, BASE_HEX, VALS(nvme_cqe_sct_tbl), 0xE00, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[4],
            { "Command Retry Delay", "nvme.cqe.status.crd",
               FT_UINT16, BASE_HEX, NULL, 0x3000, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[5],
            { "More Infornation in Log Page", "nvme.cqe.status.m",
               FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[6],
            { "Do not Retry", "nvme.cqe.status.dnr",
               FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_cmd_pkt,
            { "Cmd in", "nvme.cmd_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cmd for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_req,
            { "DATA Transfer Request", "nvme.data_req",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer request for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[0],
            { "DATA Transfer 0", "nvme.data.tr0",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 0 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[1],
            { "DATA Transfer 1", "nvme.data_tr1",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 1 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[2],
            { "DATA Transfer 2", "nvme.data_tr2",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 2 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[3],
            { "DATA Transfer 3", "nvme.data_tr3",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 3 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[4],
            { "DATA Transfer 4", "nvme.data_tr4",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 4 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[5],
            { "DATA Transfer 5", "nvme.data_tr5",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 5 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[6],
            { "DATA Transfer 6", "nvme.data_tr6",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 6 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[7],
            { "DATA Transfer 7", "nvme.data_tr7",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 7 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[8],
            { "DATA Transfer 8", "nvme.data_tr8",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 8 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[9],
            { "DATA Transfer 9", "nvme.data_tr9",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 9 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[10],
            { "DATA Transfer 10", "nvme.data_tr10",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 10 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[11],
            { "DATA Transfer 11", "nvme.data_tr11",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 11 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[12],
            { "DATA Transfer 12", "nvme.data_tr12",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 12 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[13],
            { "DATA Transfer 13", "nvme.data_tr13",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 13 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[14],
            { "DATA Transfer 14", "nvme.data_tr14",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 14 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_data_tr[15],
            { "DATA Transfer 15", "nvme.data_tr15",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer 15 for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_cqe_pkt,
            { "Cqe in", "nvme.cqe_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cqe for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_cmd_latency,
            { "Cmd Latency", "nvme.cmd_latency",
              FT_DOUBLE, BASE_NONE, NULL, 0x0,
              "The time between the command and completion, in usec", HFILL }
        },
        { &hf_nvme_gen_data,
            { "Nvme Data", "nvme.data",
              FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
        },
    };
    static gint *ett[] = {
        &ett_data,
    };

    proto_nvme = proto_register_protocol("NVM Express", "nvme", "nvme");

    proto_register_field_array(proto_nvme, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
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
