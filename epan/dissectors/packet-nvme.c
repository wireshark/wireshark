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

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>

#include <wsutil/array.h>
#include "packet-nvme.h"

void proto_register_nvme(void);

static int proto_nvme;

/* Dissector table for Security Send/Receive payloads, keyed on the Security
 * Protocol (SECP); see struct nvme_security_info in packet-nvme.h. */
static dissector_table_t nvme_security_secp_table;
static dissector_table_t nvme_security_send_failed_table;


/* NVMeOF fields */
/* NVMe Fabric Cmd */
static int hf_nvmeof_cmd;
static int hf_nvmeof_cmd_opc;
static int hf_nvmeof_cmd_rsvd;
static int hf_nvmeof_cmd_cid;
static int hf_nvmeof_cmd_fctype;
static int hf_nvmeof_cmd_connect_rsvd1;
static int hf_nvmeof_cmd_connect_sgl1;
static int hf_nvmeof_cmd_connect_recfmt;
static int hf_nvmeof_cmd_connect_qid;
static int hf_nvmeof_cmd_connect_sqsize;
static int hf_nvmeof_cmd_connect_cattr[5];
static int hf_nvmeof_cmd_connect_rsvd2;
static int hf_nvmeof_cmd_connect_kato;
static int hf_nvmeof_cmd_connect_rsvd3;
static int hf_nvmeof_cmd_connect_data_hostid;
static int hf_nvmeof_cmd_connect_data_cntlid;
static int hf_nvmeof_cmd_connect_data_rsvd0;
static int hf_nvmeof_cmd_connect_data_subnqn;
static int hf_nvmeof_cmd_connect_data_hostnqn;
static int hf_nvmeof_cmd_connect_data_rsvd1;

static int hf_nvmeof_cmd_auth_rsdv1;
static int hf_nvmeof_cmd_auth_sgl1;
static int hf_nvmeof_cmd_auth_rsdv2;
static int hf_nvmeof_cmd_auth_spsp0;
static int hf_nvmeof_cmd_auth_spsp1;
static int hf_nvmeof_cmd_auth_secp;
static int hf_nvmeof_cmd_auth_al;
static int hf_nvmeof_cmd_auth_rsdv3;

static int hf_nvmeof_cmd_disconnect_rsvd0;
static int hf_nvmeof_cmd_disconnect_recfmt;
static int hf_nvmeof_cmd_disconnect_rsvd1;

static int hf_nvmeof_cmd_prop_get_set_rsvd0;
static int hf_nvmeof_cmd_prop_get_set_attrib[3];
static int hf_nvmeof_cmd_prop_get_set_rsvd1;
static int hf_nvmeof_cmd_prop_get_set_offset;
static int hf_nvmeof_cmd_prop_get_rsvd2;

static int hf_nvmeof_cmd_prop_set_rsvd;

static int hf_nvmeof_cmd_generic_rsvd1;
static int hf_nvmeof_cmd_generic_field;

static int hf_nvmeof_prop_get_set_data;
static int hf_nvmeof_prop_get_set_data_4B;
static int hf_nvmeof_prop_get_set_data_4B_rsvd;
static int hf_nvmeof_prop_get_set_data_8B;
static int hf_nvmeof_prop_get_set_cc[10];
static int hf_nvmeof_prop_get_set_csts[7];
static int hf_nvmeof_prop_get_set_nssr[2];
static int hf_nvmeof_prop_get_vs[4];
static int hf_nvmeof_prop_get_ccap[17];


/* NVMe Fabric CQE */
static int hf_nvmeof_cqe;
static int hf_nvmeof_cqe_sts;

static int hf_nvmeof_cqe_connect_cntlid;
static int hf_nvmeof_cqe_connect_authreq;
static int hf_nvmeof_cqe_connect_rsvd;
static int hf_nvmeof_cqe_prop_set_rsvd;

/* tracking Cmd and its respective CQE */
int hf_nvmeof_cmd_pkt;
int hf_nvmeof_data_req;
static int hf_nvmeof_data_tr[NVME_CMD_MAX_TRS];
static int hf_nvmeof_cqe_pkt;
static int hf_nvmeof_cmd_latency;

static const range_string fctype_tbl[] = {
    { NVME_FCTYPE_PROP_SET,      NVME_FCTYPE_PROP_SET,      "Property Set" },
    { NVME_FCTYPE_CONNECT,       NVME_FCTYPE_CONNECT,       "Connect" },
    { NVME_FCTYPE_PROP_GET,      NVME_FCTYPE_PROP_GET,      "Property Get" },
    { NVME_FCTYPE_AUTH_SEND,     NVME_FCTYPE_AUTH_SEND,     "Authentication Send" },
    { NVME_FCTYPE_AUTH_RECV,     NVME_FCTYPE_AUTH_RECV,     "Authentication Recv" },
    { NVME_FCTYPE_DISCONNECT,    NVME_FCTYPE_DISCONNECT,    "Disconnect" },
    { 0xC0, 0xFF,                                           "Vendor Specific" },
    { 0, 0, NULL}
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
    { 0x64,     "NVM Subsystem Shutdown"},
    { 0x68,     "Controller Ready Timeouts"},
    { 0, NULL}
};

static const value_string attr_size_tbl[] = {
    { 0,       "4 bytes"},
    { 1,       "8 bytes"},
    { 0, NULL}
};

static const value_string css_table[] = {
     { 0x0, "NVM Command Set"},
     { 0x6, "All Supported I/O Command Sets"},
     { 0x7, "Admin Command Set Only"},
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

/* Shared with the NVMe-MI Controller Health Data Structure CSTS.SHST decode. */
const value_string shst_table[] = {
    { 0x0, "No Shutdown"},
    { 0x1, "Shutdown in Process"},
    { 0x2, "Shutdown Complete"},
    { 0x3, "Reserved"},
    { 0x0, NULL}
};

/* NVMe Cmd fields */
static int hf_nvme_cmd_opc;
static int hf_nvme_cmd_rsvd;
static int hf_nvme_cmd_cid;
static int hf_nvme_cmd_fuse_op;
static int hf_nvme_cmd_psdt;
static int hf_nvme_cmd_nsid;
static int hf_nvme_cmd_dword2;
static int hf_nvme_cmd_dword3;
static int hf_nvme_cmd_mptr;
static int hf_nvme_cmd_sgl;
static int hf_nvme_cmd_sgl_desc_type;
static int hf_nvme_cmd_sgl_desc_sub_type;
static int hf_nvme_cmd_sgl_desc_addr;
static int hf_nvme_cmd_sgl_desc_addr_rsvd;
static int hf_nvme_cmd_sgl_desc_len;
static int hf_nvme_cmd_sgl_desc_rsvd;
static int hf_nvme_cmd_sgl_desc_key;
static int hf_nvme_cmd_dword10;
static int hf_nvme_cmd_dword11;
static int hf_nvme_cmd_dword12;
static int hf_nvme_cmd_dword13;
static int hf_nvme_cmd_dword14;
static int hf_nvme_cmd_dword15;
static int hf_nvme_cmd_slba;
static int hf_nvme_cmd_nlb;
static int hf_nvme_cmd_rsvd2;
static int hf_nvme_cmd_prinfo;
static int hf_nvme_cmd_prinfo_prchk_lbrtag;
static int hf_nvme_cmd_prinfo_prchk_apptag;
static int hf_nvme_cmd_prinfo_prchk_guard;
static int hf_nvme_cmd_prinfo_pract;
static int hf_nvme_cmd_fua;
static int hf_nvme_cmd_lr;
static int hf_nvme_cmd_elbtl;
static int hf_nvme_cmd_elbat;
static int hf_nvme_cmd_elbatm;
static int hf_nvme_cmd_lbtl;
static int hf_nvme_cmd_lbat;
static int hf_nvme_cmd_lbatm;
static int hf_nvme_cmd_dsm;
static int hf_nvme_cmd_dsm_access_freq;
static int hf_nvme_cmd_dsm_access_lat;
static int hf_nvme_cmd_dsm_seq_req;
static int hf_nvme_cmd_dsm_incompressible;
static int hf_nvme_cmd_rsvd3;
static int hf_nvme_identify_dword10[4];
static int hf_nvme_identify_dword11[4];
static int hf_nvme_identify_dword14[3];

static int hf_nvme_get_logpage_dword10[5];
/* LSP is LID specific; these two are only defined for LID 19h. */
static int hf_nvme_get_logpage_dword10_lsp_act;
static int hf_nvme_get_logpage_dword10_lsp_mqual;
static int hf_nvme_lsp_cthid;
static int hf_nvme_lsp_mcda;
static int hf_nvme_lsp_rgo;
static int hf_nvme_lsp_pel_act;
static int hf_nvme_lsp_scope;
static int hf_nvme_lsp_contents;
static int hf_nvme_lsp_elpf;
static int hf_nvme_lsp_bpid;
static int hf_nvme_lsp_rao;
static int hf_nvme_lsp_rmc;
static int hf_nvme_lsp_events;
static int hf_nvme_lsp_extdlpe;
static int hf_nvme_lsp_pleo;
static int hf_nvme_lsp_allsube;
static int hf_nvme_lsp_allhoste;
static int hf_nvme_lsp_nlt;
static int hf_nvme_lsp_reserved;
static int hf_nvme_lidsp_mcdas;
static int hf_nvme_lidsp_ecrh;
static int hf_nvme_lidsp_extdlpes;
static int hf_nvme_lidsp_pleos;
static int hf_nvme_lidsp_allsubes;
static int hf_nvme_lidsp_allhostes;
static int hf_nvme_admin_ns_mgmt_sel;
static int hf_nvme_admin_ns_csi;
static int hf_nvme_admin_ns_attach_sel;
static int hf_nvme_admin_vm_act;
static int hf_nvme_admin_vm_rt;
static int hf_nvme_admin_vm_cntlid;
static int hf_nvme_admin_vm_nr;
static int hf_nvme_admin_cap_oper;
static int hf_nvme_admin_cap_elid;
static int hf_nvme_admin_cap_capacity;
static int hf_nvme_admin_export_ra;
static int hf_nvme_admin_export_recv_sel;
static int hf_nvme_admin_export_subsys_sel;
static int hf_nvme_admin_export_ns_sel;
static int hf_nvme_admin_export_port_sel;
static int hf_nvme_admin_lba_slba;
static int hf_nvme_admin_lba_mndw;
static int hf_nvme_admin_lba_atype;
static int hf_nvme_admin_lba_rl;
static int hf_nvme_admin_sanns_act;
static int hf_nvme_admin_sanns_ause;
static int hf_nvme_admin_sanns_emvs;
static int hf_nvme_admin_sanns_preq;
static int hf_nvme_admin_sanns_rsvd[2];
static int hf_nvme_id_lbstm;
static int hf_nvme_id_pic[6];
static int hf_nvme_id_pifa[3];
static int hf_nvme_id_elbaf[5];
static int hf_nvme_id_npdgl;
static int hf_nvme_id_nprg;
static int hf_nvme_id_npra;
static int hf_nvme_id_nors;
static int hf_nvme_id_npdal;
static int hf_nvme_id_lbapss;
static int hf_nvme_id_tlbaag;
static int hf_nvme_id_nvm_ctrl[8];
static int hf_nvme_id_nvm_ctrl_kpiocap[4];
static int hf_nvme_id_nvm_ctrl_aocs[3];
static int hf_nvme_id_nvm_ctrl_ver[4];
static int hf_nvme_id_nvm_ctrl_rla[4];
static int hf_nvme_id_nvm_ctrl_slmc;
static int hf_nvme_id_domain_num;
static int hf_nvme_id_domain_id;
static int hf_nvme_id_domain_capacity[3];
static int hf_nvme_id_eg_num;
static int hf_nvme_id_eg_id;
static int hf_nvme_id_iocsc[7];
static int hf_nvme_id_genctr;
static int hf_nvme_id_nument;
static int hf_nvme_id_unsnqn;
static int hf_nvme_id_unsid;
static int hf_nvme_id_ucntlid;
static int hf_nvme_id_uidx;
static int hf_nvme_id_portid;
static int hf_nvme_id_trtype;
static int hf_nvme_id_adrfam;
static int hf_nvme_id_traddr;
static int hf_nvme_id_tsas;
static int hf_nvme_id_treq[6];
static int hf_nvme_id_state_nv;
static int hf_nvme_id_state_nuuid;
static int hf_nvme_id_state_version;
static int hf_nvme_id_state_uuid;
static int hf_nvme_reach_chngc;
static int hf_nvme_reach_count;
static int hf_nvme_reach_id;
static int hf_nvme_reach_nids;
static int hf_nvme_reach_desc_chngc;
static int hf_nvme_reach_rac;
static int hf_nvme_reach_member;
static int hf_nvme_hostdisc_genctr;
static int hf_nvme_hostdisc_numrec;
static int hf_nvme_hostdisc_recfmt;
static int hf_nvme_hostdisc_flags;
static int hf_nvme_hostdisc_length;
static int hf_nvme_hostdisc_nqn;
static int hf_nvme_hostdisc_trtype;
static int hf_nvme_hostdisc_adrfam;
static int hf_nvme_hostdisc_ncc;
static int hf_nvme_hostdisc_tel;
static int hf_nvme_hostdisc_numexat;
static int hf_nvme_feat_attri;
static int hf_nvme_feat_rvspa;
static int hf_nvme_feat_cdqid;
static int hf_nvme_feat_etpt;
static int hf_nvme_feat_hp;
static int hf_nvme_feat_tpt;
static int hf_nvme_feat_fdpcidx;
static int hf_nvme_feat_fdpe;
static int hf_nvme_feat_fdpee;
static int hf_nvme_feat_hsize;
static int hf_nvme_feat_hmdlal;
static int hf_nvme_feat_hmdlau;
static int hf_nvme_feat_hmdlec;
static int hf_nvme_feat_ehm;
static int hf_nvme_feat_hmnare;
static int hf_nvme_feat_hmnar;
static int hf_nvme_feat_scs;
static int hf_nvme_feat_perid;
static int hf_nvme_feat_perfs;
static int hf_nvme_feat_chps;
static int hf_nvme_feat_ppsc;
static int hf_nvme_feat_pmdss;
static int hf_nvme_feat_ldpe;
static int hf_nvme_feat_ldp_rsvd;
static int hf_nvme_cqe_cdp_ldps;
static int hf_nvme_cqe_cdp_rsvd;
static int hf_nvme_feat_plv;
static int hf_nvme_feat_pls;
static int hf_nvme_feat_ptv;
static int hf_nvme_feat_pts;
static int hf_nvme_feat_pmts;
static int hf_nvme_feat_ept;
static int hf_nvme_feat_pm_act;
static int hf_nvme_feat_pm_type;
static int hf_nvme_feat_pm_smt;
static int hf_nvme_feat_pm_actsp;
static int hf_nvme_feat_pm_smtr;
static int hf_nvme_feat_pm_pmgn;
static int hf_nvme_feat_pm_pme;
static int hf_nvme_feat_vt_uvt;
static int hf_nvme_feat_vt_ovt;
static int hf_nvme_feat_vt_evt;
static int hf_nvme_feat_vt_vsens;
static int hf_nvme_feat_vt_rsvd;
static int hf_nvme_feat_vm_act;
static int hf_nvme_feat_vm_rsvd;
static int hf_nvme_feat_svm_lvolta[4];
static int hf_nvme_feat_svm_svmt;
static int hf_nvme_feat_svm_lvolt[5];
static int hf_nvme_feat_svm_rsvd;
static int hf_nvme_feat_rl_tgt;
static int hf_nvme_feat_rl_tid;
static int hf_nvme_feat_rl_rsvd;
static int hf_nvme_feat_rl_rlc[4];
static int hf_nvme_feat_rl_rsvd0;
static int hf_nvme_feat_rl_bwsf;
static int hf_nvme_feat_rl_tbwv;
static int hf_nvme_feat_rl_wbwv;
static int hf_nvme_feat_rl_tiops;
static int hf_nvme_feat_rl_wiops;
static int hf_nvme_feat_rl_riopsr;
static int hf_nvme_feat_rl_wiopsr;
static int hf_nvme_feat_rl_rbwr;
static int hf_nvme_feat_rl_wbwr;
static int hf_nvme_feat_rl_rsvd1;
static int hf_nvme_feat_rl_vs;
static int hf_nvme_feat_gdhm;
static int hf_nvme_feat_noet;
static int hf_nvme_feat_fdpet;
static int hf_nvme_feat_fdpe_attr;
static int hf_nvme_feat_nsal;
static int hf_nvme_feat_emca;
static int hf_nvme_feat_hmaa;
static int hf_nvme_feat_hostid;
static int hf_nvme_feat_hostid_rsvd;
static int hf_nvme_feat_security_set[6];
static int hf_nvme_feat_security_status[6];
static int hf_nvme_feat_security_supported[6];
static int hf_nvme_feat_r4karl;
static int hf_nvme_feat_attrtyp;
static int hf_nvme_feat_msvspa;
static int hf_nvme_feat_usvspa;
static int hf_nvme_feat_paid;
static int hf_nvme_get_logpage_numd;
static int hf_nvme_get_logpage_dword11[3];
static int hf_nvme_get_logpage_lpo;
static int hf_nvme_get_logpage_dword14[5];
static int hf_nvme_get_logpage_cs_name;
static int hf_nvme_set_features_dword10[4];
static int hf_nvme_set_features_dword14[3];

/* Admin opcodes whose CDW10-15 decode is shared with the NVMe-MI Admin
 * dissector (the request layout is a standard SQE from offset 40 onward). */
static int hf_nvme_format_nvm_dword10[8];
static int hf_nvme_fw_commit_dword10[5];
static int hf_nvme_fw_download_numd;
static int hf_nvme_fw_download_ofst;
static int hf_nvme_self_test_dword10[3];
static int hf_nvme_self_test_dstp;
static int hf_nvme_lockdown_dword10[8];
static int hf_nvme_lockdown_dword14[4];
static int hf_nvme_sanitize_dword10[9];
static int hf_nvme_sanitize_ovrpat;
static int hf_nvme_security_dword10[5];
static int hf_nvme_security_send_dword11_tl;
static int hf_nvme_security_spsp;
static int hf_nvme_security_recv_dword11_al;
static int hf_nvme_security_data;
static int hf_nvme_security_info;
static int hf_nvme_security_info_rsvd;
static int hf_nvme_security_info_list_len;
static int hf_nvme_security_info_protocol;
static int hf_nvme_security_info_cert_len;
static int hf_nvme_security_info_cert_data;
static int hf_nvme_security_info_compliance_len;
static int hf_nvme_security_info_compliance_desc;
static int hf_nvme_security_info_residue;
static int hf_nvme_cmd_set_features_dword11_arb[6];
static int hf_nvme_cmd_set_features_dword11_pm[5];
static int hf_nvme_cmd_set_features_dword11_lbart[3];
static int hf_nvme_cmd_set_features_dword11_tt[6];
static int hf_nvme_cmd_get_features_dword11_tt_tmpsel;
static int hf_nvme_cmd_set_features_dword11_erec[4];
static int hf_nvme_cmd_set_features_dword11_vwce[3];
static int hf_nvme_cmd_set_features_dword11_nq[3];
static int hf_nvme_cmd_set_features_dword11_irqc[4];
static int hf_nvme_cmd_set_features_dword11_irqv[4];
static int hf_nvme_cmd_set_features_dword11_wan[3];
static int hf_nvme_cmd_set_features_dword11_aec[23];
static int hf_nvme_cmd_set_features_dword11_apst[3];
static int hf_nvme_cmd_set_features_dword11_kat[2];
static int hf_nvme_cmd_set_features_dword11_hctm[3];
static int hf_nvme_cmd_set_features_dword11_nops[3];
static int hf_nvme_cmd_set_features_dword11_rrl[3];
static int hf_nvme_cmd_set_features_dword12_rrl[3];
static int hf_nvme_cmd_set_features_dword11_plmc[3];
static int hf_nvme_cmd_set_features_dword12_plmc[3];
static int hf_nvme_cmd_set_features_dword11_plmw[3];
static int hf_nvme_cmd_set_features_dword12_plmw[3];
static int hf_nvme_cmd_set_features_dword11_lbasi[3];
static int hf_nvme_cmd_set_features_dword11_san[3];
static int hf_nvme_cmd_set_features_dword11_eg[4];
static int hf_nvme_cmd_set_features_dword11_swp[3];
static int hf_nvme_cmd_set_features_dword11_hid[3];
static int hf_nvme_cmd_set_features_dword11_rsrvn[6];
static int hf_nvme_cmd_set_features_dword11_rsrvp[3];
static int hf_nvme_cmd_set_features_dword11_nswp[3];
static int hf_nvme_cmd_set_features_dword11_hmd[3];
static int hf_nvme_cmd_set_features_dword11_hmb[6];
static int hf_nvme_cmd_set_features_dword11_iocsp[3];
static int hf_nvme_cmd_set_features_dword11_spinup[3];
static int hf_nvme_cmd_set_features_dword11_plsc[3];
static int hf_nvme_cmd_set_features_dword11_fdp[3];
static int hf_nvme_cmd_set_features_dword11_fdpe[4];
static int hf_nvme_cmd_set_features_dword11_bpwpc[4];
static int hf_nvme_set_features_tr_lbart;
static int hf_nvme_set_features_tr_lbart_type;
static int hf_nvme_set_features_tr_lbart_attr[4];
static int hf_nvme_set_features_tr_lbart_rsvd0;
static int hf_nvme_set_features_tr_lbart_slba;
static int hf_nvme_set_features_tr_lbart_nlb;
static int hf_nvme_set_features_tr_lbart_guid;
static int hf_nvme_set_features_tr_lbart_rsvd1;
static int hf_nvme_set_features_tr_apst[5];
static int hf_nvme_set_features_tr_tst[3];
static int hf_nvme_get_features_tr_tst[6];
static int hf_nvme_set_features_tr_plmc;
static int hf_nvme_set_features_tr_plmc_ee[7];
static int hf_nvme_set_features_tr_plmc_rsvd0;
static int hf_nvme_set_features_tr_plmc_dtwinrt;
static int hf_nvme_set_features_tr_plmc_dtwinwt;
static int hf_nvme_set_features_tr_plmc_dtwintt;
static int hf_nvme_set_features_tr_plmc_rsvd1;
static int hf_nvme_set_features_tr_hbs;
static int hf_nvme_set_features_tr_hbs_acre;
static int hf_nvme_set_features_tr_hbs_etdas;
static int hf_nvme_set_features_tr_hbs_lbafee;
static int hf_nvme_set_features_tr_hbs_hdisns;
static int hf_nvme_set_features_tr_hbs_cdfe[6];
static int hf_nvme_set_features_tr_hbs_rsvd;
static int hf_nvme_set_features_tr_hmd;
static int hf_nvme_set_features_tr_hmd_nmed;
static int hf_nvme_set_features_tr_hmd_rsvd;
static int hf_nvme_set_features_tr_hmd_med;
static int hf_nvme_set_features_tr_hmd_med_et;
static int hf_nvme_set_features_tr_hmd_med_er;
static int hf_nvme_set_features_tr_hmd_med_elen;
static int hf_nvme_set_features_tr_hmd_med_eval;
static int hf_nvme_get_features_dword10[4];
static int hf_nvme_get_features_dword14[3];
static int hf_nvme_cmd_get_features_dword11_rrl[3];
static int hf_nvme_cmd_get_features_dword11_plmc[3];
static int hf_nvme_cmd_get_features_dword11_plmw[3];
static int hf_nvme_identify_ns_nsze;
static int hf_nvme_identify_ns_ncap;
static int hf_nvme_identify_ns_nuse;
static int hf_nvme_identify_ns_nsfeat[8];
static int hf_nvme_identify_ns_nlbaf;
static int hf_nvme_identify_ns_flbas[5];
static int hf_nvme_identify_ns_mc[4];
static int hf_nvme_identify_ns_dpc[7];
static int hf_nvme_identify_ns_dps[4];
static int hf_nvme_identify_ns_nmic[4];
static int hf_nvme_identify_ns_rescap[9];
static int hf_nvme_identify_ns_fpi[3];
static int hf_nvme_identify_ns_dlfeat[5];
static int hf_nvme_identify_ns_nawun;
static int hf_nvme_identify_ns_nawupf;
static int hf_nvme_identify_ns_nacwu;
static int hf_nvme_identify_ns_nabsn;
static int hf_nvme_identify_ns_nabo;
static int hf_nvme_identify_ns_nabspf;
static int hf_nvme_identify_ns_noiob;
static int hf_nvme_identify_ns_nvmcap;
static int hf_nvme_identify_ns_npwg;
static int hf_nvme_identify_ns_npwa;
static int hf_nvme_identify_ns_npdg;
static int hf_nvme_identify_ns_npda;
static int hf_nvme_identify_ns_nows;
static int hf_nvme_identify_ns_mssrl;
static int hf_nvme_identify_ns_mcl;
static int hf_nvme_identify_ns_msrc;
static int hf_nvme_identify_ns_kpios[4];
static int hf_nvme_identify_ns_nulbaf;
static int hf_nvme_identify_ns_rsvd0;
static int hf_nvme_identify_ns_kpiodaag;
static int hf_nvme_identify_ns_rsvd1;
static int hf_nvme_identify_ns_anagrpid;
static int hf_nvme_identify_ns_rsvd2;
static int hf_nvme_identify_ns_nsattr[3];
static int hf_nvme_identify_ns_nvmsetid;
static int hf_nvme_identify_ns_endgid;
static int hf_nvme_identify_ns_nguid;
static int hf_nvme_identify_ns_eui64;
static int hf_nvme_identify_ns_lbafs;
static int hf_nvme_identify_ns_lbaf;
static int hf_nvme_identify_ns_vs;
/* CNS 08h: I/O Command Set Independent Identify Namespace (Base 2.3 Fig 335) */
static int hf_nvme_identify_cs_ind_ns_nsfeat[6];
static int hf_nvme_identify_cs_ind_ns_nmic[4];
static int hf_nvme_identify_cs_ind_ns_rescap[9];
static int hf_nvme_identify_cs_ind_ns_fpi[3];
static int hf_nvme_identify_cs_ind_ns_anagrpid;
static int hf_nvme_identify_cs_ind_ns_nsattr[3];
static int hf_nvme_identify_cs_ind_ns_rsvd0;
static int hf_nvme_identify_cs_ind_ns_nvmsetid;
static int hf_nvme_identify_cs_ind_ns_endgid;
static int hf_nvme_identify_cs_ind_ns_nstat[4];
static int hf_nvme_identify_cs_ind_ns_kpios[4];
static int hf_nvme_identify_cs_ind_ns_maxkt;
static int hf_nvme_identify_cs_ind_ns_rsvd1;
static int hf_nvme_identify_cs_ind_ns_rgrpid;
static int hf_nvme_identify_cs_ind_ns_rsvd2;
static int hf_nvme_identify_ctrl_vid;
static int hf_nvme_identify_ctrl_ssvid;
static int hf_nvme_identify_ctrl_sn;
static int hf_nvme_identify_ctrl_mn;
static int hf_nvme_identify_ctrl_fr;
static int hf_nvme_identify_ctrl_rab;
static int hf_nvme_identify_ctrl_ieee;
static int hf_nvme_identify_ctrl_cmic[6];
static int hf_nvme_window_partial;
static int hf_nvme_identify_ctrl_mdts;
static int hf_nvme_identify_ctrl_cntlid;
static int hf_nvme_identify_ctrl_ver;
static int hf_nvme_identify_ctrl_ver_min;
static int hf_nvme_identify_ctrl_ver_mjr;
static int hf_nvme_identify_ctrl_ver_ter;
static int hf_nvme_identify_ctrl_rtd3r;
static int hf_nvme_identify_ctrl_rtd3e;
static int hf_nvme_identify_ctrl_oaes[21];
static int hf_nvme_identify_ctrl_ctratt[26];
static int hf_nvme_identify_ctrl_rrls[17];
static int hf_nvme_identify_ctrl_bpcap[4];
static int hf_nvme_identify_ctrl_chsi[3];
static int hf_nvme_identify_ctrl_nssl;
static int hf_nvme_identify_ctrl_rsvd6; /* bytes 109:108 */
static int hf_nvme_identify_ctrl_plsi[4];
static int hf_nvme_identify_ctrl_cntrltype;
static int hf_nvme_identify_ctrl_fguid;
static int hf_nvme_identify_ctrl_fguid_vse;
static int hf_nvme_identify_ctrl_fguid_oui;
static int hf_nvme_identify_ctrl_fguid_ei;
static int hf_nvme_identify_ctrl_crdt1;
static int hf_nvme_identify_ctrl_crdt2;
static int hf_nvme_identify_ctrl_crdt3;
static int hf_nvme_identify_ctrl_crcap[4];
static int hf_nvme_identify_ctrl_ciu;
static int hf_nvme_identify_ctrl_cirn;
static int hf_nvme_identify_ctrl_rsvd1; /* bytes 239:144 */
static int hf_nvme_identify_ctrl_mi;
static int hf_nvme_identify_ctrl_mi_rsvd;
static int hf_nvme_identify_ctrl_mi_nvmsr[4];
static int hf_nvme_identify_ctrl_mi_vwci[3];
static int hf_nvme_identify_ctrl_mi_mec[4];
static int hf_nvme_identify_ctrl_oacs[16];
static int hf_nvme_identify_ctrl_acl;
static int hf_nvme_identify_ctrl_aerl;
static int hf_nvme_identify_ctrl_frmw[6];
static int hf_nvme_identify_ctrl_lpa[9];
static int hf_nvme_identify_ctrl_elpe;
static int hf_nvme_identify_ctrl_npss;
static int hf_nvme_identify_ctrl_avscc[3];
static int hf_nvme_identify_ctrl_apsta[3];
static int hf_nvme_identify_ctrl_wctemp;
static int hf_nvme_identify_ctrl_cctemp;
static int hf_nvme_identify_ctrl_mtfa;
static int hf_nvme_identify_ctrl_hmpre;
static int hf_nvme_identify_ctrl_hmmin;
static int hf_nvme_identify_ctrl_tnvmcap;
static int  hf_nvme_identify_ctrl_unvmcap;
static int hf_nvme_identify_ctrl_rpmbs[6];
static int hf_nvme_identify_ctrl_edstt;
static int hf_nvme_identify_ctrl_dsto[4];
static int hf_nvme_identify_ctrl_fwug;
static int hf_nvme_identify_ctrl_kas;
static int hf_nvme_identify_ctrl_hctma[3];
static int hf_nvme_identify_ctrl_mntmt;
static int hf_nvme_identify_ctrl_mxtmt;
static int hf_nvme_identify_ctrl_sanicap[10];
static int hf_nvme_identify_ctrl_hmminds;
static int hf_nvme_identify_ctrl_hmmaxd;
static int hf_nvme_identify_ctrl_nsetidmax;
static int hf_nvme_identify_ctrl_endgidmax;
static int hf_nvme_identify_ctrl_anatt;
static int hf_nvme_identify_ctrl_anacap[9];
static int hf_nvme_identify_ctrl_anagrpmax;
static int hf_nvme_identify_ctrl_nanagrpid;
static int hf_nvme_identify_ctrl_pels;
static int hf_nvme_identify_ctrl_did;
static int hf_nvme_identify_ctrl_kpioc[4];
static int hf_nvme_identify_ctrl_rsvd2; /* byte 359 */
static int hf_nvme_identify_ctrl_mptfawr;
static int hf_nvme_identify_ctrl_rmdca[5];
static int hf_nvme_identify_ctrl_rsvd7; /* bytes 367:363 */
static int hf_nvme_identify_ctrl_megcap;
static int hf_nvme_identify_ctrl_tmpthha[3];
static int hf_nvme_identify_ctrl_mupa[3];
static int hf_nvme_identify_ctrl_cqt;
static int hf_nvme_identify_ctrl_cdpa[3];
static int hf_nvme_identify_ctrl_mup;
static int hf_nvme_identify_ctrl_ipmsr[3];
static int hf_nvme_identify_ctrl_msmt;
static int hf_nvme_identify_ctrl_mnens;
static int hf_nvme_identify_ctrl_mnecpens;
static int hf_nvme_identify_ctrl_mensnn;
static int hf_nvme_identify_ctrl_ensa[4];
static int hf_nvme_identify_ctrl_endsfs[4];
static int hf_nvme_identify_ctrl_vsen1[6];
static int hf_nvme_identify_ctrl_vsen2[6];
static int hf_nvme_identify_ctrl_vsen3[6];
static int hf_nvme_identify_ctrl_vsen4[6];
static int hf_nvme_identify_ctrl_msvmt;
static int hf_nvme_identify_ctrl_rsvd8; /* bytes 511:424 */
static int hf_nvme_identify_ctrl_sqes[3];
static int hf_nvme_identify_ctrl_cqes[3];
static int hf_nvme_identify_ctrl_maxcmd;
static int hf_nvme_identify_ctrl_nn;
static int hf_nvme_identify_ctrl_oncs[15];
static int hf_nvme_identify_ctrl_fuses[3];
static int hf_nvme_identify_ctrl_fna[6];
static int hf_nvme_identify_ctrl_vwc[4];
static int hf_nvme_identify_ctrl_awun;
static int hf_nvme_identify_ctrl_awupf;
static int hf_nvme_identify_ctrl_nvscc[3];
static int hf_nvme_identify_ctrl_nwpc[5];
static int hf_nvme_identify_ctrl_acwu;
static int hf_nvme_identify_ctrl_cdfs[7];
static int hf_nvme_identify_ctrl_sgls[12];
static int hf_nvme_identify_ctrl_mnan;
static int hf_nvme_identify_ctrl_maxdna;
static int hf_nvme_identify_ctrl_maxcna;
static int hf_nvme_identify_ctrl_oaqd;
static int hf_nvme_identify_ctrl_rhiri;
static int hf_nvme_identify_ctrl_hirt;
static int hf_nvme_identify_ctrl_cmmrtd;
static int hf_nvme_identify_ctrl_nmmrtd;
static int hf_nvme_identify_ctrl_minmrtg;
static int hf_nvme_identify_ctrl_maxmrtg;
static int hf_nvme_identify_ctrl_trattr[5];
static int hf_nvme_identify_ctrl_rsvd4; /* byte 577 */
static int hf_nvme_identify_ctrl_mcudmq;
static int hf_nvme_identify_ctrl_mnsudmq;
static int hf_nvme_identify_ctrl_mcmr;
static int hf_nvme_identify_ctrl_nmcmr;
static int hf_nvme_identify_ctrl_mcdqpc;
static int hf_nvme_identify_ctrl_rsvd9; /* bytes 767:588 */
static int hf_nvme_identify_ctrl_subnqn;
static int hf_nvme_identify_ctrl_rsvd5;
static int hf_nvme_identify_ctrl_nvmeof;
static int hf_nvme_identify_ctrl_nvmeof_ioccsz;
static int hf_nvme_identify_ctrl_nvmeof_iorcsz;
static int hf_nvme_identify_ctrl_nvmeof_icdoff;
static int hf_nvme_identify_ctrl_nvmeof_fcatt[4];
static int hf_nvme_identify_ctrl_nvmeof_msdbd;
static int hf_nvme_identify_ctrl_nvmeof_ofcs[3];
static int hf_nvme_identify_ctrl_nvmeof_dctype;
static int hf_nvme_identify_ctrl_nvmeof_ccrl;
static int hf_nvme_identify_ctrl_nvmeof_rsvd; /* bytes 2047:1808 */
static int hf_nvme_identify_ctrl_psds;
static int hf_nvme_identify_ctrl_psd;
static int hf_nvme_identify_ctrl_psd_mp;
static int hf_nvme_identify_ctrl_psd_rsvd0;
static int hf_nvme_identify_ctrl_psd_mxps;
static int hf_nvme_identify_ctrl_psd_nops;
static int hf_nvme_identify_ctrl_psd_rsvd1;
static int hf_nvme_identify_ctrl_psd_enlat;
static int hf_nvme_identify_ctrl_psd_exlat;
static int hf_nvme_identify_ctrl_psd_rrt;
static int hf_nvme_identify_ctrl_psd_rsvd2;
static int hf_nvme_identify_ctrl_psd_rrl;
static int hf_nvme_identify_ctrl_psd_rsvd3;
static int hf_nvme_identify_ctrl_psd_rwt;
static int hf_nvme_identify_ctrl_psd_rsvd4;
static int hf_nvme_identify_ctrl_psd_rwl;
static int hf_nvme_identify_ctrl_psd_rsvd5;
static int hf_nvme_identify_ctrl_psd_idlp;
static int hf_nvme_identify_ctrl_psd_rsvd6;
static int hf_nvme_identify_ctrl_psd_ips;
static int hf_nvme_identify_ctrl_psd_rsvd7;
static int hf_nvme_identify_ctrl_psd_actp;
static int hf_nvme_identify_ctrl_psd_apw;
static int hf_nvme_identify_ctrl_psd_rsvd8;
static int hf_nvme_identify_ctrl_psd_aps;
static int hf_nvme_identify_ctrl_psd_epfrt;
static int hf_nvme_identify_ctrl_psd_fqvt;
static int hf_nvme_identify_ctrl_psd_epfvt;
static int hf_nvme_identify_ctrl_psd_epfrts;
static int hf_nvme_identify_ctrl_psd_fqvts;
static int hf_nvme_identify_ctrl_psd_epfvts;
static int hf_nvme_identify_ctrl_psd_rsvd9;
static int hf_nvme_identify_ctrl_psd_mbw;
static int hf_nvme_identify_ctrl_psd_mbws;
static int hf_nvme_identify_ctrl_psd_rsvd10;
static int hf_nvme_identify_ctrl_psd_miiell;
static int hf_nvme_identify_ctrl_vs;

static int hf_nvme_identify_nslist_nsid;

/* Identify Namespace Identification Descriptor list (CNS 03h) response */
static int hf_nvme_identify_nsdesc_nidt;
static int hf_nvme_identify_nsdesc_nidl;
static int hf_nvme_identify_nsdesc_rsvd;
static int hf_nvme_identify_nsdesc_nid;
static int hf_nvme_identify_nsdesc_csi;

/* Identify Controller List (CNS 12h/13h) response */
static int hf_nvme_identify_ctrl_list_num;
static int hf_nvme_identify_ctrl_list_id;
static int hf_nvme_identify_enst_rsvd;
static int hf_nvme_identify_enst_uuid;

/* Identify NVM Set List (CNS 04h) response */
static int hf_nvme_identify_nvmset_num;
static int hf_nvme_identify_nvmset_id;
static int hf_nvme_identify_nvmset_endgid;
static int hf_nvme_identify_nvmset_r4krt;
static int hf_nvme_identify_nvmset_ows;
static int hf_nvme_identify_nvmset_tnvmsc;
static int hf_nvme_identify_nvmset_unvmsc;

/* Identify Primary Controller Capabilities (CNS 14h) response */
static int hf_nvme_identify_pcc_cntlid;
static int hf_nvme_identify_pcc_portid;
static int hf_nvme_identify_pcc_crt[4];
static int hf_nvme_identify_pcc_rsvd;
static int hf_nvme_identify_pcc_vqfrt;
static int hf_nvme_identify_pcc_vqrfa;
static int hf_nvme_identify_pcc_vqrfap;
static int hf_nvme_identify_pcc_vqprt;
static int hf_nvme_identify_pcc_vqfrsm;
static int hf_nvme_identify_pcc_vqgran;
static int hf_nvme_identify_pcc_vifrt;
static int hf_nvme_identify_pcc_virfa;
static int hf_nvme_identify_pcc_virfap;
static int hf_nvme_identify_pcc_viprt;
static int hf_nvme_identify_pcc_vifrsm;
static int hf_nvme_identify_pcc_vigran;

/* Identify Secondary Controller List (CNS 15h) response */
static int hf_nvme_identify_scl_num;
static int hf_nvme_identify_scl_scid;
static int hf_nvme_identify_scl_pcid;
static int hf_nvme_identify_scl_scs[3];
static int hf_nvme_identify_scl_vfn;
static int hf_nvme_identify_scl_nvq;
static int hf_nvme_identify_scl_nvi;

/* Identify Namespace Granularity List (CNS 16h) response */
static int hf_nvme_identify_ngl_nga[3];
static int hf_nvme_identify_ngl_nd;
static int hf_nvme_identify_ngl_nsg;
static int hf_nvme_identify_ngl_ncg;

/* Identify UUID List (CNS 17h) response */
static int hf_nvme_identify_uuid_idassoc;
static int hf_nvme_identify_uuid_uuid;

/* get logpage response */
static int hf_nvme_get_logpage_ify_genctr;
static int hf_nvme_get_logpage_ify_numrec;
static int hf_nvme_get_logpage_ify_recfmt;
static int hf_nvme_get_logpage_ify_dlpf[5];
static int hf_nvme_get_logpage_ify_rsvd0;
static int hf_nvme_get_logpage_ify_tdlpl;
static int hf_nvme_get_logpage_ify_rsvd;
static int hf_nvme_get_logpage_ify_rcrd;
static int hf_nvme_get_logpage_ify_rcrd_tel;
static int hf_nvme_get_logpage_ify_rcrd_numexat;
static int hf_nvme_get_logpage_ify_rcrd_rsvd2;
static int hf_nvme_get_logpage_ify_rcrd_exat;
static int hf_nvme_get_logpage_ify_rcrd_exat_type;
static int hf_nvme_get_logpage_ify_rcrd_exat_len;
static int hf_nvme_get_logpage_ify_rcrd_exat_val;
static int hf_nvme_get_logpage_ify_rcrd_trtype;
static int hf_nvme_get_logpage_ify_rcrd_adrfam;
static int hf_nvme_get_logpage_ify_rcrd_subtype;
static int hf_nvme_get_logpage_ify_rcrd_treq[6];
static int hf_nvme_get_logpage_ify_rcrd_portid;
static int hf_nvme_get_logpage_ify_rcrd_cntlid;
static int hf_nvme_get_logpage_ify_rcrd_asqsz;
static int hf_nvme_get_logpage_ify_rcrd_rsvd0;
static int hf_nvme_get_logpage_ify_rcrd_trsvcid;
static int hf_nvme_get_logpage_ify_rcrd_rsvd1;
static int hf_nvme_get_logpage_ify_rcrd_subnqn;
static int hf_nvme_get_logpage_ify_rcrd_traddr;
static int hf_nvme_get_logpage_ify_rcrd_tsas;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_qptype;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_prtype;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_cms;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_rsvd0;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_pkey;
static int hf_nvme_get_logpage_ify_rcrd_tsas_rdma_rsvd1;
static int hf_nvme_get_logpage_ify_rcrd_tsas_tcp_sectype;
static int hf_nvme_get_logpage_ify_rcrd_tsas_tcp_rsvd;
static int hf_nvme_get_logpage_errinf_entry;
static int hf_nvme_get_logpage_errinf_errcnt;
static int hf_nvme_get_logpage_errinf_sqid;
static int hf_nvme_get_logpage_errinf_cid;
static int hf_nvme_get_logpage_errinf_sf[3];
static int hf_nvme_get_logpage_errinf_pel[4];
static int hf_nvme_get_logpage_errinf_lba;
static int hf_nvme_get_logpage_errinf_ns;
static int hf_nvme_get_logpage_errinf_vsi;
static int hf_nvme_get_logpage_errinf_trtype;
static int hf_nvme_get_logpage_errinf_cmdset;
static int hf_nvme_get_logpage_errinf_opc;
static int hf_nvme_get_logpage_errinf_csi;
static int hf_nvme_get_logpage_errinf_tsi;
static int hf_nvme_get_logpage_errinf_rsvd1;
static int hf_nvme_get_logpage_errinf_lpver;
static int hf_nvme_get_logpage_smart_cw[9];
static int hf_nvme_get_logpage_smart_ct;
static int hf_nvme_get_logpage_smart_asc;
static int hf_nvme_get_logpage_smart_ast;
static int hf_nvme_get_logpage_smart_lpu;
static int hf_nvme_get_logpage_smart_egcws[6];
static int hf_nvme_get_logpage_smart_infw[3];
static int hf_nvme_get_logpage_smart_rsvd0;
static int hf_nvme_get_logpage_smart_dur;
static int hf_nvme_get_logpage_smart_duw;
static int hf_nvme_get_logpage_smart_hrc;
static int hf_nvme_get_logpage_smart_hwc;
static int hf_nvme_get_logpage_smart_cbt;
static int hf_nvme_get_logpage_smart_pc;
static int hf_nvme_get_logpage_smart_poh;
static int hf_nvme_get_logpage_smart_us;
static int hf_nvme_get_logpage_smart_mie;
static int hf_nvme_get_logpage_smart_ele;
static int hf_nvme_get_logpage_smart_wctt;
static int hf_nvme_get_logpage_smart_cctt;
static int hf_nvme_get_logpage_smart_ts[9];
static int hf_nvme_get_logpage_smart_tmt1c;
static int hf_nvme_get_logpage_smart_tmt2c;
static int hf_nvme_get_logpage_smart_tmt1t;
static int hf_nvme_get_logpage_smart_tmt2t;
static int hf_nvme_get_logpage_smart_olec;
static int hf_nvme_get_logpage_smart_ipm[6];
static int hf_nvme_get_logpage_smart_rsvd1;
static int hf_nvme_get_logpage_fw_slot_afi[5];
static int hf_nvme_get_logpage_fw_slot_rsvd0;
static int hf_nvme_get_logpage_fw_slot_frs;
static int hf_nvme_get_logpage_fw_slot_frs_ascii[7];
static int hf_nvme_get_logpage_fw_slot_rsvd1;
static int hf_nvme_get_logpage_changed_nslist;
static int hf_nvme_get_logpage_cmd_and_eff_cs;
static int hf_nvme_get_logpage_cmd_and_eff_cseds[18];
static int hf_nvme_get_logpage_supported_lids;
static int hf_nvme_get_logpage_supported_lidseds[5];
static int hf_nvme_get_logpage_selftest_csto[3];
static int hf_nvme_get_logpage_selftest_cstc[3];
static int hf_nvme_get_logpage_selftest_rsvd;
static int hf_nvme_get_logpage_selftest_res;
static int hf_nvme_get_logpage_selftest_res_status[3];
static int hf_nvme_get_logpage_selftest_res_sn;
static int hf_nvme_get_logpage_selftest_res_vdi[6];
static int hf_nvme_get_logpage_selftest_res_rsvd;
static int hf_nvme_get_logpage_selftest_res_poh;
static int hf_nvme_get_logpage_selftest_res_nsid;
static int hf_nvme_get_logpage_selftest_res_flba;
static int hf_nvme_get_logpage_selftest_res_sct[3];
static int hf_nvme_get_logpage_selftest_res_sc;
static int hf_nvme_get_logpage_selftest_res_vs;
static int hf_nvme_get_logpage_telemetry_li;
static int hf_nvme_get_logpage_telemetry_rsvd0;
static int hf_nvme_get_logpage_telemetry_ieee;
static int hf_nvme_get_logpage_telemetry_da1lb;
static int hf_nvme_get_logpage_telemetry_da2lb;
static int hf_nvme_get_logpage_telemetry_da3lb;
static int hf_nvme_get_logpage_telemetry_rsvd1;
static int hf_nvme_get_logpage_telemetry_da4lb;
static int hf_nvme_get_logpage_telemetry_rsvd2;
static int hf_nvme_get_logpage_telemetry_scope;
static int hf_nvme_get_logpage_telemetry_hdgn;
static int hf_nvme_get_logpage_telemetry_da;
static int hf_nvme_get_logpage_telemetry_dgn;
static int hf_nvme_get_logpage_telemetry_ri;
static int hf_nvme_get_logpage_telemetry_db;
static int hf_nvme_get_logpage_egroup_cw[6];
static int hf_nvme_get_logpage_egroup_egfeat[3];
static int hf_nvme_get_logpage_egroup_rsvd0;
static int hf_nvme_get_logpage_egroup_as;
static int hf_nvme_get_logpage_egroup_ast;
static int hf_nvme_get_logpage_egroup_pu;
static int hf_nvme_get_logpage_egroup_did;
static int hf_nvme_get_logpage_egroup_rsvd1;
static int hf_nvme_get_logpage_egroup_ee;
static int hf_nvme_get_logpage_egroup_dur;
static int hf_nvme_get_logpage_egroup_duw;
static int hf_nvme_get_logpage_egroup_muw;
static int hf_nvme_get_logpage_egroup_hrc;
static int hf_nvme_get_logpage_egroup_hwc;
static int hf_nvme_get_logpage_egroup_mdie;
static int hf_nvme_get_logpage_egroup_ele;
static int hf_nvme_get_logpage_egroup_tegcap;
static int hf_nvme_get_logpage_egroup_uegcap;
static int hf_nvme_get_logpage_egroup_rsvd2;
static int hf_nvme_get_logpage_pred_lat_status[3];
static int hf_nvme_get_logpage_pred_lat_rsvd0;
static int hf_nvme_get_logpage_pred_lat_etype[7];
static int hf_nvme_get_logpage_pred_lat_rsvd1;
static int hf_nvme_get_logpage_pred_lat_dtwin_rt;
static int hf_nvme_get_logpage_pred_lat_dtwin_wt;
static int hf_nvme_get_logpage_pred_lat_dtwin_tm;
static int hf_nvme_get_logpage_pred_lat_ndwin_tmh;
static int hf_nvme_get_logpage_pred_lat_ndwin_tml;
static int hf_nvme_get_logpage_pred_lat_rsvd2;
static int hf_nvme_get_logpage_pred_lat_dtwin_re;
static int hf_nvme_get_logpage_pred_lat_dtwin_we;
static int hf_nvme_get_logpage_pred_lat_dtwin_te;
static int hf_nvme_get_logpage_pred_lat_rsvd3;
static int hf_nvme_get_logpage_pred_lat_aggreg_ne;
static int hf_nvme_get_logpage_pred_lat_aggreg_nset;
static int hf_nvme_get_logpage_pred_lat_aggreg_fill;
static int hf_nvme_get_logpage_ana_chcnt;
static int hf_nvme_get_logpage_ana_ngd;
static int hf_nvme_get_logpage_ana_rsvd;
static int hf_nvme_get_logpage_ana_grp;
static int hf_nvme_get_logpage_ana_grp_id;
static int hf_nvme_get_logpage_ana_grp_nns;
static int hf_nvme_get_logpage_ana_grp_chcnt;
static int hf_nvme_get_logpage_ana_grp_anas[3];
static int hf_nvme_get_logpage_ana_grp_rsvd;
static int hf_nvme_get_logpage_ana_grp_nsid;
static int hf_nvme_get_logpage_lba_status_lslplen;
static int hf_nvme_get_logpage_lba_status_nlslne;
static int hf_nvme_get_logpage_lba_status_estulb;
static int hf_nvme_get_logpage_lba_status_rsvd;
static int hf_nvme_get_logpage_lba_status_lsgc;
static int hf_nvme_get_logpage_lba_status_nel;
static int hf_nvme_get_logpage_lba_status_nel_ne;
static int hf_nvme_get_logpage_lba_status_nel_ne_neid;
static int hf_nvme_get_logpage_lba_status_nel_ne_nlrd;
static int hf_nvme_get_logpage_lba_status_nel_ne_ratype;
static int hf_nvme_get_logpage_lba_status_nel_ne_rsvd;
static int hf_nvme_get_logpage_lba_status_nel_ne_rd;
static int hf_nvme_get_logpage_lba_status_nel_ne_rd_rslba;
static int hf_nvme_get_logpage_lba_status_nel_ne_rd_rnlb;
static int hf_nvme_get_logpage_lba_status_nel_ne_rd_rsvd;
static int hf_nvme_get_logpage_egroup_aggreg_ne;
static int hf_nvme_get_logpage_egroup_aggreg_eg;
static int hf_nvme_get_logpage_egroup_aggreg_fill;
static int hf_nvme_get_logpage_reserv_notif_lpc;
static int hf_nvme_get_logpage_reserv_notif_lpt;
static int hf_nvme_get_logpage_reserv_notif_nalp;
static int hf_nvme_get_logpage_reserv_notif_rsvd0;
static int hf_nvme_get_logpage_reserv_notif_nsid;
static int hf_nvme_get_logpage_reserv_notif_rsvd1;
static int hf_nvme_get_logpage_sanitize_sprog;
static int hf_nvme_get_logpage_sanitize_sstat[8];
static int hf_nvme_get_logpage_sanitize_scdw10;
static int hf_nvme_get_logpage_sanitize_eto;
static int hf_nvme_get_logpage_sanitize_etbe;
static int hf_nvme_get_logpage_sanitize_etce;
static int hf_nvme_get_logpage_sanitize_etond;
static int hf_nvme_get_logpage_sanitize_etbend;
static int hf_nvme_get_logpage_sanitize_etcend;
static int hf_nvme_get_logpage_sanitize_etpvds;
static int hf_nvme_get_logpage_sanitize_ssi[3];
static int hf_nvme_get_logpage_sanitize_rsvd0;
static int hf_nvme_get_logpage_sanitize_mnsoip;
static int hf_nvme_get_logpage_sanitize_stnsid;
static int hf_nvme_get_logpage_sanitize_rsvd;
static int hf_nvme_get_logpage_disc_rcrd_eflags[5];
/* Feature Identifiers Supported and Effects Response */
static int hf_nvme_get_logpage_feat_sup_and_eff_fidx;
static int hf_nvme_get_logpage_feat_sup_and_eff_fids[18];
/* NVMe-MI Commands Supported and Effects Response */
static int hf_nvme_get_logpage_mi_cmd_sup_and_eff_cs;
static int hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[15];
/* Command and Feature Lockdown Response */
static int hf_nvme_get_logpage_cmd_feat_lockdown_cfila[4];
static int hf_nvme_get_logpage_cmd_feat_lockdown_rsvd;
static int hf_nvme_get_logpage_cmd_feat_lockdown_lngth;
static int hf_nvme_get_logpage_cmd_feat_lockdown_cfil;
static int hf_nvme_get_logpage_cmd_feat_lockdown_rsvd1;
static int hf_nvme_lp_lockdown_enh_ver;
static int hf_nvme_lp_lockdown_enh_cfia[4];
static int hf_nvme_lp_lockdown_enh_cntlid;
static int hf_nvme_lp_lockdown_enh_sze;
static int hf_nvme_lp_lockdown_enh_ncfid;
static int hf_nvme_lp_lockdown_enh_cfids;
static int hf_nvme_lp_lockdown_enh_rsvd;
static int hf_nvme_lp_lockdown_enh_desc;
static int hf_nvme_lp_lockdown_enh_cfi;
static int hf_nvme_lp_lockdown_enh_dcfia[3];
static int hf_nvme_lp_lockdown_enh_desc_rsvd;
/* Physical Interface Receiver Eye Opening Measurement Response (LID 19h) */
static int hf_nvme_get_logpage_eom_lid;
static int hf_nvme_get_logpage_eom_eomip;
static int hf_nvme_get_logpage_eom_hsize;
static int hf_nvme_get_logpage_eom_rsz;
static int hf_nvme_get_logpage_eom_edgn;
static int hf_nvme_get_logpage_eom_lrev;
static int hf_nvme_get_logpage_eom_odp[4];
static int hf_nvme_get_logpage_eom_lns;
static int hf_nvme_get_logpage_eom_epl;
static int hf_nvme_get_logpage_eom_lspfc[3];
static int hf_nvme_get_logpage_eom_lspfc_act;
static int hf_nvme_get_logpage_eom_lspfc_mqual;
static int hf_nvme_get_logpage_eom_linfo[3];
static int hf_nvme_get_logpage_eom_rsvd0;
static int hf_nvme_get_logpage_eom_lsic;
static int hf_nvme_get_logpage_eom_ds;
static int hf_nvme_get_logpage_eom_nd;
static int hf_nvme_get_logpage_eom_maxtb;
static int hf_nvme_get_logpage_eom_maxlr;
static int hf_nvme_get_logpage_eom_etgood;
static int hf_nvme_get_logpage_eom_etbetter;
static int hf_nvme_get_logpage_eom_etbest;
static int hf_nvme_get_logpage_eom_rsvd1;
static int hf_nvme_get_logpage_eom_desc;
static int hf_nvme_get_logpage_eom_desc_rsvd0;
static int hf_nvme_get_logpage_eom_desc_mstat[3];
static int hf_nvme_get_logpage_eom_desc_ln;
static int hf_nvme_get_logpage_eom_desc_eye;
static int hf_nvme_get_logpage_eom_desc_top;
static int hf_nvme_get_logpage_eom_desc_btm;
static int hf_nvme_get_logpage_eom_desc_lft;
static int hf_nvme_get_logpage_eom_desc_rgt;
static int hf_nvme_get_logpage_eom_desc_nrows;
static int hf_nvme_get_logpage_eom_desc_ncols;
static int hf_nvme_get_logpage_eom_desc_edlen;
static int hf_nvme_get_logpage_eom_desc_rsvd1;
static int hf_nvme_get_logpage_eom_desc_pe;
static int hf_nvme_get_logpage_eom_desc_ed;
static int hf_nvme_get_logpage_eom_desc_pad;
static int hf_nvme_get_logpage_eom_desc_undef;

static int hf_nvme_pel_lid;
static int hf_nvme_pel_tnev;
static int hf_nvme_pel_tll;
static int hf_nvme_pel_lrev;
static int hf_nvme_pel_lhl;
static int hf_nvme_pel_timestamp;
static int hf_nvme_pel_synch;
static int hf_nvme_pel_origin;
static int hf_nvme_pel_poh;
static int hf_nvme_pel_pwrcc;
static int hf_nvme_pel_vid;
static int hf_nvme_pel_ssvid;
static int hf_nvme_pel_sn;
static int hf_nvme_pel_mn;
static int hf_nvme_pel_subnqn;
static int hf_nvme_pel_gnum;
static int hf_nvme_pel_rce;
static int hf_nvme_pel_rcpit;
static int hf_nvme_pel_rcpid;
static int hf_nvme_pel_seb;
static int hf_nvme_pel_seb_ev;
static int hf_nvme_pel_reserved;
static int hf_nvme_pel_extension;
static int hf_nvme_pel_events;
static int hf_nvme_pel_past_tll;
/* Persistent Event Log events (Base 2.3 Figures 231-243) */
static int hf_nvme_pel_ev;
static int hf_nvme_pel_ev_et;
static int hf_nvme_pel_ev_etr;
static int hf_nvme_pel_ev_ehl;
static int hf_nvme_pel_ev_pit;
static int hf_nvme_pel_ev_ehai_rsvd;
static int hf_nvme_pel_ev_cntlid;
static int hf_nvme_pel_ev_etstp;
static int hf_nvme_pel_ev_synch;
static int hf_nvme_pel_ev_origin;
static int hf_nvme_pel_ev_pelpid;
static int hf_nvme_pel_ev_rsvd;
static int hf_nvme_pel_ev_vsil;
static int hf_nvme_pel_ev_el;
static int hf_nvme_pel_ev_hdr_ext;
static int hf_nvme_pel_ev_vsi;
static int hf_nvme_pel_ev_data;
static int hf_nvme_pel_fwc_ofr;
static int hf_nvme_pel_fwc_nfr;
static int hf_nvme_pel_fwc_fca;
static int hf_nvme_pel_fwc_fslt;
static int hf_nvme_pel_fwc_stctfcc;
static int hf_nvme_pel_fwc_srfcc;
static int hf_nvme_pel_fwc_vafcrc;
static int hf_nvme_pel_tsc_ptstp;
static int hf_nvme_pel_tsc_synch;
static int hf_nvme_pel_tsc_origin;
static int hf_nvme_pel_tsc_msr;
static int hf_nvme_pel_por_frev;
static int hf_nvme_pel_por_desc;
static int hf_nvme_pel_por_cntlid;
static int hf_nvme_pel_por_fa;
static int hf_nvme_pel_por_rdnf;
static int hf_nvme_pel_por_oip_rsvd;
static int hf_nvme_pel_por_cpwrc;
static int hf_nvme_pel_por_pom;
static int hf_nvme_pel_por_ctstp;
static int hf_nvme_pel_por_synch;
static int hf_nvme_pel_por_origin;
static int hf_nvme_pel_hwe_code;
static int hf_nvme_pel_hwe_ahei;
static int hf_nvme_pel_hwe_pciedsr;
static int hf_nvme_pel_hwe_pcieaers;
static int hf_nvme_pel_hwe_pcieas_rsvd;
static int hf_nvme_pel_hwe_pcieaes;
static int hf_nvme_pel_hwe_pcieaem;
static int hf_nvme_pel_hwe_pcieahlr;
static int hf_nvme_pel_hwe_pcieatplr;
static int hf_nvme_pel_hwe_lnksta;
static int hf_nvme_pel_hwe_egid;
static int hf_nvme_pel_hwe_upl;
static int hf_nvme_pel_hwe_uploa;
static int hf_nvme_pel_hwe_upli_rsvd;
static int hf_nvme_pel_hwe_cqe;
static int hf_nvme_pel_hwe_cst_cnr;
static int hf_nvme_pel_hwe_cst_acmnr;
static int hf_nvme_pel_hwe_cst_nnr;
static int hf_nvme_pel_hwe_cst_crime;
static int hf_nvme_pel_hwe_cst_rsvd;
static int hf_nvme_pel_nsid;
static int hf_nvme_pel_cinfo;
static int hf_nvme_pel_cns_nmcdw10[3];
static int hf_nvme_pel_cns_nsze;
static int hf_nvme_pel_cns_ncap;
static int hf_nvme_pel_cns_anagrpid;
static int hf_nvme_pel_cns_nvmsetid;
static int hf_nvme_pel_cns_endgid;
static int hf_nvme_pel_fmc_sfpi;
static int hf_nvme_pel_fmc_fnvms[4];
static int hf_nvme_pel_fmc_info[7];
static int hf_nvme_pel_sfe_sfel[5];
static int hf_nvme_pel_sfe_cdw;
static int hf_nvme_pel_sfe_mbuf;
static int hf_nvme_pel_sfe_ccdw0;
static int hf_nvme_pel_tlc_til;
static int hf_nvme_pel_te_otmp;
static int hf_nvme_pel_te_thresh;
static int hf_nvme_pel_cdp_ps[4];
static int hf_nvme_pel_cdp_perid;
static int hf_nvme_pel_cdp_ped;
static int hf_nvme_pel_ensc_esubid;
static int hf_nvme_pel_ensc_otyp;
static int hf_nvme_pel_ensc_eeid;
static int hf_nvme_pel_ensc_eeid_esubid;
static int hf_nvme_pel_ensc_eeid_nsid;
static int hf_nvme_pel_ensc_eeid_cntlid;
static int hf_nvme_pel_ensc_eeid_portid;
static int hf_nvme_pel_ensc_ueid;
static int hf_nvme_pel_ensc_ueid_nsid;
static int hf_nvme_pel_ensc_ueid_cntlid;
static int hf_nvme_pel_ensc_ueid_portid;
static int hf_nvme_pel_ensc_id_rsvd;
static int hf_nvme_pel_vse_desc;
static int hf_nvme_pel_vse_vsec;
static int hf_nvme_pel_vse_vsedt;
static int hf_nvme_pel_vse_uidx;
static int hf_nvme_pel_vse_vsedl;
static int hf_nvme_pel_vse_vsed_str;
static int hf_nvme_pel_vse_vsed_int;
static int hf_nvme_pel_vse_vsed;

/* NVMe CQE fields */
static int hf_nvme_cqe_dword0;
static int hf_nvme_cqe_aev_dword0[6];
static int hf_nvme_cqe_dword0_sf_nq[3];
static int hf_nvme_cqe_fwc_dword0[4];
static int hf_nvme_cqe_ns_mgmt_nsid;
static int hf_nvme_cqe_cap_mgmt_dword0[3];
static int hf_nvme_cqe_virt_mgmt_dword0[3];

static int hf_nvme_cqe_get_features_dword0_arb[6];
static int hf_nvme_cqe_get_features_dword0_pm[5];
static int hf_nvme_cqe_get_features_dword0_lbart[3];
static int hf_nvme_cqe_get_features_dword0_tt[3];
static int hf_nvme_cqe_get_features_dword0_erec[4];
static int hf_nvme_cqe_get_features_dword0_vwce[3];
static int hf_nvme_cqe_get_features_dword0_nq[3];
static int hf_nvme_cqe_get_features_dword0_irqc[4];
static int hf_nvme_cqe_get_features_dword0_irqv[4];
static int hf_nvme_cqe_get_features_dword0_wan[3];
static int hf_nvme_cqe_get_features_dword0_aec[23];
static int hf_nvme_cqe_get_features_dword0_apst[3];
static int hf_nvme_cqe_get_features_dword0_kat[2];
static int hf_nvme_cqe_get_features_dword0_hctm[3];
static int hf_nvme_cqe_get_features_dword0_nops[3];
static int hf_nvme_cqe_get_features_dword0_rrl[3];
static int hf_nvme_cqe_get_features_dword0_plmc[3];
static int hf_nvme_cqe_get_features_dword0_plmw[3];
static int hf_nvme_cqe_get_features_dword0_lbasi[3];
static int hf_nvme_cqe_get_features_dword0_san[3];
static int hf_nvme_cqe_get_features_dword0_eg[4];
static int hf_nvme_cqe_get_features_dword0_swp[3];
static int hf_nvme_cqe_get_features_dword0_rsrvn[6];
static int hf_nvme_cqe_get_features_dword0_rsrvp[3];
static int hf_nvme_cqe_get_features_dword0_nswp[3];
static int hf_nvme_cqe_get_features_dword0_caps[5];

static int hf_nvme_cqe_dword1;
static int hf_nvme_cqe_sqhd;
static int hf_nvme_cqe_sqid;
static int hf_nvme_cqe_cid;
static int hf_nvme_cqe_status[7];
static int hf_nvme_cqe_status_rsvd;

/* tracking Cmd and its respective CQE */
static int hf_nvme_cmd_pkt;
static int hf_nvme_data_req;
static int hf_nvme_data_tr[NVME_CMD_MAX_TRS];
static int hf_nvme_cqe_pkt;
static int hf_nvme_cmd_latency;

/* Data response fields */
static int hf_nvme_gen_data;
/* Initialize the subtree pointers */
static int hf_nvme_lp_bp_lid;
static int hf_nvme_lp_bp_rsvd0;
static int hf_nvme_lp_bp_bpinfo[4];
static int hf_nvme_lp_bp_rsvd1;
static int hf_nvme_lp_bp_bpd;
static int hf_nvme_lp_rmi_endgid;
static int hf_nvme_lp_rmi_numa;
static int hf_nvme_lp_rmi_nrs;
static int hf_nvme_lp_rmi_rsvd0;
static int hf_nvme_lp_rmi_spinc;
static int hf_nvme_lp_rmi_fspinc;
static int hf_nvme_lp_rmi_ldc;
static int hf_nvme_lp_rmi_fldc;
static int hf_nvme_lp_rmi_rsvd1;
static int hf_nvme_lp_mal_mat;
static int hf_nvme_lp_mal_rsvd;
static int hf_nvme_lp_mal_madrs;
static int hf_nvme_lp_dp_nump;
static int hf_nvme_lp_dp_cdplpv;
static int hf_nvme_lp_mdcs_mdcsv;
static int hf_nvme_lp_mdcs_mdcs;
static int hf_nvme_lp_mdcs_dscs;
static int hf_nvme_lp_mdcs_dncs;
static int hf_nvme_lp_mdcs_dccs;
static int hf_nvme_lp_mdcs_rsvd;
static int hf_nvme_lp_dp_dplphl;
static int hf_nvme_lp_dp_cdplps;
static int hf_nvme_lp_dp_pps;
static int hf_nvme_lp_dp_perid;
static int hf_nvme_lp_dp_mrstt;
static int hf_nvme_lp_dp_aus[4];
static int hf_nvme_lp_dp_attr[3];
static int hf_nvme_lp_pm_ver;
static int hf_nvme_lp_pm_pmgn;
static int hf_nvme_lp_pm_pma[8];
static int hf_nvme_lp_pm_sze;
static int hf_nvme_lp_pm_pmc;
static int hf_nvme_lp_pm_nphd;
static int hf_nvme_lp_pm_smtr;
static int hf_nvme_lp_pm_smts[6];
static int hf_nvme_lp_pm_phds;
static int hf_nvme_lp_pm_phbs;
static int hf_nvme_lp_pm_nphds;
static int hf_nvme_lp_pm_vss;
static int hf_nvme_lp_pm_phdoc;
static int hf_nvme_lp_pm_rsvd0;
static int hf_nvme_lp_pm_aipwr[4];
static int hf_nvme_lp_pm_mipwr[4];
static int hf_nvme_lp_pm_mipwrt[6];
static int hf_nvme_lp_pm_ipwrpe;
static int hf_nvme_lp_pm_rsvd1;
static int hf_nvme_lp_pm_phbc;
static int hf_nvme_lp_pm_phblt[4];
static int hf_nvme_lp_pm_vs;
static int hf_nvme_lp_vm_vmgn;
static int hf_nvme_lp_vm_vma[6];
static int hf_nvme_lp_vm_vsi[4];
static int hf_nvme_lp_vm_vmlsz;
static int hf_nvme_lp_vm_nvmds;
static int hf_nvme_lp_vm_nvmde;
static int hf_nvme_lp_vm_svmtr;
static int hf_nvme_lp_vm_svmts[6];
static int hf_nvme_lp_vm_cntlid;
static int hf_nvme_lp_vm_vlvss;
static int hf_nvme_lp_vm_rsvd0;
static int hf_nvme_lp_vm_ovol[4];
static int hf_nvme_lp_vm_ovc;
static int hf_nvme_lp_vm_ovlt;
static int hf_nvme_lp_vm_ovts[6];
static int hf_nvme_lp_vm_iovpe;
static int hf_nvme_lp_vm_uvol[4];
static int hf_nvme_lp_vm_uvc;
static int hf_nvme_lp_vm_uvlt;
static int hf_nvme_lp_vm_uvts[6];
static int hf_nvme_lp_vm_iuvpe;
static int hf_nvme_lp_vm_rsvd1;
static int hf_nvme_lp_vm_ivolm[4];
static int hf_nvme_lp_vm_vlvs;
static int hf_nvme_lp_rl_rsvd0;
static int hf_nvme_lp_rl_np;
static int hf_nvme_lp_rl_lpl;
static int hf_nvme_lp_rl_gc;
static int hf_nvme_lp_rl_nst;
static int hf_nvme_lp_rl_rsvd1;
static int hf_nvme_lp_rl_port_off;
static int hf_nvme_lp_rl_ctrl_off;
static int hf_nvme_lp_rl_nsma_off;
static int hf_nvme_lp_rl_port;
static int hf_nvme_lp_rl_portid;
static int hf_nvme_lp_rl_nc;
static int hf_nvme_lp_rl_abwsf;
static int hf_nvme_lp_rl_arbwv;
static int hf_nvme_lp_rl_awbwv;
static int hf_nvme_lp_rl_ariops;
static int hf_nvme_lp_rl_awiops;
static int hf_nvme_lp_rl_ctrl;
static int hf_nvme_lp_rl_cntlid;
static int hf_nvme_lp_rl_nnsmad;
static int hf_nvme_lp_rl_nsma;
static int hf_nvme_lp_rl_sc;
static int hf_nvme_lp_rl_si;
static int hf_nvme_lp_rl_rlma;
static int hf_nvme_lp_rl_mbsf;
static int hf_nvme_lp_rl_mrbwv;
static int hf_nvme_lp_rl_mwbwv;
static int hf_nvme_lp_rl_mriops;
static int hf_nvme_lp_rl_mwiops;
static int hf_nvme_lp_rl_dsc_rsvd;
static int hf_nvme_lp_rl_dsc_vs;
static int hf_nvme_lp_rl_tgt;
static int hf_nvme_lp_rl_pad;
static int hf_nvme_lp_snsl_genctr;
static int hf_nvme_lp_snsl_numnsid;
static int hf_nvme_lp_snsl_nsid;
static int hf_nvme_lp_mus_nmu;
static int hf_nvme_lp_mus_cchans;
static int hf_nvme_lp_mus_selc;
static int hf_nvme_lp_mus_rsvd0;
static int hf_nvme_lp_mus_muid;
static int hf_nvme_lp_mus_did;
static int hf_nvme_lp_mus_endgid;
static int hf_nvme_lp_mus_nvmsetid;
static int hf_nvme_lp_mus_caf;
static int hf_nvme_lp_mus_avsp;
static int hf_nvme_lp_mus_pused;
static int hf_nvme_lp_mus_mucs;
static int hf_nvme_lp_mus_cio;
static int hf_nvme_lp_mus_rsvd1;
static int hf_nvme_lp_mus_chid;
static int hf_nvme_lp_scc_sccn;
static int hf_nvme_lp_scc_rsvd0;
static int hf_nvme_lp_scc_ccid;
static int hf_nvme_lp_scc_did;
static int hf_nvme_lp_scc_egcn;
static int hf_nvme_lp_scc_rsvd1;
static int hf_nvme_lp_scc_endgid;
static int hf_nvme_lp_scc_cadjf;
static int hf_nvme_lp_scc_rsvd2;
static int hf_nvme_lp_scc_tegcap;
static int hf_nvme_lp_scc_segcap;
static int hf_nvme_lp_scc_ee;
static int hf_nvme_lp_scc_rsvd3;
static int hf_nvme_lp_scc_egsets;
static int hf_nvme_lp_scc_nvmsetid;
static int hf_nvme_lp_scc_egchans;
static int hf_nvme_lp_scc_chid;
static int hf_nvme_lp_scc_chmus;
static int hf_nvme_lp_scc_muid;
static int hf_nvme_lp_scc_rsvd4;
static int hf_nvme_lp_scc_mudl;
static int hf_nvme_lp_scc_mudi;
static int hf_nvme_lp_dnps_genctr;
static int hf_nvme_lp_dnps_numpsub;
static int hf_nvme_lp_dnps_rsvd;
static int hf_nvme_lp_dnps_nqn;
static int hf_nvme_reach_rsvd;
static int hf_nvme_window_decode_skipped;
static int hf_nvme_cqe_sc_note;
static int ett_data;

static expert_field ei_nvme_cqe_status_error;
static expert_field ei_nvme_cqe_sc_undefined_for_cmd;
static expert_field ei_nvme_lbaf_count_invalid;
static expert_field ei_nvme_data_len_exceeds_frame;
static expert_field ei_nvme_logpage_window_misaligned;
static expert_field ei_nvme_eom_desc_field_overrun;
static expert_field ei_nvme_eom_hsize_invalid;
static expert_field ei_nvme_security_length;
static expert_field ei_nvme_security_tper_reset_tl;
static expert_field ei_nvme_security_secp_send;
static expert_field ei_nvme_security_secp_nvme;
static expert_field ei_nvme_lp_layout;
static expert_field ei_nvme_ctrl_list_count;
static expert_field ei_nvme_nidl_mismatch;
static expert_field ei_nvme_identify_cns_reserved;
static expert_field ei_nvme_id_nument_excess;
static expert_field ei_nvme_logpage_lpo_misaligned;
static expert_field ei_nvme_data_wrong_direction;
static expert_field ei_nvme_feat_sel_reserved;
static expert_field ei_nvme_feat_sel_no_data;
static expert_field ei_nvme_feat_sel_caps_data;
static expert_field ei_nvme_feat_field_invalid;
static expert_field ei_nvme_pel_invalid_header;
static expert_field ei_nvme_pel_invalid_event;
static expert_field ei_nvme_pel_event_length;
static expert_field ei_nvme_pel_event_revision;
static expert_field ei_nvme_pel_tnev_mismatch;

/* NVME_AQ_OPC_* admin opcodes are defined in packet-nvme.h (shared with the
 * NVMe-MI Admin dissector). */

#define NVME_IOQ_OPC_FLUSH                  0x0
#define NVME_IOQ_OPC_WRITE                  0x1
#define NVME_IOQ_OPC_READ                   0x2
#define NVME_IOQ_OPC_WRITE_UNCORRECTABLE    0x4
#define NVME_IOQ_OPC_COMPARE                0x5
#define NVME_IOQ_OPC_WRITE_ZEROS            0x8
#define NVME_IOQ_OPC_DATASET_MGMT           0x9
#define NVME_IOQ_OPC_VERIFY                 0xc
#define NVME_IOQ_OPC_RESV_REG               0xd
#define NVME_IOQ_OPC_RESV_REPORT            0xe
#define NVME_IOQ_OPC_RESV_ACQUIRE           0x11
#define NVME_IOQ_OPC_IO_MGMT_RECV           0x12
#define NVME_IOQ_OPC_RESV_RELEASE           0x15
#define NVME_IOQ_OPC_CANCEL                 0x18
#define NVME_IOQ_OPC_COPY                   0x19
#define NVME_IOQ_OPC_IO_MGMT_SEND           0x1d

/* NVME_IDENTIFY_CNS_* values are defined in packet-nvme.h. */

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
    NVME_CQE_SC_GEN_CMD_PROHIBITED_LOCKDOWN = 0x23,
    NVME_CQE_SC_GEN_ADMIN_CMD_MEDIA_NOT_READY = 0x24,
    NVME_CQE_SC_GEN_INVALID_KEY_TAG = 0x25,
    NVME_CQE_SC_GEN_HOST_DISP_NS_SUPP_NOT_ENABLED = 0x26,
    NVME_CQE_SC_GEN_HOST_ID_NOT_INITIALIZED = 0x27,
    NVME_CQE_SC_GEN_INCORRECT_KEY = 0x28,
    NVME_CQE_SC_GEN_FDP_DISABLED = 0x29,
    NVME_CQE_SC_GEN_INVALID_PLACEMENT_HANDLE_LIST = 0x2A,
    NVME_CQE_SC_GEN_SANITIZE_NAMESPACE_FAILED = 0x2B,
    NVME_CQE_SC_GEN_SANITIZE_NAMESPACE_IN_PROGRESS = 0x2C,
    NVME_CQE_SC_GEN_LBA_OUT_OF_RANGE = 0x80,
    NVME_CQE_SC_GEN_CAPACITY_EXCEED = 0x81,
    NVME_CQE_SC_GEN_NAMESPACE_NOT_ERADY = 0x82,
    NVME_CQE_SC_GEN_RESERVATION_CONFLICT = 0x83,
    NVME_CQE_SC_GEN_FMT_IN_PROGRESS = 0x84,
    NVME_CQE_SC_GEN_INVALID_VALUE_SIZE = 0x85,
    NVME_CQE_SC_GEN_INVALID_KEY_SIZE = 0x86,
    NVME_CQE_SC_GEN_KV_KEY_DOES_NOT_EXIST = 0x87,
    NVME_CQE_SC_GEN_UNRECOVERED_ERROR = 0x88,
    NVME_CQE_SC_GEN_KEY_EXISTS = 0x89,
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
    NVME_CQE_SC_CMD_INSUFFICIENT_CAPACITY = 0x26,
    NVME_CQE_SC_CMD_NS_ATTACHMENT_LIMIT_EXCEEDED = 0x27,
    NVME_CQE_SC_CMD_PROHIBITION_NOT_SUPPORTED = 0x28,
    NVME_CQE_SC_CMD_IO_CMD_SET_NOT_SUPPORTED = 0x29,
    NVME_CQE_SC_CMD_IO_CMD_SET_NOT_ENABLED = 0x2A,
    NVME_CQE_SC_CMD_IO_CMD_SET_COMBINATION_REJECTED = 0x2B,
    NVME_CQE_SC_CMD_INVALID_IO_CMD_SET = 0x2C,
    NVME_CQE_SC_CMD_IDENTIFIER_UNAVAILABLE = 0x2D,
    NVME_CQE_SC_CMD_NAMESPACE_IS_DISPERSED = 0x2E,
    NVME_CQE_SC_CMD_INVALID_DISCOVERY_INFO = 0x2F,
    NVME_CQE_SC_CMD_ZONING_DS_LOCKED = 0x30,
    NVME_CQE_SC_CMD_ZONING_DS_NOT_FOUND = 0x31,
    NVME_CQE_SC_CMD_INSUFFICIENT_DISCOVERY_RES = 0x32,
    NVME_CQE_SC_CMD_REQUESTED_FUNCTION_DISABLED = 0x33,
    NVME_CQE_SC_CMD_ZONEGROUP_ORIGINATOR_INVALID = 0x34,
    NVME_CQE_SC_CMD_INVALID_HOST = 0x35,
    NVME_CQE_SC_CMD_INVALID_NVM_SUBSYSTEM = 0x36,
    NVME_CQE_SC_CMD_INVALID_CTRL_DATA_QUEUE = 0x37,
    NVME_CQE_SC_CMD_NOT_ENOUGH_RESOURCES = 0x38,
    NVME_CQE_SC_CMD_CONTROLLER_SUSPENDED = 0x39,
    NVME_CQE_SC_CMD_CONTROLLER_NOT_SUSPENDED = 0x3A,
    NVME_CQE_SC_CMD_CTRL_DATA_QUEUE_FULL = 0x3B,
    NVME_CQE_SC_CMD_EXCEEDS_MAX_NS_SANITIZE_OPS = 0x3C,
    NVME_CQE_SC_CMD_MFG_DEFAULT_PERSONALITY_REQUIRED = 0x3D,
    NVME_CQE_SC_CMD_INVALID_POWER_LIMIT = 0x3E,
    NVME_CQE_SC_CMD_CROSS_CTRL_RESET_IN_PROGRESS = 0x3F,
    NVME_CQE_SC_CMD_CROSS_CTRL_RESET_LOG_PAGE_FULL = 0x40,
    NVME_CQE_SC_CMD_CROSS_CTRL_RESET_LIMIT_EXCEEDED = 0x41,
    NVME_CQE_SC_CMD_CONFLICTING_ATTRS = 0x80,
    NVME_CQE_SC_CMD_INVALID_PROTECTION_INF = 0x81,
    NVME_CQE_SC_CMD_WRITE_TO_RO_REGION = 0x82,
    NVME_CQE_SC_CMD_SIZE_LIMIT_EXCEEDED = 0x83,
    NVME_CQE_SC_CMD_INVALID_COMMAND_ID = 0x84,
    NVME_CQE_SC_CMD_INCOMPAT_NAMESPACE_OR_FMT = 0x85,
    NVME_CQE_SC_CMD_FAST_COPY_NOT_POSSIBLE = 0x86,
    NVME_CQE_SC_CMD_OVERLAPPING_IO_RANGE = 0x87,
    NVME_CQE_SC_CMD_NAMESPACE_NOT_REACHABLE = 0x88,
    NVME_CQE_SC_CMD_INSUFFICIENT_RESOURCES = 0x89,
    NVME_CQE_SC_CMD_INSUFFICIENT_PROGRAM_RESOURCES = 0x8A,
    NVME_CQE_SC_CMD_INVALID_MEMORY_NAMESPACE = 0x8B,
    NVME_CQE_SC_CMD_INVALID_MEMORY_RANGE_SET = 0x8C,
    NVME_CQE_SC_CMD_INVALID_MEMORY_RANGE_SET_ID = 0x8D,
    NVME_CQE_SC_CMD_INVALID_PROGRAM_DATA = 0x8E,
    NVME_CQE_SC_CMD_INVALID_PROGRAM_INDEX = 0x8F,
    NVME_CQE_SC_CMD_INVALID_PROGRAM_TYPE = 0x90,
    NVME_CQE_SC_CMD_MAX_MEMORY_RANGES_EXCEEDED = 0x91,
    NVME_CQE_SC_CMD_MAX_MEMORY_RANGE_SETS_EXCEEDED = 0x92,
    NVME_CQE_SC_CMD_MAX_PROGRAMS_ACTIVATED = 0x93,
    NVME_CQE_SC_CMD_MAX_PROGRAM_BYTES_EXCEEDED = 0x94,
    NVME_CQE_SC_CMD_MEMORY_RANGE_SET_IN_USE = 0x95,
    NVME_CQE_SC_CMD_NO_PROGRAM = 0x96,
    NVME_CQE_SC_CMD_OVERLAPPING_MEMORY_RANGES = 0x97,
    NVME_CQE_SC_CMD_PROGRAM_NOT_ACTIVATED = 0x98,
    NVME_CQE_SC_CMD_PROGRAM_IN_USE = 0x99,
    NVME_CQE_SC_CMD_PROGRAM_INDEX_NOT_DOWNLOADABLE = 0x9A,
    NVME_CQE_SC_CMD_PROGRAM_TOO_BIG = 0x9B,
    NVME_CQE_SC_CMD_SUCCESSFUL_MEDIA_VERIFICATION_READ = 0x9C,
    NVME_CQE_SC_CMD_ZONE_BOUNDARY_ERROR = 0xB8,
    NVME_CQE_SC_CMD_ZONE_IS_FULL = 0xB9,
    NVME_CQE_SC_CMD_ZONE_IS_READ_ONLY = 0xBA,
    NVME_CQE_SC_CMD_ZONE_IS_OFFLINE = 0xBB,
    NVME_CQE_SC_CMD_ZONE_INVALID_WRITE = 0xBC,
    NVME_CQE_SC_CMD_TOO_MANY_ACTIVE_ZONES = 0xBD,
    NVME_CQE_SC_CMD_TOO_MANY_OPEN_ZONES = 0xBE,
    NVME_CQE_SC_CMD_INVALID_ZONE_STATE_TRANSITION = 0xBF,
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
    NVME_CQE_SC_MEDIA_ETE_STORAGE_TAG_CHECK_ERR = 0x88,
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

static const range_string nvme_cqe_sct_tbl[] = {
    { NVME_CQE_SCT_GENERIC, NVME_CQE_SCT_GENERIC, "Generic Command Status" },
    { NVME_CQE_SCT_COMMAND, NVME_CQE_SCT_COMMAND, "Command Specific Status" },
    { NVME_CQE_SCT_MEDIA, NVME_CQE_SCT_MEDIA, "Media and Data Integrity Errors" },
    { NVME_CQE_SCT_PATH, NVME_CQE_SCT_PATH, "Path Related Status" },
    { 4, 6, "Reserved" },
    { NVME_CQE_SCT_VENDOR, NVME_CQE_SCT_VENDOR, "Vendor Specific" },
    { 0, 0, NULL },
};

/* Base 2.4 Figure 103. Unlisted assigned I/O codes are not Reserved. */
static const range_string nvme_cqe_sc_gen_tbl[] = {
    { NVME_CQE_SC_GEN_CMD_OK, NVME_CQE_SC_GEN_CMD_OK, "Successful Completion" },
    { NVME_CQE_SC_CMD_INVALID_OPCODE, NVME_CQE_SC_CMD_INVALID_OPCODE, "Invalid Command Opcode" },
    { NVME_CQE_SC_GEN_CMD_INVALID_FIELD, NVME_CQE_SC_GEN_CMD_INVALID_FIELD, "Invalid Field in Command" },
    { NVME_CQE_SC_GEN_CMD_CID_CONFLICT, NVME_CQE_SC_GEN_CMD_CID_CONFLICT, "Command ID Conflict" },
    { NVME_CQE_SC_GEN_DATA_TRANSFER_ERR, NVME_CQE_SC_GEN_DATA_TRANSFER_ERR, "Data Transfer Error" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_POWER_LOSS, NVME_CQE_SC_GEN_ABORT_DUE_TO_POWER_LOSS, "Commands Aborted due to Power Loss Notification" },
    { NVME_CQE_SC_GEN_INTERNAL_ERROR, NVME_CQE_SC_GEN_INTERNAL_ERROR, "Internal Error" },
    { NVME_CQE_SC_GEN_ABORT_REQUESTED, NVME_CQE_SC_GEN_ABORT_REQUESTED, "Command Abort Requested" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_SQ_DELETE, NVME_CQE_SC_GEN_ABORT_DUE_TO_SQ_DELETE, "Command Aborted due to SQ Deletion" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_FAILED_FUSE, NVME_CQE_SC_GEN_ABORT_DUE_TO_FAILED_FUSE, "Command Aborted due to Failed Fused Command" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_MISSED_FUSE, NVME_CQE_SC_GEN_ABORT_DUE_TO_MISSED_FUSE, "Command Aborted due to Missing Fused Command" },
    { NVME_CQE_SC_GEN_INVALID_NAMESPACE_OR_FMT, NVME_CQE_SC_GEN_INVALID_NAMESPACE_OR_FMT, "Invalid Namespace or Format" },
    { NVME_CQE_SC_GEN_COMMAND_SEQUENCE_ERR, NVME_CQE_SC_GEN_COMMAND_SEQUENCE_ERR, "Command Sequence Error" },
    { NVME_CQE_SC_GEN_INVALID_SGL_SD, NVME_CQE_SC_GEN_INVALID_SGL_SD, "Invalid SGL Segment Descriptor" },
    { NVME_CQE_SC_GEN_INVALID_SGL_SD_NUM, NVME_CQE_SC_GEN_INVALID_SGL_SD_NUM, "Invalid Number of SGL Descriptors" },
    { NVME_CQE_SC_GEN_INVALID_SGL_LEN, NVME_CQE_SC_GEN_INVALID_SGL_LEN, "Data SGL Length Invalid" },
    { NVME_CQE_SC_GEN_INVALID_MDATA_SGL_LEN, NVME_CQE_SC_GEN_INVALID_MDATA_SGL_LEN, "Metadata SGL Length Invalid" },
    { NVME_CQE_SC_GEN_INVALID_SGL_SD_TYPE, NVME_CQE_SC_GEN_INVALID_SGL_SD_TYPE, "SGL Descriptor Type Invalid" },
    { NVME_CQE_SC_GEN_INVALID_USE_OF_MC_BUF, NVME_CQE_SC_GEN_INVALID_USE_OF_MC_BUF, "Invalid Use of Controller Memory Buffer" },
    { NVME_CQE_SC_GEN_INVALID_PRP_OFFSET, NVME_CQE_SC_GEN_INVALID_PRP_OFFSET, "PRP Offset Invalid" },
    { NVME_CQE_SC_GEN_ATOMIC_WRITE_UNIT_EXCEED, NVME_CQE_SC_GEN_ATOMIC_WRITE_UNIT_EXCEED, "Atomic Write Unit Exceeded" },
    { NVME_CQE_SC_GEN_OPERATION_DENIED, NVME_CQE_SC_GEN_OPERATION_DENIED, "Operation Denied" },
    { NVME_CQE_SC_GEN_INVALID_SGL_OFFSET, NVME_CQE_SC_GEN_INVALID_SGL_OFFSET, "SGL Offset Invalid" },
    { NVME_CQE_SC_GEN_RESERVED_17H, NVME_CQE_SC_GEN_RESERVED_17H, "Reserved" },
    { NVME_CQE_SC_GEN_HOST_ID_INVALID_FMT, NVME_CQE_SC_GEN_HOST_ID_INVALID_FMT, "Host Identifier Inconsistent Format" },
    { NVME_CQE_SC_GEN_KEEP_ALLIVE_EXPIRED, NVME_CQE_SC_GEN_KEEP_ALLIVE_EXPIRED, "Keep Alive Timer Expired" },
    { NVME_CQE_SC_GEN_KEEP_ALIVE_INVALID, NVME_CQE_SC_GEN_KEEP_ALIVE_INVALID, "Keep Alive Timeout Invalid" },
    { NVME_CQE_SC_GEN_ABORT_DUE_TO_PREEMPT_ABRT, NVME_CQE_SC_GEN_ABORT_DUE_TO_PREEMPT_ABRT, "Command Aborted due to Preempt and Abort" },
    { NVME_CQE_SC_GEN_SANITIZE_FAILED, NVME_CQE_SC_GEN_SANITIZE_FAILED, "Sanitize Failed" },
    { NVME_CQE_SC_GEN_SANITZE_IN_PROGRESS, NVME_CQE_SC_GEN_SANITZE_IN_PROGRESS, "Sanitize In Progress" },
    { NVME_CQE_SC_GEN_SGL_BLOCK_GRAN_INVALID, NVME_CQE_SC_GEN_SGL_BLOCK_GRAN_INVALID, "SGL Data Block Granularity Invalid" },
    { NVME_CQE_SC_GEN_CMD_NOT_SUPP_IN_CMB, NVME_CQE_SC_GEN_CMD_NOT_SUPP_IN_CMB, "Command Not Supported for Queue in CMB" },
    { NVME_CQE_SC_GEN_NAMESPACE_IS_WP, NVME_CQE_SC_GEN_NAMESPACE_IS_WP, "Namespace is Write Protected" },
    { NVME_CQE_SC_GEN_COMMAND_INTERRUPTED, NVME_CQE_SC_GEN_COMMAND_INTERRUPTED, "Command Interrupted" },
    { NVME_CQE_SC_GEN_TRANSIENT_TRASPORT_ERROR, NVME_CQE_SC_GEN_TRANSIENT_TRASPORT_ERROR, "Transient Transport Error" },
    { NVME_CQE_SC_GEN_CMD_PROHIBITED_LOCKDOWN, NVME_CQE_SC_GEN_CMD_PROHIBITED_LOCKDOWN, "Command Prohibited by Command and Feature Lockdown" },
    { NVME_CQE_SC_GEN_ADMIN_CMD_MEDIA_NOT_READY, NVME_CQE_SC_GEN_ADMIN_CMD_MEDIA_NOT_READY, "Admin Command Media Not Ready" },
    { NVME_CQE_SC_GEN_INVALID_KEY_TAG, NVME_CQE_SC_GEN_INVALID_KEY_TAG, "Invalid Key Tag" },
    { NVME_CQE_SC_GEN_HOST_DISP_NS_SUPP_NOT_ENABLED, NVME_CQE_SC_GEN_HOST_DISP_NS_SUPP_NOT_ENABLED, "Host Dispersed Namespace Support Not Enabled" },
    { NVME_CQE_SC_GEN_HOST_ID_NOT_INITIALIZED, NVME_CQE_SC_GEN_HOST_ID_NOT_INITIALIZED, "Host Identifier Not Initialized" },
    { NVME_CQE_SC_GEN_INCORRECT_KEY, NVME_CQE_SC_GEN_INCORRECT_KEY, "Incorrect Key" },
    { NVME_CQE_SC_GEN_FDP_DISABLED, NVME_CQE_SC_GEN_FDP_DISABLED, "FDP Disabled" },
    { NVME_CQE_SC_GEN_INVALID_PLACEMENT_HANDLE_LIST, NVME_CQE_SC_GEN_INVALID_PLACEMENT_HANDLE_LIST, "Invalid Placement Handle List" },
    { NVME_CQE_SC_GEN_SANITIZE_NAMESPACE_FAILED, NVME_CQE_SC_GEN_SANITIZE_NAMESPACE_FAILED, "Sanitize Namespace Failed" },
    { NVME_CQE_SC_GEN_SANITIZE_NAMESPACE_IN_PROGRESS, NVME_CQE_SC_GEN_SANITIZE_NAMESPACE_IN_PROGRESS, "Sanitize Namespace In Progress" },
    { 0x2d, 0x2d, "Failed to Restore Configuration" },
    { 0x2e, 0x7f, "Reserved" },
    { NVME_CQE_SC_GEN_LBA_OUT_OF_RANGE, NVME_CQE_SC_GEN_LBA_OUT_OF_RANGE, "LBA Out of Range" },
    { NVME_CQE_SC_GEN_CAPACITY_EXCEED, NVME_CQE_SC_GEN_CAPACITY_EXCEED, "Capacity Exceeded" },
    { NVME_CQE_SC_GEN_NAMESPACE_NOT_ERADY, NVME_CQE_SC_GEN_NAMESPACE_NOT_ERADY, "Namespace Not Ready" },
    { NVME_CQE_SC_GEN_RESERVATION_CONFLICT, NVME_CQE_SC_GEN_RESERVATION_CONFLICT, "Reservation Conflict" },
    { NVME_CQE_SC_GEN_FMT_IN_PROGRESS, NVME_CQE_SC_GEN_FMT_IN_PROGRESS, "Format In Progress" },
    { NVME_CQE_SC_GEN_INVALID_VALUE_SIZE, NVME_CQE_SC_GEN_INVALID_VALUE_SIZE, "Invalid Value Size" },
    { NVME_CQE_SC_GEN_INVALID_KEY_SIZE, NVME_CQE_SC_GEN_INVALID_KEY_SIZE, "Invalid Key Size" },
    { NVME_CQE_SC_GEN_KV_KEY_DOES_NOT_EXIST, NVME_CQE_SC_GEN_KV_KEY_DOES_NOT_EXIST, "KV Key Does Not Exist" },
    { NVME_CQE_SC_GEN_UNRECOVERED_ERROR, NVME_CQE_SC_GEN_UNRECOVERED_ERROR, "Unrecovered Error" },
    { NVME_CQE_SC_GEN_KEY_EXISTS, NVME_CQE_SC_GEN_KEY_EXISTS, "Key Exists" },
    { 0x90, 0xbf, "Reserved" },
    { 0xc0, 0xff, "Vendor Specific" },
    { 0, 0, NULL },
};

/* Base 2.4 Figures 103/104. The Fabrics-specific table is independent. */
static const range_string nvme_cqe_sc_cmd_tbl[] = {
    { 0x00, 0x00, "Completion Queue Invalid" },
    { 0x01, 0x01, "Invalid Queue Identifier" },
    { 0x02, 0x02, "Invalid Queue Size" },
    { 0x03, 0x03, "Abort Command Limit Exceeded" },
    { 0x04, 0x04, "Reserved" },
    { 0x05, 0x05, "Asynchronous Event Request Limit Exceeded" },
    { 0x06, 0x06, "Invalid Firmware Slot" },
    { 0x07, 0x07, "Invalid Firmware Image" },
    { 0x08, 0x08, "Invalid Interrupt Vector" },
    { 0x09, 0x09, "Invalid Log Page" },
    { 0x0a, 0x0a, "Invalid Format" },
    { 0x0b, 0x0b, "Firmware Activation Requires Conventional Reset" },
    { 0x0c, 0x0c, "Invalid Queue Deletion" },
    { 0x0d, 0x0d, "Feature Identifier Not Saveable" },
    { 0x0e, 0x0e, "Feature Not Changeable" },
    { 0x0f, 0x0f, "Feature Not Namespace Specific" },
    { 0x10, 0x10, "Firmware Activation Requires NVM Subsystem Reset" },
    { 0x11, 0x11, "Firmware Activation Requires Controller Level Reset" },
    { 0x12, 0x12, "Firmware Activation Requires Maximum Time Violation" },
    { 0x13, 0x13, "Firmware Activation Prohibited" },
    { 0x14, 0x14, "Overlapping Range" },
    { 0x15, 0x15, "Namespace Insufficient Capacity" },
    { 0x16, 0x16, "Namespace Identifier Unavailable" },
    { 0x17, 0x17, "Reserved" },
    { 0x18, 0x18, "Namespace Already Attached" },
    { 0x19, 0x19, "Namespace Is Private" },
    { 0x1a, 0x1a, "Namespace Not Attached" },
    { 0x1b, 0x1b, "Thin Provisioning Not Supported" },
    { 0x1c, 0x1c, "Controller List Invalid" },
    { 0x1d, 0x1d, "Device Self-test In Progress" },
    { 0x1e, 0x1e, "Boot Partition Write Prohibited" },
    { 0x1f, 0x1f, "Invalid Controller Identifier" },
    { 0x20, 0x20, "Invalid Secondary Controller State" },
    { 0x21, 0x21, "Invalid Number of Controller Resources" },
    { 0x22, 0x22, "Invalid Resource Identifier" },
    { 0x23, 0x23, "Sanitize Prohibited While Persistent Memory Region is Enabled" },
    { 0x24, 0x24, "ANA Group Identifier Invalid" },
    { 0x25, 0x25, "ANA Attach Failed" },
    { 0x26, 0x26, "Insufficient Capacity" },
    { 0x27, 0x27, "Namespace Attachment Limit Exceeded" },
    { 0x28, 0x28, "Prohibition of Command Execution Not Supported" },
    { 0x29, 0x29, "I/O Command Set Not Supported" },
    { 0x2a, 0x2a, "I/O Command Set Not Enabled" },
    { 0x2b, 0x2b, "I/O Command Set Combination Rejected" },
    { 0x2c, 0x2c, "Invalid I/O Command Set" },
    { 0x2d, 0x2d, "Identifier Unavailable" },
    { 0x2e, 0x2e, "Namespace Is Dispersed" },
    { 0x2f, 0x2f, "Invalid Discovery Information" },
    { 0x30, 0x30, "Zoning Data Structure Locked" },
    { 0x31, 0x31, "Zoning Data Structure Not Found" },
    { 0x32, 0x32, "Insufficient Discovery Resources" },
    { 0x33, 0x33, "Requested Function Disabled" },
    { 0x34, 0x34, "ZoneGroup Originator Invalid" },
    { 0x35, 0x35, "Invalid Host" },
    { 0x36, 0x36, "Invalid NVM Subsystem" },
    { 0x37, 0x37, "Invalid Controller Data Queue" },
    { 0x38, 0x38, "Not Enough Resources" },
    { 0x39, 0x39, "Controller Suspended" },
    { 0x3a, 0x3a, "Controller Not Suspended" },
    { 0x3b, 0x3b, "Controller Data Queue Full" },
    { 0x3c, 0x3c, "Request Exceeds Maximum Namespace Sanitize Operations In Progress" },
    { 0x3d, 0x3d, "Manufacturing Default Personality Required" },
    { 0x3e, 0x3e, "Invalid Power Limit" },
    { 0x3f, 0x3f, "Cross-Controller Reset in Progress" },
    { 0x40, 0x40, "Cross-Controller Reset Log Page Full" },
    { 0x41, 0x41, "Cross-Controller Reset Limit Exceeded" },
    { 0x42, 0x42, "Controller Active" },
    { 0x43, 0x43, "Invalid Exported Association" },
    { 0x44, 0x44, "Invalid Exported Configuration State" },
    { 0x45, 0x6f, "Reserved" },
    { 0x70, 0x7f, "Directive Specific" },
    { 0x80, 0x80, "Conflicting Attributes" },
    { 0x81, 0x81, "Invalid Protection Information" },
    { 0x82, 0x82, "Attempted Write to Read Only Range" },
    { 0x83, 0x83, "Command Size Limit Exceeded" },
    { 0x84, 0x84, "Invalid Command ID" },
    { 0x85, 0x85, "Incompatible Namespace or Format" },
    { 0x86, 0x86, "Fast Copy Not Possible" },
    { 0x87, 0x87, "Overlapping I/O Range" },
    { 0x88, 0x88, "Namespace Not Reachable" },
    { 0x89, 0x89, "Insufficient Resources" },
    { 0x8a, 0x8a, "Insufficient Program Resources" },
    { 0x8b, 0x8b, "Invalid Memory Namespace" },
    { 0x8c, 0x8c, "Invalid Memory Range Set" },
    { 0x8d, 0x8d, "Invalid Memory Range Set Identifier" },
    { 0x8e, 0x8e, "Invalid Program Data" },
    { 0x8f, 0x8f, "Invalid Program Index" },
    { 0x90, 0x90, "Invalid Program Type" },
    { 0x91, 0x91, "Maximum Memory Ranges Exceeded" },
    { 0x92, 0x92, "Maximum Memory Range Sets Exceeded" },
    { 0x93, 0x93, "Maximum Programs Activated" },
    { 0x94, 0x94, "Maximum Program Bytes Exceeded" },
    { 0x95, 0x95, "Memory Range Set In Use" },
    { 0x96, 0x96, "No Program" },
    { 0x97, 0x97, "Overlapping Memory Ranges" },
    { 0x98, 0x98, "Program Not Activated" },
    { 0x99, 0x99, "Program In Use" },
    { 0x9a, 0x9a, "Program Index Not Downloadable" },
    { 0x9b, 0x9b, "Program Too Big" },
    { 0x9c, 0x9c, "Successful Media Verification Read" },
    { 0x9d, 0xb7, "Reserved" },
    { 0xb8, 0xb8, "Zoned Boundary Error" },
    { 0xb9, 0xb9, "Zone Is Full" },
    { 0xba, 0xba, "Zone Is Read Only" },
    { 0xbb, 0xbb, "Zone Is Offline" },
    { 0xbc, 0xbc, "Zone Invalid Write" },
    { 0xbd, 0xbd, "Too Many Active Zones" },
    { 0xbe, 0xbe, "Too Many Open Zones" },
    { 0xbf, 0xbf, "Invalid Zone State Transition" },
    { 0xc0, 0xff, "Vendor Specific" },
    { 0, 0, NULL },
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

static const range_string nvme_cqe_sc_media_tbl[] = {
    { 0x00, 0x7f, "Reserved" },
    { NVME_CQE_SC_MEDIA_WRITE_FAULT, NVME_CQE_SC_MEDIA_WRITE_FAULT, "Write Fault" },
    { NVME_CQE_SC_MEDIA_READ_FAULT, NVME_CQE_SC_MEDIA_READ_FAULT, "Unrecovered Read Error" },
    { NVME_CQE_SC_MEDIA_ETE_GUARD_CHECK_ERR, NVME_CQE_SC_MEDIA_ETE_GUARD_CHECK_ERR, "End-to-end Guard Check Error" },
    { NVME_CQE_SC_MEDIA_ETE_APPTAG_CHECK_ERR, NVME_CQE_SC_MEDIA_ETE_APPTAG_CHECK_ERR, "End-to-end Application Tag Check Error" },
    { NVME_CQE_SC_MEDIA_ETE_REFTAG_CHECK_ERR, NVME_CQE_SC_MEDIA_ETE_REFTAG_CHECK_ERR, "End-to-end Reference Tag Check Error" },
    { NVME_CQE_SC_MEDIA_COMPARE_FAILURE, NVME_CQE_SC_MEDIA_COMPARE_FAILURE, "Compare Failure" },
    { NVME_CQE_SC_MEDIA_ACCESS_DENIED, NVME_CQE_SC_MEDIA_ACCESS_DENIED, "Access Denied" },
    { NVME_CQE_SC_MEDIA_DEALLOCATED_LBA, NVME_CQE_SC_MEDIA_DEALLOCATED_LBA, "Deallocated or Unwritten Logical Block" },
    { NVME_CQE_SC_MEDIA_ETE_STORAGE_TAG_CHECK_ERR, NVME_CQE_SC_MEDIA_ETE_STORAGE_TAG_CHECK_ERR, "End-to-End Storage Tag Check Error" },
    { 0x89, 0xbf, "Reserved" },
    { 0xc0, 0xff, "Vendor Specific" },
    { 0, 0, NULL },
};

static const range_string nvme_cqe_sc_path_tbl[] = {
    { NVME_CQE_SC_PATH_INTERNAL_PATH_ERROR, NVME_CQE_SC_PATH_INTERNAL_PATH_ERROR, "Internal Path Error" },
    { NVME_CQE_SC_PATH_ANA_PERSISTENT_LOSS, NVME_CQE_SC_PATH_ANA_PERSISTENT_LOSS, "Asymmetric Access Persistent Loss" },
    { NVME_CQE_SC_PATH_ANA_INACCESSIBLE, NVME_CQE_SC_PATH_ANA_INACCESSIBLE, "Asymmetric Access Inaccessible" },
    { NVME_CQE_SC_PATH_ANA_TRANSIENT, NVME_CQE_SC_PATH_ANA_TRANSIENT, "Asymmetric Access Transition" },
    { 0x04, 0x5f, "Reserved" },
    { NVME_CQE_SC_PATH_CNTRL_PATH_ERROR, NVME_CQE_SC_PATH_CNTRL_PATH_ERROR, "Controller Pathing Error" },
    { 0x61, 0x6f, "Reserved" },
    { NVME_CQE_SC_PATH_HOST_PATH_ERROR, NVME_CQE_SC_PATH_HOST_PATH_ERROR, "Host Pathing Error" },
    { NVME_CQE_SC_PATH_CMD_ABORT, NVME_CQE_SC_PATH_CMD_ABORT, "Command Aborted By Host" },
    { 0x72, 0x7f, "Reserved" },
    { 0x80, 0xbf, "I/O Command Set Specific" },
    { 0xc0, 0xff, "Vendor Specific" },
    { 0, 0, NULL },
};

/* Base 2.4 Figure 143 */
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
    { NVME_AQ_OPC_SELF_TEST,     "Device Self-test"},
    { NVME_AQ_OPC_NS_ATTACH,     "Namespace Attachment"},
    { NVME_AQ_OPC_KEEP_ALIVE,    "Keep Alive"},
    { NVME_AQ_OPC_DIRECTIVE_SEND, "Directive Send"},
    { NVME_AQ_OPC_DIRECTIVE_RECV, "Directive Receive"},
    { NVME_AQ_OPC_VIRT_MGMT,     "Virtualization Management"},
    { NVME_AQ_OPC_MI_SEND,       "NVMe-MI Send"},
    { NVME_AQ_OPC_MI_RECV,       "NVMe-MI Receive"},
    { NVME_AQ_OPC_CAP_MGMT,      "Capacity Management"},
    { NVME_AQ_OPC_DISC_INFO_MGMT, "Discovery Information Management"},
    { NVME_AQ_OPC_FABRIC_ZONING_RECV, "Fabric Zoning Receive"},
    { NVME_AQ_OPC_LOCKDOWN,      "Lockdown"},
    { NVME_AQ_OPC_FABRIC_ZONING_LOOKUP, "Fabric Zoning Lookup"},
    { NVME_AQ_OPC_CLEAR_EXP_NVM_CFG, "Clear Exported NVM Resource Configuration"},
    { NVME_AQ_OPC_FABRIC_ZONING_SEND, "Fabric Zoning Send"},
    { NVME_AQ_OPC_CREATE_EXP_NVM_SUBSYS, "Manage Exported NVM Subsystem Receive"},
    { NVME_AQ_OPC_MANAGE_EXP_NVM_SUBSYS, "Manage Exported NVM Subsystem Send"},
    { NVME_AQ_OPC_MANAGE_EXP_NS, "Manage Exported Namespace"},
    { NVME_AQ_OPC_MANAGE_EXP_PORT, "Manage Exported Port"},
    { NVME_AQ_OPC_CROSS_CTRL_RESET, "Cross-Controller Reset"},
    { NVME_AQ_OPC_SEND_DISC_LOG_PAGE, "Send Discovery Log Page"},
    { NVME_AQ_OPC_TRACK_SEND,    "Track Send"},
    { NVME_AQ_OPC_TRACK_RECV,    "Track Receive"},
    { NVME_AQ_OPC_MIGRATION_SEND, "Migration Send"},
    { NVME_AQ_OPC_MIGRATION_RECV, "Migration Receive"},
    { NVME_AQ_OPC_CTRL_DATA_QUEUE, "Controller Data Queue"},
    { NVME_AQ_OPC_DBBUF_CONFIG,  "Doorbell Buffer Config"},
    { NVME_AQ_OPC_FORMAT_NVM,    "Format NVM"},
    { NVME_AQ_OPC_SECURITY_SEND, "Security Send"},
    { NVME_AQ_OPC_SECURITY_RECV, "Security Receive"},
    { NVME_AQ_OPC_SANITIZE,      "Sanitize"},
    { NVME_AQ_OPC_LOAD_PROGRAM,  "Load Program"},
    { NVME_AQ_OPC_GET_LBA_STATUS, "Get LBA Status"},
    { NVME_AQ_OPC_PROG_ACTIVATION_MGMT, "Program Activation Management"},
    { NVME_AQ_OPC_MEM_RANGE_SET_MGMT, "Memory Range Set Management"},
    { NVME_AQ_OPC_SANITIZE_NS,   "Sanitize Namespace"},
    { NVME_FABRIC_OPC,           "Fabrics Commands"},
    { 0, NULL}
};

static const value_string ioq_opc_tbl[] = {
    { NVME_IOQ_OPC_FLUSH,         "Flush"},
    { NVME_IOQ_OPC_WRITE,         "Write"},
    { NVME_IOQ_OPC_READ,          "Read"},
    { NVME_IOQ_OPC_WRITE_UNCORRECTABLE, "Write Uncorrectable"},
    { NVME_IOQ_OPC_COMPARE,       "Compare"},
    { NVME_IOQ_OPC_WRITE_ZEROS,   "Write Zeroes"},
    { NVME_IOQ_OPC_DATASET_MGMT,  "Dataset Management"},
    { NVME_IOQ_OPC_VERIFY,        "Verify"},
    { NVME_IOQ_OPC_RESV_REG,      "Reservation Register"},
    { NVME_IOQ_OPC_RESV_REPORT,   "Reservation Report"},
    { NVME_IOQ_OPC_RESV_ACQUIRE,  "Reservation Acquire"},
    { NVME_IOQ_OPC_IO_MGMT_RECV,  "I/O Management Receive"},
    { NVME_IOQ_OPC_RESV_RELEASE,  "Reservation Release"},
    { NVME_IOQ_OPC_CANCEL,        "Cancel"},
    { NVME_IOQ_OPC_COPY,          "Copy"},
    { NVME_IOQ_OPC_IO_MGMT_SEND,  "I/O Management Send"},
    { 0, NULL}
};

/* aq_opc_tbl/ioq_opc_tbl only cover the assigned opcode space; C0h-FFh
 * (Admin, NVM CS 1.2 Fig 21) and 80h-FFh (I/O, NVM CS 1.2 Fig 21) are
 * Vendor Specific, not Reserved -- special-case them the same way
 * get_logpage_name() does for the logpage table. */
static const char *get_aq_opcode_name(uint8_t opcode)
{
    if (opcode >= 0xC0)
        return "Vendor Specific";
    return val_to_str_const(opcode, aq_opc_tbl, "Reserved");
}

bool
nvme_admin_opcode_is_reserved(uint8_t opcode)
{
    /* Base 2.4 Figure 143 note 1; C0h–FFh is an open vendor allocation. */
    return opcode < 0xc0 && try_val_to_str(opcode, aq_opc_tbl) == NULL;
}

static const char *get_ioq_opcode_name(uint8_t opcode)
{
    if (opcode >= 0x80)
        return "Vendor Specific";
    return val_to_str_const(opcode, ioq_opc_tbl, "Reserved");
}

#define NVME_CMD_SGL_DATA_DESC          0x0
#define NVME_CMD_SGL_BIT_BUCKET_DESC    0x1
#define NVME_CMD_SGL_SEGMENT_DESC       0x2
#define NVME_CMD_SGL_LAST_SEGMENT_DESC  0x3
#define NVME_CMD_SGL_KEYED_DATA_DESC    0x4
#define NVME_CMD_SGL_TRANSPORT_DESC     0x5
#define NVME_CMD_SGL_VENDOR_DESC        0xf

static const value_string sgl_type_tbl[] = {
    { NVME_CMD_SGL_DATA_DESC,         "Data Block"},
    { NVME_CMD_SGL_BIT_BUCKET_DESC,   "Bit Bucket"},
    { NVME_CMD_SGL_SEGMENT_DESC,      "Segment"},
    { NVME_CMD_SGL_LAST_SEGMENT_DESC, "Last Segment"},
    { NVME_CMD_SGL_KEYED_DATA_DESC,   "Keyed Data Block"},
    { NVME_CMD_SGL_TRANSPORT_DESC,    "Transport SGL Data Block descriptor"},
    { NVME_CMD_SGL_VENDOR_DESC,       "Vendor Specific"},
    { 0, NULL}
};

#define NVME_CMD_SGL_SUB_DESC_ADDR      0x0
#define NVME_CMD_SGL_SUB_DESC_OFFSET    0x1
#define NVME_CMD_SGL_SUB_DESC_TRANSPORT 0xf

static const value_string sgl_sub_type_tbl[] = {
    { NVME_CMD_SGL_SUB_DESC_ADDR,      "Address"},
    { NVME_CMD_SGL_SUB_DESC_OFFSET,    "Offset"},
    { 0xa,                             "NVMe Transport Specific"},
    { 0xb,                             "NVMe Transport Specific"},
    { 0xc,                             "NVMe Transport Specific"},
    { 0xd,                             "NVMe Transport Specific"},
    { 0xe,                             "NVMe Transport Specific"},
    { NVME_CMD_SGL_SUB_DESC_TRANSPORT, "Transport specific"},
    { 0, NULL}
};


static const value_string cns_table[] = {
    { 0, "Namespace"},
    { 1, "Controller"},
    { 2, "Active Namespace List"},
    { 3, "Namespace Identification Descriptor"},
    {4, "NVM Set List"},
    {0x5, "I/O Command Set Specific Namespace"},
    {0x6, "I/O Command Set Specific Controller"},
    {0x7, "I/O Command Set Specific Active Namespace List"},
    {0x8, "I/O Command Set Independent Namespace"},
    {0x9, "NVM Command Set Namespace (Format Index)"},
    {0xa, "I/O Command Set Specific Namespace (Format Index)"},
    {0x10, "Allocated Namespace ID List"},
    {0x11, "Namespace (Allocated NSID)"},
    {0x12, "Controller List Attached to NSID"},
    {0x13, "Existing Controllers List"},
    {0x14, "Primary Controller Capabilities"},
    {0x15, "Secondary Controller List"},
    {0x16, "Namespace Granularity List"},
    {0x17, "UUID List"},
    {0x18, "Domain List"},
    {0x19, "Endurance Group List"},
    {0x1a, "I/O Command Set Specific Allocated Namespace ID List"},
    {0x1b, "I/O Command Set Specific Namespace (Allocated NSID)"},
    {0x1c, "I/O Command Set Data Structure"},
    {0x1d, "Get Underlying Namespace List"},
    {0x1e, "Get Ports List"},
    {0x1f, "I/O Command Set Independent Namespace (Allocated NSID)"},
    {0x20, "Supported Controller State Formats"},
    {0x21, "Get Underlying Controller List"},
    {0x22, "Exported NVM Subsystem Template UUID List"},
    {0, NULL}
};

/* Namespace Identifier Type (NIDT), NVMe Base 2.3 "Identify – Namespace
 * Identification Descriptor". */
static const range_string nidt_tbl[] = {
    { 0x0, 0x0, "Reserved" },
    { 0x1, 0x1, "IEEE Extended Unique Identifier (EUI64)" },
    { 0x2, 0x2, "Namespace Globally Unique Identifier (NGUID)" },
    { 0x3, 0x3, "Namespace UUID" },
    { 0x4, 0x4, "Command Set Identifier (CSI)" },
    { 0x5, 0xff, "Reserved" },
    { 0, 0, NULL }
};

/* UUID List Entry Identifier Association (IDASSOC), NVMe Base 2.3 "UUID
 * List Entry". */
static const value_string uuid_idassoc_tbl[] = {
    { 0x0, "No association reported" },
    { 0x1, "Associated with PCI Vendor ID" },
    { 0x2, "Associated with PCI Subsystem Vendor ID" },
    { 0x3, "Reserved" },
    { 0, NULL }
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
nvme_publish_qid(proto_tree *tree, int field_index, uint16_t qid)
{
    proto_item *cmd_ref_item;

    cmd_ref_item = proto_tree_add_uint_format_value(tree, field_index, NULL,
                       0, 0, qid,
                     qid ? "%d (IOQ)" : "%d (AQ)",
                                     qid);

    proto_item_set_generated(cmd_ref_item);
}

static void nvme_build_pending_cmd_key(wmem_tree_key_t *cmd_key, uint32_t *key)
{
    cmd_key[0].length = 1;
    cmd_key[0].key = key;
    cmd_key[1].length = 0;
    cmd_key[1].key = NULL;
}

static void
nvme_build_done_frame_key(wmem_tree_key_t *cmd_key, uint32_t *key, uint32_t *frame)
{
    unsigned idx = 0;
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
                             void *ctx, uint16_t cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    uint32_t key = cmd_id;

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

void* nvme_lookup_cmd_in_pending_list(struct nvme_q_ctx *q_ctx, uint16_t cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    uint32_t key = cmd_id;

    nvme_build_pending_cmd_key(cmd_key, &key);
    return wmem_tree_lookup32_array(q_ctx->pending_cmds, cmd_key);
}


static void nvme_build_pending_transfer_key(wmem_tree_key_t *key, struct keyed_data_req *req)
{
    key[0].length = 2;
    key[0].key = (uint32_t *)&req->addr;
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
                       struct nvme_cmd_ctx *cmd_ctx, uint32_t rkey, uint32_t frame_num)
{
    wmem_tree_key_t cmd_key[3];

    nvme_build_done_frame_key(cmd_key, &rkey, &frame_num);
    wmem_tree_insert32_array(q_ctx->data_responses, cmd_key, (void*)cmd_ctx);
}

struct nvme_cmd_ctx*
nvme_lookup_data_tr_pkt(struct nvme_q_ctx *q_ctx,
                          uint32_t rkey, uint32_t frame_num)
{
    wmem_tree_key_t cmd_key[3];

    nvme_build_done_frame_key(cmd_key, &rkey, &frame_num);
    return (struct nvme_cmd_ctx*)wmem_tree_lookup32_array(q_ctx->data_responses, cmd_key);
}

void
nvme_add_data_tr_off(struct nvme_q_ctx *q_ctx, uint32_t off, uint32_t frame_num)
{
    wmem_tree_key_t cmd_key[2];

    nvme_build_done_frame_key(cmd_key, NULL, &frame_num);
    wmem_tree_insert32_array(q_ctx->data_offsets, cmd_key, GUINT_TO_POINTER(off));
}

uint32_t
nvme_lookup_data_tr_off(struct nvme_q_ctx *q_ctx, uint32_t frame_num)
{
    wmem_tree_key_t cmd_key[2];

    nvme_build_done_frame_key(cmd_key, NULL, &frame_num);
    return GPOINTER_TO_UINT(wmem_tree_lookup32_array(q_ctx->data_offsets, cmd_key));
}

/* Set above the 16-bit CID in a done-list key for the completion's frame.
 * A completed command's CID may be reused, so one frame can hold the
 * completion of one command and another command with the same CID; each
 * keeps its own entry. */
#define NVME_DONE_KEY_CQE 0x10000

void
nvme_add_cmd_cqe_to_done_list(struct nvme_q_ctx *q_ctx,
                              struct nvme_cmd_ctx *cmd_ctx, uint16_t cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    uint32_t key;
    uint32_t frame_num;

    nvme_build_done_frame_key(cmd_key, &key, &frame_num);

    /* found matching entry. Add entries to the matched table for both cmd and cqe.
     */
    key = cmd_id | NVME_DONE_KEY_CQE;
    frame_num = cmd_ctx->cqe_pkt_num;
    wmem_tree_insert32_array(q_ctx->done_cmds, cmd_key, (void*)cmd_ctx);

    key = cmd_id;
    frame_num = cmd_ctx->cmd_pkt_num;
    wmem_tree_insert32_array(q_ctx->done_cmds, cmd_key, (void*)cmd_ctx);
}

void*
nvme_lookup_cmd_in_done_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             uint16_t cmd_id, bool is_cqe)
{
    wmem_tree_key_t cmd_key[3];
    uint32_t key = cmd_id | (is_cqe ? NVME_DONE_KEY_CQE : 0);
    uint32_t frame_num = pinfo->num;

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
                                       uint32_t pkt_no, bool zero_ok)
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
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->cmd_pkt_num, true);
}

void
nvme_publish_to_cqe_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->cqe_pkt_num, false);
}

void
nvme_publish_to_data_req_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->data_req_pkt_num, false);
}

static void
nvme_publish_to_data_tr_links(proto_tree *tree, tvbuff_t *tvb,
                             int *index_arr, struct nvme_cmd_ctx *cmd_ctx)
{
    unsigned i;
    for (i = 0; i < NVME_CMD_MAX_TRS; i++)
        nvme_publish_link(tree, tvb, index_arr[i], cmd_ctx->data_tr_pkt_num[i], false);
}

void nvme_publish_to_data_resp_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->data_tr_pkt_num[0], false);
}

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                          int field_index, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, unsigned cmd_off, bool visited)
{
    proto_item *ti, *sgl_tree, *type_item, *sub_type_item;
    uint8_t sgl_identifier, desc_type, desc_sub_type;
    int offset = 24 + cmd_off;

    ti = proto_tree_add_item(cmd_tree, field_index, cmd_tvb, offset,
                             16, ENC_NA);
    sgl_tree = proto_item_add_subtree(ti, ett_data);

    sgl_identifier = tvb_get_uint8(cmd_tvb, offset + 15);
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
    case NVME_CMD_SGL_TRANSPORT_DESC:
        /* NVMe Base 2.3 Figure 123: no Address; 11:08 is the Length. */
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_addr_rsvd, cmd_tvb,
                            offset, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_len, cmd_tvb,
                            offset + 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_rsvd, cmd_tvb,
                            offset + 12, 3, ENC_NA);
        break;
    case NVME_CMD_SGL_VENDOR_DESC:
    default:
        break;
    }
}

static void
dissect_nvme_rwc_common_word_10_11_12_14_15(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                            bool is_write)
{
    proto_item *ti, *prinfo_tree;

    /* word 10, 11 */
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_slba, cmd_tvb,
                        40, 8, ENC_LITTLE_ENDIAN);

    /* word 12 */
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_nlb, cmd_tvb,
                        48, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_cmd_rsvd2, cmd_tvb,
                        50, 2, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(cmd_tree, hf_nvme_cmd_prinfo, cmd_tvb, 50,
                             2, ENC_LITTLE_ENDIAN);
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

    /* word 14, 15 (NVM CS 1.2 Figures 56/57 Read, 73/74 Write) */
    proto_tree_add_item(cmd_tree,
                        is_write ? hf_nvme_cmd_lbtl : hf_nvme_cmd_elbtl,
                        cmd_tvb, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree,
                        is_write ? hf_nvme_cmd_lbat : hf_nvme_cmd_elbat,
                        cmd_tvb, 60, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree,
                        is_write ? hf_nvme_cmd_lbatm : hf_nvme_cmd_elbatm,
                        cmd_tvb, 62, 2, ENC_LITTLE_ENDIAN);
}


/* Relative Performance (RP), LBA Format bits 25:24 (NVM CS 1.2 Figure 116). */
static const value_string ns_lbaf_rp_tbl[] = {
    { 0, "Best performance" },
    { 1, "Better performance" },
    { 2, "Good performance" },
    { 3, "Degraded performance" },
    { 0, NULL }
};

static bool nvme_window_intersect(unsigned off, unsigned len, unsigned struct_off,
                                  unsigned struct_len, unsigned *rel_off, unsigned *n);

static void dissect_nvme_identify_ns_lbafs(tvbuff_t *cmd_tvb, packet_info *pinfo, proto_tree *cmd_tree,
                                           unsigned off, unsigned len)
{
    proto_item *ti, *item;
    proto_tree *lbafs_tree;
    unsigned rel, n, first, last, nlbaf = 64, i;
    uint8_t lbads;
    uint16_t ms;
    uint32_t lbaf_raw;
    bool over_declared = false;

    if (!nvme_window_intersect(off, len, 128, 256, &rel, &n))
        return;
    /* NLBAF+1+NULBAF formats are supported, at most the 64 that 383:128
     * holds (NVM CS 1.2 section 5.5); clamp there.  Without both counts in
     * the window, label every complete visible slot instead. */
    if (!off && len >= 83) {
        nlbaf = tvb_get_uint8(cmd_tvb, 25) + 1 + tvb_get_uint8(cmd_tvb, 82);
        over_declared = (nlbaf > 64);
        if (over_declared)
            nlbaf = 64;
    }

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_lbafs, cmd_tvb, rel, n, ENC_NA);
    /* The count is intrinsically impossible rather than merely unseen: the
     * 383:128 region holds exactly 64 entries, so no transfer window can make
     * NLBAF+1+NULBAF > 64 legitimate. */
    if (over_declared)
        expert_add_info(pinfo, ti, &ei_nvme_lbaf_count_invalid);
    lbafs_tree = proto_item_add_subtree(ti, ett_data);

    unsigned first_byte = off + rel - 128;
    unsigned lead = MIN((4 - first_byte % 4) % 4, n);
    if (lead)
        proto_tree_add_item(cmd_tree, hf_nvme_window_partial, cmd_tvb, rel, lead, ENC_NA);
    first = (first_byte + lead) / 4;
    last = first + (n - lead) / 4;
    for (i = first; i < last && i < nlbaf; i++) {
        unsigned lbaf_off = 128 + i * 4 - off;

        /* NVM CS 1.2 Figure 116: MS 15:00, LBADS 23:16, RP 25:24. */
        item = proto_tree_add_item_ret_uint(lbafs_tree, hf_nvme_identify_ns_lbaf,
                                   cmd_tvb, lbaf_off, 4, ENC_LITTLE_ENDIAN, &lbaf_raw);
        ms = lbaf_raw & 0xFFFF;
        lbads = (lbaf_raw >> 16) & 0xFF;
        proto_item_append_text(item, " (LBAF%u: LBADS %d, MS %d, RP %s)", i, lbads, ms,
                               val_to_str_const((lbaf_raw >> 24) & 0x3, ns_lbaf_rp_tbl, "Reserved"));
    }
    unsigned tail = (n - lead) % 4;
    if (tail)
        proto_tree_add_item(cmd_tree, hf_nvme_window_partial, cmd_tvb, rel + n - tail, tail, ENC_NA);
}

/* Protection Information Type (PIT), NVM CS 1.2 Figure 114 byte 29. */
static const range_string ns_dps_pit_tbl[] = {
    { 0, 0, "Protection information is not enabled" },
    { 1, 1, "Type 1 protection information is enabled" },
    { 2, 2, "Type 2 protection information is enabled" },
    { 3, 3, "Type 3 protection information is enabled" },
    { 4, 7, "Reserved" },
    { 0, 0, NULL }
};

/* Deallocation Read Behavior (DRB), the low 3 bits of DLFEAT. */
static const range_string ns_dlfeat_drb_tbl[] = {
    { 0, 0, "read behavior is not reported" },
    { 1, 1, "deallocated logical block returns all bytes cleared to 0h" },
    { 2, 2, "deallocated logical block returns all bytes set to FFh" },
    { 3, 7, "Reserved" },
    { 0, 0, NULL }
};

#define ASPEC(_x_) _x_, array_length(_x_)

/* Both defined further down; used here for the bit-defined bytes (DLFEAT,
 * KPIOS) and the 16-byte NVM Capacity of the Identify Namespace structure. */
static proto_tree *add_group_mask_entry(tvbuff_t *tvb, proto_tree *tree, unsigned offset, unsigned bytes, int *array, unsigned array_len);
static void post_add_bytes_from_16bytes(proto_item *ti, tvbuff_t *tvb, unsigned off);
static bool nvme_field_in_window(unsigned off, unsigned len, unsigned struct_off, unsigned field_len, unsigned *rel_off);

/* A fixed field of a windowed structure: one hf, or a bitmask array for
 * add_group_mask_entry(). */
typedef struct {
    uint16_t pos, size;
    int     *hf;
    unsigned n_hf;          /* 0 for a single hf */
    unsigned encoding;      /* single hf only */
    void   (*post)(proto_item *ti, tvbuff_t *tvb, unsigned off); /* single hf only */
} nvme_window_field;
#define NVME_WF(p, s, h, enc) { p, s, &h, 0, enc, NULL }
#define NVME_WFP(p, s, h, enc, post) { p, s, &h, 0, enc, post }
#define NVME_WG(p, s, arr)    { p, s, arr, array_length(arr), 0, NULL }

/* Add each field intersecting the window, in order; false at the first one
 * that runs past the window, where the caller stops parsing. The window's
 * structure offset 'off' is at tvb offset 'base'. */
static bool
nvme_add_window_fields_at_internal(tvbuff_t *tvb, proto_tree *tree, unsigned base,
                                   unsigned off, unsigned len,
                                   const nvme_window_field *f, unsigned n,
                                   bool partial_fields)
{
    if (!len)
        return true;

    for (unsigned i = 0; i < n; i++) {
        unsigned field_end = f[i].pos + f[i].size;
        unsigned at, field_len, rel;

        if (!partial_fields) {
            if (off > f[i].pos)
                continue;
            rel = f[i].pos - off;
            if (rel >= len || f[i].size > len - rel)
                return false;
            at = base + rel;
            if (f[i].n_hf) {
                add_group_mask_entry(tvb, tree, at, f[i].size, f[i].hf, f[i].n_hf);
            } else {
                proto_item *ti = proto_tree_add_item(tree, *f[i].hf, tvb, at, f[i].size,
                                                     f[i].encoding);
                if (f[i].post)
                    f[i].post(ti, tvb, at);
            }
            continue;
        }

        if (field_end <= off)
            continue;
        if (f[i].pos < off) {
            field_len = MIN(field_end - off, len);
            proto_tree_add_item(tree, hf_nvme_window_partial, tvb, base,
                                field_len, ENC_NA);
            if (field_end - off > len)
                return false;
            continue;
        }
        rel = f[i].pos - off;
        if (rel >= len)
            return false;
        at = base + rel;
        if (f[i].size > len - rel) {
            field_len = len - rel;
            proto_tree_add_item(tree, hf_nvme_window_partial, tvb, at,
                                field_len, ENC_NA);
            return false;
        }
        if (f[i].n_hf) {
            add_group_mask_entry(tvb, tree, at, f[i].size, f[i].hf, f[i].n_hf);
        } else {
            proto_item *ti = proto_tree_add_item(tree, *f[i].hf, tvb, at, f[i].size,
                                                 f[i].encoding);
            if (f[i].post)
                f[i].post(ti, tvb, at);
        }
    }
    return true;
}

static bool
nvme_add_window_fields_at(tvbuff_t *tvb, proto_tree *tree, unsigned base,
                          unsigned off, unsigned len,
                          const nvme_window_field *f, unsigned n)
{
    return nvme_add_window_fields_at_internal(tvb, tree, base, off, len, f, n, false);
}

static bool
nvme_add_identify_window_fields_at(tvbuff_t *tvb, proto_tree *tree, unsigned base,
                                   unsigned off, unsigned len,
                                   const nvme_window_field *f, unsigned n)
{
    return nvme_add_window_fields_at_internal(tvb, tree, base, off, len, f, n, true);
}

/* True when the field at pos starts in the window but runs past its end,
 * where a windowed decoder stops parsing. */
static bool
nvme_window_cut(unsigned off, unsigned len, unsigned pos, unsigned size)
{
    return off <= pos && pos - off + size > len;
}

static bool
nvme_add_window_fields(tvbuff_t *tvb, proto_tree *tree, unsigned off, unsigned len,
                       const nvme_window_field *f, unsigned n)
{
    return nvme_add_window_fields_at(tvb, tree, 0, off, len, f, n);
}

static bool
nvme_add_identify_window_fields(tvbuff_t *tvb, proto_tree *tree, unsigned off, unsigned len,
                                const nvme_window_field *f, unsigned n)
{
    return nvme_add_identify_window_fields_at(tvb, tree, 0, off, len, f, n);
}

static bool
nvme_add_window_field(tvbuff_t *tvb, proto_tree *tree, int hf, unsigned off,
                      unsigned len, unsigned pos, unsigned size, unsigned encoding)
{
    unsigned rel;

    if (pos < off)
        return true;
    rel = pos - off;
    if (rel >= len || size > len - rel)
        return false;
    proto_tree_add_item(tree, hf, tvb, rel, size, encoding);
    return true;
}

#define NVME_WINDOW_RAW "Structure-specific decode skipped; the bytes are shown raw"

/* Why a window is not decoded further.  It is not an anomaly in the
 * packet, so it is shown under the item rather than as an expert info. */
static void
nvme_add_window_note(proto_item *ti, const char *note)
{
    proto_tree *tree = proto_item_get_subtree(ti);
    proto_item *note_it;

    if (!tree)
        tree = proto_item_add_subtree(ti, ett_data);
    note_it = proto_tree_add_string(tree, hf_nvme_window_decode_skipped, NULL, 0, 0, note);
    proto_item_set_generated(note_it);
}

static bool
nvme_add_identify_window_field(tvbuff_t *tvb, proto_tree *tree, int hf, unsigned off,
                               unsigned len, unsigned pos, unsigned size, unsigned encoding)
{
    unsigned rel;

    if (pos >= off) {
        rel = pos - off;
        if (rel >= len)
            return true;
        if (size <= len - rel) {
            proto_tree_add_item(tree, hf, tvb, rel, size, encoding);
            return true;
        }
        proto_tree_add_item(tree, hf_nvme_window_partial, tvb, rel, len - rel, ENC_NA);
        return false;
    }

    unsigned field_skip = off - pos;
    if (size > field_skip) {
        unsigned field_remaining = size - field_skip;
        unsigned partial_len = MIN(field_remaining, len);
        if (partial_len)
            proto_tree_add_item(tree, hf_nvme_window_partial, tvb, 0,
                                partial_len, ENC_NA);
        return field_remaining <= len;
    }

    return true;
}

/* The part of window [off, off+len) inside the structure region. The ends are
 * computed in 64 bits so that a window or structure ending at 2^32 does not
 * wrap and drop the intersection. */
static bool
nvme_window_intersect(unsigned off, unsigned len, unsigned struct_off,
                      unsigned struct_len, unsigned *rel_off, unsigned *n)
{
    uint64_t win_end = (uint64_t)off + len;
    uint64_t struct_end = (uint64_t)struct_off + struct_len;
    uint64_t lo, hi;

    if (off >= struct_end || win_end <= struct_off)
        return false;
    lo = MAX((uint64_t)off, (uint64_t)struct_off);
    hi = MIN(win_end, struct_end);
    *rel_off = (unsigned)(lo - off);
    *n = (unsigned)(hi - lo);
    return true;
}

static bool
nvme_tvb_is_zero(tvbuff_t *tvb, unsigned at, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        if (tvb_get_uint8(tvb, at + i))
            return false;
    return true;
}

/* End of the last non-zero byte in [from, to), or from when all are zero, so
 * that "bytes [pos, to) are all zero" is the single test pos >= end. */
static unsigned
nvme_tvb_nonzero_end(tvbuff_t *tvb, unsigned from, unsigned to)
{
    for (unsigned i = to; i > from; i--)
        if (tvb_get_uint8(tvb, i - 1))
            return i;
    return from;
}

/* A fixed-stride entry list of a windowed structure. */
typedef struct {
    unsigned first;             /* structure offset of entry 0 */
    unsigned stride;
    unsigned max;               /* entries the structure holds */
    unsigned idx_base;          /* label of entry 0 */
    const char *name;           /* NULL: the fields are added flat */
    const nvme_window_field *f;
    unsigned n_f;
} nvme_window_list;

#define NVME_LIST_COUNT_UNKNOWN UINT_MAX
#define NVME_UNDERLYING_NS_MAX 12

/* Entries [0, count) of the list that the window reaches. When the count's
 * header is outside the window, all-zero entries are skipped. */
static void
nvme_add_window_list(tvbuff_t *tvb, proto_tree *tree, unsigned off, unsigned len,
                     const nvme_window_list *l, unsigned count, bool raw_cuts,
                     bool partial_fields)
{
    unsigned rel, n, j;
    uint64_t lo, hi;

    if (!nvme_window_intersect(off, len, l->first, l->stride * l->max, &rel, &n))
        return;
    /* 64-bit: a window ending at 2^32 must not wrap hi to zero. */
    lo = (uint64_t)off + rel;
    hi = lo + n;
    for (unsigned i = (unsigned)((lo - l->first) / l->stride); i < l->max && i < count; i++) {
        uint64_t e = (uint64_t)l->first + (uint64_t)i * l->stride;
        uint64_t s = MAX(e, lo), t = MIN(e + l->stride, hi);
        unsigned s_rel, s_len, e_rel, e_len;
        proto_tree *grp = tree;

        if (s >= t)
            break;
        s_rel = (unsigned)(s - off);
        s_len = (unsigned)(t - s);
        e_len = (unsigned)(t - e);
        e_rel = (unsigned)(e - off);   /* only used when the entry starts in the window */
        if (count == NVME_LIST_COUNT_UNKNOWN && nvme_tvb_is_zero(tvb, s_rel, s_len))
            continue;
        if (s > e) {
            if (partial_fields) {
                unsigned rs = (unsigned)(s - e), rt = e_len;
                bool any = false;

                for (j = 0; j < l->n_f; j++) {
                    if (l->f[j].pos < rt && (unsigned)l->f[j].pos + l->f[j].size > rs) {
                        any = true;
                        break;
                    }
                }
                if (l->name)
                    grp = proto_tree_add_subtree_format(tree, tvb, s_rel, s_len, ett_data, NULL,
                                                        "%s %u", l->name, i + l->idx_base);
                if (any)
                    nvme_add_identify_window_fields_at(tvb, grp, s_rel, rs, s_len, l->f, l->n_f);
                else
                    proto_tree_add_item(grp, hf_nvme_gen_data, tvb, s_rel, s_len, ENC_NA);
            } else if (raw_cuts)
                proto_tree_add_item(tree, hf_nvme_gen_data, tvb, s_rel, s_len, ENC_NA);
            continue;
        }
        if (l->name)
            grp = proto_tree_add_subtree_format(tree, tvb, s_rel, s_len, ett_data, NULL,
                                                "%s %u", l->name, i + l->idx_base);
        if (partial_fields)
            nvme_add_identify_window_fields_at(tvb, grp, e_rel, 0, e_len, l->f, l->n_f);
        else
            nvme_add_window_fields_at(tvb, grp, e_rel, 0, e_len, l->f, l->n_f);
        for (j = 0; j < l->n_f && (unsigned)l->f[j].pos + l->f[j].size <= e_len; j++)
            ;
        if (raw_cuts && !partial_fields && j < l->n_f && l->f[j].pos < e_len)
            proto_tree_add_item(grp, hf_nvme_gen_data, tvb, e_rel + l->f[j].pos,
                                e_len - l->f[j].pos, ENC_NA);
    }
}

static void dissect_nvme_identify_ns_resp(tvbuff_t *cmd_tvb, packet_info *pinfo,
                                            proto_tree *cmd_tree, unsigned off, unsigned len)
{
    proto_item *ti;
    unsigned start;

    /* NVM 1.2 Figure 114 (also CNS 09h): each complete field only. */
    static const nvme_window_field ns_fields[] = {
        NVME_WF(0, 8, hf_nvme_identify_ns_nsze, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 8, hf_nvme_identify_ns_ncap, ENC_LITTLE_ENDIAN),
        NVME_WF(16, 8, hf_nvme_identify_ns_nuse, ENC_LITTLE_ENDIAN),
        NVME_WG(24, 1, hf_nvme_identify_ns_nsfeat),
        NVME_WF(25, 1, hf_nvme_identify_ns_nlbaf, ENC_LITTLE_ENDIAN),
        NVME_WG(26, 1, hf_nvme_identify_ns_flbas),
        NVME_WG(27, 1, hf_nvme_identify_ns_mc),
        NVME_WG(28, 1, hf_nvme_identify_ns_dpc),
        NVME_WG(29, 1, hf_nvme_identify_ns_dps),
        NVME_WG(30, 1, hf_nvme_identify_ns_nmic),
        NVME_WG(31, 1, hf_nvme_identify_ns_rescap),
        NVME_WG(32, 1, hf_nvme_identify_ns_fpi),
        NVME_WG(33, 1, hf_nvme_identify_ns_dlfeat),
        NVME_WF(34, 2, hf_nvme_identify_ns_nawun, ENC_LITTLE_ENDIAN),
        NVME_WF(36, 2, hf_nvme_identify_ns_nawupf, ENC_LITTLE_ENDIAN),
        NVME_WF(38, 2, hf_nvme_identify_ns_nacwu, ENC_LITTLE_ENDIAN),
        NVME_WF(40, 2, hf_nvme_identify_ns_nabsn, ENC_LITTLE_ENDIAN),
        NVME_WF(42, 2, hf_nvme_identify_ns_nabo, ENC_LITTLE_ENDIAN),
        NVME_WF(44, 2, hf_nvme_identify_ns_nabspf, ENC_LITTLE_ENDIAN),
        NVME_WF(46, 2, hf_nvme_identify_ns_noiob, ENC_LITTLE_ENDIAN),
        NVME_WFP(48, 16, hf_nvme_identify_ns_nvmcap, ENC_NA, post_add_bytes_from_16bytes),
        NVME_WF(64, 2, hf_nvme_identify_ns_npwg, ENC_LITTLE_ENDIAN),
        NVME_WF(66, 2, hf_nvme_identify_ns_npwa, ENC_LITTLE_ENDIAN),
        NVME_WF(68, 2, hf_nvme_identify_ns_npdg, ENC_LITTLE_ENDIAN),
        NVME_WF(70, 2, hf_nvme_identify_ns_npda, ENC_LITTLE_ENDIAN),
        NVME_WF(72, 2, hf_nvme_identify_ns_nows, ENC_LITTLE_ENDIAN),
        NVME_WF(74, 2, hf_nvme_identify_ns_mssrl, ENC_LITTLE_ENDIAN),
        NVME_WF(76, 4, hf_nvme_identify_ns_mcl, ENC_LITTLE_ENDIAN),
        NVME_WF(80, 1, hf_nvme_identify_ns_msrc, ENC_LITTLE_ENDIAN),
        NVME_WG(81, 1, hf_nvme_identify_ns_kpios),
        NVME_WF(82, 1, hf_nvme_identify_ns_nulbaf, ENC_LITTLE_ENDIAN),
        NVME_WF(83, 1, hf_nvme_identify_ns_rsvd0, ENC_NA),
        NVME_WF(84, 4, hf_nvme_identify_ns_kpiodaag, ENC_LITTLE_ENDIAN),
        NVME_WF(88, 4, hf_nvme_identify_ns_rsvd1, ENC_NA),
        NVME_WF(92, 4, hf_nvme_identify_ns_anagrpid, ENC_LITTLE_ENDIAN),
        NVME_WF(96, 3, hf_nvme_identify_ns_rsvd2, ENC_NA),
        NVME_WG(99, 1, hf_nvme_identify_ns_nsattr),
        NVME_WF(100, 2, hf_nvme_identify_ns_nvmsetid, ENC_LITTLE_ENDIAN),
        NVME_WF(102, 2, hf_nvme_identify_ns_endgid, ENC_LITTLE_ENDIAN),
        NVME_WF(104, 16, hf_nvme_identify_ns_nguid, ENC_NA),
        NVME_WF(120, 8, hf_nvme_identify_ns_eui64, ENC_NA),
    };

    nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, ns_fields,
                           array_length(ns_fields));

    dissect_nvme_identify_ns_lbafs(cmd_tvb, pinfo, cmd_tree, off, len);
    if (off >= 384)
        start = 0;
    else
        start = 384 - off;
    /* Vendor-specific area (structure offset 384+).  Only render it once the
     * transfer window actually reaches it; a shorter chunk carries no VS bytes
     * (and 'len - start' would otherwise underflow). */
    if (start < len) {
        ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ns_vs, cmd_tvb,
                            start, len - start, ENC_NA);
        proto_item_append_text(ti, " (offset %u)", (off <= 384) ? 0 : off-384);
    }
}

/* NSTAT.IOI (I/O Impacted) sub-field, NVMe Base 2.3 Figure 335. */
static const value_string cs_ind_ns_ioi_tbl[] = {
    { 0, "I/O performance degradation is not reported" },
    { 1, "Reserved" },
    { 2, "I/O performance is not currently degraded" },
    { 3, "I/O performance is currently degraded" },
    { 0, NULL }
};

/* Identify - I/O Command Set Independent Identify Namespace (CNS 08h), NVMe
 * Base 2.3 Figure 335.  The defined fields occupy bytes 23:00; 4095:24 is
 * reserved.  Windowed the same way as the sibling Identify decoders: each
 * field renders only when the transfer window starts at or before it, and
 * decoding stops cleanly on a DLEN-truncated chunk. */
static void dissect_nvme_identify_cs_ind_ns_fields(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, unsigned off, unsigned len)
{
    static const nvme_window_field cs_ind_ns_fields0[] = {
        NVME_WG(0, 1, hf_nvme_identify_cs_ind_ns_nsfeat),
        NVME_WG(1, 1, hf_nvme_identify_cs_ind_ns_nmic),
        NVME_WG(2, 1, hf_nvme_identify_cs_ind_ns_rescap),
        NVME_WG(3, 1, hf_nvme_identify_cs_ind_ns_fpi),
        NVME_WF(4, 4, hf_nvme_identify_cs_ind_ns_anagrpid, ENC_LITTLE_ENDIAN),
        NVME_WG(8, 1, hf_nvme_identify_cs_ind_ns_nsattr),
        NVME_WF(9, 1, hf_nvme_identify_cs_ind_ns_rsvd0, ENC_NA),
        NVME_WF(10, 2, hf_nvme_identify_cs_ind_ns_nvmsetid, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 2, hf_nvme_identify_cs_ind_ns_endgid, ENC_LITTLE_ENDIAN),
        NVME_WG(14, 1, hf_nvme_identify_cs_ind_ns_nstat),
        NVME_WG(15, 1, hf_nvme_identify_cs_ind_ns_kpios),
        NVME_WF(16, 2, hf_nvme_identify_cs_ind_ns_maxkt, ENC_LITTLE_ENDIAN),
        NVME_WF(18, 2, hf_nvme_identify_cs_ind_ns_rsvd1, ENC_NA),
        NVME_WF(20, 4, hf_nvme_identify_cs_ind_ns_rgrpid, ENC_LITTLE_ENDIAN),
    };
    nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, cs_ind_ns_fields0,
                           array_length(cs_ind_ns_fields0));
}

/* CNS 08h and 1Fh (NVMe Base 2.3 section 5.2.13.2.20); cut fields raw. */
static void dissect_nvme_identify_cs_ind_ns_resp(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, unsigned off, unsigned len)
{
    unsigned end = off + len;

    dissect_nvme_identify_cs_ind_ns_fields(cmd_tvb, cmd_tree, off, len);
    if (end > 24)
        proto_tree_add_item(cmd_tree, hf_nvme_identify_cs_ind_ns_rsvd2, cmd_tvb,
                            MAX(off, 24) - off, end - MAX(off, 24), ENC_NA);
}

static void dissect_nvme_identify_nslist_resp(tvbuff_t *cmd_tvb,
                                              proto_tree *cmd_tree, unsigned off, unsigned len)
{
    uint32_t nsid;
    proto_item *item;
    /* A window starting inside an entry leaves its cut bytes uninterpreted. */
    unsigned done = MIN((4 - off % 4) % 4, len);

    if (done)
        proto_tree_add_item(cmd_tree, hf_nvme_window_partial, cmd_tvb, 0, done, ENC_NA);
    for (; off + done < 4096 && (done + 4) <= len; done += 4) {
        nsid = tvb_get_uint32(cmd_tvb, done, ENC_LITTLE_ENDIAN);
        if (nsid == 0)
            break;

        item = proto_tree_add_uint(cmd_tree, hf_nvme_identify_nslist_nsid,
                                   cmd_tvb, done, 4, nsid);
        proto_item_set_text(item, "nsid[%u]: %u", (off + done) / 4, nsid);
    }
    /* Unused entries are raw; a trailing fragment is a partial field. */
    if (done < len) {
        unsigned remaining = len - done;
        proto_tree_add_item(cmd_tree, remaining < 4 ? hf_nvme_window_partial : hf_nvme_gen_data,
                            cmd_tvb, done, remaining, ENC_NA);
    }
}

/* Namespace Identification Descriptor list (CNS 03h), NVMe Base 2.3 Figure
 * 331: a packed list of variable-length descriptors, each NIDT(1)+NIDL(1)+
 * reserved(2)+NID(NIDL), terminated by a descriptor with NIDL == 0.  The list
 * is self-delimiting and cannot be resynchronised from a mid-structure window,
 * so only a transfer starting at structure offset 0 is decoded. */
static void dissect_nvme_identify_nsid_desc_list_resp(tvbuff_t *cmd_tvb, packet_info *pinfo,
                                              proto_tree *cmd_tree, unsigned off, unsigned len)
{
    unsigned done = 0;
    unsigned idx = 0;
    unsigned want;
    uint8_t nidt;
    proto_item *ti;

    if (off)
        return;

    while (done + 4 <= len) {
        uint8_t nidl = tvb_get_uint8(cmd_tvb, done + 1);
        unsigned dlen;
        proto_tree *grp;

        if (nidl == 0)
            break;          /* NIDL 0h marks the end of the list */
        dlen = 4u + nidl;
        if (done + dlen > len)
            break;          /* descriptor would overrun the payload */

        grp = proto_tree_add_subtree_format(cmd_tree, cmd_tvb, done, dlen,
                                            ett_data, NULL,
                                            "Namespace Identification Descriptor %u", idx);
        proto_tree_add_item_ret_uint8(grp, hf_nvme_identify_nsdesc_nidt, cmd_tvb, done, 1, ENC_NA, &nidt);
        ti = proto_tree_add_uint(grp, hf_nvme_identify_nsdesc_nidl, cmd_tvb, done + 1, 1, nidl);
        /* Figure 331: each defined NIDT has a fixed NIDL. */
        want = nidt == 1 ? 8 : (nidt == 2 || nidt == 3) ? 16 : nidt == 4 ? 1 : 0;
        if (want && nidl != want)
            expert_add_info_format(pinfo, ti, &ei_nvme_nidl_mismatch,
                                   "NIDL %u does not match the %u bytes NIDT %u requires (NVMe Base 'Identify - Namespace Identification Descriptor')",
                                   nidl, want, nidt);
        proto_tree_add_item(grp, hf_nvme_identify_nsdesc_rsvd, cmd_tvb, done + 2, 2, ENC_NA);
        if (nidt == 4 && nidl == 1)
            proto_tree_add_item(grp, hf_nvme_identify_nsdesc_csi, cmd_tvb, done + 4, 1, ENC_NA);
        else
            proto_tree_add_item(grp, hf_nvme_identify_nsdesc_nid, cmd_tvb, done + 4, nidl, ENC_NA);

        done += dlen;
        idx++;
    }
}

/* Base 2.3 Fig 138; an impossible count is not clamped. */
unsigned
nvme_dissect_controller_list(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, unsigned off, unsigned len, int hf_count, int hf_id)
{
    uint32_t numcids;
    unsigned done = 2;
    proto_item *ti;

    if (len < 2)
        return 0;
    ti = proto_tree_add_item_ret_uint(tree, hf_count, tvb, off, 2,
                                      ENC_LITTLE_ENDIAN, &numcids);
    if (numcids > 2047)
        expert_add_info(pinfo, ti, &ei_nvme_ctrl_list_count);
    for (unsigned i = 0; i < numcids && done + 2 <= len; i++) {
        proto_tree_add_item(tree, hf_id, tvb, off + done, 2, ENC_LITTLE_ENDIAN);
        done += 2;
    }
    return done;
}

static void dissect_nvme_identify_ctrl_list_resp(tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, unsigned off, unsigned len)
{
    unsigned done = 0;
    if (!off && len >= 2)
        done = nvme_dissect_controller_list(tvb, pinfo, tree, 0, len,
            hf_nvme_identify_ctrl_list_num, hf_nvme_identify_ctrl_list_id);
    if (done < len)
        proto_tree_add_item(tree, hf_nvme_gen_data, tvb, done, len - done, ENC_NA);
}

/* Base 2.3 Figs 310/328 256-byte NQN fields: raw unless whole. */
static void
dissect_nvme_nqn(tvbuff_t *tvb, proto_tree *tree,
    int hf, unsigned off, unsigned len, unsigned roff, unsigned field_off,
    bool identify_window)
{
    unsigned window_skip = field_off > roff ? field_off - roff : 0;
    unsigned field_skip = roff > field_off ? roff - field_off : 0;

    if (field_skip >= 256 || window_skip >= len)
        return;
    off += window_skip;
    len = MIN(len - window_skip, 256 - field_skip);
    if (field_skip || len < 256 || hf == hf_nvme_gen_data) {
        proto_tree_add_item(tree, identify_window ? hf_nvme_window_partial : hf_nvme_gen_data,
                            tvb, off, len, ENC_NA);
        return;
    }
    proto_tree_add_item(tree, hf, tvb, off, len, ENC_UTF_8);
    unsigned nul;
    bool has_nul = tvb_find_uint8_length(tvb, off, len, 0, &nul);
    unsigned name_len = has_nul ? nul - off : len;
    if (has_nul && name_len + 1 < len)
        proto_tree_add_item(tree, hf_nvme_gen_data, tvb, nul + 1,
                            len - name_len - 1, ENC_NA);
}

/* Returns the group's subtree, for LID/opcode-specific sub-fields. */
static proto_tree *add_group_mask_entry(tvbuff_t *tvb, proto_tree *tree, unsigned offset, unsigned bytes, int *array, unsigned array_len)
{
    proto_item *ti;
    proto_tree *grp;
    unsigned i;

    ti = proto_tree_add_item(tree, array[0], tvb, offset, bytes, ENC_LITTLE_ENDIAN);
    grp =  proto_item_add_subtree(ti, ett_data);

    for (i = 1; i < array_len; i++)
        proto_tree_add_item(grp, array[i], tvb, offset, bytes, ENC_LITTLE_ENDIAN);

    return grp;
}

/* NVM Set List (CNS 04h), Base 2.3 Figures 333-334: a 1-byte NUMENT header
 * (up to 31 entries), entries of 128 bytes from structure offset 128. */
static void dissect_nvme_identify_nvmset_resp(tvbuff_t *cmd_tvb,
                                              proto_tree *cmd_tree, unsigned off, unsigned len)
{
    static const nvme_window_field fields[] = {
        NVME_WF(0, 2, hf_nvme_identify_nvmset_id, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_identify_nvmset_endgid, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 4, hf_nvme_identify_nvmset_r4krt, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_identify_nvmset_ows, ENC_LITTLE_ENDIAN),
        NVME_WFP(16, 16, hf_nvme_identify_nvmset_tnvmsc, ENC_NA, post_add_bytes_from_16bytes),
        NVME_WFP(32, 16, hf_nvme_identify_nvmset_unvmsc, ENC_NA, post_add_bytes_from_16bytes),
    };
    static const nvme_window_list list = {
        128, 128, 31, 0, "NVM Set Attributes Entry", fields, array_length(fields)
    };
    uint32_t nument = NVME_LIST_COUNT_UNKNOWN;

    if (!off && len >= 1)
        proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_identify_nvmset_num,
                                     cmd_tvb, 0, 1, ENC_LITTLE_ENDIAN, &nument);
    nvme_add_window_list(cmd_tvb, cmd_tree, off, len, &list, nument, true, true);
}

/* Primary Controller Capabilities (CNS 14h), Base 2.3 Figure 346. */
static void dissect_nvme_identify_pri_ctrl_cap_resp(tvbuff_t *cmd_tvb,
                                              proto_tree *cmd_tree, unsigned off, unsigned len)
{
    static const nvme_window_field fields[] = {
        NVME_WF(0, 2, hf_nvme_identify_pcc_cntlid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_identify_pcc_portid, ENC_LITTLE_ENDIAN),
        NVME_WG(4, 1, hf_nvme_identify_pcc_crt),
        NVME_WF(5, 27, hf_nvme_identify_pcc_rsvd, ENC_NA),
        NVME_WF(32, 4, hf_nvme_identify_pcc_vqfrt, ENC_LITTLE_ENDIAN),
        NVME_WF(36, 4, hf_nvme_identify_pcc_vqrfa, ENC_LITTLE_ENDIAN),
        NVME_WF(40, 2, hf_nvme_identify_pcc_vqrfap, ENC_LITTLE_ENDIAN),
        NVME_WF(42, 2, hf_nvme_identify_pcc_vqprt, ENC_LITTLE_ENDIAN),
        NVME_WF(44, 2, hf_nvme_identify_pcc_vqfrsm, ENC_LITTLE_ENDIAN),
        NVME_WF(46, 2, hf_nvme_identify_pcc_vqgran, ENC_LITTLE_ENDIAN),
        NVME_WF(64, 4, hf_nvme_identify_pcc_vifrt, ENC_LITTLE_ENDIAN),
        NVME_WF(68, 4, hf_nvme_identify_pcc_virfa, ENC_LITTLE_ENDIAN),
        NVME_WF(72, 2, hf_nvme_identify_pcc_virfap, ENC_LITTLE_ENDIAN),
        NVME_WF(74, 2, hf_nvme_identify_pcc_viprt, ENC_LITTLE_ENDIAN),
        NVME_WF(76, 2, hf_nvme_identify_pcc_vifrsm, ENC_LITTLE_ENDIAN),
        NVME_WF(78, 2, hf_nvme_identify_pcc_vigran, ENC_LITTLE_ENDIAN),
    };

    nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, fields, array_length(fields));
}

/* Secondary Controller List (CNS 15h), Base 2.3 Figures 347-348: a 1-byte
 * NUMENT header (up to 127 entries), entries of 32 bytes from offset 32. */
static void dissect_nvme_identify_sec_ctrl_list_resp(tvbuff_t *cmd_tvb,
                                              proto_tree *cmd_tree, unsigned off, unsigned len)
{
    static const nvme_window_field fields[] = {
        NVME_WF(0, 2, hf_nvme_identify_scl_scid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_identify_scl_pcid, ENC_LITTLE_ENDIAN),
        NVME_WG(4, 1, hf_nvme_identify_scl_scs),
        NVME_WF(8, 2, hf_nvme_identify_scl_vfn, ENC_LITTLE_ENDIAN),
        NVME_WF(10, 2, hf_nvme_identify_scl_nvq, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 2, hf_nvme_identify_scl_nvi, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_list list = {
        32, 32, 127, 0, "Secondary Controller Entry", fields, array_length(fields)
    };
    uint32_t nument = NVME_LIST_COUNT_UNKNOWN;

    if (!off && len >= 1)
        proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_identify_scl_num,
                                     cmd_tvb, 0, 1, ENC_LITTLE_ENDIAN, &nument);
    nvme_add_window_list(cmd_tvb, cmd_tree, off, len, &list, nument, true, true);
}

/* Namespace Granularity List (CNS 16h), NVM CS 1.2 Figures 123-124: NGA and a
 * 0's based ND count (up to 64 descriptors), descriptors of 16 bytes (NSG +
 * NCG) from offset 32. */
static void dissect_nvme_identify_ns_gran_list_resp(tvbuff_t *cmd_tvb,
                                              proto_tree *cmd_tree, unsigned off, unsigned len)
{
    static const nvme_window_field fields[] = {
        NVME_WF(0, 8, hf_nvme_identify_ngl_nsg, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 8, hf_nvme_identify_ngl_ncg, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_list list = {
        32, 16, 64, 0, "Namespace Granularity Descriptor", fields, array_length(fields)
    };
    static const nvme_window_field header[] = {
        NVME_WG(0, 4, hf_nvme_identify_ngl_nga),
    };
    unsigned count = NVME_LIST_COUNT_UNKNOWN, rel;
    uint32_t nd;

    nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, header, array_length(header));
    if (nvme_field_in_window(off, len, 4, 1, &rel)) {
        proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_identify_ngl_nd,
                                     cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN, &nd);
        count = nd + 1;
    }
    nvme_add_window_list(cmd_tvb, cmd_tree, off, len, &list, count, true, true);
}

/* UUID List (CNS 17h), Base 2.3 Figures 336-337: a 32-byte reserved header,
 * then UUID List Entries 1 to 127 of 32 bytes (IDASSOC, UUID at byte 16).
 * The first UUID cleared to 0h ends the list. */
static void dissect_nvme_identify_uuid_list_resp(tvbuff_t *cmd_tvb,
                                              proto_tree *cmd_tree, unsigned off, unsigned len)
{
    static const nvme_window_field fields[] = {
        NVME_WF(0, 1, hf_nvme_identify_uuid_idassoc, ENC_LITTLE_ENDIAN),
        NVME_WF(16, 16, hf_nvme_identify_uuid_uuid, ENC_NA),
    };
    static const nvme_window_list list = {
        32, 32, 127, 1, "UUID List Entry", fields, array_length(fields)
    };
    unsigned count = list.max;

    for (unsigned i = 0; i < list.max; i++) {
        unsigned uuid = list.first + i * list.stride + 16;

        if (uuid + 16 > off + len)
            break;
        if (uuid >= off && nvme_tvb_is_zero(cmd_tvb, uuid - off, 16)) {
            count = i;
            break;
        }
    }
    nvme_add_window_list(cmd_tvb, cmd_tree, off, len, &list, count, true, true);
}

/* Base 2.4 Figure 359: 16 reserved bytes, then up to 255 UUIDs; the first
 * all-zero entry ends the list. */
static void dissect_nvme_identify_enst_list_resp(tvbuff_t *cmd_tvb,
                                                 proto_tree *cmd_tree, unsigned off, unsigned len)
{
    static const nvme_window_field hdr[] = {
        NVME_WF(0, 16, hf_nvme_identify_enst_rsvd, ENC_NA),
    };
    static const nvme_window_field fields[] = {
        NVME_WF(0, 16, hf_nvme_identify_enst_uuid, ENC_NA),
    };
    static const nvme_window_list list = {
        16, 16, 255, 1, "Exported NVM Subsystem Template", fields, array_length(fields)
    };
    unsigned count = list.max;

    nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, hdr, array_length(hdr));
    for (unsigned i = 0; i < list.max; i++) {
        unsigned e = list.first + i * list.stride;

        if (e + 16 > off + len)
            break;
        if (e >= off && nvme_tvb_is_zero(cmd_tvb, e - off, 16)) {
            count = i;
            break;
        }
    }
    nvme_add_window_list(cmd_tvb, cmd_tree, off, len, &list, count, true, true);
}

static void add_ctrl_x16_bytes( char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%x (%"PRIu64" bytes)", val, ((uint64_t)val) * 16);
}

/* NVMe Base 2.3 Figure 328 bytes 2047:1792, each field gated on its bytes. */
static void dissect_nvme_identify_ctrl_resp_nvmeof(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                                   unsigned off, unsigned len)
{
    proto_item *ti;
    proto_tree *grp;
    unsigned rel, n;

    if (!nvme_window_intersect(off, len, 1792, 256, &rel, &n))
        return;
    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nvmeof, cmd_tvb, rel, n, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);

    nvme_add_identify_window_field(cmd_tvb, grp, hf_nvme_identify_ctrl_nvmeof_ioccsz, off, len, 1792, 4, ENC_LITTLE_ENDIAN);
    nvme_add_identify_window_field(cmd_tvb, grp, hf_nvme_identify_ctrl_nvmeof_iorcsz, off, len, 1796, 4, ENC_LITTLE_ENDIAN);
    nvme_add_identify_window_field(cmd_tvb, grp, hf_nvme_identify_ctrl_nvmeof_icdoff, off, len, 1800, 2, ENC_LITTLE_ENDIAN);

    if (nvme_field_in_window(off, len, 1802, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_identify_ctrl_nvmeof_fcatt));
    nvme_add_identify_window_field(cmd_tvb, grp, hf_nvme_identify_ctrl_nvmeof_msdbd, off, len, 1803, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 1804, 2, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 2, ASPEC(hf_nvme_identify_ctrl_nvmeof_ofcs));
    nvme_add_identify_window_field(cmd_tvb, grp, hf_nvme_identify_ctrl_nvmeof_dctype, off, len, 1806, 1, ENC_LITTLE_ENDIAN);
    nvme_add_identify_window_field(cmd_tvb, grp, hf_nvme_identify_ctrl_nvmeof_ccrl, off, len, 1807, 1, ENC_LITTLE_ENDIAN);
    /* The 240-byte Reserved run is one field: whole or not at all. */
    nvme_add_identify_window_field(cmd_tvb, grp, hf_nvme_identify_ctrl_nvmeof_rsvd, off, len, 1808, 240, ENC_NA);
}


static const true_false_string units_watts = {
    "1 (0.0001 Watt units)",
    "0 (0.01 Watt units)"
};

/* NVMe Base 2.3 Figure 328, bytes 99:96 bit 18: RHII is enumerated. */
static const true_false_string ctratt_rhii_tfs = {
    "Host Identifier required to be non-zero to use reservations",
    "Not reported"
};

/* NVMe Base 2.3 Figure 328, byte 524 bit 3: set means not supported. */
static const true_false_string fna_fnvmbs_tfs = {
    "Broadcast NSID (FFFFFFFFh) not supported",
    "Broadcast NSID (FFFFFFFFh) supported"
};

/* NVMe Base 2.3 Figure 328, byte 1802 bit 0: set means static. */
static const true_false_string fcatt_dcms_tfs = {
    "Static controller model",
    "Dynamic controller model"
};

/* NVMe Base 2.3 Figure 328 ONCS bits 1-3, 7: cleared means a size limit
 * field indicates support, not that the command is unsupported. */
static const true_false_string oncs_nvmwusv_tfs = {
    "Supported; WUSL is the recommended maximum data size",
    "Support indicated by a non-zero WUSL instead"
};

static const true_false_string oncs_nvmdsmsv_tfs = {
    "Supported; DMRL, DMSL and DMRSL give the limits, if any",
    "Support indicated by non-zero DMRL, DMSL and DMRSL instead"
};

static const true_false_string oncs_nvmwzsv_tfs = {
    "Supported; WZSL is the recommended maximum data size",
    "Support indicated by a non-zero WZSL instead"
};

static const true_false_string oncs_nvmvfys_tfs = {
    "Supported; VSL is the recommended maximum data size",
    "Support indicated by a non-zero VSL instead"
};

/* NVMe Base 2.3 Figure 409 bits 18:15 name the event, but only control
 * whether its notice is sent. */
static const true_false_string aec_event_notice_tfs = {
    "Event sent to the host",
    "Event not sent to the host"
};


static const value_string power_scale_tbl[] = {
    { 0, "not reported for this power state" },
    { 1, "0.0001 Watt units" },
    { 2, "0.01 Watt units" },
    { 3,  "reserved value" },
    { 0, NULL}
};

/* Time Scale Values, NVMe Base 2.3 Figure 330 (EPFRTS / FQVTS / EPFVTS) */
static const value_string time_scale_tbl[] = {
    { 0x0, "1 microsecond" },
    { 0x1, "10 microseconds" },
    { 0x2, "100 microseconds" },
    { 0x3, "1 millisecond" },
    { 0x4, "10 milliseconds" },
    { 0x5, "100 milliseconds" },
    { 0x6, "1 second" },
    { 0x7, "10 seconds" },
    { 0x8, "100 seconds" },
    { 0x9, "1,000 seconds" },
    { 0xA, "10,000 seconds" },
    { 0xB, "100,000 seconds" },
    { 0xC, "1,000,000 seconds" },
    { 0xD, "reserved value" },
    { 0xE, "reserved value" },
    { 0xF, "reserved value" },
    { 0, NULL}
};

/* Max Bandwidth Scale, NVMe Base 2.3 Figure 329 (bits 234:232) */
static const value_string max_bw_scale_tbl[] = {
    { 0, "1 MiB/second" },
    { 1, "10 MiB/second" },
    { 2, "100 MiB/second" },
    { 3, "1 GiB/second" },
    { 4, "10 GiB/second" },
    { 5, "100 GiB/second" },
    { 6, "reserved value" },
    { 7, "reserved value" },
    { 0, NULL}
};

/* One Figure 329 descriptor, all 32 bytes in the window. */
static void dissect_nvme_identify_ctrl_resp_power_state_descriptor(tvbuff_t *cmd_tvb, proto_tree *tree, uint8_t idx, unsigned off)
{
    proto_item *ti;
    proto_tree *grp;

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
    /* Bytes 31:23, NVMe Base 2.4 Figure 340: only the two odd nibbles are
     * Reserved. */
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_epfrt, cmd_tvb, off+23, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_fqvt, cmd_tvb, off+24, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_epfvt, cmd_tvb, off+25, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_epfrts, cmd_tvb, off+26, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_fqvts, cmd_tvb, off+26, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_epfvts, cmd_tvb, off+27, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd9, cmd_tvb, off+27, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_mbw, cmd_tvb, off+28, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_mbws, cmd_tvb, off+29, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_rsvd10, cmd_tvb, off+29, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_psd_miiell, cmd_tvb, off+30, 2, ENC_LITTLE_ENDIAN);
}

/* NVMe Base 2.3 Figure 328 bytes 3071:2048: PSD0..PSD31, whole ones only. */
/* Active Power Workload (APW), Base 2.3 Figure 674. */
static const value_string psd_apw_tbl[] = {
    { 0, "No Workload" },
    { 1, "Workload #1" },
    { 2, "Workload #2" },
    { 0, NULL }
};

static void dissect_nvme_identify_ctrl_resp_power_state_descriptors(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                                                    unsigned off, unsigned len)
{
    proto_item *ti;
    proto_tree *grp;
    unsigned i, rel, n;

    if (!nvme_window_intersect(off, len, 2048, 1024, &rel, &n))
        return;
    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_psds, cmd_tvb, rel, n, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    unsigned first_byte = off + rel - 2048;
    unsigned lead = MIN((32 - first_byte % 32) % 32, n);
    if (lead)
        proto_tree_add_item(grp, hf_nvme_window_partial, cmd_tvb, rel, lead, ENC_NA);
    unsigned first = (first_byte + lead) / 32;
    unsigned count = (n - lead) / 32;
    for (i = first; i < first + count && i < 32; i++) {
        unsigned descriptor_rel;
        if (nvme_field_in_window(off, len, 2048 + 32 * i, 32, &descriptor_rel))
            dissect_nvme_identify_ctrl_resp_power_state_descriptor(cmd_tvb, grp, i, descriptor_rel);
    }
    unsigned tail = (n - lead) % 32;
    if (tail)
        proto_tree_add_item(grp, hf_nvme_window_partial, cmd_tvb, rel + n - tail, tail, ENC_NA);
}


static void add_ctrl_rab(char *result, uint32_t val)
{
    if (val >= 64)
        snprintf(result, ITEM_LABEL_LENGTH, "0x%x (overflow)", val);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"PRIu64" command%s)", val, ((uint64_t)1) << val, val ? "s" : "");
}

static void add_ctrl_mdts(char *result, uint32_t val)
{
    if (val >= 64)
        snprintf(result, ITEM_LABEL_LENGTH, "0x%x (overflow)", val);
    else if (val)
        snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"PRIu64" pages)", val, ((uint64_t)1) << val);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "0x%x (unlimited)", val);
}

static void add_ctrl_rtd3(char *result, uint32_t val)
{
    if (!val)
        snprintf(result, ITEM_LABEL_LENGTH, "0 (not reported)");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u (%u microsecond%s)", val, val, (val > 1) ? "s" : "");
}

static const value_string ctrl_type_tbl[] = {
    { 0,  "Reserved (not reported)" },
    { 1,  "I/O Controller" },
    { 2,  "Discovery Controller" },
    { 3,  "Administrative Controller" },
    { 0, NULL}
};

static const value_string ctrl_rpmbbpwps_tbl[] = {
    { 0,  "Not specified" },
    { 1,  "Not supported" },
    { 2,  "Supported" },
    { 3,  "Reserved" },
    { 0, NULL}
};

static const value_string ctrl_mups_tbl[] = {
    { 0,  "Reserved" },
    { 1,  "0.0001 W" },
    { 2,  "0.01 W" },
    { 3,  "Reserved" },
    { 0, NULL}
};

static const value_string ctrl_srs_tbl[] = {
    { 0,  "Not reported" },
    { 1,  "1 microsecond" },
    { 2,  "10 microseconds" },
    { 3,  "100 microseconds" },
    { 4,  "1 millisecond" },
    { 5,  "10 milliseconds" },
    { 0, NULL}
};

static const value_string ctratt_iiellss_tbl[] = {
    { 0,  "Not Supported" },
    { 1,  "Power State" },
    { 2,  "Global" },
    { 3,  "Reserved" },
    { 0, NULL}
};

static const value_string ctrl_vsen_volss_tbl[] = {
    { 0,  "Reserved" },
    { 1,  "0.001 V" },
    { 2,  "0.01 V" },
    { 3,  "Reserved" },
    { 0, NULL}
};

/* Base 2.4 Figure 783. */
static const value_string nvme_vsen_sel_vals[] = {
    { 0, "Voltage Sensor 1 (VSEN1)" },
    { 1, "Voltage Sensor 2 (VSEN2)" },
    { 2, "Voltage Sensor 3 (VSEN3)" },
    { 3, "Voltage Sensor 4 (VSEN4)" },
    { 0, NULL}
};

/* Base 2.4 Figure 526. */
static const range_string nvme_vm_act_rvals[] = {
    { 0x0, 0x0, "Stop Voltage Measurements" },
    { 0x1, 0x1, "Start Voltage Measurements" },
    { 0x2, 0x2, "Clear Overvoltage Valid and Undervoltage Valid" },
    { 0x3, 0x9, "Reserved" },
    { 0xa, 0xf, "Vendor Specific" },
    { 0, 0, NULL },
};

/* Rate Limiting Target (TGT), NVM CS 1.3 Figure 106. */
static const range_string nvme_rl_tgt_rvals[] = {
    { 0, 0, "Controller" },
    { 1, 191, "Reserved" },
    { 192, 255, "Vendor Specific" },
    { 0, 0, NULL },
};

/* Rate Limiting Mode (RLM), NVM CS 1.3 Figure 107. */
static const range_string nvme_rl_rlm_rvals[] = {
    { 0x0, 0x0, "Hard Limit" },
    { 0x1, 0x1, "Soft Limit" },
    { 0x2, 0xf, "Reserved" },
    { 0, 0, NULL },
};

/* Bandwidth Scale Factors, NVM CS 1.3 Figure 108. */
static const range_string nvme_rl_bwsf_rvals[] = {
    { 0x0, 0x0, "1 MiB/second" },
    { 0x1, 0x1, "10 MiB/second" },
    { 0x2, 0x2, "100 MiB/second" },
    { 0x3, 0x3, "1 GiB/second" },
    { 0x4, 0x4, "10 GiB/second" },
    { 0x5, 0x5, "100 GiB/second" },
    { 0x6, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* Non-Volatile Storage Medium Access Scope (SC), NVM CS 1.3 Figure 120. */
static const range_string nvme_rl_sc_rvals[] = {
    { 0x0, 0x0, "NVM subsystem" },
    { 0x1, 0x1, "Domain" },
    { 0x2, 0x2, "Endurance Group" },
    { 0x3, 0x3, "Namespace" },
    { 0x4, 0xbf, "Reserved" },
    { 0xc0, 0xff, "Vendor Specific" },
    { 0, 0, NULL },
};

static void add_ctrl_100us(char *result, uint32_t val)
{
    if (val)
        snprintf(result, ITEM_LABEL_LENGTH, "%u (%u us)", val, val * 100);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "0 (No minimum)");
}

static void add_pm_iiell(char *result, uint32_t val)
{
    if (val)
        snprintf(result, ITEM_LABEL_LENGTH, "%u (%u us)", val, val * 100);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "0 (Disabled / not supported)");
}

static void add_ctrl_vsen_pisv(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u (%u.%02u V)", val, (val * 5) / 100, (val * 5) % 100);
}

static void add_ctrl_minutes(char *result, uint32_t val)
{
    if (val)
        snprintf(result, ITEM_LABEL_LENGTH, "%u minute%s", val, val == 1 ? "" : "s");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "0 (Not reported)");
}

static const range_string ctrl_dctype_tbl[] = {
    { 0, 0, "Not reported" },
    { 1, 1, "Direct Discovery Controller (DDC)" },
    { 2, 2, "Centralized Discovery Controller (CDC)" },
    { 3, 0xff, "Reserved" },
    { 0, 0, NULL }
};

static void
add_nvme_kelvins(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u K", val);
}

static void
add_nvme_psd_time_value(char *result, uint32_t val)
{
    if (val == 0)
        snprintf(result, ITEM_LABEL_LENGTH, "Not reported");
    else if (val <= 99)
        snprintf(result, ITEM_LABEL_LENGTH, "%u", val);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "Reserved");
}

static void
add_nvme_sanitize_time(char *result, uint32_t val)
{
    if (val == 0)
        snprintf(result, ITEM_LABEL_LENGTH, "Completed in background");
    else if (val == UINT32_MAX)
        snprintf(result, ITEM_LABEL_LENGTH, "No time reported");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u seconds", val);
}

static void
add_nvme_sanitize_pvds_time(char *result, uint32_t val)
{
    if (val == UINT32_MAX)
        snprintf(result, ITEM_LABEL_LENGTH, "No time reported");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u seconds", val);
}

static void add_ctrl_ms(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u (%u ms)", val, val * 100);
}

static void dissect_nvme_identify_ctrl_resp_ver(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                                uint32_t off)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ver, cmd_tvb,  80-off, 4, ENC_LITTLE_ENDIAN);
    grp =  proto_item_add_subtree(ti, ett_data);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_mjr, cmd_tvb, 82-off, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_min, cmd_tvb, 81-off, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_ter, cmd_tvb, 80-off, 1, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_identify_ctrl_resp_fguid(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, uint32_t off)
{
    proto_item *ti;
    proto_tree *grp;

    /* FGUID uses the EUI-64 based 16-byte designator format and, per the
     * NVMe Base spec, "This field is big endian" -- unlike virtually all
     * other multi-byte NVMe fields, which default to little endian. */
    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_fguid, cmd_tvb, 112-off, 16, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_vse, cmd_tvb, 112-off, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_oui, cmd_tvb, 120-off, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_ei, cmd_tvb, 123-off, 5, ENC_BIG_ENDIAN);
}

static void dissect_nvme_identify_ctrl_resp_mi(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, uint32_t off)
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

static void add_ctrl_commands(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u command%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_events(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u event%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_entries(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u entr%s)", val, val+1, val ? "ies" : "y");
}

static void add_ctrl_states(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u state%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_hmpre(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"PRIu64" bytes)", val, ((uint64_t)(val)) * 4096);
}

/* Append the magnitude of an exact 128-bit byte count. */
static void post_add_bytes_from_16bytes(proto_item *ti, tvbuff_t *tvb, unsigned off)
{
    /* The 128-bit value is little-endian on the wire: byte `off` holds the
     * low-order 64 bits and byte `off+8` holds the high-order 64 bits. */
    uint64_t lo = tvb_get_uint64(tvb, off, ENC_LITTLE_ENDIAN);
    uint64_t hi = tvb_get_uint64(tvb, off+8, ENC_LITTLE_ENDIAN);

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

/* NVMe Base 2.3 Figure 210: V * 512,000 bytes is an upper bound. */
static void post_add_smart_data_units(proto_item *ti, tvbuff_t *tvb, unsigned off)
{
    static const char *const units[] = {"bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"};
    uint64_t lo = tvb_get_uint64(tvb, off, ENC_LITTLE_ENDIAN);
    uint64_t hi = tvb_get_uint64(tvb, off+8, ENC_LITTLE_ENDIAN);
    unsigned unit = 0;
    double bytes;

    /* 0h is "not reported". */
    if (!lo && !hi) {
        proto_item_append_text(ti, " (not reported)");
        return;
    }

    bytes = (double)hi;
    bytes *= (((uint64_t)1) << 63);
    bytes *= 2;
    bytes += lo;
    bytes *= 512000;

    while (bytes >= 1024.0 && unit < array_length(units) - 1) {
        bytes /= 1024.0;
        unit++;
    }

    if (unit)
        proto_item_append_text(ti, " (<= %.2f %s)", bytes, units[unit]);
    else
        proto_item_append_text(ti, " (<= %.0f bytes)", bytes);
}

static void add_ctrl_tmt(char *result, uint32_t val)
{
    if (!val)
        snprintf(result, ITEM_LABEL_LENGTH, "0 (not supported)");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u degrees K", val);
}

static const value_string mmas_type_tbl[] = {
    { 0, "modification not defined" },
    { 1, "no modification after sanitize completion" },
    { 2, "additional modification after sanitize completion" },
    { 3, "Reserved" },
    { 0, NULL }
};

static void add_ctrl_pow2_bytes(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%" PRIu64" bytes)", val, ((uint64_t)1) << val);
}

static void add_ctrl_pow2_page_size(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%" PRIu64" bytes)", val, ((uint64_t)1) << (12+val));
}

static void add_ctrl_pow2_page_size_64(char *result, uint64_t val)
{
    add_ctrl_pow2_page_size(result, (uint32_t)val);
}

static void add_ctrl_pow2_dstrd_size(char *result, uint64_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%" PRIx64 " (%" PRIu64" bytes)", val, ((uint64_t)1) << (2+val));
}


static const value_string fcb_type_tbl[] = {
    { 0, "support for the NSID field set to FFFFFFFFh is not indicated" },
    { 1, "reserved value" },
    { 2, "Flush command does not support the NSID field set to FFFFFFFFh" },
    { 3, "Flush command supports the NSID field set to FFFFFFFFh" },
    { 0, NULL}
};


static void add_ctrl_lblocks(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u logical block%s", val + 1, val ? "s" : "");
}

static const value_string sgls_ify_type_tbl[] = {
    { 0,  "SGLs are not supported." },
    { 1, "SGLs are supported without alignment or granularity limitations" },
    { 2, "SGLs are supported with DWORD alignment and granularity limitation" },
    { 3,  "reserved value" },
    { 0, NULL}
};

/* Defined further down with the Get Log Page helpers; used here for the two
 * 16-byte count fields (MAXDNA) in the Identify Controller structure. */
static void post_add_intval_from_16bytes(proto_item *ti, tvbuff_t *tvb, unsigned off);

static void dissect_nvme_identify_ctrl_resp(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                            unsigned off, unsigned len)
{
    proto_item *ti;
    unsigned rel, n;

    static const nvme_window_field ctrl_fields0[] = {
        NVME_WF(0, 2, hf_nvme_identify_ctrl_vid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_identify_ctrl_ssvid, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 20, hf_nvme_identify_ctrl_sn, ENC_ASCII),
        NVME_WF(24, 40, hf_nvme_identify_ctrl_mn, ENC_ASCII),
        NVME_WF(64, 8, hf_nvme_identify_ctrl_fr, ENC_ASCII),
        NVME_WF(72, 1, hf_nvme_identify_ctrl_rab, ENC_LITTLE_ENDIAN),
        NVME_WF(73, 3, hf_nvme_identify_ctrl_ieee, ENC_LITTLE_ENDIAN),
        NVME_WG(76, 1, hf_nvme_identify_ctrl_cmic),
        NVME_WF(77, 1, hf_nvme_identify_ctrl_mdts, ENC_LITTLE_ENDIAN),
        NVME_WF(78, 2, hf_nvme_identify_ctrl_cntlid, ENC_LITTLE_ENDIAN),
    };
    if (!nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, ctrl_fields0,
                                array_length(ctrl_fields0)))
        return;
    if (nvme_window_cut(off, len, 80, 4)) {
        nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_ver, off, len,
                              80, 4, ENC_LITTLE_ENDIAN);
        return;
    }
    if (off > 80 && off < 84 &&
        !nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_ver, off, len,
                               80, 4, ENC_LITTLE_ENDIAN))
        return;
    if (off <= 80)
        dissect_nvme_identify_ctrl_resp_ver(cmd_tvb, cmd_tree, off);
    static const nvme_window_field ctrl_fields1[] = {
        NVME_WF(84, 4, hf_nvme_identify_ctrl_rtd3r, ENC_LITTLE_ENDIAN),
        NVME_WF(88, 4, hf_nvme_identify_ctrl_rtd3e, ENC_LITTLE_ENDIAN),
        NVME_WG(92, 4, hf_nvme_identify_ctrl_oaes),
        NVME_WG(96, 4, hf_nvme_identify_ctrl_ctratt),
        NVME_WG(100, 2, hf_nvme_identify_ctrl_rrls),
        NVME_WG(102, 1, hf_nvme_identify_ctrl_bpcap),
        NVME_WG(103, 1, hf_nvme_identify_ctrl_chsi),
        NVME_WF(104, 4, hf_nvme_identify_ctrl_nssl, ENC_LITTLE_ENDIAN),
        NVME_WF(108, 2, hf_nvme_identify_ctrl_rsvd6, ENC_NA),
        NVME_WG(110, 1, hf_nvme_identify_ctrl_plsi),
        NVME_WF(111, 1, hf_nvme_identify_ctrl_cntrltype, ENC_LITTLE_ENDIAN),
    };
    if (!nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, ctrl_fields1,
                                array_length(ctrl_fields1)))
        return;
    if (nvme_window_cut(off, len, 112, 16)) {
        nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_fguid, off, len,
                              112, 16, ENC_NA);
        return;
    }
    if (off > 112 && off < 128 &&
        !nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_fguid, off, len,
                               112, 16, ENC_NA))
        return;
    if (off <= 112)
        dissect_nvme_identify_ctrl_resp_fguid(cmd_tvb, cmd_tree, off);

    static const nvme_window_field ctrl_fields2[] = {
        NVME_WF(128, 2, hf_nvme_identify_ctrl_crdt1, ENC_LITTLE_ENDIAN),
        NVME_WF(130, 2, hf_nvme_identify_ctrl_crdt2, ENC_LITTLE_ENDIAN),
        NVME_WF(132, 2, hf_nvme_identify_ctrl_crdt3, ENC_LITTLE_ENDIAN),
        NVME_WG(134, 1, hf_nvme_identify_ctrl_crcap),
        NVME_WF(135, 1, hf_nvme_identify_ctrl_ciu, ENC_LITTLE_ENDIAN),
        NVME_WF(136, 8, hf_nvme_identify_ctrl_cirn, ENC_LITTLE_ENDIAN),
        NVME_WF(144, 96, hf_nvme_identify_ctrl_rsvd1, ENC_NA),
    };
    if (!nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, ctrl_fields2,
                                array_length(ctrl_fields2)))
        return;
    if (nvme_window_cut(off, len, 240, 16)) {
        nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_mi, off, len,
                              240, 16, ENC_NA);
        return;
    }
    if (off > 240 && off < 256 &&
        !nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_mi, off, len,
                               240, 16, ENC_NA))
        return;
    if (off <= 240)
        dissect_nvme_identify_ctrl_resp_mi(cmd_tvb, cmd_tree, off);
    static const nvme_window_field ctrl_fields3[] = {
        NVME_WG(256, 2, hf_nvme_identify_ctrl_oacs),
        NVME_WF(258, 1, hf_nvme_identify_ctrl_acl, ENC_LITTLE_ENDIAN),
        NVME_WF(259, 1, hf_nvme_identify_ctrl_aerl, ENC_LITTLE_ENDIAN),
        NVME_WG(260, 1, hf_nvme_identify_ctrl_frmw),
        NVME_WG(261, 1, hf_nvme_identify_ctrl_lpa),
        NVME_WF(262, 1, hf_nvme_identify_ctrl_elpe, ENC_LITTLE_ENDIAN),
        NVME_WF(263, 1, hf_nvme_identify_ctrl_npss, ENC_LITTLE_ENDIAN),
        NVME_WG(264, 1, hf_nvme_identify_ctrl_avscc),
        NVME_WG(265, 1, hf_nvme_identify_ctrl_apsta),
        NVME_WF(266, 2, hf_nvme_identify_ctrl_wctemp, ENC_LITTLE_ENDIAN),
        NVME_WF(268, 2, hf_nvme_identify_ctrl_cctemp, ENC_LITTLE_ENDIAN),
        NVME_WF(270, 2, hf_nvme_identify_ctrl_mtfa, ENC_LITTLE_ENDIAN),
        NVME_WF(272, 4, hf_nvme_identify_ctrl_hmpre, ENC_LITTLE_ENDIAN),
        NVME_WF(276, 4, hf_nvme_identify_ctrl_hmmin, ENC_LITTLE_ENDIAN),
        NVME_WFP(280, 16, hf_nvme_identify_ctrl_tnvmcap, ENC_NA, post_add_bytes_from_16bytes),
        NVME_WFP(296, 16, hf_nvme_identify_ctrl_unvmcap, ENC_NA, post_add_bytes_from_16bytes),
        NVME_WG(312, 4, hf_nvme_identify_ctrl_rpmbs),
        NVME_WF(316, 2, hf_nvme_identify_ctrl_edstt, ENC_LITTLE_ENDIAN),
        NVME_WG(318, 1, hf_nvme_identify_ctrl_dsto),
        NVME_WF(319, 1, hf_nvme_identify_ctrl_fwug, ENC_LITTLE_ENDIAN),
        NVME_WF(320, 2, hf_nvme_identify_ctrl_kas, ENC_LITTLE_ENDIAN),
        NVME_WG(322, 2, hf_nvme_identify_ctrl_hctma),
        NVME_WF(324, 2, hf_nvme_identify_ctrl_mntmt, ENC_LITTLE_ENDIAN),
        NVME_WF(326, 2, hf_nvme_identify_ctrl_mxtmt, ENC_LITTLE_ENDIAN),
        NVME_WG(328, 4, hf_nvme_identify_ctrl_sanicap),
        NVME_WF(332, 4, hf_nvme_identify_ctrl_hmminds, ENC_LITTLE_ENDIAN),
        NVME_WF(336, 2, hf_nvme_identify_ctrl_hmmaxd, ENC_LITTLE_ENDIAN),
        NVME_WF(338, 2, hf_nvme_identify_ctrl_nsetidmax, ENC_LITTLE_ENDIAN),
        NVME_WF(340, 2, hf_nvme_identify_ctrl_endgidmax, ENC_LITTLE_ENDIAN),
        NVME_WF(342, 1, hf_nvme_identify_ctrl_anatt, ENC_LITTLE_ENDIAN),
        NVME_WG(343, 1, hf_nvme_identify_ctrl_anacap),
        NVME_WF(344, 4, hf_nvme_identify_ctrl_anagrpmax, ENC_LITTLE_ENDIAN),
        NVME_WF(348, 4, hf_nvme_identify_ctrl_nanagrpid, ENC_LITTLE_ENDIAN),
        NVME_WF(352, 4, hf_nvme_identify_ctrl_pels, ENC_LITTLE_ENDIAN),
        NVME_WF(356, 2, hf_nvme_identify_ctrl_did, ENC_LITTLE_ENDIAN),
        NVME_WG(358, 1, hf_nvme_identify_ctrl_kpioc),
        NVME_WF(359, 1, hf_nvme_identify_ctrl_rsvd2, ENC_NA),
        NVME_WF(360, 2, hf_nvme_identify_ctrl_mptfawr, ENC_LITTLE_ENDIAN),
        NVME_WG(362, 1, hf_nvme_identify_ctrl_rmdca),
        NVME_WF(363, 5, hf_nvme_identify_ctrl_rsvd7, ENC_NA),
        NVME_WFP(368, 16, hf_nvme_identify_ctrl_megcap, ENC_NA, post_add_bytes_from_16bytes),
        NVME_WG(384, 1, hf_nvme_identify_ctrl_tmpthha),
        NVME_WG(385, 1, hf_nvme_identify_ctrl_mupa),
        NVME_WF(386, 2, hf_nvme_identify_ctrl_cqt, ENC_LITTLE_ENDIAN),
        NVME_WG(388, 2, hf_nvme_identify_ctrl_cdpa),
        NVME_WF(390, 2, hf_nvme_identify_ctrl_mup, ENC_LITTLE_ENDIAN),
        NVME_WG(392, 2, hf_nvme_identify_ctrl_ipmsr),
        NVME_WF(394, 2, hf_nvme_identify_ctrl_msmt, ENC_LITTLE_ENDIAN),
        NVME_WF(396, 2, hf_nvme_identify_ctrl_mnens, ENC_LITTLE_ENDIAN),
        NVME_WF(398, 2, hf_nvme_identify_ctrl_mnecpens, ENC_LITTLE_ENDIAN),
        NVME_WF(400, 4, hf_nvme_identify_ctrl_mensnn, ENC_LITTLE_ENDIAN),
        NVME_WG(404, 1, hf_nvme_identify_ctrl_ensa),
        NVME_WG(405, 1, hf_nvme_identify_ctrl_endsfs),
        NVME_WG(406, 4, hf_nvme_identify_ctrl_vsen1),
        NVME_WG(410, 4, hf_nvme_identify_ctrl_vsen2),
        NVME_WG(414, 4, hf_nvme_identify_ctrl_vsen3),
        NVME_WG(418, 4, hf_nvme_identify_ctrl_vsen4),
        NVME_WF(422, 2, hf_nvme_identify_ctrl_msvmt, ENC_LITTLE_ENDIAN),
        NVME_WF(424, 88, hf_nvme_identify_ctrl_rsvd8, ENC_NA),
        NVME_WG(512, 1, hf_nvme_identify_ctrl_sqes),
        NVME_WG(513, 1, hf_nvme_identify_ctrl_cqes),
        NVME_WF(514, 2, hf_nvme_identify_ctrl_maxcmd, ENC_LITTLE_ENDIAN),
        NVME_WF(516, 4, hf_nvme_identify_ctrl_nn, ENC_LITTLE_ENDIAN),
        NVME_WG(520, 2, hf_nvme_identify_ctrl_oncs),
        NVME_WG(522, 2, hf_nvme_identify_ctrl_fuses),
        NVME_WG(524, 1, hf_nvme_identify_ctrl_fna),
        NVME_WG(525, 1, hf_nvme_identify_ctrl_vwc),
        NVME_WF(526, 2, hf_nvme_identify_ctrl_awun, ENC_LITTLE_ENDIAN),
        NVME_WF(528, 2, hf_nvme_identify_ctrl_awupf, ENC_LITTLE_ENDIAN),
        NVME_WG(530, 1, hf_nvme_identify_ctrl_nvscc),
        NVME_WG(531, 1, hf_nvme_identify_ctrl_nwpc),
    };
    if (!nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, ctrl_fields3,
                                array_length(ctrl_fields3)))
        return;
    if (nvme_window_cut(off, len, 532, 2)) {
        nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_acwu, off, len,
                              532, 2, ENC_LITTLE_ENDIAN);
        return;
    }
    if (off > 532 && off < 534 &&
        !nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_acwu, off, len,
                               532, 2, ENC_LITTLE_ENDIAN))
        return;
    if (off <= 532)  {
        uint32_t acwu;

        /* NVM CS 1.2 Figure 117: ACWU is 0's based logical blocks. */
        ti = proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_identify_ctrl_acwu, cmd_tvb,
                                          532-off, 2, ENC_LITTLE_ENDIAN, &acwu);
        /* 0h also means Compare and Write is not supported. */
        if (!acwu)
            proto_item_append_text(ti, " (or Compare and Write is not supported)");
    }
    static const nvme_window_field ctrl_fields4[] = {
        NVME_WG(534, 2, hf_nvme_identify_ctrl_cdfs),
        NVME_WG(536, 4, hf_nvme_identify_ctrl_sgls),
        NVME_WF(540, 4, hf_nvme_identify_ctrl_mnan, ENC_LITTLE_ENDIAN),
        NVME_WFP(544, 16, hf_nvme_identify_ctrl_maxdna, ENC_NA, post_add_intval_from_16bytes),
        NVME_WF(560, 4, hf_nvme_identify_ctrl_maxcna, ENC_LITTLE_ENDIAN),
        NVME_WF(564, 4, hf_nvme_identify_ctrl_oaqd, ENC_LITTLE_ENDIAN),
        NVME_WF(568, 1, hf_nvme_identify_ctrl_rhiri, ENC_LITTLE_ENDIAN),
        NVME_WF(569, 1, hf_nvme_identify_ctrl_hirt, ENC_LITTLE_ENDIAN),
        NVME_WF(570, 2, hf_nvme_identify_ctrl_cmmrtd, ENC_LITTLE_ENDIAN),
        NVME_WF(572, 2, hf_nvme_identify_ctrl_nmmrtd, ENC_LITTLE_ENDIAN),
        NVME_WF(574, 1, hf_nvme_identify_ctrl_minmrtg, ENC_LITTLE_ENDIAN),
        NVME_WF(575, 1, hf_nvme_identify_ctrl_maxmrtg, ENC_LITTLE_ENDIAN),
        NVME_WG(576, 1, hf_nvme_identify_ctrl_trattr),
        NVME_WF(577, 1, hf_nvme_identify_ctrl_rsvd4, ENC_NA),
        NVME_WF(578, 2, hf_nvme_identify_ctrl_mcudmq, ENC_LITTLE_ENDIAN),
        NVME_WF(580, 2, hf_nvme_identify_ctrl_mnsudmq, ENC_LITTLE_ENDIAN),
        NVME_WF(582, 2, hf_nvme_identify_ctrl_mcmr, ENC_LITTLE_ENDIAN),
        NVME_WF(584, 2, hf_nvme_identify_ctrl_nmcmr, ENC_LITTLE_ENDIAN),
        NVME_WF(586, 2, hf_nvme_identify_ctrl_mcdqpc, ENC_LITTLE_ENDIAN),
        NVME_WF(588, 180, hf_nvme_identify_ctrl_rsvd9, ENC_NA),
    };
    if (!nvme_add_identify_window_fields(cmd_tvb, cmd_tree, off, len, ctrl_fields4,
                                array_length(ctrl_fields4)))
        return;

    /* MI 2.1 Fig 136 allows windows that only intersect SUBNQN. */
    dissect_nvme_nqn(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_subnqn, 0, len, off, 768, true);
    if (nvme_window_cut(off, len, 1024, 768)) {
        nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_rsvd5, off, len,
                              1024, 768, ENC_NA);
        return;
    }
    if (off > 1024 && off < 1792 &&
        !nvme_add_identify_window_field(cmd_tvb, cmd_tree, hf_nvme_identify_ctrl_rsvd5, off, len,
                               1024, 768, ENC_NA))
        return;
    if (off <= 1024)
        proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd5, cmd_tvb, 1024-off, 768, ENC_NA);
    /* The tail blocks are windowed on their own parts. */
    dissect_nvme_identify_ctrl_resp_nvmeof(cmd_tvb, cmd_tree, off, len);
    dissect_nvme_identify_ctrl_resp_power_state_descriptors(cmd_tvb, cmd_tree, off, len);
    /* Vendor Specific, 4095:3072: the bytes of the window that lie in it. */
    if (nvme_window_intersect(off, len, 3072, 1024, &rel, &n)) {
        ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_vs, cmd_tvb, rel, n, ENC_NA);
        if (off > 3072)
            proto_item_append_text(ti, " (offset %u)", off - 3072);
    }
}

/* NVM CS 1.3 PIFA.STMLA. */
static const range_string nvm_ns_stmla_tbl[] = {
    { 0, 0, "Bit Granularity Masking" },
    { 1, 1, "Byte Granularity Masking" },
    { 2, 2, "Masking Not Supported" },
    { 3, 7, "Reserved" },
    { 0, 0, NULL }
};

/* NVM CS 1.2 Figure 119 PIF and QPIF. */
static const value_string nvm_ns_pif_tbl[] = {
    { 0, "16b Guard Protection Information" },
    { 1, "32b Guard Protection Information" },
    { 2, "64b Guard Protection Information" },
    { 3, "Qualified Type" },
    { 0, NULL }
};

static const range_string nvm_ns_qpif_tbl[] = {
    { 0x0, 0x0, "16b Guard Protection Information" },
    { 0x1, 0x1, "32b Guard Protection Information" },
    { 0x2, 0x2, "64b Guard Protection Information" },
    { 0x3, 0xf, "Reserved" },
    { 0, 0, NULL }
};

/* NVM CS 1.2 Figure 120 LBAMQF. */
static const range_string nvm_ctrl_lbamqf_tbl[] = {
    { 0x00, 0x00, "Type 0" },
    { 0x01, 0xbf, "Reserved" },
    { 0xc0, 0xff, "Vendor Specific" },
    { 0, 0, NULL }
};

/* CSI 00h only, NVM 1.2 Figures 118-120. */
static void
dissect_nvme_identify_nvm_specific(tvbuff_t *tvb, proto_tree *tree, unsigned off,
                                  unsigned len, bool controller)
{
    static const nvme_window_field ctrl_fields[] = {
        NVME_WF(0, 1, hf_nvme_id_nvm_ctrl[0], ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_id_nvm_ctrl[1], ENC_LITTLE_ENDIAN),
        NVME_WF(2, 1, hf_nvme_id_nvm_ctrl[2], ENC_LITTLE_ENDIAN),
        NVME_WF(3, 1, hf_nvme_id_nvm_ctrl[3], ENC_LITTLE_ENDIAN),
        NVME_WF(4, 4, hf_nvme_id_nvm_ctrl[4], ENC_LITTLE_ENDIAN),
        NVME_WF(8, 8, hf_nvme_id_nvm_ctrl[5], ENC_LITTLE_ENDIAN),
        NVME_WG(16, 1, hf_nvme_id_nvm_ctrl_kpiocap),
        NVME_WF(17, 1, hf_nvme_id_nvm_ctrl[6], ENC_LITTLE_ENDIAN),
        NVME_WG(18, 2, hf_nvme_id_nvm_ctrl_aocs),
        NVME_WG(20, 4, hf_nvme_id_nvm_ctrl_ver),
        NVME_WF(24, 1, hf_nvme_id_nvm_ctrl[7], ENC_LITTLE_ENDIAN),
        NVME_WG(25, 1, hf_nvme_id_nvm_ctrl_rla),     /* NVM CS 1.3 Figure 129 */
        NVME_WF(26, 2, hf_nvme_id_nvm_ctrl_slmc, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field ns_head[] = {
        NVME_WF(0, 8, hf_nvme_id_lbstm, ENC_LITTLE_ENDIAN),
        NVME_WG(8, 1, hf_nvme_id_pic),
        NVME_WG(9, 1, hf_nvme_id_pifa),
    };
    static const nvme_window_field ns_tail[] = {
        NVME_WF(268, 4, hf_nvme_id_npdgl, ENC_LITTLE_ENDIAN),
        NVME_WF(272, 4, hf_nvme_id_nprg, ENC_LITTLE_ENDIAN),
        NVME_WF(276, 4, hf_nvme_id_npra, ENC_LITTLE_ENDIAN),
        NVME_WF(280, 4, hf_nvme_id_nors, ENC_LITTLE_ENDIAN),
        NVME_WF(284, 4, hf_nvme_id_npdal, ENC_LITTLE_ENDIAN),
        NVME_WF(288, 4, hf_nvme_id_lbapss, ENC_LITTLE_ENDIAN),
        NVME_WF(292, 4, hf_nvme_id_tlbaag, ENC_LITTLE_ENDIAN),
    };
    unsigned rel, n;

    if (controller) {
        nvme_add_identify_window_fields(tvb, tree, off, len, ctrl_fields, array_length(ctrl_fields));
        return;
    }
    nvme_add_identify_window_fields(tvb, tree, off, len, ns_head, array_length(ns_head));
    /* ELBAF0..63 at 267:12, one subtree each (Figure 119). */
    if (nvme_window_intersect(off, len, 12, 256, &rel, &n)) {
        unsigned first_byte = off + rel - 12;
        unsigned lead = MIN((4 - first_byte % 4) % 4, n);
        if (lead)
            proto_tree_add_item(tree, hf_nvme_window_partial, tvb, rel, lead, ENC_NA);
        unsigned first = (first_byte + lead) / 4;
        unsigned count = (n - lead) / 4;
        for (unsigned i = first; i < first + count && i < 64; i++) {
            unsigned field_rel;
            if (!nvme_field_in_window(off, len, 12 + i * 4, 4, &field_rel))
                continue;
            proto_item_append_text(proto_tree_get_parent(
                add_group_mask_entry(tvb, tree, field_rel, 4, ASPEC(hf_nvme_id_elbaf))), " (ELBAF%u)", i);
        }
        unsigned tail = (n - lead) % 4;
        if (tail)
            proto_tree_add_item(tree, hf_nvme_window_partial, tvb, rel + n - tail, tail, ENC_NA);
    }
    nvme_add_identify_window_fields(tvb, tree, off, len, ns_tail, array_length(ns_tail));
}

static void
dissect_nvme_identify_extended(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              uint8_t cns, unsigned off, unsigned len)
{
    /* Base 2.3 Figure 340. */
    static const nvme_window_field domain_fields[] = {
        NVME_WF(0, 2, hf_nvme_id_domain_id, ENC_LITTLE_ENDIAN),
        NVME_WFP(16, 16, hf_nvme_id_domain_capacity[0], ENC_NA, post_add_bytes_from_16bytes),
        NVME_WFP(32, 16, hf_nvme_id_domain_capacity[1], ENC_NA, post_add_bytes_from_16bytes),
        NVME_WFP(48, 16, hf_nvme_id_domain_capacity[2], ENC_NA, post_add_bytes_from_16bytes),
    };
    static const nvme_window_list domain_list = {
        128, 128, 31, 0, "Domain Attributes Entry", domain_fields, array_length(domain_fields)
    };
    static const nvme_window_field eg_fields[] = {
        NVME_WF(0, 2, hf_nvme_id_eg_id, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_list eg_list = {
        2, 2, 2047, 0, NULL, eg_fields, array_length(eg_fields)
    };
    /* Base 2.3 Figure 352; 16 + 7 * 576 entries fit the 4 KiB structure. */
    static const nvme_window_field port_fields[] = {
        NVME_WF(0, 256, hf_nvme_id_traddr, ENC_ASCII),
        NVME_WF(256, 256, hf_nvme_id_tsas, ENC_NA),
        NVME_WF(512, 2, hf_nvme_id_portid, ENC_LITTLE_ENDIAN),
        NVME_WF(514, 1, hf_nvme_id_trtype, ENC_LITTLE_ENDIAN),
        NVME_WF(515, 1, hf_nvme_id_adrfam, ENC_LITTLE_ENDIAN),
        NVME_WG(516, 1, hf_nvme_id_treq),
    };
    static const nvme_window_list port_list = {
        16, 576, 7, 0, "Underlying Fabrics Transport Entry", port_fields, array_length(port_fields)
    };
    unsigned rel, count;
    uint32_t num;

    switch (cns) {
    case 0x18: /* Base 2.3 Figures 339-340. */
        count = NVME_LIST_COUNT_UNKNOWN;
        if (nvme_field_in_window(off, len, 0, 1, &rel)) {
            proto_tree_add_item_ret_uint(tree, hf_nvme_id_domain_num, tvb, rel, 1,
                                         ENC_LITTLE_ENDIAN, &num);
            count = num;
        }
        nvme_add_window_list(tvb, tree, off, len, &domain_list, count, false, true);
        break;
    case 0x19: /* Base 2.3 Figure 342. */
        count = NVME_LIST_COUNT_UNKNOWN;
        if (nvme_field_in_window(off, len, 0, 2, &rel)) {
            proto_tree_add_item_ret_uint(tree, hf_nvme_id_eg_num, tvb, rel, 2,
                                         ENC_LITTLE_ENDIAN, &num);
            count = num;
        }
        nvme_add_window_list(tvb, tree, off, len, &eg_list, count, false, true);
        break;
    case 0x1c: { /* Base 2.3 Figures 343-344; fixed 512-vector array. */
        /* Whole vectors only; partial ones stay raw. */
        unsigned lead = MIN((8 - off % 8) % 8, len), tail;
        if (lead)
            proto_tree_add_item(tree, hf_nvme_window_partial, tvb, 0, lead, ENC_NA);
        for (unsigned i = 0; i < 512; i++) {
            if (!nvme_field_in_window(off, len, i * 8, 8, &rel))
                continue;
            proto_item_append_text(proto_tree_get_parent(
                add_group_mask_entry(tvb, tree, rel, 8, ASPEC(hf_nvme_id_iocsc))),
                " (Combination %u)", i);
        }
        tail = (len - lead) % 8;
        if (tail)
            proto_tree_add_item(tree, hf_nvme_window_partial, tvb, len - tail, tail, ENC_NA);
        break;
    }
    case 0x1d: /* Base 2.4 Figures 356-357. */
        nvme_add_identify_window_field(tvb, tree, hf_nvme_id_genctr, off, len, 0, 8, ENC_LITTLE_ENDIAN);
        if (!nvme_field_in_window(off, len, 8, 8, &rel)) {
            nvme_add_identify_window_field(tvb, tree, hf_nvme_id_nument, off, len, 8, 8, ENC_LITTLE_ENDIAN);
            return;
        }
        {
            uint64_t entries;
            proto_item *ti = proto_tree_add_item_ret_uint64(tree, hf_nvme_id_nument, tvb, rel, 8,
                                                            ENC_LITTLE_ENDIAN, &entries);
            if (entries > NVME_UNDERLYING_NS_MAX)
                expert_add_info(pinfo, ti, &ei_nvme_id_nument_excess);
            count = (unsigned)MIN(MIN(entries, NVME_UNDERLYING_NS_MAX),
                                  ((uint64_t)off + len - 16 + 320 - 1) / 320);
            for (unsigned i = 0; i < count; i++) {
                unsigned pos = 16 + i * 320;
                dissect_nvme_nqn(tvb, tree, hf_nvme_id_unsnqn, 0, len, off, pos, false);
                nvme_add_identify_window_field(tvb, tree, hf_nvme_id_unsid, off, len, pos + 256, 4, ENC_LITTLE_ENDIAN);
                nvme_add_identify_window_field(tvb, tree, hf_nvme_id_ucntlid, off, len, pos + 260, 2, ENC_LITTLE_ENDIAN);
                nvme_add_identify_window_field(tvb, tree, hf_nvme_id_uidx, off, len, pos + 318, 2, ENC_LITTLE_ENDIAN);
            }
        }
        break;
    case 0x1e: /* Base 2.3 Figures 351-352. */
        nvme_add_identify_window_field(tvb, tree, hf_nvme_id_genctr, off, len, 0, 8, ENC_LITTLE_ENDIAN);
        count = NVME_LIST_COUNT_UNKNOWN;
        if (nvme_field_in_window(off, len, 8, 8, &rel)) {
            uint64_t entries;
            proto_tree_add_item_ret_uint64(tree, hf_nvme_id_nument, tvb, rel, 8,
                                           ENC_LITTLE_ENDIAN, &entries);
            count = (unsigned)MIN(entries, port_list.max);
        }
        nvme_add_window_list(tvb, tree, off, len, &port_list, count, false, true);
        break;
    case 0x20: /* Base 2.3 Figure 345. UUID list origin depends on NV. */
        nvme_add_identify_window_field(tvb, tree, hf_nvme_id_state_nv, off, len, 0, 1, ENC_LITTLE_ENDIAN);
        nvme_add_identify_window_field(tvb, tree, hf_nvme_id_state_nuuid, off, len, 1, 1, ENC_LITTLE_ENDIAN);
        if (off || len < 2)
            return;
        count = tvb_get_uint8(tvb, 0);
        for (unsigned i = 0; i < count; i++)
            nvme_add_identify_window_field(tvb, tree, hf_nvme_id_state_version, off, len, 2 + i * 2, 2, ENC_LITTLE_ENDIAN);
        for (unsigned i = 0; i < tvb_get_uint8(tvb, 1); i++)
            nvme_add_identify_window_field(tvb, tree, hf_nvme_id_state_uuid, off, len,
                                  2 + count * 2 + i * 16, 16, ENC_NA);
        break;
    }
}

static void dissect_nvme_identify_resp(tvbuff_t *cmd_tvb, packet_info *pinfo, proto_tree *cmd_tree,
                                       struct nvme_cmd_ctx *cmd_ctx, unsigned off, unsigned len)
{
    unsigned cns = cmd_ctx->cmd_ctx.cmd_identify.cns;
    unsigned csi = cmd_ctx->cmd_ctx.cmd_identify.csi;
    /* A raw copy of the window, for structures not fully decoded below. */
    bool whole = cns == 0x1c || cns == 0x1f ||
                 ((cns == 0x07 || cns == 0x1a) && csi <= 4);
    if (!whole && ((cns >= 0x05 && cns <= 0x07) || cns == 0x09 || cns == 0x0a ||
                   (cns >= 0x18 && cns <= 0x20)))
        proto_tree_add_item(cmd_tree, hf_nvme_gen_data, cmd_tvb, 0, len, ENC_NA);
    switch(cmd_ctx->cmd_ctx.cmd_identify.cns) {
    case NVME_IDENTIFY_CNS_IDENTIFY_NS:
    case NVME_IDENTIFY_CNS_NS_ALLOC:        /* same Identify Namespace structure */
        dissect_nvme_identify_ns_resp(cmd_tvb, pinfo, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_IDENTIFY_CTRL:
        dissect_nvme_identify_ctrl_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_IDENTIFY_NSLIST:
    case NVME_IDENTIFY_CNS_NS_ALLOC_LIST:   /* same Namespace ID list structure */
        dissect_nvme_identify_nslist_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_NSID_DESC_LIST:
        dissect_nvme_identify_nsid_desc_list_resp(cmd_tvb, pinfo, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_NVM_SET_LIST:
        dissect_nvme_identify_nvmset_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_CS_IND_NS:
    case 0x1f:
        dissect_nvme_identify_cs_ind_ns_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_CTRL_LIST_NS:
    case NVME_IDENTIFY_CNS_CTRL_LIST:       /* same Controller List structure */
    case 0x21:                              /* Base 2.4 section 5.2.14.3.1 */
        dissect_nvme_identify_ctrl_list_resp(cmd_tvb, pinfo, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_PRI_CTRL_CAP:
        dissect_nvme_identify_pri_ctrl_cap_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_SEC_CTRL_LIST:
        dissect_nvme_identify_sec_ctrl_list_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case NVME_IDENTIFY_CNS_NS_GRAN_LIST:
        /* Layout set by the I/O Command Set (Base 2.4 section 5.2.14.2.13). */
        if (csi == 0)
            dissect_nvme_identify_ns_gran_list_resp(cmd_tvb, cmd_tree, off, len);
        else
            proto_tree_add_item(cmd_tree, hf_nvme_gen_data, cmd_tvb, 0, len, ENC_NA);
        break;
    case NVME_IDENTIFY_CNS_UUID_LIST:
        dissect_nvme_identify_uuid_list_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case 0x22:
        dissect_nvme_identify_enst_list_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case 0x05:
    case 0x06:
    case 0x0a:
    case 0x1b:
        if (cmd_ctx->cmd_ctx.cmd_identify.csi == 0)
            dissect_nvme_identify_nvm_specific(cmd_tvb, cmd_tree, off, len,
                                               cmd_ctx->cmd_ctx.cmd_identify.cns == 0x06);
        break;
    case 0x09:
        if (cmd_ctx->cmd_ctx.cmd_identify.csi == 0)
            dissect_nvme_identify_ns_resp(cmd_tvb, pinfo, cmd_tree, off, len);
        break;
    case 0x07:
    case 0x1a:
        /* Unknown command sets do not inherit the NVM structure. */
        if (cmd_ctx->cmd_ctx.cmd_identify.csi <= 4)
            dissect_nvme_identify_nslist_resp(cmd_tvb, cmd_tree, off, len);
        break;
    case 0x18:
    case 0x19:
    case 0x1c:
    case 0x1d:
    case 0x1e:
    case 0x20:
        dissect_nvme_identify_extended(cmd_tvb, pinfo, cmd_tree,
                                      cmd_ctx->cmd_ctx.cmd_identify.cns, off, len);
        break;
    default: {
        /* 0Bh-0Fh and 23h-FFh, Base 2.4 Figure 336: no structure defined. */
        proto_item *ti = proto_tree_add_item(cmd_tree, hf_nvme_gen_data, cmd_tvb, 0, len, ENC_NA);
        expert_add_info(pinfo, ti, &ei_nvme_identify_cns_reserved);
        break;
    }
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

/* Log Page Identifiers (NVMe Base 2.3 "Get Log Page – Log Page
 * Identifiers").  LID 0Eh is defined by the
 * NVM Command Set Specification (LBA Status Information). */
typedef enum {
    NVME_LID_SUPPORTED_LOG_PAGES        = 0x00,
    NVME_LID_ERROR_INFO                 = 0x01,
    NVME_LID_SMART                      = 0x02,
    NVME_LID_FW_SLOT                    = 0x03,
    NVME_LID_CHANGED_NSLIST             = 0x04,
    NVME_LID_CMD_SUP_AND_EFF            = 0x05,
    NVME_LID_DEVICE_SELF_TEST           = 0x06,
    NVME_LID_TELEMETRY_HOST             = 0x07,
    NVME_LID_TELEMETRY_CTRL             = 0x08,
    NVME_LID_ENDURANCE_GROUP            = 0x09,
    NVME_LID_PRED_LAT_NVM_SET           = 0x0A,
    NVME_LID_PRED_LAT_EVENT_AGG         = 0x0B,
    NVME_LID_ANA                        = 0x0C,
    NVME_LID_PERSISTENT_EVENT           = 0x0D,
    NVME_LID_LBA_STATUS                 = 0x0E,
    NVME_LID_ENDURANCE_GROUP_EVENT_AGG  = 0x0F,
    NVME_LID_MEDIA_UNIT_STATUS          = 0x10,
    NVME_LID_SUP_CAP_CONFIG_LIST        = 0x11,
    NVME_LID_FEATURE_ID_SUP_AND_EFF     = 0x12,
    NVME_LID_NVME_MI_CMD_SUP_AND_EFF    = 0x13,
    NVME_LID_CMD_FEAT_LOCKDOWN          = 0x14,
    NVME_LID_BOOT_PARTITION             = 0x15,
    NVME_LID_ROTATIONAL_MEDIA           = 0x16,
    NVME_LID_DISPERSED_NS               = 0x17,
    NVME_LID_MGMT_ADDR_LIST             = 0x18,
    NVME_LID_PHY_RX_EOM                 = 0x19,
    NVME_LID_REACHABILITY_GROUPS        = 0x1A,
    NVME_LID_REACHABILITY_ASSOC         = 0x1B,
    NVME_LID_CHANGED_ALLOC_NSLIST       = 0x1C,
    NVME_LID_DEVICE_PERSONALITIES       = 0x1D,
    NVME_LID_CROSS_CTRL_RESET           = 0x1E,
    NVME_LID_LOST_HOST_COMM             = 0x1F,
    NVME_LID_FDP_CONFIGS                = 0x20,
    NVME_LID_RECLAIM_UNIT_HANDLE_USAGE  = 0x21,
    NVME_LID_FDP_STATS                  = 0x22,
    NVME_LID_FDP_EVENTS                 = 0x23,
    NVME_LID_MFR_DEFAULT_CONFIG         = 0x24,
    NVME_LID_POWER_MEASUREMENT          = 0x25,
    NVME_LID_VOLTAGE_MEASUREMENT        = 0x27,
    NVME_LID_RATE_LIMITING              = 0x28,
    NVME_LID_DISCOVERY                  = 0x70,
    NVME_LID_HOST_DISCOVERY             = 0x71,
    NVME_LID_AVE_DISCOVERY              = 0x72,
    NVME_LID_PULL_MODEL_DDC_REQ         = 0x73,
    NVME_LID_SANITIZE_NS_STATUS_LIST    = 0x7F,
    NVME_LID_RESERVATION_NOTIFICATION   = 0x80,
    NVME_LID_SANITIZE_STATUS            = 0x81,
} nvme_logpage_lid_t;

static const value_string logpage_tbl[] = {
    { NVME_LID_SUPPORTED_LOG_PAGES, "Supported Log Pages" },
    { NVME_LID_ERROR_INFO, "Error Information" },
    { NVME_LID_SMART, "SMART/Health Information" },
    { NVME_LID_FW_SLOT, "Firmware Slot Information" },
    { NVME_LID_CHANGED_NSLIST, "Changed Attached Namespace List" },
    { NVME_LID_CMD_SUP_AND_EFF, "Commands Supported and Effects" },
    { NVME_LID_DEVICE_SELF_TEST, "Device Self-test" },
    { NVME_LID_TELEMETRY_HOST, "Telemetry Host-Initiated" },
    { NVME_LID_TELEMETRY_CTRL, "Telemetry Controller-Initiated" },
    { NVME_LID_ENDURANCE_GROUP, "Endurance Group Information" },
    { NVME_LID_PRED_LAT_NVM_SET, "Predictable Latency Per NVM Set" },
    { NVME_LID_PRED_LAT_EVENT_AGG, "Predictable Latency Event Aggregate" },
    { NVME_LID_ANA, "Asymmetric Namespace Access" },
    { NVME_LID_PERSISTENT_EVENT, "Persistent Event Log" },
    { NVME_LID_LBA_STATUS, "LBA Status Information" },
    { NVME_LID_ENDURANCE_GROUP_EVENT_AGG, "Endurance Group Event Aggregate" },
    { NVME_LID_MEDIA_UNIT_STATUS, "Media Unit Status" },
    { NVME_LID_SUP_CAP_CONFIG_LIST, "Supported Capacity Configuration List" },
    { NVME_LID_FEATURE_ID_SUP_AND_EFF, "Feature Identifiers Supported and Effects" },
    { NVME_LID_NVME_MI_CMD_SUP_AND_EFF, "NVMe-MI Commands Supported and Effects" },
    { NVME_LID_CMD_FEAT_LOCKDOWN, "Command and Feature Lockdown" },
    { NVME_LID_BOOT_PARTITION, "Boot Partition" },
    { NVME_LID_ROTATIONAL_MEDIA, "Rotational Media Information" },
    { NVME_LID_DISPERSED_NS, "Dispersed Namespace Participating NVM Subsystems" },
    { NVME_LID_MGMT_ADDR_LIST, "Management Address List" },
    { NVME_LID_PHY_RX_EOM, "Physical Interface Receiver Eye Opening Measurement" },
    { NVME_LID_REACHABILITY_GROUPS, "Reachability Groups" },
    { NVME_LID_REACHABILITY_ASSOC, "Reachability Associations" },
    { NVME_LID_CHANGED_ALLOC_NSLIST, "Changed Allocated Namespace List" },
    { NVME_LID_DEVICE_PERSONALITIES, "Device Personalities" },
    { NVME_LID_CROSS_CTRL_RESET, "Cross-Controller Reset" },
    { NVME_LID_LOST_HOST_COMM, "Lost Host Communication" },
    { NVME_LID_FDP_CONFIGS, "FDP Configurations" },
    { NVME_LID_RECLAIM_UNIT_HANDLE_USAGE, "Reclaim Unit Handle Usage" },
    { NVME_LID_FDP_STATS, "FDP Statistics" },
    { NVME_LID_FDP_EVENTS, "FDP Events" },
    { NVME_LID_MFR_DEFAULT_CONFIG, "Manufacturer Default Configuration Status" },
    { NVME_LID_POWER_MEASUREMENT, "Power Measurement" },
    { NVME_LID_VOLTAGE_MEASUREMENT, "Voltage Measurement" },
    /* NVM Command Set 1.3 section 4.1.4.8 */
    { NVME_LID_RATE_LIMITING, "Rate Limiting" },
    { NVME_LID_DISCOVERY, "Discovery" },
    { NVME_LID_HOST_DISCOVERY, "Host Discovery" },
    { NVME_LID_AVE_DISCOVERY, "AVE Discovery" },
    { NVME_LID_PULL_MODEL_DDC_REQ, "Pull Model DDC Request" },
    { NVME_LID_SANITIZE_NS_STATUS_LIST, "Sanitize Namespace Status List" },
    { NVME_LID_RESERVATION_NOTIFICATION, "Reservation Notification" },
    { NVME_LID_SANITIZE_STATUS, "Sanitize Status" },
    { 0, NULL }
};

static const char *get_logpage_name(unsigned lid)
{
    if (lid >= 0x82 && lid <= 0xBE)
        return "I/O Command Set Specific";
    else if (lid == 0xBF)
        return "Zoned Namespace Command Set";
    else if (lid >= 0xC0)
        return "Vendor Specific";
    else
        return val_to_str_const(lid, logpage_tbl, "Reserved");
}

/* Names of I/O Command Set specific log pages that are only defined for one
 * CSI (Base 2.4 Figure 31, MI 2.2 Figure 144). Under any other CSI the
 * generic name stays. */
static const char *get_logpage_cs_name(unsigned lid, unsigned csi)
{
    switch (csi) {
    case 0x02:
        if (lid == 0xBF)
            return "Changed Zone List";
        break;
    case 0x03:
        if (lid == 0x85)
            return "Host Addressable Namespaces";
        break;
    case 0x04:
        if (lid == 0x82)
            return "Program List";
        if (lid == 0x83)
            return "Downloadable Program Types List";
        if (lid == 0x84)
            return "Memory Range Set List";
        break;
    default:
        break;
    }
    return NULL;
}

static const char *get_logpage_name_csi(unsigned lid, unsigned csi)
{
    const char *name = get_logpage_cs_name(lid, csi);

    return name ? name : get_logpage_name(lid);
}

static void add_logpage_lid(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%s (0x%x)", get_logpage_name(val), val);
}

static const range_string sec_type_tbl[] = {
    { 0x00, 0x00, "No security" },
    { 0x01, 0x01, "TLS 1.2" },
    { 0x02, 0x02, "TLS 1.3 or later" },
    { 0x03, 0xff, "Reserved" },
    { 0, 0, NULL }
};

static void dissect_nvme_get_logpage_ify_rcrd_tsas_tcp(tvbuff_t *cmd_tvb, proto_item *ti, unsigned off)
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

static void dissect_nvme_get_logpage_ify_rcrd_tsas_rdma(tvbuff_t *cmd_tvb, proto_item *ti, unsigned off)
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

static const range_string trt_type_tbl[] = {
    { 0, 0, "Reserved" },
    { 1, 1, "RDMA Transport" },
    { 2, 2, "Fibre Channel Transport" },
    { 3, 3, "TCP Transport" },
    { 4, 253, "Reserved" },
    { 254, 254, "Intra-host Transport" },
    { 255, 255, "Reserved" },
    { 0, 0, NULL }
};

static const range_string adrfam_type_tbl[] = {
    { 0, 0, "Reserved" },
    { 1, 1, "AF_INET" },
    { 2, 2, "AF_INET6" },
    { 3, 3, "AF_IB" },
    { 4, 4, "Fibre Channel" },
    { 5, 253, "Reserved" },
    { 254, 254, "Intra-Host" },
    { 255, 255, "Reserved" },
    { 0, 0, NULL }
};

/* Command Set Identifiers, NVMe Base 2.4 Figure 326. */
static const range_string csi_tbl[] = {
    { 0x00, 0x00, "NVM Command Set" },
    { 0x01, 0x01, "Key Value Command Set" },
    { 0x02, 0x02, "Zoned Namespace Command Set" },
    { 0x03, 0x03, "Subsystem Local Memory Command Set" },
    { 0x04, 0x04, "Computational Programs Command Set" },
    { 0x05, 0x2f, "Reserved" },
    { 0x30, 0x3f, "Vendor Specific" },
    { 0x40, 0xff, "Reserved" },
    { 0, 0, NULL }
};

static const range_string sub_type_tbl[] = {
    { 0, 0, "Reserved" },
    { 1, 1, "Referral to another Discovery Subsystem" },
    { 2, 2, "NVM subsystem with IO controllers" },
    { 3, 3, "Current Discovery Subsystem" },
    { 4, 255, "Reserved" },
    { 0, 0, NULL }
};

/* TREQ bits 1:0, NVMe Base 2.3 Figure 310 */
static const value_string treq_tsc_tbl[] = {
    { 0, "Not specified" },
    { 1, "Required" },
    { 2, "Not required" },
    { 3, "Reserved" },
    { 0, NULL }
};

/* TREQ bits 5:4, NVMe Base 2.3 Figure 310 */
static const value_string treq_tasc_tbl[] = {
    { 0, "Not specified" },
    { 1, "Authentication required" },
    { 2, "Authentication concatenated to secure channel establishment required" },
    { 3, "Reserved" },
    { 0, NULL }
};

/* Extended Attribute Type (EXATTYPE), NVMe Base 2.3 Figure 533. */
static const range_string exattype_tbl[] = {
    { 0x0000, 0x0000, "Reserved" },
    { 0x0001, 0x0001, "Host Identifier" },
    { 0x0002, 0x0002, "Admin label ASCII" },
    { 0x0003, 0x0003, "Admin label UTF-8" },
    { 0x0004, 0xFEFF, "Reserved" },
    { 0xFF00, 0xFFFF, "Vendor Specific" },
    { 0, 0, NULL }
};

/* One (Extended) Discovery Log Page Entry (NVMe Base 2.3 Figures 310/311). */
static void dissect_nvme_get_logpage_ify_rcrd_resp(tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, proto_tree *tree, uint64_t rcrd, unsigned roff, int off, unsigned len, unsigned ent_len)
{
    proto_item *ti;
    proto_tree *grp;
    unsigned tr_type;
    /* Discovery Log Page Entry bytes 255:01 (NVMe Base 2.3 Figure 311). */
    static const nvme_window_field ify_rcrd_fields[] = {
        NVME_WF(1, 1, hf_nvme_get_logpage_ify_rcrd_adrfam, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 1, hf_nvme_get_logpage_ify_rcrd_subtype, ENC_LITTLE_ENDIAN),
        NVME_WG(3, 1, hf_nvme_get_logpage_ify_rcrd_treq),
        NVME_WF(4, 2, hf_nvme_get_logpage_ify_rcrd_portid, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 2, hf_nvme_get_logpage_ify_rcrd_cntlid, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 2, hf_nvme_get_logpage_ify_rcrd_asqsz, ENC_LITTLE_ENDIAN),
        NVME_WG(10, 2, hf_nvme_get_logpage_disc_rcrd_eflags),
        NVME_WF(12, 20, hf_nvme_get_logpage_ify_rcrd_rsvd0, ENC_NA),
        NVME_WF(32, 32, hf_nvme_get_logpage_ify_rcrd_trsvcid, ENC_ASCII),
        NVME_WF(64, 192, hf_nvme_get_logpage_ify_rcrd_rsvd1, ENC_NA),
    };

    ti = proto_tree_add_bytes_format(tree, hf_nvme_get_logpage_ify_rcrd, cmd_tvb, off,
        (len < ent_len) ? len : ent_len, NULL, "Discovery Log Entry %"PRIu64" (DLE%"PRIu64")", rcrd, rcrd);
    grp =  proto_item_add_subtree(ti, ett_data);

    if (!roff) {
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ify_rcrd_trtype, cmd_tvb, off, 1, ENC_LITTLE_ENDIAN, &tr_type);
        cmd_ctx->cmd_ctx.get_logpage.tr_type = tr_type;
    } else {
        tr_type = cmd_ctx->cmd_ctx.get_logpage.tr_type;
    }

    nvme_add_window_fields_at(cmd_tvb, grp, off, roff, len, ify_rcrd_fields,
                              array_length(ify_rcrd_fields));

    dissect_nvme_nqn(cmd_tvb, grp, hf_nvme_get_logpage_ify_rcrd_subnqn,
                     off, roff < ent_len ? MIN(len, ent_len - roff) : 0, roff, 256, false);

    if (roff <= 512 && (768-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_traddr, cmd_tvb, off-roff+512, 256, ENC_ASCII);

    if (roff <= 768 && (1024-roff) <= len) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tsas, cmd_tvb, off-roff+768, 256, ENC_NA);
        if (tr_type == 1)
            dissect_nvme_get_logpage_ify_rcrd_tsas_rdma(cmd_tvb, ti, off-roff+768);
        else if (tr_type == 3)
            dissect_nvme_get_logpage_ify_rcrd_tsas_tcp(cmd_tvb, ti, off-roff+768);
    }

    /* Extended entries only (Figure 311). */
    if (ent_len <= 1024)
        return;

    if (roff <= 1024 && (1028-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_tel, cmd_tvb, off-roff+1024, 4, ENC_LITTLE_ENDIAN);

    unsigned numexat = 0;
    bool have_numexat = false;
    if (roff <= 1028 && (1030-roff) <= len) {
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ify_rcrd_numexat, cmd_tvb, off-roff+1028, 2, ENC_LITTLE_ENDIAN, &numexat);
        have_numexat = true;
    }

    if (roff <= 1030 && (1032-roff) <= len)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rcrd_rsvd2, cmd_tvb, off-roff+1030, 2, ENC_LITTLE_ENDIAN);

    if (roff > 1032 || (1032-roff) > len)
        return;

    /* Extended Attribute list (Figure 533), walked by EXATLEN. */
    unsigned exat_pos = 1032;
    unsigned nexat = 0;
    while (exat_pos + 4 <= ent_len && (exat_pos + 4 - roff) <= len &&
           (!have_numexat || nexat < numexat)) {
        unsigned exatlen;
        unsigned exattype;
        proto_item *ea_ti;
        proto_tree *ea;
        unsigned rem;

        exatlen = tvb_get_uint16(cmd_tvb, off-roff+exat_pos+2, ENC_LITTLE_ENDIAN);
        exattype = tvb_get_uint16(cmd_tvb, off-roff+exat_pos, ENC_LITTLE_ENDIAN);
        /* Bytes of this attribute the entry and the window both hold. */
        rem = ent_len - exat_pos;
        if ((len + roff - exat_pos) < rem)
            rem = len + roff - exat_pos;
        if (4 + exatlen < rem)
            rem = 4 + exatlen;

        ea_ti = proto_tree_add_bytes_format(grp, hf_nvme_get_logpage_ify_rcrd_exat,
                                            cmd_tvb, off-roff+exat_pos, rem, NULL,
                                            "Extended Attribute %u (%s)", nexat,
                                            rval_to_str_const(exattype, exattype_tbl, "Reserved"));
        ea = proto_item_add_subtree(ea_ti, ett_data);
        proto_tree_add_item(ea, hf_nvme_get_logpage_ify_rcrd_exat_type, cmd_tvb, off-roff+exat_pos, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ea, hf_nvme_get_logpage_ify_rcrd_exat_len, cmd_tvb, off-roff+exat_pos+2, 2, ENC_LITTLE_ENDIAN);
        if (rem > 4)
            proto_tree_add_item(ea, hf_nvme_get_logpage_ify_rcrd_exat_val, cmd_tvb, off-roff+exat_pos+4, rem - 4, ENC_NA);

        nexat++;
        if (!exatlen || (exatlen & 0x3))
            break;
        exat_pos += 4 + exatlen;
    }
}

static void dissect_nvme_get_logpage_ify_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned poff;
    unsigned rel;
    uint64_t rcrd;
    uint64_t recnum = 0;
    uint32_t tdlpl = 0;
    uint64_t page_end = 0;
    uint64_t pos;
    bool indexed = cmd_ctx->cmd_ctx.get_logpage.ot;
    bool have_dlpf = false;
    /* Whether entries may be extended, so have a TEL to read.  The request's
     * EXTDLPE says so until this window's DLPF says otherwise. */
    bool extended = cmd_ctx->cmd_ctx.get_logpage.extdlpe;

    grp =  proto_item_add_subtree(ti, ett_data);

    /* OT=1/LPO=0 selects the header; past it no boundary is known (Base 2.3
     * Figures 203/205/311/312). */
    if (indexed && off > 1024) {
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }

    if (nvme_field_in_window(off, len, 0, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_genctr, cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);

    if (nvme_field_in_window(off, len, 8, 8, &rel))
        proto_tree_add_item_ret_uint64(grp, hf_nvme_get_logpage_ify_numrec, cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN, &recnum);

    if (nvme_field_in_window(off, len, 16, 2, &rel)) {
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_recfmt, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
        cmd_ctx->cmd_ctx.get_logpage.records = (recnum & 0xffffffff);
    } else if (off) {
        /* NUMREC is not in this window: use an earlier window's count. */
        recnum = cmd_ctx->cmd_ctx.get_logpage.records;
    }

    /* Bytes 23:18: DLPF, Reserved, TDLPL (NVMe Base 2.3 Figure 312). */
    if (nvme_field_in_window(off, len, 18, 1, &rel)) {
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_ify_dlpf));
        extended = (tvb_get_uint8(cmd_tvb, rel) & 0x1) != 0;
        have_dlpf = true;
    }
    if (nvme_field_in_window(off, len, 19, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rsvd0, cmd_tvb, rel, 1, ENC_NA);
    if (nvme_field_in_window(off, len, 20, 4, &rel))
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ify_tdlpl, cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN, &tdlpl);
    if (nvme_field_in_window(off, len, 24, 1000, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_ify_rsvd, cmd_tvb, rel, 1000, ENC_NA);

    /* TDLPL bounds the entry list (Figure 312); 0h bounds nothing. */
    if (tdlpl > 1024) {
        page_end = tdlpl;
        extended = true;
    }

    if (off <= 1024) {
        poff = 1024 - off;
        if (poff >= len)
            return;
        rcrd = 0;
        pos = 1024;
        len -= poff;
    } else if (!extended && !((off - 1024) % 1024)) {
        /* A whole number of 1,024-byte entries past the header (Figure 312).
         * Extended entries have their own TEL, so no offset proves a boundary. */
        poff = 0;
        pos = off;
        rcrd = (off / 1024) - 1;
    } else {
        /* Nothing proves an entry boundary here; leave the bytes unplaced. */
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }

    /* The stride is each entry's TEL (Figures 311/312).  NUMREC (Figure 312)
     * counts the page's entries, so a window that starts at or past entry
     * NUMREC holds none. */
    while (len && !(recnum && rcrd >= recnum)) {
        unsigned ent_len = 1024;
        unsigned max_bytes;
        bool next_boundary = !indexed || (have_dlpf && !extended);

        if (extended && len >= 1028) {
            uint32_t tel = tvb_get_uint32(cmd_tvb, poff + 1024, ENC_LITTLE_ENDIAN);

            /* A usable TEL is dword aligned and at least 1,032. */
            if (tel >= 1032 && !(tel & 0x3)) {
                ent_len = tel;
                next_boundary = true;
            }
        } else if (extended) {
            /* No TEL in this window, so nothing proves where the entry ends. */
            next_boundary = false;
        }
        if (page_end && pos + ent_len > page_end)
            ent_len = (unsigned)(page_end - pos);
        if (!ent_len)
            break;

        max_bytes = (ent_len <= len) ? ent_len : len;
        dissect_nvme_get_logpage_ify_rcrd_resp(cmd_tvb, cmd_ctx, grp, rcrd, 0,
                                               poff, max_bytes, ent_len);
        poff += max_bytes;
        len -= max_bytes;
        pos += max_bytes;
        rcrd++;

        /* NUMREC (Figure 312) bounds the walk when known. */
        if (recnum && rcrd >= recnum)
            break;
        if (page_end && pos >= page_end)
            break;
        if (len && !next_boundary) {
            nvme_add_window_note(ti, NVME_WINDOW_RAW);
            break;
        }
    }
}

/* True if field [struct_off, struct_off+field_len) lies wholly in window
 * [off, off+len); *rel_off is its offset in cmd_tvb. */
static bool
nvme_field_in_window(unsigned off, unsigned len, unsigned struct_off, unsigned field_len,
                     unsigned *rel_off)
{
    if (off > struct_off || (struct_off + field_len - off) > len)
        return false;
    *rel_off = struct_off - off;
    return true;
}

/* True if window offset off is on a rec_len record boundary; a window
 * starting mid-record is rejected rather than spliced into a bogus entry. */
static bool
nvme_offset_record_aligned(unsigned off, unsigned rec_len)
{
    return (off % rec_len) == 0;
}

/* A 1,024-byte page of 4-byte records (LID 00h, 12h, 13h): the subtree, the
 * first record's index and how many whole records the window holds, or NULL
 * past the page or for a window starting mid-record. */
static proto_tree *
nvme_logpage_dword_array(proto_item *ti, packet_info *pinfo, unsigned off,
                         unsigned len, unsigned *first, unsigned *nrec)
{
    if (off >= 1024)
        return NULL;
    if (!nvme_offset_record_aligned(off, 4)) {
        expert_add_info(pinfo, ti, &ei_nvme_logpage_window_misaligned);
        return NULL;
    }
    *first = off / 4;
    *nrec = (1024 - off) / 4;
    if (*nrec > len / 4)
        *nrec = len / 4;
    return proto_item_add_subtree(ti, ett_data);
}

/* Error Information log page: 64-byte entries, no header (5.2.12.1.2). */
#define NVME_ERR_INF_ENTRY_LEN   64
/* ELPE (Figure 328, byte 262): at most 256 entries, 16,384 bytes. */
#define NVME_ERR_INF_MAX_ENTRIES 256

/* One Error Information Log Entry, fields wholly in the window only. */
static void dissect_nvme_get_logpage_err_inf_entry(proto_tree *tree, tvbuff_t *cmd_tvb,
                                                   unsigned base, unsigned off, unsigned len,
                                                   unsigned eidx)
{
    proto_item *ti;
    proto_tree *grp;
    unsigned rel;

    /* The entry's index in the log page, from the window offset. */
    ti = proto_tree_add_bytes_format(tree, hf_nvme_get_logpage_errinf_entry, cmd_tvb, base, len,
                                     NULL, "Error Information Log Entry %u", eidx);
    grp = proto_item_add_subtree(ti, ett_data);

    if (nvme_field_in_window(off, len, 0, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_errcnt, cmd_tvb, base+rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 8, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_sqid, cmd_tvb, base+rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 10, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_cid, cmd_tvb, base+rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 12, 2, &rel))
        add_group_mask_entry(cmd_tvb, grp, base+rel, 2, ASPEC(hf_nvme_get_logpage_errinf_sf));
    if (nvme_field_in_window(off, len, 14, 2, &rel))
        add_group_mask_entry(cmd_tvb, grp, base+rel, 2, ASPEC(hf_nvme_get_logpage_errinf_pel));
    if (nvme_field_in_window(off, len, 16, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_lba, cmd_tvb, base+rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 24, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_ns, cmd_tvb, base+rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 28, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_vsi, cmd_tvb, base+rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 29, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_trtype, cmd_tvb, base+rel, 1, ENC_LITTLE_ENDIAN);
    /* The spec's "CSI" here is Command Set Identifier (byte 30), but the
     * ".csi" filter name was already taken upstream in 2021 by Command
     * Specific Information (byte 32, below) and has shipped since 3.6.0, so
     * this field uses ".cmdset" rather than silently repurposing it. */
    if (nvme_field_in_window(off, len, 30, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_cmdset, cmd_tvb, base+rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 31, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_opc, cmd_tvb, base+rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 32, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_csi, cmd_tvb, base+rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 40, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_tsi, cmd_tvb, base+rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 42, 21, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_rsvd1, cmd_tvb, base+rel, 21, ENC_NA);
    if (nvme_field_in_window(off, len, 63, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_errinf_lpver, cmd_tvb, base+rel, 1, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_get_logpage_err_inf_resp(proto_item *ti, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned eidx, in_entry, base = 0, max_len;

    /* Walk every entry in the window (5.2.12.1.2), up to ELPE's 256. */
    if (off >= NVME_ERR_INF_MAX_ENTRIES * NVME_ERR_INF_ENTRY_LEN)
        return;
    max_len = NVME_ERR_INF_MAX_ENTRIES * NVME_ERR_INF_ENTRY_LEN - off;
    if (len > max_len)
        len = max_len;
    if (!len)
        return;

    grp = proto_item_add_subtree(ti, ett_data);

    /* Each pass covers the rest of the entry or of the window. */
    eidx = off / NVME_ERR_INF_ENTRY_LEN;
    in_entry = off % NVME_ERR_INF_ENTRY_LEN;

    while (len) {
        unsigned elen = NVME_ERR_INF_ENTRY_LEN - in_entry;

        if (elen > len)
            elen = len;
        dissect_nvme_get_logpage_err_inf_entry(grp, cmd_tvb, base, in_entry, elen, eidx);
        base += elen;
        len -= elen;
        in_entry = 0;
        eidx++;
    }
}

static void post_add_intval_from_16bytes(proto_item *ti, tvbuff_t *tvb, unsigned off)
{
    /* The 128-bit value is little-endian on the wire: byte `off` holds the
     * low-order 64 bits and byte `off+8` holds the high-order 64 bits. */
    uint64_t lo = tvb_get_uint64(tvb, off, ENC_LITTLE_ENDIAN);
    uint64_t hi = tvb_get_uint64(tvb, off+8, ENC_LITTLE_ENDIAN);
    double res;

    res = (double)hi;
    res *= (((uint64_t)1) << 63);
    res *= 2;
    res += lo;
    if (res > 99999999)
        proto_item_append_text(ti, " (%.8le)", res);
    else
        proto_item_append_text(ti, " (%.0lf)", res);
}

/* NVMe Base 2.3 Figure 222: billions of bytes, rounded up, not SMART-scaled. */
static void post_add_egroup_data_units(proto_item *ti, tvbuff_t *tvb, unsigned off)
{
    uint64_t lo = tvb_get_uint64(tvb, off, ENC_LITTLE_ENDIAN);
    uint64_t hi = tvb_get_uint64(tvb, off+8, ENC_LITTLE_ENDIAN);
    double res;

    if (!lo && !hi) {
        proto_item_append_text(ti, " (not reported)");
        return;
    }

    res = (double)hi;
    res *= (((uint64_t)1) << 63);
    res *= 2;
    res += lo;
    if (res > 99999999)
        proto_item_append_text(ti, " (<= %.8le GB)", res);
    else
        proto_item_append_text(ti, " (<= %.0lf GB)", res);
}

static void decode_smart_resp_temps(proto_tree *grp, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_item *ti;
    unsigned bytes;
    unsigned poff;
    unsigned max_bytes;
    unsigned i;


    poff = (off < 200) ? 200-off : 0;

    if (off > 214 || (poff + 2) > len)
        return;

    bytes = len - poff;
    max_bytes = (off <= 200) ? 16 : (216 - off);

    if (bytes > max_bytes)
        bytes = max_bytes;

    ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ts[0],  cmd_tvb, poff, bytes, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    for (i = 0; i < 8; i++) {
        unsigned pos = 200 + i * 2;
        unsigned rel;
        if (nvme_field_in_window(off, len, pos, 2, &rel))
            proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ts[i+1],  cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    }
}

/* NVMe Base 2.3 Figure 210, Interval Power Measurement bits 17:16 */
static const value_string smart_ipms_tbl[] = {
    { 0, "Not reported" },
    { 1, "0.0001 W" },
    { 2, "0.01 W" },
    { 3, "Reserved" },
    { 0, NULL }
};

/* NVMe Base 2.3 Figure 679: Power Measurement Types */
static const range_string smart_pmt_tbl[] = {
    { 0, 0, "NVM subsystem total power" },
    { 1, 11, "Reserved" },
    { 12, 15, "Vendor Specific" },
    { 0, 0, NULL }
};

static void dissect_nvme_get_logpage_smart_resp(proto_item *ti, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned rel;

    if (off >= 512)
        return; /* max allowed offset is < 512 */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvme_field_in_window(off, len, 0, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_smart_cw));
    if (nvme_field_in_window(off, len, 1, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ct,  cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 3, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_asc,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 4, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ast,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 5, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_lpu,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 6, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_smart_egcws));
    if (nvme_field_in_window(off, len, 7, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_smart_infw));
    if (nvme_field_in_window(off, len, 8, 24, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_rsvd0,  cmd_tvb, rel, 24, ENC_NA);
    if (nvme_field_in_window(off, len, 32, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_dur,  cmd_tvb, rel, 16, ENC_NA);
        post_add_smart_data_units(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 48, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_duw,  cmd_tvb, rel, 16, ENC_NA);
        post_add_smart_data_units(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 64, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_hrc,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 80, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_hwc,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 96, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_cbt,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 112, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_pc,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 128, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_poh,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 144, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_us,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 160, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_mie,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 176, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_smart_ele,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 192, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_wctt,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 196, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_cctt,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);

    decode_smart_resp_temps(grp, cmd_tvb, off, len);

    if (nvme_field_in_window(off, len, 216, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_tmt1c,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 220, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_tmt2c,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 224, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_tmt1t,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 228, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_tmt2t,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    /* NVMe Base 2.3 Figure 210: OLEC 239:232, IPM 243:240. */
    if (nvme_field_in_window(off, len, 232, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_smart_olec, cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 240, 4, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 4, ASPEC(hf_nvme_get_logpage_smart_ipm));
    if (off < 512) {
        unsigned poff = (off < 244) ? (244 - off) : 0;
        unsigned max_len = (off <= 244) ? 268 : 512 - off;
        if (len > poff) {
            len -= poff;
            if (len > max_len)
                len = max_len;
            proto_tree_add_item(grp, hf_nvme_get_logpage_smart_rsvd1,  cmd_tvb, poff, len, ENC_NA);
        }
    }
}

static void decode_fw_slot_frs(proto_tree *grp, tvbuff_t *cmd_tvb, uint32_t off, unsigned len)
{
    proto_item *ti;
    unsigned bytes;
    unsigned poff;
    unsigned max_bytes;
    unsigned i;


    /* tvb position of struct offset 8 (the frs array), or 0 inside it. */
    poff = (off < 8) ? 8-off : 0;

    if (off > 56 || (poff + 8) > len)
        return;

    bytes = len - poff;
    max_bytes = (off <= 8) ? 56 : (64 - off);

    if (bytes > max_bytes)
        bytes = max_bytes;

    ti = proto_tree_add_item(grp, hf_nvme_get_logpage_fw_slot_frs,  cmd_tvb, poff, bytes, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    for (i = 0; i < 7; i++) {
        unsigned pos = 8 + i * 8;
        unsigned rel;
        if (nvme_field_in_window(off, len, pos, 8, &rel))
            /* Base 2.3 Fig 212: "The firmware revision is indicated as an
             * ASCII string." The raw bytes remain visible in the hex dump
             * of the reassembled message if needed. */
            proto_tree_add_item(grp, hf_nvme_get_logpage_fw_slot_frs_ascii[i],  cmd_tvb, rel, 8, ENC_ASCII);
    }
}

/* Persistent Event Log event types, Base 2.4 Figure 236. */
static const value_string pel_event_type_tbl[] = {
    { 0x01, "SMART / Health Log Snapshot" },
    { 0x02, "Firmware Commit" },
    { 0x03, "Timestamp Change" },
    { 0x04, "Power-on or Reset" },
    { 0x05, "NVM Subsystem Hardware Error" },
    { 0x06, "Change Namespace" },
    { 0x07, "Format NVM Start" },
    { 0x08, "Format NVM Completion" },
    { 0x09, "Sanitize Start" },
    { 0x0a, "Sanitize Completion" },
    { 0x0b, "Set Feature" },
    { 0x0c, "Telemetry Log Created" },
    { 0x0d, "Thermal Excursion" },
    { 0x0e, "Sanitize Media Verification" },
    { 0x0f, "Configurable Device Personality Change" },
    { 0x10, "Exported NVM Subsystem Change" },
    { 0xde, "Vendor Specific" },
    { 0xdf, "TCG Defined" },
    { 0, NULL }
};

/* Event Header Additional Information PIT, Base 2.3 Figure 231. */
static const value_string pel_pit_tbl[] = {
    { 0, "Port identifier not reported" },
    { 1, "NVM subsystem port" },
    { 2, "Management Endpoint" },
    { 3, "Not associated with a port" },
    { 0, NULL }
};

/* Reporting Context Port Identifier Type, Base 2.4 Figure 233. */
static const value_string pel_rcpit_tbl[] = {
    { 0, "No Reporting Context" },
    { 1, "NVM Subsystem Port" },
    { 2, "Management Endpoint" },
    { 3, "Reserved" },
    { 0, NULL }
};

/* Firmware Activation, Base 2.3 Figure 238. */
static const value_string pel_por_fa_tbl[] = {
    { 0, "No firmware activation" },
    { 1, "New firmware activated due to this power-on or reset" },
    { 2, "Firmware activation attempt failed" },
    { 0, NULL }
};

/* NVM Subsystem Hardware Error Event Codes, Base 2.3 Figure 240. */
static const value_string pel_hwe_code_tbl[] = {
    { 0x01, "PCIe Correctable Error" },
    { 0x02, "PCIe Uncorrectable Non fatal Error" },
    { 0x03, "PCIe Uncorrectable Fatal Error" },
    { 0x04, "PCIe Link Status Change" },
    { 0x05, "PCIe Link Not Active" },
    { 0x06, "Critical Warning Condition" },
    { 0x07, "Endurance Group Critical Warning Condition" },
    { 0x08, "Unexpected Power Loss" },
    { 0x09, "Controller Fatal Status" },
    { 0x0a, "Media and Data Integrity Status" },
    { 0x0b, "Controller Ready Timeout Exceeded" },
    { 0, NULL }
};

/* Thermal Excursion THRESH, Base 2.3 Figure 252. */
static const range_string pel_te_thresh_rvals[] = {
    { 0x01, 0x01, "Composite Temperature reached WCTEMP" },
    { 0x02, 0x02, "Composite Temperature reached CCTEMP" },
    { 0x03, 0x03, "Composite Temperature reached TMT1 (light throttling started)" },
    { 0x04, 0x04, "Composite Temperature reached TMT2 (heavy throttling started)" },
    { 0x05, 0x05, "Vendor specific thermal management started" },
    { 0x88, 0x88, "Composite Temperature returned to normal" },
    { 0x89, 0x89, "Thermal management stopped" },
    { 0xb0, 0xb0, "Composite Temperature reached an under temperature threshold" },
    { 0xf0, 0xff, "Vendor specific" },
    { 0, 0, NULL }
};

/* Exported NVM Subsystem Change OTYP, Base 2.4 Figure 257. */
static const value_string pel_ensc_otyp_tbl[] = {
    { 0x00, "Created an Exported NVM Subsystem" },
    { 0x01, "Deleted an Exported NVM Subsystem" },
    { 0x02, "Added an Exported Namespace" },
    { 0x03, "Deleted an Exported Namespace" },
    { 0x04, "Added an Exported Controller" },
    { 0x05, "Deleted an Exported Controller" },
    { 0x06, "Added an Exported Port" },
    { 0x07, "Deleted an Exported Port" },
    { 0x08, "Allowed Host List Change" },
    { 0x09, "Restricted Access Change" },
    { 0, NULL }
};

/* Vendor Specific Event Data Type, Base 2.3 Figure 256. */
static const value_string pel_vse_vsedt_tbl[] = {
    { 0x01, "Event Name" },
    { 0x02, "ASCII String" },
    { 0x03, "Binary" },
    { 0x04, "Signed Integer" },
    { 0, NULL }
};

/* What one event's header says (Base 2.3 Figure 231), offsets event-relative. */
typedef struct {
    uint32_t start;     /* log offset of the event */
    uint32_t total;     /* EHL + 3 + EL */
    uint16_t vsil, el;
    uint8_t ehl, type, rev;
    int64_t sel;        /* the data field selecting the layout, or -1 when unseen */
} nvme_pel_event;

/* The reporting context of one scope (Base 2.3 section 5.2.12.1.14). */
typedef struct {
    uint64_t tll;
    uint32_t hlen;
    int32_t gnum;           /* -1 when unseen */
    wmem_tree_t *events;    /* event start -> nvme_pel_event */
} nvme_pel_context;

/* What a window knew of its log: kept per frame for revisits. */
typedef struct {
    uint64_t tll;           /* UINT64_MAX when unknown */
    uint32_t hlen;          /* 0 when unknown */
    bool at_boundary;       /* the window begins an event */
    bool in_event;          /* the window begins inside ev */
    nvme_pel_event ev;
} nvme_pel_known;

static wmem_map_t *nvme_pel_contexts;

typedef struct {
    tvbuff_t *tvb;
    packet_info *pinfo;
    proto_tree *tree;
    uint32_t off;           /* log offset of tvb offset 0 */
    uint32_t end;           /* log offset of the window end, within TLL */
    uint64_t tll;
    nvme_pel_context *learn;
} nvme_pel_walk;

/* The part of event-relative region [a, a+n) of the event at e that is in
 * the window: tvb offset, region-relative offset, and length. */
static bool
pel_region(const nvme_pel_walk *w, uint32_t e, uint32_t a, uint32_t n,
           unsigned *base, unsigned *roff, unsigned *avail)
{
    uint64_t lo = MAX((uint64_t)w->off, (uint64_t)e + a);
    uint64_t hi = MIN((uint64_t)w->end, (uint64_t)e + a + n);

    if (lo >= hi)
        return false;
    *base = (unsigned)(lo - w->off);
    *roff = (unsigned)(lo - e - a);
    *avail = (unsigned)(hi - lo);
    return true;
}

/* Base 2.3 Figure 235. */
static void
pel_decode_fw_commit(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff, unsigned avail)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 8, hf_nvme_pel_fwc_ofr, ENC_ASCII),
        NVME_WF(8, 8, hf_nvme_pel_fwc_nfr, ENC_ASCII),
        NVME_WF(16, 1, hf_nvme_pel_fwc_fca, ENC_LITTLE_ENDIAN),
        NVME_WF(17, 1, hf_nvme_pel_fwc_fslt, ENC_LITTLE_ENDIAN),
        NVME_WF(18, 1, hf_nvme_pel_fwc_stctfcc, ENC_LITTLE_ENDIAN),
        NVME_WF(19, 1, hf_nvme_pel_fwc_srfcc, ENC_LITTLE_ENDIAN),
        NVME_WF(20, 2, hf_nvme_pel_fwc_vafcrc, ENC_LITTLE_ENDIAN),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
}

/* Base 2.3 Figure 236; the Timestamp follows Base 2.4 Figure 480. */
static void
pel_decode_ts_change(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff, unsigned avail)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 6, hf_nvme_pel_tsc_ptstp, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 1, hf_nvme_pel_tsc_synch, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 1, hf_nvme_pel_tsc_origin, ENC_LITTLE_ENDIAN),
        NVME_WF(7, 1, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(8, 8, hf_nvme_pel_tsc_msr, ENC_LITTLE_ENDIAN),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
}

/* Base 2.3 Figures 237 and 238. */
static void
pel_decode_power_on(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff,
                    unsigned avail, unsigned dlen)
{
    static const nvme_window_field frev[] = {
        NVME_WF(0, 8, hf_nvme_pel_por_frev, ENC_ASCII),
    };
    static const nvme_window_field desc[] = {
        NVME_WF(0, 2, hf_nvme_pel_por_cntlid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 1, hf_nvme_pel_por_fa, ENC_LITTLE_ENDIAN),
        NVME_WF(3, 1, hf_nvme_pel_por_rdnf, ENC_LITTLE_ENDIAN),
        NVME_WF(3, 1, hf_nvme_pel_por_oip_rsvd, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 12, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(16, 4, hf_nvme_pel_por_cpwrc, ENC_LITTLE_ENDIAN),
        NVME_WF(20, 8, hf_nvme_pel_por_pom, ENC_LITTLE_ENDIAN),
        NVME_WF(28, 6, hf_nvme_pel_por_ctstp, ENC_LITTLE_ENDIAN),
        NVME_WF(34, 1, hf_nvme_pel_por_synch, ENC_LITTLE_ENDIAN),
        NVME_WF(34, 1, hf_nvme_pel_por_origin, ENC_LITTLE_ENDIAN),
        NVME_WF(35, 1, hf_nvme_pel_ev_rsvd, ENC_NA),
    };
    unsigned wend = roff + avail;
    unsigned n = (dlen - 8) / 36;

    nvme_add_window_fields_at(tvb, tree, base, roff, avail, frev, array_length(frev));
    for (unsigned i = roff > 8 ? (roff - 8) / 36 : 0; i < n; i++) {
        unsigned dpos = 8 + i * 36;
        unsigned lo = MAX(dpos, roff);
        unsigned hi = MIN(dpos + 36, wend);

        if (lo >= wend)
            break;
        proto_item *ti = proto_tree_add_item(tree, hf_nvme_pel_por_desc, tvb,
                                             base + lo - roff, hi - lo, ENC_NA);
        proto_item_append_text(ti, " %u", i);
        nvme_add_window_fields_at(tvb, proto_item_add_subtree(ti, ett_data),
                                  base + lo - roff, lo - dpos, hi - lo, desc,
                                  array_length(desc));
    }
}

/* Base 2.3 Figures 239-243: the AHEI starts at byte 4. */
static void
pel_decode_hw_error(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff,
                    unsigned avail, unsigned dlen, int32_t code)
{
    static const nvme_window_field head[] = {
        NVME_WF(0, 2, hf_nvme_pel_hwe_code, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_pel_ev_rsvd, ENC_NA),
    };
    /* Figure 243; bytes 79:16 may be omitted. */
    static const nvme_window_field pcie[] = {
        NVME_WF(4, 2, hf_nvme_pel_hwe_pciedsr, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 1, hf_nvme_pel_hwe_pcieaers, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 1, hf_nvme_pel_hwe_pcieas_rsvd, ENC_LITTLE_ENDIAN),
        NVME_WF(7, 13, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(20, 16, hf_nvme_pel_hwe_pcieaes, ENC_NA),
        NVME_WF(36, 16, hf_nvme_pel_hwe_pcieaem, ENC_NA),
        NVME_WF(52, 16, hf_nvme_pel_hwe_pcieahlr, ENC_NA),
        NVME_WF(68, 16, hf_nvme_pel_hwe_pcieatplr, ENC_NA),
    };
    static const nvme_window_field lnksta[] = {
        NVME_WF(4, 2, hf_nvme_pel_hwe_lnksta, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field cw[] = {
        NVME_WG(4, 1, hf_nvme_get_logpage_smart_cw),
    };
    static const nvme_window_field egcw[] = {
        NVME_WF(5, 1, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(6, 2, hf_nvme_pel_hwe_egid, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field upl[] = {
        NVME_WFP(4, 16, hf_nvme_pel_hwe_upl, ENC_NA, post_add_intval_from_16bytes),
        NVME_WF(20, 1, hf_nvme_pel_hwe_uploa, ENC_LITTLE_ENDIAN),
        NVME_WF(20, 1, hf_nvme_pel_hwe_upli_rsvd, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field cqe[] = {
        NVME_WF(4, 16, hf_nvme_pel_hwe_cqe, ENC_NA),
    };
    static const nvme_window_field cst[] = {
        NVME_WF(4, 1, hf_nvme_pel_hwe_cst_cnr, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 1, hf_nvme_pel_hwe_cst_acmnr, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 1, hf_nvme_pel_hwe_cst_nnr, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 1, hf_nvme_pel_hwe_cst_crime, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 1, hf_nvme_pel_hwe_cst_rsvd, ENC_LITTLE_ENDIAN),
        NVME_WF(5, 3, hf_nvme_pel_ev_rsvd, ENC_NA),
    };
    const nvme_window_field *f = NULL;
    unsigned n = 0;
    unsigned rel;

    nvme_add_window_fields_at(tvb, tree, base, roff, avail, head, array_length(head));
    if (dlen <= 4)
        return;
    switch (code) {
    case 0x01: case 0x02: case 0x03:
        f = pcie; n = array_length(pcie); break;
    case 0x04:
        f = lnksta; n = array_length(lnksta); break;
    case 0x06:
        f = cw; n = array_length(cw); break;
    case 0x07:
        if (nvme_field_in_window(roff, avail, 4, 1, &rel)) {
            proto_tree *t = add_group_mask_entry(tvb, tree, base + rel, 1,
                                                 hf_nvme_get_logpage_egroup_cw, 5);
            proto_tree_add_item(t, hf_nvme_get_logpage_egroup_cw[5], tvb,
                                base + rel, 1, ENC_LITTLE_ENDIAN);
        }
        f = egcw; n = array_length(egcw); break;
    case 0x08:
        f = upl; n = array_length(upl); break;
    case 0x0a:
        f = cqe; n = array_length(cqe); break;
    case 0x0b:
        f = cst; n = array_length(cst); break;
    default:
        break;
    }
    if (f) {
        nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, n);
    } else {
        unsigned b = MAX(roff, 4);
        if (b < roff + avail)
            proto_tree_add_item(tree, hf_nvme_pel_hwe_ahei, tvb, base + b - roff,
                                roff + avail - b, ENC_NA);
    }
}

static const char *get_feature_id_name(uint8_t fid);
static void dissect_nvme_get_logpage_telemetry_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, uint64_t off, unsigned len);

/* Base 2.3 Figure 244; FLBAS and DPS per NVM Command Set 1.2 Figure 108. */
static void
pel_decode_change_ns(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff, unsigned avail)
{
    static const nvme_window_field f[] = {
        NVME_WG(0, 4, hf_nvme_pel_cns_nmcdw10),
        NVME_WF(4, 4, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(8, 8, hf_nvme_pel_cns_nsze, ENC_LITTLE_ENDIAN),
        NVME_WF(16, 8, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(24, 8, hf_nvme_pel_cns_ncap, ENC_LITTLE_ENDIAN),
        NVME_WG(32, 1, hf_nvme_identify_ns_flbas),
        NVME_WG(33, 1, hf_nvme_identify_ns_dps),
        NVME_WG(34, 1, hf_nvme_identify_ns_nmic),
        NVME_WF(35, 1, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(36, 4, hf_nvme_pel_cns_anagrpid, ENC_LITTLE_ENDIAN),
        NVME_WF(40, 2, hf_nvme_pel_cns_nvmsetid, ENC_LITTLE_ENDIAN),
        NVME_WF(42, 2, hf_nvme_pel_cns_endgid, ENC_LITTLE_ENDIAN),
        NVME_WF(44, 4, hf_nvme_pel_nsid, ENC_LITTLE_ENDIAN),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
}

/* Base 2.3 Figure 245. */
static void
pel_decode_format_start(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff, unsigned avail)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 4, hf_nvme_pel_nsid, ENC_LITTLE_ENDIAN),
        NVME_WG(4, 1, hf_nvme_identify_ctrl_fna),
        NVME_WF(5, 3, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WG(8, 4, hf_nvme_format_nvm_dword10),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
}

/* Base 2.3 Figure 246; STATUS is the completion Status field (Figure 100). */
static void
pel_decode_format_cmpl(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff, unsigned avail)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 4, hf_nvme_pel_nsid, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 1, hf_nvme_pel_fmc_sfpi, ENC_LITTLE_ENDIAN),
        NVME_WG(5, 1, hf_nvme_pel_fmc_fnvms),
        NVME_WF(6, 2, hf_nvme_pel_cinfo, ENC_LITTLE_ENDIAN),
        NVME_WG(8, 2, hf_nvme_pel_fmc_info),
        NVME_WF(10, 2, hf_nvme_pel_ev_rsvd, ENC_NA),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
}

/* Base 2.3 Figure 247. */
static void
pel_decode_sanitize_start(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff, unsigned avail)
{
    static const nvme_window_field f[] = {
        NVME_WG(0, 4, hf_nvme_identify_ctrl_sanicap),
        NVME_WG(4, 4, hf_nvme_sanitize_dword10),
        NVME_WF(8, 4, hf_nvme_sanitize_ovrpat, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_pel_nsid, ENC_LITTLE_ENDIAN),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
}

/* Base 2.3 Figure 248; SPROG and SSTAT use the Sanitize Status log formats. */
static void
pel_decode_sanitize_cmpl(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff, unsigned avail)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 2, hf_nvme_get_logpage_sanitize_sprog, ENC_LITTLE_ENDIAN),
        NVME_WG(2, 2, hf_nvme_get_logpage_sanitize_sstat),
        NVME_WF(4, 2, hf_nvme_pel_cinfo, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 2, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(8, 4, hf_nvme_pel_nsid, ENC_LITTLE_ENDIAN),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
}

/* The part of data region [pos, pos+size) in the window, as a raw field. */
static void
pel_add_span(tvbuff_t *tvb, proto_tree *tree, int hf, unsigned base, unsigned roff,
             unsigned avail, unsigned pos, unsigned size)
{
    unsigned lo = MAX(pos, roff);
    unsigned hi = MIN(pos + size, roff + avail);

    if (lo < hi)
        proto_tree_add_item(tree, hf, tvb, base + lo - roff, hi - lo, ENC_NA);
}

/* Base 2.3 Figure 250, laid out by the SFEL in sel. */
static void
pel_decode_set_feature(tvbuff_t *tvb, packet_info *pinfo, proto_item *di, unsigned base,
                       unsigned roff, unsigned avail, unsigned dlen, int64_t sel)
{
    static const nvme_window_field f[] = {
        NVME_WG(0, 4, hf_nvme_pel_sfe_sfel),
    };
    proto_tree *tree = proto_item_add_subtree(di, ett_data);
    unsigned rel;

    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
    if (sel < 0)
        return;

    unsigned dwc = (unsigned)sel & 0x7;
    bool lccdw0 = (sel & 0x8) != 0;
    unsigned mbc = (unsigned)(sel >> 16) & 0xffff;
    unsigned mpos = 4 + dwc * 4;

    if (mpos + mbc + (lccdw0 ? 4 : 0) > dlen) {
        expert_add_info(pinfo, di, &ei_nvme_pel_event_length);
        return;
    }
    for (unsigned i = 0; i < dwc; i++) {
        if (!nvme_field_in_window(roff, avail, 4 + i * 4, 4, &rel))
            continue;
        proto_item *ti = proto_tree_add_item(tree, hf_nvme_pel_sfe_cdw, tvb, base + rel, 4,
                                             ENC_LITTLE_ENDIAN);
        proto_item_append_text(ti, " (CDW%u)", 10 + i);
        if (i == 0)
            proto_item_append_text(ti, ", Feature Identifier: %s",
                                   get_feature_id_name(tvb_get_uint8(tvb, base + rel)));
    }
    pel_add_span(tvb, tree, hf_nvme_pel_sfe_mbuf, base, roff, avail, mpos, mbc);
    if (lccdw0 && nvme_field_in_window(roff, avail, mpos + mbc, 4, &rel))
        proto_tree_add_item(tree, hf_nvme_pel_sfe_ccdw0, tvb, base + rel, 4, ENC_LITTLE_ENDIAN);
}

/* Base 2.3 Figure 251: a copy of the first 512 bytes of the Telemetry log
 * named by its Log Identifier byte (sel). */
static void
pel_decode_telemetry(tvbuff_t *tvb, proto_item *di, unsigned base, unsigned roff,
                     unsigned avail, int64_t sel)
{
    if (roff >= 512)
        return;
    unsigned n = MIN(avail, 512 - roff);
    if (sel == 0x07 || sel == 0x08) {
        struct nvme_cmd_ctx c;

        memset(&c, 0, sizeof(c));
        c.cmd_ctx.get_logpage.lid = (uint8_t)sel;
        dissect_nvme_get_logpage_telemetry_resp(di, tvb_new_subset_length(tvb, base, n), &c, roff, n);
    } else {
        proto_tree_add_item(proto_item_add_subtree(di, ett_data), hf_nvme_pel_tlc_til,
                            tvb, base, n, ENC_NA);
    }
}

/* Base 2.3 Figure 252. */
static void
pel_decode_thermal(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff, unsigned avail)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 1, hf_nvme_pel_te_otmp, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_pel_te_thresh, ENC_LITTLE_ENDIAN),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
}

/* Base 2.3 Figure 253. */
static void
pel_decode_cdp(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff,
               unsigned avail, unsigned dlen)
{
    static const nvme_window_field f[] = {
        NVME_WG(0, 1, hf_nvme_pel_cdp_ps),
        NVME_WF(1, 1, hf_nvme_pel_cdp_perid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 10, hf_nvme_pel_ev_rsvd, ENC_NA),
    };
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, array_length(f));
    pel_add_span(tvb, tree, hf_nvme_pel_cdp_ped, base, roff, avail, 12, dlen - 12);
}

/* Base 2.4 Figure 257: EEID and UEID are laid out by the OTYP in sel. */
static void
pel_decode_exported_ns(tvbuff_t *tvb, proto_tree *tree, unsigned base, unsigned roff,
                       unsigned avail, int64_t sel)
{
    static const nvme_window_field head[] = {
        NVME_WF(0, 2, hf_nvme_pel_ensc_esubid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 1, hf_nvme_pel_ensc_otyp, ENC_LITTLE_ENDIAN),
        NVME_WF(3, 5, hf_nvme_pel_ev_rsvd, ENC_NA),
    };
    static const nvme_window_field subsys[] = {
        NVME_WF(8, 4, hf_nvme_pel_ensc_eeid_esubid, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 4, hf_nvme_pel_ensc_id_rsvd, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_pel_ensc_ueid, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field ns[] = {
        NVME_WF(8, 4, hf_nvme_pel_ensc_eeid_nsid, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_pel_ensc_ueid_nsid, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field ctrl[] = {
        NVME_WF(8, 4, hf_nvme_pel_ensc_eeid_cntlid, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 4, hf_nvme_pel_ensc_id_rsvd, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_pel_ensc_ueid_cntlid, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_pel_ensc_id_rsvd, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field port[] = {
        NVME_WF(8, 4, hf_nvme_pel_ensc_eeid_portid, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 4, hf_nvme_pel_ensc_id_rsvd, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_pel_ensc_ueid_portid, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_pel_ensc_id_rsvd, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field raw[] = {
        NVME_WF(8, 4, hf_nvme_pel_ensc_eeid, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_pel_ensc_ueid, ENC_LITTLE_ENDIAN),
    };
    const nvme_window_field *f;
    unsigned n;

    nvme_add_window_fields_at(tvb, tree, base, roff, avail, head, array_length(head));
    switch (sel) {
    case 0x00: case 0x01: case 0x08: case 0x09:
        f = subsys; n = array_length(subsys); break;
    case 0x02: case 0x03:
        f = ns; n = array_length(ns); break;
    case 0x04: case 0x05:
        f = ctrl; n = array_length(ctrl); break;
    case 0x06: case 0x07:
        f = port; n = array_length(port); break;
    default:
        f = raw; n = array_length(raw); break;
    }
    nvme_add_window_fields_at(tvb, tree, base, roff, avail, f, n);
}

/* Base 2.3 Figures 254-256: a list of descriptors filling the event data.
 * Walked only from a window that holds the start of the data. */
static void
pel_decode_vendor(tvbuff_t *tvb, packet_info *pinfo, proto_item *di, unsigned base,
                  unsigned roff, unsigned avail, unsigned dlen)
{
    proto_tree *tree = proto_item_add_subtree(di, ett_data);
    unsigned p = 0;

    if (roff)
        return;
    while (p < dlen) {
        if (p + 6 > dlen) {
            expert_add_info(pinfo, di, &ei_nvme_pel_event_length);
            return;
        }
        if (p + 6 > avail)
            return;

        unsigned vsedl = tvb_get_letohs(tvb, base + p + 4);
        uint8_t vsedt = tvb_get_uint8(tvb, base + p + 2);
        unsigned tot = 6 + vsedl;
        unsigned shown = MIN(tot, MIN(dlen, avail) - p);
        proto_item *ti = proto_tree_add_item(tree, hf_nvme_pel_vse_desc, tvb, base + p, shown, ENC_NA);
        proto_tree *dt = proto_item_add_subtree(ti, ett_data);

        proto_tree_add_item(dt, hf_nvme_pel_vse_vsec, tvb, base + p, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(dt, hf_nvme_pel_vse_vsedt, tvb, base + p + 2, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(dt, hf_nvme_pel_vse_uidx, tvb, base + p + 3, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(dt, hf_nvme_pel_vse_vsedl, tvb, base + p + 4, 2, ENC_LITTLE_ENDIAN);
        if (p + tot > dlen) {
            expert_add_info(pinfo, ti, &ei_nvme_pel_event_length);
            return;
        }
        if (p + tot > avail)
            return;
        if (vsedl) {
            unsigned d = base + p + 6;

            if (vsedt == 0x01 || vsedt == 0x02) {
                proto_tree_add_item(dt, hf_nvme_pel_vse_vsed_str, tvb, d, vsedl, ENC_ASCII);
            } else if (vsedt == 0x04 && vsedl == 8) {
                proto_tree_add_item(dt, hf_nvme_pel_vse_vsed_int, tvb, d, 8, ENC_LITTLE_ENDIAN);
            } else {
                proto_tree_add_item(dt, hf_nvme_pel_vse_vsed, tvb, d, vsedl, ENC_NA);
                if (vsedt == 0x04)
                    expert_add_info(pinfo, ti, &ei_nvme_pel_event_length);
            }
        }
        p += tot;
    }
}

static void
pel_learn_event(nvme_pel_context *ctx, const nvme_pel_event *ev)
{
    const nvme_pel_event *p = (const nvme_pel_event *)wmem_tree_lookup32_le(ctx->events, ev->start + ev->total - 1);

    /* A conflicting or overlapping event: the earlier reads no longer hold. */
    if (p && p->start + p->total > ev->start &&
        (p->start != ev->start || p->total != ev->total || p->type != ev->type)) {
        ctx->events = wmem_tree_new(wmem_file_scope());
        p = NULL;
    }
    if (p && p->start == ev->start)
        return;
    wmem_tree_insert32(ctx->events, ev->start,
                       wmem_memdup(wmem_file_scope(), ev, sizeof(*ev)));
}

/* Known event types: ETR, event data length bounds (Base 2.3 Figures
 * 234-253, Base 2.4 Figure 257), and the data field that selects the rest
 * of the layout, kept so a later window can decode a continuation. */
typedef struct {
    uint8_t type, rev;
    uint16_t min_len, max_len;
    uint8_t sel_pos, sel_size;
} pel_layout;

static const pel_layout pel_layouts[] = {
    { 0x01, 1, 512, UINT16_MAX, 0, 0 },
    { 0x02, 1, 22, UINT16_MAX, 0, 0 },
    { 0x03, 1, 16, UINT16_MAX, 0, 0 },
    { 0x04, 1, 44, UINT16_MAX, 0, 0 },
    { 0x05, 2, 4, UINT16_MAX, 0, 2 },
    { 0x06, 2, 48, UINT16_MAX, 0, 0 },
    { 0x07, 1, 12, UINT16_MAX, 0, 0 },
    { 0x08, 2, 12, UINT16_MAX, 0, 0 },
    { 0x09, 2, 16, UINT16_MAX, 0, 0 },
    { 0x0a, 2, 12, UINT16_MAX, 0, 0 },
    { 0x0b, 1, 4, UINT16_MAX, 0, 4 },
    { 0x0c, 1, 512, UINT16_MAX, 0, 1 },
    { 0x0d, 1, 2, UINT16_MAX, 0, 0 },
    { 0x0e, 1, 0, 0, 0, 0 },
    { 0x0f, 1, 12, UINT16_MAX, 0, 0 },
    { 0x10, 1, 16, UINT16_MAX, 2, 1 },
    { 0xde, 1, 0, UINT16_MAX, 0, 0 },
};

static const pel_layout *
pel_find_layout(uint8_t type)
{
    for (unsigned i = 0; i < array_length(pel_layouts); i++) {
        if (pel_layouts[i].type == type)
            return &pel_layouts[i];
    }
    return NULL;
}

enum { PEL_EV_WINDOW_END, PEL_EV_DONE, PEL_EV_INVALID };

/* Decode the event at log offset e, or its rest when known gives its header
 * from an earlier window.  On PEL_EV_DONE, *next is the next event; on
 * PEL_EV_INVALID, it is where the unparsable bytes start. */
static int
pel_event(nvme_pel_walk *w, uint32_t e, const nvme_pel_event *known, uint32_t *next)
{
    static const nvme_window_field hdr[] = {
        NVME_WF(0, 1, hf_nvme_pel_ev_et, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_pel_ev_etr, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 1, hf_nvme_pel_ev_ehl, ENC_LITTLE_ENDIAN),
        NVME_WF(3, 1, hf_nvme_pel_ev_pit, ENC_LITTLE_ENDIAN),
        NVME_WF(3, 1, hf_nvme_pel_ev_ehai_rsvd, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 2, hf_nvme_pel_ev_cntlid, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 6, hf_nvme_pel_ev_etstp, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 1, hf_nvme_pel_ev_synch, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 1, hf_nvme_pel_ev_origin, ENC_LITTLE_ENDIAN),
        NVME_WF(13, 1, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(14, 2, hf_nvme_pel_ev_pelpid, ENC_LITTLE_ENDIAN),
        NVME_WF(16, 4, hf_nvme_pel_ev_rsvd, ENC_NA),
        NVME_WF(20, 2, hf_nvme_pel_ev_vsil, ENC_LITTLE_ENDIAN),
        NVME_WF(22, 2, hf_nvme_pel_ev_el, ENC_LITTLE_ENDIAN),
    };
    tvbuff_t *tvb = w->tvb;
    uint32_t lo = MAX(w->off, e);
    unsigned base = lo - w->off, roff = lo - e, avail = w->end - lo;
    nvme_pel_event ev = { .start = e, .sel = -1 };
    bool valid;
    unsigned b, ro, n;

    if (known) {
        ev = *known;
    } else if (avail >= 24) {
        ev.type = tvb_get_uint8(tvb, base);
        ev.rev = tvb_get_uint8(tvb, base + 1);
        ev.ehl = tvb_get_uint8(tvb, base + 2);
        ev.vsil = tvb_get_letohs(tvb, base + 20);
        ev.el = tvb_get_letohs(tvb, base + 22);
        ev.total = ev.ehl + 3 + ev.el;
    }
    bool hdr_known = known || avail >= 24;
    valid = hdr_known && ev.ehl >= 21 && ev.vsil <= ev.el &&
            (uint64_t)e + ev.total <= w->tll;
    unsigned ilen = !hdr_known ? avail : valid ? MIN(ev.total - roff, avail) : MIN(24 - roff, avail);

    proto_item *ei = proto_tree_add_item(w->tree, hf_nvme_pel_ev, tvb, base, ilen, ENC_NA);
    proto_tree *et = proto_item_add_subtree(ei, ett_data);
    if (hdr_known || roff == 0)
        proto_item_append_text(ei, ": %s",
            val_to_str_const(hdr_known ? ev.type : tvb_get_uint8(tvb, base),
                             pel_event_type_tbl, "Reserved"));
    if (roff)
        proto_item_append_text(ei, " (continued)");
    nvme_add_window_fields_at(tvb, et, base, roff, ilen, hdr, array_length(hdr));
    if (!hdr_known) {
        /* The log ends before the 24-byte header does. */
        if ((uint64_t)e + 24 > w->tll) {
            expert_add_info(w->pinfo, ei, &ei_nvme_pel_invalid_event);
            *next = w->end;
            return PEL_EV_INVALID;
        }
        proto_item_append_text(ei, " (incomplete)");
        return PEL_EV_WINDOW_END;
    }
    if (!valid) {
        expert_add_info(w->pinfo, ei, &ei_nvme_pel_invalid_event);
        *next = e + 24;
        return PEL_EV_INVALID;
    }

    uint32_t vsi_at = ev.ehl + 3, data_at = vsi_at + ev.vsil;
    unsigned dlen = ev.el - ev.vsil;
    const pel_layout *lay = pel_find_layout(ev.type);
    if (ev.sel < 0 && lay && lay->sel_size &&
        dlen >= (unsigned)lay->sel_pos + lay->sel_size &&
        pel_region(w, e, data_at + lay->sel_pos, lay->sel_size, &b, &ro, &n) &&
        ro == 0 && n == lay->sel_size)
        ev.sel = n == 1 ? tvb_get_uint8(tvb, b) : n == 2 ? tvb_get_letohs(tvb, b) : tvb_get_letohl(tvb, b);
    if (w->learn && !known)
        pel_learn_event(w->learn, &ev);

    if (pel_region(w, e, 24, vsi_at - 24, &b, &ro, &n))
        proto_tree_add_item(et, hf_nvme_pel_ev_hdr_ext, tvb, b, n, ENC_NA);
    if (pel_region(w, e, vsi_at, ev.vsil, &b, &ro, &n))
        proto_tree_add_item(et, hf_nvme_pel_ev_vsi, tvb, b, n, ENC_NA);
    bool rev_ok = lay && ev.rev == lay->rev;
    bool len_ok = !lay || (dlen >= lay->min_len && dlen <= lay->max_len &&
                           (ev.type != 0x04 || (dlen - 8) % 36 == 0));
    if (pel_region(w, e, data_at, dlen, &b, &ro, &n)) {
        proto_item *di = proto_tree_add_item(et, hf_nvme_pel_ev_data, tvb, b, n, ENC_NA);
        proto_tree *dt = proto_item_add_subtree(di, ett_data);

        if (lay && !rev_ok) {
            expert_add_info(w->pinfo, di, &ei_nvme_pel_event_revision);
        } else if (!len_ok) {
            expert_add_info(w->pinfo, di, &ei_nvme_pel_event_length);
        } else if (lay) {
            switch (ev.type) {
            case 0x01:
                dissect_nvme_get_logpage_smart_resp(di, tvb_new_subset_length(tvb, b, n), ro, n);
                break;
            case 0x02:
                pel_decode_fw_commit(tvb, dt, b, ro, n); break;
            case 0x03:
                pel_decode_ts_change(tvb, dt, b, ro, n); break;
            case 0x04:
                pel_decode_power_on(tvb, dt, b, ro, n, dlen); break;
            case 0x05:
                pel_decode_hw_error(tvb, dt, b, ro, n, dlen, (int32_t)ev.sel); break;
            case 0x06:
                pel_decode_change_ns(tvb, dt, b, ro, n); break;
            case 0x07:
                pel_decode_format_start(tvb, dt, b, ro, n); break;
            case 0x08:
                pel_decode_format_cmpl(tvb, dt, b, ro, n); break;
            case 0x09:
                pel_decode_sanitize_start(tvb, dt, b, ro, n); break;
            case 0x0a:
                pel_decode_sanitize_cmpl(tvb, dt, b, ro, n); break;
            case 0x0b:
                pel_decode_set_feature(tvb, w->pinfo, di, b, ro, n, dlen, ev.sel); break;
            case 0x0c:
                pel_decode_telemetry(tvb, di, b, ro, n, ev.sel); break;
            case 0x0d:
                pel_decode_thermal(tvb, dt, b, ro, n); break;
            case 0x0f:
                pel_decode_cdp(tvb, dt, b, ro, n, dlen); break;
            case 0x10:
                pel_decode_exported_ns(tvb, dt, b, ro, n, ev.sel); break;
            case 0xde:
                pel_decode_vendor(tvb, w->pinfo, di, b, ro, n, dlen); break;
            default:
                break;
            }
        }
    } else if (!len_ok && e >= w->off) {
        /* No event data at all where the type needs some. */
        expert_add_info(w->pinfo, ei, &ei_nvme_pel_event_length);
    }
    if ((uint64_t)e + ev.total > w->end) {
        proto_item_append_text(ei, " (incomplete)");
        return PEL_EV_WINDOW_END;
    }
    *next = e + ev.total;
    return PEL_EV_DONE;
}

/* Where the window starts relative to the events this scope has seen. */
static void
pel_locate(nvme_pel_known *k, const nvme_pel_context *ctx, uint32_t off)
{
    k->tll = ctx->tll;
    k->hlen = ctx->hlen;
    if (off == ctx->hlen) {
        k->at_boundary = true;
    } else if (off > ctx->hlen) {
        const nvme_pel_event *p = (const nvme_pel_event *)wmem_tree_lookup32_le(ctx->events, off);
        if (p && off < (uint64_t)p->start + p->total) {
            k->in_event = true;
            k->ev = *p;
        } else if (p && off == (uint64_t)p->start + p->total) {
            k->at_boundary = true;
        }
    }
}

/* Base 2.4 Figure 233 SEB: bit n set means event type n is supported. */
static void post_add_pel_seb(proto_item *ti, tvbuff_t *tvb, unsigned off)
{
    proto_tree *sub = proto_item_add_subtree(ti, ett_data);
    unsigned n = 0;

    for (unsigned bit = 0; bit < 256; bit++) {
        if (tvb_get_uint8(tvb, off + bit / 8) & (1U << (bit % 8))) {
            proto_tree_add_uint(sub, hf_nvme_pel_seb_ev, tvb, off + bit / 8, 1, bit);
            n++;
        }
    }
    proto_item_append_text(ti, " (%u supported)", n);
}

/* Base 2.3 Figures 229-243; timestamp attributes follow Base 2.4 Figure 480.
 * An NVMe-MI endpoint's reads share one reporting context, so a window that
 * starts after the header resumes the events an earlier read placed. */
static void
dissect_nvme_get_logpage_pel_resp(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo,
                                  const struct nvme_cmd_ctx *cmd_ctx,
                                  uint64_t off64, unsigned len)
{
    static const nvme_window_field header[] = {
        NVME_WF(0, 1, hf_nvme_pel_lid, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 3, hf_nvme_pel_reserved, ENC_NA),
        NVME_WF(4, 4, hf_nvme_pel_tnev, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 8, hf_nvme_pel_tll, ENC_LITTLE_ENDIAN),
        NVME_WF(16, 1, hf_nvme_pel_lrev, ENC_LITTLE_ENDIAN),
        NVME_WF(17, 1, hf_nvme_pel_reserved, ENC_NA),
        NVME_WF(18, 2, hf_nvme_pel_lhl, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field context[] = {
        NVME_WF(20, 6, hf_nvme_pel_timestamp, ENC_LITTLE_ENDIAN),
        NVME_WF(26, 1, hf_nvme_pel_synch, ENC_LITTLE_ENDIAN),
        NVME_WF(26, 1, hf_nvme_pel_origin, ENC_LITTLE_ENDIAN),
        NVME_WF(27, 1, hf_nvme_pel_reserved, ENC_NA),
        NVME_WFP(28, 16, hf_nvme_pel_poh, ENC_NA, post_add_intval_from_16bytes),
        NVME_WF(44, 8, hf_nvme_pel_pwrcc, ENC_LITTLE_ENDIAN),
        NVME_WF(52, 2, hf_nvme_pel_vid, ENC_LITTLE_ENDIAN),
        NVME_WF(54, 2, hf_nvme_pel_ssvid, ENC_LITTLE_ENDIAN),
        NVME_WF(56, 20, hf_nvme_pel_sn, ENC_ASCII),
        NVME_WF(76, 40, hf_nvme_pel_mn, ENC_ASCII),
        NVME_WF(372, 2, hf_nvme_pel_gnum, ENC_LITTLE_ENDIAN),
        NVME_WF(374, 4, hf_nvme_pel_rcpid, ENC_LITTLE_ENDIAN),
        NVME_WF(374, 4, hf_nvme_pel_rcpit, ENC_LITTLE_ENDIAN),
        NVME_WF(374, 4, hf_nvme_pel_rce, ENC_LITTLE_ENDIAN),
        NVME_WF(378, 102, hf_nvme_pel_reserved, ENC_NA),
        NVME_WFP(480, 32, hf_nvme_pel_seb, ENC_NA, post_add_pel_seb),
    };
    proto_tree *tree = proto_item_add_subtree(ti, ett_data);
    uint8_t act = cmd_ctx->cmd_ctx.get_logpage.lsp & 0x3;
    const void *scope = cmd_ctx->cmd_ctx.get_logpage.retain ?
                        cmd_ctx->cmd_ctx.get_logpage.scope : NULL;
    uint64_t tll_w = UINT64_MAX;
    uint32_t hlen_w = 0;
    int64_t tnev = -1;
    int32_t gnum = -1;
    int rce = -1;
    unsigned rel;

    /* Release (ACT 10b) returns no data (Figure 229). */
    if (act == 2) {
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    /* A large LPO must never wrap into the fixed header. */
    if (off64 > UINT32_MAX) {
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    uint32_t off = (uint32_t)off64;
    nvme_add_window_fields(tvb, tree, off, len, header, array_length(header));
    if (nvme_field_in_window(off, len, 4, 4, &rel))
        tnev = tvb_get_letohl(tvb, rel);
    if (nvme_field_in_window(off, len, 8, 8, &rel))
        tll_w = tvb_get_letoh64(tvb, rel);
    if (nvme_field_in_window(off, len, 18, 2, &rel)) {
        hlen_w = 20 + tvb_get_letohs(tvb, rel);
        if (hlen_w < 512 || tll_w < hlen_w) {
            expert_add_info(pinfo, ti, &ei_nvme_pel_invalid_header);
            return;
        }
    } else if (tll_w < 512) {
        expert_add_info(pinfo, ti, &ei_nvme_pel_invalid_header);
        return;
    }
    if (nvme_field_in_window(off, len, 16, 1, &rel) &&
        tvb_get_uint8(tvb, rel) != 3) {
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    if (nvme_field_in_window(off, len, 372, 2, &rel))
        gnum = tvb_get_letohs(tvb, rel);
    if (nvme_field_in_window(off, len, 376, 1, &rel))
        rce = (tvb_get_uint8(tvb, rel) >> 2) & 1;

    /* Track the scope's reporting context on the first pass only; revisits
     * use what the window knew then. */
    nvme_pel_known known = { .tll = UINT64_MAX };
    nvme_pel_context *ctx = NULL;
    if (scope && !PINFO_FD_VISITED(pinfo)) {
        ctx = (nvme_pel_context *)wmem_map_lookup(nvme_pel_contexts, scope);
        bool fresh = act == 1 || (act == 3 && rce != 1);
        if (ctx && (fresh || (tll_w != UINT64_MAX && tll_w != ctx->tll) ||
                    (hlen_w && hlen_w != ctx->hlen) ||
                    (gnum >= 0 && ctx->gnum >= 0 && gnum != ctx->gnum))) {
            wmem_map_remove(nvme_pel_contexts, scope);
            ctx = NULL;
        }
        if (!ctx && tll_w != UINT64_MAX && hlen_w) {
            ctx = wmem_new0(wmem_file_scope(), nvme_pel_context);
            ctx->tll = tll_w;
            ctx->hlen = hlen_w;
            ctx->gnum = -1;
            ctx->events = wmem_tree_new(wmem_file_scope());
            wmem_map_insert(nvme_pel_contexts, scope, ctx);
        }
        if (ctx) {
            if (gnum >= 0)
                ctx->gnum = gnum;
            pel_locate(&known, ctx, off);
        }
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme, pinfo->curr_layer_num,
                         wmem_memdup(wmem_file_scope(), &known, sizeof(known)));
    } else if (scope) {
        const nvme_pel_known *k = (const nvme_pel_known *)p_get_proto_data(
            wmem_file_scope(), pinfo, proto_nvme, pinfo->curr_layer_num);
        if (k)
            known = *k;
    }
    uint64_t tll = tll_w != UINT64_MAX ? tll_w : known.tll;
    uint32_t hlen = hlen_w ? hlen_w : known.hlen;

    /* Data at or beyond TLL is not part of the log (Figure 201): raw. */
    unsigned in_len = len;
    if (tll != UINT64_MAX) {
        if ((uint64_t)off >= tll) {
            proto_tree_add_item(tree, hf_nvme_pel_past_tll, tvb, 0, len, ENC_NA);
            return;
        }
        in_len = (unsigned)MIN((uint64_t)len, tll - off);
    }
    nvme_add_window_fields(tvb, tree, off, in_len, context, array_length(context));
    dissect_nvme_nqn(tvb, tree, hf_nvme_pel_subnqn, 0, in_len, off, 116, false);
    uint32_t ehlen = hlen ? hlen : 512;
    unsigned n;
    if (ehlen > 512 && nvme_window_intersect(off, in_len, 512, ehlen - 512, &rel, &n))
        proto_tree_add_item(tree, hf_nvme_pel_extension, tvb, rel, n, ENC_NA);

    if ((uint64_t)off + in_len > ehlen) {
        nvme_pel_walk w = { tvb, pinfo, tree, off, off + in_len, tll, ctx };
        const nvme_pel_event *cont = NULL;
        uint32_t e = 0, raw_at = MAX(off, ehlen);
        bool walk = tll != UINT64_MAX && hlen;

        if (walk) {
            if (off <= hlen) {
                e = hlen;
            } else if (known.in_event) {
                cont = &known.ev;
                e = known.ev.start;
            } else if (known.at_boundary) {
                e = off;
            } else {
                walk = false;
            }
        }
        if (!walk) {
            proto_tree_add_item(tree, hf_nvme_pel_events, tvb, raw_at - off,
                                off + in_len - raw_at, ENC_NA);
            nvme_add_window_note(ti, NVME_WINDOW_RAW);
        } else {
            unsigned count = 0;
            int r = PEL_EV_DONE;

            while (e < w.end) {
                uint32_t next = 0;
                r = pel_event(&w, e, cont, &next);
                cont = NULL;
                count++;
                if (r == PEL_EV_INVALID) {
                    if (next < w.end)
                        proto_tree_add_item(tree, hf_nvme_pel_events, tvb, next - off,
                                            w.end - next, ENC_NA);
                    break;
                }
                if (r == PEL_EV_WINDOW_END)
                    break;
                e = next;
            }
            /* Figure 230: TNEV counts the events the whole log holds. */
            if (off <= hlen && r == PEL_EV_DONE && e == tll && tnev >= 0 &&
                count != tnev)
                expert_add_info_format(pinfo, ti, &ei_nvme_pel_tnev_mismatch,
                    "TNEV is %" PRId64 " but the log holds %u events", tnev, count);
        }
    }
    if (in_len < len)
        proto_tree_add_item(tree, hf_nvme_pel_past_tll, tvb, in_len, len - in_len, ENC_NA);
}

static void dissect_nvme_get_logpage_fw_slot_resp(proto_item *ti, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned rel;

    if (off >= 512)
        return;  /* max allowed offset is < 512 */

    grp =  proto_item_add_subtree(ti, ett_data);

    if (nvme_field_in_window(off, len, 0, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_fw_slot_afi));
    if (nvme_field_in_window(off, len, 1, 7, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_fw_slot_rsvd0,  cmd_tvb, rel, 7, ENC_LITTLE_ENDIAN);

    decode_fw_slot_frs(grp, cmd_tvb, off, len);

    if (off < 512) {
        unsigned poff = (off < 64) ? (64 - off) : 0;
        unsigned max_len = (off <= 64) ? 448 : 512 - off;
        /* Guard before subtracting: len < poff would otherwise underflow
         * `len` (unsigned) to a huge value on a short/truncated transfer. */
        if (len > poff) {
            len -= poff;
            if (len > max_len)
                len = max_len;
            proto_tree_add_item(grp, hf_nvme_get_logpage_fw_slot_rsvd1,  cmd_tvb, poff, len, ENC_NA);
        }
    }
}

static void dissect_nvme_get_logpage_changed_nslist_resp(proto_item *ti, tvbuff_t *cmd_tvb, packet_info *pinfo, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned poff = 0;
    /* Page is 1024 four-byte entries = 4096 bytes; a nonzero window offset
     * moves where the spec-mandated 4096-byte ceiling falls relative to
     * this window, and (if 4-byte aligned) where cmd_tvb position 0 lands
     * relative to an entry boundary -- see the alignment guard below. */
    unsigned max_len = (off < 4096) ? (4096 - off) : 0;

    if (len > max_len)
        len = max_len;

    if (!nvme_offset_record_aligned(off, 4)) {
        expert_add_info(pinfo, ti, &ei_nvme_logpage_window_misaligned);
        return;
    }

    grp =  proto_item_add_subtree(ti, ett_data);
    while (len >= 4) {
        uint32_t nsid = tvb_get_uint32(cmd_tvb, poff, ENC_LITTLE_ENDIAN);
        proto_item *item;

        /* NVMe Base 2.3 Figure 139: the first 0h ends the list. */
        if (!nsid)
            break;

        item = proto_tree_add_uint(grp, hf_nvme_get_logpage_changed_nslist, cmd_tvb, poff, 4, nsid);
        /* FFFFFFFFh first means the list overflowed (5.2.12.1.5). */
        if (nsid == 0xFFFFFFFF)
            proto_item_append_text(item, " (more than 1,024 namespaces changed)");
        len -= 4;
        poff += 4;
    }
}

static const range_string lockdown_scope_rvals[] = {
    { 0x0, 0x0, "Admin Command Set opcodes" },
    { 0x1, 0x1, "Reserved" },
    { 0x2, 0x2, "Feature Identifiers" },
    { 0x3, 0x3, "NVMe-MI Command Set opcodes" },
    { 0x4, 0x4, "PCIe Command Set opcodes" },
    { 0x5, 0xf, "Reserved" },
    { 0, 0, NULL }
};

static const value_string lockdown_contents_vals[] = {
    { 0x0, "Can-be-prohibited list" },
    { 0x1, "Currently prohibited (Admin Submission Queue)" },
    { 0x2, "Currently prohibited (out-of-band Management Endpoint)" },
    { 0x3, "Reserved" },
    { 0, NULL }
};

/* Get Log Page LSP values, Base 2.4 Figures 220, 232 and 309. */
static const range_string lsp_mcda_rvals[] = {
    { 0x0, 0x0, "Controller determines the data areas" },
    { 0x1, 0x1, "Data Area 1" },
    { 0x2, 0x2, "Data Area 1 through Data Area 2" },
    { 0x3, 0x3, "Data Area 1 through Data Area 3" },
    { 0x4, 0x4, "Data Area 1 through Data Area 4" },
    { 0x5, 0x7, "Reserved" },
    { 0, 0, NULL }
};

static const value_string lsp_pel_act_vals[] = {
    { 0x0, "Read Log Data" },
    { 0x1, "Establish Context and Read Log Data" },
    { 0x2, "Release Context" },
    { 0x3, "Establish Context and Read 512 Bytes of Header" },
    { 0, NULL }
};

static const value_string lsp_nlt_vals[] = {
    { 0x0, "In Progress" },
    { 0x1, "Successfully Completed" },
    { 0, NULL }
};

static const range_string cmd_eff_cse_tbl[] = {
    { 0, 0, "No command submission or execution restriction" },
    { 1, 1, "One concurrent command per namespace" },
    { 2, 2, "One concurrent command per system" },
    { 3, 7, "Reserved" },
    { 0, 0, NULL}
};

/* NVMe Base 2.3 Figure 214, bits 15:14. */
static const range_string cmd_eff_cser_tbl[] = {
    { 0, 0, "No relaxed recommendation; use CSE" },
    { 1, 1, "One concurrent Admin command per system" },
    { 2, 3, "Reserved" },
    { 0, 0, NULL}
};

static void dissect_nvme_get_logpage_cmd_sup_and_eff_grp(proto_tree *grp, tvbuff_t *cmd_tvb, unsigned poff, unsigned nrec, unsigned fidx, bool acs)
{
    unsigned i;
    proto_item *ti;
    proto_tree *ent;
    for (i = 0; i < nrec; i++) {
        if (acs)
            ti = proto_tree_add_bytes_format(grp, hf_nvme_get_logpage_cmd_and_eff_cs, cmd_tvb, poff, 4, NULL, "Admin Command Supported %u (ACS%u)", fidx+i, fidx+i);
        else
            ti = proto_tree_add_bytes_format(grp, hf_nvme_get_logpage_cmd_and_eff_cs, cmd_tvb, poff, 4, NULL, "I/O Command Supported %u (IOCS%u)", fidx+i, fidx+i);
        ent =  proto_item_add_subtree(ti, ett_data);
        add_group_mask_entry(cmd_tvb, ent, poff, 4, ASPEC(hf_nvme_get_logpage_cmd_and_eff_cseds));
        poff += 4;
    }
}


static void dissect_nvme_get_logpage_cmd_sup_and_eff_resp(proto_item *ti, tvbuff_t *cmd_tvb, packet_info *pinfo, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned nrec = 0;
    unsigned fidx;

    if (off >= 4096)
        return; /* max allowed offset is < 4096 */

    /* 4-byte records (NVMe Base 2.3 Figure 213). */
    if (!nvme_offset_record_aligned(off, 4)) {
        expert_add_info(pinfo, ti, &ei_nvme_logpage_window_misaligned);
        return;
    }

    grp =  proto_item_add_subtree(ti, ett_data);
    if (off <= 1024 && len >= 4) {
        fidx = off / 4;
        nrec = (1024-off) / 4;
        if (nrec > (len / 4))
            nrec = len / 4;
        dissect_nvme_get_logpage_cmd_sup_and_eff_grp(grp, cmd_tvb, 0, nrec, fidx, true);
    }

    nrec = len / 4 - nrec;
    if (!nrec)
        return;

    fidx = (off > 1024) ? (off - 1024) / 4 : 0;
    /* IOCS0..IOCS255 are bytes 2047:1024 (Figure 213). */
    if (fidx >= 256)
        return;
    if (nrec > (256 - fidx))
        nrec = 256 - fidx;

    off = (off < 1024) ? (1024 - off) : 0;

    dissect_nvme_get_logpage_cmd_sup_and_eff_grp(grp, cmd_tvb, off, nrec, fidx, false);
}

static const range_string stest_type_active_tbl[] = {
    { 0, 0, "No device self-test operation in progress" },
    { 1, 1, "Short device self-test operation in progress" },
    { 2, 2, "Extended device self-test operation in progress" },
    { 3, 3, "Host-Initiated Refresh operation" },
    { 4, 0xD, "Reserved" },
    { 0xE, 0xE, "Vendor Specific" },
    { 0xF, 0xF, "Reserved" },
    { 0, 0, NULL}
};

static const range_string stest_result_tbl[] = {
    { 0, 0, "Operation completed without error" },
    { 1, 1, "Operation was aborted by a Device Self-test command" },
    { 2, 2, "Operation was aborted by a Controller Level Reset" },
    { 3, 3, "Operation was aborted due to a removal of a namespace from the namespace inventory" },
    { 4, 4, "Operation was aborted due to the processing of a Format NVM command" },
    { 5, 5, "A fatal error or unknown test error occurred while the controller was executing the device self-test operation and the operation did not complete" },
    { 6, 6, "Operation completed with a segment that failed and the segment that failed is not known" },
    { 7, 7, "Operation completed with one or more failed segments and the first segment that failed is indicated in the Segment Number field" },
    { 8, 8, "Operation was aborted for unknown reason" },
    { 9, 9, "Operation was aborted due to a sanitize operation" },
    { 0xA, 0xE, "Reserved" },
    { 0xF, 0xF, "Entry not used (does not contain a test result)" },
    { 0, 0, NULL}
};

/* DSTC of a *completed* result (Base 2.3 Figure 216), not the in-progress
 * operation status of Figure 215 that stest_type_active_tbl names. */
static const range_string stest_type_done_tbl[] = {
    { 0, 0, "Entry is empty" },
    { 1, 1, "Short device self-test operation" },
    { 2, 2, "Extended device self-test operation" },
    { 3, 3, "Host-Initiated Refresh operation" },
    { 4, 0xD, "Reserved" },
    { 0xE, 0xE, "Vendor Specific" },
    { 0xF, 0xF, "Reserved" },
    { 0, 0, NULL}
};

static void dissect_nvme_get_logpage_selftest_result(proto_tree *grp, tvbuff_t *cmd_tvb, uint32_t off, unsigned tst_idx)
{
    proto_item *ti;

    /* Base 2.3 Figure 216: 28 bytes; Figure 215 numbers RDS1 first. */
    ti = proto_tree_add_bytes_format(grp, hf_nvme_get_logpage_selftest_res, cmd_tvb, off, 28, NULL,
                                "Self-test Result Data Structure %u (RDS%u)", tst_idx + 1, tst_idx + 1);
    grp =  proto_item_add_subtree(ti, ett_data);
    add_group_mask_entry(cmd_tvb, grp, off, 1, ASPEC(hf_nvme_get_logpage_selftest_res_status));
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_sn, cmd_tvb, off+1, 1, ENC_LITTLE_ENDIAN);
    proto_tree *vdi = add_group_mask_entry(cmd_tvb, grp, off+2, 1,
                                         hf_nvme_get_logpage_selftest_res_vdi, 5);
    proto_tree_add_item(vdi, hf_nvme_get_logpage_selftest_res_vdi[5],
                        cmd_tvb, off+2, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_rsvd, cmd_tvb, off+3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_poh, cmd_tvb, off+4, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_nsid, cmd_tvb, off+12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_flba, cmd_tvb, off+16, 8, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, grp, off+24, 1, ASPEC(hf_nvme_get_logpage_selftest_res_sct));
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_sc, cmd_tvb, off+25, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_res_vs, cmd_tvb, off+26, 2, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_get_logpage_selftest_resp(proto_item *ti, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned tst_idx;
    unsigned rel;

    if (off > 536)
        return; /* max offset is <= 536 (Base 2.3 Figure 215) */

    grp =  proto_item_add_subtree(ti, ett_data);

    if (nvme_field_in_window(off, len, 0, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_selftest_csto));
    if (nvme_field_in_window(off, len, 1, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_selftest_cstc));
    if (nvme_field_in_window(off, len, 2, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_selftest_rsvd,
                            cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);

    if (off <= 4) {
        unsigned skip = 4 - off;                 /* cmd_tvb pos of result 0 */
        if (len < skip)
            return;
        len -= skip;
        tst_idx = 0;
        off = skip;
    } else {
        unsigned skip;
        tst_idx = (off - 4 + 27) / 28;            /* first fully-contained result */
        skip = tst_idx * 28 - (off - 4);          /* cmd_tvb pos of result[tst_idx] */
        if (len < skip)
            return;
        len -= skip;
        off = skip;
    }
    /* Figure 215: exactly 20 results, so the page is 564 bytes. */
    while (len >= 28 && tst_idx < 20) {
        dissect_nvme_get_logpage_selftest_result(grp, cmd_tvb, off, tst_idx);
        off += 28;
        len -= 28;
        tst_idx++;
    }
}

/* NVMe Base 2.3 "Telemetry Host-Initiated Log Page" / "Telemetry
 * Controller-Initiated Log Page" (Telemetry Scope) */
static const range_string telemetry_scope_tbl[] = {
    { 0, 0, "Not reported" },
    { 1, 1, "Controller" },
    { 2, 2, "NVM subsystem" },
    { 3, 255, "Reserved" },
    { 0, 0, NULL },
};

/*
 * Base 2.4 Figures 221/223: TCDA reports whether the log page was updated
 * since the last read with RAE cleared; revisions 2.3 and earlier defined it
 * as saved internal state availability.
 */
static const range_string telemetry_data_available_tbl[] = {
    { 0x00, 0x00, "Not updated since last read with RAE=0 (<=2.3: header only, no saved state)" },
    { 0x01, 0x01, "Updated since last read with RAE=0 (<=2.3: saved internal state available)" },
    { 0x02, 0xff, "Reserved" },
    { 0, 0, NULL }
};

/* Telemetry offsets may exceed 4 GiB (NVMe Base 2.3 Figures 218/220). */
static void dissect_nvme_get_logpage_telemetry_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, uint64_t off, unsigned len)
{
    proto_tree *grp;
    uint64_t next_block;
    uint32_t poff;
    unsigned hoff;
    unsigned rel;
    bool host_init = (cmd_ctx->cmd_ctx.get_logpage.lid == 0x7);
    const char *pfx = host_init ? "Host-Initiated" : "Controller-Initiated";

    /* off==0 means the window starts at the very beginning of the log page
     * (the 512-byte header), so poff must skip past it to reach data block 1.
     * Any other exact multiple of 512 means the window already starts at a
     * data block boundary, so poff must be 0, not another full 512 skip. */
    poff = (off == 0) ? 512 : (uint32_t)((512 - (off & 0x1ff)) % 512);
    next_block = (off + poff) / 512;

    /* Every header field is in the first 512 bytes. */
    hoff = (off > 512) ? 512 : (unsigned)off;

    grp =  proto_item_add_subtree(ti, ett_data);


    /* Past 384, nothing of the header is left. */
    if (poff >= len && off > 384)
        return;

    if (nvme_field_in_window(hoff, len, 0, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_li, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(hoff, len, 1, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_rsvd0, cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(hoff, len, 5, 3, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_ieee, cmd_tvb, rel, 3, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(hoff, len, 8, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da1lb, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(hoff, len, 10, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da2lb, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(hoff, len, 12, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da3lb, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(hoff, len, 14, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_rsvd1, cmd_tvb, rel, 2, ENC_NA);
    if (nvme_field_in_window(hoff, len, 16, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da4lb, cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (host_init) {
        /* Telemetry Host-Initiated Log Page: bytes 379:20 reserved, 380 THS,
         * 381 THDGN */
        if (nvme_field_in_window(hoff, len, 20, 360, &rel))
            proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_rsvd2, cmd_tvb, rel, 360, ENC_NA);
        if (nvme_field_in_window(hoff, len, 380, 1, &rel))
            proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_scope, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
        if (nvme_field_in_window(hoff, len, 381, 1, &rel))
            proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_hdgn, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    } else {
        /* Telemetry Controller-Initiated Log Page: bytes 380:20 reserved,
         * 381 TCS */
        if (nvme_field_in_window(hoff, len, 20, 361, &rel))
            proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_rsvd2, cmd_tvb, rel, 361, ENC_NA);
        if (nvme_field_in_window(hoff, len, 381, 1, &rel))
            proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_scope, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    }
    if (nvme_field_in_window(hoff, len, 382, 1, &rel)) {
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_da,
                            cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    }
    if (nvme_field_in_window(hoff, len, 383, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_dgn, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(hoff, len, 384, 128, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_telemetry_ri, cmd_tvb, rel, 128, ENC_NA);

    if (len < poff)
        return;
    len -= poff;
    while (len >= 512) {
         proto_tree_add_bytes_format_value(grp, hf_nvme_get_logpage_telemetry_db, cmd_tvb, poff, 512, NULL,
                                           "Telemetry %s data block %"PRIu64, pfx, next_block);
        len -= 512;
        next_block++;
        poff += 512;
    }
}

static void dissect_nvme_get_logpage_egroup_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned rel;

    /* Figure 222 has no Endurance Group ID: name it from the request's LSI
     * (Base 2.3 Figure 221). The stored LID selected this decoder, so LSI is set. */
    proto_item_append_text(ti, ", Endurance Group %u", cmd_ctx->cmd_ctx.get_logpage.lsi);

    if (off >= 512)
        return; /* max allowed offset is < 512 */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvme_field_in_window(off, len, 0, 1, &rel)) {
        proto_tree *cw = add_group_mask_entry(cmd_tvb, grp, rel, 1,
                                             hf_nvme_get_logpage_egroup_cw, 5);
        proto_tree_add_item(cw, hf_nvme_get_logpage_egroup_cw[5],
                            cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    }
    if (nvme_field_in_window(off, len, 1, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_egroup_egfeat));
    if (nvme_field_in_window(off, len, 2, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_rsvd0,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 3, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_as,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 4, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_ast,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 5, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_pu,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 6, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_did,  cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 8, 24, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_rsvd1,  cmd_tvb, rel, 24, ENC_NA);
    if (nvme_field_in_window(off, len, 32, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_ee,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 48, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_dur,  cmd_tvb, rel, 16, ENC_NA);
        post_add_egroup_data_units(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 64, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_duw,  cmd_tvb, rel, 16, ENC_NA);
        post_add_egroup_data_units(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 80, 16, &rel)) {
        /* MUW is reported like DUR and DUW (Figure 222). */
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_muw,  cmd_tvb, rel, 16, ENC_NA);
        post_add_egroup_data_units(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 96, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_hrc,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 112, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_hwc,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 128, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_mdie,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 144, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_ele,  cmd_tvb, rel, 16, ENC_NA);
        post_add_intval_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 160, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_tegcap,  cmd_tvb, rel, 16, ENC_NA);
        post_add_bytes_from_16bytes(ti, cmd_tvb, rel);
    }
    if (nvme_field_in_window(off, len, 176, 16, &rel)) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_uegcap,  cmd_tvb, rel, 16, ENC_NA);
        post_add_bytes_from_16bytes(ti, cmd_tvb, rel);
    }
    if (off <= 508 && (512 - off) <= len) {
        unsigned poff = (off <= 192) ? (192 - off) : 0;
        /* poff isn't derived from (512-off), so the guard above doesn't by
         * itself guarantee poff <= len -- check explicitly before subtracting. */
        if (poff <= len) {
            /* Remaining room at tvb position poff is (512-off)-poff, not the
             * raw len -- an oversized/malformed len must not render bytes
             * past the structure's real 512-byte end as "Reserved2". */
            unsigned max_len = (512 - off) - poff;
            unsigned rlen = len - poff;
            if (rlen > max_len)
                rlen = max_len;
            proto_tree_add_item(grp, hf_nvme_get_logpage_egroup_rsvd2,  cmd_tvb, poff, rlen, ENC_NA);
        }
    }
}
static const range_string plat_status_tbl[] = {
    { 0, 0, "Predictable Latency Mode not Enabled" },
    { 1, 1, "Deterministic Window (DTWIN)" },
    { 2, 2, "Non-Deterministic Window (NDWIN)" },
    { 3, 7, "Reserved" },
    { 0, 0, NULL}
};

static void dissect_nvme_get_logpage_pred_lat_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned poff;
    unsigned rel;

    /* As for the Endurance Group log page above: Figure 224 does not echo the
     * NVM Set Identifier, which is carried only in the Log Specific Identifier
     * of the request (NVMe Base 2.3 section 5.2.12.1.11 and Figure 223).
     * There is one such log page per NVM Set, so the label is what tells them
     * apart. */
    proto_item_append_text(ti, ", NVM Set %u", cmd_ctx->cmd_ctx.get_logpage.lsi);

    if (off > 508)
        return; /* max allowed offset is < 508 */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvme_field_in_window(off, len, 0, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_pred_lat_status));
    if (nvme_field_in_window(off, len, 1, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_rsvd0,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 2, 2, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 2, ASPEC(hf_nvme_get_logpage_pred_lat_etype));
    if (nvme_field_in_window(off, len, 4, 28, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_rsvd1,  cmd_tvb, rel, 28, ENC_NA);
    if (nvme_field_in_window(off, len, 32, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_rt,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 40, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_wt,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 48, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_tm,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 56, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_ndwin_tmh,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 64, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_ndwin_tml,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 72, 56, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_rsvd2,  cmd_tvb, rel, 56, ENC_NA);
    if (nvme_field_in_window(off, len, 128, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_re,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 136, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_we,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 144, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_dtwin_te,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    poff = (off <= 152) ? (152 - off) : 0;
    if (poff > len)
        return;
    {
        /* Remaining room at tvb position poff is (512-off)-poff, not the
         * raw len -- an oversized/malformed len must not render bytes past
         * the structure's real 512-byte end as "Reserved3". */
        unsigned max_len = (512 - off) - poff;
        unsigned rlen = len - poff;
        if (rlen > max_len)
            rlen = max_len;
        proto_tree_add_item(grp, hf_nvme_get_logpage_pred_lat_rsvd3,  cmd_tvb, poff, rlen, ENC_NA);
    }
}

/* LID 0Bh and 0Fh (NVMe Base 2.3 Figures 225/257). */
static void dissect_nvme_get_logpage_event_aggreg_resp(proto_item *ti, tvbuff_t *cmd_tvb, packet_info *pinfo,
                                                       unsigned off, unsigned len, int hf_ne, int hf_entry,
                                                       int hf_fill)
{
    proto_tree *grp;
    unsigned poff = (off < 8) ? (8 - off) : 0;
    uint64_t nument = 0;
    bool have_nument = false;

    /* Entries begin only at even offsets. */
    if (off >= 8 && !nvme_offset_record_aligned(off, 2)) {
        expert_add_info(pinfo, ti, &ei_nvme_logpage_window_misaligned);
        return;
    }

    if (len < (poff + 2) && off)
        return; /* not one whole identifier in this window */
    if (len < poff)
        return; /* not even all of NUMENT */

    grp =  proto_item_add_subtree(ti, ett_data);
    /* A zero combined offset means LPO and transport offset were zero. */
    if (!off) {
        proto_tree_add_item_ret_uint64(grp, hf_ne, cmd_tvb, 0, 8, ENC_LITTLE_ENDIAN, &nument);
        have_nument = true;
    }
    len -= poff;

    /* The list ends at NUMENT, or at an identifier of 0h; the rest is fill. */
    while (len >= 2 && (!have_nument || nument)) {
        uint16_t ident = tvb_get_letohs(cmd_tvb, poff);

        if (!have_nument && !ident) {
            proto_item *fill_ti = proto_tree_add_item(grp, hf_fill, cmd_tvb, poff, len, ENC_NA);
            proto_item_append_text(fill_ti, " (NUMENT is not in this window; the list end"
                                   " is taken from the first identifier cleared to 0h)");
            return;
        }
        proto_tree_add_uint(grp, hf_entry, cmd_tvb, poff, 2, ident);
        poff += 2;
        len -= 2;
        if (have_nument)
            nument--;
    }
}

static const range_string ana_state_tbl[] = {
    { 0x0, 0x0, "Reserved" },
    { 0x1, 0x1, "ANA Optimized State" },
    { 0x2, 0x2, "ANA Non-Optimized State" },
    { 0x3, 0x3, "ANA Inaccessible State" },
    { 0x4, 0x4, "ANA Persistent Loss State" },
    { 0x5, 0xE, "Reserved" },
    { 0xF, 0xF, "ANA Change State" },
    { 0, 0, NULL}
};

/* The part of an ANA Group Descriptor (Base 2.3 Figure 228) in this
 * window, resumed via tr_off/tr_sub_entries; returns the bytes used. */
static unsigned dissect_nvme_get_logpage_ana_resp_grp(proto_tree *grp, tvbuff_t *cmd_tvb,  struct nvme_cmd_ctx *cmd_ctx, unsigned len, uint32_t poff)
{
    unsigned pos = cmd_ctx->cmd_ctx.get_logpage.tr_off;
    uint64_t desc_len = 0;
    unsigned bytes;
    proto_item *ti;
    unsigned group_id;
    unsigned nns = 0;
    unsigned rel;
    unsigned i;

    /* Sized below, once NNV (07:04) gives the descriptor's length. */
    ti = proto_tree_add_bytes_format_value(grp, hf_nvme_get_logpage_ana_grp, cmd_tvb, poff, len, NULL,
            "ANA Group Descriptor");
    grp =  proto_item_add_subtree(ti, ett_data);

    if (pos) {
        group_id = cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id;
        proto_item_append_text(ti, " %u (continued)", group_id);
    } else if (len >= 4) {
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ana_grp_id,  cmd_tvb, poff, 4, ENC_LITTLE_ENDIAN, &group_id);
        proto_item_append_text(ti, " %u", group_id);
        cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id = group_id;
    }

    /* desc_len 0 means the descriptor's length is not known. */
    if (pos >= 8) {
        nns = cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries;
        desc_len = 32 + 4 * (uint64_t)nns;
    } else if (nvme_field_in_window(pos, len, 4, 4, &rel)) {
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ana_grp_nns,  cmd_tvb, poff + rel, 4, ENC_LITTLE_ENDIAN, &nns);
        desc_len = 32 + 4 * (uint64_t)nns;
        if (desc_len > UINT32_MAX)
            desc_len = 0;   /* tr_off cannot count to its end */
    }
    bytes = (desc_len && desc_len - pos < len) ? (unsigned)(desc_len - pos) : len;
    proto_item_set_len(ti, bytes);

    if (nvme_field_in_window(pos, bytes, 8, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_grp_chcnt,  cmd_tvb, poff + rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(pos, bytes, 16, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, poff + rel, 1, ASPEC(hf_nvme_get_logpage_ana_grp_anas));
    if (nvme_field_in_window(pos, bytes, 17, 15, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_grp_rsvd,  cmd_tvb, poff + rel, 15, ENC_NA);
    for (i = (pos <= 32) ? 0 : (pos - 32 + 3) / 4;
         desc_len && i < nns && nvme_field_in_window(pos, bytes, 32 + 4 * i, 4, &rel); i++)
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_grp_nsid,  cmd_tvb, poff + rel, 4, ENC_LITTLE_ENDIAN);

    if (desc_len && pos + bytes == desc_len) {
        cmd_ctx->cmd_ctx.get_logpage.tr_off = 0;
        cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = 0;
        cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id = 0;
        /* Without NAGD there is no count to spend (Figure 227). */
        if (cmd_ctx->cmd_ctx.get_logpage.records_valid)
            cmd_ctx->cmd_ctx.get_logpage.records--;
    } else if (desc_len || pos + bytes == 4) {
        cmd_ctx->cmd_ctx.get_logpage.tr_off = pos + bytes;
        cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = nns;
    } else {
        /* The window ends inside AGID or NNV (DATAL not a dword multiple),
         * or the descriptor is too long to track: its end is unknown, so no
         * later window of this read places a descriptor boundary. */
        cmd_ctx->cmd_ctx.get_logpage.tr_off = 0;
        cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = 0;
        cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id = 0;
        cmd_ctx->cmd_ctx.get_logpage.records_valid = false;
        cmd_ctx->cmd_ctx.get_logpage.tr_next_off = 0;
    }
    return bytes;
}

/* The window's header bytes; 'have_nagd' says whether NAGD was there. */
static unsigned dissect_nvme_get_logpage_ana_resp_header(proto_tree *grp, tvbuff_t *cmd_tvb, unsigned len, uint32_t off, bool *have_nagd)
{
    unsigned groups=1;
    unsigned rel;
    *have_nagd = false;
    if (nvme_field_in_window(off, len, 0, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_chcnt,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 8, 2, &rel)) {
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_ana_ngd,  cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN, &groups);
        *have_nagd = true;
    }
    if (nvme_field_in_window(off, len, 10, 6, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_ana_rsvd,  cmd_tvb, rel, 6, ENC_LITTLE_ENDIAN);
    return groups;
}

static void dissect_nvme_get_logpage_ana_resp(proto_item *ti, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd_ctx, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned poff = 0;
    unsigned groups = 0;
    bool have_nagd = false;
    uint64_t next_off;

    grp =  proto_item_add_subtree(ti, ett_data);
    if (off < 16) {
        /* Part of the header (Figure 227) is here. */
        groups = dissect_nvme_get_logpage_ana_resp_header(grp, cmd_tvb, len, off, &have_nagd);
        poff = 16 - off;
    } else if (off != 16 && off != cmd_ctx->cmd_ctx.get_logpage.tr_next_off) {
        /* Variable descriptors (Figure 228): the walk places a later window
         * only if it starts where the last walked window ended.  One lost
         * from the capture, or not placed, leaves a gap it cannot cross. */
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    if (off <= 16) {
        /* No descriptor has started yet.  Without NAGD here, the count is
         * what an earlier window read, which holds only if the last walked
         * window ended here: not for a window re-dissected out of order. */
        if (off && !have_nagd && off != cmd_ctx->cmd_ctx.get_logpage.tr_next_off) {
            if (cmd_ctx->cmd_ctx.get_logpage.tr_next_off) {
                nvme_add_window_note(ti, NVME_WINDOW_RAW);
                return;
            }
            /* No walked window ends anywhere (none was, or the last lost its
             * framing): the count is not known. */
            cmd_ctx->cmd_ctx.get_logpage.records = 0;
            cmd_ctx->cmd_ctx.get_logpage.records_valid = false;
        }
        cmd_ctx->cmd_ctx.get_logpage.tr_off = 0;
        cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = 0;
        cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id = 0;
        if (have_nagd) {
            cmd_ctx->cmd_ctx.get_logpage.records = groups;
            cmd_ctx->cmd_ctx.get_logpage.records_valid = true;
        }
    }
    /* UINT32_MAX is a saturated offset, not a place a window can end. */
    next_off = (uint64_t)off + len;
    cmd_ctx->cmd_ctx.get_logpage.tr_next_off = (next_off < UINT32_MAX) ? (uint32_t)next_off : 0;
    if (len < poff)
        return;
    len -= poff;
    if (!have_nagd) {
        /* No NAGD in any window: walk the window, and say the count is inferred. */
        groups = cmd_ctx->cmd_ctx.get_logpage.records;
        /* 'records_valid' tells a NAGD of 0 from the zeroed default. */
        if (!groups && !cmd_ctx->cmd_ctx.get_logpage.records_valid && len >= 4) {
            groups = (len + 31) / 32 + (cmd_ctx->cmd_ctx.get_logpage.tr_off ? 1 : 0);
            nvme_add_window_note(ti, "Descriptor count not captured; the window is walked to its end");
        }
    }
    while (len && groups) {
        unsigned done = dissect_nvme_get_logpage_ana_resp_grp(grp, cmd_tvb, cmd_ctx, len, poff);
        poff += done;
        len -= done;
        groups--;
    }
}

/* LSLPLEN and NLSLNE (NVM CS 1.2 Figure 109); NLSLNE 0h is legal. */
static void dissect_nvme_get_logpage_lba_status_resp_header(proto_tree *grp, tvbuff_t *cmd_tvb, unsigned len, uint32_t off,
                                                            uint32_t *lslplen, uint32_t *nlslne, bool *have_nlslne)
{
    unsigned rel;

    if (nvme_field_in_window(off, len, 0, 4, &rel))
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_lba_status_lslplen,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN, lslplen);
    if (nvme_field_in_window(off, len, 4, 4, &rel)) {
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_lba_status_nlslne,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN, nlslne);
        *have_nlslne = true;
    }
    if (nvme_field_in_window(off, len, 8, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_estulb,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 12, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_rsvd,  cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 14, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_lsgc,  cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    /* The Namespace Element List item is added by the caller, over the same
     * byte range; adding it here as well made the field match twice per
     * frame. */
}

static unsigned dissect_nvme_get_logpage_lba_status_lba_range(proto_tree *grp, tvbuff_t *cmd_tvb, unsigned len, uint32_t poff)
{
    uint32_t nlrd = 0;
    uint64_t slen64;
    unsigned slen, rem;
    proto_item *ti;
    proto_tree *rd;

    ti = proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne,  cmd_tvb, poff, (len < 16) ? len : 16, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);

    if (len >= 4)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_neid,  cmd_tvb, poff, 4, ENC_LITTLE_ENDIAN);
    if (len >= 8)
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_lba_status_nel_ne_nlrd,  cmd_tvb, poff+4, 4, ENC_LITTLE_ENDIAN, &nlrd);
    if (len >= 9)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_ratype,  cmd_tvb, poff+8, 1, ENC_LITTLE_ENDIAN);
    if (len >= 16)
        proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_rsvd,  cmd_tvb, poff+9, 7, ENC_NA);

    if (len < 16)
        return len;

    /* Element is 16 * (NLRD + 1) bytes, in 64 bits (NVM CS 1.2 Figures
     * 110/111); it, not the list, bounds the descriptor walk. */
    if (!nlrd || nlrd == 0xffffffff)
        slen64 = 16;
    else
        slen64 = 16ULL * ((uint64_t)nlrd + 1);
    slen = (slen64 > len) ? len : (unsigned)slen64;
    proto_item_set_len(ti, slen);

    rem = slen - 16;
    poff += 16;
    while (rem >= 8) {
        ti = proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel_ne_rd,  cmd_tvb, poff, rem >= 16 ? 16 : rem, ENC_NA);
        rd =  proto_item_add_subtree(ti, ett_data);
        proto_tree_add_item(rd, hf_nvme_get_logpage_lba_status_nel_ne_rd_rslba, cmd_tvb, poff, 8, ENC_LITTLE_ENDIAN);
        if (rem >= 12)
            proto_tree_add_item(rd, hf_nvme_get_logpage_lba_status_nel_ne_rd_rnlb, cmd_tvb, poff+8, 4, ENC_LITTLE_ENDIAN);
        if (rem >= 16) {
            proto_tree_add_item(rd, hf_nvme_get_logpage_lba_status_nel_ne_rd_rsvd, cmd_tvb, poff+12, 4, ENC_LITTLE_ENDIAN);
            poff += 16;
            rem -= 16;
        } else {
            rem = 0;
        }
    }
    return slen;
}

/* `off` is the saturated combined offset. */
static void dissect_nvme_get_logpage_lba_status_resp(proto_item *ti, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_tree *grp = NULL;
    unsigned poff = 0;
    unsigned list_off;
    uint32_t lslplen = 0;
    uint32_t nlslne = 0;
    bool have_nlslne = false;

    if (off < 16) {
        grp =  proto_item_add_subtree(ti, ett_data);
        dissect_nvme_get_logpage_lba_status_resp_header(grp, cmd_tvb, len, off,
                                                        &lslplen, &nlslne, &have_nlslne);
        poff = 16 - off;
    } else if (off != 16) {
        /* Variable elements (NVM CS 1.2 Figures 110/111): only byte 16 is known. */
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }

    if (len < (poff + 8))
        return;

    if (off >= 16)
        grp =  proto_item_add_subtree(ti, ett_data);

    len -= poff;

    /* Bounded by LSLPLEN and NLSLNE when the header was in the window. */
    if (lslplen) {
        unsigned elems_off = off + poff;
        unsigned page_rem = (lslplen > elems_off) ? (lslplen - elems_off) : 0;
        if (len > page_rem)
            len = page_rem;
    }
    if (have_nlslne && !nlslne)
        return;
    if (len < 8)
        return;

    list_off = poff;
    ti = proto_tree_add_item(grp, hf_nvme_get_logpage_lba_status_nel,  cmd_tvb, poff, len, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);

    while (len >= 8) {
        unsigned done = dissect_nvme_get_logpage_lba_status_lba_range(grp, cmd_tvb, len, poff);
        poff += done;
        len -= done;
        if (have_nlslne && !--nlslne)
            break;
    }
    /* NLSLNE can stop the walk before the window ends. */
    proto_item_set_len(ti, poff - list_off);
}

static const range_string rnlpt_tbl[] = {
    { 0, 0, "Empty Log Page" },
    { 1, 1, "Registration Preempted" },
    { 2, 2, "Reservation Released" },
    { 3, 3, "Reservation Preempted" },
    { 4, 255, "Reserved" },
    { 0, 0, NULL}
};

static void dissect_nvme_get_logpage_reserv_notif_resp(proto_item *ti, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned poff = 0;
    unsigned rel;

    if (off > 60)
        return; /* max allowed offset is < 60 */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvme_field_in_window(off, len, 0, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_lpc,  cmd_tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 8, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_lpt,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 9, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_nalp,  cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 10, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_rsvd0,  cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 12, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_reserv_notif_nsid,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
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


/* Sanitize State (SANS) in the Sanitize State Information field; the Failure
 * State (FAILS) field takes its values from the same set (NVMe Base 2.3
 * "Sanitize Status Log Page"). */
static const range_string san_sans_tbl[] = {
    { 0, 0, "Idle" },
    { 1, 1, "Restricted Processing" },
    { 2, 2, "Restricted Failure" },
    { 3, 3, "Unrestricted Processing" },
    { 4, 4, "Unrestricted Failure" },
    { 5, 5, "Media Verification" },
    { 6, 6, "Post-Verification Deallocation" },
    { 7, 15, "Reserved" },
    { 0, 0, NULL}
};

/* NVMe Base 2.3 Figure 302, SSTAT bits 02:00. */
static const range_string san_sos_tbl[] = {
    { 0, 0, "Sanitize Never Started" },
    { 1, 1, "Sanitized" },
    { 2, 2, "Sanitizing" },
    { 3, 3, "Sanitize Failed" },
    { 4, 4, "Sanitized Unexpected Deallocate"},
    { 5, 7, "Reserved" },
    { 0, 0, NULL}
};

static void dissect_nvme_get_logpage_sanitize_resp(proto_item *ti, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_item *sprog_item = NULL;
    proto_tree *grp;
    unsigned poff = 0;
    unsigned rel;
    uint32_t sprog = 0;

    if (off > 508)
        return; /* max allowed offset is < 508 */

    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvme_field_in_window(off, len, 0, 2, &rel)) {
        sprog_item = proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_sanitize_sprog, cmd_tvb, rel, 2,
                                                  ENC_LITTLE_ENDIAN, &sprog);
        /* NVMe Base 2.3 Figure 302: SPROG FFFFh is a sentinel. */
        if (sprog == 0xffff)
            proto_item_append_text(sprog_item, " (not applicable: not sanitizing, or in Media Verification)");
        else
            proto_item_append_text(sprog_item, " (%.2f%% complete)", (double)sprog * 100.0 / 65536.0);
    }
    if (nvme_field_in_window(off, len, 2, 2, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 2, ASPEC(hf_nvme_get_logpage_sanitize_sstat));
    if (nvme_field_in_window(off, len, 4, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_scdw10,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 8, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_eto,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 12, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etbe,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 16, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etce,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 20, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etond,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 24, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etbend,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 28, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etcend,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 32, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_etpvds,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 36, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_sanitize_ssi));
    if (nvme_field_in_window(off, len, 37, 3, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_rsvd0,  cmd_tvb, rel, 3, ENC_NA);
    if (nvme_field_in_window(off, len, 40, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_mnsoip,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 44, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_stnsid,  cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (off < 48) {
        poff = 48 - off;
        /* Nothing past struct offset 48 in this window. */
        if (len <= poff)
            return;
        len -= poff;
        /* Remaining room at tvb position poff (struct offset 48) is (512 -
         * off) - poff, not 512 - poff: poff is tvb-relative (48-off), so
         * "512 - poff" silently adds back `off` bytes past the structure's
         * real 512-byte end. */
        if (len > (512 - off - poff))
            len = 512 - off - poff;
    } else {
        if (len > (512 - off))
            len = 512 - off;
    }
    proto_tree_add_item(grp, hf_nvme_get_logpage_sanitize_rsvd,  cmd_tvb, poff, len, ENC_NA);
}

/* FID (LID 12h) or NVMe-MI command (LID 13h) Supported and Effects: one
 * dword per identifier, named "<label> <id>h Supported and Effects". */
static void dissect_nvme_get_logpage_sup_and_eff_resp(proto_item *ti, tvbuff_t *cmd_tvb, packet_info *pinfo,
                                                      unsigned off, unsigned len, int hf_entry,
                                                      int *hf_bits, unsigned n_bits, const char *label)
{
    proto_tree *grp;
    unsigned nrec, fidx, i;

    grp = nvme_logpage_dword_array(ti, pinfo, off, len, &fidx, &nrec);
    if (!grp)
        return;

    for (i = 0; i < nrec; i++) {
        proto_item *entry;
        proto_tree *egrp;
        entry = proto_tree_add_bytes_format(grp, hf_entry, cmd_tvb, i * 4, 4, NULL,
                                            "%s %02Xh Supported and Effects", label, fidx + i);
        egrp = proto_item_add_subtree(entry, ett_data);
        add_group_mask_entry(cmd_tvb, egrp, i * 4, 4, hf_bits, n_bits);
    }
}

/* Command and Feature Lockdown (LID 14h), NVMe Base 2.3 Figure 271. */
static void dissect_nvme_get_logpage_cmd_feat_lockdown_resp(proto_item *ti, tvbuff_t *cmd_tvb, unsigned off, unsigned len)
{
    proto_tree *grp;
    proto_item *cfil_ti;
    uint8_t lngth, ss = 0xff, code;
    unsigned i, rel, n;

    grp = proto_item_add_subtree(ti, ett_data);
    if (nvme_field_in_window(off, len, 0, 1, &rel)) {
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_cmd_feat_lockdown_cfila));
        ss = tvb_get_uint8(cmd_tvb, rel) & 0x0f;
    }
    nvme_add_window_field(cmd_tvb, grp, hf_nvme_get_logpage_cmd_feat_lockdown_rsvd, off, len, 1, 2, ENC_NA);
    if (!nvme_field_in_window(off, len, 3, 1, &rel)) {
        /* Without LNGTH the list end is unknown (00h is a valid opcode). */
        if (off >= 4)
            nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    proto_tree_add_item_ret_uint8(grp, hf_nvme_get_logpage_cmd_feat_lockdown_lngth, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN, &lngth);

    /* CFIL entries are Admin opcodes under Scope 0h and FIDs under 2h, per
     * CFILA's echoed Scope (Base 2.3 Figure 271); Scopes 3h/4h stay raw. */
    if (nvme_window_intersect(off, len, 4, lngth, &rel, &n)) {
        for (i = 0; i < n; i++) {
            cfil_ti = proto_tree_add_item_ret_uint8(grp, hf_nvme_get_logpage_cmd_feat_lockdown_cfil,
                                                    cmd_tvb, rel + i, 1, ENC_LITTLE_ENDIAN, &code);
            if (ss == 0)
                proto_item_append_text(cfil_ti, " (%s)", get_aq_opcode_name(code));
            else if (ss == 2)
                proto_item_append_text(cfil_ti, " (%s)", get_feature_id_name(code));
        }
    }
    /* 511:n+4 Reserved, within the page only (Figure 201). */
    if (nvme_window_intersect(off, len, 4 + lngth, 512 - (4 + lngth), &rel, &n))
        proto_tree_add_item(grp, hf_nvme_get_logpage_cmd_feat_lockdown_rsvd1, cmd_tvb, rel, n, ENC_NA);
}

/* Command and Feature Lockdown, Enhanced format (LSP ELPF set), Base 2.4
 * Figures 277-278: a 16-byte header and NCFID descriptors of CFIDS bytes. */
static void dissect_nvme_get_logpage_lockdown_enh_resp(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo,
                                                       unsigned off, unsigned len)
{
    proto_tree *grp, *dt;
    proto_item *di, *cfi_ti;
    unsigned rel, i, pos, ncfid, cfids;
    uint8_t ss = 0xff, code;
    uint16_t cntlid;

    grp = proto_item_add_subtree(ti, ett_data);
    nvme_add_window_field(tvb, grp, hf_nvme_lp_lockdown_enh_ver, off, len, 0, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 1, 1, &rel)) {
        add_group_mask_entry(tvb, grp, rel, 1, ASPEC(hf_nvme_lp_lockdown_enh_cfia));
        ss = tvb_get_uint8(tvb, rel) & 0x0f;
    }
    if (nvme_field_in_window(off, len, 2, 2, &rel)) {
        cfi_ti = proto_tree_add_item_ret_uint16(grp, hf_nvme_lp_lockdown_enh_cntlid, tvb, rel, 2,
                                                ENC_LITTLE_ENDIAN, &cntlid);
        if (cntlid == 0xffff)
            proto_item_append_text(cfi_ti, " (NVM subsystem-wide)");
    }
    nvme_add_window_field(tvb, grp, hf_nvme_lp_lockdown_enh_sze, off, len, 4, 4, ENC_LITTLE_ENDIAN);
    nvme_add_window_field(tvb, grp, hf_nvme_lp_lockdown_enh_ncfid, off, len, 8, 2, ENC_LITTLE_ENDIAN);
    nvme_add_window_field(tvb, grp, hf_nvme_lp_lockdown_enh_cfids, off, len, 10, 2, ENC_LITTLE_ENDIAN);
    nvme_add_window_field(tvb, grp, hf_nvme_lp_lockdown_enh_rsvd, off, len, 12, 4, ENC_NA);
    if (!nvme_field_in_window(off, len, 8, 4, &rel)) {
        /* Without NCFID and CFIDS the descriptor list is not framed. */
        if (off + len > 16)
            nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    ncfid = tvb_get_letohs(tvb, rel);
    cfids = tvb_get_letohs(tvb, rel + 2);
    if (ncfid && cfids < 2) {
        expert_add_info_format(pinfo, ti, &ei_nvme_lp_layout,
                               "CFIDS %u is smaller than the 2-byte descriptor (NVMe Base 'Command and Feature Identifier Descriptor')", cfids);
        return;
    }
    for (i = 0; i < ncfid; i++) {
        pos = 16 + i * cfids;
        if (pos >= off + len)
            break;
        if (!nvme_field_in_window(off, len, pos, 2, &rel))
            continue;
        di = proto_tree_add_item(grp, hf_nvme_lp_lockdown_enh_desc, tvb, rel,
                                 MIN(cfids, off + len - pos), ENC_NA);
        proto_item_set_text(di, "Command and Feature Identifier Descriptor %u", i);
        dt = proto_item_add_subtree(di, ett_data);
        cfi_ti = proto_tree_add_item_ret_uint8(dt, hf_nvme_lp_lockdown_enh_cfi, tvb, rel, 1,
                                               ENC_LITTLE_ENDIAN, &code);
        if (ss == 0)
            proto_item_append_text(cfi_ti, " (%s)", get_aq_opcode_name(code));
        else if (ss == 2)
            proto_item_append_text(cfi_ti, " (%s)", get_feature_id_name(code));
        add_group_mask_entry(tvb, dt, rel + 1, 1, ASPEC(hf_nvme_lp_lockdown_enh_dcfia));
        if (cfids > 2)
            nvme_add_window_field(tvb, dt, hf_nvme_lp_lockdown_enh_desc_rsvd, off, len, pos + 2, cfids - 2, ENC_NA);
    }
}

/* Supported Log Pages (LID 00h): an array of 256 four-byte LID Supported and
 * Effects data structures, one per Log Page
 * Identifier 00h..FFh.  cmd_tvb begins at the returned data window; entry 0
 * here is the LID at logical offset `off` (LPO + the MI transfer/DOFF), so the
 * first decoded entry describes LID (off / 4). */
static void dissect_nvme_get_logpage_supported_grp(proto_tree *grp, tvbuff_t *cmd_tvb, unsigned nrec, unsigned lid0)
{
    unsigned i;
    proto_item *ti;
    proto_tree *sub;

    for (i = 0; i < nrec; i++) {
        ti = proto_tree_add_bytes_format(grp, hf_nvme_get_logpage_supported_lids, cmd_tvb, i * 4, 4, NULL,
                                         "Log Page Identifier 0x%02x Supported (LIDS%u)", lid0 + i, lid0 + i);
        sub =  proto_item_add_subtree(ti, ett_data);
        add_group_mask_entry(cmd_tvb, sub, i * 4, 4, ASPEC(hf_nvme_get_logpage_supported_lidseds));
        /* Base 2.3 Figures 219, 232, 308 and 313. */
        switch (lid0 + i) {
        case NVME_LID_TELEMETRY_HOST:
            proto_tree_add_item(sub, hf_nvme_lidsp_mcdas, cmd_tvb, i * 4 + 2, 2, ENC_LITTLE_ENDIAN);
            break;
        case NVME_LID_PERSISTENT_EVENT:
            proto_tree_add_item(sub, hf_nvme_lidsp_ecrh, cmd_tvb, i * 4 + 2, 2, ENC_LITTLE_ENDIAN);
            break;
        case NVME_LID_DISCOVERY:
            proto_tree_add_item(sub, hf_nvme_lidsp_extdlpes, cmd_tvb, i * 4 + 2, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sub, hf_nvme_lidsp_pleos, cmd_tvb, i * 4 + 2, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sub, hf_nvme_lidsp_allsubes, cmd_tvb, i * 4 + 2, 2, ENC_LITTLE_ENDIAN);
            break;
        case NVME_LID_HOST_DISCOVERY:
            proto_tree_add_item(sub, hf_nvme_lidsp_allhostes, cmd_tvb, i * 4 + 2, 2, ENC_LITTLE_ENDIAN);
            break;
        }
    }
}

static void dissect_nvme_get_logpage_supported_resp(proto_item *ti, tvbuff_t *cmd_tvb, packet_info *pinfo, unsigned off, unsigned len)
{
    proto_tree *grp;
    unsigned nrec, first;

    grp = nvme_logpage_dword_array(ti, pinfo, off, len, &first, &nrec);
    if (grp)
        dissect_nvme_get_logpage_supported_grp(grp, cmd_tvb, nrec, first);
}

static const range_string eom_eomip_tbl[] = {
    { 0, 0, "No Measurement Started" },
    { 1, 1, "Measurement In Progress" },
    { 2, 2, "Measurement Completed" },
    { 3, 255, "Reserved" },
    { 0, 0, NULL },
};

/* LID 19h LSP sub-fields (NVMe over PCIe Transport 1.4 Figure 72). */
static const value_string eom_lsp_act_tbl[] = {
    { 0, "Read Log Data" },
    { 1, "Start Measurement and Read Log Data" },
    { 2, "Abort Measurement and Clear Log" },
    { 3, "Reserved" },
    { 0, NULL },
};

static const value_string eom_lsp_mqual_tbl[] = {
    { 0, "Good" },
    { 1, "Better" },
    { 2, "Best" },
    { 3, "Reserved" },
    { 0, NULL },
};

/* One EOM Lane Descriptor (NVMe over PCIe Transport 1.4 Figure 76). */
static void dissect_nvme_get_logpage_eom_desc(proto_tree *grp, tvbuff_t *cmd_tvb, packet_info *pinfo, unsigned desc_off, unsigned ds, unsigned len, unsigned idx)
{
    proto_item *desc_ti;
    proto_tree *desc_tree;
    uint32_t nrows = 0, ncols = 0, edlen = 0;
    uint64_t eye_off, eye_end, desc_end;
    bool pe_ok = true, body_ok = true;

    desc_ti = proto_tree_add_bytes_format_value(grp, hf_nvme_get_logpage_eom_desc, cmd_tvb,
                    desc_off, ds, NULL, "EOM Lane Descriptor %u", idx);
    desc_tree = proto_item_add_subtree(desc_ti, ett_data);

    proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_rsvd0, cmd_tvb, desc_off, 1, ENC_NA);
    add_group_mask_entry(cmd_tvb, desc_tree, desc_off + 1, 1, ASPEC(hf_nvme_get_logpage_eom_desc_mstat));
    proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_ln, cmd_tvb, desc_off + 2, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_eye, cmd_tvb, desc_off + 3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_top, cmd_tvb, desc_off + 4, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_btm, cmd_tvb, desc_off + 6, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_lft, cmd_tvb, desc_off + 8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_rgt, cmd_tvb, desc_off + 10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(desc_tree, hf_nvme_get_logpage_eom_desc_nrows, cmd_tvb, desc_off + 12, 2, ENC_LITTLE_ENDIAN, &nrows);
    proto_tree_add_item_ret_uint(desc_tree, hf_nvme_get_logpage_eom_desc_ncols, cmd_tvb, desc_off + 14, 2, ENC_LITTLE_ENDIAN, &ncols);
    proto_tree_add_item_ret_uint(desc_tree, hf_nvme_get_logpage_eom_desc_edlen, cmd_tvb, desc_off + 16, 4, ENC_LITTLE_ENDIAN, &edlen);
    proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_rsvd1, cmd_tvb, desc_off + 20, 12, ENC_NA);

    /* Figure 76 places Eye Data at (NROWS*NCOLS+32), i.e. directly after the
     * Printable Eye.  So if PE is declared but does not fit in the descriptor,
     * ED's own start offset is past the end of the descriptor too and the
     * descriptor is internally inconsistent -- rendering ED at the PE offset
     * instead would present eye-diagram bytes under the Eye Data label. */
    desc_end = (uint64_t)desc_off + ds;
    eye_off = (uint64_t)desc_off + 32;
    if (nrows && ncols) {
        eye_end = eye_off + (uint64_t)nrows * ncols;
        pe_ok = (eye_end <= desc_end && eye_end <= len);
        if (pe_ok) {
            proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_pe, cmd_tvb,
                        (unsigned)eye_off, (int)(nrows * ncols), ENC_ASCII);
            eye_off = eye_end;
        } else {
            body_ok = false;
        }
    }
    if (edlen && pe_ok) {
        eye_end = eye_off + edlen;
        if (eye_end <= desc_end && eye_end <= len) {
            proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_ed, cmd_tvb,
                        (unsigned)eye_off, (int)edlen, ENC_NA);
            eye_off = eye_end;
        } else {
            body_ok = false;
        }
    }

    /* Declared, but too big for DS. */
    if (!body_ok)
        expert_add_info(pinfo, desc_ti, &ei_nvme_eom_desc_field_overrun);

    /* Figure 76: PAD only to a Dword boundary; more contradicts the body. */
    if (body_ok && eye_off < desc_end && desc_end <= len) {
        uint64_t rest = desc_end - eye_off;
        uint64_t want = (4 - ((eye_off - desc_off) % 4)) % 4;
        unsigned pad_len = (unsigned)((rest < want) ? rest : want);

        if (pad_len) {
            proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_pad,
                        cmd_tvb, (unsigned)eye_off, (int)pad_len, ENC_NA);
            eye_off += pad_len;
        }
        if (eye_off < desc_end)
            proto_tree_add_item(desc_tree, hf_nvme_get_logpage_eom_desc_undef,
                        cmd_tvb, (unsigned)eye_off, (int)(desc_end - eye_off), ENC_NA);
    }
}

/* Receiver Eye Opening Measurement (LID 19h, NVMe over PCIe Transport 1.4
 * Figures 74-76). */
static void dissect_nvme_get_logpage_eom_resp(proto_item *ti, tvbuff_t *cmd_tvb, packet_info *pinfo, unsigned off, unsigned len)
{
    proto_tree *grp;
    proto_item *hsize_ti = NULL;
    unsigned rel, i;
    uint32_t ds = 0, nd = 0, hsize = 0;

    grp = proto_item_add_subtree(ti, ett_data);

    if (nvme_field_in_window(off, len, 0, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_lid, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 1, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_eomip, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 2, 2, &rel))
        hsize_ti = proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_eom_hsize, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN, &hsize);
    if (nvme_field_in_window(off, len, 4, 4, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_rsz, cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 8, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_edgn, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 9, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_lrev, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 10, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_eom_odp));
    if (nvme_field_in_window(off, len, 11, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_lns, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 12, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_epl, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 13, 1, &rel)) {
        /* LSPFV echoes the LID 19h LSP value, so it carries ACT/MQUAL too. */
        proto_tree *lspfc = add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_eom_lspfc));
        proto_tree_add_item(lspfc, hf_nvme_get_logpage_eom_lspfc_act, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(lspfc, hf_nvme_get_logpage_eom_lspfc_mqual, cmd_tvb, rel, 1, ENC_LITTLE_ENDIAN);
    }
    if (nvme_field_in_window(off, len, 14, 1, &rel))
        add_group_mask_entry(cmd_tvb, grp, rel, 1, ASPEC(hf_nvme_get_logpage_eom_linfo));
    if (nvme_field_in_window(off, len, 15, 3, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_rsvd0, cmd_tvb, rel, 3, ENC_NA);
    if (nvme_field_in_window(off, len, 18, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_lsic, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 20, 4, &rel))
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_eom_ds, cmd_tvb, rel, 4, ENC_LITTLE_ENDIAN, &ds);
    if (nvme_field_in_window(off, len, 24, 2, &rel))
        proto_tree_add_item_ret_uint(grp, hf_nvme_get_logpage_eom_nd, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN, &nd);
    if (nvme_field_in_window(off, len, 26, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_maxtb, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 28, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_maxlr, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 30, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_etgood, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 32, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_etbetter, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 34, 2, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_etbest, cmd_tvb, rel, 2, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 36, 28, &rel))
        proto_tree_add_item(grp, hf_nvme_get_logpage_eom_rsvd1, cmd_tvb, rel, 28, ENC_NA);

    /* Only the descriptor list is lost. */
    if (off != 0) {
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    /* Figure 75: HSIZE "shall be set to 64".  Figure 74 starts the
     * descriptor list at HSIZE, so a larger value is followed; a smaller one
     * would put descriptors over the header's own fields. */
    if (len >= 4 && hsize != 64) {
        if (hsize < 64) {
            expert_add_info_format(pinfo, hsize_ti, &ei_nvme_eom_hsize_invalid,
                                   "Header Size %u is smaller than the 64-byte EOM Header"
                                   " (NVMe over PCIe Transport 1.4 Figure 75);"
                                   " the descriptor list is not decoded", hsize);
            return;
        }
        expert_add_info(pinfo, hsize_ti, &ei_nvme_eom_hsize_invalid);
    }
    if (len < 64 || ds < 32 || nd == 0)
        return; /* need DS/ND from the header to walk the descriptor list */

    for (i = 0; i < nd; i++) {
        uint64_t desc_off64 = (uint64_t)hsize + (uint64_t)i * ds;

        /* ND and DS are both wire-declared and unvalidated, and a read may
         * return only a prefix of the log (Base 2.3 Figures 202/203), so ND
         * can exceed what the response holds without being malformed.  `len`
         * is already bounded by the buffer by the callers (see
         * dissect_nvme_get_logpage_resp()), so this is the structural bound:
         * stop at the last descriptor that fits in the declared response. */
        if (desc_off64 + ds > len)
            break;
        dissect_nvme_get_logpage_eom_desc(grp, cmd_tvb, pinfo, (unsigned)desc_off64, ds, len, i);
    }
}

/* Clear the Get Log Page record walk state of cmd_ctx. */
static void
nvme_logpage_walk_reset(struct nvme_cmd_ctx *cmd_ctx)
{
    cmd_ctx->cmd_ctx.get_logpage.records = 0;
    cmd_ctx->cmd_ctx.get_logpage.records_valid = false;
    cmd_ctx->cmd_ctx.get_logpage.tr_off = 0;
    cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = 0;
    cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id = 0;
    cmd_ctx->cmd_ctx.get_logpage.tr_next_off = 0;
}

/* pinfo->pool keys, above the layer numbers that key the file-scope proto
 * data: how many Security Send data windows, and how many Get Log Page windows,
 * this frame has had. */
#define NVME_SEC_SEND_ORDINAL_KEY 0x10000
#define NVME_WALK_ORDINAL_KEY 0x10001

/* The walk state a Get Log Page window started with, by (frame, ordinal of the
 * window in the frame): the first pass records it, and a later visit of the
 * window, in any order, restores it, so the window decodes as it did in
 * order.  An NVMe/TCP segment can hold several windows. */
struct nvme_walk_state {
    unsigned records;
    bool records_valid;
    unsigned tr_rcrd_id, tr_off, tr_sub_entries;
    uint32_t tr_next_off;
    uint8_t tr_type;
};
static wmem_map_t *nvme_walk_states;

static void
nvme_logpage_walk_sync(packet_info *pinfo, struct nvme_cmd_ctx *cmd_ctx)
{
    unsigned ordinal = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo,
                                        proto_nvme, NVME_WALK_ORDINAL_KEY));
    uint64_t key = ((uint64_t)pinfo->num << 32) | ordinal;
    struct nvme_walk_state *s = wmem_map_lookup(nvme_walk_states, &key);

    p_set_proto_data(pinfo->pool, pinfo, proto_nvme, NVME_WALK_ORDINAL_KEY,
                     GUINT_TO_POINTER(ordinal + 1));

    if (s) {
        cmd_ctx->cmd_ctx.get_logpage.records = s->records;
        cmd_ctx->cmd_ctx.get_logpage.records_valid = s->records_valid;
        cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id = s->tr_rcrd_id;
        cmd_ctx->cmd_ctx.get_logpage.tr_off = s->tr_off;
        cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries = s->tr_sub_entries;
        cmd_ctx->cmd_ctx.get_logpage.tr_next_off = s->tr_next_off;
        cmd_ctx->cmd_ctx.get_logpage.tr_type = s->tr_type;
    } else if (!PINFO_FD_VISITED(pinfo)) {
        s = wmem_new(wmem_file_scope(), struct nvme_walk_state);
        s->records = cmd_ctx->cmd_ctx.get_logpage.records;
        s->records_valid = cmd_ctx->cmd_ctx.get_logpage.records_valid;
        s->tr_rcrd_id = cmd_ctx->cmd_ctx.get_logpage.tr_rcrd_id;
        s->tr_off = cmd_ctx->cmd_ctx.get_logpage.tr_off;
        s->tr_sub_entries = cmd_ctx->cmd_ctx.get_logpage.tr_sub_entries;
        s->tr_next_off = cmd_ctx->cmd_ctx.get_logpage.tr_next_off;
        s->tr_type = cmd_ctx->cmd_ctx.get_logpage.tr_type;
        wmem_map_insert(nvme_walk_states,
                        wmem_memdup(wmem_file_scope(), &key, sizeof(key)), s);
    }
}

/* Reachability Association Characteristics (RAC), Base 2.3 Figure 283. */
static const range_string reach_rac_rvals[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Reachable with no performance characteristics specified" },
    { 0x02, 0x02, "Fast copy operations are supported" },
    { 0x03, 0x03, "Fast copy operations are not supported" },
    { 0x04, 0xff, "Reserved" },
    { 0, 0, NULL }
};

/* Reachability Groups (LID 1Ah) and Associations (LID 1Bh), Base 2.3
 * Figures 279-283.  With header, the window is at log page offset off;
 * otherwise it starts at descriptor idx (an OT=1 index).  The descriptors
 * vary in length, so false means the window starts past the first one. */
static bool
dissect_nvme_reach_log(tvbuff_t *tvb, proto_tree *tree, uint8_t lid, unsigned off,
                       unsigned len, bool header, unsigned idx)
{
    bool assoc = lid == NVME_LID_REACHABILITY_ASSOC;
    unsigned pos = 0;
    unsigned count = UINT_MAX;
    unsigned rel;

    if (header) {
        nvme_add_window_field(tvb, tree, hf_nvme_reach_chngc, off, len, 0, 8, ENC_LITTLE_ENDIAN);
        nvme_add_window_field(tvb, tree, hf_nvme_reach_count, off, len, 8, 2, ENC_LITTLE_ENDIAN);
        nvme_add_window_field(tvb, tree, hf_nvme_reach_rsvd, off, len, 10, 6, ENC_NA);
        if (nvme_field_in_window(off, len, 8, 2, &rel))
            count = tvb_get_letohs(tvb, rel);
        if (off > 16)
            return false;
        pos = 16 - off;
    }
    for (unsigned i = 0; pos < len && i < count; i++) {
        unsigned avail = len - pos;
        tvbuff_t *desc = tvb_new_subset_length(tvb, pos, avail);
        proto_item *di;
        proto_tree *dt = proto_tree_add_subtree_format(tree, tvb, pos, avail, ett_data, &di,
                            "Reachability %s Descriptor %u", assoc ? "Association" : "Group",
                            idx + i);

        nvme_add_window_field(desc, dt, hf_nvme_reach_id, 0, avail, 0, 4, ENC_LITTLE_ENDIAN);
        nvme_add_window_field(desc, dt, hf_nvme_reach_nids, 0, avail, 4, 4, ENC_LITTLE_ENDIAN);
        nvme_add_window_field(desc, dt, hf_nvme_reach_desc_chngc, 0, avail, 8, 8, ENC_LITTLE_ENDIAN);
        if (assoc)
            nvme_add_window_field(desc, dt, hf_nvme_reach_rac, 0, avail, 16, 1, ENC_LITTLE_ENDIAN);
        nvme_add_window_field(desc, dt, hf_nvme_reach_rsvd, 0, avail, assoc ? 17 : 16,
                              assoc ? 15 : 16, ENC_NA);
        if (avail < 8)
            break;
        uint32_t nids = tvb_get_letohl(desc, 4);
        uint64_t size = 32 + (uint64_t)nids * 4;
        for (unsigned p = 32; p <= avail && avail - p >= 4 && (p - 32) / 4 < nids; p += 4)
            proto_tree_add_item(dt, hf_nvme_reach_member, desc, p, 4, ENC_LITTLE_ENDIAN);
        if (size >= avail)
            break;
        proto_item_set_len(di, (int)size);
        pos += (unsigned)size;
    }
    return true;
}

/* Indexed log pages (MI 2.1 Figure 140): DOFST is relative to the selected
 * index; no state from other transactions. */
static bool
dissect_nvme_index_log(tvbuff_t *tvb, proto_item *ti,
                       struct nvme_cmd_ctx *ctx, unsigned off, unsigned len)
{
    struct nvme_cmd_ctx *outer = ctx;
    struct nvme_cmd_ctx local = *ctx;
    ctx = &local;
    /* A selected index restarts the walk state. */
    nvme_logpage_walk_reset(ctx);
    uint8_t lid = ctx->cmd_ctx.get_logpage.lid;
    uint64_t entry_index = ctx->cmd_ctx.get_logpage.off;
    proto_tree *tree = proto_item_add_subtree(ti, ett_data);
    unsigned rel;

    if (lid == NVME_LID_ANA) {
        if (!entry_index)
            dissect_nvme_get_logpage_ana_resp(ti, tvb, ctx, off, len);
        else if (!off)
            dissect_nvme_get_logpage_ana_resp(ti, tvb, ctx, 16, len);
        else
            return false;
        return true;
    }
    if (lid == NVME_LID_DISCOVERY) {
        if (!entry_index) {
            dissect_nvme_get_logpage_ify_resp(ti, tvb, ctx, off, len);
            return true;
        }
        if (off >= 1024)
            return false;
        /* Both entry formats share the fixed 1024-byte prefix. */
        unsigned avail = MIN(len, 1024 - off);
        dissect_nvme_get_logpage_ify_rcrd_resp(tvb, ctx, tree, entry_index - 1,
                                             off, 0, avail, 1024);
        /* The entry's TRTYPE selects its TSAS layout (Base 2.3 Figure 310)
         * in a later window of the same command. */
        if (!off)
            outer->cmd_ctx.get_logpage.tr_type = ctx->cmd_ctx.get_logpage.tr_type;
        if (len > avail)
            nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return true;
    }
    if (lid == NVME_LID_REACHABILITY_GROUPS || lid == NVME_LID_REACHABILITY_ASSOC) {
        if (entry_index && off)
            return false;
        return dissect_nvme_reach_log(tvb, tree, lid, off, len, !entry_index,
                                      entry_index ? (unsigned)MIN(entry_index - 1, UINT_MAX) : 0);
    }
    if (lid == NVME_LID_HOST_DISCOVERY) {
        unsigned pos = 0;
        uint64_t records = UINT64_MAX;
        if (!entry_index) {
            nvme_add_window_field(tvb, tree, hf_nvme_hostdisc_genctr, off, len, 0, 8, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_hostdisc_numrec, off, len, 8, 8, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_hostdisc_recfmt, off, len, 16, 2, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_hostdisc_flags, off, len, 18, 1, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_hostdisc_length, off, len, 20, 4, ENC_LITTLE_ENDIAN);
            if (!nvme_field_in_window(off, len, 16, 2, &rel) || tvb_get_letohs(tvb, rel))
                return false;
            if (nvme_field_in_window(off, len, 8, 8, &rel))
                records = tvb_get_letoh64(tvb, rel);
            if (nvme_field_in_window(off, len, 20, 4, &rel)) {
                uint32_t end = tvb_get_letohl(tvb, rel);
                if (end < 1024)
                    return true;
                len = MIN(len, end - off);
            }
            pos = 1024 - off;
            if (pos >= len)
                return true;
            off = 0;
        }
        if (off >= 1032)
            return false;
        while (pos < len && records) {
            unsigned avail = len - pos;
            tvbuff_t *entry = tvb_new_subset_length(tvb, pos, avail);
            uint32_t tel = 0;
            if (nvme_field_in_window(off, avail, 1024, 4, &rel)) {
                tel = tvb_get_letohl(entry, rel);
                if (tel < 1032 || (tel & 3))
                    return false;
                avail = MIN(avail, tel - off);
            }
            nvme_add_window_field(entry, tree, hf_nvme_hostdisc_trtype, off, avail, 0, 1, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(entry, tree, hf_nvme_hostdisc_adrfam, off, avail, 1, 1, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(entry, tree, hf_nvme_hostdisc_ncc, off, avail, 10, 2, ENC_LITTLE_ENDIAN);
            dissect_nvme_nqn(entry, tree, hf_nvme_hostdisc_nqn, 0, avail, off, 256, false);
            nvme_add_window_field(entry, tree, hf_nvme_hostdisc_tel, off, avail, 1024, 4, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(entry, tree, hf_nvme_hostdisc_numexat, off, avail, 1028, 2, ENC_LITTLE_ENDIAN);
            if (!tel || tel - off >= len - pos)
                break;
            pos += tel - off;
            off = 0;
            records--;
        }
        return true;
    }
    return false;
}

/* Boot Partition Size (BPSZ), Base 2.3 Figure 273: units of 128 KiB. */
static void add_nvme_bpsz(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u (%u KiB)", val, val * 128);
}

/* Nominal Rotational Speed (NRS), Base 2.3 Figure 274. */
static void add_nvme_rmi_nrs(char *result, uint32_t val)
{
    if (val == 0)
        snprintf(result, ITEM_LABEL_LENGTH, "Not reported (0)");
    else if (val == 1)
        snprintf(result, ITEM_LABEL_LENGTH, "Prohibited (1)");
    else if (val == 0xffff)
        snprintf(result, ITEM_LABEL_LENGTH, "Reserved (0xffff)");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u RPM", val);
}

/* Management Address Type (MAT), Base 2.3 Figure 277. */
static const value_string lp_mal_mat_tbl[] = {
    { 0x00, "Reserved (Management Address field reserved)" },
    { 0x01, "Management agent in the NVM subsystem" },
    { 0x02, "Fabric interface manager" },
    { 0xff, "End of list (this and later descriptors reserved)" },
    { 0, NULL }
};

/* Minimum Required Reset Type (MRSTT), Base 2.3 Figure 285. */
static const value_string lp_dp_mrstt_tbl[] = {
    { 0x00, "No Reset" },
    { 0x01, "Controller Level Reset" },
    { 0x02, "Limited Controller Level Reset" },
    { 0x03, "NVM Subsystem Reset" },
    { 0x04, "Power Cycle" },
    { 0, NULL }
};

/* Interval Power Percent Error (IPWRPE), Base 2.3 Figure 297. */
static const range_string lp_pm_ipwrpe_rvals[] = {
    { 0, 100, "Maximum percent error" },
    { 101, 254, "Reserved" },
    { 255, 255, "Not reported" },
    { 0, 0, NULL }
};

/* Boot Partition (LID 15h), Base 2.3 Figure 273.  The data is an image. */
static void dissect_nvme_get_logpage_boot_part_resp(proto_item *ti, tvbuff_t *tvb, unsigned off, unsigned len)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 1, hf_nvme_lp_bp_lid, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 3, hf_nvme_lp_bp_rsvd0, ENC_NA),
        NVME_WG(4, 4, hf_nvme_lp_bp_bpinfo),
        NVME_WF(8, 8, hf_nvme_lp_bp_rsvd1, ENC_NA),
    };
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    unsigned rel, n;

    nvme_add_window_fields(tvb, grp, off, len, f, array_length(f));
    if (nvme_window_intersect(off, len, 16, UINT_MAX - 16, &rel, &n))
        proto_tree_add_item(grp, hf_nvme_lp_bp_bpd, tvb, rel, n, ENC_NA);
}

/* Rotational Media Information (LID 16h), Base 2.3 Figure 274. */
static void dissect_nvme_get_logpage_rotational_resp(proto_item *ti, tvbuff_t *tvb, unsigned off, unsigned len)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 2, hf_nvme_lp_rmi_endgid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_lp_rmi_numa, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 2, hf_nvme_lp_rmi_nrs, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 2, hf_nvme_lp_rmi_rsvd0, ENC_NA),
        NVME_WF(8, 4, hf_nvme_lp_rmi_spinc, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 4, hf_nvme_lp_rmi_fspinc, ENC_LITTLE_ENDIAN),
        NVME_WF(16, 4, hf_nvme_lp_rmi_ldc, ENC_LITTLE_ENDIAN),
        NVME_WF(20, 4, hf_nvme_lp_rmi_fldc, ENC_LITTLE_ENDIAN),
        NVME_WF(24, 488, hf_nvme_lp_rmi_rsvd1, ENC_NA),
    };
    nvme_add_window_fields(tvb, proto_item_add_subtree(ti, ett_data), off, len, f, array_length(f));
}

/* Management Address List (LID 18h), Base 2.3 Figures 276-277. */
static void dissect_nvme_get_logpage_mgmt_addr_resp(proto_item *ti, tvbuff_t *tvb, unsigned off, unsigned len)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 1, hf_nvme_lp_mal_mat, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 3, hf_nvme_lp_mal_rsvd, ENC_NA),
        NVME_WF(4, 508, hf_nvme_lp_mal_madrs, ENC_UTF_8),
    };
    static const nvme_window_list l = {
        0, 512, 8, 0, "Management Address Descriptor", f, array_length(f)
    };
    unsigned count = 8, rel;

    /* MAT FFh ends the list; later descriptors are reserved. */
    for (unsigned i = 0; i < 8; i++) {
        if (nvme_field_in_window(off, len, i * 512, 1, &rel) && tvb_get_uint8(tvb, rel) == 0xff) {
            count = i + 1;
            break;
        }
    }
    nvme_add_window_list(tvb, proto_item_add_subtree(ti, ett_data), off, len, &l, count, true, false);
}

/* Device Personalities (LID 1Dh), Base 2.3 Figures 284-285. */
static void dissect_nvme_get_logpage_dev_pers_resp(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo,
                                                   unsigned off, unsigned len)
{
    static const nvme_window_field hdr[] = {
        NVME_WF(0, 2, hf_nvme_lp_dp_nump, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 1, hf_nvme_lp_dp_cdplpv, ENC_LITTLE_ENDIAN),
        NVME_WF(3, 1, hf_nvme_lp_dp_dplphl, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 2, hf_nvme_lp_dp_cdplps, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field pp[] = {
        NVME_WF(0, 1, hf_nvme_lp_dp_pps, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_lp_dp_perid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 1, hf_nvme_lp_dp_mrstt, ENC_LITTLE_ENDIAN),
        NVME_WG(3, 1, hf_nvme_lp_dp_aus),
        NVME_WG(4, 1, hf_nvme_lp_dp_attr),
    };
    /* Without the header, the layout the spec mandates: DPLPHL 6h, PPS 5h. */
    nvme_window_list l = { 6, 5, (UINT_MAX - 6) / 5, 0, "Personality", pp, array_length(pp) };
    unsigned count = NVME_LIST_COUNT_UNKNOWN;
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);

    nvme_add_window_fields(tvb, grp, off, len, hdr, array_length(hdr));
    if (!off && len >= 4) {
        count = tvb_get_letohs(tvb, 0) + 1u;
        l.first = tvb_get_uint8(tvb, 3);
        l.max = (UINT_MAX - l.first) / 5;
        if (l.first < 6) {
            expert_add_info_format(pinfo, ti, &ei_nvme_lp_layout,
                                   "DPLPHL %u is shorter than the 6-byte header (NVMe Base 'Device Personalities Log Page')", l.first);
            return;
        }
    }
    /* Each Personality Properties structure is 5 bytes (PPS shall be 5h). */
    for (unsigned i = 0, rel; i < count; i++) {
        uint64_t at = (uint64_t)l.first + (uint64_t)i * 5;
        if (at >= (uint64_t)off + len)
            break;
        if (!nvme_field_in_window(off, len, (unsigned)at, 1, &rel))
            continue;
        if (tvb_get_uint8(tvb, rel) != 5) {
            expert_add_info_format(pinfo, ti, &ei_nvme_lp_layout,
                                   "Personality %u has PPS %u; NVMe Base 'Personality Properties Data Structure' defines 5", i,
                                   tvb_get_uint8(tvb, rel));
            count = i;
            break;
        }
    }
    nvme_add_window_list(tvb, grp, off, len, &l, count, true, false);
}

/* Manufacturer Default Configuration Status (LID 24h), Base 2.4 Figure 304. */
static void dissect_nvme_get_logpage_mdcs_resp(proto_item *ti, tvbuff_t *tvb, unsigned off, unsigned len)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 1, hf_nvme_lp_mdcs_mdcsv, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_lp_mdcs_mdcs, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_lp_mdcs_dscs, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_lp_mdcs_dncs, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_lp_mdcs_dccs, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_lp_mdcs_rsvd, ENC_LITTLE_ENDIAN),
    };
    nvme_add_window_fields(tvb, proto_item_add_subtree(ti, ett_data), off, len, f, array_length(f));
}

/* Power Measurement (LID 25h), Base 2.3 Figures 297-298. */
static void dissect_nvme_get_logpage_power_meas_resp(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo,
                                                     unsigned off, unsigned len)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 1, hf_nvme_lp_pm_ver, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 1, hf_nvme_lp_pm_pmgn, ENC_LITTLE_ENDIAN),
        NVME_WG(2, 2, hf_nvme_lp_pm_pma),
        NVME_WF(4, 4, hf_nvme_lp_pm_sze, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 4, hf_nvme_lp_pm_pmc, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 2, hf_nvme_lp_pm_nphd, ENC_LITTLE_ENDIAN),
        NVME_WF(14, 2, hf_nvme_lp_pm_smtr, ENC_LITTLE_ENDIAN),
        NVME_WG(16, 8, hf_nvme_lp_pm_smts),
        NVME_WF(24, 2, hf_nvme_lp_pm_phds, ENC_LITTLE_ENDIAN),
        NVME_WF(26, 2, hf_nvme_lp_pm_phbs, ENC_LITTLE_ENDIAN),
        NVME_WF(28, 2, hf_nvme_lp_pm_nphds, ENC_LITTLE_ENDIAN),
        NVME_WF(30, 2, hf_nvme_lp_pm_vss, ENC_LITTLE_ENDIAN),
        NVME_WF(32, 4, hf_nvme_lp_pm_phdoc, ENC_LITTLE_ENDIAN),
        NVME_WF(36, 4, hf_nvme_lp_pm_rsvd0, ENC_NA),
        NVME_WG(40, 4, hf_nvme_lp_pm_aipwr),
        NVME_WG(44, 4, hf_nvme_lp_pm_mipwr),
        NVME_WG(48, 8, hf_nvme_lp_pm_mipwrt),
        NVME_WF(56, 1, hf_nvme_lp_pm_ipwrpe, ENC_LITTLE_ENDIAN),
        NVME_WF(57, 7, hf_nvme_lp_pm_rsvd1, ENC_NA),
    };
    static const nvme_window_field d[] = {
        NVME_WF(0, 4, hf_nvme_lp_pm_phbc, ENC_LITTLE_ENDIAN),
        NVME_WG(4, 4, hf_nvme_lp_pm_phblt),
    };
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    nvme_window_list l = { 64, 8, 0, 0, "Power Histogram Descriptor", d, array_length(d) };
    unsigned nphd, vss, rel, n;

    nvme_add_window_fields(tvb, grp, off, len, f, array_length(f));
    /* The list and the VS area are located by NPHD, PHDS and VSS. */
    if (off || len < 32)
        return;
    nphd = tvb_get_letohs(tvb, 12);
    l.stride = tvb_get_letohs(tvb, 24);
    vss = tvb_get_letohs(tvb, 30);
    if (nphd && l.stride < 8) {
        expert_add_info_format(pinfo, ti, &ei_nvme_lp_layout,
                               "PHDS %u is smaller than the 8-byte Power Histogram Descriptor",
                               l.stride);
        return;
    }
    l.max = nphd;
    if (nphd)
        nvme_add_window_list(tvb, grp, 0, len, &l, nphd, true, false);
    if (vss && nvme_window_intersect(0, len, 64 + nphd * l.stride, vss, &rel, &n))
        proto_tree_add_item(grp, hf_nvme_lp_pm_vs, tvb, rel, n, ENC_NA);
}

/* Interval Overvoltage/Undervoltage Percent Error, Base 2.4 Figure 307. */
static void add_nvme_vm_pct_err(char *result, uint32_t val)
{
    if (val <= 100)
        snprintf(result, ITEM_LABEL_LENGTH, "%u%%", val);
    else if (val == 255)
        snprintf(result, ITEM_LABEL_LENGTH, "Not reported (255)");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "Reserved (%u)", val);
}

/* Voltage Measurement (LID 27h), Base 2.4 Figures 307-308. */
static void dissect_nvme_get_logpage_voltage_meas_resp(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo,
                                                       unsigned off, unsigned len)
{
    static const nvme_window_field f[] = {
        NVME_WF(0, 1, hf_nvme_lp_vm_vmgn, ENC_LITTLE_ENDIAN),
        NVME_WG(1, 1, hf_nvme_lp_vm_vma),
        NVME_WG(2, 2, hf_nvme_lp_vm_vsi),
        NVME_WF(4, 4, hf_nvme_lp_vm_vmlsz, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 2, hf_nvme_lp_vm_nvmds, ENC_LITTLE_ENDIAN),
        NVME_WF(10, 2, hf_nvme_lp_vm_nvmde, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 2, hf_nvme_lp_vm_svmtr, ENC_LITTLE_ENDIAN),
        NVME_WG(14, 8, hf_nvme_lp_vm_svmts),
        NVME_WF(22, 2, hf_nvme_lp_vm_cntlid, ENC_LITTLE_ENDIAN),
        NVME_WF(24, 2, hf_nvme_lp_vm_vlvss, ENC_LITTLE_ENDIAN),
        NVME_WF(26, 6, hf_nvme_lp_vm_rsvd0, ENC_NA),
        NVME_WG(32, 2, hf_nvme_lp_vm_ovol),
        NVME_WF(34, 2, hf_nvme_lp_vm_ovc, ENC_LITTLE_ENDIAN),
        NVME_WF(36, 2, hf_nvme_lp_vm_ovlt, ENC_LITTLE_ENDIAN),
        NVME_WG(38, 8, hf_nvme_lp_vm_ovts),
        NVME_WF(46, 1, hf_nvme_lp_vm_iovpe, ENC_LITTLE_ENDIAN),
        NVME_WG(47, 2, hf_nvme_lp_vm_uvol),
        NVME_WF(49, 2, hf_nvme_lp_vm_uvc, ENC_LITTLE_ENDIAN),
        NVME_WF(51, 2, hf_nvme_lp_vm_uvlt, ENC_LITTLE_ENDIAN),
        NVME_WG(53, 8, hf_nvme_lp_vm_uvts),
        NVME_WF(61, 1, hf_nvme_lp_vm_iuvpe, ENC_LITTLE_ENDIAN),
        NVME_WF(62, 2, hf_nvme_lp_vm_rsvd1, ENC_NA),
    };
    static const nvme_window_field d[] = {
        NVME_WG(0, 2, hf_nvme_lp_vm_ivolm),
    };
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    nvme_window_list l = { 64, 2, 0, 0, "Interval Voltage Measurement Descriptor", d, array_length(d) };
    unsigned nvmds, nvmde, vlvss, rel, n;

    nvme_add_window_fields(tvb, grp, off, len, f, array_length(f));
    /* NVMDE locates the descriptor list end and so the VS area. */
    if (off || len < 26)
        return;
    nvmds = tvb_get_letohs(tvb, 8);
    nvmde = tvb_get_letohs(tvb, 10);
    vlvss = tvb_get_letohs(tvb, 24);
    if (nvmde > nvmds)
        expert_add_info_format(pinfo, ti, &ei_nvme_lp_layout,
                               "NVMDE %u exceeds NVMDS %u (NVMe Base 'Voltage Measurement Log Page')", nvmde, nvmds);
    l.max = nvmde;
    if (nvmde)
        nvme_add_window_list(tvb, grp, 0, len, &l, nvmde, true, false);
    if (vlvss && nvme_window_intersect(0, len, 64 + nvmde * 2, vlvss, &rel, &n))
        proto_tree_add_item(grp, hf_nvme_lp_vm_vlvs, tvb, rel, n, ENC_NA);
}

/* Rate Limiting (LID 28h), NVM CS 1.3 Figures 117-121.  The port,
 * controller and Non-Volatile Storage Medium Access descriptors are linked
 * by dword offsets from the start of the log page.  They are walked from a
 * queue rather than recursively, and each offset is decoded only once, so
 * shared or looping references stay bounded by the transfer size. */
enum { NVME_RL_PORT, NVME_RL_CTRL, NVME_RL_NSMA };

typedef struct {
    unsigned kind;
    unsigned pos;
    proto_tree *tree;
} nvme_rl_ref;

typedef struct {
    tvbuff_t *tvb;
    packet_info *pinfo;
    unsigned len;           /* bytes of the log page in the transfer */
    unsigned rld;           /* first byte of the Rate Limiting Data field */
    uint64_t lpl;           /* LPL in bytes */
    wmem_array_t *queue;
    uint8_t *seen;          /* per dword: a descriptor starts here */
    uint8_t *listed;        /* per dword: an offset list entry was read here */
    unsigned end;           /* end of the furthest descriptor */
    bool complete;          /* every descriptor was in the transfer */
} nvme_rl_walk;

static void add_nvme_rl_dword_off(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u (byte %" PRIu64 ")", val, (uint64_t)val * 4);
}

static void add_nvme_rl_zeroes_based(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u (%u entr%s)", val, val + 1, val ? "ies" : "y");
}

static void
nvme_rl_add_bw(proto_tree *tree, int hf, tvbuff_t *tvb, unsigned at, uint32_t sf)
{
    proto_item *ti = proto_tree_add_item(tree, hf, tvb, at, 8, ENC_LITTLE_ENDIAN);
    proto_item_append_text(ti, " x %s", rval_to_str_const(sf, nvme_rl_bwsf_rvals, "Reserved"));
}

/* Rate Limiting Maximum Access Descriptor, Figure 121. */
static void
nvme_rl_add_rlma(proto_tree *tree, tvbuff_t *tvb, unsigned at)
{
    proto_item *ti = proto_tree_add_item(tree, hf_nvme_lp_rl_rlma, tvb, at, 32, ENC_NA);
    proto_tree *t = proto_item_add_subtree(ti, ett_data);
    uint32_t mbsf;

    proto_tree_add_item_ret_uint(t, hf_nvme_lp_rl_mbsf, tvb, at, 1, ENC_LITTLE_ENDIAN, &mbsf);
    proto_tree_add_item(t, hf_nvme_lp_rl_dsc_rsvd, tvb, at + 1, 7, ENC_NA);
    nvme_rl_add_bw(t, hf_nvme_lp_rl_mrbwv, tvb, at + 8, mbsf);
    nvme_rl_add_bw(t, hf_nvme_lp_rl_mwbwv, tvb, at + 16, mbsf);
    proto_tree_add_item(t, hf_nvme_lp_rl_mriops, tvb, at + 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(t, hf_nvme_lp_rl_mwiops, tvb, at + 28, 4, ENC_LITTLE_ENDIAN);
}

/* Add the dword offset at 'at' and queue the descriptor it references. */
static void
nvme_rl_add_ref(nvme_rl_walk *w, proto_tree *tree, int hf, unsigned at, unsigned kind)
{
    uint32_t v;
    uint64_t pos;
    proto_item *ti = proto_tree_add_item_ret_uint(tree, hf, w->tvb, at, 4, ENC_LITTLE_ENDIAN, &v);
    nvme_rl_ref r;

    pos = (uint64_t)v * 4;
    if (pos < w->rld || pos >= w->lpl) {
        expert_add_info_format(w->pinfo, ti, &ei_nvme_lp_layout,
                               "Offset %u dwords is outside the Rate Limiting Data field "
                               "(NVM Command Set 'Rate Limiting Log Page')", v);
        return;
    }
    if (pos >= w->len) {
        w->complete = false;
        return;
    }
    if (w->seen[pos / 4]) {
        proto_item_append_text(ti, " [descriptor decoded at its first reference]");
        return;
    }
    w->seen[pos / 4] = 1;
    r.kind = kind;
    r.pos = (unsigned)pos;
    r.tree = tree;
    wmem_array_append_one(w->queue, r);
}

static void
nvme_rl_add_desc(nvme_rl_walk *w, const nvme_rl_ref *r)
{
    /* Fixed part sizes (Figures 118-120) and where each offset list starts. */
    static const unsigned fixed[] = { 1024, 320, 64 };
    tvbuff_t *tvb = w->tvb;
    unsigned at = r->pos, list = at + fixed[r->kind], count, child_kind, i;
    int hf_item, hf_child;
    proto_item *ti, *di;
    proto_tree *t;
    uint32_t v, sf;

    if (r->kind == NVME_RL_PORT) {
        hf_item = hf_nvme_lp_rl_port; hf_child = hf_nvme_lp_rl_ctrl_off; child_kind = NVME_RL_CTRL;
    } else if (r->kind == NVME_RL_CTRL) {
        hf_item = hf_nvme_lp_rl_ctrl; hf_child = hf_nvme_lp_rl_nsma_off; child_kind = NVME_RL_NSMA;
    } else {
        hf_item = hf_nvme_lp_rl_nsma; hf_child = hf_nvme_lp_rl_nsma_off; child_kind = NVME_RL_NSMA;
    }
    if ((uint64_t)list > w->lpl) {
        ti = proto_tree_add_item(r->tree, hf_nvme_gen_data, tvb, at, MIN(w->len, list) - at, ENC_NA);
        expert_add_info_format(w->pinfo, ti, &ei_nvme_lp_layout,
                               "Descriptor at byte %u runs past the Log Page Length "
                               "(NVM Command Set 'Rate Limiting Log Page')", at);
        return;
    }
    if (list > w->len) {
        w->complete = false;
        proto_tree_add_item(r->tree, hf_nvme_gen_data, tvb, at, w->len - at, ENC_NA);
        return;
    }
    count = r->kind == NVME_RL_PORT ? tvb_get_letohs(tvb, at + 2) + 1u : tvb_get_letohs(tvb, at + 2);
    di = proto_tree_add_item(r->tree, hf_item, tvb, at, MIN(list + count * 4, w->len) - at, ENC_NA);
    proto_item_append_text(di, " at byte %u", at);
    t = proto_item_add_subtree(di, ett_data);
    switch (r->kind) {
    case NVME_RL_PORT: /* Figure 118 */
        proto_tree_add_item(t, hf_nvme_lp_rl_portid, tvb, at, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(t, hf_nvme_lp_rl_nc, tvb, at + 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(t, hf_nvme_lp_rl_dsc_rsvd, tvb, at + 4, 3, ENC_NA);
        proto_tree_add_item_ret_uint(t, hf_nvme_lp_rl_abwsf, tvb, at + 7, 1, ENC_LITTLE_ENDIAN, &sf);
        nvme_rl_add_rlma(t, tvb, at + 8);
        nvme_rl_add_bw(t, hf_nvme_lp_rl_arbwv, tvb, at + 40, sf);
        nvme_rl_add_bw(t, hf_nvme_lp_rl_awbwv, tvb, at + 48, sf);
        proto_tree_add_item(t, hf_nvme_lp_rl_ariops, tvb, at + 56, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(t, hf_nvme_lp_rl_awiops, tvb, at + 60, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(t, hf_nvme_lp_rl_dsc_rsvd, tvb, at + 64, 448, ENC_NA);
        proto_tree_add_item(t, hf_nvme_lp_rl_dsc_vs, tvb, at + 512, 512, ENC_NA);
        break;
    case NVME_RL_CTRL: /* Figure 119 */
        proto_tree_add_item(t, hf_nvme_lp_rl_cntlid, tvb, at, 2, ENC_LITTLE_ENDIAN);
        ti = proto_tree_add_item_ret_uint(t, hf_nvme_lp_rl_nnsmad, tvb, at + 2, 2, ENC_LITTLE_ENDIAN, &v);
        if (!v)
            expert_add_info_format(w->pinfo, ti, &ei_nvme_lp_layout,
                                   "NNSMAD shall be non-zero (NVM Command Set 'Rate Limiting Controller Descriptor')");
        proto_tree_add_item(t, hf_nvme_lp_rl_dsc_rsvd, tvb, at + 4, 4, ENC_NA);
        nvme_rl_add_rlma(t, tvb, at + 8);
        proto_tree_add_item(t, hf_nvme_lp_rl_dsc_rsvd, tvb, at + 40, 24, ENC_NA);
        proto_tree_add_item(t, hf_nvme_lp_rl_dsc_vs, tvb, at + 64, 256, ENC_NA);
        break;
    default: /* Figure 120 */
        proto_tree_add_item_ret_uint(t, hf_nvme_lp_rl_sc, tvb, at, 1, ENC_LITTLE_ENDIAN, &v);
        proto_tree_add_item(t, hf_nvme_lp_rl_dsc_rsvd, tvb, at + 1, 1, ENC_NA);
        ti = proto_tree_add_item(t, hf_nvme_lp_rl_nnsmad, tvb, at + 2, 2, ENC_LITTLE_ENDIAN);
        if (!v && count)
            expert_add_info_format(w->pinfo, ti, &ei_nvme_lp_layout,
                                   "NNSMAD shall be 0h for the NVM subsystem scope (NVM Command Set 'Non-Volatile Storage Medium Access Descriptor')");
        proto_tree_add_item(t, hf_nvme_lp_rl_si, tvb, at + 4, 4, ENC_LITTLE_ENDIAN);
        nvme_rl_add_rlma(t, tvb, at + 8);
        proto_tree_add_item(t, hf_nvme_lp_rl_dsc_rsvd, tvb, at + 40, 24, ENC_NA);
        break;
    }
    if ((uint64_t)list + count * 4 > w->lpl)
        expert_add_info_format(w->pinfo, di, &ei_nvme_lp_layout,
                               "Descriptor list at byte %u runs past the Log Page Length "
                               "(NVM Command Set 'Rate Limiting Log Page')", list);
    for (i = 0; i < count; i++) {
        if (list + i * 4 + 4 > w->len) {
            w->complete = false;
            break;
        }
        /* Descriptors may start anywhere, so their lists can overlap: read
         * each dword as an offset once, which bounds the walk by the length
         * of the transfer. */
        if (w->listed[(list + i * 4) / 4]) {
            expert_add_info_format(w->pinfo, di, &ei_nvme_lp_layout,
                                   "Descriptor list at byte %u overlaps one already read "
                                   "(NVM Command Set 'Rate Limiting Log Page')", list);
            break;
        }
        w->listed[(list + i * 4) / 4] = 1;
        nvme_rl_add_ref(w, t, hf_child, list + i * 4, child_kind);
    }
    w->end = MAX(w->end, list + i * 4);
}

static void dissect_nvme_get_logpage_rate_limiting_resp(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo,
                                                        unsigned off, unsigned len)
{
    static const nvme_window_field hdr[] = {
        NVME_WF(0, 2, hf_nvme_lp_rl_rsvd0, ENC_NA),
        NVME_WF(2, 2, hf_nvme_lp_rl_np, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 4, hf_nvme_lp_rl_lpl, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 4, hf_nvme_lp_rl_gc, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 2, hf_nvme_lp_rl_nst, ENC_LITTLE_ENDIAN),
        NVME_WF(14, 2, hf_nvme_lp_rl_rsvd1, ENC_NA),
    };
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    nvme_rl_walk w;
    unsigned np, nst, i, rel, n;

    nvme_add_window_fields(tvb, grp, off, len, hdr, array_length(hdr));
    /* The offsets are from the start of the log page. */
    if (off || len < 16)
        return;
    np = tvb_get_letohs(tvb, 2) + 1u;
    nst = tvb_get_letohs(tvb, 12) + 1u;
    w.tvb = tvb;
    w.pinfo = pinfo;
    w.len = len;
    w.rld = 16 + np * 4;
    w.lpl = (uint64_t)tvb_get_letohl(tvb, 4) * 4;
    w.queue = wmem_array_new(pinfo->pool, sizeof(nvme_rl_ref));
    w.seen = (uint8_t *)wmem_alloc0(pinfo->pool, len / 4 + 1);
    w.listed = (uint8_t *)wmem_alloc0(pinfo->pool, len / 4 + 1);
    w.end = w.rld;
    w.complete = true;
    if (w.lpl < w.rld) {
        expert_add_info_format(pinfo, ti, &ei_nvme_lp_layout,
                               "LPL %" PRIu64 " bytes is shorter than the header and %u-entry port list "
                               "(NVM Command Set 'Rate Limiting Log Page')", w.lpl, np);
        return;
    }
    for (i = 0; i < np; i++) {
        if (16 + i * 4 + 4 > len) {
            w.complete = false;
            break;
        }
        nvme_rl_add_ref(&w, grp, hf_nvme_lp_rl_port_off, 16 + i * 4, NVME_RL_PORT);
    }
    /* The queue grows while it is walked; copy each entry out first. */
    for (i = 0; i < wmem_array_get_count(w.queue); i++) {
        nvme_rl_ref r = *(nvme_rl_ref *)wmem_array_index(w.queue, i);
        nvme_rl_add_desc(&w, &r);
    }
    /* The Supported Target list follows the Rate Limiting Data, so it is
     * located only when every descriptor was in the transfer. */
    if (!w.complete)
        return;
    if ((uint64_t)w.end + nst > w.lpl) {
        expert_add_info_format(pinfo, ti, &ei_nvme_lp_layout,
                               "The %u-entry Supported Target list at byte %u runs past the "
                               "Log Page Length (NVM Command Set 'Rate Limiting Log Page')", nst, w.end);
        return;
    }
    for (i = 0; i < nst && w.end + i < len; i++)
        proto_tree_add_item(grp, hf_nvme_lp_rl_tgt, tvb, w.end + i, 1, ENC_LITTLE_ENDIAN);
    rel = w.end + nst;
    n = (unsigned)MIN(w.lpl, (uint64_t)len);
    if (n > rel)
        proto_tree_add_item(grp, hf_nvme_lp_rl_pad, tvb, rel, n - rel, ENC_NA);
}

/* Sanitize Namespace Status List (LID 7Fh), Base 2.3 Figure 300. */
static void dissect_nvme_get_logpage_san_ns_list_resp(proto_item *ti, tvbuff_t *tvb, unsigned off, unsigned len)
{
    static const nvme_window_field hdr[] = {
        NVME_WF(0, 8, hf_nvme_lp_snsl_genctr, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 8, hf_nvme_lp_snsl_numnsid, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field e[] = {
        NVME_WF(0, 4, hf_nvme_lp_snsl_nsid, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_list l = { 16, 4, (UINT_MAX - 16) / 4, 0, "Entry", e, array_length(e) };
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    unsigned count = NVME_LIST_COUNT_UNKNOWN;

    nvme_add_window_fields(tvb, grp, off, len, hdr, array_length(hdr));
    if (!off && len >= 16) {
        uint64_t numnsid = tvb_get_letoh64(tvb, 8);
        count = numnsid >= l.max ? l.max : (unsigned)numnsid;
    }
    nvme_add_window_list(tvb, grp, off, len, &l, count, true, false);
}

/* Capacity Adjustment Factor (CAF/CADJF), Base 2.3 Figures 260 and 263. */
static void add_nvme_caf(char *result, uint32_t val)
{
    if (val == 0)
        snprintf(result, ITEM_LABEL_LENGTH, "Not reported (0)");
    else if (val == 0xffff)
        snprintf(result, ITEM_LABEL_LENGTH, "65535 or more (0xffff)");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u", val);
}

/* Channel Identifier (CHID), Base 2.3 Figure 264. */
static void add_nvme_chid(char *result, uint32_t val)
{
    if (val == 0xffff)
        snprintf(result, ITEM_LABEL_LENGTH, "Not specified (0xffff)");
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u", val);
}

/* Media Unit Status (LID 10h), Base 2.3 Figures 259-260.  The descriptors
 * vary in length, so they are walked only from a window holding the first. */
static void dissect_nvme_get_logpage_mus_resp(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo,
                                              unsigned off, unsigned len)
{
    static const nvme_window_field hdr[] = {
        NVME_WF(0, 2, hf_nvme_lp_mus_nmu, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_lp_mus_cchans, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 2, hf_nvme_lp_mus_selc, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 10, hf_nvme_lp_mus_rsvd0, ENC_NA),
    };
    static const nvme_window_field desc[] = {
        NVME_WF(0, 2, hf_nvme_lp_mus_muid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_lp_mus_did, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 2, hf_nvme_lp_mus_endgid, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 2, hf_nvme_lp_mus_nvmsetid, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 2, hf_nvme_lp_mus_caf, ENC_LITTLE_ENDIAN),
        NVME_WF(10, 1, hf_nvme_lp_mus_avsp, ENC_LITTLE_ENDIAN),
        NVME_WF(11, 1, hf_nvme_lp_mus_pused, ENC_LITTLE_ENDIAN),
        NVME_WF(12, 1, hf_nvme_lp_mus_mucs, ENC_LITTLE_ENDIAN),
        NVME_WF(13, 1, hf_nvme_lp_mus_cio, ENC_LITTLE_ENDIAN),
    };
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    unsigned count = UINT_MAX;

    nvme_add_window_fields(tvb, grp, off, len, hdr, array_length(hdr));
    if (off > 16) {
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    if (!off && len >= 2)
        count = tvb_get_letohs(tvb, 0);
    for (unsigned i = 0, pos = 16 - off; i < count && pos < len; i++) {
        unsigned avail = len - pos, mucs, cio, size;
        proto_item *di;
        proto_tree *dt;

        if (count == UINT_MAX && nvme_tvb_is_zero(tvb, pos, avail))
            break;
        dt = proto_tree_add_subtree_format(grp, tvb, pos, avail, ett_data, &di,
                                           "Media Unit Status Descriptor %u", i);
        if (!nvme_add_window_fields_at(tvb, dt, pos, 0, avail, desc, array_length(desc)))
            break;
        mucs = tvb_get_uint8(tvb, pos + 12);
        cio = tvb_get_uint8(tvb, pos + 13);
        if (!cio || cio % 16) {
            expert_add_info_format(pinfo, di, &ei_nvme_lp_layout,
                                   "CIO %u is not a non-zero multiple of 16 (NVMe Base 'Media Unit Status Descriptor')", cio);
            break;
        }
        size = cio + 2 * mucs;
        proto_item_set_len(di, MIN(size, avail));
        if (MIN(cio, avail) > 14)
            proto_tree_add_item(dt, hf_nvme_lp_mus_rsvd1, tvb, pos + 14, MIN(cio, avail) - 14, ENC_NA);
        for (unsigned c = 0; c < mucs && cio + 2 * c + 2 <= avail; c++)
            proto_tree_add_item(dt, hf_nvme_lp_mus_chid, tvb, pos + cio + 2 * c, 2, ENC_LITTLE_ENDIAN);
        if (size > avail)
            break;
        pos += size;
    }
}

/* Supported Capacity Configuration List (LID 11h), Base 2.3 Figures 261-265:
 * Capacity Configuration > Endurance Group > Channel > Media Unit
 * descriptors, each of variable length.  Every walk returns the bytes its
 * descriptor takes, or 0 when the window ends inside it. */
static unsigned
dissect_nvme_scc_chan(tvbuff_t *tvb, proto_tree *tree, unsigned pos, unsigned avail, unsigned idx)
{
    static const nvme_window_field chf[] = {
        NVME_WF(0, 2, hf_nvme_lp_scc_chid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_lp_scc_chmus, ENC_LITTLE_ENDIAN),
    };
    static const nvme_window_field muf[] = {
        NVME_WF(0, 2, hf_nvme_lp_scc_muid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 4, hf_nvme_lp_scc_rsvd4, ENC_NA),
        NVME_WF(6, 2, hf_nvme_lp_scc_mudl, ENC_LITTLE_ENDIAN),
    };
    proto_item *ci;
    proto_tree *ct = proto_tree_add_subtree_format(tree, tvb, pos, avail, ett_data, &ci,
                                                   "Channel %u Configuration Descriptor", idx);
    unsigned used = 4, chmus;

    if (!nvme_add_window_fields_at(tvb, ct, pos, 0, avail, chf, array_length(chf)))
        return 0;
    chmus = tvb_get_letohs(tvb, pos + 2);
    for (unsigned m = 0; m < chmus; m++) {
        unsigned left, mudl;
        proto_item *mi;

        /* The window ends where the previous descriptor did. */
        if (used >= avail)
            return 0;
        left = avail - used;
        proto_tree *mt = proto_tree_add_subtree_format(ct, tvb, pos + used, left, ett_data, &mi,
                                                       "Media Unit %u Configuration Descriptor", m);
        if (!nvme_add_window_fields_at(tvb, mt, pos + used, 0, left, muf, array_length(muf)))
            return 0;
        mudl = tvb_get_letohs(tvb, pos + used + 6);
        if (mudl)
            proto_tree_add_item(mt, hf_nvme_lp_scc_mudi, tvb, pos + used + 8, MIN(mudl, left - 8), ENC_NA);
        if (8 + mudl > left)
            return 0;
        proto_item_set_len(mi, 8 + mudl);
        used += 8 + mudl;
    }
    proto_item_set_len(ci, used);
    return used;
}

static unsigned
dissect_nvme_scc_egroup(tvbuff_t *tvb, proto_tree *tree, unsigned pos, unsigned avail, unsigned idx)
{
    static const nvme_window_field egf[] = {
        NVME_WF(0, 2, hf_nvme_lp_scc_endgid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_lp_scc_cadjf, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 12, hf_nvme_lp_scc_rsvd2, ENC_NA),
        NVME_WFP(16, 16, hf_nvme_lp_scc_tegcap, ENC_NA, post_add_bytes_from_16bytes),
        NVME_WFP(32, 16, hf_nvme_lp_scc_segcap, ENC_NA, post_add_bytes_from_16bytes),
        NVME_WFP(48, 16, hf_nvme_lp_scc_ee, ENC_NA, post_add_egroup_data_units),
        NVME_WF(64, 16, hf_nvme_lp_scc_rsvd3, ENC_NA),
        NVME_WF(80, 2, hf_nvme_lp_scc_egsets, ENC_LITTLE_ENDIAN),
    };
    proto_item *ei;
    proto_tree *et = proto_tree_add_subtree_format(tree, tvb, pos, avail, ett_data, &ei,
                                                   "Endurance Group Configuration %u Descriptor", idx);
    unsigned used, egsets;
    uint16_t egchans;

    if (!nvme_add_window_fields_at(tvb, et, pos, 0, avail, egf, array_length(egf)))
        return 0;
    egsets = tvb_get_letohs(tvb, pos + 80);
    used = 82;
    for (unsigned n = 0; n < egsets; n++, used += 2) {
        if (used + 2 > avail)
            return 0;
        proto_tree_add_item(et, hf_nvme_lp_scc_nvmsetid, tvb, pos + used, 2, ENC_LITTLE_ENDIAN);
    }
    if (used + 2 > avail)
        return 0;
    proto_tree_add_item_ret_uint16(et, hf_nvme_lp_scc_egchans, tvb, pos + used, 2,
                                   ENC_LITTLE_ENDIAN, &egchans);
    used += 2;
    for (unsigned c = 0; c < egchans; c++) {
        unsigned n = used < avail ? dissect_nvme_scc_chan(tvb, et, pos + used, avail - used, c) : 0;
        if (!n)
            return 0;
        used += n;
    }
    proto_item_set_len(ei, used);
    return used;
}

static void dissect_nvme_get_logpage_scc_resp(proto_item *ti, tvbuff_t *tvb,
                                              unsigned off, unsigned len)
{
    static const nvme_window_field hdr[] = {
        NVME_WF(0, 1, hf_nvme_lp_scc_sccn, ENC_LITTLE_ENDIAN),
        NVME_WF(1, 15, hf_nvme_lp_scc_rsvd0, ENC_NA),
    };
    static const nvme_window_field ccf[] = {
        NVME_WF(0, 2, hf_nvme_lp_scc_ccid, ENC_LITTLE_ENDIAN),
        NVME_WF(2, 2, hf_nvme_lp_scc_did, ENC_LITTLE_ENDIAN),
        NVME_WF(4, 2, hf_nvme_lp_scc_egcn, ENC_LITTLE_ENDIAN),
        NVME_WF(6, 26, hf_nvme_lp_scc_rsvd1, ENC_NA),
    };
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    unsigned count = UINT_MAX, nz_end = 0;

    nvme_add_window_fields(tvb, grp, off, len, hdr, array_length(hdr));
    if (off > 16) {
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }
    if (!off && len >= 1)
        count = tvb_get_uint8(tvb, 0);
    else if (len > 16 - off)
        /* Unknown count: trailing zeros end the list. Find them once, not
         * per descriptor, so the work stays linear in the window. */
        nz_end = nvme_tvb_nonzero_end(tvb, 16 - off, len);
    for (unsigned i = 0, pos = 16 - off; i < count && pos < len; i++) {
        unsigned avail = len - pos, used = 32, egcn;
        proto_item *ci;
        proto_tree *ct;

        if (count == UINT_MAX && pos >= nz_end)
            break;
        ct = proto_tree_add_subtree_format(grp, tvb, pos, avail, ett_data, &ci,
                                           "Capacity Configuration %u Descriptor", i);
        if (!nvme_add_window_fields_at(tvb, ct, pos, 0, avail, ccf, array_length(ccf)))
            return;
        egcn = tvb_get_letohs(tvb, pos + 4);
        for (unsigned e = 0; e < egcn; e++) {
            unsigned n = used < avail ? dissect_nvme_scc_egroup(tvb, ct, pos + used, avail - used, e) : 0;
            if (!n)
                return;
            used += n;
        }
        proto_item_set_len(ci, used);
        pos += used;
    }
}

/* Dispersed Namespace Participating NVM Subsystems (LID 17h), Base 2.3
 * Figure 275. */
static void dissect_nvme_get_logpage_dnps_resp(proto_item *ti, tvbuff_t *tvb, unsigned off, unsigned len)
{
    static const nvme_window_field hdr[] = {
        NVME_WF(0, 8, hf_nvme_lp_dnps_genctr, ENC_LITTLE_ENDIAN),
        NVME_WF(8, 8, hf_nvme_lp_dnps_numpsub, ENC_LITTLE_ENDIAN),
        NVME_WF(16, 240, hf_nvme_lp_dnps_rsvd, ENC_NA),
    };
    static const nvme_window_field e[] = {
        NVME_WF(0, 256, hf_nvme_lp_dnps_nqn, ENC_UTF_8),
    };
    static const nvme_window_list l = { 256, 256, (UINT_MAX - 256) / 256, 0,
                                        "Participating NVM Subsystem Entry", e, array_length(e) };
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    unsigned count = NVME_LIST_COUNT_UNKNOWN;

    nvme_add_window_fields(tvb, grp, off, len, hdr, array_length(hdr));
    if (!off && len >= 16) {
        uint64_t n = tvb_get_letoh64(tvb, 8);
        count = n >= l.max ? l.max : (unsigned)n;
    }
    nvme_add_window_list(tvb, grp, off, len, &l, count, true, false);
}

static void dissect_nvme_get_logpage_resp(tvbuff_t *cmd_tvb, packet_info *pinfo, proto_tree *cmd_tree, struct nvme_cmd_ctx *cmd_ctx, unsigned off, unsigned len)
{
    /* len is already bounded by the reported length; a sliced capture throws. */
    proto_item *ti = proto_tree_add_bytes_format_value(cmd_tree, hf_nvme_gen_data, cmd_tvb, 0,
                            len, NULL,
                            "NVMe Get Log Page (%s)", get_logpage_name_csi(cmd_ctx->cmd_ctx.get_logpage.lid, cmd_ctx->cmd_ctx.get_logpage.csi));
    /* Apply LPO, then the transport window, saturating the 64-bit sum.
     * Decoders take only this offset; Telemetry takes the 64-bit sum. */
    uint64_t lpo = cmd_ctx->cmd_ctx.get_logpage.off;
    uint64_t combined_off64 = (lpo > UINT64_MAX - off) ? UINT64_MAX : lpo + off;
    unsigned combined_off = (combined_off64 > UINT32_MAX) ? UINT32_MAX : (unsigned)combined_off64;

    nvme_logpage_walk_sync(pinfo, cmd_ctx);

    if (cmd_ctx->cmd_ctx.get_logpage.ot) {
        if (!dissect_nvme_index_log(cmd_tvb, ti, cmd_ctx, off, len))
            nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return;
    }

    /* Start the command's first window with clean walk state. */
    if (!off)
        nvme_logpage_walk_reset(cmd_ctx);

    switch(cmd_ctx->cmd_ctx.get_logpage.lid) {
        case NVME_LID_SUPPORTED_LOG_PAGES:
            dissect_nvme_get_logpage_supported_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
        case NVME_LID_DISCOVERY:
            dissect_nvme_get_logpage_ify_resp(ti, cmd_tvb, cmd_ctx, combined_off, len); break;
        case NVME_LID_ERROR_INFO:
            dissect_nvme_get_logpage_err_inf_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_SMART:
            dissect_nvme_get_logpage_smart_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_PERSISTENT_EVENT:
            /* ACT 11b returns the header from offset 0 whatever the LPO
             * (Base 2.3 Figure 229). */
            dissect_nvme_get_logpage_pel_resp(ti, cmd_tvb, pinfo, cmd_ctx,
                (cmd_ctx->cmd_ctx.get_logpage.lsp & 0x3) == 3 ? off : combined_off64, len);
            break;
        case NVME_LID_FW_SLOT:
            dissect_nvme_get_logpage_fw_slot_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_CHANGED_NSLIST:
        case NVME_LID_CHANGED_ALLOC_NSLIST:
            dissect_nvme_get_logpage_changed_nslist_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
        case NVME_LID_CMD_SUP_AND_EFF:
            dissect_nvme_get_logpage_cmd_sup_and_eff_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
        case NVME_LID_DEVICE_SELF_TEST:
            dissect_nvme_get_logpage_selftest_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_TELEMETRY_HOST:
        case NVME_LID_TELEMETRY_CTRL:
            dissect_nvme_get_logpage_telemetry_resp(ti, cmd_tvb, cmd_ctx, combined_off64, len); break;
        case NVME_LID_ENDURANCE_GROUP:
            dissect_nvme_get_logpage_egroup_resp(ti, cmd_tvb, cmd_ctx, combined_off, len); break;
        case NVME_LID_PRED_LAT_NVM_SET:
            dissect_nvme_get_logpage_pred_lat_resp(ti, cmd_tvb, cmd_ctx, combined_off, len); break;
        case NVME_LID_PRED_LAT_EVENT_AGG:
            dissect_nvme_get_logpage_event_aggreg_resp(ti, cmd_tvb, pinfo, combined_off, len,
                    hf_nvme_get_logpage_pred_lat_aggreg_ne,
                    hf_nvme_get_logpage_pred_lat_aggreg_nset,
                    hf_nvme_get_logpage_pred_lat_aggreg_fill); break;
        case NVME_LID_ANA:
            dissect_nvme_get_logpage_ana_resp(ti, cmd_tvb, cmd_ctx, combined_off, len); break;
        case NVME_LID_LBA_STATUS:
            dissect_nvme_get_logpage_lba_status_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_ENDURANCE_GROUP_EVENT_AGG:
            dissect_nvme_get_logpage_event_aggreg_resp(ti, cmd_tvb, pinfo, combined_off, len,
                    hf_nvme_get_logpage_egroup_aggreg_ne,
                    hf_nvme_get_logpage_egroup_aggreg_eg,
                    hf_nvme_get_logpage_egroup_aggreg_fill); break;
        case NVME_LID_RESERVATION_NOTIFICATION:
            dissect_nvme_get_logpage_reserv_notif_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_SANITIZE_STATUS:
            dissect_nvme_get_logpage_sanitize_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_FEATURE_ID_SUP_AND_EFF:
            dissect_nvme_get_logpage_sup_and_eff_resp(ti, cmd_tvb, pinfo, combined_off, len,
                hf_nvme_get_logpage_feat_sup_and_eff_fidx,
                ASPEC(hf_nvme_get_logpage_feat_sup_and_eff_fids), "FID"); break;
        case NVME_LID_NVME_MI_CMD_SUP_AND_EFF:
            dissect_nvme_get_logpage_sup_and_eff_resp(ti, cmd_tvb, pinfo, combined_off, len,
                hf_nvme_get_logpage_mi_cmd_sup_and_eff_cs,
                ASPEC(hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds), "MI Command Opcode"); break;
        case NVME_LID_CMD_FEAT_LOCKDOWN:
            if (cmd_ctx->cmd_ctx.get_logpage.lsp & 0x40)
                dissect_nvme_get_logpage_lockdown_enh_resp(ti, cmd_tvb, pinfo, combined_off, len);
            else
                dissect_nvme_get_logpage_cmd_feat_lockdown_resp(ti, cmd_tvb, combined_off, len);
            break;
        case NVME_LID_BOOT_PARTITION:
            dissect_nvme_get_logpage_boot_part_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_ROTATIONAL_MEDIA:
            dissect_nvme_get_logpage_rotational_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_MGMT_ADDR_LIST:
            dissect_nvme_get_logpage_mgmt_addr_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_DEVICE_PERSONALITIES:
            dissect_nvme_get_logpage_dev_pers_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
        case NVME_LID_MFR_DEFAULT_CONFIG:
            dissect_nvme_get_logpage_mdcs_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_POWER_MEASUREMENT:
            dissect_nvme_get_logpage_power_meas_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
        case NVME_LID_VOLTAGE_MEASUREMENT:
            dissect_nvme_get_logpage_voltage_meas_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
        case NVME_LID_RATE_LIMITING:
            dissect_nvme_get_logpage_rate_limiting_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
        case NVME_LID_SANITIZE_NS_STATUS_LIST:
            dissect_nvme_get_logpage_san_ns_list_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_MEDIA_UNIT_STATUS:
            dissect_nvme_get_logpage_mus_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
        case NVME_LID_SUP_CAP_CONFIG_LIST:
            dissect_nvme_get_logpage_scc_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_DISPERSED_NS:
            dissect_nvme_get_logpage_dnps_resp(ti, cmd_tvb, combined_off, len); break;
        case NVME_LID_REACHABILITY_GROUPS:
        case NVME_LID_REACHABILITY_ASSOC:
            if (!dissect_nvme_reach_log(cmd_tvb, proto_item_add_subtree(ti, ett_data),
                                        cmd_ctx->cmd_ctx.get_logpage.lid, combined_off, len, true, 0))
                nvme_add_window_note(ti, NVME_WINDOW_RAW);
            break;
        case NVME_LID_PHY_RX_EOM:
            dissect_nvme_get_logpage_eom_resp(ti, cmd_tvb, pinfo, combined_off, len); break;
    }
}

/* Returns CDW10 bits 15:08: LSP in bits 6:0, RAE in bit 7. */
static uint8_t
dissect_nvme_log_parameters(tvbuff_t *tvb, proto_tree *dw10, proto_item *lsi_item, uint8_t lid)
{
    int first = -1, second = -1, third = -1;
    uint8_t used = 0;
    uint8_t lsp;
    const char *lsi = NULL;
    switch (lid) {
    case NVME_LID_TELEMETRY_HOST:
        first = hf_nvme_lsp_cthid; second = hf_nvme_lsp_mcda; used = 0x0f; break;
    case NVME_LID_ANA:
    case NVME_LID_REACHABILITY_GROUPS:
        first = hf_nvme_lsp_rgo; used = 1; break;
    case NVME_LID_PERSISTENT_EVENT:
        first = hf_nvme_lsp_pel_act; used = 3; break;
    case NVME_LID_CMD_FEAT_LOCKDOWN:
        first = hf_nvme_lsp_scope; second = hf_nvme_lsp_contents;
        third = hf_nvme_lsp_elpf; used = 0x7f; break;
    case NVME_LID_BOOT_PARTITION:
        first = hf_nvme_lsp_bpid; used = 1; break;
    case NVME_LID_PHY_RX_EOM:
        proto_tree_add_item(dw10, hf_nvme_get_logpage_dword10_lsp_act, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(dw10, hf_nvme_get_logpage_dword10_lsp_mqual, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        used = 0x0f; break;
    case NVME_LID_REACHABILITY_ASSOC:
        first = hf_nvme_lsp_rao; used = 1; break;
    case NVME_LID_CROSS_CTRL_RESET:
        first = hf_nvme_lsp_rmc; used = 1; break;
    case NVME_LID_FDP_EVENTS:
        first = hf_nvme_lsp_events; used = 1; break;
    case NVME_LID_DISCOVERY:
        first = hf_nvme_lsp_extdlpe; second = hf_nvme_lsp_pleo;
        third = hf_nvme_lsp_allsube; used = 7; break;
    case NVME_LID_HOST_DISCOVERY:
        first = hf_nvme_lsp_allhoste; used = 1; break;
    case NVME_LID_SANITIZE_NS_STATUS_LIST:
        first = hf_nvme_lsp_nlt; used = 1; break;
    }
    if (first != -1)
        proto_tree_add_item(dw10, first, tvb, 41, 1, ENC_LITTLE_ENDIAN);
    if (second != -1)
        proto_tree_add_item(dw10, second, tvb, 41, 1, ENC_LITTLE_ENDIAN);
    if (third != -1)
        proto_tree_add_item(dw10, third, tvb, 41, 1, ENC_LITTLE_ENDIAN);
    lsp = tvb_get_uint8(tvb, 41);
    proto_tree_add_uint(dw10, hf_nvme_lsp_reserved, tvb, 41, 1,
                        lsp & (0x7f & ~used));

    /* Base 2.3 Figures 202, 221, 223, 258 and the per-LID definitions. */
    switch (lid) {
    case NVME_LID_ENDURANCE_GROUP:
    case NVME_LID_ROTATIONAL_MEDIA:
    case NVME_LID_FDP_CONFIGS:
    case NVME_LID_RECLAIM_UNIT_HANDLE_USAGE:
    case NVME_LID_FDP_STATS:
    case NVME_LID_FDP_EVENTS: lsi = "Endurance Group Identifier (ENDGID)"; break;
    case NVME_LID_PRED_LAT_NVM_SET: lsi = "NVM Set Identifier (NVMSETID)"; break;
    case NVME_LID_MEDIA_UNIT_STATUS:
    case NVME_LID_SUP_CAP_CONFIG_LIST: lsi = "Domain Identifier (DID)"; break;
    case NVME_LID_PHY_RX_EOM: lsi = "Target Controller (TC)"; break;
    case NVME_LID_CMD_FEAT_LOCKDOWN:
        lsi = (lsp & 0x40) ? "Controller Identifier (CNTLID)" : "Reserved";
        break;
    }
    if (lsi)
        proto_item_append_text(lsi_item, ", %s", lsi);
    return lsp;
}

static void dissect_nvme_get_logpage_cmd(tvbuff_t *cmd_tvb, packet_info *pinfo,
                                      proto_tree *cmd_tree,
                                      struct nvme_cmd_ctx *cmd_ctx)
{
    proto_item *ti, *lpo_ti;
    proto_tree *dw10;
    uint64_t lpo_raw;
    unsigned val;
    uint8_t lsp;

    cmd_ctx->cmd_ctx.get_logpage.lid = tvb_get_uint8(cmd_tvb, 40);
    cmd_ctx->cmd_ctx.get_logpage.lsi = tvb_get_uint16(cmd_tvb, 46, ENC_LITTLE_ENDIAN);
    cmd_ctx->cmd_ctx.get_logpage.csi = tvb_get_uint8(cmd_tvb, 59);

    dw10 = add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_get_logpage_dword10));
    {
        const char *cs_name = get_logpage_cs_name(cmd_ctx->cmd_ctx.get_logpage.lid,
                                                  cmd_ctx->cmd_ctx.get_logpage.csi);
        if (cs_name) {
            ti = proto_tree_add_string(dw10, hf_nvme_get_logpage_cs_name, cmd_tvb, 40, 1, cs_name);
            proto_item_set_generated(ti);
        }
    }
    ti = proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_get_logpage_numd, cmd_tvb, 42, 4, ENC_LITTLE_ENDIAN, &val);
    proto_item_append_text(ti, " (%"PRIu64" bytes)", ((uint64_t)val + 1) * 4);
    cmd_ctx->cmd_ctx.get_logpage.numd = val;

    proto_tree *dw11 = proto_item_add_subtree(
        proto_tree_add_item(cmd_tree, hf_nvme_get_logpage_dword11[0], cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN),
        ett_data);
    proto_tree_add_item(dw11, hf_nvme_get_logpage_dword11[1], cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    ti = proto_tree_add_item(dw11, hf_nvme_get_logpage_dword11[2], cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    lsp = dissect_nvme_log_parameters(cmd_tvb, dw10, ti, cmd_ctx->cmd_ctx.get_logpage.lid);
    cmd_ctx->cmd_ctx.get_logpage.extdlpe =
        cmd_ctx->cmd_ctx.get_logpage.lid == NVME_LID_DISCOVERY && (lsp & 0x01);
    cmd_ctx->cmd_ctx.get_logpage.lsp = lsp & 0x7f;

    /* CDW12/13 are LPOL/LPOU, one 64-bit offset. */
    lpo_ti = proto_tree_add_item_ret_uint64(cmd_tree, hf_nvme_get_logpage_lpo, cmd_tvb, 48, 8, ENC_LITTLE_ENDIAN, &cmd_ctx->cmd_ctx.get_logpage.off);

    /* Dword-align a byte offset (NVMe Base 2.3 Figure 203). */
    lpo_raw = cmd_ctx->cmd_ctx.get_logpage.off;
    cmd_ctx->cmd_ctx.get_logpage.off &= (~((uint64_t)3));
    cmd_ctx->cmd_ctx.get_logpage.ot =
        (tvb_get_uint32(cmd_tvb, 56, ENC_LITTLE_ENDIAN) & 0x00800000) != 0;
    if (cmd_ctx->cmd_ctx.get_logpage.ot) {
        cmd_ctx->cmd_ctx.get_logpage.off = lpo_raw;
    } else if (lpo_raw & 3) {
        /* NVMe Base 2.3 Figure 203: a byte offset shall be dword aligned. */
        expert_add_info_format(pinfo, lpo_ti, &ei_nvme_logpage_lpo_misaligned,
                               "Log Page Offset %" PRIu64 " is not dword aligned"
                               " (bits 1:0 shall be cleared to 00b): the controller"
                               " may abort with Invalid Field in Command or operate"
                               " as if the offset were %" PRIu64 ", which is how a"
                               " response is decoded here",
                               lpo_raw, cmd_ctx->cmd_ctx.get_logpage.off);
    }

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
    F_IO_CMD_SET_PROFILE = 0x19,
    F_SPINUP_CONTROL = 0x1A,
    F_POWER_LOSS_SIG_CONF = 0x1B,
    F_PERF_CHARACTERISTICS = 0x1C,
    F_FDP = 0x1D,
    F_FDP_EVENTS = 0x1E,
    F_NS_ADMIN_LABEL = 0x1F,
    F_KV_CONFIG = 0x20,
    F_CTRL_DATA_QUEUE = 0x21,
    F_CONF_DEV_PERSONALITY = 0x22,
    F_POWER_LIMIT = 0x23,
    F_POWER_THRESHOLD = 0x24,
    F_POWER_MEASUREMENT = 0x25,
    F_VOLTAGE_THRESHOLD = 0x26,
    F_VOLTAGE_MEASUREMENT = 0x27,
    F_RATE_LIMITING = 0x28,
    F_EMB_MGMT_CTRL_ADDR = 0x78,
    F_HOST_MGMT_AGENT_ADDR = 0x79,
    F_ENH_CTRL_METADATA = 0x7D,
    F_CTRL_METADATA = 0x7E,
    F_NS_METADATA = 0x7F,
    F_SW_PR_MARKER = 0x80,
    F_HOST_ID = 0x81,
    F_RSRV_NOT_MASK = 0x82,
    F_RSRV_PRST = 0x83,
    F_NS_WRITE_CONF = 0x84,
    F_BP_WRITE_PROT_CONF = 0x85,
} nvme_setf_t;

bool
nvme_data_tree_has_fields(proto_tree *tree)
{
    if (!tree)
        return false;
    for (proto_node *n = tree->first_child; n; n = n->next) {
        field_info *fi = PNODE_FINFO(n);
        if (n->first_child || !fi || fi->hfinfo->id != hf_nvme_gen_data)
            return true;
    }
    return false;
}

/* "Uses Data Buffer for Attributes" (Base 2.4 Figure 466 and NVM CS 1.3
 * Figure 92), refined by the command dwords where the transfer depends on
 * them.  Reserved, vendor specific and dword-unresolved selections are
 * unknown. */
enum nvme_feat_xfer
nvme_feature_transfer(uint8_t fid, bool get, uint8_t sel, uint32_t cdw11,
                      uint32_t cdw13, uint32_t *size)
{
    *size = 0;
    if (get && sel > 3)
        return NVME_FEAT_XFER_UNKNOWN;
    switch (fid) {
    case F_ARBITRATION:
    case F_POWER_MGMT:
    case F_TEMP_THRESHOLD:
    case F_ERROR_RECOVERY:
    case F_VOLATILE_WC:
    case F_NUM_OF_QUEUES:
    case F_IRQ_COALESCING:
    case F_IRQ_VECTOR_CONF:
    case F_WRITE_ATOM_NORM:
    case F_ASYNC_EVENT_CONF:
    case F_KA_TIMER:
    case F_HOST_CNTL_THERM_MGMT:
    case F_NO_POWER_STATE_CONF:
    case F_READ_REC_LEVEL_CONF:
    case F_PRED_LAT_MODE_WIND:
    case F_LBA_ST_INF_REP_INT:
    case F_SANITIZE_CON:
    case F_END_GROUP_EV_CONF:
    case F_IO_CMD_SET_PROFILE:
    case F_SPINUP_CONTROL:
    case F_POWER_LOSS_SIG_CONF:
    case F_FDP:
    case F_POWER_LIMIT:
    case F_POWER_THRESHOLD:
    case F_POWER_MEASUREMENT:
    case F_VOLTAGE_THRESHOLD:
    case F_SW_PR_MARKER:
    case F_RSRV_NOT_MASK:
    case F_RSRV_PRST:
    case F_NS_WRITE_CONF:
    case F_BP_WRITE_PROT_CONF:
        return NVME_FEAT_XFER_NONE;
    case F_HOST_MEM_BUF:
    case F_CTRL_DATA_QUEUE:
        if (!get)
            return NVME_FEAT_XFER_NONE; /* Figure 466 note 4 */
        break;
    default:
        break;
    }
    /* Select 011b reports capabilities in Dword 0, not a buffer
     * (Figure 201). */
    if (get && sel == 3)
        return NVME_FEAT_XFER_NONE;
    switch (fid) {
    case F_CONF_DEV_PERSONALITY: { /* Figures 512-517 */
        uint8_t perid = cdw13 & 0xff;
        if (!get && !(cdw13 & 0x200))
            return NVME_FEAT_XFER_UNKNOWN; /* CHPS 0: any data is ignored */
        if (perid == 0x00 || perid == 0x02 || perid == 0x03 || perid == 0xff)
            return NVME_FEAT_XFER_NONE;
        if (perid != 0x01)
            return NVME_FEAT_XFER_UNKNOWN;
        *size = get ? 8 : 4;
        return NVME_FEAT_XFER_DATA;
    }
    case F_VOLTAGE_MEASUREMENT: /* Figures 526, 527 */
        switch (cdw11 & 0xf) {
        case 0x1:
            *size = 4096;
            return NVME_FEAT_XFER_DATA;
        case 0x0:
        case 0x2:
            return NVME_FEAT_XFER_NONE;
        default:
            return NVME_FEAT_XFER_UNKNOWN;
        }
    case F_RATE_LIMITING: /* NVM CS 1.3 Figures 106, 107 */
        if ((cdw11 >> 16) & 0xff)
            return NVME_FEAT_XFER_UNKNOWN;
        *size = 1024;
        return NVME_FEAT_XFER_DATA;
    case F_PERF_CHARACTERISTICS: { /* NVM CS 1.3 Figures 102-105 */
        uint8_t attri = cdw11 & 0xff;
        if (attri >= 0x01 && attri <= 0xbf)
            return NVME_FEAT_XFER_UNKNOWN;
        /* RVSPA: the buffer contents are not used. */
        if (!get && attri >= 0xc1 && (cdw11 & 0x100))
            return NVME_FEAT_XFER_UNKNOWN;
        *size = 4096;
        return NVME_FEAT_XFER_DATA;
    }
    case F_HOST_ID: /* Figure 538 */
        *size = 16;
        return NVME_FEAT_XFER_DATA;
    case F_LBA_RANGE_TYPE:
    case F_HOST_MEM_BUF:
    case F_ENH_CTRL_METADATA:
    case F_CTRL_METADATA:
    case F_NS_METADATA:
        *size = 4096;
        return NVME_FEAT_XFER_DATA;
    case F_AUTO_PS_TRANSITION:
    case F_NS_ADMIN_LABEL:
        *size = 256;
        return NVME_FEAT_XFER_DATA;
    case F_TIMESTAMP:
        *size = 8;
        return NVME_FEAT_XFER_DATA;
    case F_PRED_LAT_MODE_CONF:
    case F_HOST_BEHV_SUPPORT:
    case F_CTRL_DATA_QUEUE:
    case F_EMB_MGMT_CTRL_ADDR:
    case F_HOST_MGMT_AGENT_ADDR:
        *size = 512;
        return NVME_FEAT_XFER_DATA;
    case F_FDP_EVENTS:
        return NVME_FEAT_XFER_DATA;
    default:
        return NVME_FEAT_XFER_UNKNOWN;
    }
}


static const range_string fid_table[] = {
    { 0x00, 0x00, "Reserved" },
    { F_ARBITRATION, F_ARBITRATION, "Arbitration" },
    { F_POWER_MGMT, F_POWER_MGMT, "Power Management" },
    { F_LBA_RANGE_TYPE, F_LBA_RANGE_TYPE, "LBA Range Type" },
    { F_TEMP_THRESHOLD, F_TEMP_THRESHOLD, "Temperature Threshold" },
    { F_ERROR_RECOVERY, F_ERROR_RECOVERY, "Error Recovery" },
    { F_VOLATILE_WC, F_VOLATILE_WC, "Volatile Write Cache" },
    { F_NUM_OF_QUEUES, F_NUM_OF_QUEUES, "Number of Queues" },
    { F_IRQ_COALESCING, F_IRQ_COALESCING, "Interrupt Coalescing" },
    { F_IRQ_VECTOR_CONF, F_IRQ_VECTOR_CONF, "Interrupt Vector Configuration" },
    { F_WRITE_ATOM_NORM, F_WRITE_ATOM_NORM, "Write Atomicity Normal" },
    { F_ASYNC_EVENT_CONF, F_ASYNC_EVENT_CONF, "Asynchronous Event Configuration" },
    { F_AUTO_PS_TRANSITION, F_AUTO_PS_TRANSITION, "Autonomous Power State Transition" },
    { F_HOST_MEM_BUF, F_HOST_MEM_BUF, "Host Memory Buffer" },
    { F_TIMESTAMP, F_TIMESTAMP, "Timestamp" },
    { F_KA_TIMER, F_KA_TIMER, "Keep Alive Timer" },
    { F_HOST_CNTL_THERM_MGMT, F_HOST_CNTL_THERM_MGMT, "Host Controlled Thermal Management" },
    { F_NO_POWER_STATE_CONF, F_NO_POWER_STATE_CONF, "Non-Operational Power State Config" },
    { F_READ_REC_LEVEL_CONF, F_READ_REC_LEVEL_CONF, "Read Recovery Level Config" },
    { F_PRED_LAT_MODE_CONF, F_PRED_LAT_MODE_CONF, "Predictable Latency Mode Config" },
    { F_PRED_LAT_MODE_WIND, F_PRED_LAT_MODE_WIND, "Predictable Latency Mode Window" },
    { F_LBA_ST_INF_REP_INT, F_LBA_ST_INF_REP_INT, "LBA Status Information Attributes" },
    { F_HOST_BEHV_SUPPORT, F_HOST_BEHV_SUPPORT, "Host Behavior Support" },
    { F_SANITIZE_CON, F_SANITIZE_CON, "Sanitize Config" },
    { F_END_GROUP_EV_CONF, F_END_GROUP_EV_CONF, "Endurance Group Event Configuration" },
    { F_IO_CMD_SET_PROFILE, F_IO_CMD_SET_PROFILE, "I/O Command Set Profile" },
    { F_SPINUP_CONTROL, F_SPINUP_CONTROL, "Spinup Control" },
    { F_POWER_LOSS_SIG_CONF, F_POWER_LOSS_SIG_CONF, "Power Loss Signaling Config" },
    { F_PERF_CHARACTERISTICS, F_PERF_CHARACTERISTICS, "Performance Characteristics" },
    { F_FDP, F_FDP, "Flexible Data Placement" },
    { F_FDP_EVENTS, F_FDP_EVENTS, "Flexible Data Placement Events" },
    { F_NS_ADMIN_LABEL, F_NS_ADMIN_LABEL, "Namespace Admin Label" },
    { F_KV_CONFIG, F_KV_CONFIG, "Key Value Configuration" },
    { F_CTRL_DATA_QUEUE, F_CTRL_DATA_QUEUE, "Controller Data Queue" },
    { F_CONF_DEV_PERSONALITY, F_CONF_DEV_PERSONALITY, "Configurable Device Personality" },
    { F_POWER_LIMIT, F_POWER_LIMIT, "Power Limit" },
    { F_POWER_THRESHOLD, F_POWER_THRESHOLD, "Power Threshold" },
    { F_POWER_MEASUREMENT, F_POWER_MEASUREMENT, "Power Measurement" },
    { F_VOLTAGE_THRESHOLD, F_VOLTAGE_THRESHOLD, "Voltage Threshold" },
    { F_VOLTAGE_MEASUREMENT, F_VOLTAGE_MEASUREMENT, "Voltage Measurement" },
    /* NVM Command Set 1.3 section 4.1.3.9 */
    { F_RATE_LIMITING, F_RATE_LIMITING, "Rate Limiting" },
    { 0x29, 0x77, "Reserved" },
    { F_EMB_MGMT_CTRL_ADDR, F_EMB_MGMT_CTRL_ADDR, "Embedded Management Controller Address" },
    { F_HOST_MGMT_AGENT_ADDR, F_HOST_MGMT_AGENT_ADDR, "Host Management Agent Address" },
    { 0x7a, 0x7c, "Reserved for Management Features" },
    { F_ENH_CTRL_METADATA, F_ENH_CTRL_METADATA, "Enhanced Controller Metadata" },
    { F_CTRL_METADATA, F_CTRL_METADATA, "Controller Metadata" },
    { F_NS_METADATA, F_NS_METADATA, "Namespace Metadata" },
    { F_SW_PR_MARKER, F_SW_PR_MARKER, "Software Progress Marker" },
    { F_HOST_ID, F_HOST_ID, "Host Identifier" },
    { F_RSRV_NOT_MASK, F_RSRV_NOT_MASK, "Reservation Notification Mask" },
    { F_RSRV_PRST, F_RSRV_PRST, "Reservation Persistence" },
    { F_NS_WRITE_CONF, F_NS_WRITE_CONF, "Namespace Write Protection Config" },
    { F_BP_WRITE_PROT_CONF, F_BP_WRITE_PROT_CONF, "Boot Partition Write Protection Config" },
    { 0x86, 0xbf, "Reserved" },
    { 0xC0, 0xFF, "Vendor Specific" },
    { 0, 0, NULL },
};

static const range_string feat_perf_attri_rvals[] = {
    { 0x00, 0x00, "Standard Performance Attribute" },
    { 0x01, 0xbf, "Reserved" },
    { 0xc0, 0xc0, "Performance Attribute Identifier List" },
    { 0xc1, 0xff, "Vendor Specific Performance Attribute" },
    { 0, 0, NULL },
};

static const range_string feat_perf_r4karl_rvals[] = {
    { 0x00, 0x00, "Not Reported" },
    { 0x01, 0x01, "Greater than or equal to 100 seconds" },
    { 0x02, 0x02, "Greater than or equal to 50 seconds and less than 100 seconds" },
    { 0x03, 0x03, "Greater than or equal to 10 seconds and less than 50 seconds" },
    { 0x04, 0x04, "Greater than or equal to 5 seconds and less than 10 seconds" },
    { 0x05, 0x05, "Greater than or equal to 1 second and less than 5 seconds" },
    { 0x06, 0x06, "Greater than or equal to 500 milliseconds and less than 1 second" },
    { 0x07, 0x07, "Greater than or equal to 100 milliseconds and less than 500 milliseconds" },
    { 0x08, 0x08, "Greater than or equal to 50 milliseconds and less than 100 milliseconds" },
    { 0x09, 0x09, "Greater than or equal to 10 milliseconds and less than 50 milliseconds" },
    { 0x0a, 0x0a, "Greater than or equal to 5 milliseconds and less than 10 milliseconds" },
    { 0x0b, 0x0b, "Greater than or equal to 1 millisecond and less than 5 milliseconds" },
    { 0x0c, 0x0c, "Greater than or equal to 500 microseconds and less than 1 millisecond" },
    { 0x0d, 0x0d, "Greater than or equal to 100 microseconds and less than 500 microseconds" },
    { 0x0e, 0x0e, "Greater than or equal to 50 microseconds and less than 100 microseconds" },
    { 0x0f, 0x0f, "Greater than or equal to 10 microseconds and less than 50 microseconds" },
    { 0x10, 0x10, "Greater than or equal to 5 microseconds and less than 10 microseconds" },
    { 0x11, 0x11, "Greater than or equal to 1 microsecond and less than 5 microseconds" },
    { 0x12, 0x12, "Greater than or equal to 500 nanoseconds and less than 1 microsecond" },
    { 0x13, 0x13, "Greater than or equal to 100 nanoseconds and less than 500 nanoseconds" },
    { 0x14, 0x14, "Greater than or equal to 50 nanoseconds and less than 100 nanoseconds" },
    { 0x15, 0x15, "Greater than or equal to 10 nanoseconds and less than 50 nanoseconds" },
    { 0x16, 0x16, "Greater than or equal to 5 nanoseconds and less than 10 nanoseconds" },
    { 0x17, 0x17, "Greater than or equal to 1 nanosecond and less than 5 nanoseconds" },
    { 0x18, 0xff, "Reserved" },
    { 0, 0, NULL },
};

static const range_string feat_perf_attrtyp_rvals[] = {
    { 0, 0, "Current attribute" },
    { 1, 1, "Default attribute" },
    { 2, 2, "Saved attribute" },
    { 3, 7, "Reserved" },
    { 0, 0, NULL },
};

static const range_string feat_pm_act_rvals[] = {
    { 0x0, 0x0, "Stop" },
    { 0x1, 0x1, "Start" },
    { 0x2, 0xb, "Reserved" },
    { 0xc, 0xf, "Vendor Specific" },
    { 0, 0, NULL },
};

static const range_string nvme_sanitize_ns_sanact_rvals[] = {
    { 0x0, 0x0, "Reserved" },
    { 0x1, 0x1, "Exit Failure Mode" },
    { 0x2, 0x3, "Reserved" },
    { 0x4, 0x4, "Start a Crypto Erase namespace sanitize operation" },
    { 0x5, 0x5, "Exit Media Verification State" },
    { 0x6, 0x7, "Reserved" },
    { 0, 0, NULL },
};

/* Base 2.4 Figure 512 */
static const range_string perid_rvals[] = {
    { 0x00, 0x00, "Manufacturing Default Personality" },
    { 0x01, 0x01, "Security Personality" },
    { 0x02, 0x02, "Lockdown Persistence Personality" },
    { 0x03, 0x03, "Revert to Subsystem Manufacturing Settings Personality" },
    { 0x04, 0xbf, "Reserved" },
    { 0xc0, 0xfe, "Vendor Specific" },
    { 0xff, 0xff, "All Personalities" },
    { 0, 0, NULL }
};

/* Forward-declared above for dissect_nvme_get_logpage_cmd_feat_lockdown_resp(),
 * which names Command and Feature Identifier List entries when the log page's
 * Scope Selected field says they are Feature Identifiers. */
static const char *get_feature_id_name(uint8_t fid)
{
    return rval_to_str_const(fid, fid_table, "Reserved");
}

/* Get Features Select (CDW10 bits 10:08, NVMe Base 2.3 5.2.11.1). */
#define NVME_GET_FEATURES_SEL_SUPPORTED_CAPS 0x3

static const value_string sel_table[] = {
    { 0, "Current" },
    { 1, "Default" },
    { 2, "Saved" },
    { 3, "Supported Capabilities" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
};

/* TMPSEL (NVMe Base 2.3 Figure 407); Fh is All Sensors only in Set Features. */
#define NVME_TMPSEL_SENSOR_ROWS \
    { 0x0, 0x0, "Composite Temperature" }, \
    { 0x1, 0x1, "Temperature Sensor 1" }, \
    { 0x2, 0x2, "Temperature Sensor 2" }, \
    { 0x3, 0x3, "Temperature Sensor 3" }, \
    { 0x4, 0x4, "Temperature Sensor 4" }, \
    { 0x5, 0x5, "Temperature Sensor 5" }, \
    { 0x6, 0x6, "Temperature Sensor 6" }, \
    { 0x7, 0x7, "Temperature Sensor 7" }, \
    { 0x8, 0x8, "Temperature Sensor 8" },

static const range_string sf_tmpsel_table[] = {
    NVME_TMPSEL_SENSOR_ROWS
    { 0x9, 0xE, "Reserved" },
    { 0xF, 0xF, "All Temperature Sensors" },
    { 0, 0, NULL },
};

static const range_string gf_tmpsel_table[] = {
    NVME_TMPSEL_SENSOR_ROWS
    { 0x9, 0xF, "Reserved" },
    { 0, 0, NULL },
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

/* Timestamp Origin (TSTMPO), NVMe Base 2.3 Figure 415 byte 06 bits 03:01. */
static const val64_string sf_tstmpo_table[] = {
    { 0x0, "Initialized to 0h by a Controller Level Reset" },
    { 0x1, "Initialized with a Timestamp value using a Set Features command" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0x4, "Reserved" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0, NULL },
};

/* Synch (SYNC), NVMe Base 2.3 Figure 415 byte 06 bit 00. */
static const true_false_string sf_tst_sync_tfs = {
    "May have stopped counting during vendor specific intervals",
    "Counted time in milliseconds continuously since initialization"
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

/* Power Loss Signaling Mode (PLSM), Power Loss Signaling Config Set Features
 * Command Dword 11 bits 1:0. */
static const value_string sf_plsm[] = {
    { 0x0, "Power Loss Signaling not enabled" },
    { 0x1, "Power Loss Signaling with Emergency Power Fail enabled" },
    { 0x2, "Power Loss Signaling with Forced Quiescence enabled" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

/* Boot Partition Write Protection State (BP0WPS/BP1WPS), Boot Partition Write
 * Protection Config Set Features Command Dword 11. */
static const value_string sf_bpwps[] = {
    { 0x0, "Change in state not requested" },
    { 0x1, "Write Unlocked" },
    { 0x2, "Write Locked" },
    { 0x3, "Write Locked Until Power Cycle" },
    { 0x4, "Write Protection controlled by RPMB" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0, NULL },
};

/* Render a 0's based field as "0x<wire value> (<count>)", in 64 bits. */
static void add_nvme_zero_based(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%" PRIu64 ")", val, (uint64_t)val + 1);
}

static void add_nvme_zero_based64(char *result, uint64_t val)
{
    if (val == UINT64_MAX)
        snprintf(result, ITEM_LABEL_LENGTH, "0x%" PRIx64 " (2^64)", val);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "0x%" PRIx64 " (%" PRIu64 ")", val, val + 1);
}

/* Arbitration Burst (Base 2.3 Figure 404): 2^n commands, 111b no limit. */
static void add_nvme_arb_burst(char *result, uint32_t val)
{
    if (val == 7)
        snprintf(result, ITEM_LABEL_LENGTH, "%u (No limit)", val);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u (%u commands)", val, 1U << val);
}

/* Base 2.3 Figure 681 (also PLS, Figure 452). */
static const value_string nvme_power_scale_vals[] = {
    { 0x0, "Reserved" },
    { 0x1, "0.0001 W" },
    { 0x2, "0.01 W" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

/* Base 2.3 Figure 679. */
static const range_string nvme_power_meas_type_rvals[] = {
    { 0x0, 0x0, "NVM subsystem total power" },
    { 0x1, 0xb, "Reserved" },
    { 0xc, 0xf, "Vendor Specific" },
    { 0, 0, NULL },
};

/* Host Metadata features (FID 7Dh/7Eh/7Fh) Element Action, Set Features
 * Command Dword 11 bits 14:13. */
static const value_string sf_host_metadata_ea[] = {
    { 0x0, "Add or Replace Entry" },
    { 0x1, "Delete Entry Multiple" },
    { 0x2, "Add Entry Multiple" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

/* Metadata Element Descriptor Element Type for the (Enhanced) Controller
 * Metadata features 7Dh/7Eh (NVMe Base 2.3 "Controller Metadata Element
 * Types"). */
static const range_string host_metadata_ctrl_et[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Operating System Controller Name" },
    { 0x02, 0x02, "Operating System Driver Name" },
    { 0x03, 0x03, "Operating System Driver Version" },
    { 0x04, 0x04, "Pre-boot Controller Name" },
    { 0x05, 0x05, "Pre-boot Driver Name" },
    { 0x06, 0x06, "Pre-boot Driver Version" },
    { 0x07, 0x07, "System Processor Model" },
    { 0x08, 0x08, "Chipset Driver Name" },
    { 0x09, 0x09, "Chipset Driver Version" },
    { 0x0A, 0x0A, "Operating System Name and Build" },
    { 0x0B, 0x0B, "System Product Name" },
    { 0x0C, 0x0C, "Firmware Version" },
    { 0x0D, 0x0D, "Operating System Driver Filename" },
    { 0x0E, 0x0E, "Display Driver Name" },
    { 0x0F, 0x0F, "Display Driver Version" },
    { 0x10, 0x10, "Host-Determined Failure Record" },
    { 0x11, 0x17, "Reserved" },
    { 0x18, 0x1F, "Vendor Specific" },
    { 0, 0, NULL },
};

/* Metadata Element Descriptor Element Type for the Namespace Metadata feature
 * 7Fh (NVMe Base 2.3 "Namespace Metadata Element Types"). */
static const range_string host_metadata_ns_et[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Operating System Namespace Name" },
    { 0x02, 0x02, "Pre-boot Namespace Name" },
    { 0x03, 0x03, "Operating System Namespace Name Qualifier 1" },
    { 0x04, 0x04, "Operating System Namespace Name Qualifier 2" },
    { 0x05, 0x17, "Reserved" },
    { 0x18, 0x1F, "Vendor Specific" },
    { 0, 0, NULL },
};

static void
nvme_add_dword_fields(tvbuff_t *tvb, proto_tree *tree, unsigned pos,
                      int first, int second, int third, int fourth)
{
    const int fields[] = { first, second, third, fourth };
    for (unsigned i = 0; i < array_length(fields); i++)
        if (fields[i] != -1)
            proto_tree_add_item(tree, fields[i], tvb, pos, 4, ENC_LITTLE_ENDIAN);
}

/* Base 2.3 Figures 443, 453-454; NVM 1.2 Figure 101. */
static bool
dissect_nvme_feature_extra_dw11(tvbuff_t *tvb, proto_tree *tree, unsigned fid, bool get)
{
    switch (fid) {
    case F_PERF_CHARACTERISTICS:
        nvme_add_dword_fields(tvb, tree, 44, hf_nvme_feat_attri,
                              get ? -1 : hf_nvme_feat_rvspa, -1, -1);
        break;
    case F_CTRL_DATA_QUEUE:
        nvme_add_dword_fields(tvb, tree, 44, hf_nvme_feat_cdqid,
                              get ? -1 : hf_nvme_feat_etpt, -1, -1);
        break;
    case F_POWER_THRESHOLD:
        if (get) return false;
        nvme_add_dword_fields(tvb, tree, 44, hf_nvme_feat_ptv, hf_nvme_feat_pts,
                              hf_nvme_feat_pmts, hf_nvme_feat_ept);
        break;
    case F_POWER_MEASUREMENT:
        if (get) return false;
        nvme_add_dword_fields(tvb, tree, 44, hf_nvme_feat_pm_act, hf_nvme_feat_pm_type,
                              hf_nvme_feat_pm_smt, -1);
        break;
    case F_VOLTAGE_THRESHOLD: /* Base 2.4 Figure 525; Get selects by VSENS. */
        if (get) {
            proto_tree_add_item(tree, hf_nvme_feat_vt_vsens, tvb, 44, 4, ENC_LITTLE_ENDIAN);
            break;
        }
        nvme_add_dword_fields(tvb, tree, 44, hf_nvme_feat_vt_uvt, hf_nvme_feat_vt_ovt,
                              hf_nvme_feat_vt_evt, hf_nvme_feat_vt_vsens);
        proto_tree_add_item(tree, hf_nvme_feat_vt_rsvd, tvb, 44, 4, ENC_LITTLE_ENDIAN);
        break;
    case F_VOLTAGE_MEASUREMENT: /* Base 2.4 Figure 526, for Set and Get. */
        nvme_add_dword_fields(tvb, tree, 44, hf_nvme_feat_vm_act, hf_nvme_feat_vm_rsvd, -1, -1);
        break;
    case F_RATE_LIMITING: /* NVM CS 1.3 Figure 106, for Set and Get. */
        nvme_add_dword_fields(tvb, tree, 44, hf_nvme_feat_rl_tid, hf_nvme_feat_rl_tgt,
                              hf_nvme_feat_rl_rsvd, -1);
        break;
    case F_CONF_DEV_PERSONALITY: /* Base 2.4 Figure 518: Set, PERID 02h only. */
        if (get || tvb_get_uint8(tvb, 52) != 0x02)
            return false;
        nvme_add_dword_fields(tvb, tree, 44, hf_nvme_feat_ldpe, hf_nvme_feat_ldp_rsvd, -1, -1);
        break;
    default:
        return false;
    }
    return true;
}

/* The FID, not a generic UUID layout, selects CDW13-15. */
static void
dissect_nvme_feature_tail(tvbuff_t *tvb, proto_tree *tree, unsigned fid, bool get)
{
    proto_tree_add_item(tree, hf_nvme_cmd_dword13, tvb, 52, 4, ENC_LITTLE_ENDIAN);
    if (fid == F_CONF_DEV_PERSONALITY)
        nvme_add_dword_fields(tvb, tree, 52, hf_nvme_feat_perid,
                              get ? -1 : hf_nvme_feat_perfs,
                              get ? -1 : hf_nvme_feat_chps, -1);
    else if (!get && fid == F_POWER_LIMIT)
        nvme_add_dword_fields(tvb, tree, 52, hf_nvme_feat_plv, hf_nvme_feat_pls, -1, -1);
    else if (!get && fid == F_CTRL_DATA_QUEUE)
        proto_tree_add_item(tree, hf_nvme_feat_tpt, tvb, 52, 4, ENC_LITTLE_ENDIAN);

    if (!get && fid == F_HOST_MEM_BUF) {
        proto_tree_add_item(tree, hf_nvme_feat_hmdlal, tvb, 52, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_feat_hmdlau, tvb, 56, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_feat_hmdlec, tvb, 60, 4, ENC_LITTLE_ENDIAN);
    } else {
        if (get)
            add_group_mask_entry(tvb, tree, 56, 4, ASPEC(hf_nvme_get_features_dword14));
        else
            add_group_mask_entry(tvb, tree, 56, 4, ASPEC(hf_nvme_set_features_dword14));
        proto_tree_add_item(tree, hf_nvme_cmd_dword15, tvb, 60, 4, ENC_LITTLE_ENDIAN);
    }
}

static void dissect_nvme_set_features_dword11(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, unsigned fid)
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
        case F_ENH_CTRL_METADATA:
        case F_CTRL_METADATA:
        case F_NS_METADATA: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_hmd)); break;
        case F_HOST_MEM_BUF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_hmb)); break;
        case F_IO_CMD_SET_PROFILE: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_iocsp)); break;
        case F_SPINUP_CONTROL: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_spinup)); break;
        case F_POWER_LOSS_SIG_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_plsc)); break;
        case F_FDP: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_fdp)); break;
        case F_FDP_EVENTS: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_fdpe)); break;
        case F_BP_WRITE_PROT_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_set_features_dword11_bpwpc)); break;
        default:
            if (!dissect_nvme_feature_extra_dw11(cmd_tvb, cmd_tree, fid, false))
                proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword11, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    }
}

static void dissect_nvme_set_features_dword12(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, unsigned fid)
{
    switch (fid) {
        case F_READ_REC_LEVEL_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 48, 4, ASPEC(hf_nvme_cmd_set_features_dword12_rrl)); break;
        case F_PRED_LAT_MODE_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 48, 4, ASPEC(hf_nvme_cmd_set_features_dword12_plmc)); break;
        case F_PRED_LAT_MODE_WIND: add_group_mask_entry(cmd_tvb, cmd_tree, 48, 4, ASPEC(hf_nvme_cmd_set_features_dword12_plmw)); break;
        case F_HOST_MEM_BUF:
            proto_tree_add_item(cmd_tree, hf_nvme_feat_hsize, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN); break;
        case F_FDP:
            nvme_add_dword_fields(cmd_tvb, cmd_tree, 48, hf_nvme_feat_fdpcidx, hf_nvme_feat_fdpe, -1, -1); break;
        case F_FDP_EVENTS:
            proto_tree_add_item(cmd_tree, hf_nvme_feat_fdpee, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN); break;
        case F_CTRL_DATA_QUEUE:
            proto_tree_add_item(cmd_tree, hf_nvme_feat_hp, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN); break;
        case F_POWER_MEASUREMENT:
            /* Figure 455 only defines vendor-specific ACTSP values. */
            if ((tvb_get_uint8(cmd_tvb, 44) & 0x0f) >= 0x0c)
                proto_tree_add_item(cmd_tree, hf_nvme_feat_pm_actsp, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
            break;
        default: proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    }
}

static void dissect_nvme_set_features_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                      struct nvme_cmd_ctx *cmd_ctx)
{
    cmd_ctx->cmd_ctx.set_features.fid = tvb_get_uint8(cmd_tvb, 40);
    cmd_ctx->cmd_ctx.set_features.cdw11 = tvb_get_letohl(cmd_tvb, 44);
    cmd_ctx->cmd_ctx.set_features.cdw13 = tvb_get_letohl(cmd_tvb, 52);
    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_set_features_dword10));
    dissect_nvme_set_features_dword11(cmd_tvb, cmd_tree, cmd_ctx->cmd_ctx.set_features.fid);
    dissect_nvme_set_features_dword12(cmd_tvb, cmd_tree, cmd_ctx->cmd_ctx.set_features.fid);
    dissect_nvme_feature_tail(cmd_tvb, cmd_tree, cmd_ctx->cmd_ctx.set_features.fid, false);
}

static void dissect_nvme_get_features_cmd(tvbuff_t *cmd_tvb, packet_info *pinfo, proto_tree *cmd_tree,
                                      struct nvme_cmd_ctx *cmd_ctx)
{
    cmd_ctx->cmd_ctx.set_features.fid = tvb_get_uint8(cmd_tvb, 40);
    cmd_ctx->cmd_ctx.set_features.cdw11 = tvb_get_letohl(cmd_tvb, 44);
    cmd_ctx->cmd_ctx.set_features.cdw13 = tvb_get_letohl(cmd_tvb, 52);
    /* Select (CDW10 bits 10:08) decides what Dword 0 means. */
    cmd_ctx->cmd_ctx.set_features.sel = (tvb_get_uint8(cmd_tvb, 41) & 0x7);
    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_get_features_dword10));
    if (cmd_ctx->cmd_ctx.set_features.sel > NVME_GET_FEATURES_SEL_SUPPORTED_CAPS)
        proto_tree_add_expert(cmd_tree, pinfo, &ei_nvme_feat_sel_reserved, cmd_tvb, 41, 1);
    switch(cmd_ctx->cmd_ctx.set_features.fid) {
        case F_READ_REC_LEVEL_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_get_features_dword11_rrl)); break;
        case F_PRED_LAT_MODE_CONF: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_get_features_dword11_plmc)); break;
        case F_PRED_LAT_MODE_WIND: add_group_mask_entry(cmd_tvb, cmd_tree, 44, 4, ASPEC(hf_nvme_cmd_get_features_dword11_plmw)); break;
        case F_TEMP_THRESHOLD:
            nvme_add_dword_fields(cmd_tvb, cmd_tree, 44, hf_nvme_cmd_get_features_dword11_tt_tmpsel,
                                  hf_nvme_cmd_set_features_dword11_tt[3], -1, -1); break;
        case F_IRQ_VECTOR_CONF:
            proto_tree_add_item(cmd_tree, hf_nvme_cmd_set_features_dword11_irqv[1], cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN); break;
        case F_END_GROUP_EV_CONF:
            proto_tree_add_item(cmd_tree, hf_nvme_cmd_set_features_dword11_eg[1], cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN); break;
        case F_FDP:
            proto_tree_add_item(cmd_tree, hf_nvme_cmd_set_features_dword11_fdp[1], cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN); break;
        case F_FDP_EVENTS:
            proto_tree_add_item(cmd_tree, hf_nvme_cmd_set_features_dword11_fdpe[1], cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN); break;
        case F_HOST_ID:
            proto_tree_add_item(cmd_tree, hf_nvme_cmd_set_features_dword11_hid[1], cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN); break;
        case F_ENH_CTRL_METADATA:
        case F_CTRL_METADATA:
        case F_NS_METADATA:
            proto_tree_add_item(cmd_tree, hf_nvme_feat_gdhm, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN); break;
        default:
            if (!dissect_nvme_feature_extra_dw11(cmd_tvb, cmd_tree, cmd_ctx->cmd_ctx.set_features.fid, true))
                proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword11, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
            break;
    }
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    dissect_nvme_feature_tail(cmd_tvb, cmd_tree, cmd_ctx->cmd_ctx.set_features.fid, true);
}

static void dissect_nvme_rw_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                bool is_write)
{
    proto_item *ti, *dsm_tree, *item;
    uint8_t val;

    dissect_nvme_rwc_common_word_10_11_12_14_15(cmd_tvb, cmd_tree, is_write);

    ti = proto_tree_add_item(cmd_tree, hf_nvme_cmd_dsm, cmd_tvb, 52,
                             1, ENC_NA);
    dsm_tree = proto_item_add_subtree(ti, ett_data);

    item = proto_tree_add_item_ret_uint8(dsm_tree, hf_nvme_cmd_dsm_access_freq, cmd_tvb,
                               52, 1, ENC_LITTLE_ENDIAN, &val);
    proto_item_append_text(item, " %s",
                           val_to_str_const(val, dsm_acc_freq_tbl, "Reserved"));

    item = proto_tree_add_item_ret_uint8(dsm_tree, hf_nvme_cmd_dsm_access_lat, cmd_tvb,
                               52, 1, ENC_LITTLE_ENDIAN, &val);
    proto_item_append_text(item, " %s",
                           val_to_str_const(val, dsm_acc_lat_tbl, "Reserved"));

    proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_seq_req, cmd_tvb,
                        52, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_incompressible, cmd_tvb,
                        52, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_rsvd3, cmd_tvb,
                        53, 3, ENC_NA);
}

static const range_string sf_lbart_type_table[] = {
    { 0x0, 0x0, "General Purpose" },
    { 0x1, 0x1, "Filesystem" },
    { 0x2, 0x2, "RAID" },
    { 0x3, 0x3, "Cache" },
    { 0x4, 0x4, "Page or swap file" },
    { 0x80, 0xFF, "Vendor Specific" },
    { 0, 0, NULL },
};

static void dissect_nvme_set_features_transfer_lbart(tvbuff_t *tvb, proto_tree *tree, unsigned off, unsigned len)
{
    proto_tree *grp;
    proto_item *ti;
    unsigned done = 0;
    /* Skip a leading partial entry (NVM CS 1.2 Figure 95). */
    unsigned skip = (off % 64) ? (64 - (off % 64)) : 0;

    if (skip) {
        if (skip >= len)
            return;
        proto_tree_add_bytes_format_value(tree, hf_nvme_gen_data, tvb, 0, skip,
            NULL, "Partial LBA Range Structure %u (its bytes 63:%u; bytes"
            " %u:0 are in an earlier window)", off / 64, off % 64, off % 64 - 1);
        done = skip;
        len -= skip;
    }

    while (len >= 64) {
        ti =  proto_tree_add_bytes_format_value(tree, hf_nvme_set_features_tr_lbart, tvb, done, 64, NULL, "LBA Range Structure %u", (done + off) / 64);
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
    /* A trailing partial entry. */
    if (len)
        proto_tree_add_bytes_format_value(tree, hf_nvme_gen_data, tvb, done, len,
            NULL, "Partial LBA Range Structure %u (its bytes %u:0; the rest is"
            " in a later window)", (done + off) / 64, len - 1);
}

static void dissect_nvme_set_features_transfer_apst(tvbuff_t *tvb, proto_tree *tree, unsigned off, unsigned len)
{
    unsigned poff = 0;
    /* Non-Operational Power State Transition table: 32 entries * 8 bytes =
     * 256 bytes max.  Each entry's value is self-contained, but a nonzero
     * window offset moves where that 256-byte ceiling falls. */
    unsigned max_len = (off < 256) ? (256 - off) : 0;
    /* Skip a leading partial entry. */
    unsigned skip = (off % 8) ? (8 - (off % 8)) : 0;

    if (len > max_len)
        len = max_len;
    if (skip) {
        if (skip >= len)
            return;
        proto_tree_add_bytes_format_value(tree, hf_nvme_gen_data, tvb, 0, skip,
            NULL, "Partial Non-Operational Power State Transition entry %u"
            " (its bytes 7:%u)", off / 8, off % 8);
        poff = skip;
        len -= skip;
    }
    while (len >= 8) {
        add_group_mask_entry(tvb, tree, poff, 8, ASPEC(hf_nvme_set_features_tr_apst));
        len -= 8;
        poff += 8;
    }
    if (len)
        proto_tree_add_bytes_format_value(tree, hf_nvme_gen_data, tvb, poff, len,
            NULL, "Partial Non-Operational Power State Transition entry %u"
            " (its bytes %u:0)", (off + poff) / 8, len - 1);
}

/* Timestamp (FID 0Eh): Figure 414 (Set) and 415 (Get) differ, and Get also
 * arrives here, so branch on the opcode. */
static void dissect_nvme_set_features_transfer_tst(tvbuff_t *tvb, proto_tree *tree,
                                                   struct nvme_cmd_ctx *cmd_ctx,
                                                   unsigned off, unsigned len)
{
    unsigned rel;

    if (!nvme_field_in_window(off, len, 0, 8, &rel))
        return;

    if (cmd_ctx->opcode == NVME_AQ_OPC_GET_FEATURES)
        add_group_mask_entry(tvb, tree, rel, 8, ASPEC(hf_nvme_get_features_tr_tst));
    else
        add_group_mask_entry(tvb, tree, rel, 8, ASPEC(hf_nvme_set_features_tr_tst));
}


/* The Reserved run from struct offset `start` to the end of a 512-byte
 * windowed structure, or all of a window inside it, never past byte 512. */
static void
nvme_add_tail_rsvd(tvbuff_t *tvb, proto_tree *grp, int hf, unsigned off, unsigned len,
                   unsigned start)
{
    unsigned poff = (off <= start) ? (start - off) : 0;

    if (poff <= len && off <= 512) {
        unsigned max_len = (512 - off) - poff;
        unsigned rlen = len - poff;
        if (rlen > max_len)
            rlen = max_len;
        proto_tree_add_item(grp, hf, tvb, poff, rlen, ENC_NA);
    }
}

static void dissect_nvme_set_features_transfer_plmc(tvbuff_t *tvb, proto_tree *tree, unsigned off, unsigned len)
{
    proto_tree *grp;
    proto_item *ti;
    unsigned rel;

    ti = proto_tree_add_item(tree, hf_nvme_set_features_tr_plmc, tvb, 0, len, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvme_field_in_window(off, len, 0, 2, &rel))
        add_group_mask_entry(tvb, grp, rel, 2, ASPEC(hf_nvme_set_features_tr_plmc_ee));
    if (nvme_field_in_window(off, len, 2, 30, &rel))
        proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_rsvd0, tvb, rel, 30, ENC_NA);
    if (nvme_field_in_window(off, len, 32, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_dtwinrt, tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 40, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_dtwinwt, tvb, rel, 8, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 48, 8, &rel))
        proto_tree_add_item(grp, hf_nvme_set_features_tr_plmc_dtwintt, tvb, rel, 8, ENC_LITTLE_ENDIAN);
    nvme_add_tail_rsvd(tvb, grp, hf_nvme_set_features_tr_plmc_rsvd1, off, len, 56);
}

static void dissect_nvme_set_features_transfer_hbs(tvbuff_t *tvb, proto_tree *tree, unsigned off, unsigned len)
{
    proto_tree *grp;
    proto_item *ti;
    unsigned rel;

    ti = proto_tree_add_item(tree, hf_nvme_set_features_tr_hbs, tvb, 0, len, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvme_field_in_window(off, len, 0, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_set_features_tr_hbs_acre, tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 1, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_set_features_tr_hbs_etdas, tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 2, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_set_features_tr_hbs_lbafee, tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 3, 1, &rel))
        proto_tree_add_item(grp, hf_nvme_set_features_tr_hbs_hdisns, tvb, rel, 1, ENC_LITTLE_ENDIAN);
    if (nvme_field_in_window(off, len, 4, 2, &rel))
        add_group_mask_entry(tvb, grp, rel, 2, ASPEC(hf_nvme_set_features_tr_hbs_cdfe));
    nvme_add_tail_rsvd(tvb, grp, hf_nvme_set_features_tr_hbs_rsvd, off, len, 6);
}

/* Host Metadata data structure, shared by the (Enhanced) Controller Metadata
 * and Namespace Metadata features (7Dh/7Eh/7Fh).
 * A 4 KiB structure: a 1-byte NMED count, a reserved byte, then a list of
 * variable-length Metadata Element Descriptors (a 4-byte header carrying
 * ET/ER/ELEN, followed by ELEN bytes of UTF-8 Element Value). */
static void dissect_nvme_host_metadata(tvbuff_t *tvb, proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx, unsigned off, unsigned len)
{
    const range_string *et_rs = (cmd_ctx->cmd_ctx.set_features.fid == F_NS_METADATA)
        ? host_metadata_ns_et : host_metadata_ctrl_et;
    proto_tree *grp;
    proto_item *ti;
    unsigned pos;
    uint32_t nmed, i;

    ti = proto_tree_add_item(tree, hf_nvme_set_features_tr_hmd, tvb, 0, len, ENC_NA);
    grp = proto_item_add_subtree(ti, ett_data);

    /* The NMED header is only present at the start of the structure.  Over a
     * windowed transfer (off > 0) the chunk begins mid-list and cannot be
     * realigned, so show it raw rather than misparse. */
    if (off != 0 || len < 2) {
        proto_tree_add_item(grp, hf_nvme_gen_data, tvb, 0, len, ENC_NA);
        return;
    }

    proto_tree_add_item_ret_uint(grp, hf_nvme_set_features_tr_hmd_nmed, tvb, 0, 1, ENC_LITTLE_ENDIAN, &nmed);
    proto_tree_add_item(grp, hf_nvme_set_features_tr_hmd_rsvd, tvb, 1, 1, ENC_NA);
    pos = 2;

    for (i = 0; i < nmed; i++) {
        proto_tree *med;
        proto_item *med_ti, *et_ti;
        uint32_t et, elen, er;

        /* Stop if the descriptor runs past the data (DLEN or a window). */
        if (pos + 4 > len)
            break;
        elen = tvb_get_uint16(tvb, pos + 2, ENC_LITTLE_ENDIAN);
        if (pos + 4 + elen > len)
            break;

        med_ti = proto_tree_add_item(grp, hf_nvme_set_features_tr_hmd_med, tvb, pos, 4 + elen, ENC_NA);
        proto_item_set_text(med_ti, "Metadata Element Descriptor %u", i);
        med = proto_item_add_subtree(med_ti, ett_data);

        et_ti = proto_tree_add_item_ret_uint(med, hf_nvme_set_features_tr_hmd_med_et, tvb, pos, 4, ENC_LITTLE_ENDIAN, &et);
        proto_item_append_text(et_ti, " (%s)", rval_to_str_const(et, et_rs, "Unknown"));
        proto_tree_add_item_ret_uint(med, hf_nvme_set_features_tr_hmd_med_er,
                                     tvb, pos, 4, ENC_LITTLE_ENDIAN, &er);
        proto_tree_add_item(med, hf_nvme_set_features_tr_hmd_med_elen, tvb, pos, 4, ENC_LITTLE_ENDIAN);
        if (elen) {
            bool known = er == 0 && et >= 1 &&
                et <= (cmd_ctx->cmd_ctx.set_features.fid == F_NS_METADATA ? 4U : 16U);
            if (known) {
                proto_tree_add_item(med, hf_nvme_set_features_tr_hmd_med_eval,
                                    tvb, pos + 4, elen, ENC_UTF_8);
            } else {
                proto_tree_add_item(med, hf_nvme_gen_data, tvb, pos + 4, elen, ENC_NA);
            }
        }
        pos += 4 + elen;
    }
    if (pos < len)
        proto_tree_add_item(grp, hf_nvme_gen_data, tvb, pos, len - pos, ENC_NA);
}

static void
dissect_nvme_feature_extra_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                struct nvme_cmd_ctx *ctx, unsigned off, unsigned len)
{
    unsigned fid = ctx->cmd_ctx.set_features.fid;
    bool get = ctx->opcode == NVME_AQ_OPC_GET_FEATURES;
    /* Unknown selectors and partial fields stay raw. */
    proto_item *ti = proto_tree_add_item(tree, hf_nvme_gen_data, tvb, 0, len, ENC_NA);
    switch (fid) {
    case F_HOST_MEM_BUF: /* Base 2.3 Figure 484; Set has no data buffer. */
        if (get) {
            nvme_add_window_field(tvb, tree, hf_nvme_feat_hsize, off, len, 0, 4, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_feat_hmdlal, off, len, 4, 4, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_feat_hmdlau, off, len, 8, 4, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_feat_hmdlec, off, len, 12, 4, ENC_LITTLE_ENDIAN);
        }
        break;
    case F_CTRL_DATA_QUEUE: /* Figure 446 (447 in the surrounding prose is a typo). */
        if (get) {
            nvme_add_window_field(tvb, tree, hf_nvme_feat_hp, off, len, 0, 4, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_feat_tpt, off, len, 4, 4, ENC_LITTLE_ENDIAN);
        }
        break;
    case F_FDP_EVENTS: /* Figures 439-441: Set is bytes, Get is two-byte descriptors. */
        {
            unsigned count = (ctx->cmd_ctx.set_features.cdw11 >> 16) & 0xff;
            if (get) {
                if (!ctx->cmd_ctx.set_features.response_count_valid) {
                    /* The count is NOET from a successful completion's Dword 0
                     * (Figure 436); none is recorded before NVMe/TCP or RDMA
                     * delivers that completion, or ever after an error or a
                     * TCP SUCCESS-flag completion. */
                    nvme_add_window_note(ti, NVME_WINDOW_RAW);
                    return;
                }
                count = ctx->cmd_ctx.set_features.response_count;
            }
            for (unsigned i = 0; i < count; i++) {
                nvme_add_window_field(tvb, tree, hf_nvme_feat_fdpet, off, len, i * (get ? 2 : 1), 1, ENC_LITTLE_ENDIAN);
                if (get)
                    nvme_add_window_field(tvb, tree, hf_nvme_feat_fdpe_attr, off, len, i * 2 + 1, 1, ENC_LITTLE_ENDIAN);
            }
        }
        break;
    case F_NS_ADMIN_LABEL: /* Figure 442: a complete bounded UTF-8 string. */
        if (!off && len >= 256)
            proto_tree_add_item(tree, hf_nvme_feat_nsal, tvb, 0, 256, ENC_UTF_8);
        break;
    case F_EMB_MGMT_CTRL_ADDR:
    case F_HOST_MGMT_AGENT_ADDR: /* Figures 457-458: URI bytes, not a speculative IP address. */
        nvme_add_window_field(tvb, tree, fid == F_EMB_MGMT_CTRL_ADDR ? hf_nvme_feat_emca : hf_nvme_feat_hmaa,
                              off, len, 4, 508, ENC_ASCII);
        break;
    case F_HOST_ID: /* Base 2.4 Figure 538: a 64-bit HOSTID is bytes 7:0, 15:8 Reserved. */
        if (ctx->cmd_ctx.set_features.cdw11 & 1) {
            nvme_add_window_field(tvb, tree, hf_nvme_feat_hostid, off, len, 0, 16, ENC_NA);
        } else {
            nvme_add_window_field(tvb, tree, hf_nvme_feat_hostid, off, len, 0, 8, ENC_NA);
            nvme_add_window_field(tvb, tree, hf_nvme_feat_hostid_rsvd, off, len, 8, 8, ENC_NA);
        }
        break;
    case F_CONF_DEV_PERSONALITY: /* Figures 450-451, Security Personality only. */
        if ((ctx->cmd_ctx.set_features.cdw13 & 0xff) != 1)
            return;
        if (get) {
            const nvme_window_field sps[] = {
                NVME_WG(0, 4, hf_nvme_feat_security_status),
                NVME_WG(4, 4, hf_nvme_feat_security_supported),
            };
            nvme_add_window_fields(tvb, tree, off, len, sps, array_length(sps));
        } else if (ctx->cmd_ctx.set_features.cdw13 & 0x200) {
            const nvme_window_field spa[] = { NVME_WG(0, 4, hf_nvme_feat_security_set) };
            nvme_add_window_fields(tvb, tree, off, len, spa, array_length(spa));
        }
        break;
    case F_VOLTAGE_MEASUREMENT: { /* Base 2.4 Figure 527, only with ACT 1h. */
        static const nvme_window_field svm[] = {
            NVME_WG(0, 2, hf_nvme_feat_svm_lvolta),
            NVME_WF(2, 2, hf_nvme_feat_svm_svmt, ENC_LITTLE_ENDIAN),
            NVME_WG(4, 4, hf_nvme_feat_svm_lvolt),
            NVME_WF(8, 4088, hf_nvme_feat_svm_rsvd, ENC_NA),
        };
        if ((ctx->cmd_ctx.set_features.cdw11 & 0xf) != 1) {
            proto_tree_add_item(tree, hf_nvme_gen_data, tvb, 0, len, ENC_NA);
            return;
        }
        nvme_add_window_fields(tvb, tree, off, len, svm, array_length(svm));
        break;
    }
    case F_RATE_LIMITING: { /* NVM CS 1.3 Figure 107. */
        static const nvme_window_field rl[] = {
            NVME_WG(0, 2, hf_nvme_feat_rl_rlc),
            NVME_WF(2, 5, hf_nvme_feat_rl_rsvd0, ENC_NA),
            NVME_WF(7, 1, hf_nvme_feat_rl_bwsf, ENC_LITTLE_ENDIAN),
            NVME_WF(8, 8, hf_nvme_feat_rl_tbwv, ENC_LITTLE_ENDIAN),
            NVME_WF(16, 8, hf_nvme_feat_rl_wbwv, ENC_LITTLE_ENDIAN),
            NVME_WF(24, 4, hf_nvme_feat_rl_tiops, ENC_LITTLE_ENDIAN),
            NVME_WF(28, 4, hf_nvme_feat_rl_wiops, ENC_LITTLE_ENDIAN),
            NVME_WF(32, 1, hf_nvme_feat_rl_riopsr, ENC_LITTLE_ENDIAN),
            NVME_WF(33, 1, hf_nvme_feat_rl_wiopsr, ENC_LITTLE_ENDIAN),
            NVME_WF(34, 1, hf_nvme_feat_rl_rbwr, ENC_LITTLE_ENDIAN),
            NVME_WF(35, 1, hf_nvme_feat_rl_wbwr, ENC_LITTLE_ENDIAN),
            NVME_WF(36, 476, hf_nvme_feat_rl_rsvd1, ENC_NA),
            NVME_WF(512, 512, hf_nvme_feat_rl_vs, ENC_NA),
        };
        nvme_add_window_fields(tvb, tree, off, len, rl, array_length(rl));
        /* The four ratio portions "shall be a non-zero value". */
        if (!get && !off && len >= 36) {
            uint32_t r = tvb_get_letohl(tvb, 32);
            if (!(r & 0xff) || !(r & 0xff00) || !(r & 0xff0000) || !(r & 0xff000000))
                expert_add_info_format(pinfo, ti, &ei_nvme_feat_field_invalid,
                                       "A Write to Read IOPS or Bandwidth Ratio portion is 0h; "
                                       "each shall be non-zero (NVM Command Set 'Rate Limiting - Data Buffer')");
        }
        break;
    }
    case F_PERF_CHARACTERISTICS: /* NVM 1.2 Figures 102-104. */
        if (!get)
            return; /* Standard attributes are read-only; vendor data is opaque. */
        if ((ctx->cmd_ctx.set_features.cdw11 & 0xff) == 0) {
            nvme_add_window_field(tvb, tree, hf_nvme_feat_r4karl, off, len, 4, 1, ENC_LITTLE_ENDIAN);
        } else if ((ctx->cmd_ctx.set_features.cdw11 & 0xff) == 0xc0) {
            nvme_add_window_field(tvb, tree, hf_nvme_feat_attrtyp, off, len, 0, 1, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_feat_msvspa, off, len, 1, 1, ENC_LITTLE_ENDIAN);
            nvme_add_window_field(tvb, tree, hf_nvme_feat_usvspa, off, len, 2, 1, ENC_LITTLE_ENDIAN);
            for (unsigned pos = 16; pos < 1024; pos += 16)
                nvme_add_window_field(tvb, tree, hf_nvme_feat_paid, off, len, pos, 16, ENC_NA);
        }
        break;
    }
}

static void dissect_nvme_set_features_transfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx, unsigned off, unsigned len)
{
    /* Select 011b returns its result in Dword 0, and 100b-111b are reserved
     * (Base 2.4 Figure 198): no feature structure applies. */
    if (cmd_ctx->opcode == NVME_AQ_OPC_GET_FEATURES &&
        cmd_ctx->cmd_ctx.set_features.sel >= NVME_GET_FEATURES_SEL_SUPPORTED_CAPS) {
        proto_item *ti = proto_tree_add_item(tree, hf_nvme_gen_data, tvb, 0, len, ENC_NA);
        uint32_t sz;
        /* A reserved Select is already flagged on the command. */
        if (cmd_ctx->cmd_ctx.set_features.sel > NVME_GET_FEATURES_SEL_SUPPORTED_CAPS)
            return;
        if (nvme_feature_transfer(cmd_ctx->cmd_ctx.set_features.fid, true, 0,
                                  cmd_ctx->cmd_ctx.set_features.cdw11,
                                  cmd_ctx->cmd_ctx.set_features.cdw13, &sz) == NVME_FEAT_XFER_NONE)
            expert_add_info(pinfo, ti, &ei_nvme_feat_sel_no_data);
        else
            expert_add_info(pinfo, ti, &ei_nvme_feat_sel_caps_data);
        return;
    }
    switch(cmd_ctx->cmd_ctx.set_features.fid) {
        case F_LBA_RANGE_TYPE:
            dissect_nvme_set_features_transfer_lbart(tvb, tree, off, len);
            break;
        case F_AUTO_PS_TRANSITION:
            dissect_nvme_set_features_transfer_apst(tvb, tree, off, len);
            break;
        case F_TIMESTAMP:
            dissect_nvme_set_features_transfer_tst(tvb, tree, cmd_ctx, off, len);
            break;
        case F_PRED_LAT_MODE_CONF:
            dissect_nvme_set_features_transfer_plmc(tvb, tree, off, len);
            break;
        case F_HOST_BEHV_SUPPORT:
            dissect_nvme_set_features_transfer_hbs(tvb, tree, off, len);
            break;
        case F_ENH_CTRL_METADATA:
        case F_CTRL_METADATA:
        case F_NS_METADATA:
            dissect_nvme_host_metadata(tvb, tree, cmd_ctx, off, len);
            break;
        case F_HOST_MEM_BUF:
        case F_CTRL_DATA_QUEUE:
        case F_FDP_EVENTS:
        case F_NS_ADMIN_LABEL:
        case F_EMB_MGMT_CTRL_ADDR:
        case F_HOST_MGMT_AGENT_ADDR:
        case F_HOST_ID:
        case F_CONF_DEV_PERSONALITY:
        case F_PERF_CHARACTERISTICS:
        case F_VOLTAGE_MEASUREMENT:
        case F_RATE_LIMITING:
            dissect_nvme_feature_extra_data(tvb, pinfo, tree, cmd_ctx, off, len);
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
            rval_to_str_const(cmd->cmd_ctx.fabric_cmd.fctype, fctype_tbl, "Unknown Command"));
        return;
    }
    if (!q_ctx->qid) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF Data Request for %s", get_aq_opcode_name(cmd->opcode));
        if (cmd->opcode == NVME_AQ_OPC_IDENTIFY)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", val_to_str_const(cmd->cmd_ctx.cmd_identify.cns, cns_table, "Unknown"));
        else if (cmd->opcode == NVME_AQ_OPC_GET_LOG_PAGE)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", get_logpage_name_csi(cmd->cmd_ctx.get_logpage.lid, cmd->cmd_ctx.get_logpage.csi));
    } else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF Data Request for %s", get_ioq_opcode_name(cmd->opcode));
    }
}

static void dissect_nvme_security_data(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree,
                                       struct nvme_cmd_ctx *cmd_ctx,
                                       unsigned off, unsigned len,
                                       enum nvme_data_direction dir,
                                       bool level0_prefix);

bool
nvme_dissect_admin_data_resp(tvbuff_t *nvme_tvb, packet_info *pinfo,
                             proto_tree *cmd_tree, struct nvme_cmd_ctx *cmd_ctx,
                             unsigned off, unsigned len,
                             struct nvme_data_origin origin,
                             enum nvme_data_direction dir)
{
    /* Admin data travels one way per opcode (NVMe Base 2.3 section 5). */
    enum nvme_data_direction defined;

    switch (cmd_ctx->opcode) {
    case NVME_AQ_OPC_IDENTIFY:
    case NVME_AQ_OPC_GET_LOG_PAGE:
    case NVME_AQ_OPC_GET_FEATURES:
    case NVME_AQ_OPC_SECURITY_RECV:
        defined = NVME_DATA_DIR_CONTROLLER_TO_HOST;
        break;
    case NVME_AQ_OPC_SET_FEATURES:
    case NVME_AQ_OPC_SECURITY_SEND:
        defined = NVME_DATA_DIR_HOST_TO_CONTROLLER;
        break;
    default:
        return false;
    }

    if (dir != defined) {
        /* The other half's bytes: the caller renders them raw. */
        proto_tree_add_expert_format(cmd_tree, pinfo,
                                     &ei_nvme_data_wrong_direction,
                                     nvme_tvb, 0, len,
                                     "%s data for %s, which defines data in"
                                     " the %s direction only; no"
                                     " %s-side field is decoded from it",
                                     (dir == NVME_DATA_DIR_HOST_TO_CONTROLLER)
                                         ? "Host-to-controller"
                                         : "Controller-to-host",
                                     get_aq_opcode_name(cmd_ctx->opcode),
                                     (defined == NVME_DATA_DIR_HOST_TO_CONTROLLER)
                                         ? "host-to-controller"
                                         : "controller-to-host",
                                     (defined == NVME_DATA_DIR_HOST_TO_CONTROLLER)
                                         ? "request" : "response");
        return false;
    }

    switch (cmd_ctx->opcode) {
    case NVME_AQ_OPC_IDENTIFY:
        dissect_nvme_identify_resp(nvme_tvb, pinfo, cmd_tree, cmd_ctx, off, len);
        return true;
    case NVME_AQ_OPC_GET_LOG_PAGE:
        cmd_ctx->cmd_ctx.get_logpage.retain =
            origin.prov == NVME_DATA_PROV_RESPONSE &&
            origin.window != NVME_DATA_WINDOW_UNKNOWN;
        dissect_nvme_get_logpage_resp(nvme_tvb, pinfo, cmd_tree, cmd_ctx, off, len);
        return true;
    case NVME_AQ_OPC_SET_FEATURES:
    case NVME_AQ_OPC_GET_FEATURES:
        dissect_nvme_set_features_transfer(nvme_tvb, pinfo, cmd_tree, cmd_ctx, off, len);
        return true;
    case NVME_AQ_OPC_SECURITY_SEND:
    case NVME_AQ_OPC_SECURITY_RECV:
        dissect_nvme_security_data(nvme_tvb, pinfo, cmd_tree, cmd_ctx, off, len,
                                   dir, origin.level0_prefix);
        return true;
    default:
        return false;
    }
}

void
dissect_nvme_data_response(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, unsigned len, bool is_inline,
                 enum nvme_data_direction dir, struct nvme_data_origin origin)
{
    struct nvme_cmd_ctx unretained;
    struct nvme_cmd_ctx *persistent = cmd_ctx;
    proto_tree *cmd_tree;
    proto_item *ti;
    const char *str_opcode;
    uint32_t off;
    unsigned avail;
    bool over_declared;

    /* Clamp a wire-declared length (NVMe/TCP DATAL) to the reported length:
     * a DATAL past the PDU was never sent.  Not the captured length: a
     * sliced capture must still throw and show as truncated. */
    avail = tvb_reported_length(nvme_tvb);
    over_declared = (len > avail);
    if (over_declared)
        len = avail;

    /* The block's offset: the running offset, or the transport's own. */
    if (origin.window == NVME_DATA_WINDOW_EXPLICIT)
        off = origin.offset;
    else
        off = (PINFO_FD_VISITED(pinfo)) ? nvme_lookup_data_tr_off(q_ctx, pinfo->num) : cmd_ctx->tr_bytes;

    /* Without a known origin, nothing is retained. */
    if (origin.window == NVME_DATA_WINDOW_UNKNOWN)
        origin.prov = NVME_DATA_PROV_NONE;
    /* Nor in the log page walk state: such bytes decode from a copy. */
    if (origin.prov != NVME_DATA_PROV_RESPONSE) {
        unretained = *cmd_ctx;
        cmd_ctx = &unretained;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
    ti = proto_tree_add_item(root_tree, proto_nvme, nvme_tvb, 0,
                             len, ENC_NA);
    cmd_tree = proto_item_add_subtree(ti, ett_data);
    /* The transport header and the frame disagree on length. */
    if (over_declared)
        expert_add_info(pinfo, ti, &ei_nvme_data_len_exceeds_frame);
    if (q_ctx->qid) { //IOQ
        str_opcode = get_ioq_opcode_name(cmd_ctx->opcode);
      } else { //AQ
        str_opcode = get_aq_opcode_name(cmd_ctx->opcode);
        if (cmd_ctx->opcode == NVME_AQ_OPC_SECURITY_SEND ||
            cmd_ctx->opcode == NVME_AQ_OPC_SECURITY_RECV) {
            cmd_ctx->cmd_ctx.security.scope = q_ctx;
            cmd_ctx->cmd_ctx.security.state_valid =
                !over_declared && tvb_captured_length(nvme_tvb) >= len;
            if (dir == NVME_DATA_DIR_CONTROLLER_TO_HOST)
                cmd_ctx->cmd_ctx.security.state_valid &= origin.prov == NVME_DATA_PROV_RESPONSE;
        }
        /* The transport's direction: data that goes against the opcode's
         * own direction is not its data structure, for any opcode. */
        if (!nvme_dissect_admin_data_resp(nvme_tvb, pinfo, cmd_tree, cmd_ctx, off, len,
                                          origin,
                                          dir)) {
            proto_tree_add_bytes_format_value(cmd_tree, hf_nvme_gen_data,
                                              nvme_tvb, 0, len, NULL,
                                              "%s, offset %u", str_opcode, off);
        }
        /* The Security Send's data frame outlives a decode from a copy. */
        if (cmd_ctx->opcode == NVME_AQ_OPC_SECURITY_SEND) {
            persistent->cmd_ctx.security.request_frame =
                cmd_ctx->cmd_ctx.security.request_frame;
            persistent->cmd_ctx.security.request_ordinal =
                cmd_ctx->cmd_ctx.security.request_ordinal;
        }
    }
    if (is_inline)
        return;
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF Data for %s", str_opcode);
    if (!q_ctx->qid) {
        if (cmd_ctx->opcode == NVME_AQ_OPC_IDENTIFY)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s, offset %u", val_to_str_const(cmd_ctx->cmd_ctx.cmd_identify.cns, cns_table, "Unknown"), off);
        else if (cmd_ctx->opcode == NVME_AQ_OPC_GET_LOG_PAGE)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s, offset %u", get_logpage_name_csi(cmd_ctx->cmd_ctx.get_logpage.lid, cmd_ctx->cmd_ctx.get_logpage.csi), off);
    } else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "offset %u", off);
    }
}

static void add_nvme_qid(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%x (%s)", val, val ? "IOQ" : "AQ");
}

static void add_zero_base(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u", val+1);
}

static void add_zero_base_64(char *result, uint64_t val)
{
    add_zero_base(result, (uint32_t)val);
}

static
void dissect_nvmeof_fabric_connect_cmd(proto_tree *cmd_tree, packet_info *pinfo, tvbuff_t *cmd_tvb,
        struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, unsigned off)
{
    uint32_t qid;

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
        struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, unsigned off)
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

static void dissect_nvme_fabric_disconnect_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb,  unsigned off)
{
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_disconnect_rsvd0, cmd_tvb,
                        5+off, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_disconnect_recfmt, cmd_tvb,
                        40+off, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_disconnect_rsvd1, cmd_tvb,
                        42+off, 22, ENC_NA);
}

static uint32_t dissect_nvme_fabric_prop_cmd_common(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, unsigned off, uint8_t *size)
{
    proto_item *ti;
    proto_tree *grp;
    uint32_t attr_size, prop_off;

    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_get_set_rsvd0, cmd_tvb,
                        5+off, 35, ENC_NA);

    ti = proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_get_set_attrib[0], cmd_tvb,
                             40+off, 1, ENC_LITTLE_ENDIAN);
    grp = proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item_ret_uint(grp, hf_nvmeof_cmd_prop_get_set_attrib[1], cmd_tvb,
                                 40+off, 1, ENC_LITTLE_ENDIAN, &attr_size);
    proto_tree_add_item(grp, hf_nvmeof_cmd_prop_get_set_attrib[2], cmd_tvb,
                        40+off, 1, ENC_LITTLE_ENDIAN);
    *size = (uint8_t)attr_size;

    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_get_set_rsvd1, cmd_tvb,
                        41+off, 3, ENC_NA);

    proto_tree_add_item_ret_uint(cmd_tree, hf_nvmeof_cmd_prop_get_set_offset, cmd_tvb,
                                 44+off, 4, ENC_LITTLE_ENDIAN, &prop_off);
    return prop_off;
}

static void dissect_nvmeof_fabric_prop_get_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd, unsigned off)
{
    /* The CQE's value width is the PRS asked for here (Figure 586). */
    cmd->cmd_ctx.fabric_cmd.prop_get.offset =
        dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb, off,
                                            &cmd->cmd_ctx.fabric_cmd.prop_get.attr);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_get_rsvd2, cmd_tvb,
                        48+off, 16, ENC_NA);
}

static void add_500ms_units(char *result, uint64_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%" PRIx64 " (%" PRIu64 " ms)", val, val * 500);
}

static void add_ccap_css(char *result, uint64_t val)
{
    /* Base 2.3 Figure 36, CAP.CSS (bits 44:37) is a bitmask, not an enum:
     * bit 7 NOIOCSS, bit 6 IOCSS, bits 5:1 Reserved, bit 0 NCSS. */
    char buf[64] = "";
    bool have_bit = false;

    if (val & 0x80) {
        (void)g_strlcat(buf, "NOIOCSS", sizeof(buf));
        have_bit = true;
    }
    if (val & 0x40) {
        if (have_bit)
            (void)g_strlcat(buf, ", ", sizeof(buf));
        (void)g_strlcat(buf, "IOCSS", sizeof(buf));
        have_bit = true;
    }
    if (val & 0x1) {
        if (have_bit)
            (void)g_strlcat(buf, ", ", sizeof(buf));
        (void)g_strlcat(buf, "NCSS", sizeof(buf));
        have_bit = true;
    }
    if (!have_bit)
        (void)g_strlcat(buf, "None", sizeof(buf));

    snprintf(result, ITEM_LABEL_LENGTH, "%" PRIx64 " (%s)", val, buf);
}

static void dissect_nvmeof_fabric_prop_data(proto_tree *tree, tvbuff_t *tvb, unsigned off, unsigned prop_off, uint8_t attr)
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
static void dissect_nvmeof_fabric_prop_set_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, struct nvme_cmd_ctx *cmd, unsigned off)
{
    uint8_t attr;
    uint32_t prop_off;

    prop_off = dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb, off, &attr);
    cmd->cmd_ctx.fabric_cmd.prop_get.offset = prop_off;
    dissect_nvmeof_fabric_prop_data(cmd_tree, cmd_tvb, 48+off, prop_off, attr);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_prop_set_rsvd, cmd_tvb,
                        56+off, 8, ENC_NA);
}

static void dissect_nvmeof_fabric_generic_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb, unsigned off)
{
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_generic_rsvd1, cmd_tvb,
                        5+off, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvmeof_cmd_generic_field, cmd_tvb,
                        40+off, 24, ENC_NA);
}

void dissect_nvmeof_fabric_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *nvme_tree,
        struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, unsigned off, bool link_data_req)
{
    proto_tree *cmd_tree;
    proto_item *ti;
    uint8_t fctype;
    uint32_t prop_off;

    fctype = tvb_get_uint8(nvme_tvb, 4+off);
    cmd->cmd_ctx.fabric_cmd.fctype = fctype;

    ti = proto_tree_add_item(nvme_tree, hf_nvmeof_cmd, nvme_tvb, off,
                             NVME_CMD_SIZE, ENC_NA);
    cmd_tree = proto_item_add_subtree(ti, ett_data);

    proto_tree_add_bytes_format(cmd_tree, hf_nvmeof_cmd_opc, nvme_tvb, off, 1, NULL, "Opcode: 0x%x (Fabric Command)",
                                NVME_FABRIC_OPC);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF %s", rval_to_str_const(fctype, fctype_tbl, "Unknown Command"));
    prop_off = tvb_get_uint32(nvme_tvb, 44+off, ENC_LITTLE_ENDIAN);

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
                                     unsigned pkt_off, unsigned off, unsigned len)
{
    /* NVMe Base 2.3 Figure 580: Connect Command Data. */
    static const nvme_window_field connect_fields[] = {
        NVME_WF(0, 16, hf_nvmeof_cmd_connect_data_hostid, ENC_NA),
        NVME_WF(16, 2, hf_nvmeof_cmd_connect_data_cntlid, ENC_LITTLE_ENDIAN),
        NVME_WF(18, 238, hf_nvmeof_cmd_connect_data_rsvd0, ENC_NA),
        NVME_WF(256, 256, hf_nvmeof_cmd_connect_data_subnqn, ENC_UTF_8),
        NVME_WF(512, 256, hf_nvmeof_cmd_connect_data_hostnqn, ENC_UTF_8),
        NVME_WF(768, 256, hf_nvmeof_cmd_connect_data_rsvd1, ENC_NA),
    };

    nvme_add_window_fields_at(data_tvb, data_tree, pkt_off, off, len, connect_fields,
                              array_length(connect_fields));
}

void
dissect_nvmeof_cmd_data(tvbuff_t *data_tvb, packet_info *pinfo, proto_tree *data_tree,
                                 unsigned pkt_off, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, unsigned len)
{
    uint32_t tr_off = (PINFO_FD_VISITED(pinfo)) ? nvme_lookup_data_tr_off(q_ctx, pinfo->num) : cmd->tr_bytes;

    if (!pkt_off) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeoF Data for %s, offset %u",
            rval_to_str_const(cmd->cmd_ctx.fabric_cmd.fctype, fctype_tbl, "Unknown Command"), tr_off);
    }
    if (cmd->cmd_ctx.fabric_cmd.fctype == NVME_FCTYPE_CONNECT && len >= 768)
        dissect_nvmeof_fabric_connect_cmd_data(data_tvb, data_tree, pkt_off, tr_off, len);
}

static void
dissect_nvmeof_status_prop_get(proto_tree *cqe_tree, tvbuff_t *cqe_tvb, struct nvme_cmd_ctx *cmd, unsigned off)
{
    dissect_nvmeof_fabric_prop_data(cqe_tree, cqe_tvb, off, cmd->cmd_ctx.fabric_cmd.prop_get.offset,
                                    cmd->cmd_ctx.fabric_cmd.prop_get.attr);
}

static void
dissect_nvmeof_cqe_status_8B(proto_tree *cqe_tree, tvbuff_t *cqe_tvb,
                                  struct nvme_cmd_ctx *cmd, unsigned off)
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


const char *get_nvmeof_cmd_string(uint8_t fctype)
{
    return rval_to_str_const(fctype, fctype_tbl, "Unknown Fabric Command");
}

static void dissect_nvme_cqe_common(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *cqe_tree, unsigned off, bool nvmeof);

void
dissect_nvmeof_fabric_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo,
                        proto_tree *nvme_tree,
                        struct nvme_cmd_ctx *cmd, unsigned off)
{
    proto_tree *cqe_tree;
    proto_item *ti;
    uint8_t fctype = cmd->cmd_ctx.fabric_cmd.fctype;

    ti = proto_tree_add_item(nvme_tree, hf_nvmeof_cqe, nvme_tvb,
                             0+off, NVME_CQE_SIZE, ENC_NA);

    if (fctype != NVME_FCTYPE_PROP_GET && fctype != NVME_FCTYPE_PROP_SET)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF CQE for %s", rval_to_str_const(fctype, fctype_tbl, "Unknown Command"));
    else
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMeOF CQE for Property %s %s",
                            (fctype == NVME_FCTYPE_PROP_GET) ? "Get" : "Set",
                            val_to_str_const(cmd->cmd_ctx.fabric_cmd.prop_get.offset, prop_offset_tbl, "Unknown Property"));

    proto_item_append_text(ti, " (For Cmd: %s)", rval_to_str_const(fctype, fctype_tbl, "Unknown Cmd"));

    cqe_tree = proto_item_add_subtree(ti, ett_data);

    nvme_publish_to_cmd_link(cqe_tree, nvme_tvb, hf_nvmeof_cmd_pkt,
                                 cmd);
    nvme_publish_cmd_latency(cqe_tree, cmd, hf_nvmeof_cmd_latency);

    dissect_nvmeof_cqe_status_8B(cqe_tree, nvme_tvb, cmd, off);

    dissect_nvme_cqe_common(nvme_tvb, pinfo, cqe_tree, off, true);
}

/* Raw CDW10-CDW15, except those whose bit (CDW10 = bit 0) is set in decoded. */
static void dissect_nvme_raw_cdws(tvbuff_t *nvme_tvb, proto_tree *cmd_tree, unsigned decoded)
{
    int *const hfs[] = { &hf_nvme_cmd_dword10, &hf_nvme_cmd_dword11, &hf_nvme_cmd_dword12,
                         &hf_nvme_cmd_dword13, &hf_nvme_cmd_dword14, &hf_nvme_cmd_dword15 };
    unsigned i;

    for (i = 0; i < array_length(hfs); i++)
        if (!(decoded & (1U << i)))
            proto_tree_add_item(cmd_tree, *hfs[i], nvme_tvb, 40 + 4 * i, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_unhandled_cmd(tvbuff_t *nvme_tvb, proto_tree *cmd_tree)
{
    dissect_nvme_raw_cdws(nvme_tvb, cmd_tree, 0);
}

/* Format NVM – Secure Erase Settings (SES). */
static const value_string fmt_nvm_ses_tbl[] = {
    { 0x0, "No secure erase operation requested" },
    { 0x1, "User Data Erase" },
    { 0x2, "Cryptographic Erase" },
    { 0x3, "Reserved" },
    { 0x4, "Reserved" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0, NULL }
};

static void dissect_nvme_format_nvm_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_format_nvm_dword10));
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword11, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword14, cmd_tvb, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

/* Firmware Commit – Commit Action (CA). */
static const value_string fw_commit_ca_tbl[] = {
    { 0x0, "Replace image in slot, do not activate" },
    { 0x1, "Replace image in slot, activate at next reset" },
    { 0x2, "Activate existing image in slot at next reset" },
    { 0x3, "Replace image in slot and activate immediately" },
    { 0x4, "Reserved" },
    { 0x5, "Reserved" },
    { 0x6, "Replace Boot Partition specified by BPID" },
    { 0x7, "Mark Boot Partition in BPID active, update BPINFO.ABPID" },
    { 0, NULL }
};

static void dissect_nvme_fw_commit_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_fw_commit_dword10));
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword11, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword14, cmd_tvb, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_fw_download_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_tree_add_item(cmd_tree, hf_nvme_fw_download_numd, cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fw_download_ofst, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword14, cmd_tvb, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

/* Device Self-test – Self-test Code (STC). */
static const range_string self_test_stc_rvals[] = {
    { 0x0, 0x0, "Reserved" },
    { 0x1, 0x1, "Short device self-test" },
    { 0x2, 0x2, "Extended device self-test" },
    { 0x3, 0x3, "Host-Initiated Refresh" },
    { 0x4, 0xd, "Reserved" },
    { 0xe, 0xe, "Vendor specific" },
    { 0xf, 0xf, "Abort device self-test" },
    { 0, 0, NULL }
};

static void dissect_nvme_self_test_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    add_group_mask_entry(cmd_tvb, cmd_tree, 40, 4, ASPEC(hf_nvme_self_test_dword10));
    /* Base 2.4 Figure 178: DSTP is vendor specific only for STC Eh. */
    if ((tvb_get_uint8(cmd_tvb, 40) & 0x0f) == 0xe) {
        dissect_nvme_raw_cdws(cmd_tvb, cmd_tree, 0x21);
        proto_tree_add_item(cmd_tree, hf_nvme_self_test_dstp, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
    } else {
        dissect_nvme_raw_cdws(cmd_tvb, cmd_tree, 0x01);
    }
}

/* Lockdown – Scope (SCP) / Interface (IFC). */
static const range_string lockdown_scp_rvals[] = {
    { 0x0, 0x0, "Admin command opcode" },
    { 0x1, 0x1, "Reserved" },
    { 0x2, 0x2, "Set Features Feature Identifier" },
    { 0x3, 0x3, "Management Interface Command Set opcode" },
    { 0x4, 0x4, "PCIe Command Set opcode" },
    { 0x5, 0xf, "Reserved" },
    { 0, 0, NULL }
};

static const range_string lockdown_csel_rvals[] = {
    { 0x0, 0x0, "NVM Subsystem" },
    { 0x1, 0x1, "Specific Controller" },
    { 0x2, 0x2, "Secondary Controllers for a Specific Primary Controller" },
    { 0x3, 0xe, "Reserved" },
    { 0xf, 0xf, "Vendor Specific" },
    { 0, 0, NULL }
};

static const value_string lockdown_ifc_tbl[] = {
    { 0x0, "Admin Submission Queue" },
    { 0x1, "Admin Submission Queue and out-of-band Management Endpoint" },
    { 0x2, "Out-of-band Management Endpoint" },
    { 0x3, "Reserved" },
    { 0, NULL }
};

/* Scope values naming OFI's table (NVMe Base 2.4 Figure 365). */
#define LOCKDOWN_SCP_ADMIN_OPCODE 0x0
#define LOCKDOWN_SCP_FEATURE_ID   0x2

static void dissect_nvme_lockdown_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti;
    proto_tree *grp;
    uint32_t scp, ofi;

    /* OFI is named from the table its Scope selects; CSEL/CSS are TP4222 (Figures 365-366). */
    ti = proto_tree_add_item(cmd_tree, hf_nvme_lockdown_dword10[0], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    grp = proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item_ret_uint(grp, hf_nvme_lockdown_dword10[1], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN, &scp);
    proto_tree_add_item(grp, hf_nvme_lockdown_dword10[2], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_lockdown_dword10[3], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_lockdown_dword10[4], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    ti = proto_tree_add_item_ret_uint(grp, hf_nvme_lockdown_dword10[5], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN, &ofi);
    if (scp == LOCKDOWN_SCP_ADMIN_OPCODE)
        proto_item_append_text(ti, " (%s)", get_aq_opcode_name((uint8_t)ofi));
    else if (scp == LOCKDOWN_SCP_FEATURE_ID)
        proto_item_append_text(ti, " (%s)", get_feature_id_name((uint8_t)ofi));
    proto_tree_add_item(grp, hf_nvme_lockdown_dword10[6], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_lockdown_dword10[7], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword11, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 56, 4, ASPEC(hf_nvme_lockdown_dword14));
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

/* Sanitize – Sanitize Action (SANACT). */
static const value_string sanitize_act_tbl[] = {
    { 0x0, "Reserved" },
    { 0x1, "Exit Failure Mode" },
    { 0x2, "Block Erase" },
    { 0x3, "Overwrite" },
    { 0x4, "Crypto Erase" },
    { 0x5, "Exit Media Verification State" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0, NULL }
};

/* SANACT value that gives OWPASS a meaning (NVMe Base 2.4 Figure 451). */
#define SANITIZE_SANACT_OVERWRITE 0x3

static void dissect_nvme_sanitize_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti;
    proto_tree *grp;
    uint32_t sanact, owpass;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_sanitize_dword10[0], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    grp = proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item_ret_uint(grp, hf_nvme_sanitize_dword10[1], cmd_tvb, 40, 4,
                                 ENC_LITTLE_ENDIAN, &sanact);
    proto_tree_add_item(grp, hf_nvme_sanitize_dword10[2], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    ti = proto_tree_add_item_ret_uint(grp, hf_nvme_sanitize_dword10[3], cmd_tvb, 40, 4,
                                      ENC_LITTLE_ENDIAN, &owpass);
    /* Figure 451: OWPASS 0h is 16 passes, on an Overwrite only. */
    if (!owpass && sanact == SANITIZE_SANACT_OVERWRITE)
        proto_item_append_text(ti, " (16 passes)");
    proto_tree_add_item(grp, hf_nvme_sanitize_dword10[4], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_sanitize_dword10[5], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_sanitize_dword10[6], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_sanitize_dword10[7], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_sanitize_dword10[8], cmd_tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_sanitize_ovrpat, cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword14, cmd_tvb, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

/* Security Protocol (SECP), Security Send/Receive Command Dword 10.  Values
 * are assigned by SPC-5; the commonly used identifiers are named here. */
static const range_string security_secp_tbl[] = {
    { 0x00, 0x00, "Security Protocol Information" },
    { 0x01, 0x01, "TCG Storage - SP 1" },
    { 0x02, 0x02, "TCG Storage - SP 2" },
    { 0x03, 0x03, "TCG Storage - SP 3" },
    { 0x04, 0x04, "TCG Storage - SP 4" },
    { 0x05, 0x05, "TCG Storage - SP 5" },
    { 0x06, 0x06, "TCG Storage - SP 6" },
    { 0xE9, 0xE9, "NVMe over Fabrics Authentication" },
    { 0xEA, 0xEA, "NVMe (RPMB / CDP Authentication)" },
    { 0xEE, 0xEE, "IEEE 1667" },
    { 0xF0, 0xFF, "Vendor Specific" },
    { 0, 0, NULL }
};

#define NVME_SECP_NVME 0xEA

/* Security Protocol EAh, NVMe Base 2.4 Figure 459. */
static const range_string security_ea_spsp_tbl[] = {
    { 0x0001, 0x0001, "Replay Protected Memory Block" },
    { 0x0002, 0x0002, "CDP Authentication" },
    { 0x0003, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string security_ea_nssf_tbl[] = {
    { 0x0001, 0x0001, "RPMB Target" },
    { 0x0002, 0x0002, "CDP Authentication" },
    { 0x0003, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

/* Security Send Command Dword 10 and Security Receive Command Dword 10
 * share an identical layout: SECP/SPSP1/SPSP0/NSSF.
 * The SECP and SPSP selectors are saved in cmd_ctx so the data payload
 * (request data for Send, response data for Receive) can be dispatched to
 * the matching security-protocol dissector. */
static proto_item *dissect_nvme_security_dword10(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                                 struct nvme_cmd_ctx *cmd_ctx)
{
    const unsigned dw10_off = 40;
    proto_item *ti, *secp_ti, *nssf_ti;
    proto_tree *grp;
    uint32_t secp, spsp1, spsp0;
    const char *name;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_security_dword10[0], cmd_tvb, dw10_off, 4, ENC_LITTLE_ENDIAN);
    grp = proto_item_add_subtree(ti, ett_data);
    secp_ti = proto_tree_add_item_ret_uint(grp, hf_nvme_security_dword10[1], cmd_tvb, dw10_off, 4, ENC_LITTLE_ENDIAN, &secp);
    proto_tree_add_item_ret_uint(grp, hf_nvme_security_dword10[2], cmd_tvb, dw10_off, 4, ENC_LITTLE_ENDIAN, &spsp1);
    proto_tree_add_item_ret_uint(grp, hf_nvme_security_dword10[3], cmd_tvb, dw10_off, 4, ENC_LITTLE_ENDIAN, &spsp0);
    nssf_ti = proto_tree_add_item(grp, hf_nvme_security_dword10[4], cmd_tvb, dw10_off, 4, ENC_LITTLE_ENDIAN);
    cmd_ctx->cmd_ctx.security.secp = (uint8_t)secp;
    /* SPSP1:SPSP0 is one value (Figures 394/398), bytes 42:41. */
    cmd_ctx->cmd_ctx.security.spsp = (uint16_t)((spsp1 << 8) | spsp0);
    ti = proto_tree_add_uint(grp, hf_nvme_security_spsp, cmd_tvb, dw10_off + 1, 2,
                             cmd_ctx->cmd_ctx.security.spsp);
    proto_item_set_generated(ti);
    if (secp == NVME_SECP_NVME) {
        name = try_rval_to_str(cmd_ctx->cmd_ctx.security.spsp, security_ea_spsp_tbl);
        if (name) {
            proto_item_append_text(ti, " (%s)", name);
            proto_item_append_text(nssf_ti, " (%s)",
                rval_to_str_const(cmd_ctx->cmd_ctx.security.spsp, security_ea_nssf_tbl, "Reserved"));
        }
    } else if (secp >= 0x01 && secp <= 0x03) {
        /* TCG SIIS v1.20 Tables 23/24: SPSP is the ComID. */
        proto_item_append_text(ti, " (ComID)");
    }
    return secp_ti;
}

/* Security Send / Receive: Dword 11 is the Transfer Length / Allocation Length. */
static void dissect_nvme_security_cmd(tvbuff_t *cmd_tvb, packet_info *pinfo,
                                      proto_tree *cmd_tree,
                                      struct nvme_cmd_ctx *cmd_ctx, int hf_dword11)
{
    proto_item *secp_item, *tl_item;

    secp_item = dissect_nvme_security_dword10(cmd_tvb, cmd_tree, cmd_ctx);
    /* SIIS 1.20 Tables 23/24. */
    if (cmd_ctx->opcode == NVME_AQ_OPC_SECURITY_SEND &&
        cmd_ctx->cmd_ctx.security.secp == 0x00)
        expert_add_info(pinfo, secp_item, &ei_nvme_security_secp_send);
    else if (cmd_ctx->cmd_ctx.security.secp == 0x06)
        expert_add_info(pinfo, secp_item, &ei_nvme_security_secp_nvme);
    tl_item = proto_tree_add_item_ret_uint(cmd_tree, hf_dword11, cmd_tvb, 44, 4,
                                 ENC_LITTLE_ENDIAN, &cmd_ctx->cmd_ctx.security.xfer_len);
    /* A zero-length TPer Reset never reaches the TCG dissector, so label it
     * here (Opal SSC 2.30 3.2.3 Table 13; SIIS 1.20 Table 25). */
    if (cmd_ctx->opcode == NVME_AQ_OPC_SECURITY_SEND &&
        cmd_ctx->cmd_ctx.security.secp == 0x02 &&
        cmd_ctx->cmd_ctx.security.spsp == 0x0004 &&
        cmd_ctx->cmd_ctx.security.xfer_len == 0) {
        col_append_str(pinfo->cinfo, COL_INFO, " (TPer Reset)");
        proto_item_append_text(tl_item, " (TPer Reset)");
        expert_add_info(pinfo, tl_item, &ei_nvme_security_tper_reset_tl);
    }
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword12, cmd_tvb, 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword13, cmd_tvb, 52, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword14, cmd_tvb, 56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword15, cmd_tvb, 60, 4, ENC_LITTLE_ENDIAN);
}

/* SECP 00h (Base 2.4 section 5.2.28, SPC-5): a header-only reading.  SPSP
 * 0000h is the Supported Security Protocol List, 0001h the Certificate Data
 * and 0002h the Security Compliance Information; SPC-5 is not in the spec
 * library, so 0002h's compliance descriptors stay raw. */
static bool dissect_nvme_security_info_resp(tvbuff_t *tvb, proto_tree *tree,
                                            const struct nvme_cmd_ctx *cmd_ctx,
                                            unsigned len)
{
    uint16_t spsp = cmd_ctx->cmd_ctx.security.spsp;
    unsigned header, length_size;
    int hf_length, hf_body;

    switch (spsp) {
    case 0x0000:
        header = 8;
        length_size = 2;
        hf_length = hf_nvme_security_info_list_len;
        hf_body = -1;
        break;
    case 0x0001:
        header = 4;
        length_size = 2;
        hf_length = hf_nvme_security_info_cert_len;
        hf_body = hf_nvme_security_info_cert_data;
        break;
    case 0x0002:
        header = 4;
        length_size = 4;
        hf_length = hf_nvme_security_info_compliance_len;
        hf_body = hf_nvme_security_info_compliance_desc;
        break;
    default:
        return false;
    }

    proto_item *ti = proto_tree_add_item(tree, hf_nvme_security_info,
                                         tvb, 0, len, ENC_NA);
    proto_tree *grp = proto_item_add_subtree(ti, ett_data);
    if (len < header) {
        proto_tree_add_item(grp, hf_nvme_security_data, tvb, 0, len, ENC_NA);
        nvme_add_window_note(ti, NVME_WINDOW_RAW);
        return true;
    }
    if (header > length_size)
        proto_tree_add_item(grp, hf_nvme_security_info_rsvd, tvb, 0, header - length_size, ENC_NA);
    uint32_t declared;
    proto_item *length_item = proto_tree_add_item_ret_uint(grp, hf_length, tvb,
        header - length_size, length_size, ENC_BIG_ENDIAN, &declared);
    unsigned available = len - header;
    unsigned shown = MIN(declared, available);
    /* The selected or allocated bytes may hold only a prefix. */
    if (declared > available)
        nvme_add_window_note(length_item, NVME_WINDOW_RAW);
    if (hf_body < 0) {
        for (unsigned i = 0; i < shown; i++)
            proto_tree_add_item(grp, hf_nvme_security_info_protocol, tvb,
                                header + i, 1, ENC_BIG_ENDIAN);
    } else if (shown) {
        proto_tree_add_item(grp, hf_body, tvb, header, shown, ENC_NA);
    }
    if (available > declared)
        proto_tree_add_item(grp, hf_nvme_security_info_residue, tvb,
                            header + declared, available - declared, ENC_NA);
    return true;
}

/* Security Send/Receive data: dispatched to "nvme.security.secp" only from
 * offset 0 and not known short (a short Receive still is); else raw. */
static void dissect_nvme_security_data(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree,
                                       struct nvme_cmd_ctx *cmd_ctx,
                                       unsigned off, unsigned len,
                                       enum nvme_data_direction dir,
                                       bool level0_prefix)
{
    bool is_send = dir == NVME_DATA_DIR_HOST_TO_CONTROLLER;
    uint32_t xfer_len = cmd_ctx->cmd_ctx.security.xfer_len;
    bool partial = is_send && xfer_len != 0 && len < xfer_len;
    proto_item *ti;

    if ((uint64_t)off + len > xfer_len) {
        ti = proto_tree_add_item(tree, hf_nvme_security_data, tvb, 0, len, ENC_NA);
        expert_add_info_format(pinfo, ti, &ei_nvme_security_length,
                               "Security data window [%u, %" PRIu64
                               ") exceeds %s %u; payload left raw",
                               off, (uint64_t)off + len,
                               is_send ? "TL" : "AL", xfer_len);
        return;
    }

    if (off == 0 && len > 0 && !partial) {
        struct nvme_security_info sec = nvme_security_info_of(cmd_ctx, is_send);
        tvbuff_t *sec_tvb = tvb_new_subset_length(tvb, 0, len);

        sec.level0_prefix = !is_send && level0_prefix;
        if (is_send && sec.state_valid && !PINFO_FD_VISITED(pinfo) &&
            !sec.request_frame) {
            /* Several Sends can end in one frame: tell them apart, counting
             * in the frame's own dissection. */
            unsigned ordinal = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo,
                                                proto_nvme, NVME_SEC_SEND_ORDINAL_KEY));

            p_set_proto_data(pinfo->pool, pinfo, proto_nvme, NVME_SEC_SEND_ORDINAL_KEY,
                             GUINT_TO_POINTER(ordinal + 1));
            cmd_ctx->cmd_ctx.security.request_frame = sec.request_frame = pinfo->num;
            cmd_ctx->cmd_ctx.security.request_ordinal = sec.request_ordinal = (uint16_t)ordinal;
        }
        if (sec.secp == 0x00) {
            if (!sec.send &&
                dissect_nvme_security_info_resp(sec_tvb, tree, cmd_ctx, len))
                return;
        } else if (dissector_try_uint_with_data(nvme_security_secp_table, sec.secp,
                                         sec_tvb, pinfo, tree, true, &sec))
            return;
    }
    proto_tree_add_bytes_format_value(tree, hf_nvme_security_data, tvb, 0, len, NULL,
                                      "NVMe Security Protocol Data (offset %u, %u bytes)", off, len);
}

/* Base 2.4 Figure 446. */
static const range_string ns_mgmt_sel_rvals[] = {
    { 0x0, 0x0, "Create" },
    { 0x1, 0x1, "Delete" },
    { 0x2, 0x2, "Restore Default Namespace Configuration" },
    { 0x3, 0xf, "Reserved" },
    { 0, 0, NULL }
};

/* Base 2.4 Figure 443. */
static const range_string ns_attach_sel_rvals[] = {
    { 0x0, 0x0, "Controller Attach" },
    { 0x1, 0x1, "Controller Detach" },
    { 0x2, 0xf, "Reserved" },
    { 0, 0, NULL }
};

/* Base 2.4 Figure 587. */
static const range_string vm_act_rvals[] = {
    { 0x0, 0x0, "Reserved" },
    { 0x1, 0x1, "Primary Controller Flexible Allocation" },
    { 0x2, 0x6, "Reserved" },
    { 0x7, 0x7, "Secondary Controller Offline" },
    { 0x8, 0x8, "Secondary Controller Assign" },
    { 0x9, 0x9, "Secondary Controller Online" },
    { 0xa, 0xf, "Reserved" },
    { 0, 0, NULL }
};

static const range_string vm_rt_rvals[] = {
    { 0x0, 0x0, "VQ Resources" },
    { 0x1, 0x1, "VI Resources" },
    { 0x2, 0x7, "Reserved" },
    { 0, 0, NULL }
};

/* Base 2.4 Figure 162. */
static const range_string cap_oper_rvals[] = {
    { 0x0, 0x0, "Select Capacity Configuration" },
    { 0x1, 0x1, "Create Endurance Group" },
    { 0x2, 0x2, "Delete Endurance Group" },
    { 0x3, 0x3, "Create NVM Set" },
    { 0x4, 0x4, "Delete NVM Set" },
    { 0x5, 0x5, "Restore Default Capacity Management Configuration" },
    { 0x6, 0xf, "Reserved" },
    { 0, 0, NULL }
};

/* Base 2.4 Figure 375. */
static const range_string export_recv_sel_rvals[] = {
    { 0x00, 0x00, "Create Exported NVM Subsystem" },
    { 0x01, 0x01, "List Exported NVM Subsystems" },
    { 0x02, 0x02, "List Exported Namespaces" },
    { 0x03, 0x03, "List Exported Controllers" },
    { 0x04, 0x04, "List Exported Ports" },
    { 0x05, 0x05, "Get Exported NVM Subsystem Configuration State" },
    { 0x06, 0xbf, "Reserved" },
    { 0xc0, 0xff, "Vendor Specific" },
    { 0, 0, NULL }
};

/* Base 2.4 Figure 397. */
static const range_string export_send_sel_rvals[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Delete" },
    { 0x02, 0x02, "Change Access Mode" },
    { 0x03, 0x03, "Grant Host Access" },
    { 0x04, 0x04, "Revoke Host Access" },
    { 0x05, 0x05, "Associate Controllers" },
    { 0x06, 0x06, "Set Exported Configuration State" },
    { 0x07, 0xbf, "Reserved" },
    { 0xc0, 0xff, "Vendor Specific" },
    { 0, 0, NULL }
};

/* Base 2.4 Figure 369. */
static const range_string export_ns_sel_rvals[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Associate Namespace" },
    { 0x02, 0x02, "Disassociate Namespace" },
    { 0x03, 0xff, "Reserved" },
    { 0, 0, NULL }
};

/* Base 2.4 Figure 618. */
static const range_string export_port_sel_rvals[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Create" },
    { 0x02, 0x02, "Delete" },
    { 0x03, 0xff, "Reserved" },
    { 0, 0, NULL }
};

/* NVM CS 1.3 Figure 138. */
static const range_string lba_atype_rvals[] = {
    { 0x00, 0x01, "Reserved" },
    { 0x02, 0x02, "Return tracked allocated LBAs in the specified range" },
    { 0x03, 0x0f, "Reserved" },
    { 0x10, 0x10, "Perform a scan and return Untracked LBAs and Tracked LBAs in the specified range" },
    { 0x11, 0x11, "Return Tracked LBAs in the specified range" },
    { 0x12, 0xff, "Reserved" },
    { 0, 0, NULL }
};

/* Base 2.4 Figures 162-163, 369, 375, 383, 397, 443, 446, 587-588, 618;
 * NVM CS 1.3 Figures 136-138.  A dword with no decoded field stays raw. */
static void
dissect_nvme_admin_fields(tvbuff_t *tvb, proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx)
{
    uint8_t sel = tvb_get_uint8(tvb, 40);
    unsigned decoded = 0x01;

    switch (cmd_ctx->opcode) {
    case NVME_AQ_OPC_NS_MGMT:
        cmd_ctx->cmd_ctx.admin_mgmt.sel = sel & 0x0f;
        proto_tree_add_item(tree, hf_nvme_admin_ns_mgmt_sel, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        /* Figure 447: CSI applies to the Create operation only. */
        if (!(sel & 0x0f)) {
            proto_tree_add_item(tree, hf_nvme_admin_ns_csi, tvb, 44, 4, ENC_LITTLE_ENDIAN);
            decoded |= 0x02;
        }
        break;
    case NVME_AQ_OPC_NS_ATTACH:
        proto_tree_add_item(tree, hf_nvme_admin_ns_attach_sel, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_AQ_OPC_VIRT_MGMT:
        cmd_ctx->cmd_ctx.admin_mgmt.sel = sel & 0x0f;
        proto_tree_add_item(tree, hf_nvme_admin_vm_act, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_vm_rt, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_vm_cntlid, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_vm_nr, tvb, 44, 4, ENC_LITTLE_ENDIAN);
        decoded |= 0x02;
        break;
    case NVME_AQ_OPC_CAP_MGMT:
        cmd_ctx->cmd_ctx.admin_mgmt.sel = sel & 0x0f;
        proto_tree_add_item(tree, hf_nvme_admin_cap_oper, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_cap_elid, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        /* Figures 163-164: CAPL/CAPU apply to the two Create operations. */
        if ((sel & 0x0f) == 1 || (sel & 0x0f) == 3) {
            proto_tree_add_item(tree, hf_nvme_admin_cap_capacity, tvb, 44, 8, ENC_LITTLE_ENDIAN);
            decoded |= 0x06;
        }
        break;
    case NVME_AQ_OPC_CREATE_EXP_NVM_SUBSYS:
        proto_tree_add_item(tree, hf_nvme_admin_export_recv_sel, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        /* Figure 383: RA is the MOS of Create Exported NVM Subsystem only. */
        if (sel == 0)
            proto_tree_add_item(tree, hf_nvme_admin_export_ra, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_AQ_OPC_MANAGE_EXP_NVM_SUBSYS:
        proto_tree_add_item(tree, hf_nvme_admin_export_subsys_sel, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        if (sel == 2)
            proto_tree_add_item(tree, hf_nvme_admin_export_ra, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_AQ_OPC_MANAGE_EXP_NS:
        proto_tree_add_item(tree, hf_nvme_admin_export_ns_sel, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_AQ_OPC_MANAGE_EXP_PORT:
        proto_tree_add_item(tree, hf_nvme_admin_export_port_sel, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_AQ_OPC_GET_LBA_STATUS:
        proto_tree_add_item(tree, hf_nvme_admin_lba_slba, tvb, 40, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_lba_mndw, tvb, 48, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_lba_atype, tvb, 52, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_lba_rl, tvb, 52, 4, ENC_LITTLE_ENDIAN);
        decoded = 0x0f;
        break;
    case NVME_AQ_OPC_SANITIZE_NS:
        proto_tree_add_item(tree, hf_nvme_admin_sanns_act, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_sanns_ause, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_sanns_preq, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_sanns_rsvd[0], tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_sanns_emvs, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_admin_sanns_rsvd[1], tvb, 40, 4, ENC_LITTLE_ENDIAN);
        break;
    default:
        decoded = 0;
        break;
    }
    dissect_nvme_raw_cdws(tvb, tree, decoded);
}

void
nvme_dissect_admin_sqe_cdws(tvbuff_t *sqe_tvb, packet_info *pinfo,
                            proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx)
{
    switch (cmd_ctx->opcode) {
    case NVME_AQ_OPC_IDENTIFY:
        /* CNS is one byte (CDW10 07:00); byte 41 is reserved */
        cmd_ctx->cmd_ctx.cmd_identify.cns = tvb_get_uint8(sqe_tvb, 40);
        cmd_ctx->cmd_ctx.cmd_identify.csi = tvb_get_uint8(sqe_tvb, 47);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", val_to_str_const(cmd_ctx->cmd_ctx.cmd_identify.cns, cns_table, "Unknown"));
        dissect_nvme_identify_cmd(sqe_tvb, tree);
        break;
    case NVME_AQ_OPC_GET_LOG_PAGE:
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", get_logpage_name_csi(tvb_get_uint8(sqe_tvb, 40), tvb_get_uint8(sqe_tvb, 59)));
        dissect_nvme_get_logpage_cmd(sqe_tvb, pinfo, tree, cmd_ctx);
        break;
    case NVME_AQ_OPC_SET_FEATURES:
        dissect_nvme_set_features_cmd(sqe_tvb, tree, cmd_ctx);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s",
                            get_feature_id_name(cmd_ctx->cmd_ctx.set_features.fid));
        break;
    case NVME_AQ_OPC_GET_FEATURES:
        dissect_nvme_get_features_cmd(sqe_tvb, pinfo, tree, cmd_ctx);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s",
                            get_feature_id_name(cmd_ctx->cmd_ctx.set_features.fid));
        break;
    case NVME_AQ_OPC_FW_COMMIT:
        dissect_nvme_fw_commit_cmd(sqe_tvb, tree);
        break;
    case NVME_AQ_OPC_FW_IMG_DOWNLOAD:
        dissect_nvme_fw_download_cmd(sqe_tvb, tree);
        break;
    case NVME_AQ_OPC_SELF_TEST:
        dissect_nvme_self_test_cmd(sqe_tvb, tree);
        break;
    case NVME_AQ_OPC_LOCKDOWN:
        dissect_nvme_lockdown_cmd(sqe_tvb, tree);
        break;
    case NVME_AQ_OPC_FORMAT_NVM:
        dissect_nvme_format_nvm_cmd(sqe_tvb, tree);
        break;
    case NVME_AQ_OPC_SANITIZE:
        dissect_nvme_sanitize_cmd(sqe_tvb, tree);
        break;
    case NVME_AQ_OPC_SECURITY_SEND:
        dissect_nvme_security_cmd(sqe_tvb, pinfo, tree, cmd_ctx, hf_nvme_security_send_dword11_tl);
        break;
    case NVME_AQ_OPC_SECURITY_RECV:
        dissect_nvme_security_cmd(sqe_tvb, pinfo, tree, cmd_ctx, hf_nvme_security_recv_dword11_al);
        break;
    case NVME_AQ_OPC_NS_MGMT:
    case NVME_AQ_OPC_NS_ATTACH:
    case NVME_AQ_OPC_VIRT_MGMT:
    case NVME_AQ_OPC_CAP_MGMT:
    case NVME_AQ_OPC_CREATE_EXP_NVM_SUBSYS:
    case NVME_AQ_OPC_MANAGE_EXP_NVM_SUBSYS:
    case NVME_AQ_OPC_MANAGE_EXP_NS:
    case NVME_AQ_OPC_MANAGE_EXP_PORT:
    case NVME_AQ_OPC_GET_LBA_STATUS:
    case NVME_AQ_OPC_SANITIZE_NS:
        dissect_nvme_admin_fields(sqe_tvb, tree, cmd_ctx);
        break;
    default:
        dissect_nvme_unhandled_cmd(sqe_tvb, tree);
        break;
    }
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

    opc_item = proto_tree_add_item_ret_uint8(cmd_tree, hf_nvme_cmd_opc, nvme_tvb,
                        0, 1, ENC_LITTLE_ENDIAN, &cmd_ctx->opcode);
    if (q_ctx->qid) {
        proto_item_append_text(opc_item, " %s", get_ioq_opcode_name(cmd_ctx->opcode));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMe %s", get_ioq_opcode_name(cmd_ctx->opcode));
    } else {
        proto_item_append_text(opc_item, " %s", get_aq_opcode_name(cmd_ctx->opcode));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMe %s", get_aq_opcode_name(cmd_ctx->opcode));
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
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword2, nvme_tvb,
                        8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_dword3, nvme_tvb,
                        12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_mptr, nvme_tvb,
                        16, 8, ENC_LITTLE_ENDIAN);

    dissect_nvme_cmd_sgl(nvme_tvb, cmd_tree, hf_nvme_cmd_sgl, q_ctx, cmd_ctx, 0, PINFO_FD_VISITED(pinfo));

    if (q_ctx->qid) { //IOQ
        switch (cmd_ctx->opcode) {
        case NVME_IOQ_OPC_READ:
        case NVME_IOQ_OPC_WRITE:
            dissect_nvme_rw_cmd(nvme_tvb, cmd_tree,
                                cmd_ctx->opcode == NVME_IOQ_OPC_WRITE);
            break;
        default:
            dissect_nvme_unhandled_cmd(nvme_tvb, cmd_tree);
            break;
        }
    } else { //AQ
        nvme_dissect_admin_sqe_cdws(nvme_tvb, pinfo, cmd_tree, cmd_ctx);
    }
}

const char *nvme_get_opcode_string(uint8_t opcode, uint16_t qid)
{
    if (qid)
        return get_ioq_opcode_name(opcode);
    else
        return get_aq_opcode_name(opcode);
}

const char *
nvme_get_admin_opcode_string(uint8_t opcode, uint8_t csi)
{
    /* Base 2.3 Figures 142 and 327: the CSI-specific Admin commands. */
    switch (opcode) {
    case NVME_AQ_OPC_GET_LBA_STATUS:
        if (csi >= 0x30 && csi <= 0x3f)
            return "Vendor Specific I/O Command Set";
        return (csi == 0 || csi == 2) ? get_aq_opcode_name(opcode) : "Reserved";
    case NVME_AQ_OPC_LOAD_PROGRAM:
    case NVME_AQ_OPC_PROG_ACTIVATION_MGMT:
    case NVME_AQ_OPC_MEM_RANGE_SET_MGMT:
        if (csi >= 0x30 && csi <= 0x3f)
            return "Vendor Specific I/O Command Set";
        return csi == 4 ? get_aq_opcode_name(opcode) : "Reserved";
    default:
        return get_aq_opcode_name(opcode);
    }
}

/* Whether the command at off shows an Admin queue: an Admin-only opcode,
 * a Property Get/Set, or an Admin/I-O shared opcode with NSID 0h (Base 2.3
 * Figures 142, 574, 589; NVM CS 1.2 Figure 21). A heuristic. */
bool
nvme_cmd_implies_admin_queue(tvbuff_t *tvb, unsigned off)
{
    uint8_t opcode = tvb_get_uint8(tvb, off);

    switch (opcode) {
    case NVME_FABRIC_OPC:
        if (!tvb_bytes_exist(tvb, off + 4, 1))
            return false;
        switch (tvb_get_uint8(tvb, off + 4)) {
        case NVME_FCTYPE_PROP_SET:
        case NVME_FCTYPE_PROP_GET:
            return true;
        default:
            return false;
        }
    case NVME_AQ_OPC_ASYNC_EVE_REQ:     /* Verify */
    case NVME_AQ_OPC_KEEP_ALIVE:        /* Cancel */
    case NVME_AQ_OPC_MI_SEND:           /* I/O Management Send */
    case NVME_AQ_OPC_SANITIZE:          /* I/O vendor specific */
        return tvb_bytes_exist(tvb, off + 4, 4) &&
               tvb_get_uint32(tvb, off + 4, ENC_LITTLE_ENDIAN) == 0;
    default:
        return opcode < 0x80 && !nvme_admin_opcode_is_reserved(opcode) &&
               try_val_to_str(opcode, ioq_opc_tbl) == NULL;
    }
}

static const char *get_cqe_sc_string(unsigned sct, unsigned sc, bool nvmeof)
{
    switch (sct) {
        case NVME_CQE_SCT_GENERIC: return rval_to_str_const(sc, nvme_cqe_sc_gen_tbl, "Unknown Status Code");
        case NVME_CQE_SCT_COMMAND: return (nvmeof) ? val_to_str_const(sc, nvmeof_cqe_sc_cmd_tbl, "Unknown Fabrics Status Code") :
            rval_to_str_const(sc, nvme_cqe_sc_cmd_tbl, "Unknown Status Code");
        case NVME_CQE_SCT_MEDIA: return rval_to_str_const(sc, nvme_cqe_sc_media_tbl, "Unknown Status Code");
        case NVME_CQE_SCT_PATH: return rval_to_str_const(sc, nvme_cqe_sc_path_tbl, "Unknown Status Code");
        case NVME_CQE_SCT_VENDOR: return "Vendor Specific";
        default: return "Unknown Status Code";
    }
}

static const value_string nvme_cqe_aev_aet_dword0_tbl[] = {
    { 0x0, "Error status" },
    { 0x1, "SMART / Health status" },
    { 0x2, "Notice" },
    { 0x3, "Immediate" },
    { 0x4, "One-Shot" },
    { 0x6, "IO Command Set specific status" },
    { 0x7, "Vendor specific" },
    { 0, NULL },
};

static const value_string nvme_cqe_aev_status_error_tbl[] = {
    { 0x0, "Write to Invalid Doorbell Register" },
    { 0x1, "Invalid Doorbell Write Value" },
    { 0x2, "Diagnostic Failure" },
    { 0x3, "Persistent Internal Error"},
    { 0x4, "Transient Internal Error"},
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
    { 0x0, "Attached Namespace Attribute Changed" },
    { 0x1, "Firmware Activation Starting" },
    { 0x2, "Telemetry Log Changed" },
    { 0x3, "Asymmetric Namespace Access Change" },
    { 0x4, "Predictable Latency Event Aggregate Log Change" },
    { 0x5, "LBA Status Information Alert" },
    { 0x6, "Endurance Group Event Aggregate Log Page Change" },
    { 0x7, "Reachability Group Change" },
    { 0x8, "Reachability Association Change" },
    { 0x9, "Allocated Namespace Attribute Changed" },
    { 0xA, "Rate Limiting Configuration Change" },
    { 0xEF, "Zone Descriptor Changed" },
    { 0xF0, "Discovery Log Page Change" },
    { 0xF1, "Host Discovery Log Page Change" },
    { 0xF2, "AVE Discovery Log Page Change" },
    { 0xF3, "Pull Model DDC Request" },
    { 0xF4, "Cross-Controller Reset Completed" },
    { 0xF5, "Lost Host Communication" },
    { 0, NULL },
};

static const value_string nvme_cqe_aev_status_nvm_tbl[] = {
    { 0x0, "Reservation Log Page Available" },
    { 0x1, "Sanitize Operation Completed" },
    { 0x2, "Sanitize Operation Completed With Unexpected Deallocation" },
    { 0x3, "Sanitize Operation Entered Media Verification State" },
    { 0, NULL },
};

/* NVMe Base 2.3 Figure 156: AET 011b event information. */
static const value_string nvme_cqe_aev_status_immediate_tbl[] = {
    { 0x0, "NVM Subsystem Normal Shutdown" },
    { 0x1, "Temperature Threshold Hysteresis Recovery" },
    { 0, NULL },
};

/* NVMe Base 2.3 Figure 157: AET 100b event information. */
static const value_string nvme_cqe_aev_status_oneshot_tbl[] = {
    { 0x0, "Controller Data Queue Tail Pointer" },
    { 0x1, "Controller Data Queue Full Error" },
    { 0x2, "Power Threshold Exceeded" },
    { 0, NULL },
};

static bool
dissect_nvme_feature_extra_cqe(tvbuff_t *tvb, proto_tree *tree, unsigned pos, unsigned fid)
{
    switch (fid) {
    case F_HOST_MEM_BUF: /* Base 2.3 Figure 483, not Set's MR/CTZ bits. */
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_ehm,
                              hf_nvme_feat_hmnare, hf_nvme_feat_hmnar, -1); break;
    case F_IO_CMD_SET_PROFILE:
        proto_tree_add_item(tree, hf_nvme_cmd_set_features_dword11_iocsp[1], tvb, pos, 4, ENC_LITTLE_ENDIAN); break;
    case F_SPINUP_CONTROL:
        proto_tree_add_item(tree, hf_nvme_feat_scs, tvb, pos, 4, ENC_LITTLE_ENDIAN); break;
    case F_POWER_LOSS_SIG_CONF:
        proto_tree_add_item(tree, hf_nvme_cmd_set_features_dword11_plsc[1], tvb, pos, 4, ENC_LITTLE_ENDIAN); break;
    case F_FDP: /* Figure 435: CDW12 value, not CDW11's ENDGID. */
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_fdpcidx, hf_nvme_feat_fdpe, -1, -1); break;
    case F_FDP_EVENTS:
        proto_tree_add_item(tree, hf_nvme_feat_noet, tvb, pos, 4, ENC_LITTLE_ENDIAN); break;
    case F_CTRL_DATA_QUEUE:
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_cdqid, hf_nvme_feat_etpt, -1, -1); break;
    case F_CONF_DEV_PERSONALITY: /* Figure 449: PPSC, not Set's CHPS. */
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_perid, hf_nvme_feat_perfs,
                              hf_nvme_feat_ppsc, hf_nvme_feat_pmdss); break;
    case F_POWER_LIMIT:
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_plv, hf_nvme_feat_pls, -1, -1); break;
    case F_POWER_THRESHOLD:
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_ptv, hf_nvme_feat_pts,
                              hf_nvme_feat_pmts, hf_nvme_feat_ept); break;
    case F_POWER_MEASUREMENT:
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_pm_smtr, hf_nvme_feat_pm_pmgn,
                              hf_nvme_feat_pm_pme, -1); break;
    case F_VOLTAGE_THRESHOLD: /* Base 2.4 Figure 525. */
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_vt_uvt, hf_nvme_feat_vt_ovt,
                              hf_nvme_feat_vt_evt, hf_nvme_feat_vt_vsens);
        proto_tree_add_item(tree, hf_nvme_feat_vt_rsvd, tvb, pos, 4, ENC_LITTLE_ENDIAN); break;
    case F_VOLTAGE_MEASUREMENT: /* Base 2.4 Figure 526. */
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_feat_vm_act, hf_nvme_feat_vm_rsvd, -1, -1); break;
    case F_BP_WRITE_PROT_CONF:
        nvme_add_dword_fields(tvb, tree, pos, hf_nvme_cmd_set_features_dword11_bpwpc[1],
                              hf_nvme_cmd_set_features_dword11_bpwpc[2], -1, -1); break;
    default:
        return false;
    }
    return true;
}

void nvme_dissect_admin_cqe_dw0(tvbuff_t *nvme_tvb, int dw0_off, proto_tree *cqe_tree,
                                uint16_t status, struct nvme_cmd_ctx *cmd_ctx)
{
    /* Success is SCT and SC both 0h (NVMe Base 2.3 Figures 96, 101-103). */
    bool cqe_success = ((status & 0xFFE) == 0);
    if (cmd_ctx->opcode == NVME_AQ_OPC_GET_FEATURES &&
        cmd_ctx->cmd_ctx.set_features.fid == F_FDP_EVENTS) {
        cmd_ctx->cmd_ctx.set_features.response_count_valid =
            cqe_success && cmd_ctx->cmd_ctx.set_features.sel < 3;
        if (cmd_ctx->cmd_ctx.set_features.response_count_valid)
            cmd_ctx->cmd_ctx.set_features.response_count = tvb_get_uint8(nvme_tvb, dw0_off);
    }

    /* Base 2.4 Figure 188 applies to every completion of either command. */
    if (cmd_ctx->opcode == NVME_AQ_OPC_FW_COMMIT ||
        cmd_ctx->opcode == NVME_AQ_OPC_FW_IMG_DOWNLOAD) {
        add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_fwc_dword0));
        return;
    }

    if (!cqe_success) {
        /* A failed completion's Dword 0 renders raw. */
        proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
        return;
    }

    switch (cmd_ctx->opcode) {
        case NVME_AQ_OPC_SET_FEATURES:
        {
            if (cmd_ctx->cmd_ctx.set_features.fid == F_NUM_OF_QUEUES)
                add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_dword0_sf_nq));
            /* Base 2.3 section 5.2.26.1.27: Dword 0 is Figure 456. */
            else if (cmd_ctx->cmd_ctx.set_features.fid == F_POWER_MEASUREMENT)
                nvme_add_dword_fields(nvme_tvb, cqe_tree, dw0_off, hf_nvme_feat_pm_smtr,
                                      hf_nvme_feat_pm_pmgn, hf_nvme_feat_pm_pme, -1);
            /* NVM CS 1.2 section 4.1.3.5: Set also reports the attributes in effect (Figure 99). */
            else if (cmd_ctx->cmd_ctx.set_features.fid == F_LBA_ST_INF_REP_INT)
                add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_lbasi));
            else
                proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            break;
        }
        case NVME_AQ_OPC_GET_FEATURES:
            /* Select 011b: Dword 0 is the supported capabilities (Figure 199). */
            if (cmd_ctx->cmd_ctx.set_features.sel == NVME_GET_FEATURES_SEL_SUPPORTED_CAPS) {
                add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_caps));
                break;
            }
            /* A reserved Select (Figure 196) gives Dword 0 no defined meaning. */
            if (cmd_ctx->cmd_ctx.set_features.sel > NVME_GET_FEATURES_SEL_SUPPORTED_CAPS) {
                proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
                break;
            }
            switch (cmd_ctx->cmd_ctx.set_features.fid) {
                case F_ARBITRATION: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_arb)); break;
                case F_POWER_MGMT: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_pm)); break;
                case F_LBA_RANGE_TYPE: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_lbart)); break;
                case F_TEMP_THRESHOLD: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_tt)); break;
                case F_ERROR_RECOVERY: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_erec)); break;
                case F_VOLATILE_WC: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_vwce)); break;
                case F_NUM_OF_QUEUES: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_nq)); break;
                case F_IRQ_COALESCING: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_irqc)); break;
                case F_IRQ_VECTOR_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_irqv)); break;
                case F_WRITE_ATOM_NORM: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_wan)); break;
                case F_ASYNC_EVENT_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_aec)); break;
                case F_AUTO_PS_TRANSITION: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_apst)); break;
                case F_KA_TIMER: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_kat)); break;
                case F_HOST_CNTL_THERM_MGMT: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_hctm)); break;
                case F_NO_POWER_STATE_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_nops)); break;
                case F_READ_REC_LEVEL_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_rrl)); break;
                case F_PRED_LAT_MODE_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_plmc)); break;
                case F_PRED_LAT_MODE_WIND: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_plmw)); break;
                case F_LBA_ST_INF_REP_INT: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_lbasi)); break;
                case F_SANITIZE_CON: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_san)); break;
                case F_END_GROUP_EV_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_eg)); break;
                case F_SW_PR_MARKER: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_swp)); break;
                case F_RSRV_NOT_MASK: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_rsrvn)); break;
                case F_RSRV_PRST: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_rsrvp)); break;
                case F_NS_WRITE_CONF: add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_get_features_dword0_nswp)); break;
                default:
                    if (!dissect_nvme_feature_extra_cqe(nvme_tvb, cqe_tree, dw0_off, cmd_ctx->cmd_ctx.set_features.fid))
                        proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
                    break;
            }
            break;
        case NVME_AQ_OPC_ASYNC_EVE_REQ:
        {
            proto_item *ti;
            proto_tree *grp;
            unsigned i;
            uint8_t aet;
            uint8_t aei;
            /* Event information table per AET (Base 2.3 Figures 152-157). */
            static const value_string *const aei_tbls[8] = {
                nvme_cqe_aev_status_error_tbl, nvme_cqe_aev_status_smart_tbl,
                nvme_cqe_aev_status_notice_tbl, nvme_cqe_aev_status_immediate_tbl,
                nvme_cqe_aev_status_oneshot_tbl, NULL, nvme_cqe_aev_status_nvm_tbl, NULL,
            };
            ti = proto_tree_add_item(cqe_tree, hf_nvme_cqe_aev_dword0[0], nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            grp =  proto_item_add_subtree(ti, ett_data);
            for (i = 1; i < 4; i++)
                ti = proto_tree_add_item(grp, hf_nvme_cqe_aev_dword0[i], nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            /* Asynchronous Event Information is CQE DW0 bits 15:08 (byte 1);
             * byte 2 is the Log Page Identifier. */
            aet = tvb_get_uint8(nvme_tvb, dw0_off) & 0x7;
            aei = tvb_get_uint8(nvme_tvb, dw0_off + 1);
            if (aei_tbls[aet])
                proto_item_append_text(ti, " (%s)", val_to_str_const(aei, aei_tbls[aet], "Unknown"));
            proto_tree_add_item(grp, hf_nvme_cqe_aev_dword0[4], nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(grp, hf_nvme_cqe_aev_dword0[5], nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            break;
        }
        case NVME_AQ_OPC_NS_MGMT:
            /* Base 2.4 Figure 450: NSID is reserved except for Create. */
            if (cmd_ctx->cmd_ctx.admin_mgmt.sel == 0)
                proto_tree_add_item(cqe_tree, hf_nvme_cqe_ns_mgmt_nsid, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            break;
        case NVME_AQ_OPC_CAP_MGMT:
            /* Base 2.4 Figure 166: CELID only for the two Create operations. */
            if (cmd_ctx->cmd_ctx.admin_mgmt.sel == 1 || cmd_ctx->cmd_ctx.admin_mgmt.sel == 3)
                add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_cap_mgmt_dword0));
            else
                proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            break;
        case NVME_AQ_OPC_VIRT_MGMT:
            /* Base 2.4 Figure 590: NRM for the Allocation and Assign actions. */
            if (cmd_ctx->cmd_ctx.admin_mgmt.sel == 1 || cmd_ctx->cmd_ctx.admin_mgmt.sel == 8)
                add_group_mask_entry(nvme_tvb, cqe_tree, dw0_off, 4, ASPEC(hf_nvme_cqe_virt_mgmt_dword0));
            else
                proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, dw0_off, 4, ENC_LITTLE_ENDIAN);
            break;
    }
}

/* Admin commands allowed over NVMe-MI (NVMe-MI 2.2 Figure 137) and the
 * Command Specific Status Codes defined for each: Base 2.4 Figure 104 joined
 * with the per-command figures (e.g. Figure 331 for Get Log Page), and NVM
 * CS 1.3 Figure 19 for 82h.  Where Figure 104 and a per-command figure
 * disagree on a value (Set Features 2Bh, Sanitize Namespace 3Ch), Figure 104
 * is used. */
static const uint8_t sc_get_log_page[] = { 0x09, 0x1f, 0x29 };
static const uint8_t sc_identify[] = { 0x2c };
static const uint8_t sc_set_features[] = { 0x0d, 0x0e, 0x0f, 0x14, 0x1f, 0x2b, 0x37, 0x3e };
static const uint8_t sc_get_features[] = { 0x1f, 0x37 };
static const uint8_t sc_ns_mgmt[] = { 0x0a, 0x15, 0x16, 0x1b, 0x24, 0x29 };
static const uint8_t sc_fw_commit[] = { 0x06, 0x07, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x14, 0x1e, 0x3d };
static const uint8_t sc_fw_download[] = { 0x14 };
static const uint8_t sc_self_test[] = { 0x1d };
static const uint8_t sc_ns_attach[] = { 0x18, 0x19, 0x1a, 0x1c, 0x25, 0x27, 0x29, 0x2a };
static const uint8_t sc_virt_mgmt[] = { 0x1f, 0x20, 0x21, 0x22 };
static const uint8_t sc_cap_mgmt[] = { 0x26, 0x2d };
static const uint8_t sc_lockdown[] = { 0x1f, 0x28 };
static const uint8_t sc_exp_resources[] = { 0x38 };
static const uint8_t sc_exp_subsys_send[] = { 0x35, 0x36, 0x42, 0x43, 0x44 };
static const uint8_t sc_format_nvm[] = { 0x0a, 0x82 };
static const uint8_t sc_sanitize[] = { 0x0b, 0x10, 0x11, 0x23, 0x39 };
static const uint8_t sc_sanitize_ns[] = { 0x0b, 0x10, 0x11, 0x3c };

static const struct {
    uint8_t opcode;
    const uint8_t *sc;
    unsigned count;
} nvme_admin_cmd_sc_map[] = {
#define NVME_ADMIN_SC(_opc_, _tbl_) { _opc_, _tbl_, array_length(_tbl_) }
    NVME_ADMIN_SC(NVME_AQ_OPC_GET_LOG_PAGE, sc_get_log_page),
    NVME_ADMIN_SC(NVME_AQ_OPC_IDENTIFY, sc_identify),
    NVME_ADMIN_SC(NVME_AQ_OPC_SET_FEATURES, sc_set_features),
    NVME_ADMIN_SC(NVME_AQ_OPC_GET_FEATURES, sc_get_features),
    NVME_ADMIN_SC(NVME_AQ_OPC_NS_MGMT, sc_ns_mgmt),
    NVME_ADMIN_SC(NVME_AQ_OPC_FW_COMMIT, sc_fw_commit),
    NVME_ADMIN_SC(NVME_AQ_OPC_FW_IMG_DOWNLOAD, sc_fw_download),
    NVME_ADMIN_SC(NVME_AQ_OPC_SELF_TEST, sc_self_test),
    NVME_ADMIN_SC(NVME_AQ_OPC_NS_ATTACH, sc_ns_attach),
    NVME_ADMIN_SC(NVME_AQ_OPC_VIRT_MGMT, sc_virt_mgmt),
    NVME_ADMIN_SC(NVME_AQ_OPC_CAP_MGMT, sc_cap_mgmt),
    NVME_ADMIN_SC(NVME_AQ_OPC_LOCKDOWN, sc_lockdown),
    { NVME_AQ_OPC_CLEAR_EXP_NVM_CFG, NULL, 0 },
    NVME_ADMIN_SC(NVME_AQ_OPC_CREATE_EXP_NVM_SUBSYS, sc_exp_resources),
    NVME_ADMIN_SC(NVME_AQ_OPC_MANAGE_EXP_NVM_SUBSYS, sc_exp_subsys_send),
    NVME_ADMIN_SC(NVME_AQ_OPC_MANAGE_EXP_NS, sc_exp_resources),
    { NVME_AQ_OPC_MANAGE_EXP_PORT, NULL, 0 },
    NVME_ADMIN_SC(NVME_AQ_OPC_FORMAT_NVM, sc_format_nvm),
    { NVME_AQ_OPC_SECURITY_SEND, NULL, 0 },
    { NVME_AQ_OPC_SECURITY_RECV, NULL, 0 },
    NVME_ADMIN_SC(NVME_AQ_OPC_SANITIZE, sc_sanitize),
    { NVME_AQ_OPC_GET_LBA_STATUS, NULL, 0 },
    NVME_ADMIN_SC(NVME_AQ_OPC_SANITIZE_NS, sc_sanitize_ns),
#undef NVME_ADMIN_SC
};

/* True when a Command Specific sc is defined but not for this Admin opcode.
 * Reserved, Directive Specific and Vendor Specific codes, and opcodes outside
 * the table, are never reported. */
static bool
nvme_admin_sc_undefined_for_cmd(uint8_t opcode, unsigned sc)
{
    unsigned i, j;

    if ((sc > 0x44 && sc < 0x80) || sc >= 0xc0)
        return false;
    for (i = 0; i < array_length(nvme_admin_cmd_sc_map); i++) {
        if (nvme_admin_cmd_sc_map[i].opcode != opcode)
            continue;
        for (j = 0; j < nvme_admin_cmd_sc_map[i].count; j++)
            if (nvme_admin_cmd_sc_map[i].sc[j] == sc)
                return false;
        return true;
    }
    return false;
}

static void
dissect_nvme_cqe_status_word(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *cqe_tree,
                             unsigned status_off, bool nvmeof, int admin_opcode)
{
    proto_item *ti;
    proto_tree *grp;
    uint16_t val;
    unsigned i, sct, sc;

    ti = proto_tree_add_item_ret_uint16(cqe_tree, hf_nvme_cqe_status[0], nvme_tvb, status_off, 2, ENC_LITTLE_ENDIAN, &val);
    /* SC (08:01) or SCT (11:09) nonzero means the command did not complete
     * successfully.  Phase Tag, CRD, M and DNR are deliberately excluded --
     * none of them indicates failure. */
    if (val & 0xFFE)
        expert_add_info(pinfo, ti, &ei_nvme_cqe_status_error);
    grp =  proto_item_add_subtree(ti, ett_data);
    if (nvmeof)
        proto_tree_add_item(grp, hf_nvme_cqe_status_rsvd, nvme_tvb, status_off, 2, ENC_LITTLE_ENDIAN);
    else
        proto_tree_add_item(grp, hf_nvme_cqe_status[1], nvme_tvb, status_off, 2, ENC_LITTLE_ENDIAN);

    sct = (val & 0xE00) >> 9;
    sc = (val & 0x1FE) >> 1;
    ti = proto_tree_add_item(grp, hf_nvme_cqe_status[2], nvme_tvb, status_off, 2, ENC_LITTLE_ENDIAN);
    if (admin_opcode == NVME_AQ_OPC_SANITIZE_NS &&
        sct == NVME_CQE_SCT_COMMAND && sc == 0x12) {
        proto_item *note_it;

        proto_item_append_text(ti, " (Sanitize Namespace - Command Specific Status Values: Request Exceeds Maximum Namespace Sanitize Operations In Progress)");
        /* A disagreement between two figures, not a fault in the packet. */
        note_it = proto_tree_add_string(grp, hf_nvme_cqe_sc_note, nvme_tvb, status_off, 2,
                                        "NVMe Base 'Sanitize Namespace - Command Specific Status Values' lists Request Exceeds Maximum Namespace Sanitize Operations In Progress; 'Status Code - Command Specific Status Values' assigns this status to 3Ch");
        proto_item_set_generated(note_it);
    } else if (admin_opcode >= 0 && sct == NVME_CQE_SCT_COMMAND &&
        nvme_admin_sc_undefined_for_cmd((uint8_t)admin_opcode, sc)) {
        const char *cmd = get_aq_opcode_name((uint8_t)admin_opcode);
        const char *name = get_cqe_sc_string(sct, sc, false);

        proto_item_append_text(ti, " (Undefined for %s; %s for other commands)", cmd, name);
        expert_add_info_format(pinfo, ti, &ei_nvme_cqe_sc_undefined_for_cmd,
                               "Command Specific Status %02Xh (%s) is not defined for %s (%s)",
                               sc, name, cmd,
                               sc >= 0x80 ? "NVM Command Set 'Status Code - Command Specific Status Values'" :
                                            "NVMe Base 'Status Code - Command Specific Status Values'");
    } else {
        proto_item_append_text(ti, " (%s)", get_cqe_sc_string(sct, sc, nvmeof));
    }

    for (i = 3; i < array_length(hf_nvme_cqe_status); i++)
        proto_tree_add_item(grp, hf_nvme_cqe_status[i], nvme_tvb, status_off, 2, ENC_LITTLE_ENDIAN);
}

void nvme_dissect_cqe_status(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *cqe_tree, unsigned status_off, bool nvmeof)
{
    dissect_nvme_cqe_status_word(nvme_tvb, pinfo, cqe_tree, status_off, nvmeof, -1);
}

void nvme_dissect_admin_cqe_status(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *cqe_tree,
                                   unsigned status_off, uint8_t opcode)
{
    dissect_nvme_cqe_status_word(nvme_tvb, pinfo, cqe_tree, status_off, false, opcode);
}

void nvme_dissect_admin_cqe_dw1(tvbuff_t *nvme_tvb, int dw1_off, proto_tree *cqe_tree,
                                uint16_t status, struct nvme_cmd_ctx *cmd_ctx)
{
    /* Base 2.4 Figures 515 and 519: only a successful Get Features for the
     * Lockdown Persistence Personality defines Dword 1; SEL 011b and the
     * reserved SELs (Figure 198) do not. */
    if (cmd_ctx->opcode == NVME_AQ_OPC_GET_FEATURES &&
        cmd_ctx->cmd_ctx.set_features.fid == F_CONF_DEV_PERSONALITY &&
        cmd_ctx->cmd_ctx.set_features.sel < NVME_GET_FEATURES_SEL_SUPPORTED_CAPS &&
        (cmd_ctx->cmd_ctx.set_features.cdw13 & 0xff) == 0x02 &&
        (status & 0xFFE) == 0)
        nvme_add_dword_fields(nvme_tvb, cqe_tree, dw1_off, hf_nvme_cqe_cdp_ldps,
                              hf_nvme_cqe_cdp_rsvd, -1, -1);
}

static void dissect_nvme_cqe_common(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *cqe_tree, unsigned off, bool nvmeof)
{
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_sqhd, nvme_tvb, off+8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_sqid, nvme_tvb, off+10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_cid, nvme_tvb, off+12, 2, ENC_LITTLE_ENDIAN);
    nvme_dissect_cqe_status(nvme_tvb, pinfo, cqe_tree, off+14, nvmeof);
}

void dissect_nvme_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx)
{
    proto_tree *cqe_tree;
    proto_item *ti;

    if (q_ctx->qid)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMe CQE for %s", get_ioq_opcode_name(cmd_ctx->opcode));
    else
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "| ", "NVMe CQE for %s", get_aq_opcode_name(cmd_ctx->opcode));

    if (!q_ctx->qid) {
        if (cmd_ctx->opcode == NVME_AQ_OPC_IDENTIFY)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", val_to_str_const(cmd_ctx->cmd_ctx.cmd_identify.cns, cns_table, "Unknown"));
        else if (cmd_ctx->opcode == NVME_AQ_OPC_GET_LOG_PAGE)
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%s", get_logpage_name_csi(cmd_ctx->cmd_ctx.get_logpage.lid, cmd_ctx->cmd_ctx.get_logpage.csi));
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
    ti = proto_tree_add_item(root_tree, proto_nvme, nvme_tvb, 0,
                             NVME_CQE_SIZE, ENC_NA);
    proto_item_append_text(ti, " (Cqe)");
    cqe_tree = proto_item_add_subtree(ti, ett_data);

    nvme_publish_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_cmd_pkt, cmd_ctx);
    nvme_publish_cmd_latency(cqe_tree, cmd_ctx, hf_nvme_cmd_latency);

    /* DW0 decoding is for the Admin queue (qid 0) only. */
    if (!q_ctx->qid)
        nvme_dissect_admin_cqe_dw0(nvme_tvb, 0, cqe_tree,
                                   tvb_get_uint16(nvme_tvb, 14, ENC_LITTLE_ENDIAN), cmd_ctx);
    else
        proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword0, nvme_tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_dword1, nvme_tvb, 4, 4, ENC_LITTLE_ENDIAN);
    if (!q_ctx->qid)
        nvme_dissect_admin_cqe_dw1(nvme_tvb, 4, cqe_tree,
                                   tvb_get_uint16(nvme_tvb, 14, ENC_LITTLE_ENDIAN), cmd_ctx);
    dissect_nvme_cqe_common(nvme_tvb, pinfo, cqe_tree, 0, false);

    /* A Security Send that fails transferred no data (SIIS 1.20 Table 25):
     * tell the Security Protocol dissector, on the first pass only. */
    if (!q_ctx->qid && cmd_ctx->opcode == NVME_AQ_OPC_SECURITY_SEND &&
        cmd_ctx->cmd_ctx.security.request_frame && !PINFO_FD_VISITED(pinfo) &&
        (tvb_get_letohs(nvme_tvb, 14) & 0x0ffe)) {
        struct nvme_security_info sec = nvme_security_info_of(cmd_ctx, true);

        dissector_try_uint_with_data(nvme_security_send_failed_table, sec.secp,
                                     nvme_tvb, pinfo, NULL, false, &sec);
    }
}

void
proto_register_nvme(void)
{
    static hf_register_info hf[] = {
        { &hf_nvme_feat_scs, { "Spinup Control State (SCS)", "nvme.features.spinup.scs", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_attri, { "Attribute Index (ATTRI)", "nvme.features.perf.attri", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(feat_perf_attri_rvals), 0xff, NULL, HFILL } },
        { &hf_nvme_feat_rvspa, { "Revert Vendor Specific Performance Attribute (RVSPA)", "nvme.features.perf.rvspa", FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
        { &hf_nvme_feat_cdqid, { "Controller Data Queue Identifier (CDQID)", "nvme.features.cdq.id", FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL } },
        { &hf_nvme_feat_etpt, { "Enable Tail Pointer Trigger (ETPT)", "nvme.features.cdq.etpt", FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL } },
        { &hf_nvme_feat_hp, { "Head Pointer (HP)", "nvme.features.cdq.hp", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_tpt, { "Tail Pointer Trigger (TPT)", "nvme.features.cdq.tpt", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_fdpcidx, { "Flexible Data Placement Configuration Index (FDPCIDX)", "nvme.features.fdp.fdpcidx", FT_UINT32, BASE_DEC, NULL, 0xff00, NULL, HFILL } },
        { &hf_nvme_feat_fdpe, { "Flexible Data Placement Enable (FDPE)", "nvme.features.fdp.fdpe", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_fdpee, { "FDP Event Enable (FDPEE)", "nvme.features.fdpe.enable", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_hsize, { "Host Memory Buffer Size (HSIZE)", "nvme.features.hmb.hsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_hmdlal, { "Host Memory Descriptor List Address Lower (HMDLAL)", "nvme.features.hmb.hmdlal", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_hmdlau, { "Host Memory Descriptor List Address Upper (HMDLAU)", "nvme.features.hmb.hmdlau", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_hmdlec, { "Host Memory Descriptor List Entry Count (HMDLEC)", "nvme.features.hmb.hmdlec", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_ehm, { "Enable Host Memory (EHM)", "nvme.features.hmb.ehm", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_hmnare, { "Host Memory Non-operational Access Restriction Enable (HMNARE)", "nvme.features.hmb.hmnare", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_nvme_feat_hmnar, { "Host Memory Non-operational Access Restricted (HMNAR)", "nvme.features.hmb.hmnar", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_nvme_feat_perid, { "Personality Identifier (PERID)", "nvme.features.cdp.perid", FT_UINT32, BASE_HEX|BASE_RANGE_STRING, RVALS(perid_rvals), 0xff, NULL, HFILL } },
        { &hf_nvme_feat_perfs, { "Personality Freeze State (PERFS)", "nvme.features.cdp.perfs", FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
        { &hf_nvme_feat_chps, { "Change Personality Settings (CHPS)", "nvme.features.cdp.chps", FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
        { &hf_nvme_feat_ppsc, { "Pending Personality Settings Change (PPSC)", "nvme.features.cdp.ppsc", FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
        { &hf_nvme_feat_ldpe, { "Lockdown Persistence Enable (LDPE)", "nvme.features.cdp.ldpe", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_ldp_rsvd, { "Reserved", "nvme.features.cdp.ldp_rsvd", FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL } },
        { &hf_nvme_cqe_cdp_ldps, { "Lockdown Persistence State (LDPS)", "nvme.cqe.dword1.cdp.ldps", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_cqe_cdp_rsvd, { "Reserved", "nvme.cqe.dword1.cdp.rsvd", FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL } },
        { &hf_nvme_feat_pmdss, { "Personality Manufacturing Default Settings State (PMDSS)", "nvme.features.cdp.pmdss", FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
        { &hf_nvme_feat_plv, { "Power Limit Value (PLV)", "nvme.features.power.plv", FT_UINT32, BASE_DEC, NULL, 0xffff, NULL, HFILL } },
        { &hf_nvme_feat_pls, { "Power Limit Scale (PLS)", "nvme.features.power.pls", FT_UINT32, BASE_HEX, VALS(nvme_power_scale_vals), 0x00030000, NULL, HFILL } },
        { &hf_nvme_feat_ptv, { "Power Threshold Value (PTV)", "nvme.features.power.ptv", FT_UINT32, BASE_DEC, NULL, 0xffff, NULL, HFILL } },
        { &hf_nvme_feat_pts, { "Power Threshold Scale (PTS)", "nvme.features.power.pts", FT_UINT32, BASE_HEX, VALS(nvme_power_scale_vals), 0x00030000, NULL, HFILL } },
        { &hf_nvme_feat_pmts, { "Power Measurement Type Select (PMTS)", "nvme.features.power.pmts", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_power_meas_type_rvals), 0xf00000, NULL, HFILL } },
        { &hf_nvme_feat_ept, { "Enable Power Threshold (EPT)", "nvme.features.power.ept", FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL } },
        { &hf_nvme_feat_pm_act, { "Power Measurement Action (ACT)", "nvme.features.measurement.act", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(feat_pm_act_rvals), 0x0f, NULL, HFILL } },
        { &hf_nvme_feat_pm_type, { "Power Measurement Type Select (PMTS)", "nvme.features.measurement.pmts", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_power_meas_type_rvals), 0xf0, NULL, HFILL } },
        { &hf_nvme_feat_pm_smt, { "Stop Measurement Time (SMT)", "nvme.features.measurement.smt", FT_UINT32, BASE_DEC, NULL, 0xffff0000, NULL, HFILL } },
        { &hf_nvme_feat_pm_actsp, { "Action Specific (ACTSP)", "nvme.features.measurement.actsp", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_pm_smtr, { "Stop Measurement Time Remaining (SMTR)", "nvme.features.measurement.smtr", FT_UINT32, BASE_DEC, NULL, 0xffff0000, NULL, HFILL } },
        { &hf_nvme_feat_pm_pmgn, { "Power Measurement Generation Number (PMGN)", "nvme.features.measurement.pmgn", FT_UINT32, BASE_DEC, NULL, 0xff00, NULL, HFILL } },
        { &hf_nvme_feat_pm_pme, { "Power Measurement Enable (PME)", "nvme.features.measurement.pme", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_vt_uvt, { "Undervoltage Threshold (UVT)", "nvme.features.voltage.uvt", FT_UINT32, BASE_DEC, NULL, 0x00003fff, "Volts = UVT x the VOLSS scale of the selected Identify Controller voltage sensor", HFILL } },
        { &hf_nvme_feat_vt_ovt, { "Overvoltage Threshold (OVT)", "nvme.features.voltage.ovt", FT_UINT32, BASE_DEC, NULL, 0x0fffc000, "Volts = OVT x the VOLSS scale of the selected Identify Controller voltage sensor", HFILL } },
        { &hf_nvme_feat_vt_evt, { "Enable Voltage Threshold (EVT)", "nvme.features.voltage.evt", FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL } },
        { &hf_nvme_feat_vt_vsens, { "Voltage Sensor Select (VSENS)", "nvme.features.voltage.vsens", FT_UINT32, BASE_HEX, VALS(nvme_vsen_sel_vals), 0x60000000, NULL, HFILL } },
        { &hf_nvme_feat_vt_rsvd, { "Reserved", "nvme.features.voltage.rsvd", FT_UINT32, BASE_HEX, NULL, 0x80000000, NULL, HFILL } },
        { &hf_nvme_feat_vm_act, { "Voltage Measurement Action (ACT)", "nvme.features.vmeas.act", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_vm_act_rvals), 0x0000000f, NULL, HFILL } },
        { &hf_nvme_feat_vm_rsvd, { "Reserved", "nvme.features.vmeas.rsvd", FT_UINT32, BASE_HEX, NULL, 0xfffffff0, NULL, HFILL } },
        { &hf_nvme_feat_svm_lvolta[0], { "Log Voltage Threshold Attributes (LVOLTA)", "nvme.features.vmeas.lvolta", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_svm_lvolta[1], { "Voltage Sensor Selected (VSSEL)", "nvme.features.vmeas.lvolta.vssel", FT_UINT16, BASE_HEX, VALS(nvme_vsen_sel_vals), 0x0003, NULL, HFILL } },
        { &hf_nvme_feat_svm_lvolta[2], { "Voltage Measurement Log Threshold (VMLT)", "nvme.features.vmeas.lvolta.vmlt", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_nvme_feat_svm_lvolta[3], { "Reserved", "nvme.features.vmeas.lvolta.rsvd", FT_UINT16, BASE_HEX, NULL, 0xfff8, NULL, HFILL } },
        { &hf_nvme_feat_svm_svmt, { "Stop Voltage Measurement Time (SVMT)", "nvme.features.vmeas.svmt", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_minute_minutes), 0, NULL, HFILL } },
        { &hf_nvme_feat_svm_lvolt[0], { "Log Voltage Threshold (LVOLT)", "nvme.features.vmeas.lvolt", FT_UINT32, BASE_HEX, NULL, 0, "Ignored unless VMLT is set", HFILL } },
        { &hf_nvme_feat_svm_lvolt[1], { "Log Undervoltage Threshold (LUVT)", "nvme.features.vmeas.lvolt.luvt", FT_UINT32, BASE_DEC, NULL, 0x00003fff, NULL, HFILL } },
        { &hf_nvme_feat_svm_lvolt[2], { "Reserved", "nvme.features.vmeas.lvolt.rsvd0", FT_UINT32, BASE_HEX, NULL, 0x0000c000, NULL, HFILL } },
        { &hf_nvme_feat_svm_lvolt[3], { "Log Overvoltage Threshold (LOVT)", "nvme.features.vmeas.lvolt.lovt", FT_UINT32, BASE_DEC, NULL, 0x3fff0000, NULL, HFILL } },
        { &hf_nvme_feat_svm_lvolt[4], { "Reserved", "nvme.features.vmeas.lvolt.rsvd1", FT_UINT32, BASE_HEX, NULL, 0xc0000000, NULL, HFILL } },
        { &hf_nvme_feat_svm_rsvd, { "Reserved", "nvme.features.vmeas.rsvd_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_tid, { "Target Identifier (TID)", "nvme.features.ratelim.tid", FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_feat_rl_tgt, { "Target (TGT)", "nvme.features.ratelim.tgt", FT_UINT32, BASE_DEC | BASE_RANGE_STRING, RVALS(nvme_rl_tgt_rvals), 0x00ff0000, NULL, HFILL } },
        { &hf_nvme_feat_rl_rsvd, { "Reserved", "nvme.features.ratelim.rsvd", FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL } },
        { &hf_nvme_feat_rl_rlc[0], { "Rate Limits Control (RLC)", "nvme.features.ratelim.rlc", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_rlc[1], { "Rate Limiting Mode (RLM)", "nvme.features.ratelim.rlc.rlm", FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_rl_rlm_rvals), 0x000f, NULL, HFILL } },
        { &hf_nvme_feat_rl_rlc[2], { "Reserved", "nvme.features.ratelim.rlc.rsvd", FT_UINT16, BASE_HEX, NULL, 0x7ff0, NULL, HFILL } },
        { &hf_nvme_feat_rl_rlc[3], { "Rate Limiting Enable (RLE)", "nvme.features.ratelim.rlc.rle", FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL } },
        { &hf_nvme_feat_rl_rsvd0, { "Reserved", "nvme.features.ratelim.rsvd0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_bwsf, { "Bandwidth Scale Factor (BWSF)", "nvme.features.ratelim.bwsf", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_rl_bwsf_rvals), 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_tbwv, { "Total Bandwidth Value (TBWV)", "nvme.features.ratelim.tbwv", FT_UINT64, BASE_DEC, NULL, 0, "Bandwidth = value x the BWSF scale", HFILL } },
        { &hf_nvme_feat_rl_wbwv, { "Write Bandwidth Value (WBWV)", "nvme.features.ratelim.wbwv", FT_UINT64, BASE_DEC, NULL, 0, "Bandwidth = value x the BWSF scale", HFILL } },
        { &hf_nvme_feat_rl_tiops, { "Total IOPS (TIOPS)", "nvme.features.ratelim.tiops", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_wiops, { "Write IOPS (WIOPS)", "nvme.features.ratelim.wiops", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_riopsr, { "Read IOPS Ratio (RIOPSR)", "nvme.features.ratelim.wriopsr.riopsr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_wiopsr, { "Write IOPS Ratio (WIOPSR)", "nvme.features.ratelim.wriopsr.wiopsr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_rbwr, { "Read Bandwidth Ratio (RBWR)", "nvme.features.ratelim.wrbwr.rbwr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_wbwr, { "Write Bandwidth Ratio (WBWR)", "nvme.features.ratelim.wrbwr.wbwr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_rsvd1, { "Reserved", "nvme.features.ratelim.rsvd1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_rl_vs, { "Vendor Specific (VS)", "nvme.features.ratelim.vs", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_gdhm, { "Generate Default Host Metadata (GDHM)", "nvme.features.metadata.gdhm", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_noet, { "Number of FDP Event Types (NOET)", "nvme.features.fdpe.noet", FT_UINT32, BASE_DEC, NULL, 0xff, NULL, HFILL } },
        { &hf_nvme_feat_fdpet, { "FDP Event Type (FDPET)", "nvme.features.fdpe.type", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_fdpe_attr, { "FDP Event Enable (FDPEE)", "nvme.features.fdpe.enabled", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_feat_nsal, { "Namespace Admin Label (NSAL)", "nvme.features.nsal", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_emca, { "Embedded Management Controller Address (EMCA)", "nvme.features.emca", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_hmaa, { "Host Management Agent Address (HMAA)", "nvme.features.hmaa", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_hostid, { "Host Identifier (HOSTID)", "nvme.features.hostid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_hostid_rsvd, { "Reserved", "nvme.features.hostid.rsvd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_security_status[0], { "Security Protocol Status (SPS)", "nvme.features.cdp.security_status", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_security_status[1], { "Reserved", "nvme.features.cdp.security_status.rsvd0", FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_security_status[2], { "TCG Security Protocol Status (TCGPST)", "nvme.features.cdp.security_status.tcgpst", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_nvme_feat_security_status[3], { "Authentication in Host Attachments of Transient Storage Devices Protocol Status (AHATSDPS)", "nvme.features.cdp.security_status.ahatsdps", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_nvme_feat_security_status[4], { "Reserved", "nvme.features.cdp.security_status.rsvd", FT_UINT32, BASE_HEX, NULL, 0x0000fff8, NULL, HFILL } },
        { &hf_nvme_feat_security_status[5], { "Vendor Specific Protocols F0h-FFh", "nvme.features.cdp.security_status.vsp", FT_UINT32, BASE_HEX, NULL, 0xffff0000, "Bit n (from 0) is vendor-specific security protocol F0h+n", HFILL } },
        { &hf_nvme_feat_security_supported[0], { "Supported Security Protocol (SSP)", "nvme.features.cdp.security_supported", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_security_supported[1], { "Reserved", "nvme.features.cdp.security_supported.rsvd0", FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_security_supported[2], { "TCG Security Protocol Support (TCGPSUP)", "nvme.features.cdp.security_supported.tcgpsup", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_nvme_feat_security_supported[3], { "Authentication in Host Attachments of Transient Storage Devices Protocol Support (AHATSDPS)", "nvme.features.cdp.security_supported.ahatsdps", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_nvme_feat_security_supported[4], { "Reserved", "nvme.features.cdp.security_supported.rsvd", FT_UINT32, BASE_HEX, NULL, 0x0000fff8, NULL, HFILL } },
        { &hf_nvme_feat_security_supported[5], { "Vendor Specific Protocols F0h-FFh", "nvme.features.cdp.security_supported.vsp", FT_UINT32, BASE_HEX, NULL, 0xffff0000, "Bit n (from 0) is vendor-specific security protocol F0h+n", HFILL } },
        { &hf_nvme_feat_security_set[0], { "Security Personality Attributes", "nvme.features.cdp.security_attributes", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_security_set[1], { "Allow Security Protocol (ASP)", "nvme.features.cdp.security_attributes.asp", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_nvme_feat_security_set[2], { "TCG Security Protocol (TCGP)", "nvme.features.cdp.security_attributes.tcgp", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_nvme_feat_security_set[3], { "Authentication in Host Attachments of Transient Storage Devices Protocol (AHATSDP)", "nvme.features.cdp.security_attributes.ahatsdp", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_nvme_feat_security_set[4], { "Reserved", "nvme.features.cdp.security_attributes.rsvd", FT_UINT32, BASE_HEX, NULL, 0x0000fff8, NULL, HFILL } },
        { &hf_nvme_feat_security_set[5], { "Vendor Specific Protocols F0h-FFh", "nvme.features.cdp.security_attributes.vsp", FT_UINT32, BASE_HEX, NULL, 0xffff0000, "Bit n (from 0) is vendor-specific security protocol F0h+n", HFILL } },
        { &hf_nvme_feat_r4karl, { "Random 4 KiB Average Read Latency (R4KARL)", "nvme.features.perf.r4karl", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(feat_perf_r4karl_rvals), 0, NULL, HFILL } },
        { &hf_nvme_feat_attrtyp, { "Attribute Type (ATTRTYP)", "nvme.features.perf.attrtyp", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(feat_perf_attrtyp_rvals), 0x07, NULL, HFILL } },
        { &hf_nvme_feat_msvspa, { "Maximum Saveable Vendor Specific Performance Attributes (MSVSPA)", "nvme.features.perf.msvspa", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_usvspa, { "Unused Saveable Vendor Specific Performance Attributes (USVSPA)", "nvme.features.perf.usvspa", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_feat_paid, { "Performance Attribute Identifier", "nvme.features.perf.id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_reach_chngc, { "Reachability Change Count (CHNGC)", "nvme.cmd.get_logpage.reach.chngc", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_reach_count, { "Number of Reachability Descriptors", "nvme.cmd.get_logpage.reach.count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_reach_id, { "Reachability Group or Association Identifier", "nvme.cmd.get_logpage.reach.id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_reach_nids, { "Number of Member Identifiers", "nvme.cmd.get_logpage.reach.nids", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_reach_desc_chngc, { "Descriptor Change Count (CHNGC)", "nvme.cmd.get_logpage.reach.desc_chngc", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_reach_rac, { "Reachability Association Characteristics (RAC)", "nvme.cmd.get_logpage.reach.rac", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(reach_rac_rvals), 0, NULL, HFILL } },
        { &hf_nvme_reach_member, { "Member Namespace or Reachability Group Identifier", "nvme.cmd.get_logpage.reach.member", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_genctr, { "Generation Counter (GENCTR)", "nvme.cmd.get_logpage.hostdisc.genctr", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_numrec, { "Number of Records (NUMREC)", "nvme.cmd.get_logpage.hostdisc.numrec", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_recfmt, { "Record Format (RECFMT)", "nvme.cmd.get_logpage.hostdisc.recfmt", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_flags, { "Host Discovery Log Page Flags (HDLPF)", "nvme.cmd.get_logpage.hostdisc.flags", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_length, { "Total Host Discovery Log Page Length (THDLPL)", "nvme.cmd.get_logpage.hostdisc.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_nqn, { "Host NVMe Qualified Name (HOSTNQN)", "nvme.cmd.get_logpage.hostdisc.hostnqn", FT_STRINGZTRUNC, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_trtype, { "Transport Type (TRTYPE)", "nvme.cmd.get_logpage.hostdisc.trtype", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_adrfam, { "Address Family (ADRFAM)", "nvme.cmd.get_logpage.hostdisc.adrfam", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_ncc, { "No CDC Connectivity (NCC)", "nvme.cmd.get_logpage.hostdisc.ncc", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_nvme_hostdisc_tel, { "Total Entry Length (TEL)", "nvme.cmd.get_logpage.hostdisc.tel", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_hostdisc_numexat, { "Number of Extended Attributes (NUMEXAT)", "nvme.cmd.get_logpage.hostdisc.numexat", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_lbstm, { "Logical Block Storage Tag Mask (LBSTM)", "nvme.cmd.identify.nvm_ns.lbstm", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_pic[0], { "Protection Information Capabilities (PIC)", "nvme.cmd.identify.nvm_ns.pic", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_pic[1], { "Qualified Protection Information Format Support (QPIFS)", "nvme.cmd.identify.nvm_ns.pic.qpifs", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_nvme_id_pic[2], { "Storage Tag Check Read Support (STCRS)", "nvme.cmd.identify.nvm_ns.pic.stcrs", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_nvme_id_pic[3], { "16b Guard Protection Information Storage Tag Mask (PISTM16B)", "nvme.cmd.identify.nvm_ns.pic.pistm16b", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_id_pic[4], { "16b Guard Protection Information Storage Tag Support (PISTS16B)", "nvme.cmd.identify.nvm_ns.pic.pists16b", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_id_pic[5], { "Reserved", "nvme.cmd.identify.nvm_ns.pic.rsvd", FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL } },
        { &hf_nvme_id_pifa[0], { "Protection Information Format Attribute (PIFA)", "nvme.cmd.identify.nvm_ns.pifa", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_pifa[1], { "Storage Tag Masking Level Attribute (STMLA)", "nvme.cmd.identify.nvm_ns.pifa.stmla", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvm_ns_stmla_tbl), 0x07, NULL, HFILL } },
        { &hf_nvme_id_pifa[2], { "Reserved", "nvme.cmd.identify.nvm_ns.pifa.rsvd", FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL } },
        { &hf_nvme_id_elbaf[0], { "Extended LBA Format (ELBAF)", "nvme.cmd.identify.nvm_ns.elbaf", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_elbaf[1], { "Storage Tag Size (STS)", "nvme.cmd.identify.nvm_ns.sts", FT_UINT32, BASE_DEC, NULL, 0x7f, NULL, HFILL } },
        { &hf_nvme_id_elbaf[2], { "Protection Information Format (PIF)", "nvme.cmd.identify.nvm_ns.pif", FT_UINT32, BASE_HEX, VALS(nvm_ns_pif_tbl), 0x00000180, NULL, HFILL } },
        { &hf_nvme_id_elbaf[3], { "Qualified Protection Information Format (QPIF)", "nvme.cmd.identify.nvm_ns.qpif", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(nvm_ns_qpif_tbl), 0x1e00, NULL, HFILL } },
        { &hf_nvme_id_elbaf[4], { "Reserved", "nvme.cmd.identify.nvm_ns.elbaf.rsvd", FT_UINT32, BASE_HEX, NULL, 0xffffe000, NULL, HFILL } },
        { &hf_nvme_id_npdgl, { "Namespace Preferred Deallocate Granularity Large (NPDGL)", "nvme.cmd.identify.nvm_ns.npdgl", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nprg, { "Namespace Preferred Read Granularity (NPRG)", "nvme.cmd.identify.nvm_ns.nprg", FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0, NULL, HFILL } },
        { &hf_nvme_id_npra, { "Namespace Preferred Read Alignment (NPRA)", "nvme.cmd.identify.nvm_ns.npra", FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0, NULL, HFILL } },
        { &hf_nvme_id_nors, { "Namespace Optimal Read Size (NORS)", "nvme.cmd.identify.nvm_ns.nors", FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0, NULL, HFILL } },
        { &hf_nvme_id_npdal, { "Namespace Preferred Deallocate Alignment Large (NPDAL)", "nvme.cmd.identify.nvm_ns.npdal", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_lbapss, { "LBA Format Placement Shard Size (LBAPSS)", "nvme.cmd.identify.nvm_ns.lbapss", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_tlbaag, { "Tracked LBA Allocation Granularity (TLBAAG)", "nvme.cmd.identify.nvm_ns.tlbaag", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl[0], { "Verify Size Limit (VSL)", "nvme.cmd.identify.nvm_ctrl.vsl", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl[1], { "Write Zeroes Size Limit (WZSL)", "nvme.cmd.identify.nvm_ctrl.wzsl", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl[2], { "Write Uncorrectable Size Limit (WUSL)", "nvme.cmd.identify.nvm_ctrl.wusl", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl[3], { "Dataset Management Ranges Limit (DMRL)", "nvme.cmd.identify.nvm_ctrl.dmrl", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl[4], { "Dataset Management Range Size Limit (DMRSL)", "nvme.cmd.identify.nvm_ctrl.dmrsl", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl[5], { "Dataset Management Size Limit (DMSL)", "nvme.cmd.identify.nvm_ctrl.dmsl", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl[6], { "Write Zeroes With Deallocate Size Limit (WZDSL)", "nvme.cmd.identify.nvm_ctrl.wzdsl", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl[7], { "LBA Migration Queue Format (LBAMQF)", "nvme.cmd.identify.nvm_ctrl.lbamqf", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvm_ctrl_lbamqf_tbl), 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_kpiocap[0], { "Key Per I/O Capabilities (KPIOCAP)", "nvme.cmd.identify.nvm_ctrl.kpiocap", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_kpiocap[1], { "Key Per I/O Scope (KPIOSC)", "nvme.cmd.identify.nvm_ctrl.kpiocap.kpiosc", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_kpiocap[2], { "Key Per I/O Supported (KPIOS)", "nvme.cmd.identify.nvm_ctrl.kpiocap.kpios", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_kpiocap[3], { "Reserved", "nvme.cmd.identify.nvm_ctrl.kpiocap.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_aocs[0], { "Admin Optional Command Support (AOCS)", "nvme.cmd.identify.nvm_ctrl.aocs", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_aocs[1], { "Reporting Allocated LBA Supported (RALBAS)", "nvme.cmd.identify.nvm_ctrl.aocs.ralbas", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_aocs[2], { "Reserved", "nvme.cmd.identify.nvm_ctrl.aocs.rsvd", FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_rla[0], { "Rate Limiting Attributes (RLA)", "nvme.cmd.identify.nvm_ctrl.rla", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_rla[1], { "Hard Limit Support (HLS)", "nvme.cmd.identify.nvm_ctrl.rla.hls", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_rla[2], { "Soft Limit Support (SLS)", "nvme.cmd.identify.nvm_ctrl.rla.sls", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_rla[3], { "Reserved", "nvme.cmd.identify.nvm_ctrl.rla.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_slmc, { "Soft Limit Maximum Controllers (SLMC)", "nvme.cmd.identify.nvm_ctrl.slmc", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_ver[0], { "Version (VER)", "nvme.cmd.identify.nvm_ctrl.ver", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_ver[1], { "Major Version Number (MJR)", "nvme.cmd.identify.nvm_ctrl.ver.mjr", FT_UINT32, BASE_DEC, NULL, 0xffff0000, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_ver[2], { "Minor Version Number (MNR)", "nvme.cmd.identify.nvm_ctrl.ver.mnr", FT_UINT32, BASE_DEC, NULL, 0x0000ff00, NULL, HFILL } },
        { &hf_nvme_id_nvm_ctrl_ver[3], { "Tertiary Version Number (TER)", "nvme.cmd.identify.nvm_ctrl.ver.ter", FT_UINT32, BASE_DEC, NULL, 0x000000ff, NULL, HFILL } },
        { &hf_nvme_id_domain_num, { "Number of Domain Entries (NUMENT)", "nvme.cmd.identify.domain.num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_domain_id, { "Domain Identifier (DID)", "nvme.cmd.identify.domain.id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_domain_capacity[0], { "Total Domain Capacity (TDC)", "nvme.cmd.identify.domain.tdc", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_domain_capacity[1], { "Unallocated Domain Capacity (UDC)", "nvme.cmd.identify.domain.udc", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_domain_capacity[2], { "Max Endurance Group Domain Capacity (MEGDC)", "nvme.cmd.identify.domain.megdc", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_eg_num, { "Number of Endurance Group Identifiers (NEGIDS)", "nvme.cmd.identify.eg.num", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_eg_id, { "Endurance Group Identifier", "nvme.cmd.identify.eg.id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_iocsc[0], { "I/O Command Set Combination (IOCSC)", "nvme.cmd.identify.iocsc", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_iocsc[1], { "NVM Command Set (NVMCS)", "nvme.cmd.identify.iocsc.nvmcs", FT_BOOLEAN, 64, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_id_iocsc[2], { "Key Value Command Set (KVCS)", "nvme.cmd.identify.iocsc.kvcs", FT_BOOLEAN, 64, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_id_iocsc[3], { "Zoned Namespace Command Set (ZNSCS)", "nvme.cmd.identify.iocsc.znscs", FT_BOOLEAN, 64, NULL, 0x04, NULL, HFILL } },
        { &hf_nvme_id_iocsc[4], { "Subsystem Local Memory Command Set (SLMCS)", "nvme.cmd.identify.iocsc.slmcs", FT_BOOLEAN, 64, NULL, 0x08, NULL, HFILL } },
        { &hf_nvme_id_iocsc[5], { "Computational Programs Command Set (CPNCS)", "nvme.cmd.identify.iocsc.cpncs", FT_BOOLEAN, 64, NULL, 0x10, NULL, HFILL } },
        { &hf_nvme_id_iocsc[6], { "Reserved", "nvme.cmd.identify.iocsc.rsvd", FT_UINT64, BASE_HEX, NULL, UINT64_C(0xffffffffffffffe0), NULL, HFILL } },
        { &hf_nvme_id_genctr, { "Generation Counter (GENCTR)", "nvme.cmd.identify.underlying.genctr", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_nument, { "Number Entries (NUMENT)", "nvme.cmd.identify.underlying.nument", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_unsnqn, { "Underlying NVM Subsystem NQN (UNSNQN)", "nvme.cmd.identify.underlying.unsnqn", FT_STRINGZTRUNC, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_unsid, { "Namespace Identifier (NSID)", "nvme.cmd.identify.underlying.nsid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_ucntlid, { "Controller ID (CNTLID)", "nvme.cmd.identify.underlying.cntlid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_uidx, { "Index (IDX)", "nvme.cmd.identify.underlying.idx", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_portid, { "Port ID of the Underlying Port (PIDUP)", "nvme.cmd.identify.underlying.pidup", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_traddr, { "Transport Address (TRADDR)", "nvme.cmd.identify.underlying.traddr", FT_STRINGZPAD, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_tsas, { "Transport Specific Address Subtype (TSAS)", "nvme.cmd.identify.underlying.tsas", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_trtype, { "Transport Type (TRTYPE)", "nvme.cmd.identify.underlying.trtype", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(trt_type_tbl), 0, NULL, HFILL } },
        { &hf_nvme_id_adrfam, { "Transport Address Family (ADRFAM)", "nvme.cmd.identify.underlying.adrfam", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(adrfam_type_tbl), 0, NULL, HFILL } },
        { &hf_nvme_id_treq[0], { "Transport Requirements (TREQ)", "nvme.cmd.identify.underlying.treq", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_treq[1], { "Transport Secure Channel (TSC)", "nvme.cmd.identify.underlying.treq.secch", FT_UINT8, BASE_HEX, VALS(treq_tsc_tbl), 0x03, NULL, HFILL } },
        { &hf_nvme_id_treq[2], { "SQ Flow Control Disable (SQFCD)", "nvme.cmd.identify.underlying.treq.sqfc", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_nvme_id_treq[3], { "Zero Host ID Support (ZHIDS)", "nvme.cmd.identify.underlying.treq.zhids", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_nvme_id_treq[4], { "Transport Authentication and Secure Channel (TASC)", "nvme.cmd.identify.underlying.treq.tasc", FT_UINT8, BASE_HEX, VALS(treq_tasc_tbl), 0x30, NULL, HFILL } },
        { &hf_nvme_id_treq[5], { "Reserved", "nvme.cmd.identify.underlying.treq.rsvd", FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL } },
        { &hf_nvme_id_state_nv, { "Number of Versions (NV)", "nvme.cmd.identify.state.nv", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_state_nuuid, { "Number of UUIDs (NUUID)", "nvme.cmd.identify.state.nuuid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_state_version, { "Controller State Data Structure Version", "nvme.cmd.identify.state.version", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_id_state_uuid, { "Vendor Specific Controller State UUID", "nvme.cmd.identify.state.uuid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_admin_ns_mgmt_sel, { "Namespace Management Select (SEL)", "nvme.cmd.ns_mgmt.sel", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(ns_mgmt_sel_rvals), 0x0f, NULL, HFILL } },
        { &hf_nvme_admin_ns_csi, { "Command Set Identifier (CSI)", "nvme.cmd.ns_mgmt.csi", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(csi_tbl), 0xff000000, NULL, HFILL } },
        { &hf_nvme_admin_ns_attach_sel, { "Namespace Attachment Select (SEL)", "nvme.cmd.ns_attach.sel", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(ns_attach_sel_rvals), 0x0f, NULL, HFILL } },
        { &hf_nvme_admin_vm_act, { "Action (ACT)", "nvme.cmd.virt_mgmt.act", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(vm_act_rvals), 0x0f, NULL, HFILL } },
        { &hf_nvme_admin_vm_rt, { "Resource Type (RT)", "nvme.cmd.virt_mgmt.rt", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(vm_rt_rvals), 0x00000700, NULL, HFILL } },
        { &hf_nvme_admin_vm_cntlid, { "Controller Identifier (CNTLID)", "nvme.cmd.virt_mgmt.cntlid", FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL } },
        { &hf_nvme_admin_vm_nr, { "Number of Controller Resources (NR)", "nvme.cmd.virt_mgmt.nr", FT_UINT32, BASE_DEC, NULL, 0xffff, NULL, HFILL } },
        { &hf_nvme_admin_cap_oper, { "Operation (OPER)", "nvme.cmd.cap_mgmt.oper", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(cap_oper_rvals), 0x0f, NULL, HFILL } },
        { &hf_nvme_admin_cap_elid, { "Element Identifier (ELID)", "nvme.cmd.cap_mgmt.elid", FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL } },
        { &hf_nvme_admin_cap_capacity, { "Capacity (CAPL/CAPU)", "nvme.cmd.cap_mgmt.capacity", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_admin_export_ra, { "Restricted Access (RA)", "nvme.cmd.export.ra", FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
        { &hf_nvme_admin_export_recv_sel, { "Manage Exported NVM Subsystem Receive Select (SEL)", "nvme.cmd.export.recv_sel", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(export_recv_sel_rvals), 0xff, NULL, HFILL } },
        { &hf_nvme_admin_export_subsys_sel, { "Manage Exported NVM Subsystem Send Select (SEL)", "nvme.cmd.export.subsys_sel", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(export_send_sel_rvals), 0xff, NULL, HFILL } },
        { &hf_nvme_admin_export_ns_sel, { "Manage Exported Namespace Select (SEL)", "nvme.cmd.export.ns_sel", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(export_ns_sel_rvals), 0xff, NULL, HFILL } },
        { &hf_nvme_admin_export_port_sel, { "Manage Exported Port Select (SEL)", "nvme.cmd.export.port_sel", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(export_port_sel_rvals), 0xff, NULL, HFILL } },
        { &hf_nvme_admin_lba_slba, { "Starting LBA (SLBA)", "nvme.cmd.get_lba_status.slba", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_admin_lba_mndw, { "Maximum Number of Dwords (MNDW)", "nvme.cmd.get_lba_status.mndw", FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0, NULL, HFILL } },
        { &hf_nvme_admin_lba_atype, { "Action Type (ATYPE)", "nvme.cmd.get_lba_status.atype", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(lba_atype_rvals), 0xff000000, NULL, HFILL } },
        { &hf_nvme_admin_lba_rl, { "Range Length (RL)", "nvme.cmd.get_lba_status.rl", FT_UINT32, BASE_DEC, NULL, 0xffff, NULL, HFILL } },
        { &hf_nvme_admin_sanns_act, { "Sanitize Namespace Action (SANACT)", "nvme.cmd.sanitize_ns.act", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_sanitize_ns_sanact_rvals), 0x07, NULL, HFILL } },
        { &hf_nvme_admin_sanns_ause, { "Allow Unrestricted Sanitize Exit (AUSE)", "nvme.cmd.sanitize_ns.ause", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_nvme_admin_sanns_preq, { "Purge Required (PREQ)", "nvme.cmd.sanitize_ns.preq", FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
        { &hf_nvme_admin_sanns_emvs, { "Enter Media Verification State (EMVS)", "nvme.cmd.sanitize_ns.emvs", FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
        { &hf_nvme_admin_sanns_rsvd[0], { "Reserved", "nvme.cmd.sanitize_ns.rsvd0", FT_UINT32, BASE_HEX, NULL, 0x000003e0, NULL, HFILL } },
        { &hf_nvme_admin_sanns_rsvd[1], { "Reserved", "nvme.cmd.sanitize_ns.rsvd1", FT_UINT32, BASE_HEX, NULL, 0xfffff800, NULL, HFILL } },
        { &hf_nvme_lsp_cthid, { "Create Telemetry Host-Initiated Data (CTHID)", "nvme.cmd.get_logpage.lsp.cthid", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_mcda, { "Maximum Created Data Area (MCDA)", "nvme.cmd.get_logpage.lsp.mcda", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(lsp_mcda_rvals), 0x0e, NULL, HFILL } },
        { &hf_nvme_lsp_rgo, { "Return Groups Only (RGO)", "nvme.cmd.get_logpage.lsp.rgo", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_pel_act, { "Persistent Event Log Action (ACT)", "nvme.cmd.get_logpage.lsp.pel_act", FT_UINT8, BASE_HEX, VALS(lsp_pel_act_vals), 0x03, NULL, HFILL } },
        { &hf_nvme_lsp_scope, { "Scope (SCP)", "nvme.cmd.get_logpage.lsp.scope", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(lockdown_scope_rvals), 0x0f, NULL, HFILL } },
        { &hf_nvme_lsp_contents, { "Contents (CNTTS)", "nvme.cmd.get_logpage.lsp.contents", FT_UINT8, BASE_HEX, VALS(lockdown_contents_vals), 0x30, NULL, HFILL } },
        { &hf_nvme_lsp_elpf, { "Enhanced Log Page Format (ELPF)", "nvme.cmd.get_logpage.lsp.elpf", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL } },
        { &hf_nvme_lsp_bpid, { "Boot Partition Identifier (BPID)", "nvme.cmd.get_logpage.lsp.bpid", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_rao, { "Return Associations Only (RAO)", "nvme.cmd.get_logpage.lsp.rao", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_rmc, { "Remove Completed (RMC)", "nvme.cmd.get_logpage.lsp.rmc", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_events, { "FDP Event Type (FDPET), Host Events", "nvme.cmd.get_logpage.lsp.fdpet", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_extdlpe, { "Extended Discovery Log Page Entries (EXTDLPE)", "nvme.cmd.get_logpage.lsp.extdlpe", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_pleo, { "Port Local Entries Only (PLEO)", "nvme.cmd.get_logpage.lsp.pleo", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_lsp_allsube, { "All NVM Subsystem Entries (ALLSUBE)", "nvme.cmd.get_logpage.lsp.allsube", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_nvme_lsp_allhoste, { "All Host Entries (ALLHOSTE)", "nvme.cmd.get_logpage.lsp.allhoste", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_nlt, { "NSID List Type (NLT)", "nvme.cmd.get_logpage.lsp.nlt", FT_UINT8, BASE_DEC, VALS(lsp_nlt_vals), 0x01, NULL, HFILL } },
        { &hf_nvme_lsp_reserved, { "Reserved LSP Bits", "nvme.cmd.get_logpage.lsp.reserved", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lidsp_mcdas, { "Maximum Created Data Area Support (MCDAS)", "nvme.cmd.get_logpage.supported.mcdas", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_nvme_lidsp_ecrh, { "Establish Context and Read Header Supported (ECRH)", "nvme.cmd.get_logpage.supported.ecrh", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_nvme_pel_lid, { "Log Page Identifier", "nvme.cmd.get_logpage.pel.lid", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_tnev, { "Total Number of Events", "nvme.cmd.get_logpage.pel.tnev", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_tll, { "Total Log Length", "nvme.cmd.get_logpage.pel.tll", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_lrev, { "Log Revision", "nvme.cmd.get_logpage.pel.lrev", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_lhl, { "Log Header Length (excluding first 20 bytes)", "nvme.cmd.get_logpage.pel.lhl", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_timestamp, { "Context Timestamp (milliseconds)", "nvme.cmd.get_logpage.pel.timestamp", FT_UINT48, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_synch, { "Timestamp May Have Stopped Counting", "nvme.cmd.get_logpage.pel.synch", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_origin, { "Timestamp Origin", "nvme.cmd.get_logpage.pel.origin", FT_UINT8, BASE_DEC, NULL, 0x0e, NULL, HFILL } },
        { &hf_nvme_pel_poh, { "Power on Hours", "nvme.cmd.get_logpage.pel.poh", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_pwrcc, { "Power Cycle Count", "nvme.cmd.get_logpage.pel.pwrcc", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_vid, { "PCI Vendor ID", "nvme.cmd.get_logpage.pel.vid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ssvid, { "PCI Subsystem Vendor ID", "nvme.cmd.get_logpage.pel.ssvid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_sn, { "Serial Number", "nvme.cmd.get_logpage.pel.sn", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_mn, { "Model Number", "nvme.cmd.get_logpage.pel.mn", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_subnqn, { "Subsystem NVMe Qualified Name", "nvme.cmd.get_logpage.pel.subnqn", FT_STRINGZTRUNC, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_gnum, { "Generation Number", "nvme.cmd.get_logpage.pel.gnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_rcpid, { "Reporting Context Port Identifier", "nvme.cmd.get_logpage.pel.rcpid", FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_pel_rcpit, { "Reporting Context Port Identifier Type", "nvme.cmd.get_logpage.pel.rcpit", FT_UINT32, BASE_DEC, VALS(pel_rcpit_tbl), 0x00030000, NULL, HFILL } },
        { &hf_nvme_pel_rce, { "Reporting Context Exists", "nvme.cmd.get_logpage.pel.rce", FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL } },
        { &hf_nvme_pel_seb, { "Supported Events Bitmap", "nvme.cmd.get_logpage.pel.seb", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_seb_ev, { "Supported Event Type", "nvme.cmd.get_logpage.pel.seb.event", FT_UINT8, BASE_HEX, VALS(pel_event_type_tbl), 0, NULL, HFILL } },
        { &hf_nvme_pel_reserved, { "Reserved", "nvme.cmd.get_logpage.pel.reserved", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_extension, { "Log Header Extension", "nvme.cmd.get_logpage.pel.extension", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_events, { "Undecoded Log Data (header extension or persistent events)", "nvme.cmd.get_logpage.pel.events", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_past_tll, { "Data Beyond Total Log Length", "nvme.cmd.get_logpage.pel.past_tll", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev, { "Persistent Event", "nvme.cmd.get_logpage.pel.event", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_et, { "Event Type", "nvme.cmd.get_logpage.pel.event.et", FT_UINT8, BASE_HEX, VALS(pel_event_type_tbl), 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_etr, { "Event Type Revision", "nvme.cmd.get_logpage.pel.event.etr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_ehl, { "Event Header Length", "nvme.cmd.get_logpage.pel.event.ehl", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_pit, { "Port Identifier Type", "nvme.cmd.get_logpage.pel.event.pit", FT_UINT8, BASE_DEC, VALS(pel_pit_tbl), 0x03, NULL, HFILL } },
        { &hf_nvme_pel_ev_ehai_rsvd, { "Reserved", "nvme.cmd.get_logpage.pel.event.ehai.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL } },
        { &hf_nvme_pel_ev_cntlid, { "Controller Identifier", "nvme.cmd.get_logpage.pel.event.cntlid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_etstp, { "Event Timestamp (milliseconds)", "nvme.cmd.get_logpage.pel.event.etstp", FT_UINT48, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_synch, { "Timestamp May Have Stopped Counting", "nvme.cmd.get_logpage.pel.event.synch", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_ev_origin, { "Timestamp Origin", "nvme.cmd.get_logpage.pel.event.origin", FT_UINT8, BASE_DEC, NULL, 0x0e, NULL, HFILL } },
        { &hf_nvme_pel_ev_pelpid, { "Port Identifier", "nvme.cmd.get_logpage.pel.event.pelpid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_rsvd, { "Reserved", "nvme.cmd.get_logpage.pel.event.rsvd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_vsil, { "Vendor Specific Information Length", "nvme.cmd.get_logpage.pel.event.vsil", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_el, { "Event Length", "nvme.cmd.get_logpage.pel.event.el", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_hdr_ext, { "Event Header Extension", "nvme.cmd.get_logpage.pel.event.hdr_ext", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_vsi, { "Vendor Specific Information", "nvme.cmd.get_logpage.pel.event.vsi", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ev_data, { "Event Data", "nvme.cmd.get_logpage.pel.event.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fwc_ofr, { "Old Firmware Revision", "nvme.cmd.get_logpage.pel.event.fwc.ofr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fwc_nfr, { "New Firmware Revision", "nvme.cmd.get_logpage.pel.event.fwc.nfr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fwc_fca, { "Firmware Commit Action", "nvme.cmd.get_logpage.pel.event.fwc.fca", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fwc_fslt, { "Firmware Slot", "nvme.cmd.get_logpage.pel.event.fwc.fslt", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fwc_stctfcc, { "Status Code Type for Firmware Commit Command", "nvme.cmd.get_logpage.pel.event.fwc.stctfcc", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fwc_srfcc, { "Status Returned for Firmware Commit Command", "nvme.cmd.get_logpage.pel.event.fwc.srfcc", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fwc_vafcrc, { "Vendor Assigned Firmware Commit Result Code", "nvme.cmd.get_logpage.pel.event.fwc.vafcrc", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_bp_lid, { "Log Page Identifier (LID)", "nvme.cmd.get_logpage.bp.lid", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_bp_rsvd0, { "Reserved", "nvme.cmd.get_logpage.bp.rsvd0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_bp_bpinfo[0], { "Boot Partition Information (BPINFO)", "nvme.cmd.get_logpage.bp.bpinfo", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_bp_bpinfo[1], { "Boot Partition Size (BPSZ)", "nvme.cmd.get_logpage.bp.bpinfo.bpsz", FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_bpsz), 0x00007fff, NULL, HFILL } },
        { &hf_nvme_lp_bp_bpinfo[2], { "Reserved", "nvme.cmd.get_logpage.bp.bpinfo.rsvd", FT_UINT32, BASE_HEX, NULL, 0x7fff8000, NULL, HFILL } },
        { &hf_nvme_lp_bp_bpinfo[3], { "Active Boot Partition ID (ABPID)", "nvme.cmd.get_logpage.bp.bpinfo.abpid", FT_UINT32, BASE_DEC, NULL, 0x80000000, NULL, HFILL } },
        { &hf_nvme_lp_bp_rsvd1, { "Reserved", "nvme.cmd.get_logpage.bp.rsvd1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_bp_bpd, { "Boot Partition Data (BPD)", "nvme.cmd.get_logpage.bp.bpd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_endgid, { "Endurance Group Identifier (ENDGID)", "nvme.cmd.get_logpage.rmi.endgid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_numa, { "Number of Actuators (NUMA)", "nvme.cmd.get_logpage.rmi.numa", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_nrs, { "Nominal Rotational Speed (NRS)", "nvme.cmd.get_logpage.rmi.nrs", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_rmi_nrs), 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_rsvd0, { "Reserved", "nvme.cmd.get_logpage.rmi.rsvd0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_spinc, { "Spinup Count (SPINC)", "nvme.cmd.get_logpage.rmi.spinc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_fspinc, { "Failed Spinup Count (FSPINC)", "nvme.cmd.get_logpage.rmi.fspinc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_ldc, { "Load Count (LDC)", "nvme.cmd.get_logpage.rmi.ldc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_fldc, { "Failed Load Count (FLDC)", "nvme.cmd.get_logpage.rmi.fldc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rmi_rsvd1, { "Reserved", "nvme.cmd.get_logpage.rmi.rsvd1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mal_mat, { "Management Address Type (MAT)", "nvme.cmd.get_logpage.mal.mat", FT_UINT8, BASE_HEX, VALS(lp_mal_mat_tbl), 0, NULL, HFILL } },
        { &hf_nvme_lp_mal_rsvd, { "Reserved", "nvme.cmd.get_logpage.mal.rsvd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mal_madrs, { "Management Address (MADRS)", "nvme.cmd.get_logpage.mal.madrs", FT_STRINGZPAD, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_nump, { "Number of Personalities (NUMP)", "nvme.cmd.get_logpage.dp.nump", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0, NULL, HFILL } },
        { &hf_nvme_lp_mdcs_mdcsv, { "Manufacturer Default Configuration Status Version (MDCSV)", "nvme.cmd.get_logpage.mdcs.mdcsv", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mdcs_mdcs, { "Manufacturer Default Configuration Status (MDCS)", "nvme.cmd.get_logpage.mdcs.mdcs", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mdcs_dscs, { "Default NVM Subsystem Configuration Status (DSCS)", "nvme.cmd.get_logpage.mdcs.dscs", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lp_mdcs_dncs, { "Default Namespace Configuration Status (DNCS)", "nvme.cmd.get_logpage.mdcs.dncs", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_lp_mdcs_dccs, { "Default Capacity Configuration Status (DCCS)", "nvme.cmd.get_logpage.mdcs.dccs", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_nvme_lp_mdcs_rsvd, { "Reserved", "nvme.cmd.get_logpage.mdcs.rsvd", FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL } },
        { &hf_nvme_lp_dp_cdplpv, { "CDP Log Page Version (CDPLPV)", "nvme.cmd.get_logpage.dp.cdplpv", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_dplphl, { "Device Personalities Log Page Header Length (DPLPHL)", "nvme.cmd.get_logpage.dp.dplphl", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_cdplps, { "Device Personalities Log Page Size (CDPLPS)", "nvme.cmd.get_logpage.dp.cdplps", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_pps, { "Personality Properties Size (PPS)", "nvme.cmd.get_logpage.dp.pps", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_perid, { "Personality Identifier (PERID)", "nvme.cmd.get_logpage.dp.perid", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_mrstt, { "Minimum Required Reset Type (MRSTT)", "nvme.cmd.get_logpage.dp.mrstt", FT_UINT8, BASE_HEX, VALS(lp_dp_mrstt_tbl), 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_aus[0], { "Authenticated Unfreeze Support (AUS)", "nvme.cmd.get_logpage.dp.aus", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_aus[1], { "Physical Credential Authentication Support (PCAS)", "nvme.cmd.get_logpage.dp.aus.pcas", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lp_dp_aus[2], { "Programmable Key Authentication Support (PKAS)", "nvme.cmd.get_logpage.dp.aus.pkas", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_lp_dp_aus[3], { "Reserved", "nvme.cmd.get_logpage.dp.aus.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL } },
        { &hf_nvme_lp_dp_attr[0], { "Personality Attributes", "nvme.cmd.get_logpage.dp.attr", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dp_attr[1], { "Personality Settings Change User Data Effect (PSCUDE)", "nvme.cmd.get_logpage.dp.attr.pscude", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lp_dp_attr[2], { "Reserved", "nvme.cmd.get_logpage.dp.attr.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL } },
        { &hf_nvme_lp_pm_ver, { "Version (VER)", "nvme.cmd.get_logpage.pm.ver", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_pmgn, { "Power Measurement Generation Number (PMGN)", "nvme.cmd.get_logpage.pm.pmgn", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_pma[0], { "Power Measurement Attributes (PMA)", "nvme.cmd.get_logpage.pm.pma", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_pma[1], { "Power Measurement Enable (PME)", "nvme.cmd.get_logpage.pm.pma.pme", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_nvme_lp_pm_pma[2], { "Non-Contiguous Power Data Flag (NCPDF)", "nvme.cmd.get_logpage.pm.pma.ncpdf", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_nvme_lp_pm_pma[3], { "Estimated Power Flag (EPF)", "nvme.cmd.get_logpage.pm.pma.epf", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_nvme_lp_pm_pma[4], { "Maximum Interval Power Timestamp Support (MIPWRTS)", "nvme.cmd.get_logpage.pm.pma.mipwrts", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_nvme_lp_pm_pma[5], { "Power Histogram Descriptor Overflow (PHDO)", "nvme.cmd.get_logpage.pm.pma.phdo", FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
        { &hf_nvme_lp_pm_pma[6], { "Reserved", "nvme.cmd.get_logpage.pm.pma.rsvd", FT_UINT16, BASE_HEX, NULL, 0x0fe0, NULL, HFILL } },
        { &hf_nvme_lp_pm_pma[7], { "Power Measurement Type (PMT)", "nvme.cmd.get_logpage.pm.pma.pmt", FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_power_meas_type_rvals), 0xf000, NULL, HFILL } },
        { &hf_nvme_lp_pm_sze, { "Size (SZE)", "nvme.cmd.get_logpage.pm.sze", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_pmc, { "Power Measurement Count (PMC)", "nvme.cmd.get_logpage.pm.pmc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_nphd, { "Number of Power Histogram Descriptors (NPHD)", "nvme.cmd.get_logpage.pm.nphd", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_smtr, { "Stop Measurement Time Remaining (SMTR)", "nvme.cmd.get_logpage.pm.smtr", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_minute_minutes), 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_smts[0], { "Stop Measurement Timestamp (SMTS)", "nvme.cmd.get_logpage.pm.smts", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_smts[1], { "Timestamp (TSTMP)", "nvme.cmd.get_logpage.pm.smts.tstmp", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), G_GUINT64_CONSTANT(0x0000ffffffffffff), NULL, HFILL } },
        { &hf_nvme_lp_pm_smts[2], { "Synch (SYNC)", "nvme.cmd.get_logpage.pm.smts.sync", FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0001000000000000), NULL, HFILL } },
        { &hf_nvme_lp_pm_smts[3], { "Timestamp Origin (TSTMPO)", "nvme.cmd.get_logpage.pm.smts.tstmpo", FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(sf_tstmpo_table), G_GUINT64_CONSTANT(0x000e000000000000), NULL, HFILL } },
        { &hf_nvme_lp_pm_smts[4], { "Reserved", "nvme.cmd.get_logpage.pm.smts.tstmps_rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0x00f0000000000000), NULL, HFILL } },
        { &hf_nvme_lp_pm_smts[5], { "Reserved", "nvme.cmd.get_logpage.pm.smts.rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0xff00000000000000), NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwrt[0], { "Maximum Interval Power Timestamp (MIPWRT)", "nvme.cmd.get_logpage.pm.mipwrt", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwrt[1], { "Timestamp (TSTMP)", "nvme.cmd.get_logpage.pm.mipwrt.tstmp", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), G_GUINT64_CONSTANT(0x0000ffffffffffff), NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwrt[2], { "Synch (SYNC)", "nvme.cmd.get_logpage.pm.mipwrt.sync", FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0001000000000000), NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwrt[3], { "Timestamp Origin (TSTMPO)", "nvme.cmd.get_logpage.pm.mipwrt.tstmpo", FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(sf_tstmpo_table), G_GUINT64_CONSTANT(0x000e000000000000), NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwrt[4], { "Reserved", "nvme.cmd.get_logpage.pm.mipwrt.tstmps_rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0x00f0000000000000), NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwrt[5], { "Reserved", "nvme.cmd.get_logpage.pm.mipwrt.rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0xff00000000000000), NULL, HFILL } },
        { &hf_nvme_lp_pm_phds, { "Power Histogram Descriptor Size (PHDS)", "nvme.cmd.get_logpage.pm.phds", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_phbs, { "Power Histogram Bin Size (PHBS)", "nvme.cmd.get_logpage.pm.phbs", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliwatt), 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_nphds, { "Number of Power Histogram Descriptors Supported (NPHDS)", "nvme.cmd.get_logpage.pm.nphds", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_vss, { "Vendor Specific Size (VSS)", "nvme.cmd.get_logpage.pm.vss", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_phdoc, { "Power Histogram Descriptor Overflow Count (PHDOC)", "nvme.cmd.get_logpage.pm.phdoc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_rsvd0, { "Reserved", "nvme.cmd.get_logpage.pm.rsvd0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_aipwr[0], { "Average Interval Power (AIPWR)", "nvme.cmd.get_logpage.pm.aipwr", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_aipwr[1], { "Average Interval Power Value (AIPWRV)", "nvme.cmd.get_logpage.pm.aipwr.value", FT_UINT32, BASE_DEC, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_lp_pm_aipwr[2], { "Average Interval Power Scale (AIPWRS)", "nvme.cmd.get_logpage.pm.aipwr.scale", FT_UINT32, BASE_HEX, VALS(nvme_power_scale_vals), 0x00030000, NULL, HFILL } },
        { &hf_nvme_lp_pm_aipwr[3], { "Reserved", "nvme.cmd.get_logpage.pm.aipwr.rsvd", FT_UINT32, BASE_HEX, NULL, 0xfffc0000, NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwr[0], { "Maximum Interval Power (MIPWR)", "nvme.cmd.get_logpage.pm.mipwr", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwr[1], { "Maximum Interval Power Value (MIPWRV)", "nvme.cmd.get_logpage.pm.mipwr.value", FT_UINT32, BASE_DEC, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwr[2], { "Maximum Interval Power Scale (MIPWRS)", "nvme.cmd.get_logpage.pm.mipwr.scale", FT_UINT32, BASE_HEX, VALS(nvme_power_scale_vals), 0x00030000, NULL, HFILL } },
        { &hf_nvme_lp_pm_mipwr[3], { "Reserved", "nvme.cmd.get_logpage.pm.mipwr.rsvd", FT_UINT32, BASE_HEX, NULL, 0xfffc0000, NULL, HFILL } },
        { &hf_nvme_lp_pm_phblt[0], { "Power Histogram Bin Lower Threshold (PHBLT)", "nvme.cmd.get_logpage.pm.phblt", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_phblt[1], { "Power Value (PWRV)", "nvme.cmd.get_logpage.pm.phblt.value", FT_UINT32, BASE_DEC, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_lp_pm_phblt[2], { "Power Scale (PWRS)", "nvme.cmd.get_logpage.pm.phblt.scale", FT_UINT32, BASE_HEX, VALS(nvme_power_scale_vals), 0x00030000, NULL, HFILL } },
        { &hf_nvme_lp_pm_phblt[3], { "Reserved", "nvme.cmd.get_logpage.pm.phblt.rsvd", FT_UINT32, BASE_HEX, NULL, 0xfffc0000, NULL, HFILL } },
        { &hf_nvme_lp_pm_ipwrpe, { "Interval Power Percent Error (IPWRPE)", "nvme.cmd.get_logpage.pm.ipwrpe", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(lp_pm_ipwrpe_rvals), 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_rsvd1, { "Reserved", "nvme.cmd.get_logpage.pm.rsvd1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_phbc, { "Power Histogram Bin Count (PHBC)", "nvme.cmd.get_logpage.pm.phbc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_pm_vs, { "Vendor Specific", "nvme.cmd.get_logpage.pm.vs", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_vmgn, { "Voltage Measurement Generation Number (VMGN)", "nvme.cmd.get_logpage.vm.vmgn", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_vma[0], { "Voltage Measurement Attributes (VMA)", "nvme.cmd.get_logpage.vm.vma", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_vma[1], { "Voltage Measurement Enable (VME)", "nvme.cmd.get_logpage.vm.vma.vme", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_lp_vm_vma[2], { "Interval Voltage Timestamp Support (IVOLTS)", "nvme.cmd.get_logpage.vm.vma.ivolts", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_lp_vm_vma[3], { "Voltage Sensor Measured (VSM)", "nvme.cmd.get_logpage.vm.vma.vsm", FT_UINT8, BASE_HEX, VALS(nvme_vsen_sel_vals), 0x0c, "Ignore unless VMC is set", HFILL } },
        { &hf_nvme_lp_vm_vma[4], { "Voltage Measurement Counted (VMC)", "nvme.cmd.get_logpage.vm.vma.vmc", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
        { &hf_nvme_lp_vm_vma[5], { "Reserved", "nvme.cmd.get_logpage.vm.vma.rsvd", FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL } },
        { &hf_nvme_lp_vm_vsi[0], { "Voltage Sensor Info (VSI)", "nvme.cmd.get_logpage.vm.vsi", FT_UINT16, BASE_HEX, NULL, 0, "Ignore unless VMC is set", HFILL } },
        { &hf_nvme_lp_vm_vsi[1], { "Voltage Sensor Supply Value (VSSV)", "nvme.cmd.get_logpage.vm.vsi.vssv", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_vsen_pisv), 0x0fff, NULL, HFILL } },
        { &hf_nvme_lp_vm_vsi[2], { "Voltage Sensor Supply Label (VSSL)", "nvme.cmd.get_logpage.vm.vsi.vssl", FT_UINT16, BASE_DEC, NULL, 0x3000, NULL, HFILL } },
        { &hf_nvme_lp_vm_vsi[3], { "Voltage Sensor Sample Scale (VSSS)", "nvme.cmd.get_logpage.vm.vsi.vsss", FT_UINT16, BASE_HEX, VALS(ctrl_vsen_volss_tbl), 0xc000, NULL, HFILL } },
        { &hf_nvme_lp_vm_vmlsz, { "Voltage Measurement Log Size (VMLSZ)", "nvme.cmd.get_logpage.vm.vmlsz", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_nvmds, { "Number of Voltage Measurement Descriptors Supported (NVMDS)", "nvme.cmd.get_logpage.vm.nvmds", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_nvmde, { "Number of Voltage Measurement Descriptors Entries (NVMDE)", "nvme.cmd.get_logpage.vm.nvmde", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_svmtr, { "Stop Voltage Measurement Time Remaining (SVMTR)", "nvme.cmd.get_logpage.vm.svmtr", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_minute_minutes), 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_svmts[0], { "Stop Voltage Measurement Timestamp (SVMTS)", "nvme.cmd.get_logpage.vm.svmts", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_svmts[1], { "Timestamp (TSTMP)", "nvme.cmd.get_logpage.vm.svmts.tstmp", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), G_GUINT64_CONSTANT(0x0000ffffffffffff), NULL, HFILL } },
        { &hf_nvme_lp_vm_svmts[2], { "Synch (SYNC)", "nvme.cmd.get_logpage.vm.svmts.sync", FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0001000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_svmts[3], { "Timestamp Origin (TSTMPO)", "nvme.cmd.get_logpage.vm.svmts.tstmpo", FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(sf_tstmpo_table), G_GUINT64_CONSTANT(0x000e000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_svmts[4], { "Reserved", "nvme.cmd.get_logpage.vm.svmts.tstmps_rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0x00f0000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_svmts[5], { "Reserved", "nvme.cmd.get_logpage.vm.svmts.rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0xff00000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_cntlid, { "Controller Identifier (CNTLID)", "nvme.cmd.get_logpage.vm.cntlid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_vlvss, { "Voltage Log Vendor Specific Size (VLVSS)", "nvme.cmd.get_logpage.vm.vlvss", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_rsvd0, { "Reserved", "nvme.cmd.get_logpage.vm.rsvd0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_ovol[0], { "Overvoltage (OVOL)", "nvme.cmd.get_logpage.vm.ovol", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_ovol[1], { "Maximum Overvoltage Value (MOVV)", "nvme.cmd.get_logpage.vm.ovol.movv", FT_UINT16, BASE_DEC, NULL, 0x3fff, "Volts = value x the VSSS scale", HFILL } },
        { &hf_nvme_lp_vm_ovol[2], { "Overvoltage Valid (OVV)", "nvme.cmd.get_logpage.vm.ovol.ovv", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL } },
        { &hf_nvme_lp_vm_ovol[3], { "Reserved", "nvme.cmd.get_logpage.vm.ovol.rsvd", FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL } },
        { &hf_nvme_lp_vm_ovc, { "Overvoltage Count (OVC)", "nvme.cmd.get_logpage.vm.ovc", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_ovlt, { "Overvoltage Log Threshold (OVLT)", "nvme.cmd.get_logpage.vm.ovlt", FT_UINT16, BASE_DEC, NULL, 0, "Volts = value x the VSSS scale", HFILL } },
        { &hf_nvme_lp_vm_ovts[0], { "Overvoltage Timestamp (OVTS)", "nvme.cmd.get_logpage.vm.ovts", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_ovts[1], { "Timestamp (TSTMP)", "nvme.cmd.get_logpage.vm.ovts.tstmp", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), G_GUINT64_CONSTANT(0x0000ffffffffffff), NULL, HFILL } },
        { &hf_nvme_lp_vm_ovts[2], { "Synch (SYNC)", "nvme.cmd.get_logpage.vm.ovts.sync", FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0001000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_ovts[3], { "Timestamp Origin (TSTMPO)", "nvme.cmd.get_logpage.vm.ovts.tstmpo", FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(sf_tstmpo_table), G_GUINT64_CONSTANT(0x000e000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_ovts[4], { "Reserved", "nvme.cmd.get_logpage.vm.ovts.tstmps_rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0x00f0000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_ovts[5], { "Reserved", "nvme.cmd.get_logpage.vm.ovts.rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0xff00000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_iovpe, { "Interval Overvoltage Percent Error (IOVPE)", "nvme.cmd.get_logpage.vm.iovpe", FT_UINT8, BASE_CUSTOM, CF_FUNC(add_nvme_vm_pct_err), 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_uvol[0], { "Undervoltage (UVOL)", "nvme.cmd.get_logpage.vm.uvol", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_uvol[1], { "Minimum Undervoltage Value (MUVV)", "nvme.cmd.get_logpage.vm.uvol.muvv", FT_UINT16, BASE_DEC, NULL, 0x3fff, "Volts = value x the VSSS scale", HFILL } },
        { &hf_nvme_lp_vm_uvol[2], { "Undervoltage Valid (UVV)", "nvme.cmd.get_logpage.vm.uvol.uvv", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL } },
        { &hf_nvme_lp_vm_uvol[3], { "Reserved", "nvme.cmd.get_logpage.vm.uvol.rsvd", FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL } },
        { &hf_nvme_lp_vm_uvc, { "Undervoltage Count (UVC)", "nvme.cmd.get_logpage.vm.uvc", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_uvlt, { "Undervoltage Log Threshold (UVLT)", "nvme.cmd.get_logpage.vm.uvlt", FT_UINT16, BASE_DEC, NULL, 0, "Volts = value x the VSSS scale", HFILL } },
        { &hf_nvme_lp_vm_uvts[0], { "Undervoltage Timestamp (UVTS)", "nvme.cmd.get_logpage.vm.uvts", FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_uvts[1], { "Timestamp (TSTMP)", "nvme.cmd.get_logpage.vm.uvts.tstmp", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), G_GUINT64_CONSTANT(0x0000ffffffffffff), NULL, HFILL } },
        { &hf_nvme_lp_vm_uvts[2], { "Synch (SYNC)", "nvme.cmd.get_logpage.vm.uvts.sync", FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0001000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_uvts[3], { "Timestamp Origin (TSTMPO)", "nvme.cmd.get_logpage.vm.uvts.tstmpo", FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(sf_tstmpo_table), G_GUINT64_CONSTANT(0x000e000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_uvts[4], { "Reserved", "nvme.cmd.get_logpage.vm.uvts.tstmps_rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0x00f0000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_uvts[5], { "Reserved", "nvme.cmd.get_logpage.vm.uvts.rsvd", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0xff00000000000000), NULL, HFILL } },
        { &hf_nvme_lp_vm_iuvpe, { "Interval Undervoltage Percent Error (IUVPE)", "nvme.cmd.get_logpage.vm.iuvpe", FT_UINT8, BASE_CUSTOM, CF_FUNC(add_nvme_vm_pct_err), 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_rsvd1, { "Reserved", "nvme.cmd.get_logpage.vm.rsvd1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_ivolm[0], { "Interval Voltage Measurement (IVOLM)", "nvme.cmd.get_logpage.vm.ivolm", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_ivolm[1], { "Voltage Value (VOLV)", "nvme.cmd.get_logpage.vm.ivolm.volv", FT_UINT16, BASE_DEC, NULL, 0x3fff, "Volts = value x the Identify Controller VOLSS scale", HFILL } },
        { &hf_nvme_lp_vm_ivolm[2], { "Non Contiguous Voltage Measurement (NCVM)", "nvme.cmd.get_logpage.vm.ivolm.ncvm", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL } },
        { &hf_nvme_lp_vm_ivolm[3], { "Reserved", "nvme.cmd.get_logpage.vm.ivolm.rsvd", FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL } },
        { &hf_nvme_lp_rl_rsvd0, { "Reserved", "nvme.cmd.get_logpage.rl.rsvd0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_np, { "Number of Ports (NP)", "nvme.cmd.get_logpage.rl.np", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_rl_zeroes_based), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_lpl, { "Log Page Length (LPL)", "nvme.cmd.get_logpage.rl.lpl", FT_UINT32, BASE_DEC, NULL, 0, "Length in dwords", HFILL } },
        { &hf_nvme_lp_rl_gc, { "Generation Count (GC)", "nvme.cmd.get_logpage.rl.gc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_nst, { "Number of Supported Targets (NST)", "nvme.cmd.get_logpage.rl.nst", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_rl_zeroes_based), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_rsvd1, { "Reserved", "nvme.cmd.get_logpage.rl.rsvd1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_port_off, { "Rate Limiting Port Descriptor Offset (dwords)", "nvme.cmd.get_logpage.rl.port_off", FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_rl_dword_off), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_ctrl_off, { "Rate Limiting Controller Descriptor Offset (dwords)", "nvme.cmd.get_logpage.rl.ctrl_off", FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_rl_dword_off), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_nsma_off, { "Non-Volatile Storage Medium Access Descriptor Offset (dwords)", "nvme.cmd.get_logpage.rl.nsma_off", FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_rl_dword_off), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_port, { "Rate Limiting Port Descriptor", "nvme.cmd.get_logpage.rl.port", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_portid, { "Port Identifier (PORTID)", "nvme.cmd.get_logpage.rl.port.portid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_nc, { "Number of Controllers (NC)", "nvme.cmd.get_logpage.rl.port.nc", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_rl_zeroes_based), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_abwsf, { "Available Bandwidth Scale Factor (ABWSF)", "nvme.cmd.get_logpage.rl.port.abwsf", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_rl_bwsf_rvals), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_arbwv, { "Available Read Bandwidth Value (ARBWV)", "nvme.cmd.get_logpage.rl.port.arbwv", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_awbwv, { "Available Write Bandwidth Value (AWBWV)", "nvme.cmd.get_logpage.rl.port.awbwv", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_ariops, { "Available Read IOPS (ARIOPS)", "nvme.cmd.get_logpage.rl.port.ariops", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_awiops, { "Available Write IOPS (AWIOPS)", "nvme.cmd.get_logpage.rl.port.awiops", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_ctrl, { "Rate Limiting Controller Descriptor", "nvme.cmd.get_logpage.rl.ctrl", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_cntlid, { "Controller Identifier (CNTLID)", "nvme.cmd.get_logpage.rl.ctrl.cntlid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_nnsmad, { "Number of Non-Volatile Storage Medium Access Descriptors (NNSMAD)", "nvme.cmd.get_logpage.rl.nnsmad", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_nsma, { "Non-Volatile Storage Medium Access Descriptor", "nvme.cmd.get_logpage.rl.nsma", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_sc, { "Scope (SC)", "nvme.cmd.get_logpage.rl.nsma.sc", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_rl_sc_rvals), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_si, { "Scope Identifier (SI)", "nvme.cmd.get_logpage.rl.nsma.si", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_rlma, { "Rate Limiting Maximum Access (RLMA)", "nvme.cmd.get_logpage.rl.rlma", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_mbsf, { "Maximum Bandwidth Scale Factor (MBSF)", "nvme.cmd.get_logpage.rl.rlma.mbsf", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_rl_bwsf_rvals), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_mrbwv, { "Maximum Read Bandwidth Value (MRBWV)", "nvme.cmd.get_logpage.rl.rlma.mrbwv", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_mwbwv, { "Maximum Write Bandwidth Value (MWBWV)", "nvme.cmd.get_logpage.rl.rlma.mwbwv", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_mriops, { "Maximum Random Read IOPS (MRIOPS)", "nvme.cmd.get_logpage.rl.rlma.mriops", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_mwiops, { "Maximum Random Write IOPS (MWIOPS)", "nvme.cmd.get_logpage.rl.rlma.mwiops", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_dsc_rsvd, { "Reserved", "nvme.cmd.get_logpage.rl.rsvd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_dsc_vs, { "Vendor Specific (VS)", "nvme.cmd.get_logpage.rl.vs", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_tgt, { "Supported Target", "nvme.cmd.get_logpage.rl.tgt", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(nvme_rl_tgt_rvals), 0, NULL, HFILL } },
        { &hf_nvme_lp_rl_pad, { "Padding (PAD)", "nvme.cmd.get_logpage.rl.pad", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_vm_vlvs, { "Voltage Log Vendor Specific (VLVS)", "nvme.cmd.get_logpage.vm.vlvs", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_snsl_genctr, { "Generation Counter (GENCTR)", "nvme.cmd.get_logpage.snsl.genctr", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_snsl_numnsid, { "Number of NSIDs (NUMNSID)", "nvme.cmd.get_logpage.snsl.numnsid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_snsl_nsid, { "Namespace Identifier (NSID)", "nvme.cmd.get_logpage.snsl.nsid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_nmu, { "Number of Media Unit Status Descriptors (NMU)", "nvme.cmd.get_logpage.mus.nmu", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_cchans, { "Number of Channels (CCHANS)", "nvme.cmd.get_logpage.mus.cchans", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_selc, { "Selected Configuration (SELC)", "nvme.cmd.get_logpage.mus.selc", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_rsvd0, { "Reserved", "nvme.cmd.get_logpage.mus.rsvd0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_muid, { "Media Unit Identifier (MUID)", "nvme.cmd.get_logpage.mus.muid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_did, { "Domain Identifier (DID)", "nvme.cmd.get_logpage.mus.did", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_endgid, { "Endurance Group Identifier (ENDGID)", "nvme.cmd.get_logpage.mus.endgid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_nvmsetid, { "NVM Set Identifier (NVMSETID)", "nvme.cmd.get_logpage.mus.nvmsetid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_caf, { "Capacity Adjustment Factor (CAF)", "nvme.cmd.get_logpage.mus.caf", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_caf), 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_avsp, { "Available Spare (AVSP)", "nvme.cmd.get_logpage.mus.avsp", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_percent), 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_pused, { "Percentage Used (PUSED)", "nvme.cmd.get_logpage.mus.pused", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_percent), 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_mucs, { "Number of Channels (MUCS)", "nvme.cmd.get_logpage.mus.mucs", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_cio, { "Channel Identifiers Offset (CIO)", "nvme.cmd.get_logpage.mus.cio", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_rsvd1, { "Reserved", "nvme.cmd.get_logpage.mus.rsvd1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_mus_chid, { "Channel Identifier", "nvme.cmd.get_logpage.mus.chid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_sccn, { "Number of Supported Capacity Configurations (SCCN)", "nvme.cmd.get_logpage.scc.sccn", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_rsvd0, { "Reserved", "nvme.cmd.get_logpage.scc.rsvd0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_ccid, { "Capacity Configuration Identifier (CCID)", "nvme.cmd.get_logpage.scc.ccid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_did, { "Domain Identifier (DID)", "nvme.cmd.get_logpage.scc.did", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_egcn, { "Number of Endurance Group Configuration Descriptors (EGCN)", "nvme.cmd.get_logpage.scc.egcn", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_rsvd1, { "Reserved", "nvme.cmd.get_logpage.scc.rsvd1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_endgid, { "Endurance Group Identifier (ENDGID)", "nvme.cmd.get_logpage.scc.endgid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_cadjf, { "Capacity Adjustment Factor (CADJF)", "nvme.cmd.get_logpage.scc.cadjf", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_caf), 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_rsvd2, { "Reserved", "nvme.cmd.get_logpage.scc.rsvd2", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_tegcap, { "Total Endurance Group Capacity (TEGCAP)", "nvme.cmd.get_logpage.scc.tegcap", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_segcap, { "Spare Endurance Group Capacity (SEGCAP)", "nvme.cmd.get_logpage.scc.segcap", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_ee, { "Endurance Estimate (EE)", "nvme.cmd.get_logpage.scc.ee", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_rsvd3, { "Reserved", "nvme.cmd.get_logpage.scc.rsvd3", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_egsets, { "Number of NVM Sets (EGSETS)", "nvme.cmd.get_logpage.scc.egsets", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_nvmsetid, { "NVM Set Identifier", "nvme.cmd.get_logpage.scc.nvmsetid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_egchans, { "Number of Channels (EGCHANS)", "nvme.cmd.get_logpage.scc.egchans", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_chid, { "Channel Identifier (CHID)", "nvme.cmd.get_logpage.scc.chid", FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_chid), 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_chmus, { "Number of Channel Media Units (CHMUS)", "nvme.cmd.get_logpage.scc.chmus", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_muid, { "Media Unit Identifier (MUID)", "nvme.cmd.get_logpage.scc.muid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_rsvd4, { "Reserved", "nvme.cmd.get_logpage.scc.rsvd4", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_mudl, { "Media Unit Descriptor Length (MUDL)", "nvme.cmd.get_logpage.scc.mudl", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_scc_mudi, { "Media Unit Descriptor Information", "nvme.cmd.get_logpage.scc.mudi", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dnps_genctr, { "Generation Counter (GENCTR)", "nvme.cmd.get_logpage.dnps.genctr", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dnps_numpsub, { "Number of Participating NVM Subsystems (NUMPSUB)", "nvme.cmd.get_logpage.dnps.numpsub", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dnps_rsvd, { "Reserved", "nvme.cmd.get_logpage.dnps.rsvd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lp_dnps_nqn, { "Participating NVM Subsystem NQN", "nvme.cmd.get_logpage.dnps.nqn", FT_STRINGZTRUNC, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_reach_rsvd, { "Reserved", "nvme.cmd.get_logpage.reach.rsvd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_window_decode_skipped, { "Window decode", "nvme.window_decode_skipped", FT_STRING, BASE_NONE, NULL, 0, "Why the bytes of this window are not decoded further", HFILL } },
        { &hf_nvme_pel_tsc_ptstp, { "Previous Timestamp (milliseconds)", "nvme.cmd.get_logpage.pel.event.tsc.ptstp", FT_UINT48, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_tsc_synch, { "Timestamp May Have Stopped Counting", "nvme.cmd.get_logpage.pel.event.tsc.synch", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_tsc_origin, { "Timestamp Origin", "nvme.cmd.get_logpage.pel.event.tsc.origin", FT_UINT8, BASE_DEC, NULL, 0x0e, NULL, HFILL } },
        { &hf_nvme_pel_tsc_msr, { "Milliseconds Since Reset", "nvme.cmd.get_logpage.pel.event.tsc.msr", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_por_frev, { "Firmware Revision", "nvme.cmd.get_logpage.pel.event.por.frev", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_por_desc, { "Reset Information Descriptor", "nvme.cmd.get_logpage.pel.event.por.desc", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_por_cntlid, { "Controller Identifier", "nvme.cmd.get_logpage.pel.event.por.cntlid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_por_fa, { "Firmware Activation", "nvme.cmd.get_logpage.pel.event.por.fa", FT_UINT8, BASE_HEX, VALS(pel_por_fa_tbl), 0, NULL, HFILL } },
        { &hf_nvme_pel_por_rdnf, { "Reset During NVM Format", "nvme.cmd.get_logpage.pel.event.por.rdnf", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_por_oip_rsvd, { "Reserved", "nvme.cmd.get_logpage.pel.event.por.oip.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL } },
        { &hf_nvme_pel_por_cpwrc, { "Controller Power Cycle", "nvme.cmd.get_logpage.pel.event.por.cpwrc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_por_pom, { "Power On Milliseconds", "nvme.cmd.get_logpage.pel.event.por.pom", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_por_ctstp, { "Controller Timestamp (milliseconds)", "nvme.cmd.get_logpage.pel.event.por.ctstp", FT_UINT48, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_por_synch, { "Timestamp May Have Stopped Counting", "nvme.cmd.get_logpage.pel.event.por.synch", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_por_origin, { "Timestamp Origin", "nvme.cmd.get_logpage.pel.event.por.origin", FT_UINT8, BASE_DEC, NULL, 0x0e, NULL, HFILL } },
        { &hf_nvme_pel_hwe_code, { "NVM Subsystem Hardware Error Event Code", "nvme.cmd.get_logpage.pel.event.hwe.code", FT_UINT16, BASE_HEX, VALS(pel_hwe_code_tbl), 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_ahei, { "Additional Hardware Error Information", "nvme.cmd.get_logpage.pel.event.hwe.ahei", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_pciedsr, { "PCIe Device Status Register", "nvme.cmd.get_logpage.pel.event.hwe.pciedsr", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_pcieaers, { "PCIe AER Supported", "nvme.cmd.get_logpage.pel.event.hwe.pcieas.aers", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_hwe_pcieas_rsvd, { "Reserved", "nvme.cmd.get_logpage.pel.event.hwe.pcieas.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL } },
        { &hf_nvme_pel_hwe_pcieaes, { "PCIe AER Error Status", "nvme.cmd.get_logpage.pel.event.hwe.pcieaes", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_pcieaem, { "PCIe AER Error Mask", "nvme.cmd.get_logpage.pel.event.hwe.pcieaem", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_pcieahlr, { "PCIe AER Header Log Register", "nvme.cmd.get_logpage.pel.event.hwe.pcieahlr", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_pcieatplr, { "PCIe AER TLP Prefix Log Register", "nvme.cmd.get_logpage.pel.event.hwe.pcieatplr", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_lnksta, { "PCIe Link Status Register", "nvme.cmd.get_logpage.pel.event.hwe.lnksta", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_egid, { "Endurance Group Identifier", "nvme.cmd.get_logpage.pel.event.hwe.egid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_upl, { "Unexpected Power Loss", "nvme.cmd.get_logpage.pel.event.hwe.upl", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_uploa, { "Unexpected Power Loss Due to Out-Of-Band Activity", "nvme.cmd.get_logpage.pel.event.hwe.upli.uploa", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_hwe_upli_rsvd, { "Reserved", "nvme.cmd.get_logpage.pel.event.hwe.upli.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL } },
        { &hf_nvme_pel_hwe_cqe, { "Completion Queue Entry", "nvme.cmd.get_logpage.pel.event.hwe.cqe", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_hwe_cst_cnr, { "Controller Not Ready", "nvme.cmd.get_logpage.pel.event.hwe.cst.cnr", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_nvme_pel_hwe_cst_acmnr, { "Admin Command Media Not Ready", "nvme.cmd.get_logpage.pel.event.hwe.cst.acmnr", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_nvme_pel_hwe_cst_nnr, { "Namespace Not Ready", "nvme.cmd.get_logpage.pel.event.hwe.cst.nnr", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_pel_hwe_cst_crime, { "Controller Ready Independent of Media Enable", "nvme.cmd.get_logpage.pel.event.hwe.cst.crime", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_hwe_cst_rsvd, { "Reserved", "nvme.cmd.get_logpage.pel.event.hwe.cst.rsvd", FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL } },
        { &hf_nvme_pel_nsid, { "Namespace Identifier", "nvme.cmd.get_logpage.pel.event.nsid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cinfo, { "Completion Information", "nvme.cmd.get_logpage.pel.event.cinfo", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cns_nmcdw10[0], { "Namespace Management CDW10", "nvme.cmd.get_logpage.pel.event.cns.nmcdw10", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cns_nmcdw10[1], { "Select", "nvme.cmd.get_logpage.pel.event.cns.nmcdw10.sel", FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(ns_mgmt_sel_rvals), 0x0000000f, NULL, HFILL } },
        { &hf_nvme_pel_cns_nmcdw10[2], { "Reserved", "nvme.cmd.get_logpage.pel.event.cns.nmcdw10.rsvd", FT_UINT32, BASE_HEX, NULL, 0xfffffff0, NULL, HFILL } },
        { &hf_nvme_pel_cns_nsze, { "Namespace Size", "nvme.cmd.get_logpage.pel.event.cns.nsze", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cns_ncap, { "Namespace Capacity", "nvme.cmd.get_logpage.pel.event.cns.ncap", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cns_anagrpid, { "ANA Group Identifier", "nvme.cmd.get_logpage.pel.event.cns.anagrpid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cns_nvmsetid, { "NVM Set Identifier", "nvme.cmd.get_logpage.pel.event.cns.nvmsetid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cns_endgid, { "Endurance Group Identifier", "nvme.cmd.get_logpage.pel.event.cns.endgid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fmc_sfpi, { "Smallest Format Progress Indicator", "nvme.cmd.get_logpage.pel.event.fmc.sfpi", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fmc_fnvms[0], { "Format NVM Status", "nvme.cmd.get_logpage.pel.event.fmc.fnvms", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fmc_fnvms[1], { "Format NVM Error", "nvme.cmd.get_logpage.pel.event.fmc.fnvms.fnvme", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_fmc_fnvms[2], { "Incomplete Format", "nvme.cmd.get_logpage.pel.event.fmc.fnvms.incpltf", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_pel_fmc_fnvms[3], { "Reserved", "nvme.cmd.get_logpage.pel.event.fmc.fnvms.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL } },
        { &hf_nvme_pel_fmc_info[0], { "Status Info", "nvme.cmd.get_logpage.pel.event.fmc.info", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_fmc_info[1], { "Phase Tag", "nvme.cmd.get_logpage.pel.event.fmc.info.p", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_nvme_pel_fmc_info[2], { "Status Code", "nvme.cmd.get_logpage.pel.event.fmc.info.sc", FT_UINT16, BASE_HEX, NULL, 0x01fe, NULL, HFILL } },
        { &hf_nvme_pel_fmc_info[3], { "Status Code Type", "nvme.cmd.get_logpage.pel.event.fmc.info.sct", FT_UINT16, BASE_HEX, NULL, 0x0e00, NULL, HFILL } },
        { &hf_nvme_pel_fmc_info[4], { "Command Retry Delay", "nvme.cmd.get_logpage.pel.event.fmc.info.crd", FT_UINT16, BASE_HEX, NULL, 0x3000, NULL, HFILL } },
        { &hf_nvme_pel_fmc_info[5], { "More", "nvme.cmd.get_logpage.pel.event.fmc.info.m", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL } },
        { &hf_nvme_pel_fmc_info[6], { "Do Not Retry", "nvme.cmd.get_logpage.pel.event.fmc.info.dnr", FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL } },
        { &hf_nvme_pel_sfe_sfel[0], { "Set Feature Event Layout", "nvme.cmd.get_logpage.pel.event.sfe.sfel", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_sfe_sfel[1], { "Dword Count", "nvme.cmd.get_logpage.pel.event.sfe.sfel.dwc", FT_UINT32, BASE_DEC, NULL, 0x00000007, NULL, HFILL } },
        { &hf_nvme_pel_sfe_sfel[2], { "Logged Command Completion Dword 0", "nvme.cmd.get_logpage.pel.event.sfe.sfel.lccdw0", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_nvme_pel_sfe_sfel[3], { "Reserved", "nvme.cmd.get_logpage.pel.event.sfe.sfel.rsvd", FT_UINT32, BASE_HEX, NULL, 0x0000fff0, NULL, HFILL } },
        { &hf_nvme_pel_sfe_sfel[4], { "Memory Buffer Count", "nvme.cmd.get_logpage.pel.event.sfe.sfel.mbc", FT_UINT32, BASE_DEC, NULL, 0xffff0000, NULL, HFILL } },
        { &hf_nvme_pel_sfe_cdw, { "Command Dword", "nvme.cmd.get_logpage.pel.event.sfe.cdw", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_sfe_mbuf, { "Memory Buffer", "nvme.cmd.get_logpage.pel.event.sfe.mbuf", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_sfe_ccdw0, { "Command Completion Dword 0", "nvme.cmd.get_logpage.pel.event.sfe.ccdw0", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_tlc_til, { "Telemetry Initiated Log", "nvme.cmd.get_logpage.pel.event.tlc.til", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_te_otmp, { "Over Temperature (Kelvins)", "nvme.cmd.get_logpage.pel.event.te.otmp", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_te_thresh, { "Threshold", "nvme.cmd.get_logpage.pel.event.te.thresh", FT_UINT8, BASE_RANGE_STRING | BASE_HEX, RVALS(pel_te_thresh_rvals), 0, NULL, HFILL } },
        { &hf_nvme_pel_cdp_ps[0], { "Personality Status", "nvme.cmd.get_logpage.pel.event.cdp.ps", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cdp_ps[1], { "CDP Change Error", "nvme.cmd.get_logpage.pel.event.cdp.ps.cdpce", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_nvme_pel_cdp_ps[2], { "CDP Requested Freeze State", "nvme.cmd.get_logpage.pel.event.cdp.ps.cdprfs", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_nvme_pel_cdp_ps[3], { "Reserved", "nvme.cmd.get_logpage.pel.event.cdp.ps.rsvd", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL } },
        { &hf_nvme_pel_cdp_perid, { "Personality Identifier", "nvme.cmd.get_logpage.pel.event.cdp.perid", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_cdp_ped, { "Personality Event Data", "nvme.cmd.get_logpage.pel.event.cdp.ped", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ensc_esubid, { "Exported NVM Subsystem Identifier", "nvme.cmd.get_logpage.pel.event.ensc.esubid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ensc_otyp, { "Operation Type", "nvme.cmd.get_logpage.pel.event.ensc.otyp", FT_UINT8, BASE_HEX, VALS(pel_ensc_otyp_tbl), 0, NULL, HFILL } },
        { &hf_nvme_pel_ensc_eeid, { "Exported Entity Identifier", "nvme.cmd.get_logpage.pel.event.ensc.eeid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ensc_eeid_esubid, { "Exported NVM Subsystem Identifier", "nvme.cmd.get_logpage.pel.event.ensc.eeid.esubid", FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_pel_ensc_eeid_nsid, { "Exported Namespace Identifier", "nvme.cmd.get_logpage.pel.event.ensc.eeid.nsid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ensc_eeid_cntlid, { "Exported Controller Identifier", "nvme.cmd.get_logpage.pel.event.ensc.eeid.cntlid", FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_pel_ensc_eeid_portid, { "Exported Port Identifier", "nvme.cmd.get_logpage.pel.event.ensc.eeid.portid", FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_pel_ensc_ueid, { "Underlying Entity Identifier", "nvme.cmd.get_logpage.pel.event.ensc.ueid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ensc_ueid_nsid, { "Underlying Namespace Identifier", "nvme.cmd.get_logpage.pel.event.ensc.ueid.nsid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_ensc_ueid_cntlid, { "Underlying Controller Identifier", "nvme.cmd.get_logpage.pel.event.ensc.ueid.cntlid", FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_pel_ensc_ueid_portid, { "Underlying Port Identifier", "nvme.cmd.get_logpage.pel.event.ensc.ueid.portid", FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL } },
        { &hf_nvme_pel_ensc_id_rsvd, { "Reserved", "nvme.cmd.get_logpage.pel.event.ensc.id.rsvd", FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL } },
        { &hf_nvme_pel_vse_desc, { "Vendor Specific Event Descriptor", "nvme.cmd.get_logpage.pel.event.vse.desc", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_vse_vsec, { "Vendor Specific Event Code", "nvme.cmd.get_logpage.pel.event.vse.vsec", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_vse_vsedt, { "Vendor Specific Event Data Type", "nvme.cmd.get_logpage.pel.event.vse.vsedt", FT_UINT8, BASE_HEX, VALS(pel_vse_vsedt_tbl), 0, NULL, HFILL } },
        { &hf_nvme_pel_vse_uidx, { "UUID Index", "nvme.cmd.get_logpage.pel.event.vse.uidx", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_vse_vsedl, { "Vendor Specific Event Data Length", "nvme.cmd.get_logpage.pel.event.vse.vsedl", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_vse_vsed_str, { "Vendor Specific Event Data", "nvme.cmd.get_logpage.pel.event.vse.vsed.str", FT_STRINGZPAD, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_vse_vsed_int, { "Vendor Specific Event Data", "nvme.cmd.get_logpage.pel.event.vse.vsed.int", FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_nvme_pel_vse_vsed, { "Vendor Specific Event Data", "nvme.cmd.get_logpage.pel.event.vse.vsed", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_nvme_lidsp_extdlpes, { "Extended Discovery Log Page Entry Supported (EXTDLPES)", "nvme.cmd.get_logpage.supported.extdlpes", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_nvme_lidsp_pleos, { "Port Local Entries Only Supported (PLEOS)", "nvme.cmd.get_logpage.supported.pleos", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_nvme_lidsp_allsubes, { "All NVM Subsystem Entries Supported (ALLSUBES)", "nvme.cmd.get_logpage.supported.allsubes", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_nvme_lidsp_allhostes, { "All Host Entries Supported (ALLHOSTES)", "nvme.cmd.get_logpage.supported.allhostes", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        /* NVMeOF Fabric Command Fields */
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
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(fctype_tbl), 0x0, NULL, HFILL}
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
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0, NULL, HFILL}
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
               FT_STRINGZTRUNC, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_cmd_connect_data_hostnqn,
            { "Host NQN", "nvme.fabrics.cmd.connect.data.hostnqn",
               FT_STRINGZTRUNC, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_zero_base_64), 0xffff, NULL, HFILL}
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
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_page_size_64), 0xF000000000000, NULL, HFILL}
        },
        { &hf_nvmeof_prop_get_ccap[13],
            { "Memory Page Size Maximum", "nvme.fabrics.prop_get.ccap.mpsmax",
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_ctrl_pow2_page_size_64), 0xF0000000000000, NULL, HFILL}
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
        { &hf_nvme_cmd_dword2,
            { "DWORD2", "nvme.cmd.dword2",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_dword3,
            { "DWORD3", "nvme.cmd.dword3",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
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
            { "Number of Logical Blocks (NLB)", "nvme.cmd.nlb",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_rsvd2,
            { "Reserved", "nvme.cmd.rsvd2",
               FT_UINT16, BASE_HEX, NULL, 0x03ff, NULL, HFILL}
        },
        { &hf_nvme_cmd_prinfo,
            { "Protection info fields",
              "nvme.cmd.prinfo",
               FT_UINT16, BASE_HEX, NULL, 0x3c00, NULL, HFILL}
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
        /* NVM CS 1.2 Figure 56: CDW14 is ELBTL. */
        { &hf_nvme_cmd_elbtl,
            { "Expected Logical Block Tags Lower", "nvme.cmd.elbtl",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* NVM CS 1.2 Figure 57: ELBAT 15:00, ELBATM 31:16. */
        { &hf_nvme_cmd_elbat,
            { "Expected Logical Block Application Tag", "nvme.cmd.elbat",
               FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_elbatm,
            { "Expected Logical Block Application Tag Mask", "nvme.cmd.elbatm",
               FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        /* The Write forms (NVM CS 1.2 Figures 73/74). */
        { &hf_nvme_cmd_lbtl,
            { "Logical Block Tags Lower", "nvme.cmd.lbtl",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cmd_lbat,
            { "Logical Block Application Tag", "nvme.cmd.lbat",
               FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_lbatm,
            { "Logical Block Application Tag Mask", "nvme.cmd.lbatm",
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
               FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 324: CNS Specific Identifier. */
        { &hf_nvme_identify_dword11[1],
            { "CNS Specific Identifier (CNSSID)", "nvme.cmd.identify.dword11.cnssid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 324: Reserved is 23:16, CSI is 31:24. */
        { &hf_nvme_identify_dword11[2],
            { "Reserved", "nvme.cmd.identify.dword11.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x00ff0000, NULL, HFILL}
        },
        { &hf_nvme_identify_dword11[3],
            { "Command Set Identifier (CSI)", "nvme.cmd.identify.dword11.csi",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(csi_tbl), 0xff000000, NULL, HFILL}
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
            { "Reserved", "nvme.cmd.identify.dword14.rsvd",
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
        { &hf_nvme_get_logpage_cs_name,
            { "Command Set Specific Log Page", "nvme.cmd.get_logpage.cs_name",
               FT_STRING, BASE_NONE, NULL, 0x0,
               "LID name selected by the CSI field in CDW14", HFILL}
        },
        { &hf_nvme_get_logpage_dword10[2],
            { "Log Specific Parameter (LSP)", "nvme.cmd.get_logpage.dword10.lsp",
               FT_UINT32, BASE_HEX, NULL, 0x7f00, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10_lsp_act,
            { "Action (ACT)", "nvme.cmd.get_logpage.dword10.lsp.act",
               FT_UINT32, BASE_HEX, VALS(eom_lsp_act_tbl), 0x00000c00, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10_lsp_mqual,
            { "Measurement Quality (MQUAL)", "nvme.cmd.get_logpage.dword10.lsp.mqual",
               FT_UINT32, BASE_HEX, VALS(eom_lsp_mqual_tbl), 0x00000300, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10[3],
            { "Retain Asynchronous Event (RAE)", "nvme.cmd.get_logpage.dword10.rae",
               FT_BOOLEAN, 32, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword10[4],
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
            { "Log Specific Identifier (LSI)", "nvme.cmd.get_logpage.dword11.lsi",
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
        /* NVMe Base 2.3 Figure 205: UIDX is 06:00, Reserved 22:07, Offset Type
         * bit 23, CSI 31:24. */
        { &hf_nvme_get_logpage_dword14[1],
            { "UUID Index", "nvme.cmd.get_logpage.dword14.uuid_index",
               FT_UINT32, BASE_HEX, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword14[2],
            { "Reserved", "nvme.cmd.get_logpage.dword14.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x007fff80, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword14[3],
            { "Offset Type (OT)", "nvme.cmd.get_logpage.dword14.ot",
               FT_BOOLEAN, 32, NULL, 0x00800000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_dword14[4],
            { "Command Set Identifier (CSI)", "nvme.cmd.get_logpage.dword14.csi",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(csi_tbl), 0xff000000, NULL, HFILL}
        },
        /* Set Features */
        { &hf_nvme_set_features_dword10[0],
            { "DWORD 10", "nvme.cmd.set_features.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_dword10[1],
            { "Feature Identifier", "nvme.cmd.set_features.dword10.fid",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(fid_table), 0xff, NULL, HFILL}
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
        /* Format NVM – Command Dword 10 */
        { &hf_nvme_format_nvm_dword10[0],
            { "DWORD10", "nvme.cmd.format_nvm.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_format_nvm_dword10[1],
            { "LBA Format Lower (LBAFL)", "nvme.cmd.format_nvm.dword10.lbafl",
               FT_UINT32, BASE_HEX, NULL, 0x0000000f, NULL, HFILL}
        },
        { &hf_nvme_format_nvm_dword10[2],
            { "Metadata Settings (MSET)", "nvme.cmd.format_nvm.dword10.mset",
               FT_UINT32, BASE_HEX, NULL, 0x00000010, "I/O Command Set specific", HFILL}
        },
        { &hf_nvme_format_nvm_dword10[3],
            { "Protection Information (PI)", "nvme.cmd.format_nvm.dword10.pi",
               FT_UINT32, BASE_HEX, NULL, 0x000000e0, "I/O Command Set specific", HFILL}
        },
        { &hf_nvme_format_nvm_dword10[4],
            { "Protection Information Location (PIL)", "nvme.cmd.format_nvm.dword10.pil",
               FT_UINT32, BASE_HEX, NULL, 0x00000100, "I/O Command Set specific", HFILL}
        },
        { &hf_nvme_format_nvm_dword10[5],
            { "Secure Erase Settings (SES)", "nvme.cmd.format_nvm.dword10.ses",
               FT_UINT32, BASE_HEX, VALS(fmt_nvm_ses_tbl), 0x00000e00, NULL, HFILL}
        },
        { &hf_nvme_format_nvm_dword10[6],
            { "LBA Format Upper (LBAFU)", "nvme.cmd.format_nvm.dword10.lbafu",
               FT_UINT32, BASE_HEX, NULL, 0x00003000, NULL, HFILL}
        },
        { &hf_nvme_format_nvm_dword10[7],
            { "Reserved", "nvme.cmd.format_nvm.dword10.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffc000, NULL, HFILL}
        },
        /* Firmware Commit – Command Dword 10 */
        { &hf_nvme_fw_commit_dword10[0],
            { "DWORD10", "nvme.cmd.fw_commit.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_fw_commit_dword10[1],
            { "Firmware Slot (FS)", "nvme.cmd.fw_commit.dword10.fs",
               FT_UINT32, BASE_HEX, NULL, 0x00000007, NULL, HFILL}
        },
        { &hf_nvme_fw_commit_dword10[2],
            { "Commit Action (CA)", "nvme.cmd.fw_commit.dword10.ca",
               FT_UINT32, BASE_HEX, VALS(fw_commit_ca_tbl), 0x00000038, NULL, HFILL}
        },
        { &hf_nvme_fw_commit_dword10[3],
            { "Reserved", "nvme.cmd.fw_commit.dword10.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x7fffffc0, NULL, HFILL}
        },
        { &hf_nvme_fw_commit_dword10[4],
            { "Boot Partition ID (BPID)", "nvme.cmd.fw_commit.dword10.bpid",
               FT_UINT32, BASE_HEX, NULL, 0x80000000, NULL, HFILL}
        },
        /* Firmware Image Download – Command Dwords 10/11 */
        { &hf_nvme_fw_download_numd,
            { "Number of Dwords (NUMD)", "nvme.cmd.fw_download.numd",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0x0,
               "Number of dwords to transfer, a 0's based value", HFILL}
        },
        { &hf_nvme_fw_download_ofst,
            { "Offset (OFST)", "nvme.cmd.fw_download.ofst",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               "Dword offset from the start of the firmware image", HFILL}
        },
        /* Device Self-test – Command Dword 10 */
        { &hf_nvme_self_test_dword10[0],
            { "DWORD10", "nvme.cmd.self_test.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_self_test_dword10[1],
            { "Self-test Code (STC)", "nvme.cmd.self_test.dword10.stc",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(self_test_stc_rvals), 0x0000000f, NULL, HFILL}
        },
        { &hf_nvme_self_test_dword10[2],
            { "Reserved", "nvme.cmd.self_test.dword10.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff0, NULL, HFILL}
        },
        { &hf_nvme_self_test_dstp,
            { "Device Self-test Parameter (DSTP)", "nvme.cmd.self_test.dstp",
               FT_UINT32, BASE_HEX, NULL, 0, "Vendor specific", HFILL}
        },
        /* Lockdown – Command Dword 10 */
        { &hf_nvme_lockdown_dword10[0],
            { "DWORD10", "nvme.cmd.lockdown.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword10[1],
            { "Scope (SCP)", "nvme.cmd.lockdown.dword10.scp",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(lockdown_scp_rvals), 0x0000000f, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword10[2],
            { "Prohibit (PRHBT)", "nvme.cmd.lockdown.dword10.prhbt",
               FT_UINT32, BASE_HEX, NULL, 0x00000010, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword10[3],
            { "Interface (IFC)", "nvme.cmd.lockdown.dword10.ifc",
               FT_UINT32, BASE_HEX, VALS(lockdown_ifc_tbl), 0x00000060, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword10[4],
            { "Reserved", "nvme.cmd.lockdown.dword10.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0x00000080, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword10[5],
            { "Opcode or Feature Identifier (OFI)", "nvme.cmd.lockdown.dword10.ofi",
               FT_UINT32, BASE_HEX, NULL, 0x0000ff00, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword10[6],
            { "Controller Select (CSEL)", "nvme.cmd.lockdown.dword10.csel",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(lockdown_csel_rvals), 0x000f0000, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword10[7],
            { "Reserved", "nvme.cmd.lockdown.dword10.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xfff00000, NULL, HFILL}
        },
        /* Lockdown – Command Dword 14 */
        { &hf_nvme_lockdown_dword14[0],
            { "DWORD14", "nvme.cmd.lockdown.dword14",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword14[1],
            { "UUID Index (UIDX)", "nvme.cmd.lockdown.dword14.uidx",
               FT_UINT32, BASE_HEX, NULL, 0x0000007f, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword14[2],
            { "Reserved", "nvme.cmd.lockdown.dword14.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x0000ff80, NULL, HFILL}
        },
        { &hf_nvme_lockdown_dword14[3],
            { "Controller Select Specific (CSS)", "nvme.cmd.lockdown.dword14.css",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        /* Sanitize – Command Dwords 10/11 */
        { &hf_nvme_sanitize_dword10[0],
            { "DWORD10", "nvme.cmd.sanitize.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_sanitize_dword10[1],
            { "Sanitize Action (SANACT)", "nvme.cmd.sanitize.dword10.sanact",
               FT_UINT32, BASE_HEX, VALS(sanitize_act_tbl), 0x00000007, NULL, HFILL}
        },
        { &hf_nvme_sanitize_dword10[2],
            { "Allow Unrestricted Sanitize Exit (AUSE)", "nvme.cmd.sanitize.dword10.ause",
               FT_UINT32, BASE_HEX, NULL, 0x00000008, NULL, HFILL}
        },
        { &hf_nvme_sanitize_dword10[3],
            { "Overwrite Pass Count (OWPASS)", "nvme.cmd.sanitize.dword10.owpass",
               FT_UINT32, BASE_HEX, NULL, 0x000000f0, NULL, HFILL}
        },
        { &hf_nvme_sanitize_dword10[4],
            { "Overwrite Invert Pattern Between Passes (OIPBP)", "nvme.cmd.sanitize.dword10.oipbp",
               FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL}
        },
        { &hf_nvme_sanitize_dword10[5],
            { "No-Deallocate After Sanitize (NDAS)", "nvme.cmd.sanitize.dword10.ndas",
               FT_UINT32, BASE_HEX, NULL, 0x00000200, NULL, HFILL}
        },
        { &hf_nvme_sanitize_dword10[6],
            { "Enter Media Verification State (EMVS)", "nvme.cmd.sanitize.dword10.emvs",
               FT_UINT32, BASE_HEX, NULL, 0x00000400, NULL, HFILL}
        },
        { &hf_nvme_sanitize_dword10[7],
            { "Purge Required (PREQ)", "nvme.cmd.sanitize.dword10.preq",
               FT_UINT32, BASE_HEX, NULL, 0x00000800, NULL, HFILL}
        },
        { &hf_nvme_sanitize_dword10[8],
            { "Reserved", "nvme.cmd.sanitize.dword10.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffff000, NULL, HFILL}
        },
        { &hf_nvme_sanitize_ovrpat,
            { "Overwrite Pattern (OVRPAT)", "nvme.cmd.sanitize.ovrpat",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* Security Send (81h) / Security Receive (82h) */
        { &hf_nvme_security_dword10[0],
            { "DWORD10", "nvme.cmd.security.dword10",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_security_dword10[1],
            { "Security Protocol (SECP)", "nvme.cmd.security.dword10.secp",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(security_secp_tbl), 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_security_dword10[2],
            { "SP Specific 1 (SPSP1)", "nvme.cmd.security.dword10.spsp1",
               FT_UINT32, BASE_HEX, NULL, 0x00ff0000, NULL, HFILL}
        },
        { &hf_nvme_security_dword10[3],
            { "SP Specific 0 (SPSP0)", "nvme.cmd.security.dword10.spsp0",
               FT_UINT32, BASE_HEX, NULL, 0x0000ff00, NULL, HFILL}
        },
        { &hf_nvme_security_dword10[4],
            { "NVMe Security Specific Field (NSSF)", "nvme.cmd.security.dword10.nssf",
               FT_UINT32, BASE_HEX, NULL, 0x000000ff, NULL, HFILL}
        },
        { &hf_nvme_security_spsp,
            { "SP Specific (SPSP)", "nvme.cmd.security.dword10.spsp",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               "SPSP1 (bits 15:08) and SPSP0 (bits 07:00) as one value", HFILL}
        },
        { &hf_nvme_security_send_dword11_tl,
            { "Transfer Length (TL)", "nvme.cmd.security_send.dword11.tl",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_recv_dword11_al,
            { "Allocation Length (AL)", "nvme.cmd.security_recv.dword11.al",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_data,
            { "Security Protocol Data", "nvme.cmd.security.data",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_info,
            { "Security Protocol Information", "nvme.security.info",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_info_rsvd,
            { "Reserved", "nvme.security.info.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_info_list_len,
            { "Supported Security Protocol List Length", "nvme.security.info.list_len",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_info_protocol,
            { "Supported Security Protocol", "nvme.security.info.protocol",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(security_secp_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_info_cert_len,
            { "Certificate Data Length", "nvme.security.info.cert_len",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_info_cert_data,
            { "Certificate Data", "nvme.security.info.cert_data",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_security_info_compliance_len,
            { "Compliance Descriptors Length", "nvme.security.info.compliance_len",
               FT_UINT32, BASE_DEC, NULL, 0x0, "SPC-5 Security Compliance Information", HFILL}
        },
        { &hf_nvme_security_info_compliance_desc,
            { "Compliance Descriptors", "nvme.security.info.compliance_desc",
               FT_BYTES, BASE_NONE, NULL, 0x0, "SPC-5 compliance descriptors, not decoded", HFILL}
        },
        { &hf_nvme_security_info_residue,
            { "Uninterpreted SECP 00h residue", "nvme.security.info.residue",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               "Bytes beyond the legacy declared length; SPC-5 layout unverified", HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.arb",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[1],
            { "Arbitration Burst", "nvme.cmd.set_features.dword11.arb.ab",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_arb_burst), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[2],
            { "Reserved", "nvme.cmd.set_features.dword11.arb.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[3],
            { "Low Priority Weight", "nvme.cmd.set_features.dword11.arb.lpw",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xff00, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[4],
            { "Medium Priority Weight", "nvme.cmd.set_features.dword11.arb.mpw",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_arb[5],
            { "High Priority Weight", "nvme.cmd.set_features.dword11.arb.hpw",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xff000000, NULL, HFILL}
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
            { "Workload Hint (WH)", "nvme.cmd.set_features.dword11.pm.wh",
               FT_UINT32, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_pm[3],
            { "Reserved", "nvme.cmd.set_features.dword11.pm.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x0000ff00, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_pm[4],
            { "Idle I/O Exit Latency Limit (IIELL)", "nvme.cmd.set_features.dword11.pm.iiell",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_pm_iiell), 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbart[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.lbart",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbart[1],
            { "Number of LBA Ranges (NUM)", "nvme.cmd.set_features.dword11.lbart.lbarn",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0x3f, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_lbart[2],
            { "Reserved", "nvme.cmd.set_features.dword11.lbart.rsvd",
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
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(sf_tmpsel_table), 0x000f0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_tt[3],
            { "Threshold Type Select", "nvme.cmd.set_features.dword11.tt.thpsel",
               FT_UINT32, BASE_HEX, VALS(sf_thpsel_table), 0x300000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_tt[4],
            { "Temperature Threshold Hysteresis", "nvme.cmd.set_features.dword11.tt.tmpthh",
               FT_UINT32, BASE_HEX, NULL, 0x1c00000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_tt[5],
            { "Reserved", "nvme.cmd.set_features.dword11.tt.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfe000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_get_features_dword11_tt_tmpsel,
            { "Threshold Temperature Select", "nvme.cmd.get_features.dword11.tt.tmpsel",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(gf_tmpsel_table), 0x000f0000, NULL, HFILL}
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
               FT_UINT32, BASE_HEX, NULL, 0xfffe0000, NULL, HFILL}
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
            { "Reserved", "nvme.cmd.set_features.dword11.vwce.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nq[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.nq",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nq[1],
            { "Number of IO Submission Queues Requested", "nvme.cmd.set_features.dword11.nq.nsqr",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nq[2],
            { "Number of IO Completion Queues Requested", "nvme.cmd.set_features.dword11.nq.ncqr",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xffff0000, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 474: THR 07:00 (0's based), TIME 15:08. */
        { &hf_nvme_cmd_set_features_dword11_irqc[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.irqc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqc[1],
            { "Aggregation Threshold", "nvme.cmd.set_features.dword11.irqc.thr",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqc[2],
            { "Aggregation Time (100 us units)", "nvme.cmd.set_features.dword11.irqc.time",
               FT_UINT32, BASE_HEX, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqc[3],
            { "Reserved", "nvme.cmd.set_features.dword11.irqc.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqv[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.irqv",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqv[1],
            { "IRQ Vector", "nvme.cmd.set_features.dword11.irqv.iv",
               FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_irqv[2],
            { "Coalescing Disable", "nvme.cmd.set_features.dword11.irqv.cd",
               FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 409; LHCN/CCRCN names from Figure 328. */
        { &hf_nvme_cmd_set_features_dword11_aec[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.aec",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[1],
            { "SMART and Health Critical Warnings Bitmask", "nvme.cmd.set_features.dword11.aec.smart",
               FT_UINT32, BASE_HEX, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[2],
            { "Attached Namespace Attribute Notices (NAN)", "nvme.cmd.set_features.dword11.aec.ns",
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
            { "Normal NVM Subsystem Shutdown (NNSSHDN)", "nvme.cmd.set_features.dword11.aec.nnsshdn",
               FT_BOOLEAN, 32, TFS(&aec_event_notice_tfs), 0x8000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[10],
            { "Temperature Threshold Hysteresis Recovery (TTHRY)", "nvme.cmd.set_features.dword11.aec.tthry",
               FT_BOOLEAN, 32, TFS(&aec_event_notice_tfs), 0x10000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[11],
            { "Reachability Association (RASSN)", "nvme.cmd.set_features.dword11.aec.rassn",
               FT_BOOLEAN, 32, TFS(&aec_event_notice_tfs), 0x20000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[12],
            { "Reachability Group (RGRP0)", "nvme.cmd.set_features.dword11.aec.rgrp0",
               FT_BOOLEAN, 32, TFS(&aec_event_notice_tfs), 0x40000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[13],
            { "Allocated Namespace Attribute Notices (ANSAN)", "nvme.cmd.set_features.dword11.aec.ansan",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[14],
            { "Cross-Controller Reset Completed Notices (CCRCN)", "nvme.cmd.set_features.dword11.aec.ccrcn",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[15],
            { "Lost Host Communication Notices (LHCN)", "nvme.cmd.set_features.dword11.aec.lhcn",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[16],
            { "Rate Limiting Configuration Change Notices (RLCCN)", "nvme.cmd.set_features.dword11.aec.rlccn",
               FT_BOOLEAN, 32, NULL, 0x400000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[22],
            { "Reserved", "nvme.cmd.set_features.dword11.aec.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x7800000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[17],
            { "Zone Descriptor Changed Notices (ZDCN)", "nvme.cmd.set_features.dword11.aec.zdcn",
               FT_BOOLEAN, 32, NULL, 0x8000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[18],
            { "Pull Model DDC Request Log Page Change Notification (PMDRLPCN)", "nvme.cmd.set_features.dword11.aec.pmdrlpcn",
               FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[19],
            { "AVE Discovery Log Page Change Notification (ADLPCN)", "nvme.cmd.set_features.dword11.aec.adlpcn",
               FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[20],
            { "Host Discovery Log Page Change Notification (HDLPCN)", "nvme.cmd.set_features.dword11.aec.hdlpcn",
               FT_BOOLEAN, 32, NULL, 0x40000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_aec[21],
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
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hctm[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.hctm",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hctm[1],
            { "Thermal Management Temperature 2 (K)", "nvme.cmd.set_features.dword11.hctm.tmt2",
               FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hctm[2],
            { "Thermal Management Temperature 1 (K)", "nvme.cmd.set_features.dword11.hctm.tmt1",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
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
            { "Window Select (WSEL)", "nvme.cmd.set_features.dword12.plmw.ws",
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
               FT_UINT32, BASE_HEX, NULL, 0xfffffff0, NULL, HFILL}
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
            { "Write Protection State (WPS)", "nvme.cmd.set_features.dword11.nswp.wps",
               FT_UINT32, BASE_HEX, VALS(sf_wps), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_nswp[2],
            { "Reserved", "nvme.cmd.set_features.dword11.nswp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff8, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmd[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.hmd",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmd[1],
            { "Element Action", "nvme.cmd.set_features.dword11.hmd.ea",
               FT_UINT32, BASE_HEX, VALS(sf_host_metadata_ea), 0x6000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmd[2],
            { "Reserved", "nvme.cmd.set_features.dword11.hmd.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff9fff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmb[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.hmb",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmb[1],
            { "Enable Host Memory (EHM)", "nvme.cmd.set_features.dword11.hmb.ehm",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmb[2],
            { "Memory Return (MR)", "nvme.cmd.set_features.dword11.hmb.mr",
               FT_UINT32, BASE_HEX, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmb[3],
            { "Host Memory Non-operational Access Restriction Enable (HMNARE)", "nvme.cmd.set_features.dword11.hmb.hmnare",
               FT_UINT32, BASE_HEX, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmb[4],
            { "Cleared to Zero (CTZ)", "nvme.cmd.set_features.dword11.hmb.ctz",
               FT_UINT32, BASE_HEX, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_hmb[5],
            { "Reserved", "nvme.cmd.set_features.dword11.hmb.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_iocsp[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.iocsp",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_iocsp[1],
            { "I/O Command Set Combination Index (IOCSCI)", "nvme.cmd.set_features.dword11.iocsp.iocsci",
               FT_UINT32, BASE_HEX, NULL, 0x1ff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_iocsp[2],
            { "Reserved", "nvme.cmd.set_features.dword11.iocsp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffe00, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_spinup[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.spinup",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_spinup[1],
            { "Spinup Control Enable (SCE)", "nvme.cmd.set_features.dword11.spinup.sce",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_spinup[2],
            { "Reserved", "nvme.cmd.set_features.dword11.spinup.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plsc[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.plsc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plsc[1],
            { "Power Loss Signaling Mode (PLSM)", "nvme.cmd.set_features.dword11.plsc.plsm",
               FT_UINT32, BASE_HEX, VALS(sf_plsm), 0x3, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_plsc[2],
            { "Reserved", "nvme.cmd.set_features.dword11.plsc.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffc, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_fdp[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.fdp",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_fdp[1],
            { "Endurance Group Identifier (ENDGID)", "nvme.cmd.set_features.dword11.fdp.endgid",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_fdp[2],
            { "Reserved", "nvme.cmd.set_features.dword11.fdp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_fdpe[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.fdpe",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_fdpe[1],
            { "Placement Handle (PHNDL)", "nvme.cmd.set_features.dword11.fdpe.phndl",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_fdpe[2],
            { "Number of FDP Event Types (NOET)", "nvme.cmd.set_features.dword11.fdpe.noet",
               FT_UINT32, BASE_HEX, NULL, 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_fdpe[3],
            { "Reserved", "nvme.cmd.set_features.dword11.fdpe.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_bpwpc[0],
            { "DWORD11", "nvme.cmd.set_features.dword11.bpwpc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_bpwpc[1],
            { "Boot Partition 0 Write Protection State (BP0WPS)", "nvme.cmd.set_features.dword11.bpwpc.bp0wps",
               FT_UINT32, BASE_HEX, VALS(sf_bpwps), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_bpwpc[2],
            { "Boot Partition 1 Write Protection State (BP1WPS)", "nvme.cmd.set_features.dword11.bpwpc.bp1wps",
               FT_UINT32, BASE_HEX, VALS(sf_bpwps), 0x38, NULL, HFILL}
        },
        { &hf_nvme_cmd_set_features_dword11_bpwpc[3],
            { "Reserved", "nvme.cmd.set_features.dword11.bpwpc.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffffc0, NULL, HFILL}
        },
        /* Set Features Transfers */
        { &hf_nvme_set_features_tr_lbart,
            { "LBA Range Structure", "nvme.set_features.lbart",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_lbart_type,
            { "Type", "nvme.set_features.lbart.type",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(sf_lbart_type_table), 0x0, NULL, HFILL}
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
               FT_UINT64, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based64), 0x0, NULL, HFILL}
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
            { "Idle Time Prior to Transition (ms)", "nvme.set_features.lbart.apst.itpt",
               FT_UINT64, BASE_HEX, NULL, 0xffffff00, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 415 (Get Features): byte 06 is TSTMPS. */
        { &hf_nvme_get_features_tr_tst[0],
            { "Timestamp Structure", "nvme.get_features.tst",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_features_tr_tst[1],
            { "Timestamp (TSTMP)", "nvme.get_features.tst.tstmp",
               FT_UINT64, BASE_HEX, NULL, 0xffffffffffff, NULL, HFILL}
        },
        { &hf_nvme_get_features_tr_tst[2],
            { "Synch (SYNC)", "nvme.get_features.tst.sync",
               FT_BOOLEAN, 64, TFS(&sf_tst_sync_tfs), 0x1000000000000, NULL, HFILL}
        },
        { &hf_nvme_get_features_tr_tst[3],
            { "Timestamp Origin (TSTMPO)", "nvme.get_features.tst.tstmpo",
               FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(sf_tstmpo_table), 0xe000000000000, NULL, HFILL}
        },
        { &hf_nvme_get_features_tr_tst[4],
            { "Reserved", "nvme.get_features.tst.tstmps_rsvd",
               FT_UINT64, BASE_HEX, NULL, 0xf0000000000000, NULL, HFILL}
        },
        { &hf_nvme_get_features_tr_tst[5],
            { "Reserved", "nvme.get_features.tst.rsvd",
               FT_UINT64, BASE_HEX, NULL, 0xff00000000000000, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_plmc,
            { "Deterministic Threshold Configuration Structure", "nvme.set_features.plmc",
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
        { &hf_nvme_set_features_tr_hbs_etdas,
            { "Extended Telemetry Data Area 4 Supported", "nvme.set_features.hbs.etdas",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_lbafee,
            { "LBA Format Extension Enable", "nvme.set_features.hbs.lbafee",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_hdisns,
            { "Host Dispersed Namespace Support", "nvme.set_features.hbs.hdisns",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_cdfe[0],
            { "Copy Descriptor Formats Enable (CDFE)", "nvme.set_features.hbs.cdfe",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_cdfe[1],
            { "Not Used (NUSED)", "nvme.set_features.hbs.cdfe.nused",
               FT_UINT16, BASE_HEX, NULL, 0x0003, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_cdfe[2],
            { "Copy Descriptor Format 2h Enable", "nvme.set_features.hbs.cdfe.cdf2e",
               FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_cdfe[3],
            { "Copy Descriptor Format 3h Enable", "nvme.set_features.hbs.cdfe.cdf3e",
               FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_cdfe[4],
            { "Copy Descriptor Format 4h Enable", "nvme.set_features.hbs.cdfe.cdf4e",
               FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_cdfe[5],
            { "Reserved", "nvme.set_features.hbs.cdfe.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xffe0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hbs_rsvd,
            { "Reserved", "nvme.set_features.hbs.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hmd,
            { "Host Metadata Data Structure", "nvme.set_features.hmd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hmd_nmed,
            { "Number of Metadata Element Descriptors", "nvme.set_features.hmd.nmed",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hmd_rsvd,
            { "Reserved", "nvme.set_features.hmd.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hmd_med,
            { "Metadata Element Descriptor", "nvme.set_features.hmd.med",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hmd_med_et,
            { "Element Type", "nvme.set_features.hmd.med.et",
               FT_UINT32, BASE_HEX, NULL, 0x0000001f, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hmd_med_er,
            { "Element Revision", "nvme.set_features.hmd.med.er",
               FT_UINT32, BASE_HEX, NULL, 0x00000f00, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hmd_med_elen,
            { "Element Length", "nvme.set_features.hmd.med.elen",
               FT_UINT32, BASE_DEC, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_set_features_tr_hmd_med_eval,
            { "Element Value", "nvme.set_features.hmd.med.eval",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Get Features */
        { &hf_nvme_get_features_dword10[0],
            { "DWORD 10", "nvme.cmd.get_features.dword10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_features_dword10[1],
            { "Feature Identifier", "nvme.cmd.get_features.dword10.fid",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(fid_table), 0xff, NULL, HFILL}
        },
        { &hf_nvme_get_features_dword10[2],
            { "Select", "nvme.cmd.get_features.dword10.sel",
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
            { "NVM Set Identifier", "nvme.cmd.get_features.dword11.rrl.nvmsetid",
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
        { &hf_nvme_identify_ns_nsfeat[0],
            { "Namespace Features (NSFEAT)", "nvme.cmd.identify.ns.nsfeat",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsfeat[1],
            { "Thin Provisioning (THINP)", "nvme.cmd.identify.ns.nsfeat.thinp",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsfeat[2],
            { "Namespace Supported Atomic Boundary & Power (NSABP)", "nvme.cmd.identify.ns.nsfeat.nsabp",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsfeat[3],
            { "Deallocated Error (DAE)", "nvme.cmd.identify.ns.nsfeat.dae",
               FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsfeat[4],
            { "UID Reuse (UIDREUSE)", "nvme.cmd.identify.ns.nsfeat.uidreuse",
               FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsfeat[5],
            { "Optional Write Performance (OPTPERF)", "nvme.cmd.identify.ns.nsfeat.optperf",
               FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsfeat[6],
            { "Multiple Atomicity Mode (MAM)", "nvme.cmd.identify.ns.nsfeat.mam",
               FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsfeat[7],
            { "Optional Read Performance (OPTRPERF)", "nvme.cmd.identify.ns.nsfeat.optrperf",
               FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nlbaf,
            { "Number of LBA Formats (NLBAF)", "nvme.cmd.identify.ns.nlbaf",
               FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_flbas[0],
            { "Formatted LBA Size (FLBAS)", "nvme.cmd.identify.ns.flbas",
               FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_flbas[1],
            { "Format Index Lower (FIDXL)", "nvme.cmd.identify.ns.flbas.fidxl",
               FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_flbas[2],
            { "Metadata Transferred as Extended LBA (MTELBA)", "nvme.cmd.identify.ns.flbas.mtelba",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_flbas[3],
            { "Format Index Upper (FIDXU)", "nvme.cmd.identify.ns.flbas.fidxu",
               FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_flbas[4],
            { "Reserved", "nvme.cmd.identify.ns.flbas.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_mc[0],
            { "Metadata Capabilities (MC)", "nvme.cmd.identify.ns.mc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_mc[1],
            { "Metadata Transferred as Extended LBA Support (MTELBAS)", "nvme.cmd.identify.ns.mc.mtelbas",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_mc[2],
            { "Metadata Transferred as Separate Buffer Support (MTSBS)", "nvme.cmd.identify.ns.mc.mtsbs",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_mc[3],
            { "Reserved", "nvme.cmd.identify.ns.mc.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dpc[0],
            { "End-to-end Data Protection Capabilities (DPC)", "nvme.cmd.identify.ns.dpc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dpc[1],
            { "Protection Information Type 1 Supported (PIT1S)", "nvme.cmd.identify.ns.dpc.pit1s",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dpc[2],
            { "Protection Information Type 2 Supported (PIT2S)", "nvme.cmd.identify.ns.dpc.pit2s",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dpc[3],
            { "Protection Information Type 3 Supported (PIT3S)", "nvme.cmd.identify.ns.dpc.pit3s",
               FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dpc[4],
            { "Protection Information In First Bytes (PIIFB)", "nvme.cmd.identify.ns.dpc.piifb",
               FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dpc[5],
            { "Protection Information In Last Bytes (PIILB)", "nvme.cmd.identify.ns.dpc.piilb",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dpc[6],
            { "Reserved", "nvme.cmd.identify.ns.dpc.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dps[0],
            { "End-to-end Data Protection Type Settings (DPS)", "nvme.cmd.identify.ns.dps",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dps[1],
            { "Protection Information Type (PIT)", "nvme.cmd.identify.ns.dps.pit",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(ns_dps_pit_tbl), 0x07, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dps[2],
            { "Protection Information Position (PIP)", "nvme.cmd.identify.ns.dps.pip",
               FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dps[3],
            { "Reserved", "nvme.cmd.identify.ns.dps.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nmic[0],
            { "Namespace Multi-path I/O and Namespace Sharing Capabilities (NMIC)",
              "nvme.cmd.identify.ns.nmic", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nmic[1],
            { "Shared Namespace (SHRNS)", "nvme.cmd.identify.ns.nmic.shrns",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nmic[2],
            { "Dispersed Namespace (DISNS)", "nvme.cmd.identify.ns.nmic.disns",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nmic[3],
            { "Reserved", "nvme.cmd.identify.ns.nmic.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[0],
            { "Reservation Capabilities (RESCAP)", "nvme.cmd.identify.ns.rescap",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[1],
            { "Persist Through Power Loss Support (PTPLS)", "nvme.cmd.identify.ns.rescap.ptpls",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[2],
            { "Write Exclusive Support (WES)", "nvme.cmd.identify.ns.rescap.wes",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[3],
            { "Exclusive Access Support (EAS)", "nvme.cmd.identify.ns.rescap.eas",
               FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[4],
            { "Write Exclusive - Registrants Only Support (WEROS)", "nvme.cmd.identify.ns.rescap.weros",
               FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[5],
            { "Exclusive Access - Registrants Only Support (EAROS)", "nvme.cmd.identify.ns.rescap.earos",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[6],
            { "Write Exclusive - All Registrants Support (WEARS)", "nvme.cmd.identify.ns.rescap.wears",
               FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[7],
            { "Exclusive Access - All Registrants Support (EAARS)", "nvme.cmd.identify.ns.rescap.eaars",
               FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rescap[8],
            { "Ignore Existing Key Support (IEKS)", "nvme.cmd.identify.ns.rescap.ieks",
               FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_fpi[0],
            { "Format Progress Indicator (FPI)", "nvme.cmd.identify.ns.fpi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_fpi[1],
            { "Remaining Format NVM (RFNVM)", "nvme.cmd.identify.ns.fpi.rfnvm",
               FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_fpi[2],
            { "Format Progress Indicator Support (FPIS)", "nvme.cmd.identify.ns.fpi.fpis",
               FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dlfeat[0],
            { "Deallocate Logical Block Features (DLFEAT)", "nvme.cmd.identify.ns.dlfeat",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dlfeat[1],
            { "Deallocation Read Behavior (DRB)", "nvme.cmd.identify.ns.dlfeat.drb",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(ns_dlfeat_drb_tbl), 0x7, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dlfeat[2],
            { "Write Zeroes Deallocation Support (WZDS)", "nvme.cmd.identify.ns.dlfeat.wzds",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dlfeat[3],
            { "Guard Deallocation Status (GDS)", "nvme.cmd.identify.ns.dlfeat.gds",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_dlfeat[4],
            { "Reserved", "nvme.cmd.identify.ns.dlfeat.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nawun,
            { "Namespace Atomic Write Unit Normal (NAWUN)", "nvme.cmd.identify.ns.nawun",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nawupf,
            { "Namespace Atomic Write Unit Power Fail (NAWUPF)", "nvme.cmd.identify.ns.nawupf",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nacwu,
            { "Namespace Atomic Compare & Write Unit (NACWU)", "nvme.cmd.identify.ns.nacwu",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nabsn,
            { "Namespace Atomic Boundary Size Normal (NABSN)", "nvme.cmd.identify.ns.nabsn",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nabo,
            { "Namespace Atomic Boundary Offset (NABO)", "nvme.cmd.identify.ns.nabo",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nabspf,
            { "Namespace Atomic Boundary Size Power Fail (NABSPF)", "nvme.cmd.identify.ns.nabspf",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_noiob,
            { "Namespace Optimal I/O Boundary (NOIOB)", "nvme.cmd.identify.ns.noiob",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nvmcap,
            { "NVM Capacity (NVMCAP)", "nvme.cmd.identify.ns.nvmcap",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_npwg,
            { "Namespace Preferred Write Granularity (NPWG)", "nvme.cmd.identify.ns.npwg",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_npwa,
            { "Namespace Preferred Write Alignment (NPWA)", "nvme.cmd.identify.ns.npwa",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_npdg,
            { "Namespace Preferred Deallocate Granularity (NPDG)", "nvme.cmd.identify.ns.npdg",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_npda,
            { "Namespace Preferred Deallocate Alignment (NPDA)", "nvme.cmd.identify.ns.npda",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nows,
            { "Namespace Optimal Write Size (NOWS)", "nvme.cmd.identify.ns.nows",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_mssrl,
            { "Maximum Single Source Range Length (MSSRL)", "nvme.cmd.identify.ns.mssrl",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_mcl,
            { "Maximum Copy Length (MCL)", "nvme.cmd.identify.ns.mcl",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_msrc,
            { "Maximum Source Range Count (MSRC)", "nvme.cmd.identify.ns.msrc",
               FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_kpios[0],
            { "Key Per I/O Status (KPIOS)", "nvme.cmd.identify.ns.kpios",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_kpios[1],
            { "Key Per I/O Enabled in Namespace (KPIOENS)", "nvme.cmd.identify.ns.kpios.kpioens",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_kpios[2],
            { "Key Per I/O Supported in Namespace (KPIOSNS)", "nvme.cmd.identify.ns.kpios.kpiosns",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_kpios[3],
            { "Reserved", "nvme.cmd.identify.ns.kpios.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nulbaf,
            { "Number of Unique Attribute LBA Formats (NULBAF)", "nvme.cmd.identify.ns.nulbaf",
               FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rsvd0,
            { "Reserved", "nvme.cmd.identify.ns.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_kpiodaag,
            { "Key Per I/O Data Access Alignment and Granularity (KPIODAAG)",
              "nvme.cmd.identify.ns.kpiodaag",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rsvd1,
            { "Reserved", "nvme.cmd.identify.ns.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_anagrpid,
            { "ANA Group Identifier (ANAGRPID)", "nvme.cmd.identify.ns.anagrpid",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_rsvd2,
            { "Reserved", "nvme.cmd.identify.ns.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsattr[0],
            { "Namespace Attributes (NSATTR)", "nvme.cmd.identify.ns.nsattr",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsattr[1],
            { "Currently Write Protected (CWP)", "nvme.cmd.identify.ns.nsattr.cwp",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nsattr[2],
            { "Reserved", "nvme.cmd.identify.ns.nsattr.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_nvmsetid,
            { "NVM Set Identifier (NVMSETID)", "nvme.cmd.identify.ns.nvmsetid",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_endgid,
            { "Endurance Group Identifier (ENDGID)", "nvme.cmd.identify.ns.endgid",
               FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
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
        { &hf_nvme_identify_ns_vs,
            { "Vendor Specific", "nvme.cmd.identify.ns.vs",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Identify - I/O Command Set Independent Namespace (CNS 08h), Fig 335 */
        { &hf_nvme_identify_cs_ind_ns_nsfeat[0],
            { "Common Namespace Features (NSFEAT)", "nvme.cmd.identify.cs_ind_ns.nsfeat",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nsfeat[1],
            { "Volatile Write Cache Not Present (VWCNP)", "nvme.cmd.identify.cs_ind_ns.nsfeat.vwcnp",
               FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nsfeat[2],
            { "Rotational Media (RMEDIA)", "nvme.cmd.identify.cs_ind_ns.nsfeat.rmedia",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nsfeat[3],
            { "UID Reuse (UIDREUSE)", "nvme.cmd.identify.cs_ind_ns.nsfeat.uidreuse",
               FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nsfeat[4],
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.nsfeat.rsvd0",
               FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nsfeat[5],
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.nsfeat.rsvd1",
               FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nmic[0],
            { "Namespace Multi-path I/O and Namespace Sharing Capabilities (NMIC)", "nvme.cmd.identify.cs_ind_ns.nmic",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nmic[1],
            { "Dispersed Namespace (DISNS)", "nvme.cmd.identify.cs_ind_ns.nmic.disns",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nmic[2],
            { "Shared Namespace (SHRNS)", "nvme.cmd.identify.cs_ind_ns.nmic.shrns",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nmic[3],
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.nmic.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[0],
            { "Reservation Capabilities (RESCAP)", "nvme.cmd.identify.cs_ind_ns.rescap",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[1],
            { "Ignore Existing Key Support (IEKS)", "nvme.cmd.identify.cs_ind_ns.rescap.ieks",
               FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[2],
            { "Exclusive Access - All Registrants Support (EAARS)", "nvme.cmd.identify.cs_ind_ns.rescap.eaars",
               FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[3],
            { "Write Exclusive - All Registrants Support (WEARS)", "nvme.cmd.identify.cs_ind_ns.rescap.wears",
               FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[4],
            { "Exclusive Access - Registrants Only Support (EAROS)", "nvme.cmd.identify.cs_ind_ns.rescap.earos",
               FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[5],
            { "Write Exclusive - Registrants Only Support (WEROS)", "nvme.cmd.identify.cs_ind_ns.rescap.weros",
               FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[6],
            { "Exclusive Access Support (EAS)", "nvme.cmd.identify.cs_ind_ns.rescap.eas",
               FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[7],
            { "Write Exclusive Support (WES)", "nvme.cmd.identify.cs_ind_ns.rescap.wes",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rescap[8],
            { "Persist Through Power Loss Support (PTPLS)", "nvme.cmd.identify.cs_ind_ns.rescap.ptpls",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_fpi[0],
            { "Format Progress Indicator (FPI)", "nvme.cmd.identify.cs_ind_ns.fpi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_fpi[1],
            { "Format Progress Indicator Support (FPIS)", "nvme.cmd.identify.cs_ind_ns.fpi.fpis",
               FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_fpi[2],
            { "Remaining Format NVM (RFNVM)", "nvme.cmd.identify.cs_ind_ns.fpi.rfnvm",
               FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_anagrpid,
            { "ANA Group Identifier (ANAGRPID)", "nvme.cmd.identify.cs_ind_ns.anagrpid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nsattr[0],
            { "Namespace Attributes (NSATTR)", "nvme.cmd.identify.cs_ind_ns.nsattr",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nsattr[1],
            { "Currently Write Protected (CWP)", "nvme.cmd.identify.cs_ind_ns.nsattr.cwp",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nsattr[2],
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.nsattr.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rsvd0,
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nvmsetid,
            { "NVM Set Identifier (NVMSETID)", "nvme.cmd.identify.cs_ind_ns.nvmsetid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_endgid,
            { "Endurance Group Identifier (ENDGID)", "nvme.cmd.identify.cs_ind_ns.endgid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nstat[0],
            { "Namespace Status (NSTAT)", "nvme.cmd.identify.cs_ind_ns.nstat",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nstat[1],
            { "I/O Impacted (IOI)", "nvme.cmd.identify.cs_ind_ns.nstat.ioi",
               FT_UINT8, BASE_HEX, VALS(cs_ind_ns_ioi_tbl), 0x06, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nstat[2],
            { "Namespace Ready (NRDY)", "nvme.cmd.identify.cs_ind_ns.nstat.nrdy",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_nstat[3],
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.nstat.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_kpios[0],
            { "Key Per I/O Status (KPIOS)", "nvme.cmd.identify.cs_ind_ns.kpios",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_kpios[1],
            { "Key Per I/O Supported in Namespace (KPIOSNS)", "nvme.cmd.identify.cs_ind_ns.kpios.kpiosns",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_kpios[2],
            { "Key Per I/O Enabled in Namespace (KPIOENS)", "nvme.cmd.identify.cs_ind_ns.kpios.kpioens",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_kpios[3],
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.kpios.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_maxkt,
            { "Maximum Key Tag (MAXKT)", "nvme.cmd.identify.cs_ind_ns.maxkt",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rsvd1,
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rgrpid,
            { "Reachability Group Identifier (RGRPID)", "nvme.cmd.identify.cs_ind_ns.rgrpid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cs_ind_ns_rsvd2,
            { "Reserved", "nvme.cmd.identify.cs_ind_ns.rsvd2",
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
               FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
            { "Multiple Ports (MPORTS)", "nvme.cmd.identify.ctrl.cmic.mp",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[2],
            { "Multiple Controllers (MCTRS)", "nvme.cmd.identify.ctrl.cmic.mc",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[3],
            { "Function Type (FT)", "nvme.cmd.identify.ctrl.cmic.sriov",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[4],
            { "Asymmetric Namespace Access Reporting Support (ANARS)", "nvme.cmd.identify.ctrl.cmic.ana",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmic[5],
            { "Reserved", "nvme.cmd.identify.ctrl.cmic.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_window_partial,
            { "Partial field", "nvme.window.partial",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 328, bytes 95:92. */
        { &hf_nvme_identify_ctrl_oaes[9],
            { "Normal NVM Subsystem Shutdown Supported (NNSS)", "nvme.cmd.identify.ctrl.oaes.nnss",
               FT_BOOLEAN, 32, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[10],
            { "Temperature Threshold Hysteresis Recovery Supported (TTHR)", "nvme.cmd.identify.ctrl.oaes.tthr",
               FT_BOOLEAN, 32, NULL, 0x10000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[11],
            { "Reachability Groups Change Notices Supported (RGCNS)", "nvme.cmd.identify.ctrl.oaes.rgcns",
               FT_BOOLEAN, 32, NULL, 0x20000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[12],
            { "Reserved", "nvme.cmd.identify.ctrl.oaes.rsvd2",
               FT_UINT32, BASE_HEX, NULL, 0x40000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[13],
            { "Allocated Namespace Attribute Notices Supported (ANSAN)", "nvme.cmd.identify.ctrl.oaes.ansan",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[14],
            { "Cross-Controller Reset Completed Notices Supported (CCRCN)", "nvme.cmd.identify.ctrl.oaes.ccrcn",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[15],
            { "Lost Host Communication Notices Supported (LHCN)", "nvme.cmd.identify.ctrl.oaes.lhcn",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[16],
            { "Rate Limiting Configuration Change (RLCC)", "nvme.cmd.identify.ctrl.oaes.rlcc",
               FT_BOOLEAN, 32, NULL, 0x400000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[17],
            { "Reserved", "nvme.cmd.identify.ctrl.oaes.rsvd3",
               FT_UINT32, BASE_HEX, NULL, 0x7800000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[18],
            { "Zone Descriptor Changed Notices Supported (ZDCN)", "nvme.cmd.identify.ctrl.oaes.zdcn",
               FT_BOOLEAN, 32, NULL, 0x8000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[19],
            { "Reserved", "nvme.cmd.identify.ctrl.oaes.rsvd4",
               FT_UINT32, BASE_HEX, NULL, 0x70000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes[20],
            { "Discovery Log Page Change Notification Supported (DLPCN)", "nvme.cmd.identify.ctrl.oaes.dlpcn",
               FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 328, bytes 99:96. */
        { &hf_nvme_identify_ctrl_ctratt[11],
            { "Multi-Domain Subsystem (MDS)", "nvme.cmd.identify.ctrl.ctratt.mds",
               FT_BOOLEAN, 32, NULL, 0x400, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[12],
            { "Fixed Capacity Management Support (FCM)", "nvme.cmd.identify.ctrl.ctratt.fcm",
               FT_BOOLEAN, 32, NULL, 0x800, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[13],
            { "Variable Capacity Management Support (VCM)", "nvme.cmd.identify.ctrl.ctratt.vcm",
               FT_BOOLEAN, 32, NULL, 0x1000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[14],
            { "Delete Endurance Group Support (DEG)", "nvme.cmd.identify.ctrl.ctratt.deg",
               FT_BOOLEAN, 32, NULL, 0x2000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[15],
            { "Delete NVM Set Support (DNVMS)", "nvme.cmd.identify.ctrl.ctratt.dnvms",
               FT_BOOLEAN, 32, NULL, 0x4000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[16],
            { "Extended LBA Formats Supported (ELBAS)", "nvme.cmd.identify.ctrl.ctratt.elbas",
               FT_BOOLEAN, 32, NULL, 0x8000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[17],
            { "MDTS and Size Limits Exclude Metadata (MEM)", "nvme.cmd.identify.ctrl.ctratt.mem",
               FT_BOOLEAN, 32, NULL, 0x10000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[18],
            { "HMB Restrict Non-Operational Power State Access (HMBR)", "nvme.cmd.identify.ctrl.ctratt.hmbr",
               FT_BOOLEAN, 32, NULL, 0x20000, NULL, HFILL}
        },
        /* Bit 18 is enumerated. */
        { &hf_nvme_identify_ctrl_ctratt[19],
            { "Reservations and Host Identifier Interaction (RHII)", "nvme.cmd.identify.ctrl.ctratt.rhii",
               FT_BOOLEAN, 32, TFS(&ctratt_rhii_tfs), 0x40000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[20],
            { "Flexible Data Placement Support (FDPS)", "nvme.cmd.identify.ctrl.ctratt.fdps",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[21],
            { "Power Limit Support (PLS)", "nvme.cmd.identify.ctrl.ctratt.pls",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[22],
            { "Power Measurement Support (PMS)", "nvme.cmd.identify.ctrl.ctratt.pms",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[23],
            { "Voltage Measurement Support (VMS)", "nvme.cmd.identify.ctrl.ctratt.vms",
               FT_BOOLEAN, 32, NULL, 0x400000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[24],
            { "Idle I/O Exit Latency Limit Support and Scope (IIELLSS)", "nvme.cmd.identify.ctrl.ctratt.iiellss",
               FT_UINT32, BASE_HEX, VALS(ctratt_iiellss_tbl), 0x1800000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ctratt[25],
            { "Reserved", "nvme.cmd.identify.ctrl.ctratt.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfe000000, NULL, HFILL}
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
        { &hf_nvme_identify_ctrl_bpcap[0],
            { "Boot Partition Capabilities (BPCAP)", "nvme.cmd.identify.ctrl.bpcap",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_bpcap[1],
            { "RPMB Boot Partition Write Protection Support (RPMBBPWPS)", "nvme.cmd.identify.ctrl.bpcap.rpmbbpwps",
               FT_UINT8, BASE_HEX, VALS(ctrl_rpmbbpwps_tbl), 0x3, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_bpcap[2],
            { "Set Features Boot Partition Write Protection Support (SFBPWPS)", "nvme.cmd.identify.ctrl.bpcap.sfbpwps",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_bpcap[3],
            { "Reserved", "nvme.cmd.identify.ctrl.bpcap.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_chsi[0],
            { "CXL HDM Support Information (CHSI)", "nvme.cmd.identify.ctrl.chsi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_chsi[1],
            { "CXL HDM Support (CHS)", "nvme.cmd.identify.ctrl.chsi.chs",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_chsi[2],
            { "Reserved", "nvme.cmd.identify.ctrl.chsi.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nssl,
            { "NVM Subsystem Shutdown Latency (NSSL)", "nvme.cmd.identify.ctrl.nssl",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microseconds), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd6,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd6",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_plsi[0],
            { "Power Loss Signaling Information (PLSI)", "nvme.cmd.identify.ctrl.plsi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_plsi[1],
            { "PLS Emergency Power Fail (PLSEPF)", "nvme.cmd.identify.ctrl.plsi.plsepf",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_plsi[2],
            { "PLS Forced Quiescence (PLSFQ)", "nvme.cmd.identify.ctrl.plsi.plsfq",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_plsi[3],
            { "Reserved", "nvme.cmd.identify.ctrl.plsi.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
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
        { &hf_nvme_identify_ctrl_crcap[0],
            { "Controller Reachability Capabilities (CRCAP)", "nvme.cmd.identify.ctrl.crcap",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_crcap[1],
            { "Reachability Reporting Supported (RRSUP)", "nvme.cmd.identify.ctrl.crcap.rrsup",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_crcap[2],
            { "Reachability Group ID Changeable (RGIDC)", "nvme.cmd.identify.ctrl.crcap.rgidc",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_crcap[3],
            { "Reserved", "nvme.cmd.identify.ctrl.crcap.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ciu,
            { "Controller Instance Uniquifier (CIU)", "nvme.cmd.identify.ctrl.ciu",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cirn,
            { "Controller Instance Random Number (CIRN)", "nvme.cmd.identify.ctrl.cirn",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
            { "2-Wire Port Management Endpoint (TWPME)", "nvme.cmd.identify.ctrl.mi.mec.smbusme",
               FT_BOOLEAN, 8, NULL, 0x1,
               "Formerly SMBus/I2C Port Management Endpoint (SMBUSME)", HFILL}
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
            { "NVMe-MI Send and NVMe-MI Receive Support", "nvme.cmd.identify.ctrl.oacs.mi",
               FT_BOOLEAN, 16, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[8],
            { "Virtualization Management Support", "nvme.cmd.identify.ctrl.oacs.vm",
               FT_BOOLEAN, 16, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[9],
            { "Doorbell Buffer Config Support", "nvme.cmd.identify.ctrl.oacs.db",
               FT_BOOLEAN, 16, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[10],
            { "Get LBA Status Support", "nvme.cmd.identify.ctrl.oacs.glss",
               FT_BOOLEAN, 16, NULL, 0x200, NULL, HFILL}
        },
        /* NVMe Base 2.4 Figure 338, bytes 257:256. */
        { &hf_nvme_identify_ctrl_oacs[11],
            { "Command and Feature Lockdown Supported (CFLS)", "nvme.cmd.identify.ctrl.oacs.cfls",
               FT_BOOLEAN, 16, NULL, 0x400, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[12],
            { "Host Managed Live Migration Support (HMLMS)", "nvme.cmd.identify.ctrl.oacs.hmlms",
               FT_BOOLEAN, 16, NULL, 0x800, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[13],
            { "Exported NVM Subsystem Support (ENSS)", "nvme.cmd.identify.ctrl.oacs.enss",
               FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[14],
            { "Controller-scoped Command and Feature Lockdown Supported (CCFLS)", "nvme.cmd.identify.ctrl.oacs.ccfls",
               FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs[15],
            { "Reserved", "nvme.cmd.identify.ctrl.oacs.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xc000, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 328, byte 260. */
        { &hf_nvme_identify_ctrl_frmw[4],
            { "Support Multiple Update Detection (SMUD)", "nvme.cmd.identify.ctrl.frmw.smud",
               FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_frmw[5],
            { "Reserved", "nvme.cmd.identify.ctrl.frmw.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[0],
            { "Log Page Attributes (LPA)", "nvme.cmd.identify.ctrl.lpa",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 328, byte 261. */
        { &hf_nvme_identify_ctrl_lpa[6],
            { "Miscellaneous Log Page Support (MLPS)", "nvme.cmd.identify.ctrl.lpa.mlps",
               FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[7],
            { "Data Area 4 Support (DA4S)", "nvme.cmd.identify.ctrl.lpa.da4s",
               FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_lpa[8],
            { "Reserved", "nvme.cmd.identify.ctrl.lpa.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
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
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_kelvins), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cctemp,
            { "Critical Composite Temperature Threshold (CCTEMP)", "nvme.cmd.identify.ctrl.cctemp",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_nvme_kelvins), 0x0, NULL, HFILL}
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
            { "Single Device Self-test Operation (SDSO)", "nvme.cmd.identify.ctrl.dsto.sdso",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 328, byte 318. */
        { &hf_nvme_identify_ctrl_dsto[2],
            { "Host-Initiated Refresh Support (HIRS)", "nvme.cmd.identify.ctrl.dsto.hirs",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_dsto[3],
            { "Reserved", "nvme.cmd.identify.ctrl.dsto.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 328, bytes 331:328. */
        { &hf_nvme_identify_ctrl_sanicap[4],
            { "Verification Support (VERS)", "nvme.cmd.identify.ctrl.sanicap.vers",
               FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[5],
            { "Namespace Verification Support (NVERS)", "nvme.cmd.identify.ctrl.sanicap.nvers",
               FT_BOOLEAN, 32, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[6],
            { "Sanitize Purge Request and Reporting Supported (SPRRS)", "nvme.cmd.identify.ctrl.sanicap.sprrs",
               FT_BOOLEAN, 32, NULL, 0x20, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[7],
            { "Reserved", "nvme.cmd.identify.ctrl.sanicap.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x1fffffc0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[8],
            { "No-Deallocate Inhibited (NDI)", "nvme.cmd.identify.ctrl.sanicap.ndi",
               FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sanicap[9],
            { "No-Deallocate Modifies Media After Sanitize (NODMMAS)", "nvme.cmd.identify.ctrl.sanicap.nodmmas",
               FT_UINT32, BASE_HEX, VALS(mmas_type_tbl), 0xc0000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hmminds,
            { "Host Memory Buffer Minimum Descriptor Entry Size in 4 KiB Units (HMMINDS)", "nvme.cmd.identify.ctrl.hmminds",
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
            { "Reports Inaccessible State", "nvme.cmd.identify.ctrl.anacap.isr",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[4],
            { "Reports ANA Persistent Loss State", "nvme.cmd.identify.ctrl.anacap.plsr",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_anacap[5],
            { "Reports ANA Change State", "nvme.cmd.identify.ctrl.anacap.csr",
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
        { &hf_nvme_identify_ctrl_did,
            { "Domain Identifier (DID)", "nvme.cmd.identify.ctrl.did",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_kpioc[0],
            { "Key Per I/O Capabilities (KPIOC)", "nvme.cmd.identify.ctrl.kpioc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_kpioc[1],
            { "Key Per I/O Supported (KPIOS)", "nvme.cmd.identify.ctrl.kpioc.kpios",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_kpioc[2],
            { "Key Per I/O Scope (KPIOSC)", "nvme.cmd.identify.ctrl.kpioc.kpiosc",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_kpioc[3],
            { "Reserved", "nvme.cmd.identify.ctrl.kpioc.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd2,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mptfawr,
            { "Maximum Processing Time for Firmware Activation Without Reset (MPTFAWR)", "nvme.cmd.identify.ctrl.mptfawr",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_ms), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rmdca[0],
            { "Restore Manufacturing Configuration Attributes (RMDCA)", "nvme.cmd.identify.ctrl.rmdca",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rmdca[1],
            { "Restore Default NVM Subsystem Configuration Supported (RDSCS)", "nvme.cmd.identify.ctrl.rmdca.rdscs",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rmdca[2],
            { "Restore Default Namespace Configuration Supported (RDNCS)", "nvme.cmd.identify.ctrl.rmdca.rdncs",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rmdca[3],
            { "Restore Default Capacity Management Configuration Supported (RDCCS)", "nvme.cmd.identify.ctrl.rmdca.rdccs",
               FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rmdca[4],
            { "Reserved", "nvme.cmd.identify.ctrl.rmdca.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd7,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd7",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_megcap,
            { "Max Endurance Group Capacity (MEGCAP)", "nvme.cmd.identify.ctrl.megcap",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_tmpthha[0],
            { "Temperature Threshold Hysteresis Attributes (TMPTHHA)", "nvme.cmd.identify.ctrl.tmpthha",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_tmpthha[1],
            { "Temperature Threshold Maximum Hysteresis (TMPTHMH)", "nvme.cmd.identify.ctrl.tmpthha.tmpthmh",
               FT_UINT8, BASE_DEC, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_tmpthha[2],
            { "Reserved", "nvme.cmd.identify.ctrl.tmpthha.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mupa[0],
            { "Maximum Unlimited Power Attributes (MUPA)", "nvme.cmd.identify.ctrl.mupa",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mupa[1],
            { "Maximum Unlimited Power Scale (MUPS)", "nvme.cmd.identify.ctrl.mupa.mups",
               FT_UINT8, BASE_HEX, VALS(ctrl_mups_tbl), 0x3, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mupa[2],
            { "Reserved", "nvme.cmd.identify.ctrl.mupa.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cqt,
            { "Command Quiesce Time (CQT)", "nvme.cmd.identify.ctrl.cqt",
               FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdpa[0],
            { "Configurable Device Personality Attributes (CDPA)", "nvme.cmd.identify.ctrl.cdpa",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdpa[1],
            { "HMAC-SHA-384 (HS3)", "nvme.cmd.identify.ctrl.cdpa.hs3",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdpa[2],
            { "Reserved", "nvme.cmd.identify.ctrl.cdpa.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mup,
            { "Maximum Unlimited Power (MUP)", "nvme.cmd.identify.ctrl.mup",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ipmsr[0],
            { "Interval Power Measurement Sample Rate (IPMSR)", "nvme.cmd.identify.ctrl.ipmsr",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ipmsr[1],
            { "Sample Rate Value (SRV)", "nvme.cmd.identify.ctrl.ipmsr.srv",
               FT_UINT16, BASE_DEC, NULL, 0x00ff, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ipmsr[2],
            { "Sample Rate Scale (SRS)", "nvme.cmd.identify.ctrl.ipmsr.srs",
               FT_UINT16, BASE_HEX, VALS(ctrl_srs_tbl), 0xff00, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_msmt,
            { "Maximum Stop Measurement Time (MSMT)", "nvme.cmd.identify.ctrl.msmt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mnens,
            { "Maximum Number of Exported NVM Subsystems (MNENS)", "nvme.cmd.identify.ctrl.mnens",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mnecpens,
            { "Maximum Number of Exported Controllers per Exported NVM Subsystem (MNECPENS)", "nvme.cmd.identify.ctrl.mnecpens",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mensnn,
            { "Maximum Exported NVM Subsystem Number of Namespaces (MENSNN)", "nvme.cmd.identify.ctrl.mensnn",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ensa[0],
            { "Exported NVM Subsystem Attributes (ENSA)", "nvme.cmd.identify.ctrl.ensa",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ensa[1],
            { "Exported NVM Subsystem Template Support (ENSTS)", "nvme.cmd.identify.ctrl.ensa.ensts",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ensa[2],
            { "Exported NVM Subsystem Migration Support (ENSMS)", "nvme.cmd.identify.ctrl.ensa.ensms",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ensa[3],
            { "Reserved", "nvme.cmd.identify.ctrl.ensa.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_endsfs[0],
            { "Exported Namespace Data Structure Formats Supported (ENDSFS)", "nvme.cmd.identify.ctrl.endsfs",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_endsfs[1],
            { "Exported Namespace Format 0 (ENF0)", "nvme.cmd.identify.ctrl.endsfs.enf0",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_endsfs[2],
            { "Exported Namespace Format 1 (ENF1)", "nvme.cmd.identify.ctrl.endsfs.enf1",
               FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_endsfs[3],
            { "Reserved", "nvme.cmd.identify.ctrl.endsfs.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen1[0],
            { "Voltage Sensor 1 (VSEN1)", "nvme.cmd.identify.ctrl.vsen1",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen1[1],
            { "IVMSR Voltage Sample Rate Value (VSRV)", "nvme.cmd.identify.ctrl.vsen1.vsrv",
               FT_UINT32, BASE_DEC, NULL, 0x00ff0000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen1[2],
            { "IVMSR Voltage Sample Rate Scale (VSRS)", "nvme.cmd.identify.ctrl.vsen1.vsrs",
               FT_UINT32, BASE_HEX, VALS(ctrl_srs_tbl), 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen1[3],
            { "Voltage Sample Scale (VOLSS)", "nvme.cmd.identify.ctrl.vsen1.volss",
               FT_UINT32, BASE_HEX, VALS(ctrl_vsen_volss_tbl), 0x0000c000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen1[4],
            { "Power Input Supply Label (PISL)", "nvme.cmd.identify.ctrl.vsen1.pisl",
               FT_UINT32, BASE_DEC, NULL, 0x00003000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen1[5],
            { "Power Input Supply Value (PISV)", "nvme.cmd.identify.ctrl.vsen1.pisv",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_vsen_pisv), 0x00000fff, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen2[0],
            { "Voltage Sensor 2 (VSEN2)", "nvme.cmd.identify.ctrl.vsen2",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen2[1],
            { "IVMSR Voltage Sample Rate Value (VSRV)", "nvme.cmd.identify.ctrl.vsen2.vsrv",
               FT_UINT32, BASE_DEC, NULL, 0x00ff0000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen2[2],
            { "IVMSR Voltage Sample Rate Scale (VSRS)", "nvme.cmd.identify.ctrl.vsen2.vsrs",
               FT_UINT32, BASE_HEX, VALS(ctrl_srs_tbl), 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen2[3],
            { "Voltage Sample Scale (VOLSS)", "nvme.cmd.identify.ctrl.vsen2.volss",
               FT_UINT32, BASE_HEX, VALS(ctrl_vsen_volss_tbl), 0x0000c000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen2[4],
            { "Power Input Supply Label (PISL)", "nvme.cmd.identify.ctrl.vsen2.pisl",
               FT_UINT32, BASE_DEC, NULL, 0x00003000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen2[5],
            { "Power Input Supply Value (PISV)", "nvme.cmd.identify.ctrl.vsen2.pisv",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_vsen_pisv), 0x00000fff, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen3[0],
            { "Voltage Sensor 3 (VSEN3)", "nvme.cmd.identify.ctrl.vsen3",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen3[1],
            { "IVMSR Voltage Sample Rate Value (VSRV)", "nvme.cmd.identify.ctrl.vsen3.vsrv",
               FT_UINT32, BASE_DEC, NULL, 0x00ff0000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen3[2],
            { "IVMSR Voltage Sample Rate Scale (VSRS)", "nvme.cmd.identify.ctrl.vsen3.vsrs",
               FT_UINT32, BASE_HEX, VALS(ctrl_srs_tbl), 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen3[3],
            { "Voltage Sample Scale (VOLSS)", "nvme.cmd.identify.ctrl.vsen3.volss",
               FT_UINT32, BASE_HEX, VALS(ctrl_vsen_volss_tbl), 0x0000c000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen3[4],
            { "Power Input Supply Label (PISL)", "nvme.cmd.identify.ctrl.vsen3.pisl",
               FT_UINT32, BASE_DEC, NULL, 0x00003000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen3[5],
            { "Power Input Supply Value (PISV)", "nvme.cmd.identify.ctrl.vsen3.pisv",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_vsen_pisv), 0x00000fff, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen4[0],
            { "Voltage Sensor 4 (VSEN4)", "nvme.cmd.identify.ctrl.vsen4",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen4[1],
            { "IVMSR Voltage Sample Rate Value (VSRV)", "nvme.cmd.identify.ctrl.vsen4.vsrv",
               FT_UINT32, BASE_DEC, NULL, 0x00ff0000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen4[2],
            { "IVMSR Voltage Sample Rate Scale (VSRS)", "nvme.cmd.identify.ctrl.vsen4.vsrs",
               FT_UINT32, BASE_HEX, VALS(ctrl_srs_tbl), 0xff000000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen4[3],
            { "Voltage Sample Scale (VOLSS)", "nvme.cmd.identify.ctrl.vsen4.volss",
               FT_UINT32, BASE_HEX, VALS(ctrl_vsen_volss_tbl), 0x0000c000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen4[4],
            { "Power Input Supply Label (PISL)", "nvme.cmd.identify.ctrl.vsen4.pisl",
               FT_UINT32, BASE_DEC, NULL, 0x00003000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_vsen4[5],
            { "Power Input Supply Value (PISV)", "nvme.cmd.identify.ctrl.vsen4.pisv",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_ctrl_vsen_pisv), 0x00000fff, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_msvmt,
            { "Maximum Stop Voltage Measurement Time (MSVMT)", "nvme.cmd.identify.ctrl.msvmt",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_minutes), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd8,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd8",
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
        /* NVMe Base 2.3 Figure 328 ONCS bits 3:1: "Support Variants". */
        { &hf_nvme_identify_ctrl_oncs[2],
            { "Write Uncorrectable Support Variants (NVMWUSV)", "nvme.cmd.identify.ctrl.oncs.wus",
               FT_BOOLEAN, 16, TFS(&oncs_nvmwusv_tfs), 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[3],
            { "Dataset Management Support Variants (NVMDSMSV)", "nvme.cmd.identify.ctrl.oncs.dsms",
               FT_BOOLEAN, 16, TFS(&oncs_nvmdsmsv_tfs), 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[4],
            { "Write Zeroes Support Variants (NVMWZSV)", "nvme.cmd.identify.ctrl.oncs.wzs",
               FT_BOOLEAN, 16, TFS(&oncs_nvmwzsv_tfs), 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[5],
            { "Supports non-zero Save Field in Set/Get Features", "nvme.cmd.identify.ctrl.oncs.nzfs",
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
        /* Figure 328 bit 7: "Support Variants". */
        { &hf_nvme_identify_ctrl_oncs[8],
            { "Verify Support (NVMVFYS)", "nvme.cmd.identify.ctrl.oncs.vers",
               FT_BOOLEAN, 16, TFS(&oncs_nvmvfys_tfs), 0x80, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 328, bytes 521:520. */
        { &hf_nvme_identify_ctrl_oncs[9],
            { "Copy Support (NVMCPYS)", "nvme.cmd.identify.ctrl.oncs.cpys",
               FT_BOOLEAN, 16, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[10],
            { "NVM Copy Single Atomicity (NVMCSA)", "nvme.cmd.identify.ctrl.oncs.csa",
               FT_BOOLEAN, 16, NULL, 0x200, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[11],
            { "NVM All Fast Copy (NVMAFC)", "nvme.cmd.identify.ctrl.oncs.afc",
               FT_BOOLEAN, 16, NULL, 0x400, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[12],
            { "Maximum Write Zeroes with Deallocate (MAXWZD)", "nvme.cmd.identify.ctrl.oncs.maxwzd",
               FT_BOOLEAN, 16, NULL, 0x800, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[13],
            { "Namespace Zeroes Support (NSZS)", "nvme.cmd.identify.ctrl.oncs.nszs",
               FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs[14],
            { "Reserved", "nvme.cmd.identify.ctrl.oncs.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xe000, NULL, HFILL}
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
        /* NVMe Base 2.3 Figure 328, byte 524. */
        { &hf_nvme_identify_ctrl_fna[4],
            { "Format NVM Broadcast Support (FNVMBS)", "nvme.cmd.identify.ctrl.fna.fnvmbs",
               FT_BOOLEAN, 8, TFS(&fna_fnvmbs_tfs), 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_fna[5],
            { "Reserved", "nvme.cmd.identify.ctrl.fna.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
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
            { "I/O Command Set Vendor Specific Command Configuration (ICSVSCC)", "nvme.cmd.identify.ctrl.nvscc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvscc[1],
            { "Same NVM Vendor Specific Command Format (SNVSCF)", "nvme.cmd.identify.ctrl.nvscc.std",
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
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_lblocks), 0x0, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 328, bytes 535:534. */
        { &hf_nvme_identify_ctrl_cdfs[0],
            { "Copy Descriptor Formats Supported (CDFS)", "nvme.cmd.identify.ctrl.cdfs",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdfs[1],
            { "Copy Descriptor Format 0 Support (CDF0S)", "nvme.cmd.identify.ctrl.cdfs.cdf0s",
               FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdfs[2],
            { "Copy Descriptor Format 1 Support (CDF1S)", "nvme.cmd.identify.ctrl.cdfs.cdf1s",
               FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdfs[3],
            { "Copy Descriptor Format 2 Support (CDF2S)", "nvme.cmd.identify.ctrl.cdfs.cdf2s",
               FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdfs[4],
            { "Copy Descriptor Format 3 Support (CDF3S)", "nvme.cmd.identify.ctrl.cdfs.cdf3s",
               FT_BOOLEAN, 16, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdfs[5],
            { "Copy Descriptor Format 4 Support (CDF4S)", "nvme.cmd.identify.ctrl.cdfs.cdf4s",
               FT_BOOLEAN, 16, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cdfs[6],
            { "Reserved", "nvme.cmd.identify.ctrl.cdfs.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xffe0, NULL, HFILL}
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
               FT_UINT32, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 328, bytes 539:536: SDT is a count. */
        { &hf_nvme_identify_ctrl_sgls[4],
            { "SGL Descriptor Threshold (SDT)", "nvme.cmd.identify.ctrl.sgls.sdt",
               FT_UINT32, BASE_DEC, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[5],
            { "Supports SGL Bit Bucket Descriptor", "nvme.cmd.identify.ctrl.sgls.bbd",
               FT_BOOLEAN, 32, NULL, 0x10000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[6],
            { "Supports byte aligned contiguous buffer in MPTR Field", "nvme.cmd.identify.ctrl.sgls.bufmptr",
               FT_BOOLEAN, 32, NULL, 0x20000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[7],
            { "Supports Larger SGL List than Command Requires", "nvme.cmd.identify.ctrl.sgls.lsgl",
               FT_BOOLEAN, 32, NULL, 0x40000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[8],
            { "Supports SGL Segment in MPTR Field", "nvme.cmd.identify.ctrl.sgls.kmptr",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[9],
            { "Supports Address Field as offset in Data Block, Segment and Last Segment SGLs", "nvme.cmd.identify.ctrl.sgls.offs",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[10],
            { "Supports Transport SGL Data Block Descriptor", "nvme.cmd.identify.ctrl.sgls.tdbd",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls[11],
            { "Reserved", "nvme.cmd.identify.ctrl.sgls.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xffc00000, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mnan,
            { "Maximum Number of Allowed Namespaces (MNAN)", "nvme.cmd.identify.ctrl.mnan",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_maxdna,
            { "Maximum Domain Namespace Attachments (MAXDNA)", "nvme.cmd.identify.ctrl.maxdna",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_maxcna,
            { "Maximum I/O Controller Namespace Attachments (MAXCNA)", "nvme.cmd.identify.ctrl.maxcna",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaqd,
            { "Optimal Aggregated Queue Depth (OAQD)", "nvme.cmd.identify.ctrl.oaqd",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rhiri,
            { "Recommended Host-Initiated Refresh Interval (RHIRI)", "nvme.cmd.identify.ctrl.rhiri",
               FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_day_days), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_hirt,
            { "Host-Initiated Refresh Time (HIRT)", "nvme.cmd.identify.ctrl.hirt",
               FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_minutes), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cmmrtd,
            { "Controller Maximum Memory Range Tracking Descriptors (CMMRTD)", "nvme.cmd.identify.ctrl.cmmrtd",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nmmrtd,
            { "NVM Subsystem Maximum Memory Range Tracking Descriptors (NMMRTD)", "nvme.cmd.identify.ctrl.nmmrtd",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_minmrtg,
            { "Minimum Memory Range Tracking Granularity (MINMRTG)", "nvme.cmd.identify.ctrl.minmrtg",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_maxmrtg,
            { "Maximum Memory Range Tracking Granularity (MAXMRTG)", "nvme.cmd.identify.ctrl.maxmrtg",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_trattr[0],
            { "Tracking Attributes (TRATTR)", "nvme.cmd.identify.ctrl.trattr",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_trattr[1],
            { "Track Host Memory Changes Support (THMCS)", "nvme.cmd.identify.ctrl.trattr.thmcs",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_trattr[2],
            { "Track User Data Changes Support (TUDCS)", "nvme.cmd.identify.ctrl.trattr.tudcs",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_trattr[3],
            { "Memory Range Tracking Length Limit (MRTLL)", "nvme.cmd.identify.ctrl.trattr.mrtll",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_trattr[4],
            { "Reserved", "nvme.cmd.identify.ctrl.trattr.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd4,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd4",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mcudmq,
            { "Maximum Controller User Data Migration Queues (MCUDMQ)", "nvme.cmd.identify.ctrl.mcudmq",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mnsudmq,
            { "Maximum NVM Subsystem User Data Migration Queues (MNSUDMQ)", "nvme.cmd.identify.ctrl.mnsudmq",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mcmr,
            { "Maximum CDQ Memory Ranges (MCMR)", "nvme.cmd.identify.ctrl.mcmr",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nmcmr,
            { "NVM Subsystem Maximum CDQ Memory Ranges (NMCMR)", "nvme.cmd.identify.ctrl.nmcmr",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_mcdqpc,
            { "Maximum Controller Data Queue PRP Count (MCDQPC)", "nvme.cmd.identify.ctrl.mcdqpc",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_rsvd9,
            { "Reserved", "nvme.cmd.identify.ctrl.rsvd9",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_subnqn,
            { "NVM Subsystem NVMe Qualified Name (SUBNQN)", "nvme.cmd.identify.ctrl.subnqn",
               FT_STRINGZTRUNC, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
            { "Dynamic Controller Model Support (DCMS)", "nvme.cmd.identify.ctrl.nvmeof.fcatt.dcm",
               FT_BOOLEAN, 8, TFS(&fcatt_dcms_tfs), 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_fcatt[2],
            { "Non-Zero NVM Set ID Support (NZNSETIDS)", "nvme.cmd.identify.ctrl.nvmeof.fcatt.nznsetids",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_fcatt[3],
            { "Reserved", "nvme.cmd.identify.ctrl.nvmeof.fcatt.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
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
        { &hf_nvme_identify_ctrl_nvmeof_dctype,
            { "Discovery Controller Type (DCTYPE)", "nvme.cmd.identify.ctrl.nvmeof.dctype",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(ctrl_dctype_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nvmeof_ccrl,
            { "Cross-Controller Reset Limit (CCRL)", "nvme.cmd.identify.ctrl.nvmeof.ccrl",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
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
            { "Power State Descriptor (PSD)", "nvme.cmd.identify.ctrl.psds.psd",
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
               FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_microsecond_microseconds), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_exlat,
            { "Exit Latency (EXLAT)", "nvme.cmd.identify.ctrl.psds.psd.exlat",
               FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_microsecond_microseconds), 0x0, NULL, HFILL}
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
               FT_UINT8, BASE_HEX, VALS(psd_apw_tbl), 0x7, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd8,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd8",
               FT_UINT8, BASE_HEX, NULL, 0x38, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_aps,
            { "Active Power Scale (APS)", "nvme.cmd.identify.ctrl.psds.psd.aps",
               FT_UINT8, BASE_HEX, VALS(power_scale_tbl), 0xc0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_epfrt,
            { "Emergency Power Fail Recovery Time (EPFRT)", "nvme.cmd.identify.ctrl.psds.psd.epfrt",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_nvme_psd_time_value), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_fqvt,
            { "Forced Quiescence Vault Time (FQVT)", "nvme.cmd.identify.ctrl.psds.psd.fqvt",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_nvme_psd_time_value), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_epfvt,
            { "Emergency Power Fail Vault Time (EPFVT)", "nvme.cmd.identify.ctrl.psds.psd.epfvt",
               FT_UINT8, BASE_CUSTOM, CF_FUNC(add_nvme_psd_time_value), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_epfrts,
            { "Emergency Power Fail Recovery Time Scale (EPFRTS)", "nvme.cmd.identify.ctrl.psds.psd.epfrts",
               FT_UINT8, BASE_HEX, VALS(time_scale_tbl), 0x0f, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_fqvts,
            { "Forced Quiescence Vault Time Scale (FQVTS)", "nvme.cmd.identify.ctrl.psds.psd.fqvts",
               FT_UINT8, BASE_HEX, VALS(time_scale_tbl), 0xf0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_epfvts,
            { "Emergency Power Fail Vault Time Scale (EPFVTS)", "nvme.cmd.identify.ctrl.psds.psd.epfvts",
               FT_UINT8, BASE_HEX, VALS(time_scale_tbl), 0x0f, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd9,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd9",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_mbw,
            { "Max Bandwidth (MBW)", "nvme.cmd.identify.ctrl.psds.psd.mbw",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_mbws,
            { "Max Bandwidth Scale (MBWS)", "nvme.cmd.identify.ctrl.psds.psd.mbws",
               FT_UINT8, BASE_HEX, VALS(max_bw_scale_tbl), 0x07, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_rsvd10,
            { "Reserved", "nvme.cmd.identify.ctrl.psds.psd.rsvd10",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_psd_miiell,
            { "Minimum Idle I/O Exit Latency Limit (MIIELL)", "nvme.cmd.identify.ctrl.psds.psd.miiell",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_ctrl_100us), 0x0, NULL, HFILL}
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
        /* Identify Namespace Identification Descriptor list (CNS 03h) response */
        { &hf_nvme_identify_nsdesc_nidt,
            { "Namespace Identifier Type (NIDT)", "nvme.cmd.identify.nsdesc.nidt",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nidt_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_nsdesc_nidl,
            { "Namespace Identifier Length (NIDL)", "nvme.cmd.identify.nsdesc.nidl",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_nsdesc_rsvd,
            { "Reserved", "nvme.cmd.identify.nsdesc.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_nsdesc_nid,
            { "Namespace Identifier (NID)", "nvme.cmd.identify.nsdesc.nid",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_nsdesc_csi,
            { "Command Set Identifier (CSI)", "nvme.cmd.identify.nsdesc.csi",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(csi_tbl), 0x0, NULL, HFILL}
        },
        /* Identify Controller List (CNS 12h/13h) response */
        { &hf_nvme_identify_ctrl_list_num,
            { "Number of Controller Identifiers (NUMCIDS)", "nvme.cmd.identify.ctrl_list.num",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_enst_rsvd,
            { "Reserved", "nvme.cmd.identify.enst.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_enst_uuid,
            { "Exported NVM Subsystem Template UUID (ENST)", "nvme.cmd.identify.enst.uuid",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_list_id,
            { "Controller Identifier", "nvme.cmd.identify.ctrl_list.id",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* Identify NVM Set List (CNS 04h) response */
        { &hf_nvme_identify_nvmset_num,
            { "Number of Entries (NUMENT)", "nvme.cmd.identify.nvmset.num",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_nvmset_id,
            { "NVM Set Identifier (NSETID)", "nvme.cmd.identify.nvmset.id",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_nvmset_endgid,
            { "Endurance Group Identifier (ENDGID)", "nvme.cmd.identify.nvmset.endgid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_nvmset_r4krt,
            { "Random 4 KiB Read Typical (R4KRT)", "nvme.cmd.identify.nvmset.r4krt",
               FT_UINT32, BASE_DEC, NULL, 0x0, "In 100 ns units", HFILL}
        },
        { &hf_nvme_identify_nvmset_ows,
            { "Optimal Write Size (OWS)", "nvme.cmd.identify.nvmset.ows",
               FT_UINT32, BASE_DEC, NULL, 0x0, "In bytes", HFILL}
        },
        { &hf_nvme_identify_nvmset_tnvmsc,
            { "Total NVM Set Capacity (TNVMSC)", "nvme.cmd.identify.nvmset.tnvmsc",
               FT_BYTES, BASE_NONE, NULL, 0x0, "In bytes (128-bit)", HFILL}
        },
        { &hf_nvme_identify_nvmset_unvmsc,
            { "Unallocated NVM Set Capacity (UNVMSC)", "nvme.cmd.identify.nvmset.unvmsc",
               FT_BYTES, BASE_NONE, NULL, 0x0, "In bytes (128-bit)", HFILL}
        },
        /* Identify Primary Controller Capabilities (CNS 14h) response */
        { &hf_nvme_identify_pcc_cntlid,
            { "Controller Identifier (CNTLID)", "nvme.cmd.identify.pcc.cntlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_portid,
            { "Port Identifier (PORTID)", "nvme.cmd.identify.pcc.portid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_crt[0],
            { "Controller Resource Types (CRT)", "nvme.cmd.identify.pcc.crt",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_crt[1],
            { "VQ Resources Support (VQRS)", "nvme.cmd.identify.pcc.crt.vqrs",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_crt[2],
            { "VI Resources Support (VIRS)", "nvme.cmd.identify.pcc.crt.virs",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_crt[3],
            { "Reserved", "nvme.cmd.identify.pcc.crt.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_rsvd,
            { "Reserved", "nvme.cmd.identify.pcc.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vqfrt,
            { "VQ Resources Flexible Total (VQFRT)", "nvme.cmd.identify.pcc.vqfrt",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vqrfa,
            { "VQ Resources Flexible Assigned (VQRFA)", "nvme.cmd.identify.pcc.vqrfa",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vqrfap,
            { "VQ Resources Flexible Allocated to Primary (VQRFAP)", "nvme.cmd.identify.pcc.vqrfap",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vqprt,
            { "VQ Resources Private Total (VQPRT)", "nvme.cmd.identify.pcc.vqprt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vqfrsm,
            { "VQ Resources Flexible Secondary Maximum (VQFRSM)", "nvme.cmd.identify.pcc.vqfrsm",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vqgran,
            { "VQ Flexible Resource Preferred Granularity (VQGRAN)", "nvme.cmd.identify.pcc.vqgran",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vifrt,
            { "VI Resources Flexible Total (VIFRT)", "nvme.cmd.identify.pcc.vifrt",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_virfa,
            { "VI Resources Flexible Assigned (VIRFA)", "nvme.cmd.identify.pcc.virfa",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_virfap,
            { "VI Resources Flexible Allocated to Primary (VIRFAP)", "nvme.cmd.identify.pcc.virfap",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_viprt,
            { "VI Resources Private Total (VIPRT)", "nvme.cmd.identify.pcc.viprt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vifrsm,
            { "VI Resources Flexible Secondary Maximum (VIFRSM)", "nvme.cmd.identify.pcc.vifrsm",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_pcc_vigran,
            { "VI Flexible Resource Preferred Granularity (VIGRAN)", "nvme.cmd.identify.pcc.vigran",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        /* Identify Secondary Controller List (CNS 15h) response */
        { &hf_nvme_identify_scl_num,
            { "Number of Entries (NUMENT)", "nvme.cmd.identify.scl.num",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_scl_scid,
            { "Secondary Controller Identifier (SCID)", "nvme.cmd.identify.scl.scid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_scl_pcid,
            { "Primary Controller Identifier (PCID)", "nvme.cmd.identify.scl.pcid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_scl_scs[0],
            { "Secondary Controller State (SCS)", "nvme.cmd.identify.scl.scs",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_scl_scs[1],
            { "Online State (OLS)", "nvme.cmd.identify.scl.scs.ols",
               FT_UINT8, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_scl_scs[2],
            { "Reserved", "nvme.cmd.identify.scl.scs.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_identify_scl_vfn,
            { "Virtual Function Number (VFN)", "nvme.cmd.identify.scl.vfn",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_scl_nvq,
            { "Number of VQ Flexible Resources Assigned (NVQ)", "nvme.cmd.identify.scl.nvq",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_scl_nvi,
            { "Number of VI Flexible Resources Assigned (NVI)", "nvme.cmd.identify.scl.nvi",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        /* Identify Namespace Granularity List (CNS 16h) response */
        { &hf_nvme_identify_ngl_nga[0],
            { "Namespace Granularity Attributes (NGA)", "nvme.cmd.identify.ngl.nga",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ngl_nga[1],
            { "Granularity Descriptor Mapping (GDM)", "nvme.cmd.identify.ngl.nga.gdm",
               FT_UINT32, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_identify_ngl_nga[2],
            { "Reserved", "nvme.cmd.identify.ngl.nga.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_identify_ngl_nd,
            { "Number of Descriptors (ND)", "nvme.cmd.identify.ngl.nd",
               FT_UINT8, BASE_DEC, NULL, 0x0, "0's based count", HFILL}
        },
        { &hf_nvme_identify_ngl_nsg,
            { "Namespace Size Granularity (NSG)", "nvme.cmd.identify.ngl.nsg",
               FT_UINT64, BASE_DEC, NULL, 0x0, "In bytes", HFILL}
        },
        { &hf_nvme_identify_ngl_ncg,
            { "Namespace Capacity Granularity (NCG)", "nvme.cmd.identify.ngl.ncg",
               FT_UINT64, BASE_DEC, NULL, 0x0, "In bytes", HFILL}
        },
        /* Identify UUID List (CNS 17h) response */
        { &hf_nvme_identify_uuid_idassoc,
            { "Identifier Association (IDASSOC)", "nvme.cmd.identify.uuid.idassoc",
               FT_UINT8, BASE_HEX, VALS(uuid_idassoc_tbl), 0x3, NULL, HFILL}
        },
        { &hf_nvme_identify_uuid_uuid,
            { "UUID", "nvme.cmd.identify.uuid.uuid",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
        { &hf_nvme_get_logpage_ify_dlpf[0],
            { "Discovery Log Page Flags (DLPF)", "nvme.cmd.get_logpage.identify.dlpf",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_dlpf[1],
            { "Extended (EXTEND)", "nvme.cmd.get_logpage.identify.dlpf.extend",
               FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x1,
               "The records contained in the log page may include Extended"
               " Discovery Log Page Entries", HFILL}
        },
        { &hf_nvme_get_logpage_ify_dlpf[2],
            { "Port Local (PORTLCL)", "nvme.cmd.get_logpage.identify.dlpf.portlcl",
               FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_dlpf[3],
            { "All Subsystems (ALLSUB)", "nvme.cmd.get_logpage.identify.dlpf.allsub",
               FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_dlpf[4],
            { "Reserved", "nvme.cmd.get_logpage.identify.dlpf.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.identify.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_tdlpl,
            { "Total Discovery Log Page Length (TDLPL)", "nvme.cmd.get_logpage.identify.tdlpl",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               "Length in bytes of the entire Discovery log page; 0h means not"
               " reported", HFILL}
        },
        { &hf_nvme_get_logpage_ify_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.identify.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd,
            { "Discovery Log Entry", "nvme.cmd.get_logpage.identify.rcrd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tel,
            { "Total Entry Length (TEL)", "nvme.cmd.get_logpage.identify.rcrd.tel",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               "Length in bytes of the entire Extended Discovery Log Page"
               " Entry", HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_numexat,
            { "Number of Extended Attributes (NUMEXAT)", "nvme.cmd.get_logpage.identify.rcrd.numexat",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_rsvd2,
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.rsvd2",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_exat,
            { "Extended Attribute", "nvme.cmd.get_logpage.identify.rcrd.exat",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_exat_type,
            { "Extended Attribute Type (EXATTYPE)", "nvme.cmd.get_logpage.identify.rcrd.exat.type",
               FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(exattype_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_exat_len,
            { "Extended Attribute Length (EXATLEN)", "nvme.cmd.get_logpage.identify.rcrd.exat.len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               "Length of the Extended Attribute Value field; a non-zero"
               " multiple of four", HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_exat_val,
            { "Extended Attribute Value (EXATVAL)", "nvme.cmd.get_logpage.identify.rcrd.exat.val",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_trtype,
            { "Transport Type (TRTYPE)", "nvme.cmd.get_logpage.identify.rcrd.trtype",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(trt_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_adrfam,
            { "Address Family (ADRFAM)", "nvme.cmd.get_logpage.identify.rcrd.adrfam",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(adrfam_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_subtype,
            { "Subsystem Type (SUBTYPE)", "nvme.cmd.get_logpage.identify.rcrd.subtype",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(sub_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[0],
            { "Transport Requirements (TREQ)", "nvme.cmd.get_logpage.identify.rcrd.treq",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 310, byte 03: TSC 1:0, SQFCD 2, ZHIDS 3,
         * TASC 5:4, Reserved 7:6.  The pre-2.0 layout this was written against
         * had a 1-bit secure-channel flag and SQ flow control on bit 1. */
        { &hf_nvme_get_logpage_ify_rcrd_treq[1],
            { "Transport Secure Channel (TSC)", "nvme.cmd.get_logpage.identify.rcrd.treq.secch",
               FT_UINT8, BASE_HEX, VALS(treq_tsc_tbl), 0x3, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[2],
            { "SQ Flow Control Disable (SQFCD)", "nvme.cmd.get_logpage.identify.rcrd.treq.sqfc",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[3],
            { "Zero Host ID Support (ZHIDS)", "nvme.cmd.get_logpage.identify.rcrd.treq.zhids",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[4],
            { "Transport Authentication and Secure Channel (TASC)",
               "nvme.cmd.get_logpage.identify.rcrd.treq.tasc",
               FT_UINT8, BASE_HEX, VALS(treq_tasc_tbl), 0x30, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_treq[5],
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.treq.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL}
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
        { &hf_nvme_get_logpage_disc_rcrd_eflags[0],
            { "Entry flags (EFLAGS)", "nvme.cmd.get_logpage.discovery.rcrd.eflags",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_disc_rcrd_eflags[1],
            { "Duplicate Returned Information (DUPRETINFO)", "nvme.cmd.get_logpage.discovery.rcrd.eflags.dupretinfo",
                FT_BOOLEAN, 16, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_disc_rcrd_eflags[2],
            { "Explicit Persistent Connection Support for Discovery (EPCSD)",
                "nvme.cmd.get_logpage.discovery.rcrd.eflags.epcsd",
                FT_BOOLEAN, 16, NULL, 0x2, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 310, bytes 11:10: NCC is bit 2. */
        { &hf_nvme_get_logpage_disc_rcrd_eflags[3],
            { "No CDC Connectivity (NCC)", "nvme.cmd.get_logpage.discovery.rcrd.eflags.ncc",
                FT_BOOLEAN, 16, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_disc_rcrd_eflags[4],
            { "Reserved", "nvme.cmd.get_logpage.discovery.rcrd.eflags.rsvd0",
                FT_UINT16, BASE_HEX, NULL, 0xfff8, NULL, HFILL}
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
               FT_STRINGZTRUNC, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(sec_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ify_rcrd_tsas_tcp_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.identify.rcrd.tsas.tcp_rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Error Information Response */
        { &hf_nvme_get_logpage_errinf_entry,
            { "Error Information Log Entry", "nvme.cmd.get_logpage.errinf.entry",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
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
        /* NVMe Base 2.3 Figure 209 STS: Phase Tag bit 0, Status 15:1. */
        { &hf_nvme_get_logpage_errinf_sf[1],
            { "Status Field Value", "nvme.cmd.get_logpage.errinf.sf.val",
               FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_sf[2],
            { "Status Field Phase Tag", "nvme.cmd.get_logpage.errinf.sf.ptag",
               FT_UINT16, BASE_HEX, NULL, 0x0001, NULL, HFILL}
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
               FT_UINT16, BASE_DEC, NULL, 0x0700, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_pel[3],
            { "Reserved", "nvme.cmd.get_logpage.errinf.pel.rsvd",
               FT_UINT16, BASE_DEC, NULL, 0xf800, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_lba,
            { "LBA", "nvme.cmd.get_logpage.errinf.lba",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_ns,
            { "Namespace ID", "nvme.cmd.get_logpage.errinf.nsid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_vsi,
            { "Vendor Specific Information Available", "nvme.cmd.get_logpage.errinf.vsi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_trtype,
            { "Transport Type", "nvme.cmd.get_logpage.errinf.trype",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(trt_type_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_cmdset,
            { "Command Set Identifier (CSI)", "nvme.cmd.get_logpage.errinf.cmdset",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(csi_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_opc,
            { "Opcode", "nvme.cmd.get_logpage.errinf.opc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_csi,
            { "Command Specific Information", "nvme.cmd.get_logpage.errinf.csi",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_tsi,
            { "Transport Type Specific Information", "nvme.cmd.get_logpage.errinf.tsi",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.errinf.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_errinf_lpver,
            { "Log Page Version", "nvme.cmd.get_logpage.errinf.lpver",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
            { "Indeterminate Personality State", "nvme.cmd.get_logpage.smart.cw.ips",
               FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_cw[8],
            { "Reserved", "nvme.cmd.get_logpage.smart.cw.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL}
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
            { "Percentage Used (PUSED)", "nvme.cmd.get_logpage.smart.lae",
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
        { &hf_nvme_get_logpage_smart_infw[0],
            { "Informative Warning (INFW)", "nvme.cmd.get_logpage.smart.infw",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_infw[1],
            { "Voltage Log Threshold Warning (VLTHW)", "nvme.cmd.get_logpage.smart.infw.vlthw",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_infw[2],
            { "Reserved", "nvme.cmd.get_logpage.smart.infw.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
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
            { "Media and Data Integrity Errors (MDIE)", "nvme.cmd.get_logpage.smart.mie",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_us,
            { "Unexpected Power Losses (UPL)", "nvme.cmd.get_logpage.smart.us",
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
        { &hf_nvme_get_logpage_smart_olec,
            { "Operational Lifetime Energy Consumed (watt-hours)", "nvme.cmd.get_logpage.smart.olec",
               FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ipm[0],
            { "Interval Power Measurement", "nvme.cmd.get_logpage.smart.ipm",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ipm[1],
            { "Interval Power Measurement Value", "nvme.cmd.get_logpage.smart.ipm.ipmv",
               FT_UINT32, BASE_DEC, NULL, 0x0000ffff, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ipm[2],
            { "Interval Power Measurement Scale", "nvme.cmd.get_logpage.smart.ipm.ipms",
               FT_UINT32, BASE_HEX, VALS(smart_ipms_tbl), 0x00030000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ipm[3],
            { "Reserved", "nvme.cmd.get_logpage.smart.ipm.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0x000c0000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ipm[4],
            { "Power Measurement Type", "nvme.cmd.get_logpage.smart.ipm.pmt",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(smart_pmt_tbl), 0x00f00000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_smart_ipm[5],
            { "Reserved", "nvme.cmd.get_logpage.smart.ipm.rsvd1",
               FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL}
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
            { "Current Active Firmware Slot (CAFS)", "nvme.cmd.get_logpage.fw_slot.afi.afs",
               FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_afi[2],
            { "Reserved", "nvme.cmd.get_logpage.fw_slot.afi.rsvd0",
               FT_UINT8, BASE_HEX, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_afi[3],
            { "Next Active Firmware Slot (NAFS)", "nvme.cmd.get_logpage.fw_slot.afi.nfs",
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
        { &hf_nvme_get_logpage_fw_slot_frs,
            { "Firmware Slot Revisions", "nvme.cmd.get_logpage.fw_slot.frs",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs_ascii[0],
            { "Firmware Revision for Slot 1 (ASCII)", "nvme.cmd.get_logpage.fw_slot.frs.s1.ascii",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs_ascii[1],
            { "Firmware Revision for Slot 2 (ASCII)", "nvme.cmd.get_logpage.fw_slot.frs.s2.ascii",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs_ascii[2],
            { "Firmware Revision for Slot 3 (ASCII)", "nvme.cmd.get_logpage.fw_slot.frs.s3.ascii",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs_ascii[3],
            { "Firmware Revision for Slot 4 (ASCII)", "nvme.cmd.get_logpage.fw_slot.frs.s4.ascii",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs_ascii[4],
            { "Firmware Revision for Slot 5 (ASCII)", "nvme.cmd.get_logpage.fw_slot.frs.s5.ascii",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs_ascii[5],
            { "Firmware Revision for Slot 6 (ASCII)", "nvme.cmd.get_logpage.fw_slot.frs.s6.ascii",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_fw_slot_frs_ascii[6],
            { "Firmware Revision for Slot 7 (ASCII)", "nvme.cmd.get_logpage.fw_slot.frs.s7.ascii",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
               FT_UINT32, BASE_HEX, NULL, 0x3fe0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[7],
            { "Command Submission and Execution Relaxations (CSER)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.cser",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(cmd_eff_cser_tbl), 0xc000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[8],
            { "Command Submission and Execution (CSE)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.cse",
               FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(cmd_eff_cse_tbl), 0x70000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[9],
            { "UUID Selection Supported (USS)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.uss",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        /* CSP (Figure 214) reserves bits 11:6. */
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[10],
            { "Command Scope (CSP)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csp",
               FT_UINT32, BASE_HEX, NULL, 0xfff00000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[11],
            { "Namespace Scope (NSCPE)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.nscpe",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[12],
            { "Controller Scope (CSCPE)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.cscpe",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[13],
            { "NVM Set Scope (NSETSCPE)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.nsetscpe",
               FT_BOOLEAN, 32, NULL, 0x400000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[14],
            { "Endurance Group Scope (EGSCPE)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.egscpe",
               FT_BOOLEAN, 32, NULL, 0x800000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[15],
            { "Domain Scope (DSCPE)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.dscpe",
               FT_BOOLEAN, 32, NULL, 0x1000000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[16],
            { "NVM Subsystem Scope (NSSCPE)", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.nsscpe",
               FT_BOOLEAN, 32, NULL, 0x2000000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_and_eff_cseds[17],
            { "Reserved", "nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfc000000, NULL, HFILL}
        },
        /* Supported Log Pages Response (LID 00h) */
        { &hf_nvme_get_logpage_supported_lids,
            { "Log Page Identifier Supported", "nvme.cmd.get_logpage.supported.lids",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_supported_lidseds[0],
            { "LID Supported and Effects Data Structure", "nvme.cmd.get_logpage.supported.lidseds",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_supported_lidseds[1],
            { "LID Supported (LSUPP)", "nvme.cmd.get_logpage.supported.lidseds.lsupp",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_supported_lidseds[2],
            { "Index Offset Supported (IOS)", "nvme.cmd.get_logpage.supported.lidseds.ios",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_supported_lidseds[3],
            { "Reserved", "nvme.cmd.get_logpage.supported.lidseds.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffc, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_supported_lidseds[4],
            { "LID Specific Parameter (LIDSP)", "nvme.cmd.get_logpage.supported.lidseds.lidsp",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        /* Device Self-Test Response */
                { &hf_nvme_get_logpage_selftest_csto[0],
            { "Current Device Self-Test Operation", "nvme.cmd.get_logpage.selftest.csto",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_csto[1],
            { "Current Self-Test Operation Status", "nvme.cmd.get_logpage.selftest.csto.st",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(stest_type_active_tbl), 0xf, NULL, HFILL}
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
            { "Reserved", "nvme.cmd.get_logpage.selftest.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xffff, NULL, HFILL}
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
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(stest_result_tbl), 0xf, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_status[2],
            { "Device Self-test Type", "nvme.cmd.get_logpage.selftest.res.status.type",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(stest_type_done_tbl), 0xf0, NULL, HFILL}
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
            { "Status Code Type (SCT) Field Valid", "nvme.cmd.get_logpage.selftest.res.vdi.sct",
               FT_BOOLEAN, 8, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vdi[4],
            { "Status Code (SC) Field Valid", "nvme.cmd.get_logpage.selftest.res.vdi.sc",
               FT_BOOLEAN, 8, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_selftest_res_vdi[5],
            { "Reserved", "nvme.cmd.get_logpage.selftest.res.vdi.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
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
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
        { &hf_nvme_get_logpage_telemetry_da4lb,
            { "Telemetry Data Area 4 Last Block", "nvme.cmd.get_logpage.telemetry.da4b",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_rsvd2,
            { "Reserved", "nvme.cmd.get_logpage.telemetry.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_scope,
            { "Telemetry Scope", "nvme.cmd.get_logpage.telemetry.scope",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(telemetry_scope_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_hdgn,
            { "Telemetry Host-Initiated Data Generation Number", "nvme.cmd.get_logpage.telemetry.hdgn",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_da,
            { "Telemetry Controller-Initiated Data Available", "nvme.cmd.get_logpage.telemetry.da",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(telemetry_data_available_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_telemetry_dgn,
            { "Telemetry Controller-Initiated Data Generation Number", "nvme.cmd.get_logpage.telemetry.dgn",
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
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_egfeat[0],
            { "Endurance Group Features", "nvme.cmd.get_logpage.egroup.egfeat",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_egfeat[1],
            { "Endurance Group Media (Rotational)", "nvme.cmd.get_logpage.egroup.egfeat.egrmedia",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_egfeat[2],
            { "Reserved", "nvme.cmd.get_logpage.egroup.egfeat.rsvd0",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.egroup.rsvd0",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
        { &hf_nvme_get_logpage_egroup_did,
            { "Domain Identifier", "nvme.cmd.get_logpage.egroup.did",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
            { "Number of Error Information Log Entries", "nvme.cmd.get_logpage.egroup.ele",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_tegcap,
            { "Total Endurance Group Capacity (TEGCAP)", "nvme.cmd.get_logpage.egroup.tegcap",
               FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_egroup_uegcap,
            { "Unallocated Endurance Group Capacity (UEGCAP)", "nvme.cmd.get_logpage.egroup.uegcap",
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
            { "Predictable Latency Mode Window (PLMW)", "nvme.cmd.get_logpage.pred_lat.status.plmw",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(plat_status_tbl), 0x7, NULL, HFILL}
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
        { &hf_nvme_get_logpage_pred_lat_aggreg_fill,
            { "Fill past the end of the list", "nvme.cmd.get_logpage.pred_lat_aggreg.fill",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
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
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_ana_grp_anas[1],
            { "Asymmetric Namespace Access State", "nvme.cmd.get_logpage.ana.grp.anas.state",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(ana_state_tbl), 0xf, NULL, HFILL}
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
            { "Recommended Action Type (RATYPE)", "nvme.cmd.get_logpage.lba_status.nel.ne.ratype",
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
            { "Range Starting LBA (RSLBA)", "nvme.cmd.get_logpage.lba_status.nel.ne.rd.rslba",
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
        { &hf_nvme_get_logpage_egroup_aggreg_fill,
            { "Fill past the end of the list", "nvme.cmd.get_logpage.egroup_agreg.fill",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Get LogPage Reservation Notification Response */
        { &hf_nvme_get_logpage_reserv_notif_lpc,
            { "Log Page Count", "nvme.cmd.get_logpage.reserv_notif.lpc",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_reserv_notif_lpt,
            { "Reservation Notification Log Page Type", "nvme.cmd.get_logpage.reserv_notif.lpt",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(rnlpt_tbl), 0x0, NULL, HFILL}
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
            { "Sanitize Operation Status (SOS)", "nvme.cmd.get_logpage.sanitize.sstat.sos",
               FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(san_sos_tbl), 0x7, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[2],
            { "Overwrite Passes Completed (OPC)", "nvme.cmd.get_logpage.sanitize.sstat.opc",
               FT_UINT16, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[3],
            { "Global Data Erased", "nvme.cmd.get_logpage.sanitize.sstat.gde",
               FT_BOOLEAN, 16, NULL, 0x100, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[4],
            { "Media Verification Canceled", "nvme.cmd.get_logpage.sanitize.sstat.mvcncld",
               FT_BOOLEAN, 16, NULL, 0x200, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[5],
            { "Namespace Data Erased", "nvme.cmd.get_logpage.sanitize.sstat.nde",
               FT_BOOLEAN, 16, NULL, 0x400, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[6],
            { "Purged (PRGD)", "nvme.cmd.get_logpage.sanitize.sstat.prgd",
               FT_BOOLEAN, 16, NULL, 0x800, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_sstat[7],
            { "Reserved", "nvme.cmd.get_logpage.sanitize.sstat.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0xf000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_scdw10,
            { "Sanitize Command Dword 10 Information (SCDW10)", "nvme.cmd.get_logpage.sanitize.scdw10",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_eto,
            { "Estimated Time For Overwrite", "nvme.cmd.get_logpage.sanitize.eto",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_sanitize_time), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etbe,
            { "Estimated Time For Block Erase", "nvme.cmd.get_logpage.sanitize.etbe",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_sanitize_time), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etce,
            { "Estimated Time For Crypto Erase", "nvme.cmd.get_logpage.sanitize.etce",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_sanitize_time), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etond,
            { "Estimated Time For Overwrite With No-Deallocate Media Modification (ETODMM)", "nvme.cmd.get_logpage.sanitize.etond",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_sanitize_time), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etbend,
            { "Estimated Time For Block Erase With No-Deallocate Media Modification (ETBENMM)", "nvme.cmd.get_logpage.sanitize.etbend",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_sanitize_time), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etcend,
            { "Estimated Time For Crypto Erase With No-Deallocate Media Modification (ETCENMM)", "nvme.cmd.get_logpage.sanitize.etcend",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_sanitize_time), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_etpvds,
            { "Estimated Time For Post-Verification Deallocation State", "nvme.cmd.get_logpage.sanitize.etpvds",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_sanitize_pvds_time), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_ssi[0],
            { "Sanitize State Information (SSI)", "nvme.cmd.get_logpage.sanitize.ssi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_ssi[1],
            { "Sanitize State (SANS)", "nvme.cmd.get_logpage.sanitize.ssi.sans",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(san_sans_tbl), 0x0f, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_ssi[2],
            { "Failure State (FAILS)", "nvme.cmd.get_logpage.sanitize.ssi.fails",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(san_sans_tbl), 0xf0,
               "Sanitize state in which the failure occurred", HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.sanitize.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_mnsoip,
            { "Maximum Namespace Sanitize Operations In Progress (MNSOIP)", "nvme.cmd.get_logpage.sanitize.mnsoip",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_stnsid,
            { "Sanitization Target NSID (STNSID)", "nvme.cmd.get_logpage.sanitize.stnsid",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_sanitize_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.sanitize.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Feature Identifiers Supported and Effects Response */
        { &hf_nvme_get_logpage_feat_sup_and_eff_fidx,
            { "FID Supported Entry", "nvme.cmd.get_logpage.feat_sup_and_eff.fidx",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[0],
            { "FID Supported and Effects Data Structure", "nvme.cmd.get_logpage.feat_sup_and_eff.fids",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[1],
            { "FID Supported (FSUPP)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsupp",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[2],
            { "User Data Content Change (UDCC)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.udcc",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[3],
            { "Namespace Capability Change (NCC)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.ncc",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[4],
            { "Namespace Inventory Change (NIC)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.nic",
               FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[5],
            { "Controller Capability Change (CCC)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.ccc",
               FT_BOOLEAN, 32, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[6],
            { "Reserved", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.rsvd0",
               FT_UINT32, BASE_HEX, NULL, 0x7ffe0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[7],
            { "UUID Selection Supported (USS)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.uss",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        /* FSP (Base 2.4 Figure 271) defines CDQSCP at bit 6 and RUHS at bit 7. */
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[8],
            { "FID Scope (FSP)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp",
               FT_UINT32, BASE_HEX, NULL, 0xfff00000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[9],
            { "Namespace Scope (NSCPE)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.nscpe",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[10],
            { "Controller Scope (CSCPE)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.cscpe",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[11],
            { "NVM Set Scope (NSETSCPE)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.nsetscpe",
               FT_BOOLEAN, 32, NULL, 0x400000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[12],
            { "Endurance Group Scope (EGSCPE)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.egscpe",
               FT_BOOLEAN, 32, NULL, 0x800000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[13],
            { "Domain Scope (DSCPE)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.dscpe",
               FT_BOOLEAN, 32, NULL, 0x1000000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[14],
            { "NVM Subsystem Scope (NSSCPE)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.nsscpe",
               FT_BOOLEAN, 32, NULL, 0x2000000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[15],
            { "Controller Data Queue (CDQSCP)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.cdqscp",
               FT_BOOLEAN, 32, NULL, 0x4000000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[16],
            { "Reclaim Unit Handle Scope (RUHS)", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.ruhs",
               FT_BOOLEAN, 32, NULL, 0x8000000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_feat_sup_and_eff_fids[17],
            { "Reserved", "nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xf0000000, NULL, HFILL}
        },
        /* NVMe-MI Commands Supported and Effects Response */
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cs,
            { "MI Command Supported Entry", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cs",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[0],
            { "NVMe-MI Commands Supported and Effects Data Structure", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[1],
            { "Command Supported (CSUPP)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csupp",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[2],
            { "User Data Content Change (UDCC)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.udcc",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[3],
            { "Namespace Capability Change (NCC)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.ncc",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[4],
            { "Namespace Inventory Change (NIC)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.nic",
               FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[5],
            { "Controller Capability Change (CCC)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.ccc",
               FT_BOOLEAN, 32, NULL, 0x10, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[6],
            { "Reserved", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffe0, NULL, HFILL}
        },
        /* CSP (Figure 269) reserves bits 11:6. */
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[7],
            { "Command Scope (CSP)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp",
               FT_UINT32, BASE_HEX, NULL, 0xfff00000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[8],
            { "Namespace Scope (NSCPE)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.nscpe",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[9],
            { "Controller Scope (CSCPE)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.cscpe",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[10],
            { "NVM Set Scope (NSETSCPE)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.nsetscpe",
               FT_BOOLEAN, 32, NULL, 0x400000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[11],
            { "Endurance Group Scope (EGSCPE)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.egscpe",
               FT_BOOLEAN, 32, NULL, 0x800000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[12],
            { "Domain Scope (DSCPE)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.dscpe",
               FT_BOOLEAN, 32, NULL, 0x1000000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[13],
            { "NVM Subsystem Scope (NSSCPE)", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.nsscpe",
               FT_BOOLEAN, 32, NULL, 0x2000000, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_mi_cmd_sup_and_eff_cseds[14],
            { "Reserved", "nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfc000000, NULL, HFILL}
        },
        /* Command and Feature Lockdown Response */
        { &hf_nvme_get_logpage_cmd_feat_lockdown_cfila[0],
            { "Command and Feature Identifier List Attributes (CFILA)", "nvme.cmd.get_logpage.cmd_feat_lockdown.cfila",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_feat_lockdown_cfila[1],
            { "Scope Selected (SS)", "nvme.cmd.get_logpage.cmd_feat_lockdown.cfila.ss",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(lockdown_scope_rvals), 0x0f, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_feat_lockdown_cfila[2],
            { "Contents Selected (CS)", "nvme.cmd.get_logpage.cmd_feat_lockdown.cfila.cs",
               FT_UINT8, BASE_HEX, VALS(lockdown_contents_vals), 0x30, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_feat_lockdown_cfila[3],
            { "Reserved", "nvme.cmd.get_logpage.cmd_feat_lockdown.cfila.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_feat_lockdown_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.cmd_feat_lockdown.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Command and Feature Lockdown, Enhanced format (Base 2.4 Figures 277-278) */
        { &hf_nvme_lp_lockdown_enh_ver,
            { "Version (VER)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.ver",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_cfia[0],
            { "Command and Feature Identifier Attributes (CFIA)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.cfia",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_cfia[1],
            { "Scope Selected (SS)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.cfia.ss",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(lockdown_scope_rvals), 0x0f, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_cfia[2],
            { "Contents Selected (CS)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.cfia.cs",
               FT_UINT8, BASE_HEX, VALS(lockdown_contents_vals), 0x30, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_cfia[3],
            { "Reserved", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.cfia.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_cntlid,
            { "Controller Identifier (CNTLID)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.cntlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_sze,
            { "Size (SZE)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.sze",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_ncfid,
            { "Number of Command and Feature Identifier Descriptors (NCFID)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.ncfid",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_cfids,
            { "Command and Feature Identifier Descriptors Size (CFIDS)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.cfids",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_desc,
            { "Command and Feature Identifier Descriptor", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.desc",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_cfi,
            { "Command and Feature Identifier (CFI)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.desc.cfi",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_dcfia[0],
            { "Command and Feature Identifier Attributes (CFIA)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.desc.cfia",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_dcfia[1],
            { "All Controllers (ACNTL)", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.desc.cfia.acntl",
               FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_dcfia[2],
            { "Reserved", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.desc.cfia.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_lp_lockdown_enh_desc_rsvd,
            { "Reserved", "nvme.cmd.get_logpage.cmd_feat_lockdown.enh.desc.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_feat_lockdown_lngth,
            { "Length (LNGTH)", "nvme.cmd.get_logpage.cmd_feat_lockdown.lngth",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_feat_lockdown_cfil,
            { "Command/Feature Identifier", "nvme.cmd.get_logpage.cmd_feat_lockdown.cfil",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_cmd_feat_lockdown_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.cmd_feat_lockdown.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* Get LogPage Physical Interface Receiver Eye Opening Measurement (LID 19h) response */
        { &hf_nvme_get_logpage_eom_lid,
            { "Log Identifier", "nvme.cmd.get_logpage.eom.lid",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_eomip,
            { "EOM In Progress", "nvme.cmd.get_logpage.eom.eomip",
               FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(eom_eomip_tbl), 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_hsize,
            { "Header Size (bytes)", "nvme.cmd.get_logpage.eom.hsize",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_rsz,
            { "Result Size (bytes)", "nvme.cmd.get_logpage.eom.rsz",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_edgn,
            { "EOM Data Generation Number", "nvme.cmd.get_logpage.eom.edgn",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_lrev,
            { "Log Revision", "nvme.cmd.get_logpage.eom.lrev",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_odp[0],
            { "Optional Data Present", "nvme.cmd.get_logpage.eom.odp",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_odp[1],
            { "Printable Eye Field Present", "nvme.cmd.get_logpage.eom.odp.pefp",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_odp[2],
            { "Eye Data Field Present", "nvme.cmd.get_logpage.eom.odp.edfp",
               FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_odp[3],
            { "Reserved", "nvme.cmd.get_logpage.eom.odp.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_lns,
            { "Lanes Configured", "nvme.cmd.get_logpage.eom.lns",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_epl,
            { "Eyes Per Lane", "nvme.cmd.get_logpage.eom.epl",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_lspfc[0],
            { "Log Specific Parameter Field Copy", "nvme.cmd.get_logpage.eom.lspfc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_lspfc[1],
            { "Log Specific Parameter Field Value", "nvme.cmd.get_logpage.eom.lspfc.lspfv",
               FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_lspfc[2],
            { "Reserved", "nvme.cmd.get_logpage.eom.lspfc.rsvd",
               FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_lspfc_act,
            { "Action (ACT)", "nvme.cmd.get_logpage.eom.lspfc.lspfv.act",
               FT_UINT8, BASE_HEX, VALS(eom_lsp_act_tbl), 0x0c, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_lspfc_mqual,
            { "Measurement Quality (MQUAL)", "nvme.cmd.get_logpage.eom.lspfc.lspfv.mqual",
               FT_UINT8, BASE_HEX, VALS(eom_lsp_mqual_tbl), 0x03, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_linfo[0],
            { "Link Information", "nvme.cmd.get_logpage.eom.linfo",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_linfo[1],
            { "Measurement Link Speed", "nvme.cmd.get_logpage.eom.linfo.mls",
               FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_linfo[2],
            { "Reserved", "nvme.cmd.get_logpage.eom.linfo.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.eom.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_lsic,
            { "Log Specific Identifier Copy", "nvme.cmd.get_logpage.eom.lsic",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_ds,
            { "Descriptor Size (bytes)", "nvme.cmd.get_logpage.eom.ds",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_nd,
            { "Number of Descriptors", "nvme.cmd.get_logpage.eom.nd",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_maxtb,
            { "Maximum Top Bottom", "nvme.cmd.get_logpage.eom.maxtb",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_maxlr,
            { "Maximum Left Right", "nvme.cmd.get_logpage.eom.maxlr",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_etgood,
            { "Estimated Time for Good Quality (seconds)", "nvme.cmd.get_logpage.eom.etgood",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_etbetter,
            { "Estimated Time for Better Quality (seconds)", "nvme.cmd.get_logpage.eom.etbetter",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_etbest,
            { "Estimated Time for Best Quality (seconds)", "nvme.cmd.get_logpage.eom.etbest",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.eom.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc,
            { "EOM Lane Descriptor", "nvme.cmd.get_logpage.eom.desc",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_rsvd0,
            { "Reserved", "nvme.cmd.get_logpage.eom.desc.rsvd0",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_mstat[0],
            { "Measurement Status", "nvme.cmd.get_logpage.eom.desc.mstat",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_mstat[1],
            { "Measurement Successful", "nvme.cmd.get_logpage.eom.desc.mstat.mscs",
               FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_mstat[2],
            { "Reserved", "nvme.cmd.get_logpage.eom.desc.mstat.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0xfe, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_ln,
            { "Lane", "nvme.cmd.get_logpage.eom.desc.ln",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_eye,
            { "Eye", "nvme.cmd.get_logpage.eom.desc.eye",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_top,
            { "Top", "nvme.cmd.get_logpage.eom.desc.top",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_btm,
            { "Bottom", "nvme.cmd.get_logpage.eom.desc.btm",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_lft,
            { "Left", "nvme.cmd.get_logpage.eom.desc.lft",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_rgt,
            { "Right", "nvme.cmd.get_logpage.eom.desc.rgt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_nrows,
            { "Number of Rows", "nvme.cmd.get_logpage.eom.desc.nrows",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_ncols,
            { "Number of Columns", "nvme.cmd.get_logpage.eom.desc.ncols",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_edlen,
            { "Eye Data Length (bytes)", "nvme.cmd.get_logpage.eom.desc.edlen",
               FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_rsvd1,
            { "Reserved", "nvme.cmd.get_logpage.eom.desc.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_pe,
            { "Printable Eye", "nvme.cmd.get_logpage.eom.desc.pe",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_ed,
            { "Eye Data", "nvme.cmd.get_logpage.eom.desc.ed",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_pad,
            { "Padding", "nvme.cmd.get_logpage.eom.desc.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_get_logpage_eom_desc_undef,
            { "Undefined Descriptor Bytes", "nvme.cmd.get_logpage.eom.desc.undefined",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               "Bytes inside Descriptor Size that the EOM Lane Descriptor does not define", HFILL}
        },
        /* NVMe Response fields */
        { &hf_nvme_cqe_dword0,
            { "DWORD0", "nvme.cqe.dword0",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
        { &hf_nvme_cqe_fwc_dword0[0],
            { "DWORD0", "nvme.cqe.dword0.fw_commit",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_fwc_dword0[1],
            { "Admin Submission Queue FW Overlap (ASQFWO)", "nvme.cqe.dword0.fw_commit.asqfwo",
               FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL}
        },
        { &hf_nvme_cqe_fwc_dword0[2],
            { "Management Endpoint FW Overlap (MEFWO)", "nvme.cqe.dword0.fw_commit.mefwo",
               FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL}
        },
        { &hf_nvme_cqe_fwc_dword0[3],
            { "Reserved", "nvme.cqe.dword0.fw_commit.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffc, NULL, HFILL}
        },
        { &hf_nvme_cqe_ns_mgmt_nsid,
            { "Namespace Identifier (NSID)", "nvme.cqe.dword0.ns_mgmt.nsid",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_cap_mgmt_dword0[0],
            { "DWORD0", "nvme.cqe.dword0.cap_mgmt",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_cap_mgmt_dword0[1],
            { "Created Element Identifier (CELID)", "nvme.cqe.dword0.cap_mgmt.celid",
               FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_cap_mgmt_dword0[2],
            { "Reserved", "nvme.cqe.dword0.cap_mgmt.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_virt_mgmt_dword0[0],
            { "DWORD0", "nvme.cqe.dword0.virt_mgmt",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_virt_mgmt_dword0[1],
            { "Number of Controller Resources Modified (NRM)", "nvme.cqe.dword0.virt_mgmt.nrm",
               FT_UINT32, BASE_DEC, NULL, 0x0000ffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_virt_mgmt_dword0[2],
            { "Reserved", "nvme.cqe.dword0.virt_mgmt.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_dword0_sf_nq[0],
            { "DWORD0: Set Feature Number of Queues Result", "nvme.cqe.dword0.set_features.nq",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_dword0_sf_nq[1],
            { "Number of IO Submission Queues Allocated", "nvme.cqe.dword0.set_features.nq.nsqa",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_dword0_sf_nq[2],
            { "Number of IO Completion Queues Allocated", "nvme.cqe.dword0.set_features.ncqa",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xffff0000, NULL, HFILL}
        },
        /* Get Feature Responses */
        { &hf_nvme_cqe_get_features_dword0_arb[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.arb",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[1],
            { "Arbitration Burst", "nvme.cqe.dword0.get_features.arb.ab",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_arb_burst), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[2],
            { "Reserved", "nvme.cqe.dword0.get_features.arb.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x000000f8, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[3],
            { "Low Priority Weight", "nvme.cqe.dword0.get_features.arb.lpw",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xff00, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[4],
            { "Medium Priority Weight", "nvme.cqe.dword0.get_features.arb.mpw",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_arb[5],
            { "High Priority Weight", "nvme.cqe.dword0.get_features.arb.hpw",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xff000000, NULL, HFILL}
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
            { "Workload Hint (WH)", "nvme.cqe.dword0.get_features.pm.wh",
               FT_UINT32, BASE_HEX, NULL, 0xe0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_pm[3],
            { "Reserved", "nvme.cqe.dword0.get_features.pm.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x0000ff00, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_pm[4],
            { "Idle I/O Exit Latency Limit (IIELL)", "nvme.cqe.dword0.get_features.pm.iiell",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_pm_iiell), 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbart[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.lbart",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbart[1],
            { "Number of LBA Ranges (NUM)", "nvme.cqe.dword0.get_features.lbart.lbarn",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0x3f, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_lbart[2],
            { "Reserved", "nvme.cqe.dword0.get_features.lbart.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffffffc0, NULL, HFILL}
        },
        /* NVMe Base 2.3 section 5.2.26.1.3: the selected 16-bit threshold. */
        { &hf_nvme_cqe_get_features_dword0_tt[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.tt",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_tt[1],
            { "Temperature Threshold", "nvme.cqe.dword0.get_features.tt.tmpth",
               FT_UINT32, BASE_HEX, NULL, 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_tt[2],
            { "Not defined for a Get Features completion",
               "nvme.cqe.dword0.get_features.tt.undefined",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000,
               "NVMe Base 5.2.26.1.3 returns only \"the temperature"
               " threshold selected by Command Dword 11\" in Dword 0, so these"
               " bits have no assigned meaning -- not even Reserved, which"
               " would require them to be cleared to 0h", HFILL}
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
               FT_UINT32, BASE_HEX, NULL, 0xfffe0000, NULL, HFILL}
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
            { "Reserved", "nvme.cqe.dword0.get_features.vwce.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nq[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.nq",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nq[1],
            { "Number of IO Submission Queues Allocated", "nvme.cqe.dword0.get_features.nq.nsqa",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nq[2],
            { "Number of IO Completion Queues Allocated", "nvme.cqe.dword0.get_features.nq.ncqa",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xffff0000, NULL, HFILL}
        },
        /* Section 5.2.26.2.2: Dword 0 is Figure 474. */
        { &hf_nvme_cqe_get_features_dword0_irqc[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.irqc",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqc[1],
            { "Aggregation Threshold", "nvme.cqe.dword0.get_features.irqc.thr",
               FT_UINT32, BASE_CUSTOM, CF_FUNC(add_nvme_zero_based), 0xff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqc[2],
            { "Aggregation Time (100 us units)", "nvme.cqe.dword0.get_features.irqc.time",
               FT_UINT32, BASE_HEX, NULL, 0xff00, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqc[3],
            { "Reserved", "nvme.cqe.dword0.get_features.irqc.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqv[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.irqv",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqv[1],
            { "IRQ Vector", "nvme.cqe.dword0.get_features.irqv.iv",
               FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_irqv[2],
            { "Coalescing Disable", "nvme.cqe.dword0.get_features.irqv.cd",
               FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL}
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
        /* Section 5.2.26.1.5: Dword 0 is Figure 409. */
        { &hf_nvme_cqe_get_features_dword0_aec[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.aec",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[1],
            { "SMART and Health Critical Warnings Bitmask", "nvme.cqe.dword0.get_features.aec.smart",
               FT_UINT32, BASE_HEX, NULL, 0xff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[2],
            { "Attached Namespace Attribute Notices (NAN)", "nvme.cqe.dword0.get_features.aec.ns",
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
            { "Normal NVM Subsystem Shutdown (NNSSHDN)", "nvme.cqe.dword0.get_features.aec.nnsshdn",
               FT_BOOLEAN, 32, TFS(&aec_event_notice_tfs), 0x8000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[10],
            { "Temperature Threshold Hysteresis Recovery (TTHRY)", "nvme.cqe.dword0.get_features.aec.tthry",
               FT_BOOLEAN, 32, TFS(&aec_event_notice_tfs), 0x10000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[11],
            { "Reachability Association (RASSN)", "nvme.cqe.dword0.get_features.aec.rassn",
               FT_BOOLEAN, 32, TFS(&aec_event_notice_tfs), 0x20000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[12],
            { "Reachability Group (RGRP0)", "nvme.cqe.dword0.get_features.aec.rgrp0",
               FT_BOOLEAN, 32, TFS(&aec_event_notice_tfs), 0x40000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[13],
            { "Allocated Namespace Attribute Notices (ANSAN)", "nvme.cqe.dword0.get_features.aec.ansan",
               FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[14],
            { "Cross-Controller Reset Completed Notices (CCRCN)", "nvme.cqe.dword0.get_features.aec.ccrcn",
               FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[15],
            { "Lost Host Communication Notices (LHCN)", "nvme.cqe.dword0.get_features.aec.lhcn",
               FT_BOOLEAN, 32, NULL, 0x200000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[16],
            { "Rate Limiting Configuration Change Notices (RLCCN)", "nvme.cqe.dword0.get_features.aec.rlccn",
               FT_BOOLEAN, 32, NULL, 0x400000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[22],
            { "Reserved", "nvme.cqe.dword0.get_features.aec.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x7800000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[17],
            { "Zone Descriptor Changed Notices (ZDCN)", "nvme.cqe.dword0.get_features.aec.zdcn",
               FT_BOOLEAN, 32, NULL, 0x8000000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[18],
            { "Pull Model DDC Request Log Page Change Notification (PMDRLPCN)", "nvme.cqe.dword0.get_features.aec.pmdrlpcn",
               FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[19],
            { "AVE Discovery Log Page Change Notification (ADLPCN)", "nvme.cqe.dword0.get_features.aec.adlpcn",
               FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[20],
            { "Host Discovery Log Page Change Notification (HDLPCN)", "nvme.cqe.dword0.get_features.aec.hdlpcn",
               FT_BOOLEAN, 32, NULL, 0x40000000, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_aec[21],
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
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hctm[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.hctm",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hctm[1],
            { "Thermal Management Temperature 2 (K)", "nvme.cqe.dword0.get_features.hctm.tmt2",
               FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_hctm[2],
            { "Thermal Management Temperature 1 (K)", "nvme.cqe.dword0.get_features.hctm.tmt1",
               FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL}
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
        /* NVMe Base 2.3 section 5.2.26.1.13: Dword 0 is Figure 425. */
        { &hf_nvme_cqe_get_features_dword0_plmw[1],
            { "Window Select (WSEL)", "nvme.cqe.dword0.get_features.plmw.ws",
               FT_UINT32, BASE_HEX, VALS(sf_ws_table), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_plmw[2],
            { "Reserved", "nvme.cqe.dword0.get_features.plmw.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff8, NULL, HFILL}
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
               FT_UINT32, BASE_HEX, NULL, 0xfffffff0, NULL, HFILL}
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
            { "Write Protection State (WPS)", "nvme.cqe.dword0.get_features.nswp.wps",
               FT_UINT32, BASE_HEX, VALS(sf_wps), 0x7, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_nswp[2],
            { "Reserved", "nvme.cqe.dword0.get_features.nswp.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0xfffffff8, NULL, HFILL}
        },
        /* NVMe Base 2.3 Figure 199: Dword 0 when Select is 11b. */
        { &hf_nvme_cqe_get_features_dword0_caps[0],
            { "DWORD0", "nvme.cqe.dword0.get_features.caps",
               FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_caps[1],
            { "Saveable (SVBL)", "nvme.cqe.dword0.get_features.caps.svbl",
               FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_caps[2],
            { "NS Specific (NSSPEC)", "nvme.cqe.dword0.get_features.caps.nsspec",
               FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_caps[3],
            { "Changeable (CHANG)", "nvme.cqe.dword0.get_features.caps.chang",
               FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL}
        },
        { &hf_nvme_cqe_get_features_dword0_caps[4],
            { "Reserved", "nvme.cqe.dword0.get_features.caps.rsvd",
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
        { &hf_nvme_cqe_sc_note,
            { "Status Code note", "nvme.cqe.status.sc.note",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[3],
            { "Status Code Type", "nvme.cqe.status.sct",
               FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_cqe_sct_tbl), 0xE00, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[4],
            { "Command Retry Delay", "nvme.cqe.status.crd",
               FT_UINT16, BASE_HEX, NULL, 0x3000, NULL, HFILL}
        },
        { &hf_nvme_cqe_status[5],
            { "More Information in Log Page", "nvme.cqe.status.m",
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
    static int *ett[] = {
        &ett_data,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_nidl_mismatch,
            { "nvme.identify.nsdesc.nidl_mismatch", PI_MALFORMED, PI_WARN,
              "NIDL does not match the length the NIDT requires", EXPFILL }
        },
        { &ei_nvme_identify_cns_reserved,
            { "nvme.identify.cns_reserved", PI_PROTOCOL, PI_WARN,
              "Reserved CNS value: no Identify data structure is defined (NVMe Base 'Identify - CNS Values')", EXPFILL }
        },
        { &ei_nvme_id_nument_excess,
            { "nvme.cmd.identify.underlying.nument.excess", PI_MALFORMED, PI_WARN,
              "NUMENT exceeds the maximum of 12 Underlying Namespace entries (Base 5.2.14.2.20)", EXPFILL }
        },
        { &ei_nvme_ctrl_list_count,
            { "nvme.controller_list.count_invalid", PI_PROTOCOL, PI_WARN,
              "NUMCIDS exceeds the defined maximum of 2047", EXPFILL } },
        { &ei_nvme_cqe_sc_undefined_for_cmd,
            { "nvme.cqe.status.sc.undefined_for_cmd", PI_PROTOCOL, PI_WARN,
              "Command Specific Status is not defined for this command", EXPFILL }
        },
        { &ei_nvme_cqe_status_error,
            { "nvme.cqe.status.error", PI_RESPONSE_CODE, PI_NOTE,
              "Command completed with an error status", EXPFILL }
        },
        { &ei_nvme_lbaf_count_invalid,
            { "nvme.identify.ns.lbaf.count_invalid", PI_MALFORMED, PI_WARN,
              "NLBAF and NULBAF describe more LBA Formats than the LBA Format list holds", EXPFILL }
        },
        { &ei_nvme_data_len_exceeds_frame,
            { "nvme.data.len_exceeds_frame", PI_MALFORMED, PI_WARN,
              "Transport declared more data than the frame carries", EXPFILL }
        },
        { &ei_nvme_logpage_window_misaligned,
            { "nvme.cmd.get_logpage.window_misaligned", PI_MALFORMED, PI_WARN,
              "Log page window does not start on a record boundary", EXPFILL }
        },
        { &ei_nvme_eom_desc_field_overrun,
            { "nvme.cmd.get_logpage.eom.desc_field_overrun", PI_MALFORMED, PI_WARN,
              "EOM Lane Descriptor declares a Printable Eye or Eye Data field"
              " larger than the descriptor holds", EXPFILL }
        },
        { &ei_nvme_eom_hsize_invalid,
            { "nvme.cmd.get_logpage.eom.hsize_invalid", PI_PROTOCOL, PI_WARN,
              "Header Size is not 64 (NVMe over PCIe Transport 1.4 Figure 75)", EXPFILL }
        },
        { &ei_nvme_security_length,
            { "nvme.security.invalid_length", PI_PROTOCOL, PI_WARN,
              "Security data exceeds the command's TL/AL", EXPFILL }
        },
        { &ei_nvme_security_tper_reset_tl,
            { "nvme.security.tper_reset_zero_tl", PI_PROTOCOL, PI_WARN,
              "TPer Reset Transfer Length shall be non-zero (Opal SSC section 3.2.3"
              " 'TPER_RESET Command'); SIIS NVMe TPer Interface Status Codes: Invalid Field in Command", EXPFILL }
        },
        { &ei_nvme_security_secp_send,
            { "nvme.security.secp_send_undefined", PI_PROTOCOL, PI_WARN,
              "Security Protocol 0x00 is not defined for Security Send (IF-SEND)"
              " (SIIS 'IF-SEND command parameters (NVM Express)')", EXPFILL }
        },
        { &ei_nvme_security_secp_nvme,
            { "nvme.security.secp_nvme_undefined", PI_PROTOCOL, PI_WARN,
              "Security Protocol 0x06 is not defined for NVMe (SIIS IF-SEND and"
              " IF-RECV command parameters)", EXPFILL }
        },
        { &ei_nvme_pel_invalid_event,
            { "nvme.cmd.get_logpage.pel.invalid_event", PI_MALFORMED, PI_ERROR,
              "Persistent event header is invalid: EHL below 21, VSIL above EL, or the event runs past Total Log Length", EXPFILL }
        },
        { &ei_nvme_pel_event_length,
            { "nvme.cmd.get_logpage.pel.event_length", PI_MALFORMED, PI_WARN,
              "Persistent event data length does not fit the event type", EXPFILL }
        },
        { &ei_nvme_pel_event_revision,
            { "nvme.cmd.get_logpage.pel.event_revision", PI_UNDECODED, PI_NOTE,
              "Persistent event revision differs from the one this decoder knows; data shown raw", EXPFILL }
        },
        { &ei_nvme_pel_tnev_mismatch,
            { "nvme.cmd.get_logpage.pel.tnev_mismatch", PI_PROTOCOL, PI_WARN,
              "Total Number of Events differs from the events in the log", EXPFILL }
        },
        { &ei_nvme_pel_invalid_header,
            { "nvme.cmd.get_logpage.pel.invalid_header", PI_MALFORMED, PI_WARN,
              "Persistent Event Log header length is less than 512 bytes or exceeds Total Log Length", EXPFILL }
        },
        { &ei_nvme_lp_layout,
            { "nvme.cmd.get_logpage.layout_invalid", PI_MALFORMED, PI_WARN,
              "Log page header declares a layout the structure does not allow;"
              " the rest is shown raw", EXPFILL }
        },
        { &ei_nvme_logpage_lpo_misaligned,
            { "nvme.cmd.get_logpage.lpo_misaligned", PI_PROTOCOL, PI_WARN,
              "Log Page Offset shall be dword aligned when Offset Type is"
              " clear (bits 1:0 cleared to 00b)", EXPFILL }
        },
        { &ei_nvme_data_wrong_direction,
            { "nvme.data.wrong_direction", PI_UNDECODED, PI_NOTE,
              "Data travelled in the direction this command does not define"
              " data for; structure-specific decode skipped", EXPFILL }
        },
        { &ei_nvme_feat_field_invalid,
            { "nvme.features.field_invalid", PI_PROTOCOL, PI_WARN,
              "Feature data field value is invalid", EXPFILL }},
        { &ei_nvme_feat_sel_reserved,
            { "nvme.cmd.get_features.sel_reserved", PI_PROTOCOL, PI_WARN,
              "Get Features Select value is reserved (NVMe Base 'Get Features - Command Dword 10');"
              " completion Dword 0 and data are shown raw", EXPFILL }
        },
        { &ei_nvme_feat_sel_no_data,
            { "nvme.cmd.get_features.sel_no_data", PI_PROTOCOL, PI_WARN,
              "Get Features with Select 011b returns capabilities in Dword 0 and"
              " this Feature uses no data buffer (NVMe Base 'Get Features - Command Dword 10',"
              " 'Set Features - Feature Identifiers');"
              " data shown raw", EXPFILL }
        },
        { &ei_nvme_feat_sel_caps_data,
            { "nvme.cmd.get_features.sel_caps_data", PI_PROTOCOL, PI_NOTE,
              "Get Features with Select 011b reports capabilities in Dword 0"
              "; data returned for this Feature is shown"
              " raw", EXPFILL }
        },
    };

    expert_module_t *expert_nvme;

    proto_nvme = proto_register_protocol("NVM Express", "nvme", "nvme");

    proto_register_field_array(proto_nvme, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme = expert_register_protocol(proto_nvme);
    expert_register_field_array(expert_nvme, ei, array_length(ei));
    nvme_pel_contexts = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                               g_direct_hash, g_direct_equal);
    nvme_walk_states = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                              g_int64_hash, g_int64_equal);

    /* Security Send/Receive payload dissectors register here, keyed on the
     * Security Protocol (SECP) value; struct nvme_security_info is passed
     * as the data pointer. */
    nvme_security_secp_table = register_dissector_table("nvme.security.secp",
            "NVMe Security Protocol (SECP)", proto_nvme, FT_UINT8, BASE_HEX);
    /* A Security Send's failed completion, for the same SECP, with the
     * completion queue entry as the tvb and the same data pointer. */
    nvme_security_send_failed_table = register_dissector_table(
            "nvme.security.send_failed", "NVMe Security Send failure",
            proto_nvme, FT_UINT8, BASE_HEX);
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
