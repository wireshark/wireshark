/* packet-nvme-mi-mi.c
 * NVMe-MI MI Command dissector (NMIMT=1, NVMe-MI 2.2 section 5) and Asynchronous
 * Event Message dissector (NMIMT=5h, NVMe-MI 2.2 section 4.4)
 * Copyright 2026, Brandon Chiu
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Reference: NVM Express Management Interface specification
 * https://nvmexpress.org/specification/nvme-mi-specification/
 * The AEM is here because its body is an AE Occurrence List (Figure 61). */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>
#include <wsutil/utf8_entities.h>
#include "packet-mctp.h"
#include "packet-nvme.h"
#include "packet-nvme-mi.h"

void proto_register_nvme_mi_mi(void);
void proto_reg_handoff_nvme_mi_mi(void);

static int proto_nvme_mi_mi;
/* AEMs are their own message category (NVMe-MI 2.2 Figure 26). */
static int proto_nvme_mi_aem;

static dissector_handle_t nvme_mi_mi_handle;
static dissector_handle_t nvme_mi_aem_handle;

static int hf_nvme_mi_mi_opcode;
static int hf_nvme_mi_mi_rsvd;
static int hf_nvme_mi_mi_cdw0;
static int hf_nvme_mi_mi_cdw1;
static int hf_nvme_mi_mi_status;
static int hf_nvme_mi_mi_nmresp;
static int hf_nvme_mi_mi_nmresp_rsvd;
static int hf_nvme_mi_mi_nmresp_rsvd_bits;
static int hf_nvme_mi_mi_nmd0_rsvd;
static int hf_nvme_mi_mi_nmd1_rsvd;
static int hf_nvme_mi_mi_data;
static int hf_nvme_mi_mi_ds_rsvd;
static int hf_nvme_mi_mi_response_surplus;

/* Read NVMe-MI Data Structure (00h) */
static int hf_nvme_mi_mi_rds_dtyp;
static int hf_nvme_mi_mi_rds_portid;
static int hf_nvme_mi_mi_rds_ctrlid;
static int hf_nvme_mi_mi_rds_iocsi;
static int hf_nvme_mi_mi_rds_rdl;

/* NVM Subsystem Health Status Poll (01h) */
static int hf_nvme_mi_mi_nshsp_cs;

/* Controller Health Status Poll (02h) */
static int hf_nvme_mi_mi_chsp_all;
static int hf_nvme_mi_mi_chsp_incvf;
static int hf_nvme_mi_mi_chsp_incpf;
static int hf_nvme_mi_mi_chsp_incf;
static int hf_nvme_mi_mi_chsp_maxrent;
static int hf_nvme_mi_mi_chsp_sctlid;
static int hf_nvme_mi_mi_chsp_ccf;
static int hf_nvme_mi_mi_chsp_cwarn;
static int hf_nvme_mi_mi_chsp_spare;
static int hf_nvme_mi_mi_chsp_pdlu;
static int hf_nvme_mi_mi_chsp_ctemp;
static int hf_nvme_mi_mi_chsp_csts;
static int hf_nvme_mi_mi_chsp_rent;

/* Configuration Set (03h) / Configuration Get (04h) */
static int hf_nvme_mi_mi_cfg_cid;
static int hf_nvme_mi_mi_cfg_portid;
static int hf_nvme_mi_mi_cfg_sfreq;
static int hf_nvme_mi_mi_cfg_mtus;
static int hf_nvme_mi_mi_cfg_sfreq_cur;
static int hf_nvme_mi_mi_cfg_mtus_cur;
static int hf_nvme_mi_mi_cfg_aeelver;
/* Health Status Change clear-selection bits (Configuration Set, NMD1) */
static int hf_nvme_mi_mi_cfg_hsc_tcida;
static int hf_nvme_mi_mi_cfg_hsc_cwarn;
static int hf_nvme_mi_mi_cfg_hsc_spare;
static int hf_nvme_mi_mi_cfg_hsc_pdlu;
static int hf_nvme_mi_mi_cfg_hsc_ctemp;
static int hf_nvme_mi_mi_cfg_hsc_cschng;
static int hf_nvme_mi_mi_cfg_hsc_fa;
static int hf_nvme_mi_mi_cfg_hsc_nac;
static int hf_nvme_mi_mi_cfg_hsc_ceco;
static int hf_nvme_mi_mi_cfg_hsc_nssro;
static int hf_nvme_mi_mi_cfg_hsc_shst;
static int hf_nvme_mi_mi_cfg_hsc_cfs;
static int hf_nvme_mi_mi_cfg_hsc_rdy;

/* VPD Read (05h) / VPD Write (06h) - shared layout */
static int hf_nvme_mi_mi_vpd_dofst;
static int hf_nvme_mi_mi_vpd_dlen;
static int hf_nvme_mi_mi_vpd_data;
static int hf_nvme_mi_mi_vpd_undecoded;
static int hf_nvme_mi_mi_vpd_pcivid;

/* SES Receive (08h) / SES Send (09h) */
static int hf_nvme_mi_mi_ses_pcode;
static int hf_nvme_mi_mi_ses_alength;
static int hf_nvme_mi_mi_ses_dlen;
static int hf_nvme_mi_mi_ses_rdl;
static int hf_nvme_mi_mi_ses_page;

/* Management Endpoint Buffer Read (0Ah) / Write (0Bh) */
static int hf_nvme_mi_mi_meb_dofst;
static int hf_nvme_mi_mi_meb_dlen;
static int hf_nvme_mi_mi_meb_data;
static int hf_nvme_mi_mi_pda_dformat;
static int hf_nvme_mi_mi_pda_rsvd;
static int hf_nvme_mi_mi_pda_dofst;
static int hf_nvme_mi_mi_pda_dlen;
static int hf_nvme_mi_mi_pda_byte_offset;
static int hf_nvme_mi_mi_pda_byte_length;
static int hf_nvme_mi_mi_pda_data;
static int hf_nvme_mi_mi_vpd_common[8];
static int hf_nvme_mi_mi_vpd_record;
static int hf_nvme_mi_mi_vpd_rti;
static int hf_nvme_mi_mi_vpd_rver;
static int hf_nvme_mi_mi_vpd_lrec;
static int hf_nvme_mi_mi_vpd_rlen;
static int hf_nvme_mi_mi_vpd_rcsum;
static int hf_nvme_mi_mi_vpd_hsum;
static int hf_nvme_mi_mi_vpd_version;
static int hf_nvme_mi_mi_vpd_raw;
static int hf_nvme_mi_mi_vpd_ff;
static int hf_nvme_mi_mi_vpd_power[10];
static int hf_nvme_mi_mi_vpd_capacity;
static int hf_nvme_mi_mi_vpd_pn;
static int hf_nvme_mi_mi_vpd_pinfo;
static int hf_nvme_mi_mi_vpd_pinfo_rsvd;
static int hf_nvme_mi_mi_vpd_cppc;
static int hf_nvme_mi_mi_vpd_linkspeed;
static int hf_nvme_mi_mi_vpd_linkwidth;
static int hf_nvme_mi_mi_vpd_mctps;
static int hf_nvme_mi_mi_vpd_rccap;
static int hf_nvme_mi_mi_vpd_portid;
static int hf_nvme_mi_mi_vpd_elemc;
static int hf_nvme_mi_mi_vpd_element;
static int hf_nvme_mi_mi_vpd_typ;
static int hf_nvme_mi_mi_vpd_rev;
static int hf_nvme_mi_mi_vpd_len;
static int hf_nvme_mi_mi_vpd_lstr;
static int hf_nvme_mi_mi_vpd_lptr;
static int hf_nvme_mi_mi_vpd_maxapwr;
static int hf_nvme_mi_mi_vpd_maxpwr;
static int hf_nvme_mi_mi_vpd_portcount;
static int hf_nvme_mi_mi_vpd_port;
static int hf_nvme_mi_mi_vpd_porttyp;
static int hf_nvme_mi_mi_vpd_portlen;
static int hf_nvme_mi_mi_vpd_count;
static int hf_nvme_mi_mi_vpd_pointer;
static int hf_nvme_mi_mi_vpd_sl;
static int hf_nvme_mi_mi_vpd_el;
static int hf_nvme_mi_mi_vpd_dport;
static int hf_nvme_mi_mi_vpd_addri;
static int hf_nvme_mi_mi_vpd_twcap;
static int hf_nvme_mi_mi_vpd_merim;
static int hf_nvme_mi_mi_vpd_merwmto;
static int hf_nvme_mi_mi_vpd_mut;
static int hf_nvme_mi_mi_vpd_rsvd;
static int hf_nvme_mi_mi_vpd_pciels_gts64;
static int hf_nvme_mi_mi_vpd_pciels_gts32;
static int hf_nvme_mi_mi_vpd_pciels_gts16;
static int hf_nvme_mi_mi_vpd_pciels_gts8;
static int hf_nvme_mi_mi_vpd_pciels_gts5;
static int hf_nvme_mi_mi_vpd_pciels_gts2p5;
static int hf_nvme_mi_mi_vpd_mctps_mctppcievs;
static int hf_nvme_mi_mi_vpd_rccap_rcs;
static int hf_nvme_mi_mi_vpd_rccap_srcss;
static int hf_nvme_mi_mi_vpd_rccap_srcnss;
static int hf_nvme_mi_mi_vpd_rccap_crcs;
static int hf_nvme_mi_mi_vpd_twaddr;
static int hf_nvme_mi_mi_vpd_arpc;
static int hf_nvme_mi_mi_vpd_twcap_rst;
static int hf_nvme_mi_mi_vpd_twcap_ffr;
static int hf_nvme_mi_mi_vpd_twcap_pecs;
static int hf_nvme_mi_mi_vpd_twcap_m2was;
static int hf_nvme_mi_mi_vpd_twcap_i3cs;
static int hf_nvme_mi_mi_vpd_twcap_mspd;
static int hf_nvme_mi_mi_vpd_twcap_i2cwa;
static int hf_nvme_mi_mi_vpd_twcap_bfcs;
static int hf_nvme_mi_mi_vpd_mfids;
static int hf_nvme_mi_mi_vpd_pia;
static int hf_nvme_mi_mi_vpd_pia_ipmiver;
static int hf_nvme_mi_mi_vpd_pia_palen;
static int hf_nvme_mi_mi_vpd_pia_lcode;
static int hf_nvme_mi_mi_vpd_pia_tl;
static int hf_nvme_mi_mi_vpd_pia_tcode;
static int hf_nvme_mi_mi_vpd_pia_ndb;
static int hf_nvme_mi_mi_vpd_pia_mname;
static int hf_nvme_mi_mi_vpd_pia_pname;
static int hf_nvme_mi_mi_vpd_pia_ppmn;
static int hf_nvme_mi_mi_vpd_pia_pver;
static int hf_nvme_mi_mi_vpd_pia_psn;
static int hf_nvme_mi_mi_vpd_pia_at;
static int hf_nvme_mi_mi_vpd_pia_ffi;
static int hf_nvme_mi_mi_vpd_pia_cpia;
static int hf_nvme_mi_mi_vpd_pia_eor;
static int hf_nvme_mi_mi_vpd_pia_pichk;

/* Configuration Set (03h) Asynchronous Event - request dword 0
 * and the AE Enable List request data */
static int hf_nvme_mi_mi_cfg_ae_envfa;
static int hf_nvme_mi_mi_cfg_ae_enpfa;
static int hf_nvme_mi_mi_cfg_ae_encfa;
static int hf_nvme_mi_mi_cfg_ae_aemd;
static int hf_nvme_mi_mi_cfg_ae_aerd;
static int hf_nvme_mi_mi_ae;
static int hf_nvme_mi_mi_ae_numaee;
static int hf_nvme_mi_mi_ae_aeelver;
static int hf_nvme_mi_mi_ae_aeetl;
static int hf_nvme_mi_mi_ae_aeelhl;
static int hf_nvme_mi_mi_ae_entry;
static int hf_nvme_mi_mi_ae_aeel;
static int hf_nvme_mi_mi_ae_aee;
static int hf_nvme_mi_mi_ae_id;
static int hf_nvme_mi_mi_ae_aee_rsvd;

/* Configuration Get (04h) Asynchronous Event - AE Supported List response
 * data; same shape as the AE Enable List, different names. */
static int hf_nvme_mi_mi_aes;
static int hf_nvme_mi_mi_aes_numaes;
static int hf_nvme_mi_mi_aes_aeslver;
static int hf_nvme_mi_mi_aes_aestl;
static int hf_nvme_mi_mi_aes_aeslhl;
static int hf_nvme_mi_mi_aes_entry;
static int hf_nvme_mi_mi_aes_aesl;
static int hf_nvme_mi_mi_aes_aese;
static int hf_nvme_mi_mi_aes_id;
static int hf_nvme_mi_mi_aes_aese_rsvd;

/* AE Occurrence List (NVMe-MI 2.2 Figures 61/62). */
static int hf_nvme_mi_mi_aeo_list;
static int hf_nvme_mi_mi_aeo_numaeo;
static int hf_nvme_mi_mi_aeo_aelver;
static int hf_nvme_mi_mi_aeo_aeolli;
static int hf_nvme_mi_mi_aeo_aeolo;
static int hf_nvme_mi_mi_aeo_aeoltl;
static int hf_nvme_mi_mi_aeo_aeolhl;
static int hf_nvme_mi_mi_aeo_hdr_unknown;
static int hf_nvme_mi_mi_aeo_aemti;
static int hf_nvme_mi_mi_aeo_aemgn;
static int hf_nvme_mi_mi_aeo_aemrc;
/* Per-occurrence (Figure 62) */
static int hf_nvme_mi_mi_aeo_entry;
static int hf_nvme_mi_mi_aeo_aelhlen;
static int hf_nvme_mi_mi_aeo_aeosil;
static int hf_nvme_mi_mi_aeo_aeovsil;
static int hf_nvme_mi_mi_aeo_aeoui;
static int hf_nvme_mi_mi_aeo_aeoi;
static int hf_nvme_mi_mi_aeo_aeocidi;
static int hf_nvme_mi_mi_aeo_aessi;
static int hf_nvme_mi_mi_aeo_aess;
static int hf_nvme_mi_mi_aeo_aessi_rsvd;
/* Scope-selected AE Occurrence Scope ID Info variants (Figure 64) */
static int hf_nvme_mi_mi_aeo_aeonsid;
static int hf_nvme_mi_mi_aeo_aeocid;
static int hf_nvme_mi_mi_aeo_aeomeid;
static int hf_nvme_mi_mi_aeo_aeopt;
static int hf_nvme_mi_mi_aeo_aeopid;
static int hf_nvme_mi_mi_aeo_aeoegid;
static int hf_nvme_mi_mi_aeo_scope_rsvd;
static int hf_nvme_mi_mi_aeo_meid_rsvd;
static int hf_nvme_mi_mi_aeo_port_rsvd;
static int hf_nvme_mi_mi_aeo_subsys_rsvd;
/* Specific / Vendor Specific Info */
static int hf_nvme_mi_mi_aeo_aeosi;
static int hf_nvme_mi_mi_aeosi_rv;
static int hf_nvme_mi_mi_aeosi_cfsv;
static int hf_nvme_mi_mi_aeosi_stv;
static int hf_nvme_mi_mi_aeosi_ssv;
static int hf_nvme_mi_mi_aeosi_crime;
static int hf_nvme_mi_mi_aeosi_cev;
static int hf_nvme_mi_mi_aeosi_ctv;
static int hf_nvme_mi_mi_aeosi_puv;
static int hf_nvme_mi_mi_aeosi_asv;
static int hf_nvme_mi_mi_aeosi_cwv;
static int hf_nvme_mi_mi_aeosi_plav;
static int hf_nvme_mi_mi_aeosi_sfmv;
static int hf_nvme_mi_mi_aeosi_snfmv;
static int hf_nvme_mi_mi_aeosi_rsvd1;
static int hf_nvme_mi_mi_aeosi_rsvd2;
static int hf_nvme_mi_mi_aeosi_rsvd3;
static int hf_nvme_mi_mi_aeosi_pmt;
static int hf_nvme_mi_mi_aeosi_pwrs;
static int hf_nvme_mi_mi_aeosi_pwrv;
static int hf_nvme_mi_mi_aeosi_pwr_rsvd;
static int hf_nvme_mi_mi_aeosi_pwrid;
static int hf_nvme_mi_mi_aeosi_pwril;
static int hf_nvme_mi_mi_aeosi_pwriv;
static int hf_nvme_mi_mi_aeosi_vsent;
static int hf_nvme_mi_mi_aeosi_vtht;
static int hf_nvme_mi_mi_aeosi_volv;
static int hf_nvme_mi_mi_aeo_aeovsi;
static int hf_nvme_mi_mi_aeo_aeovsh;
static int hf_nvme_mi_mi_aeo_aeovsui;
static int hf_nvme_mi_mi_aeo_aeovs_data;

/* Reset (07h) */
static int hf_nvme_mi_mi_reset_rsttyp;

/* Shutdown (0Ch) */
static int hf_nvme_mi_mi_shutdown_shdntyp;

/* NVM Subsystem Information data structure (DTYP 00h) */
static int hf_nvme_mi_mi_subsys_nump;
static int hf_nvme_mi_mi_subsys_mjr;
static int hf_nvme_mi_mi_subsys_mnr;
static int hf_nvme_mi_mi_subsys_nnsc;
static int hf_nvme_mi_mi_subsys_sre;
static int hf_nvme_mi_mi_subsys_nnsc_rsvd;

/* Port Information data structure (DTYP 01h) */
static int hf_nvme_mi_mi_port_prttyp;
static int hf_nvme_mi_mi_port_prtcap;
static int hf_nvme_mi_mi_port_aems;
static int hf_nvme_mi_mi_port_ciaps;
static int hf_nvme_mi_mi_port_mmtus;
static int hf_nvme_mi_mi_port_mebs;
static int hf_nvme_mi_mi_port_pcie_mps;
static int hf_nvme_mi_mi_port_pcie_slsv;
static int hf_nvme_mi_mi_port_pcie_cls;
static int hf_nvme_mi_mi_port_pcie_mlw;
static int hf_nvme_mi_mi_port_pcie_nlw;
static int hf_nvme_mi_mi_port_pcie_pn;
static int hf_nvme_mi_mi_port_twire_cvpdaddr;
static int hf_nvme_mi_mi_port_twire_mvpdfreq;
static int hf_nvme_mi_mi_port_twire_cmeaddr;
static int hf_nvme_mi_mi_port_twire_twprt;
static int hf_nvme_mi_mi_port_twire_i3csprt;
static int hf_nvme_mi_mi_port_twire_msmbfreq;
static int hf_nvme_mi_mi_port_twire_nvmebm;
static int hf_nvme_mi_mi_port_twire_nvmebms;
static int hf_nvme_mi_mi_port_prtcap_rsvd;
static int hf_nvme_mi_mi_port_twire_twprt_rsvd;
static int hf_nvme_mi_mi_port_twire_nvmebm_rsvd;
static int hf_nvme_mi_mi_port_twire_pdas;
static int hf_nvme_mi_mi_port_twire_sdformat;
static int hf_nvme_mi_mi_port_twire_sdformat_byte;
static int hf_nvme_mi_mi_port_twire_sdformat_512;
static int hf_nvme_mi_mi_port_twire_sdformat_4k;
static int hf_nvme_mi_mi_port_twire_sdformat_rsvd;
/* PCIe Supported Link Speeds Vector bits (NVMe-MI 2.2 Figure 118 byte 09) */
static int hf_nvme_mi_mi_port_pcie_slsv_g2p5;
static int hf_nvme_mi_mi_port_pcie_slsv_g5;
static int hf_nvme_mi_mi_port_pcie_slsv_g8;
static int hf_nvme_mi_mi_port_pcie_slsv_g16;
static int hf_nvme_mi_mi_port_pcie_slsv_g32;
static int hf_nvme_mi_mi_port_pcie_slsv_g64;
static int hf_nvme_mi_mi_port_pcie_slsv_rsvd;

/* Controller List data structure (DTYP 02h, NVMe Base) */
static int hf_nvme_mi_mi_ctrllist_numids;
static int hf_nvme_mi_mi_ctrllist_ctrlid;

/* Controller Information data structure (DTYP 03h) */
static int hf_nvme_mi_mi_ctrlinfo_portid;
static int hf_nvme_mi_mi_ctrlinfo_prii;
static int hf_nvme_mi_mi_ctrlinfo_riv;
static int hf_nvme_mi_mi_ctrlinfo_pri;
static int hf_nvme_mi_mi_ctrlinfo_pri_bus;
static int hf_nvme_mi_mi_ctrlinfo_pri_dev;
static int hf_nvme_mi_mi_ctrlinfo_pri_fn;
static int hf_nvme_mi_mi_ctrlinfo_pri_arifn;
static int hf_nvme_mi_mi_ctrlinfo_pcivid;
static int hf_nvme_mi_mi_ctrlinfo_pcidid;
static int hf_nvme_mi_mi_ctrlinfo_pcisvid;
static int hf_nvme_mi_mi_ctrlinfo_pcisdid;
static int hf_nvme_mi_mi_ctrlinfo_pciesn;
static int hf_nvme_mi_mi_ctrlinfo_prii_rsvd;

/* Optionally Supported / MEB Supported Command List (DTYP 04h/05h) */
static int hf_nvme_mi_mi_cmdlist_numcmd;
static int hf_nvme_mi_mi_cmdlist_ctyp;
static int hf_nvme_mi_mi_cmdlist_rsvd_high;
static int hf_nvme_mi_mi_cmdlist_rsvd_low;
static int hf_nvme_mi_mi_cmdlist_nmimt;
static int hf_nvme_mi_mi_cmdlist_opc;

/* Bytes after the last element a list data structure declares. */
static int hf_nvme_mi_mi_list_surplus;

/* NVM Subsystem Health Data Structure (NSHDS) */
static int hf_nvme_mi_mi_nshds_nss;
static int hf_nvme_mi_mi_nshds_nss_atf;
static int hf_nvme_mi_mi_nshds_nss_sfm;
static int hf_nvme_mi_mi_nshds_nss_df;
static int hf_nvme_mi_mi_nshds_nss_rnr;
static int hf_nvme_mi_mi_nshds_nss_p0la;
static int hf_nvme_mi_mi_nshds_nss_p1la;
static int hf_nvme_mi_mi_nshds_nss_snfm;
static int hf_nvme_mi_mi_nshds_nss_rsvd;
static int hf_nvme_mi_mi_nshds_sw;
static int hf_nvme_mi_mi_nshds_sw_rsvd;
static int hf_nvme_mi_mi_nshds_sw_ips;
static int hf_nvme_mi_mi_nshds_sw_pmre;
static int hf_nvme_mi_mi_nshds_sw_vmbf;
static int hf_nvme_mi_mi_nshds_sw_ro;
static int hf_nvme_mi_mi_nshds_sw_rd;
static int hf_nvme_mi_mi_nshds_sw_taut;
static int hf_nvme_mi_mi_nshds_sw_st;
static int hf_nvme_mi_mi_nshds_ctemp;
static int hf_nvme_mi_mi_nshds_pdlu;
static int hf_nvme_mi_mi_nshds_ccs;
static int hf_nvme_mi_mi_nshds_rsvd;

/* Shared health-status flag bits - same bit layout in the NVMe-MI 2.1
 * "Composite Controller Status Data Structure (CCSDS)" and "Controller
 * Health Status Changed Flags (CHSCF)" figures. */
static int hf_nvme_mi_mi_hsf_rsvd_15_14;
static int hf_nvme_mi_mi_hsf_tcida;
static int hf_nvme_mi_mi_hsf_cwarn;
static int hf_nvme_mi_mi_hsf_spare;
static int hf_nvme_mi_mi_hsf_pdlu;
static int hf_nvme_mi_mi_hsf_ctemp;
static int hf_nvme_mi_mi_hsf_csts;
static int hf_nvme_mi_mi_hsf_fa;
static int hf_nvme_mi_mi_hsf_nac;
static int hf_nvme_mi_mi_hsf_ceco;
static int hf_nvme_mi_mi_hsf_nssro;
static int hf_nvme_mi_mi_hsf_rsvd_3;
static int hf_nvme_mi_mi_hsf_shst;
static int hf_nvme_mi_mi_hsf_cfs;
static int hf_nvme_mi_mi_hsf_rdy;

/* Controller Health Data Structure (CHDS) */
static int hf_nvme_mi_mi_chds_ctlid;
static int hf_nvme_mi_mi_chds_csts;
static int hf_nvme_mi_mi_chds_csts_tcida;
static int hf_nvme_mi_mi_chds_csts_fa;
static int hf_nvme_mi_mi_chds_csts_nac;
static int hf_nvme_mi_mi_chds_csts_ceco;
static int hf_nvme_mi_mi_chds_csts_nssro;
static int hf_nvme_mi_mi_chds_csts_shst;
static int hf_nvme_mi_mi_chds_csts_cfs;
static int hf_nvme_mi_mi_chds_csts_rdy;
static int hf_nvme_mi_mi_chds_ctemp;
static int hf_nvme_mi_mi_chds_pdlu;
static int hf_nvme_mi_mi_chds_spare;
static int hf_nvme_mi_mi_chds_cwarn;
static int hf_nvme_mi_mi_chds_cwarn_rsvd;
static int hf_nvme_mi_mi_chds_cwarn_ips;
static int hf_nvme_mi_mi_chds_cwarn_pmre;
static int hf_nvme_mi_mi_chds_cwarn_vmbf;
static int hf_nvme_mi_mi_chds_cwarn_ro;
static int hf_nvme_mi_mi_chds_cwarn_rd;
static int hf_nvme_mi_mi_chds_cwarn_taut;
static int hf_nvme_mi_mi_chds_cwarn_st;
static int hf_nvme_mi_mi_chds_chsc;
static int hf_nvme_mi_mi_chds_csts_rsvd;
static int hf_nvme_mi_mi_chds_rsvd;

static int ett_nvme_mi_mi;
static int ett_nvme_mi_mi_field;
static int ett_nvme_mi_mi_entry;
static int ett_nvme_mi_aem;

static expert_field ei_nvme_mi_mi_truncated;
static expert_field ei_nvme_mi_mi_orphan_response;
static expert_field ei_nvme_mi_mi_reserved_dtyp;
static expert_field ei_nvme_mi_mi_reserved_configid;
static expert_field ei_nvme_mi_mi_reserved_value;
static expert_field ei_nvme_mi_mi_reserved_opcode;
static expert_field ei_nvme_mi_mi_ae_list_invalid;
static expert_field ei_nvme_mi_mi_ae_aeetl_mismatch;
static expert_field ei_nvme_mi_mi_pda_dlen_max;
static expert_field ei_nvme_mi_mi_aes_field_invalid;
static expert_field ei_nvme_mi_mi_cfg_aeelver;
static expert_field ei_nvme_mi_mi_error_surplus;
static expert_field ei_nvme_mi_mi_aeo_list_invalid;
static expert_field ei_nvme_mi_mi_vpd_checksum;
static expert_field ei_nvme_mi_mi_vpd_length;
#define NVME_MI_VPD_UNKNOWN_FORMAT \
    "VPD format not decoded; bytes shown raw"
static expert_field ei_nvme_mi_mi_request_data_length;
static expert_field ei_nvme_mi_mi_response_data_length;
static expert_field ei_nvme_mi_mi_chsp_maxrent;
static expert_field ei_nvme_mi_mi_unexpected_request_data;
static expert_field ei_nvme_mi_mi_aeo_field_invalid;
static expert_field ei_nvme_mi_mi_reset_response;
static int hf_nvme_mi_mi_meb_routed;
static int hf_nvme_mi_mi_data_routing;

enum nvme_mi_mi_data_routing {
    NVME_MI_MI_DATA_UNKNOWN,
    NVME_MI_MI_DATA_INLINE,
    NVME_MI_MI_DATA_MEB,
};

static const value_string mi_data_routing_vals[] = {
    { NVME_MI_MI_DATA_UNKNOWN, "Unknown" },
    { NVME_MI_MI_DATA_INLINE,  "Inline" },
    { NVME_MI_MI_DATA_MEB,     "Management Endpoint Buffer" },
    { 0, NULL }
};

/* MI command opcodes (NVMe-MI 2.2 Figure 68); 08h-0Bh and 0Dh-0Fh are
 * named only. */
enum nvme_mi_mi_opc {
    NVME_MI_MI_OPC_READ_DS    = 0x00,
    NVME_MI_MI_OPC_SUBSYS_HSP = 0x01,
    NVME_MI_MI_OPC_CTRL_HSP   = 0x02,
    NVME_MI_MI_OPC_CONFIG_SET = 0x03,
    NVME_MI_MI_OPC_CONFIG_GET = 0x04,
    NVME_MI_MI_OPC_VPD_READ   = 0x05,
    NVME_MI_MI_OPC_VPD_WRITE  = 0x06,
    /* 07h is NVME_MI_MI_OPC_RESET, defined in packet-nvme-mi.h because the
     * framing layer's command slot bookkeeping needs it too. */
    NVME_MI_MI_OPC_SES_RECV   = 0x08,
    NVME_MI_MI_OPC_SES_SEND   = 0x09,
    NVME_MI_MI_OPC_MEB_READ   = 0x0A,
    NVME_MI_MI_OPC_MEB_WRITE  = 0x0B,
    NVME_MI_MI_OPC_SHUTDOWN   = 0x0C,
    NVME_MI_MI_OPC_PDA_READ   = 0x0D,
    NVME_MI_MI_OPC_PDA_WRITE  = 0x0E,
    NVME_MI_MI_OPC_PDA_WRITE_ZEROES = 0x0F,
    NVME_MI_MI_OPC_RESERVED_FIRST = 0x10,
    NVME_MI_MI_OPC_RESERVED_LAST  = 0xBF,
};

static const range_string mi_opcode_vals[] = {
    { NVME_MI_MI_OPC_READ_DS,    NVME_MI_MI_OPC_READ_DS,    "Read NVMe-MI Data Structure" },
    { NVME_MI_MI_OPC_SUBSYS_HSP, NVME_MI_MI_OPC_SUBSYS_HSP, "NVM Subsystem Health Status Poll" },
    { NVME_MI_MI_OPC_CTRL_HSP,   NVME_MI_MI_OPC_CTRL_HSP,   "Controller Health Status Poll" },
    { NVME_MI_MI_OPC_CONFIG_SET, NVME_MI_MI_OPC_CONFIG_SET, "Configuration Set" },
    { NVME_MI_MI_OPC_CONFIG_GET, NVME_MI_MI_OPC_CONFIG_GET, "Configuration Get" },
    { NVME_MI_MI_OPC_VPD_READ,   NVME_MI_MI_OPC_VPD_READ,   "VPD Read" },
    { NVME_MI_MI_OPC_VPD_WRITE,  NVME_MI_MI_OPC_VPD_WRITE,  "VPD Write" },
    { NVME_MI_MI_OPC_RESET,      NVME_MI_MI_OPC_RESET,      "Reset" },
    { NVME_MI_MI_OPC_SES_RECV,   NVME_MI_MI_OPC_SES_RECV,   "SES Receive" },
    { NVME_MI_MI_OPC_SES_SEND,   NVME_MI_MI_OPC_SES_SEND,   "SES Send" },
    { NVME_MI_MI_OPC_MEB_READ,   NVME_MI_MI_OPC_MEB_READ,   "Management Endpoint Buffer Read" },
    { NVME_MI_MI_OPC_MEB_WRITE,  NVME_MI_MI_OPC_MEB_WRITE,  "Management Endpoint Buffer Write" },
    { NVME_MI_MI_OPC_SHUTDOWN,   NVME_MI_MI_OPC_SHUTDOWN,   "Shutdown" },
    { NVME_MI_MI_OPC_PDA_READ,   NVME_MI_MI_OPC_PDA_READ,   "NVMe-MI PDA Read" },
    { NVME_MI_MI_OPC_PDA_WRITE,  NVME_MI_MI_OPC_PDA_WRITE,  "NVMe-MI PDA Write" },
    { NVME_MI_MI_OPC_PDA_WRITE_ZEROES, NVME_MI_MI_OPC_PDA_WRITE_ZEROES, "NVMe-MI PDA Write Zeroes" },
    { NVME_MI_MI_OPC_RESERVED_FIRST, NVME_MI_MI_OPC_RESERVED_LAST, "Reserved" },
    { 0xC0, 0xFF,                                           "Vendor Specific" },
    { 0, 0, NULL },
};

/* Data Structure Types (Read NVMe-MI Data Structure NVMe Management
 * Dword 0); 06h-FFh are reserved. */
enum nvme_mi_dtyp {
    NVME_MI_DTYP_SUBSYS_INFO = 0x00,
    NVME_MI_DTYP_PORT_INFO   = 0x01,
    NVME_MI_DTYP_CTRL_LIST   = 0x02,
    NVME_MI_DTYP_CTRL_INFO   = 0x03,
    NVME_MI_DTYP_OSC_LIST    = 0x04,
    NVME_MI_DTYP_MEB_LIST    = 0x05,
    NVME_MI_DTYP_MAX         = NVME_MI_DTYP_MEB_LIST,
};

static const range_string mi_dtyp_vals[] = {
    { NVME_MI_DTYP_SUBSYS_INFO, NVME_MI_DTYP_SUBSYS_INFO, "NVM Subsystem Information" },
    { NVME_MI_DTYP_PORT_INFO, NVME_MI_DTYP_PORT_INFO, "Port Information" },
    { NVME_MI_DTYP_CTRL_LIST, NVME_MI_DTYP_CTRL_LIST, "Controller List" },
    { NVME_MI_DTYP_CTRL_INFO, NVME_MI_DTYP_CTRL_INFO, "Controller Information" },
    { NVME_MI_DTYP_OSC_LIST, NVME_MI_DTYP_OSC_LIST, "Optionally Supported Command List" },
    { NVME_MI_DTYP_MEB_LIST, NVME_MI_DTYP_MEB_LIST, "Management Endpoint Buffer Command Support List" },
    { 0x06, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* Configuration Identifiers; 00h and 05h-BFh are reserved,
 * C0h-FFh vendor specific. */
enum nvme_mi_cfgid {
    NVME_MI_CFGID_SMBUS_FREQ = 0x01,
    NVME_MI_CFGID_HSC        = 0x02,
    NVME_MI_CFGID_MTUS       = 0x03,
    NVME_MI_CFGID_AE         = 0x04,
    NVME_MI_CFGID_RESERVED_FIRST = 0x05,
    NVME_MI_CFGID_RESERVED_LAST  = 0xBF,
};

/* The two AE configuration variations (NVMe-MI 2.2 5.2.4), told apart by
 * NUMAEE; UNKNOWN when the AE Enable List is absent. */
enum nvme_mi_ae_variant {
    NVME_MI_AE_VARIANT_ACK     = 0,
    NVME_MI_AE_VARIANT_SYNC    = 1,
    NVME_MI_AE_VARIANT_UNKNOWN = 0xff,
};

static const range_string mi_configid_vals[] = {
    { 0x00, 0x00,                                                 "Reserved" },
    { NVME_MI_CFGID_SMBUS_FREQ, NVME_MI_CFGID_SMBUS_FREQ,         "SMBus/I2C Frequency" },
    { NVME_MI_CFGID_HSC,        NVME_MI_CFGID_HSC,                "Health Status Change" },
    { NVME_MI_CFGID_MTUS,       NVME_MI_CFGID_MTUS,               "MCTP Transmission Unit Size" },
    { NVME_MI_CFGID_AE,         NVME_MI_CFGID_AE,                 "Asynchronous Event" },
    { NVME_MI_CFGID_RESERVED_FIRST, NVME_MI_CFGID_RESERVED_LAST,  "Reserved" },
    { 0xC0, 0xFF,                                                 "Vendor Specific" },
    { 0, 0, NULL },
};

/* AE Enable ID - Asynchronous Events (NVMe-MI 2.2 Figure 63) */
static const range_string mi_ae_id_vals[] = {
    { 0x00, 0x00, "Controller Ready" },
    { 0x01, 0x01, "Controller Fatal Status" },
    { 0x02, 0x02, "Shutdown Status" },
    { 0x03, 0x03, "Controller Enable" },
    { 0x04, 0x04, "Namespace Attribute Changed" },
    { 0x05, 0x05, "Firmware Activated" },
    { 0x06, 0x06, "Composite Temperature" },
    { 0x07, 0x07, "Percentage Drive Life Used" },
    { 0x08, 0x08, "Available Spare" },
    { 0x09, 0x09, "SMART Warnings" },
    { 0x0a, 0x0a, "Telemetry Controller-Initiated Data Available" },
    { 0x0b, 0x0b, "PCIe Link Active" },
    { 0x0c, 0x0c, "Sanitize Failure Mode" },
    { 0x0d, 0x0d, "Sanitize Namespace Failure Mode" },
    { 0x0e, 0x0e, "Power Threshold Exceeded" },
    { 0x0f, 0x0f, "Voltage Threshold Event" },
    { 0x10, 0xbf, "Reserved" },
    { 0xC0, 0xFF, "Vendor Specific" },
    { 0, 0, NULL },
};

/* AE Occurrence Scope (NVMe-MI 2.2 Figure 62, AESS); selects which Figure 64
 * layout the AE Occurrence Scope ID Info field carries. */
enum nvme_mi_aeo_scope {
    NVME_MI_AEO_SCOPE_NAMESPACE = 0x0,
    NVME_MI_AEO_SCOPE_CONTROLLER = 0x1,
    NVME_MI_AEO_SCOPE_SUBSYSTEM = 0x2,
    NVME_MI_AEO_SCOPE_MGMT_EP = 0x3,
    NVME_MI_AEO_SCOPE_PORT = 0x4,
    NVME_MI_AEO_SCOPE_ENDURANCE_GRP = 0x5,
};

static const range_string mi_aeo_scope_vals[] = {
    { NVME_MI_AEO_SCOPE_NAMESPACE,      NVME_MI_AEO_SCOPE_NAMESPACE,      "Namespace" },
    { NVME_MI_AEO_SCOPE_CONTROLLER,     NVME_MI_AEO_SCOPE_CONTROLLER,     "Controller" },
    { NVME_MI_AEO_SCOPE_SUBSYSTEM,      NVME_MI_AEO_SCOPE_SUBSYSTEM,      "NVM Subsystem" },
    { NVME_MI_AEO_SCOPE_MGMT_EP,        NVME_MI_AEO_SCOPE_MGMT_EP,        "Management Endpoint" },
    { NVME_MI_AEO_SCOPE_PORT,           NVME_MI_AEO_SCOPE_PORT,           "Port" },
    { NVME_MI_AEO_SCOPE_ENDURANCE_GRP,  NVME_MI_AEO_SCOPE_ENDURANCE_GRP,  "Endurance Group" },
    { 0x6, 0xf, "Reserved" },
    { 0, 0, NULL },
};

/* NVMe-MI 2.2 Figure 65, Power Threshold Exceeded Info (AE 0Eh). */
static const range_string mi_aeosi_pmt_vals[] = {
    { 0x0, 0x0, "NVM Subsystem total power" },
    { 0x1, 0xb, "Reserved" },
    { 0xc, 0xf, "Vendor Specific" },
    { 0, 0, NULL },
};

static const value_string mi_aeosi_pwrs_vals[] = {
    { 0x0, "Reserved" },
    { 0x1, "0.0001 W" },
    { 0x2, "0.01 W" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

/* NVMe-MI 2.2 Figure 65, Voltage Threshold Event Info (AE 0Fh). */
static const value_string mi_aeosi_vsent_vals[] = {
    { 0x0, "Voltage Sensor 1 (VSEN1)" },
    { 0x1, "Voltage Sensor 2 (VSEN2)" },
    { 0x2, "Voltage Sensor 3 (VSEN3)" },
    { 0x3, "Voltage Sensor 4 (VSEN4)" },
    { 0, NULL },
};

static const value_string mi_aeosi_vtht_vals[] = {
    { 0x0, "Overvoltage Threshold" },
    { 0x1, "Undervoltage Threshold" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

/* PWRIV is in units of 0.05 V. */
static void
nvme_mi_pwriv_fmt(char *result, uint32_t val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u (%.2f V)", val, val * 5 / 100.0);
}

/* IPMI FRU 1.0r1.3 Table 16-2; 0Bh-0Dh per NVMe-MI 2.2 Figures 175-177. */
static const range_string mi_vpd_record_vals[] = {
    { 0x00, 0x00, "Power Supply Information" },
    { 0x01, 0x01, "DC Output" },
    { 0x02, 0x02, "DC Load" },
    { 0x03, 0x03, "Management Access" },
    { 0x04, 0x04, "Base Compatibility" },
    { 0x05, 0x05, "Extended Compatibility" },
    { 0x06, 0x06, "Reserved for ASF Fixed SMBus Device" },
    { 0x07, 0x07, "Reserved for ASF Legacy-Device Alerts" },
    { 0x08, 0x08, "Reserved for ASF Remote Control" },
    { 0x09, 0x09, "Extended DC Output" },
    { 0x0A, 0x0A, "Extended DC Load" },
    { 0x0B, 0x0B, "NVMe" },
    { 0x0C, 0x0C, "NVMe PCIe Port" },
    { 0x0D, 0x0D, "Topology" },
    { 0x0E, 0x0F, "Reserved (NVMe)" },
    { 0x10, 0xBF, "Reserved" },
    { 0xC0, 0xFF, "OEM" },
    { 0, 0, NULL }
};
/* Figure 180 */
static const range_string mi_vpd_element_vals[] = {
    { 0x00, 0x00, "Reserved" }, { 0x01, 0x01, "Extended" },
    { 0x02, 0x02, "Upstream Connector" }, { 0x03, 0x03, "Expansion Connector" },
    { 0x04, 0x04, "Label" }, { 0x05, 0x05, "2-Wire Mux" },
    { 0x06, 0x06, "PCIe Switch" }, { 0x07, 0x07, "NVM Subsystem" },
    { 0x08, 0x08, "FRU Information Device" }, { 0x09, 0xEF, "Reserved" },
    { 0xF0, 0xFF, "Vendor Specific" }, { 0, 0, NULL }
};

/* NVMe-MI 2.2 Figure 172, Boot Failure Code. */
static const value_string mi_vpd_bfc_vals[] = {
    { 0x0, "No boot failure has occurred" },
    { 0x1, "Unrecoverable Hardware Issue" },
    { 0x2, "Self-test Failure" },
    { 0x4, "Corrupted Critical Data" },
    { 0x6, "Corrupted Key Manifest" },
    { 0x8, "Corrupted Firmware Image" },
    { 0xa, "Corrupted Security Data" },
    { 0xc, "Corrupted Recovery Firmware" },
    { 0, NULL }
};

/* NVMe-MI 2.2 Figure 183, Form Factors ("Interface, Form Factor
 * Description"). */
static const range_string mi_vpd_ff_vals[] = {
    { 0x00, 0x00, "Unspecified, Other - unknown" },
    { 0x01, 0x01, "PCIe, Integrated" },
    { 0x02, 0x02, "PCIe, Other - unknown" },
    { 0x03, 0x0f, "Reserved" },
    { 0x10, 0x10, "PCIe, 2.5\" Form Factor - unknown" },
    { 0x11, 0x11, "PCIe, 2.5\" Form Factor - PCI Express SFF-8639 Module (U.2) 15 mm" },
    { 0x12, 0x12, "PCIe, 2.5\" Form Factor - PCI Express SFF-8639 Module (U.2) 7 mm" },
    { 0x13, 0x13, "PCIe, 2.5\" Form Factor - (SFF-TA-1001) 15 mm" },
    { 0x14, 0x14, "PCIe, 2.5\" Form Factor - (SFF-TA-1001) 7 mm" },
    { 0x15, 0x1f, "Reserved" },
    { 0x20, 0x20, "PCIe, CEM add in card - unknown" },
    { 0x21, 0x21, "PCIe, CEM add in card - Low Profile (HHHL)" },
    { 0x22, 0x22, "PCIe, CEM add in card - Standard Height Half Length (FHHL)" },
    { 0x23, 0x23, "PCIe, CEM add in card - Standard Height Full Length (FHFL)" },
    { 0x24, 0x2f, "Reserved" },
    { 0x30, 0x30, "PCIe, M.2 module - unknown" },
    { 0x31, 0x31, "PCIe, M.2 module - 2230" },
    { 0x32, 0x32, "PCIe, M.2 module - 2242" },
    { 0x33, 0x33, "PCIe, M.2 module - 2260" },
    { 0x34, 0x34, "PCIe, M.2 module - 2280" },
    { 0x35, 0x35, "PCIe, M.2 module - 22110" },
    { 0x36, 0x3f, "Reserved" },
    { 0x40, 0x40, "PCIe, BGA SSD - unknown" },
    { 0x41, 0x41, "PCIe, BGA SSD - 16 x 20mm (M.2 Type 1620)" },
    { 0x42, 0x42, "PCIe, BGA SSD - 11.5 x 13mm (M.2 Type 1113)" },
    { 0x43, 0x4f, "Reserved" },
    { 0x50, 0x50, "PCIe, Enterprise & Datacenter SSD Form Factor - unknown" },
    { 0x51, 0x51, "PCIe, E1.S - (SFF-TA-1006) 5.9 mm" },
    { 0x52, 0x52, "PCIe, E1.S - (SFF-TA-1006) 8 mm" },
    { 0x53, 0x53, "PCIe, E1.L - (SFF-TA-1007) 9.5 mm" },
    { 0x54, 0x54, "PCIe, E1.L - (SFF-TA-1007) 18 mm" },
    { 0x55, 0x55, "PCIe, E3.S - (SFF-TA-1008) 7.5 mm" },
    { 0x56, 0x56, "PCIe, E3.S - (SFF-TA-1008) 16.8 mm" },
    { 0x57, 0x57, "PCIe, E3.L - (SFF-TA-1008) 7.5 mm" },
    { 0x58, 0x58, "PCIe, E3.L - (SFF-TA-1008) 16.8 mm" },
    { 0x59, 0x59, "PCIe, E1.S - (SFF-TA-1006) 9.5 mm" },
    { 0x5a, 0x5a, "PCIe, E1.S - (SFF-TA-1006) 15 mm" },
    { 0x5b, 0x5b, "PCIe, E1.S - (SFF-TA-1006) 25 mm" },
    { 0x5c, 0x5c, "PCIe, E2 - (SFF-TA-1042) 9.5 mm" },
    { 0x5d, 0x5f, "Reserved" },
    { 0x60, 0x60, "Ethernet, Other - unknown" },
    { 0x61, 0x61, "Ethernet, 2.5\" Form Factor - (Native NVMe-oF Drive) 15 mm" },
    { 0x62, 0x62, "Ethernet, 2.5\" Form Factor - (Native NVMe-oF Drive) 7 mm" },
    { 0x63, 0x63, "Ethernet, E3.S - (Native NVMe-oF Drive) 7.5 mm" },
    { 0x64, 0x64, "Ethernet, E3.S - (Native NVMe-oF Drive) 16.8 mm" },
    { 0x65, 0xef, "Reserved" },
    { 0xf0, 0xff, "Vendor Specific" },
    { 0, 0, NULL }
};

/* NVMe-MI 2.2 Figures 189/194/196, 2-Wire Capabilities MSPD. */
static const value_string mi_vpd_mspd_vals[] = {
    { 0, "100 kHz" }, { 1, "400 kHz" }, { 2, "1 MHz" }, { 3, "Reserved" }, { 0, NULL }
};

/* NVMe-MI 2.2 Figure 194, M2WAS. */
static const value_string mi_vpd_m2was_vals[] = {
    { 0, "Support for this capability is not indicated" },
    { 1, "The 2-Wire port does not support MCTP during the Auxiliary Only power state" },
    { 2, "The 2-Wire port supports MCTP during the Auxiliary Only power state" },
    { 3, "Reserved" },
    { 0, NULL }
};

/* NVMe-MI 2.2 Figure 173 TCODE ("11b - Always corresponds to ASCII in this
 * specification"); IPMI FRU 1.0 section 13 names the other codes. */
static const value_string mi_vpd_tcode_vals[] = {
    { 0, "Binary or unspecified" },
    { 1, "BCD plus" },
    { 2, "6-bit ASCII, packed" },
    { 3, "8-bit ASCII + Latin 1" },
    { 0, NULL }
};

/* Figure 64 Port variant: AEOPT selects which port namespace AEOPID names. */
static const true_false_string tfs_aeo_port_type = {
    "NVMe-MI port", "NVM Subsystem port"
};

/* Fixed header lengths the spec mandates (Figures 61/62). */
#define NVME_MI_AEO_LIST_HDR_LEN  7
#define NVME_MI_AEO_ENTRY_HDR_LEN 9

/* NVMe-MI 2.2 Figures 86 and 77 assign different meanings to SFREQ zero. */
static const range_string mi_sfreq_vals[] = {
    { 0x0, 0x0, "Reserved" },
    { 0x1, 0x1, "100 kHz" },
    { 0x2, 0x2, "400 kHz" },
    { 0x3, 0x3, "1 MHz" },
    { 0x4, 0xf, "Reserved" },
    { 0, 0, NULL },
};

static const range_string mi_sfreq_cur_vals[] = {
    { 0x0, 0x0, "Obsolete" },
    { 0x1, 0x1, "100 kHz" },
    { 0x2, 0x2, "400 kHz" },
    { 0x3, 0x3, "1 MHz" },
    { 0x4, 0xf, "Reserved" },
    { 0, 0, NULL },
};

/* Maximum VPD access / maximum SMBus frequency (2-Wire Port Specific
 * Data) */
static const range_string mi_vpdfreq_vals[] = {
    { 0x0, 0x0, "Not supported" },
    { 0x1, 0x1, "100 kHz" },
    { 0x2, 0x2, "400 kHz" },
    { 0x3, 0x3, "1 MHz" },
    { 0x4, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* NVMe-MI 2.2 Figure 117. */
static const range_string mi_prttyp_vals[] = {
    { 0x0, 0x0, "Inactive" },
    { 0x1, 0x1, "PCIe" },
    { 0x2, 0x2, "2-Wire" },
    { 0x3, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* NVMe-MI 2.2 Figure 118. */
static const range_string mi_pciemps_vals[] = {
    { 0x0, 0x0, "128 bytes" },
    { 0x1, 0x1, "256 bytes" },
    { 0x2, 0x2, "512 bytes" },
    { 0x3, 0x3, "1 KiB" },
    { 0x4, 0x4, "2 KiB" },
    { 0x5, 0x5, "4 KiB" },
    { 0x6, 0xff, "Reserved" },
    { 0, 0, NULL },
};

static const range_string mi_pciecls_vals[] = {
    { 0x0, 0x0, "Link not active" },
    { 0x1, 0x1, "2.5 GT/s" },
    { 0x2, 0x2, "5.0 GT/s" },
    { 0x3, 0x3, "8.0 GT/s" },
    { 0x4, 0x4, "16.0 GT/s" },
    { 0x5, 0x5, "32.0 GT/s" },
    { 0x6, 0x6, "64.0 GT/s" },
    { 0x7, 0xff, "Reserved" },
    { 0, 0, NULL },
};

static const range_string mi_pciemlw_vals[] = {
    { 0, 0, "Reserved" },
    { 1, 1, "PCIe x1" },
    { 2, 2, "PCIe x2" },
    { 3, 3, "Reserved" },
    { 4, 4, "PCIe x4" },
    { 5, 7, "Reserved" },
    { 8, 8, "PCIe x8" },
    { 9, 11, "Reserved" },
    { 12, 12, "PCIe x12" },
    { 13, 15, "Reserved" },
    { 16, 16, "PCIe x16" },
    { 17, 31, "Reserved" },
    { 32, 32, "PCIe x32" },
    { 33, 255, "Reserved" },
    { 0, 0, NULL },
};

static const range_string mi_pcienlw_vals[] = {
    { 0, 0, "Link not active" },
    { 1, 1, "PCIe x1" },
    { 2, 2, "PCIe x2" },
    { 3, 3, "Reserved" },
    { 4, 4, "PCIe x4" },
    { 5, 7, "Reserved" },
    { 8, 8, "PCIe x8" },
    { 9, 11, "Reserved" },
    { 12, 12, "PCIe x12" },
    { 13, 15, "Reserved" },
    { 16, 16, "PCIe x16" },
    { 17, 31, "Reserved" },
    { 32, 32, "PCIe x32" },
    { 33, 255, "Reserved" },
    { 0, 0, NULL },
};

/* Reset Type; 01h-FFh reserved */
#define NVME_MI_RSTTYP_MAX 0x00     /* highest valid Reset Type */
static const range_string mi_rsttyp_vals[] = {
    { 0x00, 0x00, "Reset NVM Subsystem" },
    { 0x01, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* Shutdown Type; 02h-FFh reserved */
#define NVME_MI_SHDNTYP_MAX 0x01    /* highest valid Shutdown Type */
static const range_string mi_shdntyp_vals[] = {
    { 0x00, 0x00, "Normal NVM Subsystem Shutdown" },
    { 0x01, 0x01, "Abrupt NVM Subsystem Shutdown" },
    { 0x02, 0xff, "Reserved" },
    { 0, 0, NULL },
};

/* The request parameters that select the response layout; kept in
 * nvme_mi_transaction.body_ctx. */
struct nvme_mi_mi_req_ctx {
    uint8_t dtyp;       /* Read NVMe-MI Data Structure (00h) */
    uint8_t iocsi;
    uint8_t configid;   /* Configuration Set/Get (03h/04h) */
    /* CONFIGID 04h Configuration Set only: the 5.2.4 variation. */
    uint8_t ae_variant;
    uint8_t port;
    uint16_t dlen;      /* VPD/MEB DLEN or SES ALENGTH; not the FRU size. */
    uint32_t dofst;     /* VPD (16-bit) or MEB (32-bit) DOFST. */
    /* PDA Read/Write: DLEN in bytes, when DFORMAT names a unit and the
     * product fits. */
    bool pda_bytes_known;
    uint32_t pda_bytes;
};

static int * const rds_cdw0_fields[] = {
    &hf_nvme_mi_mi_rds_dtyp,
    &hf_nvme_mi_mi_rds_portid,
    &hf_nvme_mi_mi_rds_ctrlid,
    NULL,
};
static int * const rds_cdw1_fields[] = {
    &hf_nvme_mi_mi_rds_iocsi,
    NULL,
};
static int * const nshsp_cdw1_fields[] = {
    &hf_nvme_mi_mi_nshsp_cs,
    NULL,
};
static int * const chsp_cdw0_fields[] = {
    &hf_nvme_mi_mi_chsp_all,
    &hf_nvme_mi_mi_chsp_incvf,
    &hf_nvme_mi_mi_chsp_incpf,
    &hf_nvme_mi_mi_chsp_incf,
    &hf_nvme_mi_mi_chsp_maxrent,
    &hf_nvme_mi_mi_chsp_sctlid,
    NULL,
};
static int * const chsp_cdw1_fields[] = {
    &hf_nvme_mi_mi_chsp_ccf,
    &hf_nvme_mi_mi_chsp_cwarn,
    &hf_nvme_mi_mi_chsp_spare,
    &hf_nvme_mi_mi_chsp_pdlu,
    &hf_nvme_mi_mi_chsp_ctemp,
    &hf_nvme_mi_mi_chsp_csts,
    NULL,
};
static int * const cfg_cdw0_fields_cid[] = {
    &hf_nvme_mi_mi_cfg_cid,
    NULL,
};
static int * const cfg_cdw0_fields_port[] = {
    &hf_nvme_mi_mi_cfg_portid,
    &hf_nvme_mi_mi_cfg_cid,
    NULL,
};
static int * const cfg_cdw0_fields_sfreq[] = {
    &hf_nvme_mi_mi_cfg_portid,
    &hf_nvme_mi_mi_cfg_sfreq,
    &hf_nvme_mi_mi_cfg_cid,
    NULL,
};
static int * const cfg_cdw1_fields_hsc[] = {
    &hf_nvme_mi_mi_cfg_hsc_tcida,
    &hf_nvme_mi_mi_cfg_hsc_cwarn,
    &hf_nvme_mi_mi_cfg_hsc_spare,
    &hf_nvme_mi_mi_cfg_hsc_pdlu,
    &hf_nvme_mi_mi_cfg_hsc_ctemp,
    &hf_nvme_mi_mi_cfg_hsc_cschng,
    &hf_nvme_mi_mi_cfg_hsc_fa,
    &hf_nvme_mi_mi_cfg_hsc_nac,
    &hf_nvme_mi_mi_cfg_hsc_ceco,
    &hf_nvme_mi_mi_cfg_hsc_nssro,
    &hf_nvme_mi_mi_cfg_hsc_shst,
    &hf_nvme_mi_mi_cfg_hsc_cfs,
    &hf_nvme_mi_mi_cfg_hsc_rdy,
    NULL,
};
static int * const cfg_cdw1_fields_mtus[] = {
    &hf_nvme_mi_mi_cfg_mtus,
    NULL,
};
/* Configuration Set of the Asynchronous Event configuration; the
 * Configuration Get form has these bits reserved. */
static int * const cfg_cdw0_fields_ae_set[] = {
    &hf_nvme_mi_mi_cfg_ae_envfa,
    &hf_nvme_mi_mi_cfg_ae_enpfa,
    &hf_nvme_mi_mi_cfg_ae_encfa,
    &hf_nvme_mi_mi_cfg_ae_aemd,
    &hf_nvme_mi_mi_cfg_ae_aerd,
    &hf_nvme_mi_mi_cfg_cid,
    NULL,
};
static int * const vpd_cdw0_fields[] = {
    &hf_nvme_mi_mi_vpd_dofst,
    NULL,
};
static int * const vpd_cdw1_fields[] = {
    &hf_nvme_mi_mi_vpd_dlen,
    NULL,
};
static int * const meb_cdw0_fields[] = {
    &hf_nvme_mi_mi_meb_dofst,
    NULL,
};
static int * const meb_cdw1_fields[] = {
    &hf_nvme_mi_mi_meb_dlen,
    NULL,
};
static int * const pda_cdw0_fields[] = {
    &hf_nvme_mi_mi_pda_dofst,
    NULL,
};
static int * const pda_cdw1_fields[] = {
    &hf_nvme_mi_mi_pda_dlen,
    NULL,
};

/* MI 2.2 Figure 107: DFORMAT. */
#define NVME_MI_PDA_DFORMAT_4KIB  0x1
#define NVME_MI_PDA_DFORMAT_512B  0x2
#define NVME_MI_PDA_DFORMAT_BYTE  0x3
static const range_string mi_pda_dformat_vals[] = {
    { 0x00, 0x00, "Reserved" },
    { NVME_MI_PDA_DFORMAT_4KIB, NVME_MI_PDA_DFORMAT_4KIB, "4KiB" },
    { NVME_MI_PDA_DFORMAT_512B, NVME_MI_PDA_DFORMAT_512B, "512B" },
    { NVME_MI_PDA_DFORMAT_BYTE, NVME_MI_PDA_DFORMAT_BYTE, "Byte Level" },
    { 0x04, 0xFF, "Reserved" },
    { 0, 0, NULL },
};

/* Bytes per DFORMAT unit, or 0 for a Reserved DFORMAT. */
static unsigned
nvme_mi_pda_unit(uint8_t dformat)
{
    switch (dformat) {
    case NVME_MI_PDA_DFORMAT_4KIB: return 4096;
    case NVME_MI_PDA_DFORMAT_512B: return 512;
    case NVME_MI_PDA_DFORMAT_BYTE: return 1;
    default:                       return 0;
    }
}

/* Conservative DLEN ceiling from MI 2.2 Figures 109 (Read) and 111 (Write).
 * The 512B row's "512B" maximum may mean units or bytes; 512 is the smaller
 * bound under either reading.  Read Byte Level states no maximum. */
static bool
nvme_mi_pda_dlen_max(uint8_t opcode, uint8_t dformat, uint32_t *max)
{
    switch (dformat) {
    case NVME_MI_PDA_DFORMAT_4KIB:
        *max = 4096;
        return true;
    case NVME_MI_PDA_DFORMAT_512B:
        *max = 512;
        return true;
    case NVME_MI_PDA_DFORMAT_BYTE:
        *max = 4096;
        return opcode == NVME_MI_MI_OPC_PDA_WRITE;
    default:
        return false;
    }
}

static int * const ses_recv_cdw0_fields[] = {
    &hf_nvme_mi_mi_ses_pcode,
    NULL,
};
static int * const ses_recv_cdw1_fields[] = {
    &hf_nvme_mi_mi_ses_alength,
    NULL,
};
static int * const ses_send_cdw1_fields[] = {
    &hf_nvme_mi_mi_ses_dlen,
    NULL,
};
static int * const reset_cdw0_fields[] = {
    &hf_nvme_mi_mi_reset_rsttyp,
    NULL,
};
static int * const shutdown_cdw0_fields[] = {
    &hf_nvme_mi_mi_shutdown_shdntyp,
    NULL,
};
static int * const subsys_nnsc_fields[] = {
    &hf_nvme_mi_mi_subsys_nnsc_rsvd,
    &hf_nvme_mi_mi_subsys_sre,
    NULL,
};
static int * const port_prtcap_fields[] = {
    &hf_nvme_mi_mi_port_prtcap_rsvd,
    &hf_nvme_mi_mi_port_aems,
    &hf_nvme_mi_mi_port_ciaps,
    NULL,
};
/* Figure 118 byte 09: one bit per supported link speed. */
static int * const port_pcie_slsv_fields[] = {
    &hf_nvme_mi_mi_port_pcie_slsv_rsvd,
    &hf_nvme_mi_mi_port_pcie_slsv_g64,
    &hf_nvme_mi_mi_port_pcie_slsv_g32,
    &hf_nvme_mi_mi_port_pcie_slsv_g16,
    &hf_nvme_mi_mi_port_pcie_slsv_g8,
    &hf_nvme_mi_mi_port_pcie_slsv_g5,
    &hf_nvme_mi_mi_port_pcie_slsv_g2p5,
    NULL,
};
static int * const port_twprt_fields[] = {
    &hf_nvme_mi_mi_port_twire_i3csprt,
    &hf_nvme_mi_mi_port_twire_twprt_rsvd,
    &hf_nvme_mi_mi_port_twire_msmbfreq,
    NULL,
};
static int * const port_nvmebm_fields[] = {
    &hf_nvme_mi_mi_port_twire_nvmebm_rsvd,
    &hf_nvme_mi_mi_port_twire_nvmebms,
    NULL,
};
/* MI 2.2 Figure 119 byte 17 */
static int * const port_sdformat_fields[] = {
    &hf_nvme_mi_mi_port_twire_sdformat_rsvd,
    &hf_nvme_mi_mi_port_twire_sdformat_4k,
    &hf_nvme_mi_mi_port_twire_sdformat_512,
    &hf_nvme_mi_mi_port_twire_sdformat_byte,
    NULL,
};
static int * const ctrlinfo_prii_fields[] = {
    &hf_nvme_mi_mi_ctrlinfo_prii_rsvd,
    &hf_nvme_mi_mi_ctrlinfo_riv,
    NULL,
};
static int * const ctrlinfo_pri_fields[] = {
    &hf_nvme_mi_mi_ctrlinfo_pri_bus,
    &hf_nvme_mi_mi_ctrlinfo_pri_dev,
    &hf_nvme_mi_mi_ctrlinfo_pri_fn,
    NULL,
};
/* The ARI reading (NVMe-MI 2.2 Figure 120 note): Bus Number and an 8-bit
 * Function Number replace the Device and Function Numbers. */
static int * const ctrlinfo_pri_ari_fields[] = {
    &hf_nvme_mi_mi_ctrlinfo_pri_bus,
    &hf_nvme_mi_mi_ctrlinfo_pri_arifn,
    NULL,
};
static int * const cmdlist_ctyp_fields[] = {
    &hf_nvme_mi_mi_cmdlist_nmimt,
    &hf_nvme_mi_mi_cmdlist_rsvd_high,
    &hf_nvme_mi_mi_cmdlist_rsvd_low,
    NULL,
};
static int * const nshds_nss_fields[] = {
    &hf_nvme_mi_mi_nshds_nss_atf,
    &hf_nvme_mi_mi_nshds_nss_sfm,
    &hf_nvme_mi_mi_nshds_nss_df,
    &hf_nvme_mi_mi_nshds_nss_rnr,
    &hf_nvme_mi_mi_nshds_nss_p0la,
    &hf_nvme_mi_mi_nshds_nss_p1la,
    &hf_nvme_mi_mi_nshds_nss_snfm,
    &hf_nvme_mi_mi_nshds_nss_rsvd,
    NULL,
};
/* NSHDS SMART Warnings: CHDS CWARN bit positions, inverted sense (1 =
 * Normal; NVMe-MI 2.2 Figure 105). */
static const true_false_string tfs_nshds_sw = { "Normal", "Warning" };
static int * const nshds_sw_fields[] = {
    &hf_nvme_mi_mi_nshds_sw_rsvd,
    &hf_nvme_mi_mi_nshds_sw_ips,
    &hf_nvme_mi_mi_nshds_sw_pmre,
    &hf_nvme_mi_mi_nshds_sw_vmbf,
    &hf_nvme_mi_mi_nshds_sw_ro,
    &hf_nvme_mi_mi_nshds_sw_rd,
    &hf_nvme_mi_mi_nshds_sw_taut,
    &hf_nvme_mi_mi_nshds_sw_st,
    NULL,
};
static int * const hsf_fields[] = {
    &hf_nvme_mi_mi_hsf_rsvd_15_14,
    &hf_nvme_mi_mi_hsf_tcida,
    &hf_nvme_mi_mi_hsf_cwarn,
    &hf_nvme_mi_mi_hsf_spare,
    &hf_nvme_mi_mi_hsf_pdlu,
    &hf_nvme_mi_mi_hsf_ctemp,
    &hf_nvme_mi_mi_hsf_csts,
    &hf_nvme_mi_mi_hsf_fa,
    &hf_nvme_mi_mi_hsf_nac,
    &hf_nvme_mi_mi_hsf_ceco,
    &hf_nvme_mi_mi_hsf_nssro,
    &hf_nvme_mi_mi_hsf_rsvd_3,
    &hf_nvme_mi_mi_hsf_shst,
    &hf_nvme_mi_mi_hsf_cfs,
    &hf_nvme_mi_mi_hsf_rdy,
    NULL,
};
static int * const chds_csts_fields[] = {
    &hf_nvme_mi_mi_chds_csts_rsvd,
    &hf_nvme_mi_mi_chds_csts_tcida,
    &hf_nvme_mi_mi_chds_csts_fa,
    &hf_nvme_mi_mi_chds_csts_nac,
    &hf_nvme_mi_mi_chds_csts_ceco,
    &hf_nvme_mi_mi_chds_csts_nssro,
    &hf_nvme_mi_mi_chds_csts_shst,
    &hf_nvme_mi_mi_chds_csts_cfs,
    &hf_nvme_mi_mi_chds_csts_rdy,
    NULL,
};
static int * const chds_cwarn_fields[] = {
    &hf_nvme_mi_mi_chds_cwarn_rsvd,
    &hf_nvme_mi_mi_chds_cwarn_ips,
    &hf_nvme_mi_mi_chds_cwarn_pmre,
    &hf_nvme_mi_mi_chds_cwarn_vmbf,
    &hf_nvme_mi_mi_chds_cwarn_ro,
    &hf_nvme_mi_mi_chds_cwarn_rd,
    &hf_nvme_mi_mi_chds_cwarn_taut,
    &hf_nvme_mi_mi_chds_cwarn_st,
    NULL,
};

/*
 * NSHDS CTEMP encoding: 00h-7Eh = 0-126 deg C, 7Fh = 127 deg C or
 * higher, 80h/81h = sentinel codes, C4h = -60 deg C or lower, C5h-FFh =
 * -59 to -1 deg C in two's complement, the rest reserved.
 */
static void
nvme_mi_mi_fmt_nshds_ctemp(char *buf, uint32_t value)
{
    if (value <= 0x7e)
        snprintf(buf, ITEM_LABEL_LENGTH, "%u " UTF8_DEGREE_SIGN "C", value);
    else if (value == 0x7f)
        snprintf(buf, ITEM_LABEL_LENGTH, "127 " UTF8_DEGREE_SIGN "C or higher");
    else if (value == 0x80)
        snprintf(buf, ITEM_LABEL_LENGTH, "Temperature data is more than 5 s old");
    else if (value == 0x81)
        snprintf(buf, ITEM_LABEL_LENGTH, "Temperature sensor failure");
    else if (value <= 0xc3)
        snprintf(buf, ITEM_LABEL_LENGTH, "Reserved (0x%02x)", value);
    else if (value == 0xc4)
        snprintf(buf, ITEM_LABEL_LENGTH, "-60 " UTF8_DEGREE_SIGN "C or lower");
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "%d " UTF8_DEGREE_SIGN "C",
                 (int)value - 256);
}

/* Figure 97 CTEMP: Kelvins, as in the SMART / Health log. */
static void
nvme_mi_mi_fmt_kelvin(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u K (%d " UTF8_DEGREE_SIGN "C)",
             value, (int)value - 273);
}

/* Figure 196 MFIDS: "The maximum size of the FRU Information Device is 2^N
 * bytes where N is the value in this field". */
static void
nvme_mi_mi_fmt_mfids(char *buf, uint32_t value)
{
    if (value < 32)
        snprintf(buf, ITEM_LABEL_LENGTH, "%u (%u bytes)", value, 1U << value);
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "%u", value);
}

/* Flag truncated response data and render the leftover bytes raw. */
static void
nvme_mi_mi_data_truncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          proto_item *it, int off)
{
    nvme_mi_dissect_truncated(tvb, pinfo, tree, it, &ei_nvme_mi_mi_truncated,
                              hf_nvme_mi_mi_data, off);
}

/* Reconcile this response's extent (RDL, RENT; Figures 114/96). */
static int
nvme_mi_mi_response_extent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            proto_item *it, int off, int len, unsigned declared,
                            int fixed, const char *declaration, bool reconcile)
{
    int selected = (int)declared;
    bool mismatch = len != selected || (fixed >= 0 && selected != fixed);

    if (reconcile && mismatch) {
        if (fixed >= 0)
            expert_add_info_format(pinfo, it, &ei_nvme_mi_mi_response_data_length,
                "Response Data has %d bytes; %s declares %u bytes;"
                " the fixed data structure requires exactly %d bytes",
                len, declaration, declared, fixed);
        else
            expert_add_info_format(pinfo, it, &ei_nvme_mi_mi_response_data_length,
                "Response Data has %d bytes but %s declares %u bytes",
                len, declaration, declared);
    }
    if (fixed >= 0)
        selected = MIN(selected, fixed);
    int bounded = MIN(len, selected);
    if (bounded < len)
        proto_tree_add_item(tree, hf_nvme_mi_mi_response_surplus, tvb,
                            off + bounded, len - bounded, ENC_NA);
    return bounded;
}

static void
nvme_mi_mi_data_raw(tvbuff_t *tvb, proto_tree *tree, int off, int len)
{
    if (len > 0)
        proto_tree_add_item(tree, hf_nvme_mi_mi_data, tvb, off, len, ENC_NA);
}

static void
nvme_mi_mi_data_ds_reserved(tvbuff_t *tvb, proto_tree *tree, int off, int len)
{
    if (len > 0)
        proto_tree_add_item(tree, hf_nvme_mi_mi_ds_rsvd, tvb, off, len, ENC_NA);
}

/* NVMe-MI 2.2 Figures 176/195 PCIELS (7:6 Reserved), MCTPS (7:1 Reserved)
 * and RCCAP (7:4 Reserved); the Reserved runs get no item. */
static int * const vpd_pciels_fields[] = {
    &hf_nvme_mi_mi_vpd_pciels_gts64, &hf_nvme_mi_mi_vpd_pciels_gts32,
    &hf_nvme_mi_mi_vpd_pciels_gts16, &hf_nvme_mi_mi_vpd_pciels_gts8,
    &hf_nvme_mi_mi_vpd_pciels_gts5, &hf_nvme_mi_mi_vpd_pciels_gts2p5, NULL
};
static int * const vpd_pinfo_fields[] = {
    &hf_nvme_mi_mi_vpd_pinfo_rsvd, &hf_nvme_mi_mi_vpd_cppc, NULL
};
static int * const vpd_mctps_fields[] = { &hf_nvme_mi_mi_vpd_mctps_mctppcievs, NULL };
static int * const vpd_rccap_fields[] = {
    &hf_nvme_mi_mi_vpd_rccap_rcs, &hf_nvme_mi_mi_vpd_rccap_srcss,
    &hf_nvme_mi_mi_vpd_rccap_srcnss, &hf_nvme_mi_mi_vpd_rccap_crcs, NULL
};
/* 2-Wire Address Info: TWADDRI (Figures 189, 196), SADDRI (Figure 194). */
static int * const vpd_twaddri_fields[] = {
    &hf_nvme_mi_mi_vpd_twaddr, &hf_nvme_mi_mi_vpd_arpc, NULL
};
/* 2-Wire Capabilities differ per Element Descriptor: Figure 189 (2-Wire Mux,
 * 5:2 Reserved), Figure 194 (NVM Subsystem, 3:2 Reserved). */
static int * const vpd_twcap_mux_fields[] = {
    &hf_nvme_mi_mi_vpd_twcap_ffr, &hf_nvme_mi_mi_vpd_twcap_pecs,
    &hf_nvme_mi_mi_vpd_twcap_mspd, NULL
};
static int * const vpd_twcap_nvms_fields[] = {
    &hf_nvme_mi_mi_vpd_twcap_rst, &hf_nvme_mi_mi_vpd_twcap_m2was,
    &hf_nvme_mi_mi_vpd_twcap_i3cs, &hf_nvme_mi_mi_vpd_twcap_mspd, NULL
};
/* Figure 196 (FRU Information Device, 4:2 Reserved). */
static int * const vpd_twcap_fru_fields[] = {
    &hf_nvme_mi_mi_vpd_twcap_rst, &hf_nvme_mi_mi_vpd_twcap_i2cwa,
    &hf_nvme_mi_mi_vpd_twcap_bfcs, &hf_nvme_mi_mi_vpd_twcap_mspd, NULL
};
/* Figure 173, Type/Length. */
static int * const vpd_tl_fields[] = {
    &hf_nvme_mi_mi_vpd_pia_tcode, &hf_nvme_mi_mi_vpd_pia_ndb, NULL
};
/* Figure 174's Type/Length fields in order; from the eighth on, each is a
 * Custom Product Info Area field. */
static int * const vpd_pia_fields[] = {
    &hf_nvme_mi_mi_vpd_pia_mname, &hf_nvme_mi_mi_vpd_pia_pname,
    &hf_nvme_mi_mi_vpd_pia_ppmn, &hf_nvme_mi_mi_vpd_pia_pver,
    &hf_nvme_mi_mi_vpd_pia_psn, &hf_nvme_mi_mi_vpd_pia_at,
    &hf_nvme_mi_mi_vpd_pia_ffi, &hf_nvme_mi_mi_vpd_pia_cpia
};
static const char * const vpd_pia_names[] = {
    "Manufacturer Name", "Product Name", "Product Part/Model Number",
    "Product Version", "Product Serial Number", "Asset Tag", "FRU File ID",
    "Custom Product Info Area"
};

static void
nvme_mi_vpd_raw(tvbuff_t *tvb, proto_tree *tree, unsigned pos, unsigned end)
{
    if (pos < end)
        proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_raw, tvb, pos, end - pos, ENC_NA);
}

static void
nvme_mi_vpd_checksum(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,
    unsigned pos, unsigned len, uint8_t sum)
{
    for (unsigned i = 0; i < len; i++)
        sum += tvb_get_uint8(tvb, pos + i);
    if (sum)
        expert_add_info(pinfo, ti, &ei_nvme_mi_mi_vpd_checksum);
}

/* Product Info Area (NVMe-MI 2.2 section 8.2.2, Figure 174), rendered up
 * to 'limit'; PICHK is checked only for a whole area. */
static unsigned
nvme_mi_vpd_product_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    unsigned start, unsigned limit)
{
    /* PALEN is in multiples of 8 bytes and PICHK is the area's last byte.
     * Without a PALEN (not captured, or 0h) the area has no known end. */
    unsigned palen = limit - start > 1 ? tvb_get_uint8(tvb, start + 1) : 0;
    unsigned area_end = palen ? start + palen * 8 : limit;
    unsigned stop = MIN(area_end, limit);
    unsigned fields_end = (palen && area_end <= limit) ? area_end - 1 : stop;
    unsigned pos = start + 3;
    proto_item *ti = proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_pia, tvb, start,
                                         stop - start, ENC_NA);
    proto_tree *pia = proto_item_add_subtree(ti, ett_nvme_mi_mi_entry);

    uint32_t ipmiver;
    proto_tree_add_item_ret_uint(pia, hf_nvme_mi_mi_vpd_pia_ipmiver, tvb, start, 1,
                                 ENC_LITTLE_ENDIAN, &ipmiver);
    /* Figure 174 IPMIVER 01h; IPMI FRU section 4: "If the area format
     * version is correct, the application can proceed an access the data." */
    if (ipmiver != 1) {
        nvme_mi_vpd_raw(tvb, pia, start + 1, stop);
        return stop;
    }
    if (start + 1 < stop)
        proto_tree_add_item(pia, hf_nvme_mi_mi_vpd_pia_palen, tvb, start + 1, 1, ENC_LITTLE_ENDIAN);
    if (start + 2 < stop)
        proto_tree_add_item(pia, hf_nvme_mi_mi_vpd_pia_lcode, tvb, start + 2, 1, ENC_LITTLE_ENDIAN);
    /* IPMI FRU section 4: walk the fields "until the 'end-of-fields'
     * type/length byte (value C1h) is encountered". */
    for (unsigned i = 0; pos < fields_end; i++) {
        unsigned tl = tvb_get_uint8(tvb, pos), ndb = tl & 0x3f, n;
        proto_item *tl_item;

        if (tl == 0xc1) {
            proto_tree_add_item(pia, hf_nvme_mi_mi_vpd_pia_eor, tvb, pos++, 1, ENC_LITTLE_ENDIAN);
            break;
        }
        tl_item = proto_tree_add_bitmask(pia, tvb, pos, hf_nvme_mi_mi_vpd_pia_tl,
                                         ett_nvme_mi_mi_field, vpd_tl_fields, ENC_NA);
        proto_item_prepend_text(tl_item, "%s ", vpd_pia_names[MIN(i, 7)]);
        pos++;
        n = MIN(ndb, fields_end - pos);
        /* Figure 173: TCODE "11b - Always corresponds to ASCII in this
         * specification"; the other codes stay raw. */
        if ((tl >> 6) == 3)
            proto_tree_add_item(pia, *vpd_pia_fields[MIN(i, 7)], tvb, pos, n, ENC_ISO_8859_1);
        else
            nvme_mi_vpd_raw(tvb, pia, pos, pos + n);
        pos += n;
        if (n < ndb)
            break;      /* the field runs past the area or the window */
    }
    /* After C1h, "00h - any remaining unused space" (IPMI FRU Table 12-1). */
    nvme_mi_vpd_raw(tvb, pia, pos, fields_end);
    if (palen && area_end <= limit) {
        proto_item *sum = proto_tree_add_item(pia, hf_nvme_mi_mi_vpd_pia_pichk, tvb,
                                              area_end - 1, 1, ENC_LITTLE_ENDIAN);
        nvme_mi_vpd_checksum(tvb, pinfo, sum, start, palen * 8, 0);
    }
    return stop;
}

/* Figs 184/185/187/191/195 have local, length-delimited port formats.
 * Element pointers remain indices: never follow them recursively. */
static unsigned
nvme_mi_vpd_ports(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_item *owner, unsigned pos, unsigned end, unsigned count, unsigned family)
{
    for (unsigned i = 0; i < count; i++) {
        if (end - pos < 2) {
            expert_add_info(pinfo, owner, &ei_nvme_mi_mi_vpd_length);
            return pos;
        }
        unsigned type = tvb_get_uint8(tvb, pos);
        unsigned len = tvb_get_uint8(tvb, pos + 1);
        proto_item *ti = proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_port,
                                            tvb, pos, MIN(MAX(len, 2U), end - pos), ENC_NA);
        proto_tree *port = proto_item_add_subtree(ti, ett_nvme_mi_mi_entry);
        proto_tree_add_item(port, hf_nvme_mi_mi_vpd_porttyp, tvb, pos, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(port, hf_nvme_mi_mi_vpd_portlen, tvb, pos + 1, 1, ENC_LITTLE_ENDIAN);
        if (len < 2 || len > end - pos) {
            expert_add_info(pinfo, ti, &ei_nvme_mi_mi_vpd_length);
            nvme_mi_vpd_raw(tvb, port, pos + 2, end);
            return end;
        }
        unsigned used = 2;
        if ((family == 2 || family == 5) && type == 0 && len >= 3) {
            uint32_t pointers;
            proto_tree_add_item_ret_uint(port, hf_nvme_mi_mi_vpd_count, tvb, pos + 2, 1,
                                         ENC_LITTLE_ENDIAN, &pointers);
            if (pointers > len - 3)
                expert_add_info(pinfo, ti, &ei_nvme_mi_mi_vpd_length);
            used = 3;
            for (unsigned j = 0; j < pointers && used < len; j++, used++)
                proto_tree_add_item(port, hf_nvme_mi_mi_vpd_pointer, tvb,
                                    pos + used, 1, ENC_LITTLE_ENDIAN);
        } else if (((family == 2 && type == 1) || (family == 3 && type == 0))
                    && len >= (family == 2 ? 6U : 4U)) {
            proto_tree_add_item(port, hf_nvme_mi_mi_vpd_sl, tvb, pos + 2, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(port, hf_nvme_mi_mi_vpd_el, tvb, pos + 3, 1, ENC_LITTLE_ENDIAN);
            used = 4;
            if (family == 2) {
                proto_tree_add_item(port, hf_nvme_mi_mi_vpd_pointer, tvb, pos + 4, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(port, hf_nvme_mi_mi_vpd_dport, tvb, pos + 5, 1, ENC_LITTLE_ENDIAN);
                used = 6;
            }
        } else if (family == 7 && type == 0 && len >= 7) {
            proto_tree_add_bitmask(port, tvb, pos + 2, hf_nvme_mi_mi_vpd_linkspeed,
                                   ett_nvme_mi_mi_field, vpd_pciels_fields, ENC_NA);
            proto_tree_add_item(port, hf_nvme_mi_mi_vpd_linkwidth, tvb, pos + 3, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_bitmask(port, tvb, pos + 4, hf_nvme_mi_mi_vpd_rccap,
                                   ett_nvme_mi_mi_field, vpd_rccap_fields, ENC_NA);
            proto_tree_add_item(port, hf_nvme_mi_mi_vpd_portid, tvb, pos + 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_bitmask(port, tvb, pos + 6, hf_nvme_mi_mi_vpd_mctps,
                                   ett_nvme_mi_mi_field, vpd_mctps_fields, ENC_NA);
            used = 7;
        }
        nvme_mi_vpd_raw(tvb, port, pos + used, pos + len);
        pos += len;
    }
    return pos;
}

static void
nvme_mi_vpd_element(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_item *ti, unsigned pos, unsigned len, unsigned type, unsigned rev)
{
    unsigned end = pos + len, used = pos + 3, count = 0;
    unsigned minimum = type == 2 ? 11 : type == 4 ? 4 : 6;
    /* Figure 196, FRU Information Device: REV defaults to 00h but shall be
     * 1h, and both decode.  A descriptor under 6 bytes stays raw. */
    if (type == 8 && rev <= 1) {
        if (len < 6) {
            nvme_mi_vpd_raw(tvb, tree, used, end);
            return;
        }
        proto_tree_add_bitmask(tree, tvb, pos + 3, hf_nvme_mi_mi_vpd_addri,
                               ett_nvme_mi_mi_field, vpd_twaddri_fields, ENC_NA);
        proto_tree_add_bitmask(tree, tvb, pos + 4, hf_nvme_mi_mi_vpd_twcap,
                               ett_nvme_mi_mi_field, vpd_twcap_fru_fields, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_mfids, tvb, pos + 5, 1, ENC_LITTLE_ENDIAN);
        nvme_mi_vpd_raw(tvb, tree, pos + 6, end);
        return;
    }
    /* Figure 197: a vendor-specific descriptor names its PCI vendor; REV is
     * vendor defined and does not gate the layout. */
    if (type >= 0xF0) {
        if (len >= 5) {
            proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_pcivid, tvb, pos + 3, 2,
                                ENC_LITTLE_ENDIAN);
            used = pos + 5;
        } else {
            expert_add_info(pinfo, ti, &ei_nvme_mi_mi_vpd_length);
        }
        nvme_mi_vpd_raw(tvb, tree, used, end);
        return;
    }
    if ((type != 2 && type != 3 && type != 4 && type != 5 && type != 7)
        || rev != (type == 7 ? 1U : 0U)) {
        /* Fig 192's USPD extent is contradictory in the 2.2 source, so it
         * stays opaque, as do unknown types and revisions. */
        nvme_mi_vpd_raw(tvb, tree, used, end);
        return;
    }
    if (len < minimum) {
        expert_add_info(pinfo, ti, &ei_nvme_mi_mi_vpd_length);
        nvme_mi_vpd_raw(tvb, tree, used, end);
        return;
    }
    if (type == 4) {
        proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_lstr, tvb, used, end - used,
                            ENC_UTF_8);
        unsigned nul;
        if (tvb_find_uint8_length(tvb, used, end - used, 0, &nul))
            nvme_mi_vpd_raw(tvb, tree, nul + 1, end);
        return;
    }
    if (type == 2 || type == 3) {
        proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_ff, tvb, pos + 3, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_lptr, tvb, pos + 4, 1, ENC_LITTLE_ENDIAN);
        if (type == 2) {
            nvme_mi_vpd_raw(tvb, tree, pos + 5, pos + 7);
            proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_maxapwr, tvb, pos + 7, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_maxpwr, tvb, pos + 8, 2, ENC_LITTLE_ENDIAN);
        }
    } else {
        proto_tree_add_bitmask(tree, tvb, pos + 3, hf_nvme_mi_mi_vpd_addri,
                               ett_nvme_mi_mi_field, vpd_twaddri_fields, ENC_NA);
        proto_tree_add_bitmask(tree, tvb, pos + 4, hf_nvme_mi_mi_vpd_twcap, ett_nvme_mi_mi_field,
                               type == 5 ? vpd_twcap_mux_fields : vpd_twcap_nvms_fields, ENC_NA);
    }
    used = pos + minimum;
    proto_tree_add_item_ret_uint(tree, hf_nvme_mi_mi_vpd_portcount, tvb,
                                 used - 1, 1, ENC_LITTLE_ENDIAN, &count);
    used = nvme_mi_vpd_ports(tvb, pinfo, tree, ti, used, end, count, type);
    if (type == 7 && end - used >= 6) {
        proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_merim, tvb, used, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_merwmto, tvb, used + 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_mut, tvb, used + 4, 2, ENC_LITTLE_ENDIAN);
        used += 6;
    } else if (type == 7) {
        expert_add_info(pinfo, ti, &ei_nvme_mi_mi_vpd_length);
    }
    nvme_mi_vpd_raw(tvb, tree, used, end);
}

static void
nvme_mi_vpd_topology(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_item *ti, unsigned pos, unsigned len, bool final_complete)
{
    unsigned end = pos + len, used = pos + 3;
    uint32_t count;
    nvme_mi_vpd_raw(tvb, tree, pos + 1, pos + 2);
    proto_tree_add_item_ret_uint(tree, hf_nvme_mi_mi_vpd_elemc, tvb, pos + 2, 1,
                                 ENC_LITTLE_ENDIAN, &count);
    for (unsigned i = 0; i < count; i++) {
        if (end - used < 3) {
            expert_add_info(pinfo, ti, &ei_nvme_mi_mi_vpd_length);
            break;
        }
        unsigned type = tvb_get_uint8(tvb, used);
        unsigned rev = tvb_get_uint8(tvb, used + 1);
        unsigned size = tvb_get_uint8(tvb, used + 2);
        proto_item *element = proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_element,
            tvb, used, MIN(MAX(size, 3U), end - used), ENC_NA);
        proto_tree *sub = proto_item_add_subtree(element, ett_nvme_mi_mi_entry);
        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_typ, tvb, used, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_rev, tvb, used + 1, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_len, tvb, used + 2, 1, ENC_LITTLE_ENDIAN);
        if (size < 3 || size > end - used) {
            /* section 8.2.5.1 permits the last element to continue in the next
             * Topology record. Never label such a fragment invalid UTF-8. */
            if (size < 3 || i + 1 < count || final_complete)
                expert_add_info(pinfo, element, &ei_nvme_mi_mi_vpd_length);
            nvme_mi_vpd_raw(tvb, sub, used + 3, end);
            return;
        }
        if (i + 1 == count && !final_complete)
            nvme_mi_vpd_raw(tvb, sub, used + 3, used + size);
        else
            nvme_mi_vpd_element(tvb, pinfo, sub, element, used, size, type, rev);
        used += size;
    }
    nvme_mi_vpd_raw(tvb, tree, used, end);
}

/* MI 2.2 section 8.2, Figs 172/175-179: one selected VPD window. */
static void
nvme_mi_mi_vpd_undecoded(proto_tree *tree, tvbuff_t *tvb, proto_item *item,
                         int offset, int len, const char *reason)
{
    proto_item_append_text(item, " (%s)", reason);
    proto_item *marker = proto_tree_add_boolean(tree, hf_nvme_mi_mi_vpd_undecoded,
                                                tvb, offset, len, TRUE);
    proto_item_set_generated(marker);
    proto_item_set_hidden(marker);
}

static void
nvme_mi_mi_vpd_read(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    unsigned off, unsigned len, const struct nvme_mi_mi_req_ctx *req,
    bool extent_diagnosed)
{
    proto_item *ti = proto_tree_add_item(tree, hf_nvme_mi_mi_vpd_data,
                                        tvb, off, len, ENC_NA);
    proto_tree *vpd = proto_item_add_subtree(ti, ett_nvme_mi_mi_field);
    unsigned end = off + len, pos, pia, limit;
    if (!req || req->dofst) {
        if (!extent_diagnosed)
            nvme_mi_mi_vpd_undecoded(vpd, tvb, ti, off, len,
                                     "VPD window has no Common Header;"
                                     " bytes shown raw");
        return;
    }
    if (len < 8)
        return;
    for (unsigned i = 0; i < 8; i++)
        proto_tree_add_item(vpd, hf_nvme_mi_mi_vpd_common[i], tvb, off + i, 1, ENC_LITTLE_ENDIAN);
    if (tvb_get_uint8(tvb, off) != 1) {
        nvme_mi_mi_vpd_undecoded(vpd, tvb, ti, off, len,
                                 NVME_MI_VPD_UNKNOWN_FORMAT);
        return;
    }
    nvme_mi_vpd_checksum(tvb, pinfo, ti, off, 8, 0);
    pos = tvb_get_uint8(tvb, off + 5) * 8U;
    pia = tvb_get_uint8(tvb, off + 4) * 8U;
    /* Where the bytes before the MultiRecord Info Area end in this window. */
    limit = (pos && pos < len) ? off + pos : end;
    /* Product Info Area (section 8.2.2), when it starts in this window. */
    if (pia && off + pia < limit) {
        nvme_mi_vpd_raw(tvb, vpd, off + 8, off + pia);
        nvme_mi_vpd_raw(tvb, vpd, nvme_mi_vpd_product_info(tvb, pinfo, vpd, off + pia, limit),
                        limit);
    } else {
        nvme_mi_vpd_raw(tvb, vpd, off + 8, limit);
    }
    if (!pos || pos >= len)
        return;
    pos += off;
    while (end - pos >= 5) {
        unsigned type = tvb_get_uint8(tvb, pos);
        unsigned fmt = tvb_get_uint8(tvb, pos + 1);
        unsigned rlen = tvb_get_uint8(tvb, pos + 2);
        unsigned size = rlen + 5;
        proto_item *record = proto_tree_add_item(vpd, hf_nvme_mi_mi_vpd_record,
                                                tvb, pos, MIN(size, end - pos), ENC_NA);
        proto_tree *sub = proto_item_add_subtree(record, ett_nvme_mi_mi_entry);
        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_rti, tvb, pos, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_lrec, tvb, pos + 1, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_rver, tvb, pos + 1, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_rlen, tvb, pos + 2, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_rcsum, tvb, pos + 3, 1, ENC_LITTLE_ENDIAN);
        proto_item *hsum = proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_hsum,
                                               tvb, pos + 4, 1, ENC_LITTLE_ENDIAN);
        nvme_mi_vpd_checksum(tvb, pinfo, hsum, pos, 5, 0);
        if (size > end - pos) {
            nvme_mi_vpd_raw(tvb, sub, pos + 5, end);
            return;
        }
        nvme_mi_vpd_checksum(tvb, pinfo, record, pos + 5, rlen, tvb_get_uint8(tvb, pos + 3));
        unsigned used = pos + 5;
        if ((fmt & 0x7f) != 2)
            nvme_mi_mi_vpd_undecoded(sub, tvb, record, pos, MIN(size, end - pos),
                                     NVME_MI_VPD_UNKNOWN_FORMAT);
        if ((fmt & 0x7f) == 2 && type >= 0x0b && type <= 0x0d && rlen) {
            uint32_t version;
            proto_tree_add_item_ret_uint(sub, hf_nvme_mi_mi_vpd_version, tvb, used, 1,
                                         ENC_LITTLE_ENDIAN, &version);
            used++;
            if (type == 0x0b && version == 0) {
                if (rlen == 0x20 || rlen == 0x3b) {
                    proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_ff, tvb, pos + 6, 1, ENC_LITTLE_ENDIAN);
                    /* Figure 175: bytes 12:07 and byte 17 are Reserved; byte
                     * 17 sits between M3P3PSR (16) and M3P3APSR (18). */
                    proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_rsvd, tvb, pos + 7, 6, ENC_NA);
                    for (unsigned i = 0; i < 10; i++) {
                        unsigned p = pos + 13 + i + (i >= 4 ? 1 : 0);
                        if (i == 4)
                            proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_rsvd, tvb, pos + 17, 1, ENC_NA);
                        proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_power[i], tvb, p, 1, ENC_LITTLE_ENDIAN);
                    }
                    proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_capacity, tvb, pos + 24, 13, ENC_NA);
                    used = pos + 37;
                } else
                    expert_add_info(pinfo, record, &ei_nvme_mi_mi_vpd_length);
            } else if (type == 0x0c && version == 1) {
                if (rlen == 8 || rlen == 11) {
                    proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_pn, tvb, pos + 6, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_bitmask(sub, tvb, pos + 7, hf_nvme_mi_mi_vpd_pinfo,
                                           ett_nvme_mi_mi_field, vpd_pinfo_fields, ENC_NA);
                    proto_tree_add_bitmask(sub, tvb, pos + 8, hf_nvme_mi_mi_vpd_linkspeed,
                                           ett_nvme_mi_mi_field, vpd_pciels_fields, ENC_NA);
                    proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_linkwidth, tvb, pos + 9, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_bitmask(sub, tvb, pos + 10, hf_nvme_mi_mi_vpd_mctps,
                                           ett_nvme_mi_mi_field, vpd_mctps_fields, ENC_NA);
                    proto_tree_add_bitmask(sub, tvb, pos + 11, hf_nvme_mi_mi_vpd_rccap,
                                           ett_nvme_mi_mi_field, vpd_rccap_fields, ENC_NA);
                    proto_tree_add_item(sub, hf_nvme_mi_mi_vpd_portid, tvb, pos + 12, 1, ENC_LITTLE_ENDIAN);
                    used = pos + 13;
                } else
                    expert_add_info(pinfo, record, &ei_nvme_mi_mi_vpd_length);
            } else if (type == 0x0d && version == 0) {
                if (rlen >= 3) {
                    nvme_mi_vpd_topology(tvb, pinfo, sub, record, pos + 5, rlen,
                                         (fmt & 0x80) != 0);
                    used = pos + size;
                } else
                    expert_add_info(pinfo, record, &ei_nvme_mi_mi_vpd_length);
            }
        } else if (type >= 0x0b && type <= 0x0d && (fmt & 0x7f) == 2 && !rlen) {
            expert_add_info(pinfo, record, &ei_nvme_mi_mi_vpd_length);
        }
        nvme_mi_vpd_raw(tvb, sub, used, pos + size);
        pos += size;
        if (fmt & 0x80)
            break;
    }
    nvme_mi_vpd_raw(tvb, vpd, pos, end);
}

/* DTYP 00h - NVM Subsystem Information Data Structure */
static void
nvme_mi_mi_data_subsys_info(tvbuff_t *tvb, proto_tree *tree, proto_item *it _U_, int off, int len)
{
    /* Figure 115's field-bearing bytes, even when the tail is short. */
    if (len < 4) {
        nvme_mi_mi_data_raw(tvb, tree, off, len);
        return;
    }
    proto_tree_add_item(tree, hf_nvme_mi_mi_subsys_nump, tvb, off, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_subsys_mjr, tvb, off + 1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_subsys_mnr, tvb, off + 2, 1, ENC_NA);
    /* Figure 115: NNSC bits 7:1 are Reserved. */
    proto_tree_add_bitmask(tree, tvb, off + 3, hf_nvme_mi_mi_subsys_nnsc,
                           ett_nvme_mi_mi_field, subsys_nnsc_fields, ENC_NA);
    /* bytes 31:04 reserved */
    nvme_mi_mi_data_ds_reserved(tvb, tree, off + 4, len - 4);
}

static void
nvme_mi_pdas_fmt(char *result, uint32_t val)
{
    if (val == 0)
        snprintf(result, ITEM_LABEL_LENGTH, "0 (No NVMe-MI PDA)");
    else if (val < 64)
        snprintf(result, ITEM_LABEL_LENGTH, "%u (2^%u = %" PRIu64 " bytes)",
                 val, val, UINT64_C(1) << val);
    else
        snprintf(result, ITEM_LABEL_LENGTH, "%u (2^%u bytes)", val, val);
}

/* Does a Figure 119 2-Wire address name this message's physical responder?
 * Its 7- or 8-bit form is unspecified, so both match, 7-bit first;
 * *eight_bit says which. */
static bool
nvme_mi_twire_addr_matches(uint8_t addr, uint8_t src7, bool *eight_bit)
{
    if (addr == src7) {
        *eight_bit = false;
        return true;
    }
    if (addr == (uint8_t)(src7 << 1)) {
        *eight_bit = true;
        return true;
    }
    return false;
}

/* DTYP 01h - Port Information Data Structure */
static void
nvme_mi_mi_data_port_info(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, proto_item *it _U_, int off, int len)
{
    uint32_t prttyp;

    if (len < 8) {
        nvme_mi_mi_data_raw(tvb, tree, off, len);
        return;
    }
    proto_tree_add_item_ret_uint(tree, hf_nvme_mi_mi_port_prttyp,
                                 tvb, off, 1, ENC_NA, &prttyp);
    /* Figure 117: PRTCAP bits 7:2 are Reserved. */
    proto_tree_add_bitmask(tree, tvb, off + 1, hf_nvme_mi_mi_port_prtcap,
                           ett_nvme_mi_mi_field, port_prtcap_fields, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_port_mmtus,
                        tvb, off + 2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_nvme_mi_mi_port_mebs,
                        tvb, off + 4, 4, ENC_LITTLE_ENDIAN);

    switch (prttyp) {
    case 0x1:   /* PCIe Port Specific Data */
        if (len < 14) {
            nvme_mi_mi_data_raw(tvb, tree, off + 8, len - 8);
            return;
        }
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_mps,
                            tvb, off + 8, 1, ENC_NA);
        /* Figure 118: PCIESLSV is a per-speed support vector; bits 7:6 are
         * Reserved. */
        proto_tree_add_bitmask(tree, tvb, off + 9, hf_nvme_mi_mi_port_pcie_slsv,
                               ett_nvme_mi_mi_field, port_pcie_slsv_fields, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_cls,
                            tvb, off + 10, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_mlw,
                            tvb, off + 11, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_nlw,
                            tvb, off + 12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_pn,
                            tvb, off + 13, 1, ENC_NA);
        /* bytes 31:14 reserved */
        nvme_mi_mi_data_ds_reserved(tvb, tree, off + 14, len - 14);
        break;
    case 0x2:   /* 2-Wire Port Specific Data */
        if (len < 13) {
            nvme_mi_mi_data_raw(tvb, tree, off + 8, len - 8);
            return;
        }
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_twire_cvpdaddr,
                            tvb, off + 8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_twire_mvpdfreq,
                            tvb, off + 9, 1, ENC_NA);
        {
            proto_item *cme_it;
            uint32_t cmeaddr;
            uint8_t src7;
            bool eight_bit;

            cme_it = proto_tree_add_item_ret_uint(tree,
                            hf_nvme_mi_mi_port_twire_cmeaddr, tvb, off + 10, 1,
                            ENC_NA, &cmeaddr);
            /* Say which reading matched, if either did. */
            if (cmeaddr && mctp_smbus_slave_addr(&pinfo->net_src, &src7) &&
                nvme_mi_twire_addr_matches((uint8_t)cmeaddr, src7, &eight_bit))
                proto_item_append_text(cme_it, eight_bit
                        ? " (8-bit form of this port's 2-Wire address)"
                        : " (7-bit form of this port's 2-Wire address)");
        }
        /* Figure 119: TWPRT bits 6:2 and NVMEBM bits 7:1 are Reserved. */
        proto_tree_add_bitmask(tree, tvb, off + 11, hf_nvme_mi_mi_port_twire_twprt,
                               ett_nvme_mi_mi_field, port_twprt_fields, ENC_NA);
        proto_tree_add_bitmask(tree, tvb, off + 12, hf_nvme_mi_mi_port_twire_nvmebm,
                               ett_nvme_mi_mi_field, port_nvmebm_fields, ENC_NA);
        /* MI 2.2 Figure 119: PDAS 16:13, SDFORMAT 17, 31:18 Reserved. */
        if (len < 17) {
            nvme_mi_mi_data_raw(tvb, tree, off + 13, len - 13);
            return;
        }
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_twire_pdas,
                            tvb, off + 13, 4, ENC_LITTLE_ENDIAN);
        if (len < 18)
            return;
        proto_tree_add_bitmask(tree, tvb, off + 17, hf_nvme_mi_mi_port_twire_sdformat,
                               ett_nvme_mi_mi_field, port_sdformat_fields, ENC_NA);
        nvme_mi_mi_data_ds_reserved(tvb, tree, off + 18, len - 18);
        break;
    default:
        /* Inactive or reserved port type: PTSP bytes rendered raw */
        nvme_mi_mi_data_raw(tvb, tree, off + 8, len - 8);
        break;
    }
}

/* Bytes after the last element a list declared (NVMe-MI 2.2 5.8.5,
 * 5.8.6). */
static void
nvme_mi_mi_list_surplus(tvbuff_t *tvb, proto_tree *tree, int pos, int end)
{
    if (pos < end)
        proto_tree_add_item(tree, hf_nvme_mi_mi_list_surplus, tvb, pos,
                            end - pos, ENC_NA);
}

/* DTYP 02h - Controller List (NVMe Base format: count + uint16le IDs) */
static void
nvme_mi_mi_data_ctrl_list(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, proto_item *it, int off, int len)
{
    uint32_t numids;
    int pos;

    if (len < 2) {
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off);
        return;
    }
    numids = tvb_get_letohs(tvb, off);
    pos = off + nvme_dissect_controller_list(tvb, pinfo, tree, off, len,
        hf_nvme_mi_mi_ctrllist_numids, hf_nvme_mi_mi_ctrllist_ctrlid);
    if (pos - off < 2 + (int)numids * 2) {
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, pos);
        return;
    }
    nvme_mi_mi_list_surplus(tvb, tree, pos, off + len);
}

/* DTYP 03h - Controller Information Data Structure (Figure 120).  A short
 * structure decodes each field that fits; the caller flags the length. */
static void
nvme_mi_mi_data_ctrl_info(tvbuff_t *tvb, proto_tree *tree, proto_item *it _U_, int off, int len)
{
    static const struct {
        int at, size;
        int *hf;
    } u16s[] = {
        { 8,  2, &hf_nvme_mi_mi_ctrlinfo_pcivid },
        { 10, 2, &hf_nvme_mi_mi_ctrlinfo_pcidid },
        { 12, 2, &hf_nvme_mi_mi_ctrlinfo_pcisvid },
        { 14, 2, &hf_nvme_mi_mi_ctrlinfo_pcisdid },
    };

    if (len < 1)
        return;
    proto_tree_add_item(tree, hf_nvme_mi_mi_ctrlinfo_portid,
                        tvb, off, 1, ENC_NA);
    /* bytes 04:01 reserved */
    nvme_mi_mi_data_ds_reserved(tvb, tree, off + 1, MIN(len, 5) - 1);
    if (len < 6)
        return;
    /* PRII bits 7:1 are Reserved. */
    proto_tree_add_bitmask(tree, tvb, off + 5, hf_nvme_mi_mi_ctrlinfo_prii,
                           ett_nvme_mi_mi_field, ctrlinfo_prii_fields, ENC_NA);
    if (len < 8) {
        nvme_mi_mi_data_raw(tvb, tree, off + 6, len - 6);
        return;
    }
    /* The PCIe Routing ID; see nvme_mi_ctrlinfo_ari. */
    proto_tree_add_bitmask(tree, tvb, off + 6, hf_nvme_mi_mi_ctrlinfo_pri,
                           ett_nvme_mi_mi_field,
                           nvme_mi_ctrlinfo_ari ? ctrlinfo_pri_ari_fields
                                                : ctrlinfo_pri_fields,
                           ENC_LITTLE_ENDIAN);
    for (unsigned i = 0; i < array_length(u16s); i++) {
        if (len < u16s[i].at + u16s[i].size) {
            nvme_mi_mi_data_raw(tvb, tree, off + u16s[i].at,
                                len - u16s[i].at);
            return;
        }
        proto_tree_add_item(tree, *u16s[i].hf, tvb, off + u16s[i].at,
                            u16s[i].size, ENC_LITTLE_ENDIAN);
    }
    if (len < 17)
        return;
    proto_tree_add_item(tree, hf_nvme_mi_mi_ctrlinfo_pciesn,
                        tvb, off + 16, 1, ENC_NA);
    /* bytes 31:17 reserved */
    nvme_mi_mi_data_ds_reserved(tvb, tree, off + 17, len - 17);
}

/* DTYP 04h/05h - Optionally Supported / MEB Supported Command List
 * (both share the count + (CTYP, OPC) entry format) */
static void
nvme_mi_mi_data_cmd_list(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, proto_item *it, int off, int len,
                         uint8_t iocsi)
{
    uint32_t numcmd;
    int pos = off + 2;

    if (len < 2) {
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off);
        return;
    }
    proto_tree_add_item_ret_uint(tree, hf_nvme_mi_mi_cmdlist_numcmd,
                                 tvb, off, 2, ENC_LITTLE_ENDIAN, &numcmd);
    for (uint32_t i = 0; i < numcmd; i++) {
        uint64_t ctyp;
        uint8_t opc;
        proto_item *opc_it;
        const char *opc_name = NULL;

        if (pos + 2 > off + len) {
            nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, pos);
            return;
        }
        proto_tree_add_bitmask_ret_uint64(tree, tvb, pos, hf_nvme_mi_mi_cmdlist_ctyp,
                                          ett_nvme_mi_mi_field, cmdlist_ctyp_fields,
                                          ENC_NA, &ctyp);
        opc_it = proto_tree_add_item_ret_uint8(tree, hf_nvme_mi_mi_cmdlist_opc,
                                               tvb, pos + 1, 1, ENC_NA, &opc);
        /* NMIMT (CTYP bits 6:3) selects the OPC namespace (Figs 122/124). */
        switch ((ctyp & 0x78) >> 3) {
        case NVME_MI_TYPE_MI:
            opc_name = rval_to_str_const(opc, mi_opcode_vals, "Unknown");
            break;
        case NVME_MI_TYPE_ADMIN:
            opc_name = nvme_get_admin_opcode_string(opc, iocsi);
            break;
        case NVME_MI_TYPE_PCIE:
            opc_name = rval_to_str_const(opc, nvme_mi_pcie_opcode_vals,
                                         "Reserved");
            break;
        default:
            break;
        }
        if (opc_name)
            proto_item_append_text(opc_it, " (%s)", opc_name);
        pos += 2;
    }
    nvme_mi_mi_list_surplus(tvb, tree, pos, off + len);
}

static void
nvme_mi_mi_data_read_ds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *it, int off, int len,
                        const struct nvme_mi_mi_req_ctx *req, bool reconcile)
{
    /* Stay opaque when the selecting request was sliced. */
    if (!req) {
        nvme_mi_mi_data_raw(tvb, tree, off, len);
        return;
    }
    unsigned rdl = tvb_get_letohs(tvb, 1);
    /* MI 2.2 Figs 115, 117 and 120 include their reserved bytes in the
     * 32-byte structure; a field-bearing prefix is not a complete structure. */
    int fixed = (req->dtyp == NVME_MI_DTYP_SUBSYS_INFO ||
                 req->dtyp == NVME_MI_DTYP_PORT_INFO ||
                 req->dtyp == NVME_MI_DTYP_CTRL_INFO) ? 32 : -1;
    len = nvme_mi_mi_response_extent(tvb, pinfo, tree, it, off, len,
                                    rdl, fixed, "RDL", reconcile);
    if (len == 0)
        return;
    /* List truncation/tail helpers must not see bytes outside RDL either. */
    tvbuff_t *data_tvb = tvb_new_subset_length(tvb, off, len);
    switch (req->dtyp) {
    case NVME_MI_DTYP_SUBSYS_INFO:
        nvme_mi_mi_data_subsys_info(data_tvb, tree, it, 0, len);
        break;
    case NVME_MI_DTYP_PORT_INFO:
        nvme_mi_mi_data_port_info(data_tvb, pinfo, tree, it, 0, len);
        break;
    case NVME_MI_DTYP_CTRL_LIST:
        nvme_mi_mi_data_ctrl_list(data_tvb, pinfo, tree, it, 0, len);
        break;
    case NVME_MI_DTYP_CTRL_INFO:
        nvme_mi_mi_data_ctrl_info(data_tvb, tree, it, 0, len);
        break;
    case NVME_MI_DTYP_OSC_LIST:
    case NVME_MI_DTYP_MEB_LIST:
        nvme_mi_mi_data_cmd_list(data_tvb, pinfo, tree, it, 0, len, req->iocsi);
        break;
    default:
        nvme_mi_mi_data_raw(data_tvb, tree, 0, len);
        break;
    }
}

/* NVM Subsystem Health Data Structure (NSHDS; 8 bytes) */
static void
nvme_mi_mi_data_nshds(tvbuff_t *tvb, packet_info *pinfo,
                      proto_tree *tree, proto_item *it, int off, int len,
                      bool reconcile)
{
    len = nvme_mi_mi_response_extent(tvb, pinfo, tree, it, off, len,
                                    8, 8, "NSHDS", reconcile);
    if (len < 8) {
        nvme_mi_mi_data_raw(tvb, tree, off, len);
        return;
    }
    proto_tree_add_bitmask(tree, tvb, off, hf_nvme_mi_mi_nshds_nss,
                           ett_nvme_mi_mi_field, nshds_nss_fields, ENC_NA);
    /* Inverted sense: appending set-bit names would list healthy bits. */
    proto_tree_add_bitmask_with_flags(tree, tvb, off + 1, hf_nvme_mi_mi_nshds_sw,
                                      ett_nvme_mi_mi_field, nshds_sw_fields,
                                      ENC_NA, BMT_NO_APPEND);
    proto_tree_add_item(tree, hf_nvme_mi_mi_nshds_ctemp,
                        tvb, off + 2, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_nshds_pdlu,
                        tvb, off + 3, 1, ENC_NA);
    proto_tree_add_bitmask(tree, tvb, off + 4, hf_nvme_mi_mi_nshds_ccs,
                           ett_nvme_mi_mi_field, hsf_fields,
                           ENC_LITTLE_ENDIAN);
    /* Figure 105: bytes 7:6 are Reserved. */
    proto_tree_add_item(tree, hf_nvme_mi_mi_nshds_rsvd,
                        tvb, off + 6, 2, ENC_LITTLE_ENDIAN);
}

/* Array of 16-byte Controller Health Data Structures (CHDS) */
static void
nvme_mi_mi_data_chds_list(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, proto_item *it, int off, int len,
                          unsigned rent, bool reconcile)
{
    unsigned idx = 0;
    int pos = off;

    /* RENT is one based, at most 255; surplus entries must stay raw. */
    len = nvme_mi_mi_response_extent(tvb, pinfo, tree, it, off, len,
                                    rent * 16, -1, "RENT * 16", reconcile);
    while (off + len - pos >= 16) {
        proto_tree *etree = proto_tree_add_subtree_format(tree, tvb, pos, 16,
                ett_nvme_mi_mi_entry, NULL,
                "Controller Health Data Structure %u", idx);
        proto_tree_add_item(etree, hf_nvme_mi_mi_chds_ctlid,
                            tvb, pos, 2, ENC_LITTLE_ENDIAN);
        /* Figure 97: CS bits 15:09 are Reserved. */
        proto_tree_add_bitmask(etree, tvb, pos + 2, hf_nvme_mi_mi_chds_csts,
                               ett_nvme_mi_mi_field, chds_csts_fields, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(etree, hf_nvme_mi_mi_chds_ctemp,
                            tvb, pos + 4, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(etree, hf_nvme_mi_mi_chds_pdlu,
                            tvb, pos + 6, 1, ENC_NA);
        proto_tree_add_item(etree, hf_nvme_mi_mi_chds_spare,
                            tvb, pos + 7, 1, ENC_NA);
        proto_tree_add_bitmask(etree, tvb, pos + 8, hf_nvme_mi_mi_chds_cwarn,
                               ett_nvme_mi_mi_field, chds_cwarn_fields,
                               ENC_NA);
        proto_tree_add_bitmask(etree, tvb, pos + 9, hf_nvme_mi_mi_chds_chsc,
                               ett_nvme_mi_mi_field, hsf_fields,
                               ENC_LITTLE_ENDIAN);
        /* Figure 97: bytes 15:11 are Reserved. */
        proto_tree_add_item(etree, hf_nvme_mi_mi_chds_rsvd,
                            tvb, pos + 11, 5, ENC_NA);
        pos += 16;
        idx++;
    }
    nvme_mi_mi_data_raw(tvb, tree, pos, off + len - pos);
}

/* Append " (<opcode>[: <detail>])" to COL_INFO. */
static void
nvme_mi_mi_col_append(packet_info *pinfo, unsigned opcode, const char *detail)
{
    const char *name = rval_to_str_const(opcode, mi_opcode_vals, "Unknown");

    if (detail)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s: %s)", name, detail);
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", name);
}

/* The Configuration Identifier name, with the AE variation (5.2.4) when
 * known. */
static const char *
nvme_mi_mi_configid_detail(packet_info *pinfo, uint8_t cid,
                           enum nvme_mi_ae_variant variant)
{
    const char *name = rval_to_str_const(cid, mi_configid_vals, "Reserved");

    if (cid != NVME_MI_CFGID_AE || variant == NVME_MI_AE_VARIANT_UNKNOWN)
        return name;
    return wmem_strdup_printf(pinfo->pool, "%s (%s)", name,
                              variant == NVME_MI_AE_VARIANT_SYNC
                                  ? "AE Sync" : "AEM Ack");
}

/* The Reserved bits of a Success Response's 24-bit NMRESP (NVMe-MI 2.2
 * Figures 77, 79, 81, 96, 114, 128; sections 5.1.2, 5.2.1, 5.2.3, 5.2.4,
 * 5.9, 5.10, 5.12 and the MEB/VPD commands).  A NULL 'req' claims nothing
 * about configuration-specific layouts. */
static uint32_t
nvme_mi_mi_nmresp_rsvd_mask(unsigned opcode,
                            const struct nvme_mi_mi_req_ctx *req)
{
    switch (opcode) {
    case NVME_MI_MI_OPC_READ_DS:
    case NVME_MI_MI_OPC_SES_RECV:
        return 0xFF0000;
    case NVME_MI_MI_OPC_CTRL_HSP:
        return 0x00FFFF;
    case NVME_MI_MI_OPC_SUBSYS_HSP:
    case NVME_MI_MI_OPC_VPD_READ:
    case NVME_MI_MI_OPC_VPD_WRITE:
    case NVME_MI_MI_OPC_RESET:
    case NVME_MI_MI_OPC_SHUTDOWN:
    case NVME_MI_MI_OPC_SES_SEND:
    case NVME_MI_MI_OPC_MEB_READ:
    case NVME_MI_MI_OPC_MEB_WRITE:
    case NVME_MI_MI_OPC_PDA_READ:
    case NVME_MI_MI_OPC_PDA_WRITE:
    case NVME_MI_MI_OPC_PDA_WRITE_ZEROES:
        return 0xFFFFFF;
    case NVME_MI_MI_OPC_CONFIG_SET:
        return req && (req->configid == NVME_MI_CFGID_SMBUS_FREQ ||
                       req->configid == NVME_MI_CFGID_MTUS ||
                       req->configid == NVME_MI_CFGID_AE) ? 0xFFFFFF : 0;
    case NVME_MI_MI_OPC_CONFIG_GET:
        if (!req)
            return 0;
        switch (req->configid) {
        case NVME_MI_CFGID_SMBUS_FREQ: return 0xFFFFF0;
        case NVME_MI_CFGID_HSC:        return 0xFFFFFF;
        case NVME_MI_CFGID_MTUS:       return 0xFF0000;
        case NVME_MI_CFGID_AE:         return 0xFFFF00;
        default:                       return 0;
        }
    default:
        return 0;
    }
}

/* The Reserved bits of NMD0 and NMD1 (NVMe-MI 2.2 Figures 76-90, 94, 95,
 * 99-104, 112, 113, 125-135).  Unknown CONFIGIDs claim nothing. */
static void
nvme_mi_mi_nmd_rsvd_masks(unsigned opcode, uint8_t cid,
                          uint32_t *m0, uint32_t *m1)
{
    *m0 = 0;
    *m1 = 0;
    switch (opcode) {
    case NVME_MI_MI_OPC_READ_DS:
        *m1 = 0xFFFFFF00;
        break;
    case NVME_MI_MI_OPC_SUBSYS_HSP:
        *m0 = 0xFFFFFFFF;
        *m1 = 0x7FFFFFFF;
        break;
    case NVME_MI_MI_OPC_CTRL_HSP:
        *m0 = 0x78000000;
        *m1 = 0x7FFFFFE0;
        break;
    case NVME_MI_MI_OPC_CONFIG_GET:
        switch (cid) {
        case NVME_MI_CFGID_SMBUS_FREQ:
        case NVME_MI_CFGID_MTUS:
            *m0 = 0x00FFFF00;
            *m1 = 0xFFFFFFFF;
            break;
        case NVME_MI_CFGID_HSC:
        case NVME_MI_CFGID_AE:
            *m0 = 0xFFFFFF00;
            *m1 = 0xFFFFFFFF;
            break;
        default:
            break;
        }
        break;
    case NVME_MI_MI_OPC_CONFIG_SET:
        switch (cid) {
        case NVME_MI_CFGID_SMBUS_FREQ:
            *m0 = 0x00FFF000;
            *m1 = 0xFFFFFFFF;
            break;
        case NVME_MI_CFGID_HSC:
            *m0 = 0xFFFFFF00;
            *m1 = 0xFFFFE000;
            break;
        case NVME_MI_CFGID_MTUS:
            *m0 = 0x00FFFF00;
            *m1 = 0xFFFF0000;
            break;
        case NVME_MI_CFGID_AE:
            *m0 = 0xF8000000;
            *m1 = 0xFFFFFFFF;
            break;
        default:
            break;
        }
        break;
    case NVME_MI_MI_OPC_VPD_READ:
    case NVME_MI_MI_OPC_VPD_WRITE:
        *m0 = 0xFFFF0000;
        *m1 = 0xFFFF0000;
        break;
    case NVME_MI_MI_OPC_RESET:
    case NVME_MI_MI_OPC_SHUTDOWN:
        *m0 = 0x00FFFFFF;
        *m1 = 0xFFFFFFFF;
        break;
    case NVME_MI_MI_OPC_SES_RECV:
        *m0 = 0xFFFFFF00;
        *m1 = 0xFFFF0000;
        break;
    case NVME_MI_MI_OPC_SES_SEND:
        *m0 = 0xFFFFFFFF;
        *m1 = 0xFFFF0000;
        break;
    case NVME_MI_MI_OPC_MEB_READ:
    case NVME_MI_MI_OPC_MEB_WRITE:
        *m1 = 0xFFFF0000;
        break;
    case NVME_MI_MI_OPC_PDA_WRITE_ZEROES:
        /* MI 2.2 5.7.3: NMD0 and NMD1 are not used. */
        *m0 = 0xFFFFFFFF;
        *m1 = 0xFFFFFFFF;
        break;
    default:
        break;
    }
}

/* Nonzero reserved bits are shown, unshifted, as sent; like every other
 * reserved run here they carry no expert ("or in accordance with a future
 * extension", 1.5). */
static void
nvme_mi_mi_show_reserved(tvbuff_t *tvb, proto_tree *tree, int hf,
                         int off, int len, uint32_t value, uint32_t mask)
{
    if (value & mask)
        proto_tree_add_uint(tree, hf, tvb, off, len, value & mask);
}

/* A request whose only parameter is a type byte in NMD0 bits 31:24
 * (RSTTYP, SHDNTYP).  Returns its name. */
static const char *
nvme_mi_mi_dissect_typebyte_req(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *mi_tree, int * const *cdw0_fields,
                                uint8_t max_valid, const range_string *vals)
{
    proto_item *cdw_it;
    uint64_t cdw0;
    uint8_t typ;

    cdw_it = proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 4,
            hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field,
            cdw0_fields, ENC_LITTLE_ENDIAN, &cdw0);
    typ = (uint8_t)(cdw0 >> 24);
    if (typ > max_valid)
        expert_add_info(pinfo, cdw_it, &ei_nvme_mi_mi_reserved_value);
    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw1,
                        tvb, 8, 4, ENC_LITTLE_ENDIAN);
    return rval_to_str_const(typ, vals, "Reserved");
}

/* One check after a list walk: every entry present, and the Total Length
 * equal to the header plus entries and within the list data.  Bytes past
 * the Total Length are shown raw. */
static void
nvme_mi_mi_list_check(packet_info *pinfo, proto_item *tl_ti, expert_field *ei,
                      const char *name, unsigned present, unsigned num,
                      unsigned total_len, unsigned hdr_len, unsigned body_len,
                      unsigned len)
{
    if (present < num || total_len != hdr_len + body_len || total_len > len)
        expert_add_info_format(pinfo, tl_ti, ei,
                               "%u of %u %s entries present; Total Length %u,"
                               " header plus entries %u, list data %u bytes",
                               present, num, name, total_len,
                               hdr_len + body_len, len);
}

/* AE Enable List (NVMe-MI 2.2 Figures 91/92) and AE Supported List (Figures
 * 82/83). */
struct nvme_mi_mi_ae_list_hf {
    int         list;
    int         num;
    int         ver;
    int         total_len;
    int         hdr_len;
    int         entry;
    int         entry_len;
    int         flag;
    int         id;
    int         rsvd;       /* Figures 92/83: info-word bits 14:08 */
    const char *entry_name;
    bool        supported;  /* Figures 82/83 "shall" values are checked */
};

static void
dissect_nvme_mi_mi_ae_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           proto_item *it, unsigned off, unsigned len,
                           const struct nvme_mi_mi_ae_list_hf *hf)
{
    proto_tree *ae_tree;
    proto_item *ti, *tl_ti, *num_ti, *ver_ti, *hl_ti;
    uint32_t num, ver, total_len, hdr_len, i;
    unsigned pos, body_len = 0;

    ti = proto_tree_add_item(tree, hf->list, tvb, off, len, ENC_NA);
    ae_tree = proto_item_add_subtree(ti, ett_nvme_mi_mi);

    /* The list header is 5 bytes; anything shorter is truncated. */
    if (len < 5) {
        nvme_mi_mi_data_truncated(tvb, pinfo, ae_tree, it, off);
        return;
    }

    num_ti = proto_tree_add_item_ret_uint(ae_tree, hf->num, tvb, off, 1,
                                          ENC_LITTLE_ENDIAN, &num);
    ver_ti = proto_tree_add_item_ret_uint(ae_tree, hf->ver, tvb, off + 1, 1,
                                          ENC_LITTLE_ENDIAN, &ver);
    tl_ti = proto_tree_add_item_ret_uint(ae_tree, hf->total_len,
                                         tvb, off + 2, 2, ENC_LITTLE_ENDIAN,
                                         &total_len);
    hl_ti = proto_tree_add_item_ret_uint(ae_tree, hf->hdr_len, tvb, off + 4, 1,
                                         ENC_LITTLE_ENDIAN, &hdr_len);
    if (hf->supported) {
        if (num == 0)
            expert_add_info_format(pinfo, num_ti, &ei_nvme_mi_mi_aes_field_invalid,
                "NUMAES shall be 1h or greater (NVMe-MI 'AE Supported List Data Structure')");
        if (ver != 0)
            expert_add_info_format(pinfo, ver_ti, &ei_nvme_mi_mi_aes_field_invalid,
                "AESLVER shall be cleared to 0h (NVMe-MI 'AE Supported List Data Structure')");
        if (hdr_len != 5)
            expert_add_info_format(pinfo, hl_ti, &ei_nvme_mi_mi_aes_field_invalid,
                "AESLHL shall be set to 5h (NVMe-MI 'AE Supported List Data Structure')");
    }

    /* The body starts at the declared header length, clamped to 5. */
    if (hdr_len < 5)
        hdr_len = 5;

    pos = off + hdr_len;
    for (i = 0; i < num; i++) {
        proto_tree *e_tree;
        proto_item *e_ti, *el_ti;
        unsigned elen, elen_wire, entry_len;

        /* Each entry is at least 3 bytes (length + info word). */
        if (pos + 3 > off + len)
            break;
        elen_wire = tvb_get_uint8(tvb, pos);
        /* spec value is 3h; clamp to guarantee forward progress */
        elen = MAX(elen_wire, 3U);

        /* Clamp the entry item to the list data. */
        entry_len = elen;
        if (pos + entry_len > off + len)
            entry_len = off + len - pos;

        e_ti = proto_tree_add_item(ae_tree, hf->entry,
                                   tvb, pos, entry_len, ENC_NA);
        proto_item_set_text(e_ti, "%s %u", hf->entry_name, i);
        e_tree = proto_item_add_subtree(e_ti, ett_nvme_mi_mi_field);
        el_ti = proto_tree_add_uint(e_tree, hf->entry_len, tvb, pos, 1, elen_wire);
        if (hf->supported && elen_wire != 3)
            expert_add_info_format(pinfo, el_ti, &ei_nvme_mi_mi_aes_field_invalid,
                "AESL shall be set to 3h (NVMe-MI 'AE Supported Data Structure')");
        proto_tree_add_item(e_tree, hf->flag,
                            tvb, pos + 1, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(e_tree, hf->rsvd, tvb, pos + 1, 2,
                            ENC_LITTLE_ENDIAN);
        proto_tree_add_item(e_tree, hf->id,
                            tvb, pos + 1, 2, ENC_LITTLE_ENDIAN);
        pos += elen;
        body_len += elen;
    }

    /* Figures 82/83: the Supported List's lengths are a "shall".  Figure 91
     * states AEETL only as a "should"; 5.2.4 has the ME ignore the rest. */
    if (hf->supported || i < num || hdr_len + body_len > len)
        nvme_mi_mi_list_check(pinfo, tl_ti, &ei_nvme_mi_mi_ae_list_invalid,
                              hf->entry_name, i, num, total_len, hdr_len,
                              body_len, len);
    else if (total_len != hdr_len + body_len)
        expert_add_info_format(pinfo, tl_ti, &ei_nvme_mi_mi_ae_aeetl_mismatch,
                               "AEETL %u should equal AEELHL plus the AE Enable"
                               " entries, %u bytes (NVMe-MI 'AE Enable List Data Structure')",
                               total_len, hdr_len + body_len);
    if (pos < off + len)
        proto_tree_add_item(ae_tree, hf_nvme_mi_mi_data, tvb, pos,
                            off + len - pos, ENC_NA);
}

/* AE Enable List (Configuration Set request data). */
static void
dissect_nvme_mi_mi_ae_enable_list(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, proto_item *it,
                                  unsigned off, unsigned len)
{
    const struct nvme_mi_mi_ae_list_hf hf = {
        hf_nvme_mi_mi_ae,        hf_nvme_mi_mi_ae_numaee,
        hf_nvme_mi_mi_ae_aeelver, hf_nvme_mi_mi_ae_aeetl,
        hf_nvme_mi_mi_ae_aeelhl, hf_nvme_mi_mi_ae_entry,
        hf_nvme_mi_mi_ae_aeel,   hf_nvme_mi_mi_ae_aee,
        hf_nvme_mi_mi_ae_id,     hf_nvme_mi_mi_ae_aee_rsvd,
        "AE Enable",             false,
    };

    dissect_nvme_mi_mi_ae_list(tvb, pinfo, tree, it, off, len, &hf);
}

/* AE Supported List (Configuration Get response data). */
static void
dissect_nvme_mi_mi_ae_supported_list(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, proto_item *it,
                                     unsigned off, unsigned len)
{
    const struct nvme_mi_mi_ae_list_hf hf = {
        hf_nvme_mi_mi_aes,        hf_nvme_mi_mi_aes_numaes,
        hf_nvme_mi_mi_aes_aeslver, hf_nvme_mi_mi_aes_aestl,
        hf_nvme_mi_mi_aes_aeslhl, hf_nvme_mi_mi_aes_entry,
        hf_nvme_mi_mi_aes_aesl,   hf_nvme_mi_mi_aes_aese,
        hf_nvme_mi_mi_aes_id,     hf_nvme_mi_mi_aes_aese_rsvd,
        "AE Supported",           true,
    };

    dissect_nvme_mi_mi_ae_list(tvb, pinfo, tree, it, off, len, &hf);
}

/* AE Occurrence Scope ID Info (NVMe-MI 2.2 Figure 64), by scope. */
static void
dissect_nvme_mi_mi_aeo_scope_id(tvbuff_t *tvb, proto_tree *tree,
                                unsigned pos, uint32_t scope)
{
    int rsvd_hf = -1;

    switch (scope) {
    case NVME_MI_AEO_SCOPE_NAMESPACE:
        proto_tree_add_item(tree, hf_nvme_mi_mi_aeo_aeonsid, tvb, pos, 4,
                            ENC_LITTLE_ENDIAN);
        break;
    case NVME_MI_AEO_SCOPE_CONTROLLER:
        proto_tree_add_item(tree, hf_nvme_mi_mi_aeo_aeocid, tvb, pos, 4,
                            ENC_LITTLE_ENDIAN);
        rsvd_hf = hf_nvme_mi_mi_aeo_scope_rsvd;
        break;
    case NVME_MI_AEO_SCOPE_SUBSYSTEM:
        /* Figure 64: the whole dword is Reserved for this scope. */
        rsvd_hf = hf_nvme_mi_mi_aeo_subsys_rsvd;
        break;
    case NVME_MI_AEO_SCOPE_MGMT_EP:
        proto_tree_add_item(tree, hf_nvme_mi_mi_aeo_aeomeid, tvb, pos, 4,
                            ENC_LITTLE_ENDIAN);
        rsvd_hf = hf_nvme_mi_mi_aeo_meid_rsvd;
        break;
    case NVME_MI_AEO_SCOPE_PORT:
        proto_tree_add_item(tree, hf_nvme_mi_mi_aeo_aeopt, tvb, pos, 4,
                            ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_nvme_mi_mi_aeo_aeopid, tvb, pos, 4,
                            ENC_LITTLE_ENDIAN);
        rsvd_hf = hf_nvme_mi_mi_aeo_port_rsvd;
        break;
    case NVME_MI_AEO_SCOPE_ENDURANCE_GRP:
        proto_tree_add_item(tree, hf_nvme_mi_mi_aeo_aeoegid, tvb, pos, 4,
                            ENC_LITTLE_ENDIAN);
        rsvd_hf = hf_nvme_mi_mi_aeo_scope_rsvd;
        break;
    default:
        /* A reserved scope has no defined layout, so no breakout. */
        break;
    }
    /* Figure 64's Reserved bits. */
    if (rsvd_hf >= 0)
        proto_tree_add_item(tree, rsvd_hf, tvb, pos, 4, ENC_LITTLE_ENDIAN);
}

/* MI 2.2 Fig 65: exactly thirteen layouts. The enclosing occurrence, not any
 * earlier event or command, supplies the scope and scope identifier. */
static void
dissect_nvme_mi_mi_aeosi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_item *sil_ti, unsigned pos, unsigned len, unsigned id)
{
    /* Per AE ID 00h-0Dh: a leading field, the value, the Reserved bits.
     * 09h is a bitmask, 0Eh a power value and 0Fh a voltage value, all
     * handled below. */
    static int * const layout[0x0e][3] = {
        [0x00] = { NULL, &hf_nvme_mi_mi_aeosi_rv, &hf_nvme_mi_mi_aeosi_rsvd1 },
        [0x01] = { NULL, &hf_nvme_mi_mi_aeosi_cfsv, &hf_nvme_mi_mi_aeosi_rsvd1 },
        [0x02] = { &hf_nvme_mi_mi_aeosi_stv, &hf_nvme_mi_mi_aeosi_ssv,
                   &hf_nvme_mi_mi_aeosi_rsvd3 },
        [0x03] = { &hf_nvme_mi_mi_aeosi_crime, &hf_nvme_mi_mi_aeosi_cev,
                   &hf_nvme_mi_mi_aeosi_rsvd2 },
        [0x06] = { NULL, &hf_nvme_mi_mi_aeosi_ctv, NULL },
        [0x07] = { NULL, &hf_nvme_mi_mi_aeosi_puv, NULL },
        [0x08] = { NULL, &hf_nvme_mi_mi_aeosi_asv, NULL },
        [0x0b] = { NULL, &hf_nvme_mi_mi_aeosi_plav, &hf_nvme_mi_mi_aeosi_rsvd1 },
        [0x0c] = { NULL, &hf_nvme_mi_mi_aeosi_sfmv, &hf_nvme_mi_mi_aeosi_rsvd1 },
        [0x0d] = { NULL, &hf_nvme_mi_mi_aeosi_snfmv, &hf_nvme_mi_mi_aeosi_rsvd1 },
    };
    proto_tree *info = tree;
    unsigned expected;
    int * const *fields;
    int *reserved = NULL;

    if (len) {
        proto_item *ti = proto_tree_add_item(tree, hf_nvme_mi_mi_aeo_aeosi,
                                            tvb, pos, len, ENC_NA);
        info = proto_item_add_subtree(ti, ett_nvme_mi_mi_field);
    }
    if (id >= 0xC0 && len) {
        expert_add_info_format(pinfo, sil_ti, &ei_nvme_mi_mi_response_data_length,
            "AEOSIL shall be 0h for a vendor specific AE (NVMe-MI 'AE Occurrence"
            " Data Structure', 'AE Occurrence Specific Info Data Structure')");
        return;
    }
    if (id > 0x0f)
        return;
    expected = (id == 4 || id == 5 || id == 10) ? 0 : (id >= 14 ? 4 : 1);
    if (len != expected) {
        expert_add_info_format(pinfo, sil_ti, &ei_nvme_mi_mi_response_data_length,
            "NVMe-MI 'AE Occurrence Specific Info Data Structure' defines %u"
            " Specific Info bytes for AE %#x, not %u",
            expected, id, len);
        return;
    }
    if (id == 0x09) {
        /* Figure 65 CWV: Figure 105's SMART Warnings bits. */
        proto_tree_add_bitmask(info, tvb, pos, hf_nvme_mi_mi_aeosi_cwv,
                               ett_nvme_mi_mi_field, nshds_sw_fields, ENC_NA);
    } else if (id == 0x0e) {
        uint32_t pwrs, pwrv;
        proto_item *pwrv_it;

        proto_tree_add_item(info, hf_nvme_mi_mi_aeosi_pmt, tvb, pos, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item_ret_uint(info, hf_nvme_mi_mi_aeosi_pwrs, tvb, pos, 4,
                                     ENC_LITTLE_ENDIAN, &pwrs);
        pwrv_it = proto_tree_add_item_ret_uint(info, hf_nvme_mi_mi_aeosi_pwrv, tvb, pos, 4,
                                               ENC_LITTLE_ENDIAN, &pwrv);
        /* Figure 65: Watts = Power Value x Power Scale; 00b, 11b Reserved. */
        if (pwrs == 1)
            proto_item_append_text(pwrv_it, " (%.4f W)", pwrv / 10000.0);
        else if (pwrs == 2)
            proto_item_append_text(pwrv_it, " (%.2f W)", pwrv / 100.0);
        reserved = &hf_nvme_mi_mi_aeosi_pwr_rsvd;
    } else if (id == 0x0f) {
        proto_item *ti = proto_tree_add_item(info, hf_nvme_mi_mi_aeosi_pwrid, tvb, pos, 4,
                                             ENC_LITTLE_ENDIAN);
        proto_tree *pwrid = proto_item_add_subtree(ti, ett_nvme_mi_mi_field);

        proto_tree_add_item(pwrid, hf_nvme_mi_mi_aeosi_pwril, tvb, pos, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pwrid, hf_nvme_mi_mi_aeosi_pwriv, tvb, pos, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(info, hf_nvme_mi_mi_aeosi_vsent, tvb, pos, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(info, hf_nvme_mi_mi_aeosi_vtht, tvb, pos, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(info, hf_nvme_mi_mi_aeosi_volv, tvb, pos, 4, ENC_LITTLE_ENDIAN);
    } else {
        fields = layout[id];
        if (fields[0])
            proto_tree_add_item(info, *fields[0], tvb, pos, 1, ENC_LITTLE_ENDIAN);
        if (fields[1])
            proto_tree_add_item(info, *fields[1], tvb, pos, 1, ENC_LITTLE_ENDIAN);
        reserved = fields[2];
    }
    if (reserved)
        proto_tree_add_item(info, *reserved, tvb, pos, len, ENC_LITTLE_ENDIAN);
}

/* Scopes each AE 00h-0Fh is reported with (NVMe-MI 2.2 Figure 63), as
 * bits indexed by AESS. */
#define AEO_SCOPE(s) (1U << NVME_MI_AEO_SCOPE_##s)
static const uint8_t mi_aeo_id_scopes[0x10] = {
    [0x00] = AEO_SCOPE(CONTROLLER),
    [0x01] = AEO_SCOPE(CONTROLLER),
    [0x02] = AEO_SCOPE(CONTROLLER) | AEO_SCOPE(SUBSYSTEM),
    [0x03] = AEO_SCOPE(CONTROLLER),
    [0x04] = AEO_SCOPE(CONTROLLER),
    [0x05] = AEO_SCOPE(SUBSYSTEM),
    [0x06] = AEO_SCOPE(SUBSYSTEM),
    [0x07] = AEO_SCOPE(SUBSYSTEM),
    [0x08] = AEO_SCOPE(SUBSYSTEM),
    [0x09] = AEO_SCOPE(SUBSYSTEM),
    [0x0a] = AEO_SCOPE(CONTROLLER) | AEO_SCOPE(SUBSYSTEM),
    [0x0b] = AEO_SCOPE(PORT),
    [0x0c] = AEO_SCOPE(SUBSYSTEM),
    [0x0d] = AEO_SCOPE(NAMESPACE),
    [0x0e] = AEO_SCOPE(CONTROLLER),
    [0x0f] = AEO_SCOPE(CONTROLLER),
};
#undef AEO_SCOPE

/* Reserved AEOI and AESS values, the AE-to-scope pairing (Figure 63) and
 * the port rules (Figures 63 and 64); vendor specific AEs are not checked. */
static void
nvme_mi_mi_aeo_check(tvbuff_t *tvb, packet_info *pinfo, unsigned pos,
                     uint32_t aeoi, uint32_t scope, proto_item *aeoi_ti,
                     proto_item *aess_ti, proto_item *ui_ti)
{
    if (aeoi >= 0x10 && aeoi <= 0xbf)
        expert_add_info_format(pinfo, aeoi_ti, &ei_nvme_mi_mi_reserved_value,
                               "AE Occurrence ID 0x%02x is Reserved (NVMe-MI"
                               " 'Asynchronous Events')", aeoi);
    if (scope > NVME_MI_AEO_SCOPE_ENDURANCE_GRP) {
        expert_add_info_format(pinfo, aess_ti, &ei_nvme_mi_mi_reserved_value,
                               "AE Occurrence Scope 0x%x is Reserved (NVMe-MI"
                               " 'AE Occurrence Data Structure')", scope);
        return;
    }
    if (aeoi < array_length(mi_aeo_id_scopes) &&
        !(mi_aeo_id_scopes[aeoi] & (1U << scope)))
        expert_add_info_format(pinfo, aess_ti, &ei_nvme_mi_mi_aeo_field_invalid,
                               "%s is not reported with %s scope (NVMe-MI"
                               " 'Asynchronous Events')",
                               rval_to_str_const(aeoi, mi_ae_id_vals,
                                                 "Reserved"),
                               rval_to_str_const(scope, mi_aeo_scope_vals,
                                                 "Reserved"));
    if (scope == NVME_MI_AEO_SCOPE_PORT) {
        uint32_t psi = tvb_get_letohl(tvb, pos + 4);
        bool aeopt = (psi & 0x00010000) != 0;

        if (aeoi == 0x0b && !aeopt)
            expert_add_info_format(pinfo, ui_ti,
                                   &ei_nvme_mi_mi_aeo_field_invalid,
                                   "PCIe Link Active shall set AEOPT to 1"
                                   " (NVMe-MI 'Asynchronous Events')");
        if (aeopt && (psi & 0x0000ff00))
            expert_add_info_format(pinfo, ui_ti,
                                   &ei_nvme_mi_mi_aeo_field_invalid,
                                   "The most-significant byte of AEOPID shall"
                                   " be cleared to 0h when AEOPT is 1 (NVMe-MI"
                                   " 'AE Occurrence Scope ID Info Field Format')");
    }
}

/* AE Occurrence List (NVMe-MI 2.2 Figures 61/62): Configuration Set
 * response data, or the whole AEM body (4.4.4).  AEMTI is checked
 * cleared only when !is_aem.  7-byte header; the entry stride is
 * AELHLEN + AEOSIL + AEOVSIL. */
static void
dissect_nvme_mi_mi_aeo_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            proto_item *it, unsigned off, unsigned len,
                            bool is_aem)
{
    proto_tree *ae_tree, *hdr_tree;
    proto_item *ti, *tl_ti, *aemti_ti, *aelver_ti, *hl_ti;
    uint32_t num, hdr_len, aeolli, total_len, i;
    unsigned pos, body_len = 0;
    bool overflow;

    ti = proto_tree_add_item(tree, hf_nvme_mi_mi_aeo_list, tvb, off, len,
                             ENC_NA);
    ae_tree = proto_item_add_subtree(ti, ett_nvme_mi_mi);

    if (len < NVME_MI_AEO_LIST_HDR_LEN) {
        nvme_mi_mi_data_truncated(tvb, pinfo, ae_tree, it, off);
        return;
    }

    proto_tree_add_item_ret_uint(ae_tree, hf_nvme_mi_mi_aeo_numaeo,
                                 tvb, off, 1, ENC_LITTLE_ENDIAN, &num);
    aelver_ti = proto_tree_add_item(ae_tree, hf_nvme_mi_mi_aeo_aelver, tvb,
                                    off + 1, 1, ENC_LITTLE_ENDIAN);
    /* Figure 61: AELVER shall be cleared to 0h. */
    if (tvb_get_uint8(tvb, off + 1))
        expert_add_info_format(pinfo, aelver_ti, &ei_nvme_mi_mi_aeo_list_invalid,
                               "AELVER shall be cleared to 0h (NVMe-MI 'AE"
                               " Occurrence List Data Structure')");

    /* Bytes 4:2 are one 24-bit field: bit 23 is the overflow flag, 22:00 the
     * total length. */
    proto_tree_add_item_ret_uint(ae_tree, hf_nvme_mi_mi_aeo_aeolli, tvb,
                                 off + 2, 3, ENC_LITTLE_ENDIAN, &aeolli);
    proto_tree_add_item(ae_tree, hf_nvme_mi_mi_aeo_aeolo, tvb, off + 2, 3,
                        ENC_LITTLE_ENDIAN);
    tl_ti = proto_tree_add_item_ret_uint(ae_tree, hf_nvme_mi_mi_aeo_aeoltl,
                                         tvb, off + 2, 3, ENC_LITTLE_ENDIAN,
                                         &total_len);
    overflow = (aeolli & 0x800000) != 0;

    hl_ti = proto_tree_add_item_ret_uint(ae_tree, hf_nvme_mi_mi_aeo_aeolhl,
                                         tvb, off + 5, 1, ENC_LITTLE_ENDIAN,
                                         &hdr_len);
    if (hdr_len != NVME_MI_AEO_LIST_HDR_LEN)
        expert_add_info_format(pinfo, hl_ti, &ei_nvme_mi_mi_aeo_field_invalid,
                               "AEOLHL shall be set to 7h (NVMe-MI"
                               " 'AE Occurrence List Data Structure')");

    aemti_ti = proto_tree_add_item(ae_tree, hf_nvme_mi_mi_aeo_aemti,
                                   tvb, off + 6, 1, ENC_LITTLE_ENDIAN);
    hdr_tree = proto_item_add_subtree(aemti_ti, ett_nvme_mi_mi_field);
    proto_tree_add_item(hdr_tree, hf_nvme_mi_mi_aeo_aemgn, tvb, off + 6, 1,
                        ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_nvme_mi_mi_aeo_aemrc, tvb, off + 6, 1,
                        ENC_LITTLE_ENDIAN);
    /* Figure 61: AEMTI is not applicable outside an AEM, and cleared. */
    if (!is_aem && tvb_get_uint8(tvb, off + 6))
        expert_add_info_format(pinfo, aemti_ti, &ei_nvme_mi_mi_aeo_list_invalid,
                               "AEMTI shall be cleared to 0h in a response to"
                               " an AEM Ack or AE Sync (NVMe-MI 'AE Occurrence"
                               " List Data Structure')");

    /* AEOLHL is 7h.  A shorter value would start the body inside the header,
     * so clamp forward to keep the walk in the body. */
    if (hdr_len < NVME_MI_AEO_LIST_HDR_LEN)
        hdr_len = NVME_MI_AEO_LIST_HDR_LEN;

    /* AEM only: the occurrence count. */
    if (is_aem) {
        if (overflow)
            col_append_str(pinfo->cinfo, COL_INFO, " (list overflow)");
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%u AE occurrence%s)",
                            num, num == 1 ? "" : "s");
    }

    /* Figure 61: on overflow there is no body.  Bytes past the header lie
     * outside AEOLTL and are shown raw, as after any other list. */
    if (overflow) {
        if (total_len != 0 || num != 0)
            expert_add_info_format(pinfo, tl_ti, &ei_nvme_mi_mi_aeo_list_invalid,
                "An overflowed AE Occurrence List shall have AEOLTL 0h and"
                " NUMAEO 0h (NVMe-MI 'AE Occurrence List Data Structure', section 4.4.4)");
        if (len > NVME_MI_AEO_LIST_HDR_LEN)
            proto_tree_add_item(ae_tree, hf_nvme_mi_mi_data, tvb,
                off + NVME_MI_AEO_LIST_HDR_LEN,
                len - NVME_MI_AEO_LIST_HDR_LEN, ENC_NA);
        return;
    }

    /* A longer header is honored; its extra bytes have no definition. */
    if (hdr_len > NVME_MI_AEO_LIST_HDR_LEN && len > NVME_MI_AEO_LIST_HDR_LEN)
        proto_tree_add_item(ae_tree, hf_nvme_mi_mi_aeo_hdr_unknown, tvb,
                            off + NVME_MI_AEO_LIST_HDR_LEN,
                            MIN(hdr_len, len) - NVME_MI_AEO_LIST_HDR_LEN,
                            ENC_NA);

    pos = off + hdr_len;
    for (i = 0; i < num; i++) {
        proto_tree *e_tree, *ui_tree, *ss_tree;
        proto_item *e_ti, *ui_ti, *ss_ti;
        proto_item *sil_ti, *el_ti, *aeoi_ti, *aess_ti;
        uint32_t elen, aeosil, aeovsil, aeoi, aeocidi, scope, stride;
        unsigned body;

        /* Stop before an occurrence whose fixed header does not fit. */
        if (pos + NVME_MI_AEO_ENTRY_HDR_LEN > off + len)
            break;

        e_ti = proto_tree_add_item(ae_tree, hf_nvme_mi_mi_aeo_entry, tvb, pos,
                                   NVME_MI_AEO_ENTRY_HDR_LEN, ENC_NA);
        e_tree = proto_item_add_subtree(e_ti, ett_nvme_mi_mi_entry);

        el_ti = proto_tree_add_item_ret_uint(e_tree, hf_nvme_mi_mi_aeo_aelhlen,
                                             tvb, pos, 1, ENC_LITTLE_ENDIAN,
                                             &elen);
        if (elen != NVME_MI_AEO_ENTRY_HDR_LEN)
            expert_add_info_format(pinfo, el_ti,
                                   &ei_nvme_mi_mi_aeo_field_invalid,
                                   "AELHLEN shall be set to 9h (NVMe-MI"
                                   " 'AE Occurrence Data Structure')");
        sil_ti = proto_tree_add_item_ret_uint(e_tree, hf_nvme_mi_mi_aeo_aeosil,
                                              tvb, pos + 1, 1,
                                              ENC_LITTLE_ENDIAN, &aeosil);
        proto_tree_add_item_ret_uint(e_tree, hf_nvme_mi_mi_aeo_aeovsil, tvb,
                                     pos + 2, 1, ENC_LITTLE_ENDIAN, &aeovsil);

        /* AELHLEN is 9h.  Clamping a short value up also guarantees the
         * stride below is non-zero, so the walk advances. */
        if (elen < NVME_MI_AEO_ENTRY_HDR_LEN)
            elen = NVME_MI_AEO_ENTRY_HDR_LEN;

        /* AEOUI: AE Occurrence ID, the scope-selected Scope ID Info, and the
         * scope itself (Figure 62). */
        ui_ti = proto_tree_add_item(e_tree, hf_nvme_mi_mi_aeo_aeoui, tvb,
                                    pos + 3, 6, ENC_NA);
        ui_tree = proto_item_add_subtree(ui_ti, ett_nvme_mi_mi_field);
        aeoi_ti = proto_tree_add_item_ret_uint(ui_tree, hf_nvme_mi_mi_aeo_aeoi,
                                               tvb, pos + 3, 1,
                                               ENC_LITTLE_ENDIAN, &aeoi);
        proto_tree_add_item_ret_uint(ui_tree, hf_nvme_mi_mi_aeo_aeocidi, tvb,
                                     pos + 4, 4, ENC_LITTLE_ENDIAN, &aeocidi);
        ss_ti = proto_tree_add_item(ui_tree, hf_nvme_mi_mi_aeo_aessi, tvb,
                                    pos + 8, 1, ENC_LITTLE_ENDIAN);
        ss_tree = proto_item_add_subtree(ss_ti, ett_nvme_mi_mi_field);
        aess_ti = proto_tree_add_item_ret_uint(ss_tree, hf_nvme_mi_mi_aeo_aess,
                                               tvb, pos + 8, 1,
                                               ENC_LITTLE_ENDIAN, &scope);
        proto_tree_add_item(ss_tree, hf_nvme_mi_mi_aeo_aessi_rsvd, tvb, pos + 8,
                            1, ENC_LITTLE_ENDIAN);

        dissect_nvme_mi_mi_aeo_scope_id(tvb, ui_tree, pos + 4, scope);
        nvme_mi_mi_aeo_check(tvb, pinfo, pos, aeoi, scope, aeoi_ti, aess_ti,
                             ui_ti);

        /* A longer occurrence header is honored; its extra bytes have no
         * definition. */
        if (elen > NVME_MI_AEO_ENTRY_HDR_LEN &&
            pos + NVME_MI_AEO_ENTRY_HDR_LEN < off + len)
            proto_tree_add_item(e_tree, hf_nvme_mi_mi_aeo_hdr_unknown, tvb,
                                pos + NVME_MI_AEO_ENTRY_HDR_LEN,
                                MIN(pos + elen, off + len) -
                                    (pos + NVME_MI_AEO_ENTRY_HDR_LEN),
                                ENC_NA);

        proto_item_set_text(e_ti, "AE Occurrence %u: %s (%s)", i,
                            rval_to_str_const(aeoi, mi_ae_id_vals, "Reserved"),
                            rval_to_str_const(scope, mi_aeo_scope_vals,
                                              "Reserved"));

        /* Figure 62: the occurrence spans its header plus both optional
         * payloads; clamp the item to what is present. */
        stride = elen + aeosil + aeovsil;
        proto_item_set_len(e_ti, MIN(stride, off + len - pos));

        body = pos + elen;
        if (body + aeosil <= off + len)
            dissect_nvme_mi_mi_aeosi(tvb, pinfo, e_tree, sil_ti, body, aeosil, aeoi);
        body += aeosil;
        if (aeovsil && body + aeovsil <= off + len) {
            proto_tree *vs_tree;

            ti = proto_tree_add_item(e_tree, hf_nvme_mi_mi_aeo_aeovsi, tvb,
                                     body, aeovsil, ENC_NA);
            vs_tree = proto_item_add_subtree(ti, ett_nvme_mi_mi_field);
            proto_tree_add_item(vs_tree, hf_nvme_mi_mi_aeo_aeovsh, tvb,
                                body, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(vs_tree, hf_nvme_mi_mi_aeo_aeovsui, tvb,
                                body, 1, ENC_LITTLE_ENDIAN);
            if (aeovsil > 1)
                proto_tree_add_item(vs_tree, hf_nvme_mi_mi_aeo_aeovs_data, tvb,
                                    body + 1, aeovsil - 1, ENC_NA);
        }

        pos += stride;
        body_len += stride;
    }

    /* AEOLTL is the header length plus every occurrence (Figure 61), and the
     * list is minimally sized (4.4.4, 5.2.4). */
    nvme_mi_mi_list_check(pinfo, tl_ti, &ei_nvme_mi_mi_aeo_list_invalid,
                          "AE Occurrence", i, num, total_len, hdr_len, body_len, len);
    if (pos < off + len)
        proto_tree_add_item(ae_tree, hf_nvme_mi_mi_data, tvb, pos,
                            off + len - pos, ENC_NA);
}

/* Admit MEB observations, or decline: from the message bytes,
 * the transaction and the integrity verdicts, independent of the tree.
 * Declining raises no expert. */
void
nvme_mi_mi_pre_observe(tvbuff_t *tvb, packet_info *pinfo,
                       const struct nvme_mi_dissect_ctx *ctx)
{
    const struct nvme_mi_mi_req_ctx *req;
    const struct nvme_mi_transaction *trans;
    struct nvme_mi_endpoint *ep;
    unsigned opcode, len;

    /* Only a response advertises anything. */
    if (!ctx || !ctx->resp || !ctx->admitted || ctx->replay)
        return;

    trans = ctx->trans;
    ep    = ctx->endpoint;
    len   = tvb_reported_length(tvb);

    /* An endpoint, and a response whose MIC verified (section 3.2.1.1). */
    if (!ep || !ctx->integrity_ok)
        return;

    /* A matched request of this NMIMT whose opcode was recorded. */
    if (!nvme_mi_resp_opcode(trans, NVME_MI_TYPE_MI, &opcode))
        return;
    if (opcode != NVME_MI_MI_OPC_READ_DS)
        return;

    /* The request's MIC passed too. */
    if (!trans->req_integrity_ok)
        return;

    /* The request context, published only once its selectors were read. */
    req = (const struct nvme_mi_mi_req_ctx *)trans->body_ctx;
    if (!req)
        return;

    /* A Success Response. */
    if (!tvb_bytes_exist(tvb, 0, 4))
        return;
    if (tvb_get_uint8(tvb, 0) != NVME_MI_STATUS_SUCCESS)
        return;

    /* Complete and MIC-good only; never learn from data that belonged in MEB. */
    if (trans->req_meb &&
        nvme_mi_meb_routes(ep, trans->req_frame, opcode))
        return;
    unsigned rdl = tvb_get_letohs(tvb, 1);
    if (len != 4 + rdl || !tvb_bytes_exist(tvb, 4, rdl))
        return;
    if (req->dtyp == NVME_MI_DTYP_PORT_INFO) {
        /* Fig 119's CMEADDR matches the physical responder (Fig 117 allows
         * other ports); EIDs and unproven port mappings do not count. */
        uint8_t src7, dst7;

        if (rdl == 32 && tvb_get_uint8(tvb, 4) == 2 &&
            mctp_smbus_slave_addr(&pinfo->net_src, &src7) &&
            mctp_smbus_slave_addr(&pinfo->net_dst, &dst7) &&
            tvb_get_uint8(tvb, 14) != 0) {
            bool eight_bit;

            if (nvme_mi_twire_addr_matches(tvb_get_uint8(tvb, 14), src7,
                                           &eight_bit))
                nvme_mi_mebs_observe(ep, pinfo, req->port,
                                     tvb_get_letohl(tvb, 8));
        }
        return;
    }
    if (req->dtyp == NVME_MI_DTYP_MEB_LIST) {
        if (rdl < 2)
            return;
        unsigned count = tvb_get_letohs(tvb, 4);
        if (count > 2047 || rdl != 2 + 2 * count)
            return;
        uint8_t commands[32] = { 0 };
        for (unsigned n = 0; n < count; n++) {
            uint8_t ctyp = tvb_get_uint8(tvb, 6 + 2 * n);
            uint8_t opc = tvb_get_uint8(tvb, 7 + 2 * n);
            /* Figs 123/124; only MI opcodes are retained. */
            if ((ctyp & 0x87) ||
                (ctyp != (NVME_MI_TYPE_MI << 3) &&
                 ctyp != (NVME_MI_TYPE_ADMIN << 3) &&
                 ctyp != (NVME_MI_TYPE_PCIE << 3)))
                return;
            if (ctyp == (NVME_MI_TYPE_MI << 3))
                commands[opc / 8] |= (uint8_t)(1U << (opc % 8));
        }
        nvme_mi_meb_commands_observe(ep, pinfo, req->port, commands);
    }
}

static int
dissect_nvme_mi_mi_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mi_tree,
                            proto_item *it, unsigned len,
                            const struct nvme_mi_dissect_ctx *ctx,
                            struct nvme_mi_transaction *trans,
                            enum nvme_mi_mi_data_routing routing)
{
    /* Recover the opcode from the matching request, tree or no tree. */
    unsigned opcode;
    bool opcode_known =
        nvme_mi_recover_resp_opcode(tvb, pinfo, mi_tree, it, trans,
                                    NVME_MI_TYPE_MI, hf_nvme_mi_mi_opcode,
                                    &ei_nvme_mi_mi_orphan_response,
                                    &opcode, NULL);
    const struct nvme_mi_mi_req_ctx *req = opcode_known
            ? (const struct nvme_mi_mi_req_ctx *)trans->body_ctx : NULL;
    const char *detail = NULL;
    uint8_t status;

    if (opcode_known) {
        if (req) {
            if (opcode == NVME_MI_MI_OPC_READ_DS)
                detail = rval_to_str_const(req->dtyp, mi_dtyp_vals,
                                          "Reserved");
            else if (opcode == NVME_MI_MI_OPC_CONFIG_SET ||
                     opcode == NVME_MI_MI_OPC_CONFIG_GET) {
                detail = nvme_mi_mi_configid_detail(pinfo, req->configid,
                                                    req->ae_variant);
            }
        }
        nvme_mi_mi_col_append(pinfo, opcode, detail);
    }

    if (len < 1) {
        expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item_ret_uint8(mi_tree, hf_nvme_mi_mi_status,
                                  tvb, 0, 1, ENC_NA, &status);

    if (len < 4) {
        nvme_mi_mi_data_truncated(tvb, pinfo, mi_tree, it, 1);
        return tvb_captured_length(tvb);
    }

    /* NMRESP and Response Data exist only on Success (Figures 30-34). */
    bool success = nvme_mi_dissect_resp_status_bytes(tvb, pinfo, mi_tree,
                                                     status);
    if (success && trans && trans->reset_nvm_subsystem)
        expert_add_info(pinfo, it, &ei_nvme_mi_mi_reset_response);

    if (success) {
        uint32_t rsvd_mask = opcode_known
                ? nvme_mi_mi_nmresp_rsvd_mask(opcode, req) : 0;
        uint32_t nmresp;

        proto_tree_add_item_ret_uint(mi_tree,
                                     rsvd_mask == 0xFFFFFF ? hf_nvme_mi_mi_nmresp_rsvd
                                                           : hf_nvme_mi_mi_nmresp,
                                     tvb, 1, 3, ENC_LITTLE_ENDIAN, &nmresp);
        if (rsvd_mask != 0xFFFFFF)
            nvme_mi_mi_show_reserved(tvb, mi_tree,
                                     hf_nvme_mi_mi_nmresp_rsvd_bits, 1, 3,
                                     nmresp, rsvd_mask);
    }

    if (success && opcode_known) {
        switch (opcode) {
        case NVME_MI_MI_OPC_READ_DS:
            /* NMRESP bits 15:0 = Response Data Length (Read NVMe-MI
             * Data Structure NVMe Management Response) */
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_rds_rdl,
                                tvb, 1, 2, ENC_LITTLE_ENDIAN);
            break;
        case NVME_MI_MI_OPC_SES_RECV: {
            /* Figure 128: RDL covers inline or MEB-routed data. */
            uint32_t rdl;

            proto_tree_add_item_ret_uint(mi_tree, hf_nvme_mi_mi_ses_rdl,
                                         tvb, 1, 2, ENC_LITTLE_ENDIAN, &rdl);
            if (req && rdl > req->dlen)
                proto_tree_add_expert_format(mi_tree, pinfo,
                    &ei_nvme_mi_mi_response_data_length, tvb, 1, 2,
                    "RDL %u exceeds the request's ALENGTH %u",
                    rdl, req->dlen);
            break;
        }
        case NVME_MI_MI_OPC_CTRL_HSP:
            /* NMRESP bits 23:16 = Response Entries (Controller Health
             * Status Poll NVMe Management Response) */
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_chsp_rent,
                                tvb, 3, 1, ENC_NA);
            break;
        case NVME_MI_MI_OPC_CONFIG_GET:
            if (!req)
                break;
            switch (req->configid) {
            case NVME_MI_CFGID_SMBUS_FREQ:
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cfg_sfreq_cur,
                                    tvb, 1, 1, ENC_NA);
                break;
            case NVME_MI_CFGID_MTUS:
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cfg_mtus_cur,
                                    tvb, 1, 2, ENC_LITTLE_ENDIAN);
                break;
            case NVME_MI_CFGID_AE: {
                /* Figure 81's AEELVER, not Figure 91's. */
                proto_item *ver_ti;
                uint32_t aeelver;

                ver_ti = proto_tree_add_item_ret_uint(mi_tree,
                        hf_nvme_mi_mi_cfg_aeelver, tvb, 1, 1, ENC_NA,
                        &aeelver);
                if (aeelver != 0)
                    expert_add_info(pinfo, ver_ti, &ei_nvme_mi_mi_cfg_aeelver);
                break;
            }
            default:
                break;
            }
            break;
        default:
            break;
        }
    }

    /* Figures 81/82, 61/91, 100, 105, 114, 128: data is required, when
     * inline. */
    bool missing_data = len == 4 && success && opcode_known &&
        routing == NVME_MI_MI_DATA_INLINE &&
        (opcode == NVME_MI_MI_OPC_SUBSYS_HSP ||
         ((opcode == NVME_MI_MI_OPC_READ_DS ||
           opcode == NVME_MI_MI_OPC_SES_RECV) && tvb_get_letohs(tvb, 1) > 0) ||
         (opcode == NVME_MI_MI_OPC_MEB_READ && req && req->dlen > 0) ||
         (opcode == NVME_MI_MI_OPC_PDA_READ && req && req->pda_bytes_known &&
          req->pda_bytes > 0) ||
         (req && req->configid == NVME_MI_CFGID_AE &&
          (opcode == NVME_MI_MI_OPC_CONFIG_SET ||
           opcode == NVME_MI_MI_OPC_CONFIG_GET)));
    if (missing_data)
        expert_add_info_format(pinfo, it, &ei_nvme_mi_mi_response_data_length,
                               "Successful MI response omits mandatory"
                               " Response Data");

    if (len > 4 || (!missing_data && success && opcode_known &&
                   routing == NVME_MI_MI_DATA_INLINE &&
                   (opcode == NVME_MI_MI_OPC_READ_DS ||
                    opcode == NVME_MI_MI_OPC_CTRL_HSP ||
                    (opcode == NVME_MI_MI_OPC_VPD_READ && req)))) {
        int dlen = (int)len - 4;
        bool reconcile = routing == NVME_MI_MI_DATA_INLINE;

        if (success && routing == NVME_MI_MI_DATA_MEB &&
            ctx->admitted && ctx->integrity_ok) {
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                tvb, 4, -1, ENC_NA);
            return tvb_captured_length(tvb);
        }
        /* Response Data is only defined for a Success response of a known
         * opcode; everything else (errors, MPR, orphan) renders raw. */
        if (success && opcode_known) {
            switch (opcode) {
            case NVME_MI_MI_OPC_READ_DS:
                nvme_mi_mi_data_read_ds(tvb, pinfo, mi_tree, it,
                                        4, dlen, req, reconcile);
                break;
            case NVME_MI_MI_OPC_SUBSYS_HSP:
                nvme_mi_mi_data_nshds(tvb, pinfo, mi_tree, it,
                                      4, dlen, reconcile);
                break;
            case NVME_MI_MI_OPC_CTRL_HSP:
                nvme_mi_mi_data_chds_list(tvb, pinfo, mi_tree, it,
                    4, dlen, tvb_get_uint8(tvb, 3), reconcile);
                break;
            case NVME_MI_MI_OPC_CONFIG_GET:
                /* Only the Asynchronous Event configuration returns
                 * Response Data: the AE Supported List. */
                if (req && req->configid == NVME_MI_CFGID_AE)
                    dissect_nvme_mi_mi_ae_supported_list(tvb, pinfo,
                            mi_tree, it, 4, dlen);
                else if (req && req->configid == NVME_MI_CFGID_HSC)
                    /* NVMe-MI 2.2 5.1.2: Health Status Change completes
                     * with a Success Response and no Response Data. */
                    nvme_mi_mi_response_extent(tvb, pinfo, mi_tree, it,
                        4, dlen, 0, 0, "Health Status Change", reconcile);
                else
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                        tvb, 4, -1, ENC_NA);
                break;
            case NVME_MI_MI_OPC_CONFIG_SET:
                /* AE Occurrence List (NVMe-MI 2.2 Figure 61). */
                if (req && req->configid == NVME_MI_CFGID_AE)
                    dissect_nvme_mi_mi_aeo_list(tvb, pinfo, mi_tree, it,
                                                4, dlen, false);
                else
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                        tvb, 4, -1, ENC_NA);
                break;
            case NVME_MI_MI_OPC_VPD_READ: {
                /* Response Data is the requested window of VPD bytes
                 * (MI 2.2 Figs 132/133), not the entire FRU device. */
                bool extent_diagnosed = req && reconcile && dlen != req->dlen;
                if (req) {
                    dlen = nvme_mi_mi_response_extent(tvb, pinfo, mi_tree,
                        it, 4, dlen, req->dlen, -1, "DLEN", reconcile);
                }
                if (dlen > 0)
                    nvme_mi_mi_vpd_read(tvb, pinfo, mi_tree, 4, dlen, req,
                                        extent_diagnosed);
                break;
            }
            case NVME_MI_MI_OPC_SES_RECV:
                /* Figure 128: the page, truncated to ALENGTH; SES-4
                 * defines its layout, so it stays opaque. */
                dlen = nvme_mi_mi_response_extent(tvb, pinfo, mi_tree, it,
                    4, dlen, tvb_get_letohs(tvb, 1), -1, "RDL", reconcile);
                if (dlen > 0)
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_ses_page,
                                        tvb, 4, dlen, ENC_NA);
                break;
            case NVME_MI_MI_OPC_MEB_READ:
                /* Figure 100: exactly DLEN bytes of the buffer. */
                if (req)
                    dlen = nvme_mi_mi_response_extent(tvb, pinfo, mi_tree,
                        it, 4, dlen, req->dlen, -1, "DLEN", reconcile);
                if (dlen > 0)
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_meb_data,
                                        tvb, 4, dlen, ENC_NA);
                break;
            case NVME_MI_MI_OPC_PDA_READ:
                /* MI 2.2 5.7.1: DLEN units of DFORMAT from DOFST. */
                if (req && req->pda_bytes_known)
                    dlen = nvme_mi_mi_response_extent(tvb, pinfo, mi_tree,
                        it, 4, dlen, req->pda_bytes, -1, "DLEN", reconcile);
                if (dlen > 0)
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_pda_data,
                                        tvb, 4, dlen, ENC_NA);
                break;
            case NVME_MI_MI_OPC_PDA_WRITE:
            case NVME_MI_MI_OPC_PDA_WRITE_ZEROES:
            case NVME_MI_MI_OPC_VPD_WRITE:
            case NVME_MI_MI_OPC_RESET:
            case NVME_MI_MI_OPC_SES_SEND:
            case NVME_MI_MI_OPC_MEB_WRITE:
            case NVME_MI_MI_OPC_SHUTDOWN:
                /* No Response Data is defined (sections 5.5, 5.7.2, 5.7.3,
                 * 5.9, 5.11, 5.12 and 5.14). */
                nvme_mi_mi_response_extent(tvb, pinfo, mi_tree, it, 4, dlen,
                    0, 0, rval_to_str_const(opcode, mi_opcode_vals,
                                            "this command"), reconcile);
                break;
            default:
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                    tvb, 4, -1, ENC_NA);
                break;
            }
        } else if (!success && nvme_mi_status_has_response_format(status)) {
            /* Figures 30-34: the 4-byte body is the whole response. */
            proto_item *surplus = proto_tree_add_item(mi_tree,
                    hf_nvme_mi_mi_response_surplus, tvb, 4, -1, ENC_NA);
            expert_add_info_format(pinfo, surplus,
                                   &ei_nvme_mi_mi_error_surplus,
                                   "%d bytes follow the 4-byte %s Response",
                                   dlen,
                                   rval_to_str_const(status,
                                                     nvme_mi_status_vals,
                                                     "Error"));
        } else {
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                tvb, 4, -1, ENC_NA);
        }
    }

    return tvb_captured_length(tvb);
}

/* Whether the command defines Request Data (NVMe-MI 2.2 Figure 67 and the
 * per-command sections); reserved and vendor specific opcodes are unknown,
 * so allowed. */
static bool
nvme_mi_mi_req_has_request_data(uint8_t opcode, uint8_t configid)
{
    switch (opcode) {
    case NVME_MI_MI_OPC_CONFIG_SET:
        return configid == NVME_MI_CFGID_AE;
    case NVME_MI_MI_OPC_VPD_WRITE:
    case NVME_MI_MI_OPC_SES_SEND:
    case NVME_MI_MI_OPC_MEB_WRITE:
    case NVME_MI_MI_OPC_PDA_WRITE:
        return true;
    default:
        return opcode >= NVME_MI_MI_OPC_RESERVED_FIRST;
    }
}

static int
dissect_nvme_mi_mi_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mi_tree,
                           proto_item *it, unsigned len,
                           struct nvme_mi_transaction *trans,
                           enum nvme_mi_mi_data_routing routing)
{
    struct nvme_mi_mi_req_ctx *req = NULL;
    const char *detail = NULL;
    proto_item *cdw_it, *opc_it;
    uint8_t opcode;

    if (len < 1) {
        expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
        return tvb_captured_length(tvb);
    }

    opc_it = proto_tree_add_item_ret_uint8(mi_tree, hf_nvme_mi_mi_opcode,
                                           tvb, 0, 1, ENC_NA, &opcode);

    if (opcode >= NVME_MI_MI_OPC_RESERVED_FIRST &&
        opcode <= NVME_MI_MI_OPC_RESERVED_LAST)
        expert_add_info(pinfo, opc_it, &ei_nvme_mi_mi_reserved_opcode);

    /* The fixed twelve bytes must be reported before any selector is read. */
    if (len < 12) {
        nvme_mi_mi_col_append(pinfo, opcode, NULL);
        nvme_mi_mi_data_truncated(tvb, pinfo, mi_tree, it, 1);
        return tvb_captured_length(tvb);
    }

    /* Selectors are parsed into packet scope and published once below. */
    req = wmem_new0(pinfo->pool, struct nvme_mi_mi_req_ctx);

    if (opcode >= NVME_MI_MI_OPC_PDA_READ &&
        opcode <= NVME_MI_MI_OPC_PDA_WRITE_ZEROES) {
        /* MI 2.2 Figures 106/107: DFORMAT, then bytes 07:06 Reserved. */
        proto_item *df_it;
        uint8_t dformat;

        df_it = proto_tree_add_item_ret_uint8(mi_tree,
                    hf_nvme_mi_mi_pda_dformat, tvb, 1, 1, ENC_NA, &dformat);
        if (!nvme_mi_pda_unit(dformat))
            expert_add_info(pinfo, df_it, &ei_nvme_mi_mi_reserved_value);
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_pda_rsvd, tvb, 2, 2,
                            ENC_LITTLE_ENDIAN);
    } else {
        /* Figure 67: message bytes 07:05 are Reserved. */
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_rsvd, tvb, 1, 3,
                            ENC_LITTLE_ENDIAN);
    }

    switch (opcode) {
    case NVME_MI_MI_OPC_READ_DS: {
        uint64_t cdw0, cdw1;
        uint8_t dtyp;

        cdw_it = proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 4,
                hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field,
                rds_cdw0_fields, ENC_LITTLE_ENDIAN, &cdw0);
        dtyp = (uint8_t)(cdw0 >> 24);
        if (dtyp > NVME_MI_DTYP_MAX)
            expert_add_info(pinfo, cdw_it, &ei_nvme_mi_mi_reserved_dtyp);
        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 8, hf_nvme_mi_mi_cdw1,
                               ett_nvme_mi_mi_field, rds_cdw1_fields,
                               ENC_LITTLE_ENDIAN, &cdw1);
        req->dtyp       = dtyp;
        req->iocsi = (uint8_t)cdw1;
        req->port = (uint8_t)(cdw0 >> 16);
        detail = rval_to_str_const(dtyp, mi_dtyp_vals, "Reserved");
        break;
    }
    case NVME_MI_MI_OPC_SUBSYS_HSP:
        /* NMD0 is reserved for this command */
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw0,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(mi_tree, tvb, 8, hf_nvme_mi_mi_cdw1,
                               ett_nvme_mi_mi_field, nshsp_cdw1_fields,
                               ENC_LITTLE_ENDIAN);
        break;
    case NVME_MI_MI_OPC_CTRL_HSP:
        cdw_it = proto_tree_add_bitmask(mi_tree, tvb, 4,
                hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field,
                chsp_cdw0_fields, ENC_LITTLE_ENDIAN);
        /* MAXRENT, NMD0 bits 23:16, is 0's based with at most 255 entries
         * (Figure 94). */
        if (tvb_get_uint8(tvb, 6) == 0xFF)
            expert_add_info(pinfo, cdw_it, &ei_nvme_mi_mi_chsp_maxrent);
        proto_tree_add_bitmask(mi_tree, tvb, 8,
                hf_nvme_mi_mi_cdw1, ett_nvme_mi_mi_field,
                chsp_cdw1_fields, ENC_LITTLE_ENDIAN);
        break;
    case NVME_MI_MI_OPC_CONFIG_SET:
    case NVME_MI_MI_OPC_CONFIG_GET: {
        /* The CONFIGID value in NMD0 bits 7:0 selects the layout of the
         * surrounding configuration-specific fields, so peek it before
         * choosing which field array decodes the dword. */
        uint8_t cid = tvb_get_uint8(tvb, 4);
        bool set = opcode == NVME_MI_MI_OPC_CONFIG_SET;
        int * const *f0 = cfg_cdw0_fields_cid;
        int * const *f1 = NULL;
        /* 0 is AEM Ack, so mark it unknown until read. */
        req->ae_variant = NVME_MI_AE_VARIANT_UNKNOWN;

        switch (cid) {
        case NVME_MI_CFGID_SMBUS_FREQ:
            /* Figures 76 and 86; NMD1 reserved in both (5.1.1, 5.2.1). */
            f0 = set ? cfg_cdw0_fields_sfreq : cfg_cdw0_fields_port;
            break;
        case NVME_MI_CFGID_HSC:
            /* Figure 87 for a Set; 5.1.2 reserves both dwords for a Get. */
            if (set)
                f1 = cfg_cdw1_fields_hsc;
            break;
        case NVME_MI_CFGID_MTUS:
            /* Figures 78 and 88; Figure 89 for a Set's NMD1. */
            f0 = cfg_cdw0_fields_port;
            if (set)
                f1 = cfg_cdw1_fields_mtus;
            break;
        case NVME_MI_CFGID_AE:
            /* Figure 90 for a Set (bits 31:27), Figure 80 for a Get
             * (bits 31:08); NMD1 reserved either way (5.1.4, 5.2.4). */
            if (set)
                f0 = cfg_cdw0_fields_ae_set;
            break;
        default:
            break;
        }

        cdw_it = proto_tree_add_bitmask(mi_tree, tvb, 4,
                                        hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field, f0,
                                        ENC_LITTLE_ENDIAN);
        if (cid == 0 || (cid >= NVME_MI_CFGID_RESERVED_FIRST &&
                         cid <= NVME_MI_CFGID_RESERVED_LAST))
            expert_add_info(pinfo, cdw_it,
                            &ei_nvme_mi_mi_reserved_configid);
        if (f1)
            proto_tree_add_bitmask(mi_tree, tvb, 8, hf_nvme_mi_mi_cdw1,
                                   ett_nvme_mi_mi_field, f1, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw1,
                                tvb, 8, 4, ENC_LITTLE_ENDIAN);
        req->configid = cid;
        /* 5.2.4: NUMAEE 0h is an AEM Ack, otherwise an AE Sync.  Read before
         * the context is published. */
        if (opcode == NVME_MI_MI_OPC_CONFIG_SET &&
            cid == NVME_MI_CFGID_AE && len > 12 &&
            tvb_bytes_exist(tvb, 12, 1))
            req->ae_variant = tvb_get_uint8(tvb, 12)
                    ? NVME_MI_AE_VARIANT_SYNC : NVME_MI_AE_VARIANT_ACK;
        detail = nvme_mi_mi_configid_detail(pinfo, cid, req->ae_variant);
        break;
    }
    case NVME_MI_MI_OPC_VPD_READ:
    case NVME_MI_MI_OPC_VPD_WRITE: {
        /* DOFST in NMD0 bits 15:0, DLEN in NMD1 bits 15:0 (Figures
         * 131/132 and 134/135 - identical layouts). */
        uint64_t cdw0, cdw1;

        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 4,
                hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field,
                vpd_cdw0_fields, ENC_LITTLE_ENDIAN, &cdw0);
        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 8,
                hf_nvme_mi_mi_cdw1, ett_nvme_mi_mi_field,
                vpd_cdw1_fields, ENC_LITTLE_ENDIAN, &cdw1);
        detail = wmem_strdup_printf(pinfo->pool, "offset %u, %u bytes",
                                    (unsigned)(cdw0 & 0xFFFF),
                                    (unsigned)(cdw1 & 0xFFFF));
        req->dlen = (uint16_t)cdw1;
        req->dofst = (uint16_t)cdw0;
        break;
    }
    case NVME_MI_MI_OPC_RESET:
        detail = nvme_mi_mi_dissect_typebyte_req(tvb, pinfo, mi_tree,
                reset_cdw0_fields, NVME_MI_RSTTYP_MAX, mi_rsttyp_vals);
        break;
    case NVME_MI_MI_OPC_SHUTDOWN:
        detail = nvme_mi_mi_dissect_typebyte_req(tvb, pinfo, mi_tree,
                shutdown_cdw0_fields, NVME_MI_SHDNTYP_MAX,
                mi_shdntyp_vals);
        break;
    case NVME_MI_MI_OPC_SES_RECV: {
        /* Figures 126/127. */
        uint64_t cdw0, cdw1;

        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 4,
                hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field,
                ses_recv_cdw0_fields, ENC_LITTLE_ENDIAN, &cdw0);
        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 8,
                hf_nvme_mi_mi_cdw1, ett_nvme_mi_mi_field,
                ses_recv_cdw1_fields, ENC_LITTLE_ENDIAN, &cdw1);
        req->dlen = (uint16_t)cdw1;
        detail = wmem_strdup_printf(pinfo->pool, "page 0x%02x, up to %u bytes",
                                    (unsigned)(cdw0 & 0xFF), req->dlen);
        break;
    }
    case NVME_MI_MI_OPC_SES_SEND: {
        uint64_t ses_cdw1;

        /* Section 5.11: NMD0 is Reserved; Figure 129 for NMD1. */
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw0,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 8, hf_nvme_mi_mi_cdw1,
                                          ett_nvme_mi_mi_field, ses_send_cdw1_fields,
                                          ENC_LITTLE_ENDIAN, &ses_cdw1);
        req->dlen = (uint16_t)ses_cdw1;
        detail = wmem_strdup_printf(pinfo->pool, "%u bytes", req->dlen);
        break;
    }
    case NVME_MI_MI_OPC_MEB_READ:
    case NVME_MI_MI_OPC_MEB_WRITE: {
        /* Figures 99/100 and 102/103: a 32-bit DOFST. */
        uint64_t cdw0, cdw1;

        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 4,
                hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field,
                meb_cdw0_fields, ENC_LITTLE_ENDIAN, &cdw0);
        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 8,
                hf_nvme_mi_mi_cdw1, ett_nvme_mi_mi_field,
                meb_cdw1_fields, ENC_LITTLE_ENDIAN, &cdw1);
        req->dofst = (uint32_t)cdw0;
        req->dlen = (uint16_t)cdw1;
        detail = wmem_strdup_printf(pinfo->pool, "offset %u, %u bytes",
                                    req->dofst, req->dlen);
        break;
    }
    case NVME_MI_MI_OPC_PDA_READ:
    case NVME_MI_MI_OPC_PDA_WRITE: {
        /* MI 2.2 Figures 108-111: DOFST and DLEN, in DFORMAT units. */
        uint8_t dformat = tvb_get_uint8(tvb, 1);
        unsigned unit = nvme_mi_pda_unit(dformat);
        uint64_t cdw0, cdw1;
        uint32_t dlen_max;

        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 4,
                hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field,
                pda_cdw0_fields, ENC_LITTLE_ENDIAN, &cdw0);
        proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 8,
                hf_nvme_mi_mi_cdw1, ett_nvme_mi_mi_field,
                pda_cdw1_fields, ENC_LITTLE_ENDIAN, &cdw1);
        if (nvme_mi_pda_dlen_max(opcode, dformat, &dlen_max) &&
            (uint32_t)cdw1 > dlen_max)
            proto_tree_add_expert_format(mi_tree, pinfo,
                &ei_nvme_mi_mi_pda_dlen_max, tvb, 8, 4,
                "DLEN %u (DFORMAT %s) exceeds the conservative maximum %u"
                " (NVMe-MI '%s')",
                (uint32_t)cdw1,
                rval_to_str_const(dformat, mi_pda_dformat_vals, "Reserved"),
                dlen_max,
                opcode == NVME_MI_MI_OPC_PDA_WRITE ?
                    "NVMe-MI PDA Write NVMe Management Dword 1" :
                    "NVMe-MI PDA Read NVMe Management Dword 1");
        req->dofst = (uint32_t)cdw0;
        if (unit) {
            uint64_t bytes = (uint64_t)(uint32_t)cdw1 * unit;
            proto_item *gi;

            gi = proto_tree_add_uint64(mi_tree, hf_nvme_mi_mi_pda_byte_offset,
                    tvb, 4, 4, (uint64_t)(uint32_t)cdw0 * unit);
            proto_item_set_generated(gi);
            gi = proto_tree_add_uint64(mi_tree, hf_nvme_mi_mi_pda_byte_length,
                    tvb, 8, 4, bytes);
            proto_item_set_generated(gi);
            if (bytes <= INT32_MAX) {
                req->pda_bytes_known = true;
                req->pda_bytes = (uint32_t)bytes;
            }
        }
        detail = wmem_strdup_printf(pinfo->pool, "%s, offset %u, length %u",
                    rval_to_str_const(dformat, mi_pda_dformat_vals,
                                      "Reserved"),
                    (uint32_t)cdw0, (uint32_t)cdw1);
        break;
    }
    default:
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw0,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw1,
                            tvb, 8, 4, ENC_LITTLE_ENDIAN);
        break;
    }

    {
        uint32_t m0, m1;

        nvme_mi_mi_nmd_rsvd_masks(opcode, tvb_get_uint8(tvb, 4), &m0, &m1);
        nvme_mi_mi_show_reserved(tvb, mi_tree, hf_nvme_mi_mi_nmd0_rsvd, 4, 4,
                                 tvb_get_letohl(tvb, 4), m0);
        nvme_mi_mi_show_reserved(tvb, mi_tree, hf_nvme_mi_mi_nmd1_rsvd, 8, 4,
                                 tvb_get_letohl(tvb, 8), m1);
    }

    /* Every selector is read: publish, before the Request Data, which may
     * throw. */
    nvme_mi_trans_publish_body_ctx(pinfo, trans, req, sizeof(*req));

    nvme_mi_mi_col_append(pinfo, opcode, detail);

    /* Figure 67, Figures 103/129/135: NMD1 is the Request Data DLEN; only a
     * proven inline route makes it authoritative. */
    if (routing == NVME_MI_MI_DATA_INLINE &&
        (opcode == NVME_MI_MI_OPC_VPD_WRITE ||
         opcode == NVME_MI_MI_OPC_SES_SEND ||
         opcode == NVME_MI_MI_OPC_MEB_WRITE)) {
        unsigned dlen = tvb_get_letohs(tvb, 8);
        if (dlen != len - 12)
            proto_tree_add_expert_format(mi_tree, pinfo,
                &ei_nvme_mi_mi_request_data_length, tvb, 8, 2,
                "Request Data length is %u bytes but DLEN declares %u",
                len - 12, dlen);
    }
    /* MI 2.2 5.7: REQD must be DLEN DFORMAT units, else Invalid Command
     * Input Data Size. */
    if (routing == NVME_MI_MI_DATA_INLINE &&
        opcode == NVME_MI_MI_OPC_PDA_WRITE && req->pda_bytes_known &&
        req->pda_bytes != len - 12)
        proto_tree_add_expert_format(mi_tree, pinfo,
            &ei_nvme_mi_mi_request_data_length, tvb, 8, 4,
            "Request Data length is %u bytes but DLEN declares %u bytes",
            len - 12, req->pda_bytes);

    if (routing == NVME_MI_MI_DATA_INLINE && len > 12 &&
        !nvme_mi_mi_req_has_request_data(opcode, tvb_get_uint8(tvb, 4)))
        proto_tree_add_expert(mi_tree, pinfo,
                              &ei_nvme_mi_mi_unexpected_request_data,
                              tvb, 12, len - 12);

    if (len > 12) {
        /* A few commands carry structured Request Data after the command
         * dwords: a Configuration Set of the Asynchronous Event config
         * sends an AE Enable List; VPD Write sends the VPD bytes (opaque,
         * just labeled).  Everything else is an opaque blob. */
        if (opcode == NVME_MI_MI_OPC_CONFIG_SET &&
            tvb_get_uint8(tvb, 4) == NVME_MI_CFGID_AE) {
            dissect_nvme_mi_mi_ae_enable_list(tvb, pinfo, mi_tree, it, 12,
                                              len - 12);
        } else {
            int data_hf = hf_nvme_mi_mi_data;

            if (opcode == NVME_MI_MI_OPC_VPD_WRITE)
                data_hf = hf_nvme_mi_mi_vpd_data;
            else if (opcode == NVME_MI_MI_OPC_SES_SEND)
                data_hf = hf_nvme_mi_mi_ses_page;
            else if (opcode == NVME_MI_MI_OPC_MEB_WRITE)
                data_hf = hf_nvme_mi_mi_meb_data;
            else if (opcode == NVME_MI_MI_OPC_PDA_WRITE)
                data_hf = hf_nvme_mi_mi_pda_data;
            proto_tree_add_item(mi_tree, data_hf, tvb, 12, -1, ENC_NA);
        }
    } else if (opcode == NVME_MI_MI_OPC_CONFIG_SET &&
               tvb_get_uint8(tvb, 4) == NVME_MI_CFGID_AE) {
        /* 5.2.4: the AE Enable List is the Request Data. */
        expert_add_info_format(pinfo, it, &ei_nvme_mi_mi_truncated,
                               "Configuration Set (Asynchronous Event) omits"
                               " the AE Enable List (NVMe-MI section"
                               " 5.2.4)");
    }

    return tvb_captured_length(tvb);
}

/* Endpoint observations were already decided by nvme_mi_mi_pre_observe(). */
static int
dissect_nvme_mi_mi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   void *data)
{
    const struct nvme_mi_dissect_ctx *ctx = (const struct nvme_mi_dissect_ctx *)data;

    if (!ctx)
        return 0;

    bool resp = ctx->resp;
    struct nvme_mi_transaction *trans = ctx->trans;
    proto_item *it;
    proto_tree *mi_tree;
    unsigned len = tvb_reported_length(tvb);

    it = proto_tree_add_item(tree, proto_nvme_mi_mi, tvb, 0, -1, ENC_NA);
    mi_tree = proto_item_add_subtree(it, ett_nvme_mi_mi);
    bool request_known = trans && trans->nmimt == NVME_MI_TYPE_MI &&
        trans->req_parsed;
    enum nvme_mi_mi_data_routing routing = NVME_MI_MI_DATA_UNKNOWN;
    /* Figure 20, section 4.2.3: an unproven MEB route is not inline transfer. */
    if (!ctx->meb && (!resp || request_known))
        routing = NVME_MI_MI_DATA_INLINE;
    else if (ctx->meb && request_known && trans->req_integrity_ok &&
             nvme_mi_meb_routes(ctx->endpoint, trans->req_frame, trans->opcode))
        routing = NVME_MI_MI_DATA_MEB;
    /* section 5.2.4: AE Enable List is inline regardless of request MEB. */
    if (!resp && len >= 12 && tvb_bytes_exist(tvb, 0, 12) &&
        tvb_get_uint8(tvb, 0) == NVME_MI_MI_OPC_CONFIG_SET &&
        tvb_get_uint8(tvb, 4) == NVME_MI_CFGID_AE)
        routing = NVME_MI_MI_DATA_INLINE;
    proto_item *routing_it = proto_tree_add_uint(mi_tree,
        hf_nvme_mi_mi_data_routing, tvb, 0, 0, routing);
    proto_item_set_generated(routing_it);
    if (routing == NVME_MI_MI_DATA_MEB) {
        proto_item *gi = proto_tree_add_boolean(mi_tree,
                             hf_nvme_mi_mi_meb_routed, tvb, 0, 0, true);
        proto_item_set_generated(gi);
    }

    if (!resp)
        return dissect_nvme_mi_mi_request(tvb, pinfo, mi_tree, it, len, trans, routing);
    return dissect_nvme_mi_mi_response(tvb, pinfo, mi_tree, it, len, ctx, trans, routing);
}

/* Asynchronous Event Message (NMIMT 5h): the tvb is the AED, whose offset
 * 0h is the AE Occurrence List (4.4.4).  AEMs own no transaction. */
static int
dissect_nvme_mi_aem(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data)
{
    struct nvme_mi_dissect_ctx *ctx = (struct nvme_mi_dissect_ctx *)data;
    proto_tree *aem_tree;
    proto_item *it;

    if (!ctx)
        return 0;

    it = proto_tree_add_item(tree, proto_nvme_mi_aem, tvb, 0, -1, ENC_NA);
    aem_tree = proto_item_add_subtree(it, ett_nvme_mi_aem);

    dissect_nvme_mi_mi_aeo_list(tvb, pinfo, aem_tree, it, 0,
                                tvb_reported_length(tvb), true);

    return tvb_captured_length(tvb);
}

void
proto_register_nvme_mi_mi(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        { &hf_nvme_mi_mi_vpd_common[0],
          { "IPMI Format Version (IPMIVER)", "nvme-mi.mi.vpd.ipmiver",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_common[1],
          { "Internal Use Area Offset (IUAOFF)", "nvme-mi.mi.vpd.iuaoff",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Units of 8 bytes", HFILL } },
        { &hf_nvme_mi_mi_vpd_common[2],
          { "Chassis Info Area Offset (CIAOFF)", "nvme-mi.mi.vpd.ciaoff",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Units of 8 bytes", HFILL } },
        { &hf_nvme_mi_mi_vpd_common[3],
          { "Board Info Area Offset (BIAOFF)", "nvme-mi.mi.vpd.biaoff",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Units of 8 bytes", HFILL } },
        { &hf_nvme_mi_mi_vpd_common[4],
          { "Product Info Area Offset (PIAOFF)", "nvme-mi.mi.vpd.piaoff",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Units of 8 bytes", HFILL } },
        { &hf_nvme_mi_mi_vpd_common[5],
          { "MultiRecord Info Area Offset (MRIOFF)", "nvme-mi.mi.vpd.mrioff",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Units of 8 bytes", HFILL } },
        { &hf_nvme_mi_mi_vpd_common[6],
          { "Boot Failure Code (BFC)", "nvme-mi.mi.vpd.bfc",
            FT_UINT8, BASE_HEX, VALS(mi_vpd_bfc_vals), 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_common[7],
          { "Common Header Checksum (CHCHK)", "nvme-mi.mi.vpd.chchk",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_record,
          { "MultiRecord", "nvme-mi.mi.vpd.record",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rti,
          { "Record Type Identifier (RTI)", "nvme-mi.mi.vpd.rti",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_vpd_record_vals), 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rver,
          { "Record Version (RVER)", "nvme-mi.mi.vpd.rver",
            FT_UINT8, BASE_HEX, NULL, 0x7f,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_lrec,
          { "Last Record (LREC)", "nvme-mi.mi.vpd.lrec",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rlen,
          { "Record Length (RLEN)", "nvme-mi.mi.vpd.rlen",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rcsum,
          { "Record Checksum (RCSUM)", "nvme-mi.mi.vpd.rcsum",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_hsum,
          { "Header Checksum (HSUM)", "nvme-mi.mi.vpd.hsum",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_version,
          { "MultiRecord Area Version", "nvme-mi.mi.vpd.version",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_raw,
          { "Uninterpreted VPD Data / Padding", "nvme-mi.mi.vpd.raw",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_ff,
          { "Form Factor (FF)", "nvme-mi.mi.vpd.ff",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_vpd_ff_vals), 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[0],
          { "Initial 1.8 V Power (W)", "nvme-mi.mi.vpd.i1p8psr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[1],
          { "Maximum 1.8 V Power (W)", "nvme-mi.mi.vpd.m1p8psr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[2],
          { "Initial 3.3 V Power (W)", "nvme-mi.mi.vpd.i3p3psr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[3],
          { "Maximum 3.3 V Power (W)", "nvme-mi.mi.vpd.m3p3psr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[4],
          { "Maximum 3.3 V Auxiliary Power (10 mW)", "nvme-mi.mi.vpd.m3p3apsr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[5],
          { "Initial 5 V Power (W)", "nvme-mi.mi.vpd.i5psr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[6],
          { "Maximum 5 V Power (W)", "nvme-mi.mi.vpd.m5psr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[7],
          { "Initial 12 V Power (W)", "nvme-mi.mi.vpd.i12psr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[8],
          { "Maximum 12 V Power (W)", "nvme-mi.mi.vpd.m12psr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_power[9],
          { "Maximum Thermal Load (W)", "nvme-mi.mi.vpd.mtl",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_capacity,
          { "Total NVM Capacity (TNVMCAP)", "nvme-mi.mi.vpd.tnvmcap",
            FT_BYTES, BASE_NONE, NULL, 0,
            "13-byte little-endian capacity", HFILL } },
        { &hf_nvme_mi_mi_vpd_pn,
          { "PCIe Port Number", "nvme-mi.mi.vpd.pciepn",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pinfo,
          { "Port Information (PINFO)", "nvme-mi.mi.vpd.pinfo",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pinfo_rsvd,
          { "Reserved", "nvme-mi.mi.vpd.pinfo.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xfe,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_cppc,
          { "Common PCIe Port Capabilities (CPPC)", "nvme-mi.mi.vpd.cppc",
            FT_BOOLEAN, 8, NULL, 1,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_linkspeed,
          { "PCIe Link Speed Support (PCIELS)", "nvme-mi.mi.vpd.pciels",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_linkwidth,
          { "PCIe Maximum Link Width (PCIEMLW)", "nvme-mi.mi.vpd.pciemlw",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(mi_pciemlw_vals), 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_mctps,
          { "MCTP Support (MCTPS)", "nvme-mi.mi.vpd.mctps",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rccap,
          { "Reference Clock Capability (RCCAP)", "nvme-mi.mi.vpd.rccap",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_portid,
          { "NVMe-MI Port Identifier", "nvme-mi.mi.vpd.portid",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_elemc,
          { "Element Count (ELEMC)", "nvme-mi.mi.vpd.elemc",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_element,
          { "Element Descriptor", "nvme-mi.mi.vpd.element",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_typ,
          { "Element Type (TYP)", "nvme-mi.mi.vpd.typ",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(mi_vpd_element_vals), 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rev,
          { "Element Revision (REV)", "nvme-mi.mi.vpd.rev",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_len,
          { "Element Length (LEN)", "nvme-mi.mi.vpd.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_lstr,
          { "Label String (LSTR)", "nvme-mi.mi.vpd.lstr",
            FT_STRINGZTRUNC, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_lptr,
          { "Label Pointer (LPTR)", "nvme-mi.mi.vpd.lptr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_maxapwr,
          { "Maximum Auxiliary Power (10 mW)", "nvme-mi.mi.vpd.maxapwr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_maxpwr,
          { "Maximum Power (W)", "nvme-mi.mi.vpd.maxpwr",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_portcount,
          { "Port / Channel Descriptor Count", "nvme-mi.mi.vpd.portcount",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_port,
          { "Port / Channel Descriptor", "nvme-mi.mi.vpd.port",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_porttyp,
          { "Port / Channel Type", "nvme-mi.mi.vpd.porttyp",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_portlen,
          { "Port / Channel Length", "nvme-mi.mi.vpd.portlen",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_count,
          { "Pointer Count", "nvme-mi.mi.vpd.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pointer,
          { "Child Element Pointer", "nvme-mi.mi.vpd.pointer",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_sl,
          { "Starting Lane (SL)", "nvme-mi.mi.vpd.sl",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_el,
          { "Ending Lane (EL)", "nvme-mi.mi.vpd.el",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_dport,
          { "Destination Port (DPORT)", "nvme-mi.mi.vpd.dport",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_addri,
          { "2-Wire Address Info", "nvme-mi.mi.vpd.addri",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap,
          { "2-Wire Capabilities", "nvme-mi.mi.vpd.twcap",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_merim,
          { "Management Endpoint Ready Independent of Media Timeout (100 ms)", "nvme-mi.mi.vpd.merim",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_merwmto,
          { "Management Endpoint Ready With Media Timeout (100 ms)", "nvme-mi.mi.vpd.merwmto",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_mut,
          { "Maximum Unresponsive Time (100 ms)", "nvme-mi.mi.vpd.mut",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rsvd,
          { "Reserved", "nvme-mi.mi.vpd.rsvd",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pciels_gts64,
          { "64.0 GT/s Support (GTS64)", "nvme-mi.mi.vpd.pciels.gts64",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pciels_gts32,
          { "32.0 GT/s Support (GTS32)", "nvme-mi.mi.vpd.pciels.gts32",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pciels_gts16,
          { "16.0 GT/s Support (GTS16)", "nvme-mi.mi.vpd.pciels.gts16",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pciels_gts8,
          { "8.0 GT/s Support (GTS8)", "nvme-mi.mi.vpd.pciels.gts8",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pciels_gts5,
          { "5.0 GT/s Support (GTS5)", "nvme-mi.mi.vpd.pciels.gts5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pciels_gts2p5,
          { "2.5 GT/s Support (GTS2P5)", "nvme-mi.mi.vpd.pciels.gts2p5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_mctps_mctppcievs,
          { "MCTP PCIe VDM Support (MCTPPCIEVS)", "nvme-mi.mi.vpd.mctps.mctppcievs",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rccap_rcs,
          { "RefClk Support (RCS)", "nvme-mi.mi.vpd.rccap.rcs",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rccap_srcss,
          { "Separate RefClk with SSC Support (SRCSS)", "nvme-mi.mi.vpd.rccap.srcss",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rccap_srcnss,
          { "Separate RefClk with No SSC Support (SRCNSS)", "nvme-mi.mi.vpd.rccap.srcnss",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_rccap_crcs,
          { "Common RefClk Support (CRCS)", "nvme-mi.mi.vpd.rccap.crcs",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twaddr,
          { "2-Wire Address (TWADDR)", "nvme-mi.mi.vpd.addri.twaddr", FT_UINT8, BASE_HEX, NULL, 0xfe,
            "7-bit address; SADDR in an NVM Subsystem Element Descriptor", HFILL } },
        { &hf_nvme_mi_mi_vpd_arpc,
          { "ARP Capable (ARPC)", "nvme-mi.mi.vpd.addri.arpc",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap_rst,
          { "Reset (RST)", "nvme-mi.mi.vpd.twcap.rst",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap_ffr,
          { "Form Factor Reset (FFR)", "nvme-mi.mi.vpd.twcap.ffr",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap_pecs,
          { "Packet Error Code Support (PECS)", "nvme-mi.mi.vpd.twcap.pecs",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap_m2was,
          { "MCTP over 2-Wire In Aux Power Support (M2WAS)", "nvme-mi.mi.vpd.twcap.m2was",
            FT_UINT8, BASE_DEC, VALS(mi_vpd_m2was_vals), 0x60,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap_i3cs,
          { "I3C Support (I3CS)", "nvme-mi.mi.vpd.twcap.i3cs",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap_mspd,
          { "Maximum Speed (MSPD)", "nvme-mi.mi.vpd.twcap.mspd",
            FT_UINT8, BASE_DEC, VALS(mi_vpd_mspd_vals), 0x03,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap_i2cwa,
          { "I2C Writes Allowed (I2CWA)", "nvme-mi.mi.vpd.twcap.i2cwa",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x40,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_twcap_bfcs,
          { "Boot Failure Code Support (BFCS)", "nvme-mi.mi.vpd.twcap.bfcs",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_mfids,
          { "Maximum FRU Information Device Size (MFIDS)", "nvme-mi.mi.vpd.mfids",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(nvme_mi_mi_fmt_mfids), 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia,
          { "Product Info Area", "nvme-mi.mi.vpd.pia",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_ipmiver,
          { "IPMI Format Version Number (IPMIVER)", "nvme-mi.mi.vpd.pia.ipmiver",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_palen,
          { "Product Info Area Length (PALEN)", "nvme-mi.mi.vpd.pia.palen",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Units of 8 bytes", HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_lcode,
          { "Language Code (LCODE)", "nvme-mi.mi.vpd.pia.lcode",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_tl,
          { "Type/Length", "nvme-mi.mi.vpd.pia.tl",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_tcode,
          { "Type Code (TCODE)", "nvme-mi.mi.vpd.pia.tcode",
            FT_UINT8, BASE_DEC, VALS(mi_vpd_tcode_vals), 0xc0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_ndb,
          { "Number of Data Bytes (NDB)", "nvme-mi.mi.vpd.pia.ndb",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_mname,
          { "Manufacturer Name (MNAME)", "nvme-mi.mi.vpd.pia.mname",
            FT_STRINGZPAD, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_pname,
          { "Product Name (PNAME)", "nvme-mi.mi.vpd.pia.pname",
            FT_STRINGZPAD, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_ppmn,
          { "Product Part/Model Number (PPMN)", "nvme-mi.mi.vpd.pia.ppmn",
            FT_STRINGZPAD, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_pver,
          { "Product Version (PVER)", "nvme-mi.mi.vpd.pia.pver",
            FT_STRINGZPAD, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_psn,
          { "Product Serial Number (PSN)", "nvme-mi.mi.vpd.pia.psn",
            FT_STRINGZPAD, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_at,
          { "Asset Tag (AT)", "nvme-mi.mi.vpd.pia.at",
            FT_STRINGZPAD, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_ffi,
          { "FRU File ID (FFI)", "nvme-mi.mi.vpd.pia.ffi",
            FT_STRINGZPAD, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_cpia,
          { "Custom Product Info Area (CPIA)", "nvme-mi.mi.vpd.pia.cpia",
            FT_STRINGZPAD, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_eor,
          { "End of Record (EOR)", "nvme-mi.mi.vpd.pia.eor",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_vpd_pia_pichk,
          { "Product Info Area Checksum (PICHK)", "nvme-mi.mi.vpd.pia.pichk",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_rv,
          { "Ready Value (RV)", "nvme-mi.mi.aeosi.rv",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_cfsv,
          { "Controller Fatal Status Value (CFSV)", "nvme-mi.mi.aeosi.cfsv",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_stv,
          { "Shutdown Type Value (STV)", "nvme-mi.mi.aeosi.stv",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_ssv,
          { "Shutdown Status Value (SSV)", "nvme-mi.mi.aeosi.ssv",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_crime,
          { "Controller Ready Independent of Media Enable (CRIME)", "nvme-mi.mi.aeosi.crime",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_cev,
          { "Controller Enable Value (CEV)", "nvme-mi.mi.aeosi.cev",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_ctv,
          { "Composite Temperature Value (CTV)", "nvme-mi.mi.aeosi.ctv",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(nvme_mi_mi_fmt_nshds_ctemp), 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_puv,
          { "Percentage Drive Life Used Value (PUV)", "nvme-mi.mi.aeosi.puv",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_asv,
          { "Available Spare Value (ASV)", "nvme-mi.mi.aeosi.asv",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_cwv,
          { "SMART Warnings Value (CWV)", "nvme-mi.mi.aeosi.cwv",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_plav,
          { "PCIe Link Active Value (PLAV)", "nvme-mi.mi.aeosi.plav",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_sfmv,
          { "Sanitize Failure Mode Value (SFMV)", "nvme-mi.mi.aeosi.sfmv",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_snfmv,
          { "Sanitize Namespace Failure Mode Value (SNFMV)", "nvme-mi.mi.aeosi.snfmv",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_rsvd1,
          { "Reserved", "nvme-mi.mi.aeosi.rsvd1",
            FT_UINT8, BASE_HEX, NULL, 0xfe,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_rsvd2,
          { "Reserved", "nvme-mi.mi.aeosi.rsvd2",
            FT_UINT8, BASE_HEX, NULL, 0xfc,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_rsvd3,
          { "Reserved", "nvme-mi.mi.aeosi.rsvd3",
            FT_UINT8, BASE_HEX, NULL, 0xf8,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_pmt,
          { "Power Measurement Type (PMT)", "nvme-mi.mi.aeosi.pmt",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_aeosi_pmt_vals), 0x00f00000,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_pwrs,
          { "Power Scale (PWRS)", "nvme-mi.mi.aeosi.pwrs",
            FT_UINT32, BASE_HEX, VALS(mi_aeosi_pwrs_vals), 0x00030000,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_pwrv,
          { "Power Value (PWRV)", "nvme-mi.mi.aeosi.pwrv",
            FT_UINT32, BASE_DEC, NULL, 0x0000ffff,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_pwr_rsvd,
          { "Reserved", "nvme-mi.mi.aeosi.pwr_rsvd",
            FT_UINT32, BASE_HEX, NULL, 0xff0c0000,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_pwrid,
          { "Power Input Details (PWRID)", "nvme-mi.mi.aeosi.pwrid",
            FT_UINT32, BASE_HEX, NULL, 0xfffc0000,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_pwril,
          { "Power Input Label (PWRIL)", "nvme-mi.mi.aeosi.pwril",
            FT_UINT32, BASE_DEC, NULL, 0xc0000000,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_pwriv,
          { "Power Input Value (PWRIV)", "nvme-mi.mi.aeosi.pwriv",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(nvme_mi_pwriv_fmt), 0x3ffc0000,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_vsent,
          { "Voltage Sensor Triggered (VSENT)", "nvme-mi.mi.aeosi.vsent",
            FT_UINT32, BASE_HEX, VALS(mi_aeosi_vsent_vals), 0x00030000,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_vtht,
          { "Voltage Threshold Triggered (VTHT)", "nvme-mi.mi.aeosi.vtht",
            FT_UINT32, BASE_HEX, VALS(mi_aeosi_vtht_vals), 0x0000c000,
            NULL, HFILL } },
        { &hf_nvme_mi_mi_aeosi_volv,
          { "Voltage Value (VOLV)", "nvme-mi.mi.aeosi.volv",
            FT_UINT32, BASE_DEC, NULL, 0x00003fff,
            "Volts = value x the VOLSS scale of the triggering voltage sensor", HFILL } },
        { &hf_nvme_mi_mi_response_surplus,
          { "Surplus Response Data", "nvme-mi.mi.response_surplus",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Bytes outside the declared response or fixed structure extent",
            HFILL },
        },
        { &hf_nvme_mi_mi_data_routing,
          { "Data routing", "nvme-mi.mi.data_routing",
            FT_UINT8, BASE_DEC, VALS(mi_data_routing_vals), 0,
            "Routing established by the request MEB bit, observed capabilities and command-specific rules",
            HFILL },
        },
        { &hf_nvme_mi_mi_meb_routed,
          { "Data routed through MEB", "nvme-mi.mi.meb_routed",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "Request MEB and observed endpoint capabilities select buffer routing",
            HFILL },
        },
        { &hf_nvme_mi_mi_opcode,
          { "Opcode", "nvme-mi.mi.opcode",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_opcode_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_rsvd,
          { "Reserved", "nvme-mi.mi.reserved",
            FT_UINT24, BASE_HEX, NULL, 0,
            "Message bytes 07:05 of an MI Command Request Message, between the"
            " Opcode and NVMe Management Dword 0 (NVMe-MI 'NVMe-MI Command"
            " Request Message Description')", HFILL },
        },
        { &hf_nvme_mi_mi_cdw0,
          { "Command dword 0", "nvme-mi.mi.cdw0",
            FT_UINT32, BASE_HEX, NULL, 0,
            "NVMe Management Dword 0 (NMD0)", HFILL },
        },
        { &hf_nvme_mi_mi_cdw1,
          { "Command dword 1", "nvme-mi.mi.cdw1",
            FT_UINT32, BASE_HEX, NULL, 0,
            "NVMe Management Dword 1 (NMD1)", HFILL },
        },
        { &hf_nvme_mi_mi_status,
          { "Status", "nvme-mi.mi.status",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_mi_status_vals), 0,
            "Response Message Status (NVMe-MI 'Response Message"
            " Status Values')", HFILL },
        },
        { &hf_nvme_mi_mi_nmresp,
          { "Management Response", "nvme-mi.mi.nmresp",
            FT_UINT24, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nmresp_rsvd,
          { "Reserved (Management Response)", "nvme-mi.mi.nmresp_reserved",
            FT_UINT24, BASE_HEX, NULL, 0,
            "The NVMe Management Response field of a command whose Success"
            " Response reserves it rather than giving it a command specific"
            " meaning", HFILL },
        },
        { &hf_nvme_mi_mi_nmresp_rsvd_bits,
          { "Reserved bits (Management Response)",
            "nvme-mi.mi.nmresp_reserved_bits",
            FT_UINT24, BASE_HEX, NULL, 0,
            "Nonzero bits of the NVMe Management Response that this command"
            " reserves, unshifted", HFILL },
        },
        { &hf_nvme_mi_mi_nmd0_rsvd,
          { "Reserved bits (NMD0)", "nvme-mi.mi.nmd0_reserved",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Nonzero bits of Management Request Doubleword 0 that this"
            " command reserves, unshifted", HFILL },
        },
        { &hf_nvme_mi_mi_nmd1_rsvd,
          { "Reserved bits (NMD1)", "nvme-mi.mi.nmd1_reserved",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Nonzero bits of Management Request Doubleword 1 that this"
            " command reserves, unshifted", HFILL },
        },
        { &hf_nvme_mi_mi_data,
          { "Data", "nvme-mi.mi.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ds_rsvd,
          { "Reserved", "nvme-mi.mi.ds_reserved",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Reserved bytes in an NVMe-MI data structure", HFILL },
        },

        /* Read NVMe-MI Data Structure (00h) */
        { &hf_nvme_mi_mi_rds_dtyp,
          { "Data Structure Type (DTYP)", "nvme-mi.mi.rds.dtyp",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_dtyp_vals), 0xFF000000,
            "Data structure to return", HFILL },
        },
        { &hf_nvme_mi_mi_rds_portid,
          { "Port Identifier (PORTID)", "nvme-mi.mi.rds.portid",
            FT_UINT32, BASE_DEC, NULL, 0x00FF0000,
            "Port whose data structure is returned (DTYP 01h/05h)", HFILL },
        },
        { &hf_nvme_mi_mi_rds_ctrlid,
          { "Controller Identifier (CTRLID)", "nvme-mi.mi.rds.ctrlid",
            FT_UINT32, BASE_HEX, NULL, 0x0000FFFF,
            "Controller whose data structure is returned (DTYP 02h-04h)",
            HFILL },
        },
        { &hf_nvme_mi_mi_rds_iocsi,
          { "I/O Command Set Identifier (IOCSI)", "nvme-mi.mi.rds.iocsi",
            FT_UINT32, BASE_HEX, NULL, 0x000000FF,
            "Selects the I/O Command Set for Admin entries (DTYP 04h/05h)",
            HFILL },
        },
        { &hf_nvme_mi_mi_rds_rdl,
          { "Response Data Length (RDL)", "nvme-mi.mi.rds.rdl",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Length in bytes of the Response Data field",
            HFILL },
        },

        /* NVM Subsystem Health Status Poll (01h) */
        { &hf_nvme_mi_mi_nshsp_cs,
          { "Clear Change Flags (CCF)", "nvme-mi.mi.nshsp.cs",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
            "Clear the Composite Controller Status Flags after copying them"
            " into the response", HFILL },
        },

        /* Controller Health Status Poll (02h) */
        { &hf_nvme_mi_mi_chsp_all,
          { "Report All (ALL)", "nvme-mi.mi.chsp.all",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
            "Overrides the controller health criteria bits (CWARN, SPARE, PDLU, CTEMP, CSC) in NMD1",
            HFILL },
        },
        { &hf_nvme_mi_mi_chsp_incvf,
          { "Include SR-IOV Virtual Functions (INCVF)", "nvme-mi.mi.chsp.incvf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x04000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_incpf,
          { "Include SR-IOV Physical Functions (INCPF)", "nvme-mi.mi.chsp.incpf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x02000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_incf,
          { "Include PCI Functions (INCF)", "nvme-mi.mi.chsp.incf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x01000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_maxrent,
          { "Maximum Response Entries (MAXRENT)", "nvme-mi.mi.chsp.maxrent",
            FT_UINT32, BASE_DEC, NULL, 0x00FF0000,
            "Maximum number of CHDS entries to return, 0's based", HFILL },
        },
        { &hf_nvme_mi_mi_chsp_sctlid,
          { "Starting Controller ID (SCTLID)", "nvme-mi.mi.chsp.sctlid",
            FT_UINT32, BASE_HEX, NULL, 0x0000FFFF,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_ccf,
          { "Clear Change Flags (CCF)", "nvme-mi.mi.chsp.ccf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
            "Copy then clear each returned Controller's Health Status"
            " Changed Flags", HFILL },
        },
        { &hf_nvme_mi_mi_chsp_cwarn,
          { "Select on Critical Warning (CWARN)", "nvme-mi.mi.chsp.cwarn",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_spare,
          { "Select on Available Spare (SPARE)", "nvme-mi.mi.chsp.spare",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_pdlu,
          { "Select on Percentage Drive Life Used (PDLU)",
            "nvme-mi.mi.chsp.pdlu",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_ctemp,
          { "Select on Composite Temperature Change (CTEMP)",
            "nvme-mi.mi.chsp.ctemp",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_csts,
          { "Select on Controller Status Change (CSC)",
            "nvme-mi.mi.chsp.csts",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_rent,
          { "Response Entries (RENT)", "nvme-mi.mi.chsp.rent",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Number of CHDS entries in the Response Data",
            HFILL },
        },

        /* Configuration Set (03h) / Configuration Get (04h) */
        { &hf_nvme_mi_mi_cfg_cid,
          { "Configuration Identifier (CID)", "nvme-mi.mi.config.cid",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_configid_vals), 0x000000FF,
            "Configuration being read or written (NVMe-MI 'NVMe"
            " Management Interface Configuration Identifiers')", HFILL },
        },
        { &hf_nvme_mi_mi_cfg_portid,
          { "Port Identifier (PORTID)", "nvme-mi.mi.config.portid",
            FT_UINT32, BASE_DEC, NULL, 0xFF000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_sfreq,
          { "SMBus/I2C Frequency (SFREQ)", "nvme-mi.mi.config.sfreq",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_sfreq_vals), 0x00000F00,
            "New frequency for the 2-Wire port", HFILL },
        },
        { &hf_nvme_mi_mi_cfg_mtus,
          { "MCTP Transmission Unit Size (MTUS)", "nvme-mi.mi.config.mtus",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Requested MCTP Transmission Unit Size in bytes",
            HFILL },
        },
        { &hf_nvme_mi_mi_cfg_sfreq_cur,
          { "Current SMBus/I2C Frequency (SFREQ)",
            "nvme-mi.mi.config.sfreq_cur",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_sfreq_cur_vals), 0x0F,
            "Current 2-Wire frequency", HFILL },
        },
        { &hf_nvme_mi_mi_cfg_mtus_cur,
          { "Current MCTP Transmission Unit Size (MTUS)",
            "nvme-mi.mi.config.mtus_cur",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Current MCTP Transmission Unit Size in bytes",
            HFILL },
        },
        { &hf_nvme_mi_mi_cfg_aeelver,
          { "AE Enable List Version Number (AEELVER)",
            "nvme-mi.mi.config.aeelver",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Version of the AE Enable List data structure",
            HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_tcida,
          { "Clear Telemetry Controller-Initiated Data Available (TCIDA)",
            "nvme-mi.mi.config.hsc.tcida",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00001000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_cwarn,
          { "Clear Critical Warning (CWARN)", "nvme-mi.mi.config.hsc.cwarn",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000800,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_spare,
          { "Clear Available Spare (SPARE)", "nvme-mi.mi.config.hsc.spare",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000400,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_pdlu,
          { "Clear Percentage Drive Life Used (PDLU)",
            "nvme-mi.mi.config.hsc.pdlu",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000200,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_ctemp,
          { "Clear Composite Temperature (CTEMP)",
            "nvme-mi.mi.config.hsc.ctemp",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000100,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_cschng,
          { "Clear Controller Status Change (CSC)",
            "nvme-mi.mi.config.hsc.cschng",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000080,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_fa,
          { "Clear Firmware Activated (FA)", "nvme-mi.mi.config.hsc.fa",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000040,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_nac,
          { "Clear Namespace Attribute Changed (NAC)",
            "nvme-mi.mi.config.hsc.nac",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000020,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_ceco,
          { "Clear Controller Enable Change Occurred (CECO)",
            "nvme-mi.mi.config.hsc.ceco",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_nssro,
          { "Clear NVM Subsystem Reset Occurred (NSSRO)",
            "nvme-mi.mi.config.hsc.nssro",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_shst,
          { "Clear Shutdown Status (SHST)", "nvme-mi.mi.config.hsc.shst",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_cfs,
          { "Clear Controller Fatal Status (CFS)",
            "nvme-mi.mi.config.hsc.cfs",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_hsc_rdy,
          { "Clear Ready (RDY)", "nvme-mi.mi.config.hsc.rdy",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
            NULL, HFILL },
        },

        /* VPD Read (05h) / VPD Write (06h) */
        { &hf_nvme_mi_mi_vpd_dofst,
          { "Data Offset (DOFST)", "nvme-mi.mi.vpd.dofst",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Starting byte offset into the VPD", HFILL },
        },
        { &hf_nvme_mi_mi_vpd_dlen,
          { "Data Length (DLEN)", "nvme-mi.mi.vpd.dlen",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Length in bytes to read from or write to the VPD", HFILL },
        },
        { &hf_nvme_mi_mi_vpd_pcivid,
          { "PCI Vendor ID (PCIVID)", "nvme-mi.mi.vpd.pcivid",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Vendor-Specific Element Descriptor vendor", HFILL },
        },
        { &hf_nvme_mi_mi_ses_pcode,
          { "Page Code (PCODE)", "nvme-mi.mi.ses.pcode",
            FT_UINT32, BASE_HEX, NULL, 0x000000FF,
            "SES status diagnostic page to return", HFILL },
        },
        { &hf_nvme_mi_mi_ses_alength,
          { "Allocation Length (ALENGTH)", "nvme-mi.mi.ses.alength",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Maximum length in bytes of the Response Data", HFILL },
        },
        { &hf_nvme_mi_mi_ses_dlen,
          { "Data Length (DLEN)", "nvme-mi.mi.ses.dlen",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Length in bytes of the Request Data", HFILL },
        },
        { &hf_nvme_mi_mi_ses_rdl,
          { "Response Data Length (RDL)", "nvme-mi.mi.ses.rdl",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Length in bytes of the Response Data, inline or in the MEB",
            HFILL },
        },
        { &hf_nvme_mi_mi_ses_page,
          { "SES Diagnostic Page", "nvme-mi.mi.ses.page",
            FT_BYTES, BASE_NONE, NULL, 0,
            "SES-4 diagnostic page bytes (not decoded)", HFILL },
        },
        { &hf_nvme_mi_mi_meb_dofst,
          { "Data Offset (DOFST)", "nvme-mi.mi.meb.dofst",
            FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFF,
            "Starting byte offset into the Management Endpoint Buffer",
            HFILL },
        },
        { &hf_nvme_mi_mi_meb_dlen,
          { "Data Length (DLEN)", "nvme-mi.mi.meb.dlen",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Length in bytes to read from or write to the Management"
            " Endpoint Buffer", HFILL },
        },
        { &hf_nvme_mi_mi_meb_data,
          { "Management Endpoint Buffer Data", "nvme-mi.mi.meb.data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_pda_dformat,
          { "Data Format (DFORMAT)", "nvme-mi.mi.pda.dformat",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
            RVALS(mi_pda_dformat_vals), 0,
            "Unit of the NVMe-MI Persistent Data Area DOFST and DLEN"
            " (NVMe-MI 'NVMe-MI PDA Command Request Message Description')", HFILL },
        },
        { &hf_nvme_mi_mi_pda_rsvd,
          { "Reserved", "nvme-mi.mi.pda.reserved",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Message bytes 07:06 of an NVMe-MI PDA Command Request",
            HFILL },
        },
        { &hf_nvme_mi_mi_pda_dofst,
          { "Data Offset (DOFST)", "nvme-mi.mi.pda.dofst",
            FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFF,
            "Starting offset into the NVMe-MI PDA, in DFORMAT units",
            HFILL },
        },
        { &hf_nvme_mi_mi_pda_dlen,
          { "Data Length (DLEN)", "nvme-mi.mi.pda.dlen",
            FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFF,
            "Length to read or write, in DFORMAT units", HFILL },
        },
        { &hf_nvme_mi_mi_pda_byte_offset,
          { "Data Offset in bytes", "nvme-mi.mi.pda.byte_offset",
            FT_UINT64, BASE_DEC, NULL, 0,
            "DOFST multiplied by the DFORMAT unit", HFILL },
        },
        { &hf_nvme_mi_mi_pda_byte_length,
          { "Data Length in bytes", "nvme-mi.mi.pda.byte_length",
            FT_UINT64, BASE_DEC, NULL, 0,
            "DLEN multiplied by the DFORMAT unit", HFILL },
        },
        { &hf_nvme_mi_mi_pda_data,
          { "NVMe-MI PDA Data", "nvme-mi.mi.pda.data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_vpd_data,
          { "VPD Data", "nvme-mi.mi.vpd.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            "VPD contents transferred by the command (NVMe-MI 'VPD"
            " Read Response Data' / 'VPD Write Request Data')",
            HFILL },
        },
        { &hf_nvme_mi_mi_vpd_undecoded,
          { "VPD data not decoded", "nvme-mi.mi.vpd.undecoded",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "The VPD bytes were retained raw because their format or position"
            " is not decoded", HFILL },
        },

        /* Configuration Set (03h) Asynchronous Event - command dword 0 */
        { &hf_nvme_mi_mi_cfg_ae_envfa,
          { "Enable SR-IOV Virtual Functions AE (ENVFA)",
            "nvme-mi.mi.config.ae.envfa",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x04000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_ae_enpfa,
          { "Enable SR-IOV Physical Functions AE (ENPFA)",
            "nvme-mi.mi.config.ae.enpfa",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x02000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_ae_encfa,
          { "Enable PCI Functions AE (ENCFA)", "nvme-mi.mi.config.ae.encfa",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x01000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_ae_aemd,
          { "AEM Delay (AEMD)", "nvme-mi.mi.config.ae.aemd",
            FT_UINT32, BASE_DEC, NULL, 0x00FF0000,
            "Delay in seconds before an AEM is transmitted",
            HFILL },
        },
        { &hf_nvme_mi_mi_cfg_ae_aerd,
          { "AEM Retry Delay (AERD)", "nvme-mi.mi.config.ae.aerd",
            FT_UINT32, BASE_DEC, NULL, 0x0000FF00,
            "Delay in 100 ms units between AEM retransmissions",
            HFILL },
        },

        /* Configuration Set (03h) Asynchronous Event - AE Enable List */
        { &hf_nvme_mi_mi_ae,
          { "AE Enable List", "nvme-mi.mi.ae",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Asynchronous Event Enable List request data (NVMe-MI"
            " 'AE Enable List Data Structure')", HFILL },
        },
        { &hf_nvme_mi_mi_ae_numaee,
          { "Number of AE Enable Data Structures (NUMAEE)", "nvme-mi.mi.ae.numaee",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ae_aeelver,
          { "AE Enable List Version (AEELVER)", "nvme-mi.mi.ae.aeelver",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ae_aeetl,
          { "AE Enable Total Length (AEETL)", "nvme-mi.mi.ae.aeetl",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ae_aeelhl,
          { "AE Enable List Header Length (AEELHL)", "nvme-mi.mi.ae.aeelhl",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ae_entry,
          { "AE Enable", "nvme-mi.mi.ae.entry",
            FT_BYTES, BASE_NONE, NULL, 0,
            "AE Enable data structure", HFILL },
        },
        { &hf_nvme_mi_mi_ae_aeel,
          { "AE Enable Length (AEEL)", "nvme-mi.mi.ae.aeel",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ae_aee,
          { "AE Enable (AEE)", "nvme-mi.mi.ae.aee",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000,
            "Enable (1) or disable (0) the indicated asynchronous event", HFILL },
        },
        { &hf_nvme_mi_mi_ae_id,
          { "AE Enable ID", "nvme-mi.mi.ae.id",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_ae_id_vals), 0x00FF,
            "Identifier of the asynchronous event (NVMe-MI"
            " 'Asynchronous Events')", HFILL },
        },
        { &hf_nvme_mi_mi_ae_aee_rsvd,
          { "Reserved", "nvme-mi.mi.ae.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x7F00,
            "AE Enable Info bits 14:08", HFILL },
        },

        /* Configuration Get (04h) Asynchronous Event - AE Supported List */
        { &hf_nvme_mi_mi_aes,
          { "AE Supported List", "nvme-mi.mi.aes",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Asynchronous Event Supported List response data (NVMe-MI"
            " 'AE Supported List Data Structure')",
            HFILL },
        },
        { &hf_nvme_mi_mi_aes_numaes,
          { "Number of AE Supported Data Structures (NUMAES)",
            "nvme-mi.mi.aes.numaes",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aes_aeslver,
          { "AE Supported List Version (AESLVER)", "nvme-mi.mi.aes.aeslver",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aes_aestl,
          { "AE Supported Total Length (AESTL)", "nvme-mi.mi.aes.aestl",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aes_aeslhl,
          { "AE Supported List Header Length (AESLHL)",
            "nvme-mi.mi.aes.aeslhl",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aes_entry,
          { "AE Supported", "nvme-mi.mi.aes.entry",
            FT_BYTES, BASE_NONE, NULL, 0,
            "AE Supported data structure", HFILL },
        },
        { &hf_nvme_mi_mi_aes_aesl,
          { "AE Supported Length (AESL)", "nvme-mi.mi.aes.aesl",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aes_aese,
          { "AE Supported Enable (AESE)", "nvme-mi.mi.aes.aese",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000,
            "The indicated asynchronous event is currently enabled", HFILL },
        },
        { &hf_nvme_mi_mi_aes_id,
          { "AE Supported ID", "nvme-mi.mi.aes.id",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_ae_id_vals), 0x00FF,
            "Identifier of the asynchronous event (NVMe-MI"
            " 'Asynchronous Events')", HFILL },
        },
        { &hf_nvme_mi_mi_aes_aese_rsvd,
          { "Reserved", "nvme-mi.mi.aes.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x7F00,
            "AE Supported Info bits 14:08", HFILL },
        },

        /* AE Occurrence List (Configuration Set Asynchronous Event response
         * data / AEM body; NVMe-MI 2.2 Figures 61 and 62) */
        { &hf_nvme_mi_mi_aeo_list,
          { "AE Occurrence List", "nvme-mi.mi.aeo",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_numaeo,
          { "Number of AE Occurrence Data Structures (NUMAEO)",
            "nvme-mi.mi.aeo.numaeo",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aelver,
          { "AE Occurrence List Version Number (AELVER)",
            "nvme-mi.mi.aeo.aelver",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeolli,
          { "AE Occurrence List Length Info (AEOLLI)",
            "nvme-mi.mi.aeo.aeolli",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeolo,
          { "AE Occurrence List Overflow (AEOLO)", "nvme-mi.mi.aeo.aeolo",
            FT_BOOLEAN, 24, NULL, 0x800000,
            "Set when the list body would exceed 4 KiB; the header is then"
            " present without a body", HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeoltl,
          { "AE Occurrence List Total Length (AEOLTL)",
            "nvme-mi.mi.aeo.aeoltl",
            FT_UINT24, BASE_DEC, NULL, 0x7fffff, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeolhl,
          { "AE Occurrence List Header Length (AEOLHL)",
            "nvme-mi.mi.aeo.aeolhl",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_hdr_unknown,
          { "Unknown header bytes", "nvme-mi.mi.aeo.hdr_unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Bytes of a header longer than AEOLHL 7h or AELHLEN 9h", HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aemti,
          { "AEM Transmission Info (AEMTI)", "nvme-mi.mi.aeo.aemti",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Not applicable, and cleared to 0h, in a Configuration Set"
            " response", HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aemgn,
          { "AEM Generation Number (AEMGN)", "nvme-mi.mi.aeo.aemgn",
            FT_UINT8, BASE_DEC, NULL, 0xf8, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aemrc,
          { "AEM Retry Count (AEMRC)", "nvme-mi.mi.aeo.aemrc",
            FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_entry,
          { "AE Occurrence", "nvme-mi.mi.aeo.entry",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aelhlen,
          { "AE Occurrence Header Length (AELHLEN)",
            "nvme-mi.mi.aeo.aelhlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeosil,
          { "AE Occurrence Specific Info Length (AEOSIL)",
            "nvme-mi.mi.aeo.aeosil",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeovsil,
          { "AE Occurrence Vendor Specific Info Length (AEOVSIL)",
            "nvme-mi.mi.aeo.aeovsil",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeoui,
          { "AE Occurrence Unique ID (AEOUI)", "nvme-mi.mi.aeo.aeoui",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeoi,
          { "AE Occurrence ID (AEOI)", "nvme-mi.mi.aeo.aeoi",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_ae_id_vals), 0x0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeocidi,
          { "AE Occurrence Scope ID Info (AEOCIDI)",
            "nvme-mi.mi.aeo.aeocidi",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Scope identifier; its layout is selected by the AE Occurrence"
            " Scope field", HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aessi,
          { "AE Occurrence Scope Info (AESSI)", "nvme-mi.mi.aeo.aessi",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aess,
          { "AE Occurrence Scope (AESS)", "nvme-mi.mi.aeo.aess",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_aeo_scope_vals),
            0x0f, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aessi_rsvd,
          { "Reserved", "nvme-mi.mi.aeo.aessi.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeonsid,
          { "AE Occurrence Namespace ID (AEONSID)",
            "nvme-mi.mi.aeo.aeonsid",
            FT_UINT32, BASE_HEX, NULL, 0xffffffff, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeocid,
          { "AE Occurrence Controller ID (AEOCID)",
            "nvme-mi.mi.aeo.aeocid",
            FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeomeid,
          { "AE Occurrence Management Endpoint ID (AEOMEID)",
            "nvme-mi.mi.aeo.aeomeid",
            FT_UINT32, BASE_HEX, NULL, 0x000000ff, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeopt,
          { "AE Occurrence Port Type (AEOPT)", "nvme-mi.mi.aeo.aeopt",
            FT_BOOLEAN, 32, TFS(&tfs_aeo_port_type), 0x00010000, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeopid,
          { "AE Occurrence Port ID (AEOPID)", "nvme-mi.mi.aeo.aeopid",
            FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeoegid,
          { "AE Occurrence Endurance Group ID (AEOEGID)",
            "nvme-mi.mi.aeo.aeoegid",
            FT_UINT32, BASE_HEX, NULL, 0x0000ffff, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_scope_rsvd,
          { "Reserved", "nvme-mi.mi.aeo.scope_rsvd",
            FT_UINT32, BASE_HEX, NULL, 0xffff0000, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_meid_rsvd,
          { "Reserved", "nvme-mi.mi.aeo.meid_rsvd",
            FT_UINT32, BASE_HEX, NULL, 0xffffff00, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_port_rsvd,
          { "Reserved", "nvme-mi.mi.aeo.port_rsvd",
            FT_UINT32, BASE_HEX, NULL, 0xfffe0000, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_subsys_rsvd,
          { "Reserved", "nvme-mi.mi.aeo.subsys_rsvd",
            FT_UINT32, BASE_HEX, NULL, 0xffffffff,
            "NVM Subsystem scope: the whole Scope ID Info field is Reserved"
            " (NVMe-MI 'AE Occurrence Scope ID Info Field Format')", HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeosi,
          { "AE Occurrence Specific Info (AEOSI)", "nvme-mi.mi.aeo.aeosi",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Per-AE-ID info; the layout is defined per identifier in NVMe-MI"
            " 2.2 'AE Occurrence Specific Info Data Structure'", HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeovsi,
          { "AE Occurrence Vendor Specific Info (AEOVSI)",
            "nvme-mi.mi.aeo.aeovsi",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeovsh,
          { "Vendor Specific", "nvme-mi.mi.aeo.aeovsh",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeovsui,
          { "AE Occurrence Vendor Specific UUID Index (AEOVSUI)",
            "nvme-mi.mi.aeo.aeovsui",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            "Index into the UUID List identifying the defining vendor; 0h if"
            " none", HFILL },
        },
        { &hf_nvme_mi_mi_aeo_aeovs_data,
          { "Vendor Specific Data", "nvme-mi.mi.aeo.aeovs_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },

        /* Reset (07h) */
        { &hf_nvme_mi_mi_reset_rsttyp,
          { "Reset Type (RSTTYP)", "nvme-mi.mi.reset.rsttyp",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_rsttyp_vals), 0xFF000000,
            "Type of reset to perform", HFILL },
        },

        /* Shutdown (0Ch) */
        { &hf_nvme_mi_mi_shutdown_shdntyp,
          { "Shutdown Type (SHDNTYP)", "nvme-mi.mi.shutdown.shdntyp",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_shdntyp_vals), 0xFF000000,
            "Type of shutdown to perform", HFILL },
        },

        /* NVM Subsystem Information (DTYP 00h) */
        { &hf_nvme_mi_mi_subsys_nump,
          { "Number of Ports (NUMP)", "nvme-mi.mi.subsys.nump",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Maximum number of ports supported, 0's based", HFILL },
        },
        { &hf_nvme_mi_mi_subsys_mjr,
          { "NVMe-MI Major Version Number (MJR)", "nvme-mi.mi.subsys.mjr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_subsys_mnr,
          { "NVMe-MI Minor Version Number (MNR)", "nvme-mi.mi.subsys.mnr",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_subsys_nnsc,
          { "NVM Subsystem Capabilities (NNSC)", "nvme-mi.mi.subsys.nnsc",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_subsys_sre,
          { "Status Reporting Enhancements (SRE) [obsolete in MI 2.2, shall be 1]",
            "nvme-mi.mi.subsys.sre",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_subsys_nnsc_rsvd,
          { "Reserved", "nvme-mi.mi.subsys.nnsc_reserved",
            FT_UINT8, BASE_HEX, NULL, 0xfe,
            NULL, HFILL },
        },

        /* Port Information (DTYP 01h) */
        { &hf_nvme_mi_mi_port_prttyp,
          { "Port Type (PRTTYP)", "nvme-mi.mi.port.prttyp",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_prttyp_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_prtcap,
          { "Port Capabilities (PRTCAP)", "nvme-mi.mi.port.prtcap",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_aems,
          { "Asynchronous Event Messages Supported (AEMS)",
            "nvme-mi.mi.port.aems",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_ciaps,
          { "Command Initiated Auto Pause Supported (CIAPS) [obsolete in MI 2.2, shall be 1]",
            "nvme-mi.mi.port.ciaps",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_mmtus,
          { "Maximum MCTP Transmission Unit Size (MMTUS)",
            "nvme-mi.mi.port.mmtus",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_mebs,
          { "Management Endpoint Buffer Size (MEBS)", "nvme-mi.mi.port.mebs",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Size in bytes; 0 = no Management Endpoint Buffer", HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_mps,
          { "PCIe Maximum Payload Size (PCIEMPS)", "nvme-mi.mi.port.pcie.mps",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_pciemps_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv,
          { "PCIe Supported Link Speeds Vector (PCIESLSV)",
            "nvme-mi.mi.port.pcie.slsv",
            FT_UINT8, BASE_HEX, NULL, 0,
            "One bit per supported link speed, not an enumeration", HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv_g2p5,
          { "2.5 GT/s Support (GTS2P5)", "nvme-mi.mi.port.pcie.slsv.gts2p5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv_g5,
          { "5.0 GT/s Support (GTS5)", "nvme-mi.mi.port.pcie.slsv.gts5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv_g8,
          { "8.0 GT/s Support (GTS8)", "nvme-mi.mi.port.pcie.slsv.gts8",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv_g16,
          { "16.0 GT/s Support (GTS16)", "nvme-mi.mi.port.pcie.slsv.gts16",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv_g32,
          { "32.0 GT/s Support (GTS32)", "nvme-mi.mi.port.pcie.slsv.gts32",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv_g64,
          { "64.0 GT/s Support (GTS64)", "nvme-mi.mi.port.pcie.slsv.gts64",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv_rsvd,
          { "Reserved", "nvme-mi.mi.port.pcie.slsv_reserved",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_cls,
          { "PCIe Current Link Speed (PCIECLS)", "nvme-mi.mi.port.pcie.cls",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_pciecls_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_mlw,
          { "PCIe Maximum Link Width (PCIEMLW)", "nvme-mi.mi.port.pcie.mlw",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(mi_pciemlw_vals), 0,
            "Maximum link width in lanes", HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_nlw,
          { "PCIe Negotiated Link Width (PCIENLW)", "nvme-mi.mi.port.pcie.nlw",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(mi_pcienlw_vals), 0,
            "Negotiated link width in lanes; 0 = link not active", HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_pn,
          { "PCIe Port Number (PCIEPN)", "nvme-mi.mi.port.pcie.pn",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_cvpdaddr,
          { "Current VPD Address (CVPDADDR)", "nvme-mi.mi.port.cvpdaddr",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Current VPD SMBus/I2C address; 0 = no VPD", HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_mvpdfreq,
          { "Maximum VPD Access Frequency (MVPDFREQ)",
            "nvme-mi.mi.port.mvpdfreq",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_vpdfreq_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_cmeaddr,
          { "Current Management Endpoint Address (CMEADDR)",
            "nvme-mi.mi.port.cmeaddr",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Current 2-Wire address; 0 = no Management Endpoint", HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_twprt,
          { "2-Wire Protocols Supported (TWPRT)", "nvme-mi.mi.port.twprt",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_i3csprt,
          { "I3C Support (I3CSPRT)", "nvme-mi.mi.port.i3csprt",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_msmbfreq,
          { "Maximum SMBus/I2C Frequency (MSMBFREQ)",
            "nvme-mi.mi.port.msmbfreq",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_vpdfreq_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_nvmebm,
          { "NVMe Basic Management (NVMEBM)", "nvme-mi.mi.port.nvmebm",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_nvmebms,
          { "NVMe Basic Management Support (NVMEBMS)",
            "nvme-mi.mi.port.nvmebms",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_prtcap_rsvd,
          { "Reserved", "nvme-mi.mi.port.prtcap_reserved",
            FT_UINT8, BASE_HEX, NULL, 0xfc,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_twprt_rsvd,
          { "Reserved", "nvme-mi.mi.port.twprt_reserved",
            FT_UINT8, BASE_HEX, NULL, 0x7c,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_nvmebm_rsvd,
          { "Reserved", "nvme-mi.mi.port.nvmebm_reserved",
            FT_UINT8, BASE_HEX, NULL, 0xfe,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_pdas,
          { "PDA Size (PDAS)", "nvme-mi.mi.port.pdas",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(nvme_mi_pdas_fmt), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_sdformat,
          { "Supported Data Format (SDFORMAT)", "nvme-mi.mi.port.sdformat",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_sdformat_byte,
          { "Byte Level", "nvme-mi.mi.port.sdformat.byte",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_sdformat_512,
          { "512B", "nvme-mi.mi.port.sdformat.512b",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_sdformat_4k,
          { "4 KiB", "nvme-mi.mi.port.sdformat.4kib",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_twire_sdformat_rsvd,
          { "Reserved", "nvme-mi.mi.port.sdformat.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0xf8,
            NULL, HFILL },
        },

        /* Controller List (DTYP 02h) */
        { &hf_nvme_mi_mi_ctrllist_numids,
          { "Number of Identifiers", "nvme-mi.mi.ctrllist.numids",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrllist_ctrlid,
          { "Controller Identifier", "nvme-mi.mi.ctrllist.ctrlid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },

        /* Controller Information (DTYP 03h) */
        { &hf_nvme_mi_mi_ctrlinfo_portid,
          { "Port Identifier (PORTID)", "nvme-mi.mi.ctrlinfo.portid",
            FT_UINT8, BASE_DEC, NULL, 0,
            "PCIe port with which the Controller is associated", HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_prii,
          { "PCIe Routing ID Information (PRII)", "nvme-mi.mi.ctrlinfo.prii",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_riv,
          { "PCIe Routing ID Valid (PCIERIV)", "nvme-mi.mi.ctrlinfo.riv",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
            "Bus and Device numbers have been captured", HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_prii_rsvd,
          { "Reserved", "nvme-mi.mi.ctrlinfo.prii_reserved",
            FT_UINT8, BASE_HEX, NULL, 0xfe,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pri,
          { "PCIe Routing ID (PRI)", "nvme-mi.mi.ctrlinfo.pri",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pri_bus,
          { "PCI Bus Number (PCIBN)", "nvme-mi.mi.ctrlinfo.pri.bus",
            FT_UINT16, BASE_HEX, NULL, 0xFF00,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pri_dev,
          { "PCI Device Number (PCIDN)", "nvme-mi.mi.ctrlinfo.pri.dev",
            FT_UINT16, BASE_HEX, NULL, 0x00F8,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pri_fn,
          { "PCI Function Number (PCIFN)", "nvme-mi.mi.ctrlinfo.pri.fn",
            FT_UINT16, BASE_HEX, NULL, 0x0007,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pri_arifn,
          { "PCI Function Number (ARI)", "nvme-mi.mi.ctrlinfo.pri.arifn",
            FT_UINT16, BASE_HEX, NULL, 0x00FF,
            "For an ARI Device, PCIe Routing ID bits 7:0 are a single 8-bit"
            " Function Number that replaces the 5-bit Device Number and 3-bit"
            " Function Number (NVMe-MI 'Controller Information Data Structure',"
            " note)", HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pcivid,
          { "PCI Vendor ID (PCIVID)", "nvme-mi.mi.ctrlinfo.pcivid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pcidid,
          { "PCI Device ID (PCIDID)", "nvme-mi.mi.ctrlinfo.pcidid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pcisvid,
          { "PCI Subsystem Vendor ID (PCISVID)", "nvme-mi.mi.ctrlinfo.pcisvid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pcisdid,
          { "PCI Subsystem Device ID (PCISDID)", "nvme-mi.mi.ctrlinfo.pcisdid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_ctrlinfo_pciesn,
          { "PCIe Segment Number (PCIESN)", "nvme-mi.mi.ctrlinfo.pciesn",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Segment Number when the PCIe link is in Flit mode", HFILL },
        },

        /* Command lists (DTYP 04h/05h) */
        { &hf_nvme_mi_mi_cmdlist_numcmd,
          { "Number of Commands (NUMCMD)", "nvme-mi.mi.cmdlist.numcmd",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cmdlist_ctyp,
          { "Command Type (CTYP)", "nvme-mi.mi.cmdlist.ctyp",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cmdlist_nmimt,
          { "NVMe-MI Message Type (NMIMT)", "nvme-mi.mi.cmdlist.nmimt",
            FT_UINT8, BASE_HEX, VALS(mi_type_vals), 0x78,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cmdlist_rsvd_high,
          { "Reserved (bit 7)", "nvme-mi.mi.cmdlist.rsvd_high",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cmdlist_rsvd_low,
          { "Reserved (bits 2:0)", "nvme-mi.mi.cmdlist.rsvd_low",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cmdlist_opc,
          { "Opcode (OPC)", "nvme-mi.mi.cmdlist.opc",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_list_surplus,
          { "Surplus List Data", "nvme-mi.mi.list_surplus",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Response Data present after the last element declared by a"
            " Controller or command list", HFILL },
        },

        /* NVM Subsystem Health Data Structure */
        { &hf_nvme_mi_mi_nshds_nss,
          { "NVM Subsystem Status (NSS)", "nvme-mi.mi.nshds.nss",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_nss_atf,
          { "AEM Transmission Failure (ATF)", "nvme-mi.mi.nshds.nss.atf",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_nss_sfm,
          { "Sanitize Failure Mode (SFM)", "nvme-mi.mi.nshds.nss.sfm",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_nss_df,
          { "Drive Functional (DF)", "nvme-mi.mi.nshds.nss.df",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_nss_rnr,
          { "Reset Not Required (RNR)", "nvme-mi.mi.nshds.nss.rnr",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_nss_p0la,
          { "Port 0 PCIe Link Active (P0LA)", "nvme-mi.mi.nshds.nss.p0la",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_nss_p1la,
          { "Port 1 PCIe Link Active (P1LA)", "nvme-mi.mi.nshds.nss.p1la",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_nss_snfm,
          { "Sanitize Namespace Failure Mode (SNFM)",
            "nvme-mi.mi.nshds.nss.snfm",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_nss_rsvd,
          { "Reserved", "nvme-mi.mi.nshds.nss.reserved",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw,
          { "SMART Warnings (SW)", "nvme-mi.mi.nshds.sw",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Inverted Critical Warning field of the SMART log page",
            HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw_rsvd,
          { "Reserved", "nvme-mi.mi.nshds.sw_reserved",
            FT_BOOLEAN, 8, NULL, 0x80,
            "Inverted Critical Warning bit 7 (Reserved); normally 1", HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw_ips,
          { "Indeterminate Personality State (IPS)",
            "nvme-mi.mi.nshds.sw.ips",
            FT_BOOLEAN, 8, TFS(&tfs_nshds_sw), 0x40,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw_pmre,
          { "Persistent Memory Region Error (PMRE)",
            "nvme-mi.mi.nshds.sw.pmre",
            FT_BOOLEAN, 8, TFS(&tfs_nshds_sw), 0x20,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw_vmbf,
          { "Volatile Memory Backup Failed (VMBF)",
            "nvme-mi.mi.nshds.sw.vmbf",
            FT_BOOLEAN, 8, TFS(&tfs_nshds_sw), 0x10,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw_ro,
          { "Read Only (RO)", "nvme-mi.mi.nshds.sw.ro",
            FT_BOOLEAN, 8, TFS(&tfs_nshds_sw), 0x08,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw_rd,
          { "Reliability Degraded (RD)", "nvme-mi.mi.nshds.sw.rd",
            FT_BOOLEAN, 8, TFS(&tfs_nshds_sw), 0x04,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw_taut,
          { "Temperature Above or Under Threshold (TAUT)",
            "nvme-mi.mi.nshds.sw.taut",
            FT_BOOLEAN, 8, TFS(&tfs_nshds_sw), 0x02,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_sw_st,
          { "Spare Threshold (ST)", "nvme-mi.mi.nshds.sw.st",
            FT_BOOLEAN, 8, TFS(&tfs_nshds_sw), 0x01,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_ctemp,
          { "Composite Temperature (CTEMP)", "nvme-mi.mi.nshds.ctemp",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(nvme_mi_mi_fmt_nshds_ctemp), 0,
            "Composite temperature of the NVM Subsystem", HFILL },
        },
        { &hf_nvme_mi_mi_nshds_pdlu,
          { "Percentage Drive Life Used (PDLU)", "nvme-mi.mi.nshds.pdlu",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_nshds_ccs,
          { "Composite Controller Status Flags (CCSF)", "nvme-mi.mi.nshds.ccs",
            FT_UINT16, BASE_HEX, NULL, 0,
            "NVMe-MI 'NVM Subsystem Health Data Structure (NSHDS)'", HFILL },
        },
        { &hf_nvme_mi_mi_nshds_rsvd,
          { "Reserved", "nvme-mi.mi.nshds.reserved",
            FT_UINT16, BASE_HEX, NULL, 0,
            "NVM Subsystem Health data structure bytes 7:6", HFILL },
        },

        /* Shared health-status flag bits (NVMe-MI 2.1 "Controller Health
         * Status Changed Flags (CHSCF)" / "Composite Controller Status
         * Data Structure (CCSDS)") */
        { &hf_nvme_mi_mi_hsf_rsvd_15_14,
          { "Reserved", "nvme-mi.mi.hsf.rsvd_15_14",
            FT_UINT16, BASE_HEX, NULL, 0xc000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_tcida,
          { "Telemetry Controller-Initiated Data Available Flag (TCIDAF)",
            "nvme-mi.mi.hsf.tcida",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x2000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_cwarn,
          { "Critical Warning Flag (CWARNF)", "nvme-mi.mi.hsf.cwarn",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x1000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_spare,
          { "Available Spare Flag (SPAREF)", "nvme-mi.mi.hsf.spare",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0800,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_pdlu,
          { "Percentage Drive Life Used Flag (PDLUF)", "nvme-mi.mi.hsf.pdlu",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0400,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_ctemp,
          { "Composite Temperature Change Flag (CTEMPF)", "nvme-mi.mi.hsf.ctemp",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0200,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_csts,
          { "Controller Status Change Flag (CSF)", "nvme-mi.mi.hsf.csts",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0100,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_fa,
          { "Firmware Activated Flag (FAF)", "nvme-mi.mi.hsf.fa",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0080,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_nac,
          { "Namespace Attribute Changed Flag (NACF)", "nvme-mi.mi.hsf.nac",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0040,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_ceco,
          { "Controller Enable Change Occurred Flag (CECOF)", "nvme-mi.mi.hsf.ceco",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0020,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_nssro,
          { "NVM Subsystem Reset Occurred Flag (NSSROF)", "nvme-mi.mi.hsf.nssro",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0010,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_rsvd_3,
          { "Reserved", "nvme-mi.mi.hsf.rsvd_3",
            FT_UINT16, BASE_HEX, NULL, 0x0008,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_shst,
          { "Shutdown Status Flag (SHSTF)", "nvme-mi.mi.hsf.shst",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_cfs,
          { "Controller Fatal Status Flag (CFSF)", "nvme-mi.mi.hsf.cfs",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_rdy,
          { "Ready Flag (RDYF)", "nvme-mi.mi.hsf.rdy",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001,
            NULL, HFILL },
        },

        /* Controller Health Data Structure */
        { &hf_nvme_mi_mi_chds_ctlid,
          { "Controller Identifier (CTLID)", "nvme-mi.mi.chds.ctlid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts,
          { "Controller Status (CS)", "nvme-mi.mi.chds.csts",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Named CSTS in NVMe-MI 2.1", HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_tcida,
          { "Telemetry Controller-Initiated Data Available (TCIDA) [obsolete in MI 2.2, shall be 1]",
            "nvme-mi.mi.chds.csts.tcida",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0100,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_fa,
          { "Firmware Activated (FA)", "nvme-mi.mi.chds.csts.fa",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0080,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_nac,
          { "Namespace Attribute Changed (NAC)", "nvme-mi.mi.chds.csts.nac",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0040,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_ceco,
          { "Controller Enable Change Occurred (CECO)",
            "nvme-mi.mi.chds.csts.ceco",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0020,
            "Indicates the value of CC.EN", HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_nssro,
          { "NVM Subsystem Reset Occurred (NSSRO)",
            "nvme-mi.mi.chds.csts.nssro",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0010,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_shst,
          { "Shutdown Status (SHST)", "nvme-mi.mi.chds.csts.shst",
            FT_UINT16, BASE_HEX, VALS(shst_table), 0x000C,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_cfs,
          { "Controller Fatal Status (CFS)", "nvme-mi.mi.chds.csts.cfs",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_rdy,
          { "Ready (RDY)", "nvme-mi.mi.chds.csts.rdy",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_ctemp,
          { "Composite Temperature (CTEMP)", "nvme-mi.mi.chds.ctemp",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(nvme_mi_mi_fmt_kelvin), 0,
            "Composite temperature of the Controller in Kelvins", HFILL },
        },
        { &hf_nvme_mi_mi_chds_pdlu,
          { "Percentage Used (PDLU)", "nvme-mi.mi.chds.pdlu",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_percent), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_spare,
          { "Available Spare (SPARE)", "nvme-mi.mi.chds.spare",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_percent), 0,
            "Normalized percentage of remaining spare capacity", HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn,
          { "Critical Warning (CWARN)", "nvme-mi.mi.chds.cwarn",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn_rsvd,
          { "Reserved", "nvme-mi.mi.chds.cwarn_reserved",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn_ips,
          { "Indeterminate Personality State (IPS)",
            "nvme-mi.mi.chds.cwarn.ips",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn_pmre,
          { "Persistent Memory Region Error (PMRE)",
            "nvme-mi.mi.chds.cwarn.pmre",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn_vmbf,
          { "Volatile Memory Backup Failed (VMBF)",
            "nvme-mi.mi.chds.cwarn.vmbf",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn_ro,
          { "Read Only (RO)", "nvme-mi.mi.chds.cwarn.ro",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn_rd,
          { "Reliability Degraded (RD)", "nvme-mi.mi.chds.cwarn.rd",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn_taut,
          { "Temperature Above or Under Threshold (TAUT)",
            "nvme-mi.mi.chds.cwarn.taut",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn_st,
          { "Spare Threshold (ST)", "nvme-mi.mi.chds.cwarn.st",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_chsc,
          { "Controller Health Status Changed Flags (CHSCF)",
            "nvme-mi.mi.chds.chsc",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Controller Health Status Changed Flags (CHSCF)", HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_rsvd,
          { "Reserved", "nvme-mi.mi.chds.csts_reserved",
            FT_UINT16, BASE_HEX, NULL, 0xfe00,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_rsvd,
          { "Reserved", "nvme-mi.mi.chds.reserved",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Controller Health data structure bytes 15:11", HFILL },
        },
    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi_mi,
        &ett_nvme_mi_mi_field,
        &ett_nvme_mi_mi_entry,
        &ett_nvme_mi_aem,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_mi_mi_reset_response,
          { "nvme-mi.mi.reset_success_response", PI_PROTOCOL, PI_NOTE,
            "The Reset NVM Subsystem command does not transmit a Success"
            " Response (NVMe-MI section 5.9)", EXPFILL } },
        { &ei_nvme_mi_mi_vpd_checksum,
          { "nvme-mi.mi.vpd.bad_checksum", PI_CHECKSUM, PI_WARN,
            "VPD checksum is not zero modulo 256", EXPFILL } },
        { &ei_nvme_mi_mi_vpd_length,
          { "nvme-mi.mi.vpd.invalid_length", PI_PROTOCOL, PI_WARN,
            "VPD length or count contradicts the bounded structure", EXPFILL } },
        { &ei_nvme_mi_mi_truncated,
          { "nvme-mi.mi.truncated", PI_MALFORMED, PI_WARN,
            "MI command payload truncated", EXPFILL }
        },
        { &ei_nvme_mi_mi_orphan_response,
          { "nvme-mi.mi.orphan_response", PI_SEQUENCE, PI_NOTE,
            "MI response without a usable matching request; opcode could"
            " not be recovered", EXPFILL }
        },
        { &ei_nvme_mi_mi_reserved_dtyp,
          { "nvme-mi.mi.reserved_dtyp", PI_PROTOCOL, PI_NOTE,
            "Data Structure Type is in the Reserved range (06h-FFh)",
            EXPFILL }
        },
        { &ei_nvme_mi_mi_reserved_configid,
          { "nvme-mi.mi.reserved_configid", PI_PROTOCOL, PI_NOTE,
            "Configuration Identifier is in a Reserved range (00h, 05h-BFh)",
            EXPFILL }
        },
        { &ei_nvme_mi_mi_reserved_value,
          { "nvme-mi.mi.reserved_value", PI_PROTOCOL, PI_NOTE,
            "A command-specific field carries a Reserved value", EXPFILL }
        },
        { &ei_nvme_mi_mi_reserved_opcode,
          { "nvme-mi.mi.reserved_opcode", PI_PROTOCOL, PI_NOTE,
            "MI command opcode is in the Reserved range (10h-BFh)",
            EXPFILL }
        },
        { &ei_nvme_mi_mi_aeo_list_invalid,
          { "nvme-mi.mi.aeo_list_invalid", PI_MALFORMED, PI_ERROR,
            "AE Occurrence List count or length contradicts the data present",
            EXPFILL }
        },
        { &ei_nvme_mi_mi_ae_list_invalid,
          { "nvme-mi.mi.ae_list_invalid", PI_MALFORMED, PI_ERROR,
            "AE Enable/Supported List count or length contradicts the data"
            " present", EXPFILL }
        },
        { &ei_nvme_mi_mi_ae_aeetl_mismatch,
          { "nvme-mi.mi.ae.aeetl_mismatch", PI_PROTOCOL, PI_NOTE,
            "AE Enable List Total Length is not AEELHL plus its entries"
            " (NVMe-MI 'AE Enable List Data Structure')", EXPFILL }
        },
        { &ei_nvme_mi_mi_aes_field_invalid,
          { "nvme-mi.mi.aes.field_invalid", PI_PROTOCOL, PI_WARN,
            "AE Supported List field does not hold its required value",
            EXPFILL }
        },
        { &ei_nvme_mi_mi_error_surplus,
          { "nvme-mi.mi.error_surplus", PI_MALFORMED, PI_WARN,
            "Bytes follow a 4-byte Response Message whose format the Status"
            " defines", EXPFILL }
        },
        { &ei_nvme_mi_mi_cfg_aeelver,
          { "nvme-mi.mi.config.aeelver_nonzero", PI_PROTOCOL, PI_WARN,
            "AEELVER shall be cleared to 0h (NVMe-MI 'Asynchronous Event -"
            " NVMe Management Response')",
            EXPFILL }
        },
        { &ei_nvme_mi_mi_pda_dlen_max,
          { "nvme-mi.mi.pda.dlen_max", PI_PROTOCOL, PI_WARN,
            "DLEN exceeds the conservative PDA maximum for its DFORMAT", EXPFILL }
        },
        { &ei_nvme_mi_mi_request_data_length,
          { "nvme-mi.mi.request_data_length", PI_MALFORMED, PI_ERROR,
            "Request Data length does not match DLEN", EXPFILL }
        },
        { &ei_nvme_mi_mi_chsp_maxrent,
          { "nvme-mi.mi.chsp.maxrent_invalid", PI_PROTOCOL, PI_WARN,
            "MAXRENT FFh asks for 256 entries but the maximum is 255; the"
            " Responder returns an Invalid Parameter Error Response (NVMe-MI"
            " 'Controller Health Status Poll - NVMe Management Dword 0')", EXPFILL }
        },
        { &ei_nvme_mi_mi_unexpected_request_data,
          { "nvme-mi.mi.unexpected_request_data", PI_PROTOCOL, PI_WARN,
            "Request Data on a command that defines none; a Responder returns"
            " Invalid Command Size (NVMe-MI 'Response Message Status Values', 05h)", EXPFILL }
        },
        { &ei_nvme_mi_mi_aeo_field_invalid,
          { "nvme-mi.mi.aeo_field_invalid", PI_PROTOCOL, PI_WARN,
            "AE Occurrence field violates its NVMe-MI definition",
            EXPFILL }
        },
        { &ei_nvme_mi_mi_response_data_length,
          { "nvme-mi.mi.response_data_length", PI_MALFORMED, PI_ERROR,
            "Response Data contradicts its declared or fixed length", EXPFILL }
        },
    };

    expert_module_t *expert_nvme_mi_mi;

    proto_nvme_mi_mi = proto_register_protocol(
            "NVMe-MI MI Command", "NVMe-MI MI", "nvme-mi.mi");
    proto_register_field_array(proto_nvme_mi_mi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi_mi = expert_register_protocol(proto_nvme_mi_mi);
    expert_register_field_array(expert_nvme_mi_mi, ei, array_length(ei));

    nvme_mi_mi_handle = register_dissector_with_description(
            "nvme-mi.mi", "NVMe-MI MI Command",
            dissect_nvme_mi_mi, proto_nvme_mi_mi);

    proto_nvme_mi_aem = proto_register_protocol(
            "NVMe-MI Asynchronous Event Message", "NVMe-MI AEM",
            "nvme-mi.aem");
    nvme_mi_aem_handle = register_dissector_with_description(
            "nvme-mi.aem", "NVMe-MI Asynchronous Event Message",
            dissect_nvme_mi_aem, proto_nvme_mi_aem);
}

void
proto_reg_handoff_nvme_mi_mi(void)
{
    dissector_add_uint("nvme-mi.type", NVME_MI_TYPE_MI,
                       nvme_mi_mi_handle);
    dissector_add_uint("nvme-mi.type", NVME_MI_TYPE_AEM,
                       nvme_mi_aem_handle);
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
