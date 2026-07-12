/* packet-nvme-mi-mi.c
 * NVMe-MI MI Command dissector (NMIMT=1, NVMe-MI 2.1 §5)
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
 *
 * Decodes the Management Interface Command Set request dwords (NMD0/NMD1),
 * the command-specific NVMe Management Response field, and the Response Data
 * structures for opcodes 00h-04h.  Opcodes 05h-0Ch are named but their
 * bodies are rendered as raw dwords/data until fixtures exist for them.
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wsutil/utf8_entities.h>
#include "packet-nvme-mi.h"

void proto_register_nvme_mi_mi(void);
void proto_reg_handoff_nvme_mi_mi(void);

static int proto_nvme_mi_mi;

static int hf_nvme_mi_mi_opcode;
static int hf_nvme_mi_mi_cdw0;
static int hf_nvme_mi_mi_cdw1;
static int hf_nvme_mi_mi_status;
static int hf_nvme_mi_mi_nmresp;
static int hf_nvme_mi_mi_data;

/* Read NVMe-MI Data Structure (00h) — Figures 109/110/111 */
static int hf_nvme_mi_mi_rds_dtyp;
static int hf_nvme_mi_mi_rds_portid;
static int hf_nvme_mi_mi_rds_ctrlid;
static int hf_nvme_mi_mi_rds_iocsi;
static int hf_nvme_mi_mi_rds_rdl;

/* NVM Subsystem Health Status Poll (01h) — Figure 106 */
static int hf_nvme_mi_mi_nshsp_cs;

/* Controller Health Status Poll (02h) — Figures 94/95/96 */
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

/* Configuration Set (03h) / Configuration Get (04h) — Figures 73-90 */
static int hf_nvme_mi_mi_cfg_cid;
static int hf_nvme_mi_mi_cfg_portid;
static int hf_nvme_mi_mi_cfg_sfreq;
static int hf_nvme_mi_mi_cfg_mtus;
static int hf_nvme_mi_mi_cfg_sfreq_cur;
static int hf_nvme_mi_mi_cfg_mtus_cur;
static int hf_nvme_mi_mi_cfg_aeelver;
/* Health Status Change clear-selection bits (Set NMD1, Figure 88) */
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

/* VPD Read (05h) / VPD Write (06h) — Figures 128-133 (shared layout) */
static int hf_nvme_mi_mi_vpd_dofst;
static int hf_nvme_mi_mi_vpd_dlen;
static int hf_nvme_mi_mi_vpd_data;

/* Reset (07h) — Figure 122 */
static int hf_nvme_mi_mi_reset_rsttyp;

/* Shutdown (0Ch) — Figure 127 */
static int hf_nvme_mi_mi_shutdown_shdntyp;

/* NVM Subsystem Information data structure (DTYP 00h, Figure 112) */
static int hf_nvme_mi_mi_subsys_nump;
static int hf_nvme_mi_mi_subsys_mjr;
static int hf_nvme_mi_mi_subsys_mnr;
static int hf_nvme_mi_mi_subsys_nnsc;
static int hf_nvme_mi_mi_subsys_sre;

/* Port Information data structure (DTYP 01h, Figures 114/115/116) */
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

/* Controller List data structure (DTYP 02h, NVMe Base) */
static int hf_nvme_mi_mi_ctrllist_numids;
static int hf_nvme_mi_mi_ctrllist_ctrlid;

/* Controller Information data structure (DTYP 03h, Figure 117) */
static int hf_nvme_mi_mi_ctrlinfo_portid;
static int hf_nvme_mi_mi_ctrlinfo_prii;
static int hf_nvme_mi_mi_ctrlinfo_riv;
static int hf_nvme_mi_mi_ctrlinfo_pri;
static int hf_nvme_mi_mi_ctrlinfo_pri_bus;
static int hf_nvme_mi_mi_ctrlinfo_pri_dev;
static int hf_nvme_mi_mi_ctrlinfo_pri_fn;
static int hf_nvme_mi_mi_ctrlinfo_pcivid;
static int hf_nvme_mi_mi_ctrlinfo_pcidid;
static int hf_nvme_mi_mi_ctrlinfo_pcisvid;
static int hf_nvme_mi_mi_ctrlinfo_pcisdid;
static int hf_nvme_mi_mi_ctrlinfo_pciesn;

/* Optionally Supported / MEB Supported Command List (DTYP 04h/05h,
 * Figures 118-121) */
static int hf_nvme_mi_mi_cmdlist_numcmd;
static int hf_nvme_mi_mi_cmdlist_ctyp;
static int hf_nvme_mi_mi_cmdlist_nmimt;
static int hf_nvme_mi_mi_cmdlist_opc;

/* NVM Subsystem Health Data Structure (Figure 108) */
static int hf_nvme_mi_mi_nshds_nss;
static int hf_nvme_mi_mi_nshds_nss_atf;
static int hf_nvme_mi_mi_nshds_nss_sfm;
static int hf_nvme_mi_mi_nshds_nss_df;
static int hf_nvme_mi_mi_nshds_nss_rnr;
static int hf_nvme_mi_mi_nshds_nss_p0la;
static int hf_nvme_mi_mi_nshds_nss_p1la;
static int hf_nvme_mi_mi_nshds_nss_snfm;
static int hf_nvme_mi_mi_nshds_sw;
static int hf_nvme_mi_mi_nshds_ctemp;
static int hf_nvme_mi_mi_nshds_pdlu;
static int hf_nvme_mi_mi_nshds_ccs;

/* Shared health-status flag bits — same bit layout in the Composite
 * Controller Status Flags (Figure 107) and the Controller Health Status
 * Changed Flags (Figure 98). */
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
static int hf_nvme_mi_mi_hsf_shst;
static int hf_nvme_mi_mi_hsf_cfs;
static int hf_nvme_mi_mi_hsf_rdy;

/* Controller Health Data Structure (Figure 97) */
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
static int hf_nvme_mi_mi_chds_cwarn_ips;
static int hf_nvme_mi_mi_chds_cwarn_pmre;
static int hf_nvme_mi_mi_chds_cwarn_vmbf;
static int hf_nvme_mi_mi_chds_cwarn_ro;
static int hf_nvme_mi_mi_chds_cwarn_rd;
static int hf_nvme_mi_mi_chds_cwarn_taut;
static int hf_nvme_mi_mi_chds_cwarn_st;
static int hf_nvme_mi_mi_chds_chsc;

static int ett_nvme_mi_mi;
static int ett_nvme_mi_mi_field;
static int ett_nvme_mi_mi_entry;

static expert_field ei_nvme_mi_mi_truncated;
static expert_field ei_nvme_mi_mi_orphan_response;
static expert_field ei_nvme_mi_mi_reserved_dtyp;
static expert_field ei_nvme_mi_mi_reserved_configid;
static expert_field ei_nvme_mi_mi_reserved_value;

/* MI command opcodes (NVMe-MI 2.1 Figure 68).  Only 00h-07h, 0Ch get field-level
 * decode; 08h-0Bh are named for display and fall through to the raw dword
 * rendering. */
enum nvme_mi_mi_opc {
    NVME_MI_MI_OPC_READ_DS    = 0x00,
    NVME_MI_MI_OPC_SUBSYS_HSP = 0x01,
    NVME_MI_MI_OPC_CTRL_HSP   = 0x02,
    NVME_MI_MI_OPC_CONFIG_SET = 0x03,
    NVME_MI_MI_OPC_CONFIG_GET = 0x04,
    NVME_MI_MI_OPC_VPD_READ   = 0x05,
    NVME_MI_MI_OPC_VPD_WRITE  = 0x06,
    NVME_MI_MI_OPC_RESET      = 0x07,
    NVME_MI_MI_OPC_SHUTDOWN   = 0x0C,
};

static const value_string mi_opcode_vals[] = {
    { NVME_MI_MI_OPC_READ_DS,    "Read NVMe-MI Data Structure" },
    { NVME_MI_MI_OPC_SUBSYS_HSP, "NVM Subsystem Health Status Poll" },
    { NVME_MI_MI_OPC_CTRL_HSP,   "Controller Health Status Poll" },
    { NVME_MI_MI_OPC_CONFIG_SET, "Configuration Set" },
    { NVME_MI_MI_OPC_CONFIG_GET, "Configuration Get" },
    { NVME_MI_MI_OPC_VPD_READ,   "VPD Read" },
    { NVME_MI_MI_OPC_VPD_WRITE,  "VPD Write" },
    { NVME_MI_MI_OPC_RESET,      "Reset" },
    { 0x08,                      "SES Receive" },
    { 0x09,                      "SES Send" },
    { 0x0a,                      "Management Endpoint Buffer Read" },
    { 0x0b,                      "Management Endpoint Buffer Write" },
    { NVME_MI_MI_OPC_SHUTDOWN,   "Shutdown" },
    { 0, NULL },
};

/* Data Structure Types (Figure 109); 06h-FFh are reserved. */
enum nvme_mi_dtyp {
    NVME_MI_DTYP_SUBSYS_INFO = 0x00,
    NVME_MI_DTYP_PORT_INFO   = 0x01,
    NVME_MI_DTYP_CTRL_LIST   = 0x02,
    NVME_MI_DTYP_CTRL_INFO   = 0x03,
    NVME_MI_DTYP_OSC_LIST    = 0x04,
    NVME_MI_DTYP_MEB_LIST    = 0x05,
    NVME_MI_DTYP_MAX         = NVME_MI_DTYP_MEB_LIST,
};

static const value_string mi_dtyp_vals[] = {
    { NVME_MI_DTYP_SUBSYS_INFO, "NVM Subsystem Information" },
    { NVME_MI_DTYP_PORT_INFO,   "Port Information" },
    { NVME_MI_DTYP_CTRL_LIST,   "Controller List" },
    { NVME_MI_DTYP_CTRL_INFO,   "Controller Information" },
    { NVME_MI_DTYP_OSC_LIST,    "Optionally Supported Command List" },
    { NVME_MI_DTYP_MEB_LIST,    "Management Endpoint Buffer Command Support List" },
    { 0, NULL },
};

/* Configuration Identifiers (Figure 75); 00h and 05h-BFh are reserved,
 * C0h-FFh vendor specific. */
enum nvme_mi_cfgid {
    NVME_MI_CFGID_SMBUS_FREQ = 0x01,
    NVME_MI_CFGID_HSC        = 0x02,
    NVME_MI_CFGID_MTUS       = 0x03,
    NVME_MI_CFGID_AE         = 0x04,
    NVME_MI_CFGID_RESERVED_FIRST = 0x05,
    NVME_MI_CFGID_RESERVED_LAST  = 0xBF,
};

static const value_string mi_configid_vals[] = {
    { NVME_MI_CFGID_SMBUS_FREQ, "SMBus/I2C Frequency" },
    { NVME_MI_CFGID_HSC,        "Health Status Change" },
    { NVME_MI_CFGID_MTUS,       "MCTP Transmission Unit Size" },
    { NVME_MI_CFGID_AE,         "Asynchronous Event" },
    { 0, NULL },
};

/* SMBus/I2C frequency encoding (Figures 77/86) */
static const value_string mi_sfreq_vals[] = {
    { 0x0, "Obsolete/Reserved" },
    { 0x1, "100 kHz" },
    { 0x2, "400 kHz" },
    { 0x3, "1 MHz" },
    { 0, NULL },
};

/* Maximum VPD access / maximum SMBus frequency (Figure 116) */
static const value_string mi_vpdfreq_vals[] = {
    { 0x0, "Not supported" },
    { 0x1, "100 kHz" },
    { 0x2, "400 kHz" },
    { 0x3, "1 MHz" },
    { 0, NULL },
};

static const value_string mi_prttyp_vals[] = {
    { 0x0, "Inactive" },
    { 0x1, "PCIe" },
    { 0x2, "2-Wire" },
    { 0, NULL },
};

static const value_string mi_pciemps_vals[] = {
    { 0x0, "128 bytes" },
    { 0x1, "256 bytes" },
    { 0x2, "512 bytes" },
    { 0x3, "1 KiB" },
    { 0x4, "2 KiB" },
    { 0x5, "4 KiB" },
    { 0, NULL },
};

static const value_string mi_pciecls_vals[] = {
    { 0x0, "Link not active" },
    { 0x1, "2.5 GT/s" },
    { 0x2, "5.0 GT/s" },
    { 0x3, "8.0 GT/s" },
    { 0x4, "16.0 GT/s" },
    { 0x5, "32.0 GT/s" },
    { 0x6, "64.0 GT/s" },
    { 0, NULL },
};

/* Reset Type (Figure 122); 01h-FFh reserved */
#define NVME_MI_RSTTYP_MAX 0x00     /* highest valid Reset Type */
static const value_string mi_rsttyp_vals[] = {
    { 0x00, "Reset NVM Subsystem" },
    { 0, NULL },
};

/* Shutdown Type (Figure 127); 02h-FFh reserved */
#define NVME_MI_SHDNTYP_MAX 0x01    /* highest valid Shutdown Type */
static const value_string mi_shdntyp_vals[] = {
    { 0x00, "Normal NVM Subsystem Shutdown" },
    { 0x01, "Abrupt NVM Subsystem Shutdown" },
    { 0, NULL },
};

/* CSTS.SHST shutdown status (NVMe Base) */
static const value_string mi_shst_vals[] = {
    { 0x0, "Normal operation" },
    { 0x1, "Shutdown processing occurring" },
    { 0x2, "Shutdown processing complete" },
    { 0x3, "Reserved" },
    { 0, NULL },
};

/* NMIMT in command-list entries (Figure 119/121); same encoding as the
 * message header NMIMT. */
static const value_string mi_cmdlist_nmimt_vals[] = {
    { NVME_MI_TYPE_CONTROL, "Control Primitive" },
    { NVME_MI_TYPE_MI,      "MI Command" },
    { NVME_MI_TYPE_ADMIN,   "NVMe Admin Command" },
    { NVME_MI_TYPE_PCIE,    "PCIe Command" },
    { 0, NULL },
};

/*
 * Per-transaction request context hung off nvme_mi_transaction.body_ctx
 * (wmem_file_scope).  Records the request parameter that selects the
 * response layout; only the member matching the transaction's opcode is
 * meaningful.
 */
struct nvme_mi_mi_req_ctx {
    uint8_t dtyp;       /* Read NVMe-MI Data Structure (00h) */
    uint8_t configid;   /* Configuration Set/Get (03h/04h) */
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
static int * const vpd_cdw0_fields[] = {
    &hf_nvme_mi_mi_vpd_dofst,
    NULL,
};
static int * const vpd_cdw1_fields[] = {
    &hf_nvme_mi_mi_vpd_dlen,
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
    &hf_nvme_mi_mi_subsys_sre,
    NULL,
};
static int * const port_prtcap_fields[] = {
    &hf_nvme_mi_mi_port_aems,
    &hf_nvme_mi_mi_port_ciaps,
    NULL,
};
static int * const port_twprt_fields[] = {
    &hf_nvme_mi_mi_port_twire_i3csprt,
    &hf_nvme_mi_mi_port_twire_msmbfreq,
    NULL,
};
static int * const port_nvmebm_fields[] = {
    &hf_nvme_mi_mi_port_twire_nvmebms,
    NULL,
};
static int * const ctrlinfo_prii_fields[] = {
    &hf_nvme_mi_mi_ctrlinfo_riv,
    NULL,
};
static int * const ctrlinfo_pri_fields[] = {
    &hf_nvme_mi_mi_ctrlinfo_pri_bus,
    &hf_nvme_mi_mi_ctrlinfo_pri_dev,
    &hf_nvme_mi_mi_ctrlinfo_pri_fn,
    NULL,
};
static int * const cmdlist_ctyp_fields[] = {
    &hf_nvme_mi_mi_cmdlist_nmimt,
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
    NULL,
};
static int * const hsf_fields[] = {
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
    &hf_nvme_mi_mi_hsf_shst,
    &hf_nvme_mi_mi_hsf_cfs,
    &hf_nvme_mi_mi_hsf_rdy,
    NULL,
};
static int * const chds_csts_fields[] = {
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
 * NSHDS CTEMP encoding (Figure 108): 00h-7Eh = 0-126 °C, 7Fh = 127 °C or
 * higher, 80h/81h = sentinel codes, C4h = -60 °C or lower, C5h-FFh =
 * -59 to -1 °C in two's complement, the rest reserved.
 */
static void
nvme_mi_mi_fmt_nshds_ctemp(char *buf, uint32_t value)
{
    if (value <= 0x7e)
        snprintf(buf, ITEM_LABEL_LENGTH, "%u " UTF8_DEGREE_SIGN "C", value);
    else if (value == 0x7f)
        snprintf(buf, ITEM_LABEL_LENGTH, "127 " UTF8_DEGREE_SIGN "C or higher");
    else if (value == 0x80)
        snprintf(buf, ITEM_LABEL_LENGTH, "No temperature data or data is stale");
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

/* Flag truncated response data and render the leftover bytes raw. */
static void
nvme_mi_mi_data_truncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          proto_item *it, int off)
{
    expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
    if (tvb_reported_length_remaining(tvb, off) > 0)
        proto_tree_add_item(tree, hf_nvme_mi_mi_data, tvb, off, -1, ENC_NA);
}

/* DTYP 00h — NVM Subsystem Information (Figure 112) */
static void
nvme_mi_mi_data_subsys_info(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, proto_item *it, int off, int len)
{
    if (len < 4) {
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off);
        return;
    }
    proto_tree_add_item(tree, hf_nvme_mi_mi_subsys_nump, tvb, off, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_subsys_mjr, tvb, off + 1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_subsys_mnr, tvb, off + 2, 1, ENC_NA);
    proto_tree_add_bitmask(tree, tvb, off + 3, hf_nvme_mi_mi_subsys_nnsc,
                           ett_nvme_mi_mi_field, subsys_nnsc_fields, ENC_NA);
    /* bytes 31:04 reserved */
}

/* DTYP 01h — Port Information (Figures 114/115/116) */
static void
nvme_mi_mi_data_port_info(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, proto_item *it, int off, int len)
{
    uint32_t prttyp;

    if (len < 8) {
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off);
        return;
    }
    proto_tree_add_item_ret_uint(tree, hf_nvme_mi_mi_port_prttyp,
                                 tvb, off, 1, ENC_NA, &prttyp);
    proto_tree_add_bitmask(tree, tvb, off + 1, hf_nvme_mi_mi_port_prtcap,
                           ett_nvme_mi_mi_field, port_prtcap_fields, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_port_mmtus,
                        tvb, off + 2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_nvme_mi_mi_port_mebs,
                        tvb, off + 4, 4, ENC_LITTLE_ENDIAN);

    switch (prttyp) {
    case 0x1:   /* PCIe Port Specific Data (Figure 115) */
        if (len < 14) {
            nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off + 8);
            return;
        }
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_mps,
                            tvb, off + 8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_slsv,
                            tvb, off + 9, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_cls,
                            tvb, off + 10, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_mlw,
                            tvb, off + 11, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_nlw,
                            tvb, off + 12, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_pcie_pn,
                            tvb, off + 13, 1, ENC_NA);
        break;
    case 0x2:   /* 2-Wire Port Specific Data (Figure 116) */
        if (len < 13) {
            nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off + 8);
            return;
        }
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_twire_cvpdaddr,
                            tvb, off + 8, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_twire_mvpdfreq,
                            tvb, off + 9, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_port_twire_cmeaddr,
                            tvb, off + 10, 1, ENC_NA);
        proto_tree_add_bitmask(tree, tvb, off + 11,
                               hf_nvme_mi_mi_port_twire_twprt,
                               ett_nvme_mi_mi_field, port_twprt_fields, ENC_NA);
        proto_tree_add_bitmask(tree, tvb, off + 12,
                               hf_nvme_mi_mi_port_twire_nvmebm,
                               ett_nvme_mi_mi_field, port_nvmebm_fields, ENC_NA);
        break;
    default:
        /* Inactive or reserved port type: PTSP bytes rendered raw */
        if (len > 8)
            proto_tree_add_item(tree, hf_nvme_mi_mi_data, tvb, off + 8, -1,
                                ENC_NA);
        break;
    }
}

/* DTYP 02h — Controller List (NVMe Base format: count + uint16le IDs) */
static void
nvme_mi_mi_data_ctrl_list(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, proto_item *it, int off, int len)
{
    uint32_t numids;
    int pos = off + 2;

    if (len < 2) {
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off);
        return;
    }
    proto_tree_add_item_ret_uint(tree, hf_nvme_mi_mi_ctrllist_numids,
                                 tvb, off, 2, ENC_LITTLE_ENDIAN, &numids);
    for (uint32_t i = 0; i < numids; i++) {
        if (pos + 2 > off + len) {
            nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, pos);
            return;
        }
        proto_tree_add_item(tree, hf_nvme_mi_mi_ctrllist_ctrlid,
                            tvb, pos, 2, ENC_LITTLE_ENDIAN);
        pos += 2;
    }
}

/* DTYP 03h — Controller Information (Figure 117) */
static void
nvme_mi_mi_data_ctrl_info(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, proto_item *it, int off, int len)
{
    if (len < 17) {
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off);
        return;
    }
    proto_tree_add_item(tree, hf_nvme_mi_mi_ctrlinfo_portid,
                        tvb, off, 1, ENC_NA);
    /* bytes 04:01 reserved */
    proto_tree_add_bitmask(tree, tvb, off + 5, hf_nvme_mi_mi_ctrlinfo_prii,
                           ett_nvme_mi_mi_field, ctrlinfo_prii_fields, ENC_NA);
    proto_tree_add_bitmask(tree, tvb, off + 6, hf_nvme_mi_mi_ctrlinfo_pri,
                           ett_nvme_mi_mi_field, ctrlinfo_pri_fields,
                           ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_nvme_mi_mi_ctrlinfo_pcivid,
                        tvb, off + 8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_nvme_mi_mi_ctrlinfo_pcidid,
                        tvb, off + 10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_nvme_mi_mi_ctrlinfo_pcisvid,
                        tvb, off + 12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_nvme_mi_mi_ctrlinfo_pcisdid,
                        tvb, off + 14, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_nvme_mi_mi_ctrlinfo_pciesn,
                        tvb, off + 16, 1, ENC_NA);
    /* bytes 31:17 reserved */
}

/* DTYP 04h/05h — Optionally Supported / MEB Supported Command List
 * (Figures 118-121; both share the count + (CTYP, OPC) entry format) */
static void
nvme_mi_mi_data_cmd_list(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, proto_item *it, int off, int len)
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
        if (pos + 2 > off + len) {
            nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, pos);
            return;
        }
        proto_tree_add_bitmask(tree, tvb, pos, hf_nvme_mi_mi_cmdlist_ctyp,
                               ett_nvme_mi_mi_field, cmdlist_ctyp_fields,
                               ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mi_cmdlist_opc,
                            tvb, pos + 1, 1, ENC_NA);
        pos += 2;
    }
}

/* NVM Subsystem Health Data Structure (Figure 108; 8 bytes) */
static void
nvme_mi_mi_data_nshds(tvbuff_t *tvb, packet_info *pinfo,
                      proto_tree *tree, proto_item *it, int off, int len)
{
    if (len < 8) {
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, off);
        return;
    }
    proto_tree_add_bitmask(tree, tvb, off, hf_nvme_mi_mi_nshds_nss,
                           ett_nvme_mi_mi_field, nshds_nss_fields, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_nshds_sw, tvb, off + 1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_nshds_ctemp,
                        tvb, off + 2, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_nshds_pdlu,
                        tvb, off + 3, 1, ENC_NA);
    proto_tree_add_bitmask(tree, tvb, off + 4, hf_nvme_mi_mi_nshds_ccs,
                           ett_nvme_mi_mi_field, hsf_fields,
                           ENC_LITTLE_ENDIAN);
    /* bytes 7:6 reserved */
}

/* Array of 16-byte Controller Health Data Structures (Figure 97) */
static void
nvme_mi_mi_data_chds_list(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, proto_item *it, int off, int len)
{
    unsigned idx = 0;
    int pos = off;

    while (off + len - pos >= 16) {
        proto_tree *etree = proto_tree_add_subtree_format(tree, tvb, pos, 16,
                ett_nvme_mi_mi_entry, NULL,
                "Controller Health Data Structure %u", idx);
        proto_tree_add_item(etree, hf_nvme_mi_mi_chds_ctlid,
                            tvb, pos, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(etree, tvb, pos + 2, hf_nvme_mi_mi_chds_csts,
                               ett_nvme_mi_mi_field, chds_csts_fields,
                               ENC_LITTLE_ENDIAN);
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
        /* bytes 15:11 reserved */
        pos += 16;
        idx++;
    }
    if (pos < off + len)
        nvme_mi_mi_data_truncated(tvb, pinfo, tree, it, pos);
}

/* Append " (<opcode>[: <detail>])" to COL_INFO. */
static void
nvme_mi_mi_col_append(packet_info *pinfo, unsigned opcode, const char *detail)
{
    const char *name = val_to_str_const(opcode, mi_opcode_vals, "Unknown");

    if (detail)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s: %s)", name, detail);
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", name);
}

static const char *
nvme_mi_mi_configid_name(uint8_t cid)
{
    const char *name = try_val_to_str(cid, mi_configid_vals);

    if (!name)
        name = (cid >= 0xC0) ? "Vendor Specific" : "Reserved";
    return name;
}

/*
 * Decode a request whose only parameter is a type byte in NMD0 bits 31:24
 * with NMD1 reserved (Reset RSTTYP, Figure 122; Shutdown SHDNTYP,
 * Figure 127).  Values above max_valid are in the Reserved range.  Returns
 * the type's display name for COL_INFO.
 */
static const char *
nvme_mi_mi_dissect_typebyte_req(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *mi_tree, int * const *cdw0_fields,
                                uint8_t max_valid, const value_string *vals)
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
    return val_to_str_const(typ, vals, "Reserved");
}

/*
 * Body worker.  Kept separate from the registered wrapper so that a future
 * in-band NVMe-MI Send/Receive decode (NVMe Admin opcodes 1Dh/1Eh tunnel the
 * same MI command bytes) can call it directly with an explicit direction and
 * a NULL transaction.
 */
static int
dissect_nvme_mi_mi_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        bool resp, struct nvme_mi_transaction *trans)
{
    proto_item *it, *it2;
    proto_tree *mi_tree;
    unsigned len = tvb_reported_length(tvb);

    it = proto_tree_add_item(tree, proto_nvme_mi_mi, tvb, 0, -1, ENC_NA);
    mi_tree = proto_item_add_subtree(it, ett_nvme_mi_mi);

    if (!resp) {
        struct nvme_mi_mi_req_ctx *req = NULL;
        const char *detail = NULL;
        proto_item *cdw_it;
        uint8_t opcode;

        if (len < 1) {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_item_ret_uint8(mi_tree, hf_nvme_mi_mi_opcode, tvb, 0, 1, ENC_NA, &opcode);
        /* Record the request opcode so the matching response (which carries
         * no opcode of its own) can display it. */
        if (trans) {
            trans->opcode = opcode;
            trans->req_parsed = true;
        }

        if (len < 12) {
            nvme_mi_mi_col_append(pinfo, opcode, NULL);
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
            if (len > 1)
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                    tvb, 1, -1, ENC_NA);
            return tvb_captured_length(tvb);
        }

        /* The command dwords are present; persist the response-layout
         * selectors for the response pass. */
        if (trans) {
            if (!trans->body_ctx)
                trans->body_ctx = wmem_new0(wmem_file_scope(),
                                            struct nvme_mi_mi_req_ctx);
            req = (struct nvme_mi_mi_req_ctx *)trans->body_ctx;
        }

        switch (opcode) {
        case NVME_MI_MI_OPC_READ_DS: {
            uint64_t cdw0;
            uint8_t dtyp;

            cdw_it = proto_tree_add_bitmask_ret_uint64(mi_tree, tvb, 4,
                    hf_nvme_mi_mi_cdw0, ett_nvme_mi_mi_field,
                    rds_cdw0_fields, ENC_LITTLE_ENDIAN, &cdw0);
            dtyp = (uint8_t)(cdw0 >> 24);
            if (dtyp > NVME_MI_DTYP_MAX)
                expert_add_info(pinfo, cdw_it, &ei_nvme_mi_mi_reserved_dtyp);
            proto_tree_add_bitmask(mi_tree, tvb, 8, hf_nvme_mi_mi_cdw1,
                                   ett_nvme_mi_mi_field, rds_cdw1_fields,
                                   ENC_LITTLE_ENDIAN);
            if (req)
                req->dtyp = dtyp;
            detail = val_to_str_const(dtyp, mi_dtyp_vals, "Reserved");
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
            proto_tree_add_bitmask(mi_tree, tvb, 4, hf_nvme_mi_mi_cdw0,
                                   ett_nvme_mi_mi_field, chsp_cdw0_fields,
                                   ENC_LITTLE_ENDIAN);
            proto_tree_add_bitmask(mi_tree, tvb, 8, hf_nvme_mi_mi_cdw1,
                                   ett_nvme_mi_mi_field, chsp_cdw1_fields,
                                   ENC_LITTLE_ENDIAN);
            break;
        case NVME_MI_MI_OPC_CONFIG_SET:
        case NVME_MI_MI_OPC_CONFIG_GET: {
            /* The CONFIGID value in NMD0 bits 7:0 selects the layout of the
             * surrounding configuration-specific fields, so peek it before
             * choosing which field array decodes the dword. */
            uint8_t cid = tvb_get_uint8(tvb, 4);
            int * const *f0 = cfg_cdw0_fields_cid;
            int * const *f1 = NULL;

            switch (cid) {
            case NVME_MI_CFGID_SMBUS_FREQ:
                f0 = (opcode == NVME_MI_MI_OPC_CONFIG_SET)
                         ? cfg_cdw0_fields_sfreq : cfg_cdw0_fields_port;
                break;
            case NVME_MI_CFGID_HSC:
                if (opcode == NVME_MI_MI_OPC_CONFIG_SET)
                    f1 = cfg_cdw1_fields_hsc;
                break;
            case NVME_MI_CFGID_MTUS:
                f0 = cfg_cdw0_fields_port;
                if (opcode == NVME_MI_MI_OPC_CONFIG_SET)
                    f1 = cfg_cdw1_fields_mtus;
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
                                       ett_nvme_mi_mi_field, f1,
                                       ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw1,
                                    tvb, 8, 4, ENC_LITTLE_ENDIAN);
            if (req)
                req->configid = cid;
            detail = nvme_mi_mi_configid_name(cid);
            break;
        }
        case NVME_MI_MI_OPC_VPD_READ:
        case NVME_MI_MI_OPC_VPD_WRITE: {
            /* DOFST in NMD0 bits 15:0, DLEN in NMD1 bits 15:0 (Figures
             * 128/129 and 131/132 — identical layouts). */
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
        default:
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw0,
                                tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw1,
                                tvb, 8, 4, ENC_LITTLE_ENDIAN);
            break;
        }

        nvme_mi_mi_col_append(pinfo, opcode, detail);

        if (len > 12) {
            /* VPD Write carries the VPD bytes to write as Request Data
             * (Figure 133); label them rather than as an opaque blob. */
            int data_hf = (opcode == NVME_MI_MI_OPC_VPD_WRITE)
                          ? hf_nvme_mi_mi_vpd_data : hf_nvme_mi_mi_data;
            proto_tree_add_item(mi_tree, data_hf, tvb, 12, -1, ENC_NA);
        }
    } else {
        /* The response carries no opcode; recover it from the request.  When
         * there is no matching request (or it was too truncated to record an
         * opcode), say so rather than fabricating an opcode-0 item. */
        bool opcode_known = trans && trans->req_parsed;
        unsigned opcode = opcode_known ? trans->opcode : 0;
        const struct nvme_mi_mi_req_ctx *req = opcode_known
                ? (const struct nvme_mi_mi_req_ctx *)trans->body_ctx : NULL;
        const char *detail = NULL;
        uint8_t status;

        if (opcode_known) {
            it2 = proto_tree_add_uint(mi_tree, hf_nvme_mi_mi_opcode,
                                      tvb, 0, 0, opcode);
            proto_item_set_generated(it2);
            if (req) {
                if (opcode == NVME_MI_MI_OPC_READ_DS)
                    detail = val_to_str_const(req->dtyp, mi_dtyp_vals,
                                              "Reserved");
                else if (opcode == NVME_MI_MI_OPC_CONFIG_SET ||
                         opcode == NVME_MI_MI_OPC_CONFIG_GET)
                    detail = nvme_mi_mi_configid_name(req->configid);
            }
            nvme_mi_mi_col_append(pinfo, opcode, detail);
        } else {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_orphan_response);
        }

        if (len < 1) {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_item_ret_uint8(mi_tree, hf_nvme_mi_mi_status,
                                      tvb, 0, 1, ENC_NA, &status);

        if (len < 4) {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
            if (len > 1)
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                    tvb, 1, -1, ENC_NA);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_nmresp,
                            tvb, 1, 3, ENC_LITTLE_ENDIAN);

        if (status == NVME_MI_STATUS_INVALID_PARAMETER)
            nvme_mi_dissect_invalid_param_resp(tvb, mi_tree);

        /* The NVMe Management Response field and the Response Data are only
         * defined for a Success Response; error and MPR responses carry no
         * command-specific content. */
        bool success = (status == NVME_MI_STATUS_SUCCESS);

        if (success && opcode_known) {
            switch (opcode) {
            case NVME_MI_MI_OPC_READ_DS:
                /* NMRESP bits 15:0 = Response Data Length (Figure 111) */
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_rds_rdl,
                                    tvb, 1, 2, ENC_LITTLE_ENDIAN);
                break;
            case NVME_MI_MI_OPC_CTRL_HSP:
                /* NMRESP bits 23:16 = Response Entries (Figure 96) */
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
                case NVME_MI_CFGID_AE:
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cfg_aeelver,
                                        tvb, 1, 1, ENC_NA);
                    break;
                default:
                    break;
                }
                break;
            default:
                break;
            }
        }

        if (len > 4) {
            int dlen = (int)len - 4;

            if (success && opcode == NVME_MI_MI_OPC_READ_DS && req) {
                switch (req->dtyp) {
                case NVME_MI_DTYP_SUBSYS_INFO:
                    nvme_mi_mi_data_subsys_info(tvb, pinfo, mi_tree, it,
                                                4, dlen);
                    break;
                case NVME_MI_DTYP_PORT_INFO:
                    nvme_mi_mi_data_port_info(tvb, pinfo, mi_tree, it,
                                              4, dlen);
                    break;
                case NVME_MI_DTYP_CTRL_LIST:
                    nvme_mi_mi_data_ctrl_list(tvb, pinfo, mi_tree, it,
                                              4, dlen);
                    break;
                case NVME_MI_DTYP_CTRL_INFO:
                    nvme_mi_mi_data_ctrl_info(tvb, pinfo, mi_tree, it,
                                              4, dlen);
                    break;
                case NVME_MI_DTYP_OSC_LIST:
                case NVME_MI_DTYP_MEB_LIST:
                    nvme_mi_mi_data_cmd_list(tvb, pinfo, mi_tree, it,
                                             4, dlen);
                    break;
                default:
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                        tvb, 4, -1, ENC_NA);
                    break;
                }
            } else if (success && opcode_known &&
                       opcode == NVME_MI_MI_OPC_SUBSYS_HSP) {
                nvme_mi_mi_data_nshds(tvb, pinfo, mi_tree, it, 4, dlen);
            } else if (success && opcode_known &&
                       opcode == NVME_MI_MI_OPC_CTRL_HSP) {
                nvme_mi_mi_data_chds_list(tvb, pinfo, mi_tree, it, 4, dlen);
            } else if (success && opcode_known &&
                       opcode == NVME_MI_MI_OPC_VPD_READ) {
                /* Response Data is the requested window of VPD bytes
                 * (Figure 130). */
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_vpd_data,
                                    tvb, 4, -1, ENC_NA);
            } else {
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                    tvb, 4, -1, ENC_NA);
            }
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nvme_mi_mi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   void *data)
{
    struct nvme_mi_dissect_ctx *ctx = (struct nvme_mi_dissect_ctx *)data;

    if (!ctx)
        return 0;

    return dissect_nvme_mi_mi_body(tvb, pinfo, tree, ctx->resp, ctx->trans);
}

void
proto_register_nvme_mi_mi(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        { &hf_nvme_mi_mi_opcode,
          { "Opcode", "nvme-mi.mi.opcode",
            FT_UINT8, BASE_HEX, VALS(mi_opcode_vals), 0,
            NULL, HFILL },
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
            FT_UINT8, BASE_HEX, VALS(nvme_mi_status_vals), 0,
            "Response Message Status (NVMe-MI 2.1 Figure 29)", HFILL },
        },
        { &hf_nvme_mi_mi_nmresp,
          { "Management Response", "nvme-mi.mi.nmresp",
            FT_UINT24, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_data,
          { "Data", "nvme-mi.mi.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },

        /* Read NVMe-MI Data Structure (00h) */
        { &hf_nvme_mi_mi_rds_dtyp,
          { "Data Structure Type (DTYP)", "nvme-mi.mi.rds.dtyp",
            FT_UINT32, BASE_HEX, VALS(mi_dtyp_vals), 0xFF000000,
            "Data structure to return (Figure 109)", HFILL },
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
            "Length in bytes of the Response Data field (Figure 111)",
            HFILL },
        },

        /* NVM Subsystem Health Status Poll (01h) */
        { &hf_nvme_mi_mi_nshsp_cs,
          { "Clear Status (CS)", "nvme-mi.mi.nshsp.cs",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
            "Clear the Composite Controller Status Flags after copying them "
            "into the response (Figure 106)", HFILL },
        },

        /* Controller Health Status Poll (02h) */
        { &hf_nvme_mi_mi_chsp_all,
          { "Report All (ALL)", "nvme-mi.mi.chsp.all",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
            "Ignore the error selection bits when selecting Controllers",
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
          { "Clear Changed Flags (CCF)", "nvme-mi.mi.chsp.ccf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
            "Copy then clear each returned Controller's Health Status "
            "Changed Flags", HFILL },
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
          { "Select on Percentage Used (PDLU)", "nvme-mi.mi.chsp.pdlu",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_ctemp,
          { "Select on Composite Temperature Changes (CTEMP)",
            "nvme-mi.mi.chsp.ctemp",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_csts,
          { "Select on Controller Status Changes (CSTS)",
            "nvme-mi.mi.chsp.csts",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chsp_rent,
          { "Response Entries (RENT)", "nvme-mi.mi.chsp.rent",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Number of CHDS entries in the Response Data (Figure 96)",
            HFILL },
        },

        /* Configuration Set (03h) / Configuration Get (04h) */
        { &hf_nvme_mi_mi_cfg_cid,
          { "Configuration Identifier (CID)", "nvme-mi.mi.config.cid",
            FT_UINT32, BASE_HEX, VALS(mi_configid_vals), 0x000000FF,
            "Configuration being read or written (Figure 75)", HFILL },
        },
        { &hf_nvme_mi_mi_cfg_portid,
          { "Port Identifier (PORTID)", "nvme-mi.mi.config.portid",
            FT_UINT32, BASE_DEC, NULL, 0xFF000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_sfreq,
          { "SMBus/I2C Frequency (SFREQ)", "nvme-mi.mi.config.sfreq",
            FT_UINT32, BASE_HEX, VALS(mi_sfreq_vals), 0x00000F00,
            "New frequency for the 2-Wire port (Figure 86)", HFILL },
        },
        { &hf_nvme_mi_mi_cfg_mtus,
          { "MCTP Transmission Unit Size (MTUS)", "nvme-mi.mi.config.mtus",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Requested MCTP Transmission Unit Size in bytes (Figure 90)",
            HFILL },
        },
        { &hf_nvme_mi_mi_cfg_sfreq_cur,
          { "Current SMBus/I2C Frequency (SFREQ)",
            "nvme-mi.mi.config.sfreq_cur",
            FT_UINT8, BASE_HEX, VALS(mi_sfreq_vals), 0x0F,
            "Current 2-Wire frequency (Figure 77)", HFILL },
        },
        { &hf_nvme_mi_mi_cfg_mtus_cur,
          { "Current MCTP Transmission Unit Size (MTUS)",
            "nvme-mi.mi.config.mtus_cur",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Current MCTP Transmission Unit Size in bytes (Figure 79)",
            HFILL },
        },
        { &hf_nvme_mi_mi_cfg_aeelver,
          { "AE Enable List Version Number (AEELVER)",
            "nvme-mi.mi.config.aeelver",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Version of the AE Enable List data structure (Figure 81)",
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
          { "Clear Percentage Used (PDLU)", "nvme-mi.mi.config.hsc.pdlu",
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
          { "Clear Controller Status Change (CSCHNG)",
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
            "Starting byte offset into the VPD (Figures 128/131)", HFILL },
        },
        { &hf_nvme_mi_mi_vpd_dlen,
          { "Data Length (DLEN)", "nvme-mi.mi.vpd.dlen",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Length in bytes to read from or write to the VPD "
            "(Figures 129/132)", HFILL },
        },
        { &hf_nvme_mi_mi_vpd_data,
          { "VPD Data", "nvme-mi.mi.vpd.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            "VPD contents transferred by the command (Figures 130/133)",
            HFILL },
        },

        /* Reset (07h) */
        { &hf_nvme_mi_mi_reset_rsttyp,
          { "Reset Type (RSTTYP)", "nvme-mi.mi.reset.rsttyp",
            FT_UINT32, BASE_HEX, VALS(mi_rsttyp_vals), 0xFF000000,
            "Type of reset to perform (Figure 122)", HFILL },
        },

        /* Shutdown (0Ch) */
        { &hf_nvme_mi_mi_shutdown_shdntyp,
          { "Shutdown Type (SHDNTYP)", "nvme-mi.mi.shutdown.shdntyp",
            FT_UINT32, BASE_HEX, VALS(mi_shdntyp_vals), 0xFF000000,
            "Type of shutdown to perform (Figure 127)", HFILL },
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
          { "Status Reporting Enhancements (SRE)", "nvme-mi.mi.subsys.sre",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL },
        },

        /* Port Information (DTYP 01h) */
        { &hf_nvme_mi_mi_port_prttyp,
          { "Port Type (PRTTYP)", "nvme-mi.mi.port.prttyp",
            FT_UINT8, BASE_HEX, VALS(mi_prttyp_vals), 0,
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
          { "Command Initiated Auto Pause Supported (CIAPS)",
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
            FT_UINT8, BASE_HEX, VALS(mi_pciemps_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_slsv,
          { "PCIe Supported Link Speeds Vector (PCIESLSV)",
            "nvme-mi.mi.port.pcie.slsv",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Bit 0 = 2.5, 1 = 5.0, 2 = 8.0, 3 = 16.0, 4 = 32.0, 5 = 64.0 GT/s",
            HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_cls,
          { "PCIe Current Link Speed (PCIECLS)", "nvme-mi.mi.port.pcie.cls",
            FT_UINT8, BASE_HEX, VALS(mi_pciecls_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_mlw,
          { "PCIe Maximum Link Width (PCIEMLW)", "nvme-mi.mi.port.pcie.mlw",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Maximum link width in lanes", HFILL },
        },
        { &hf_nvme_mi_mi_port_pcie_nlw,
          { "PCIe Negotiated Link Width (PCIENLW)", "nvme-mi.mi.port.pcie.nlw",
            FT_UINT8, BASE_DEC, NULL, 0,
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
            FT_UINT8, BASE_HEX, VALS(mi_vpdfreq_vals), 0,
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
            FT_UINT8, BASE_HEX, VALS(mi_vpdfreq_vals), 0x03,
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
            FT_UINT8, BASE_HEX, VALS(mi_cmdlist_nmimt_vals), 0x78,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cmdlist_opc,
          { "Opcode (OPC)", "nvme-mi.mi.cmdlist.opc",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
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
        { &hf_nvme_mi_mi_nshds_sw,
          { "SMART Warnings (SW)", "nvme-mi.mi.nshds.sw",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Inverted Critical Warning field of the SMART log page",
            HFILL },
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
          { "Composite Controller Status (CCS)", "nvme-mi.mi.nshds.ccs",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Composite Controller Status Flags (Figure 107)", HFILL },
        },

        /* Shared health-status flag bits (Figures 98/107) */
        { &hf_nvme_mi_mi_hsf_tcida,
          { "Telemetry Controller-Initiated Data Available (TCIDA)",
            "nvme-mi.mi.hsf.tcida",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x2000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_cwarn,
          { "Critical Warning (CWARN)", "nvme-mi.mi.hsf.cwarn",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x1000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_spare,
          { "Available Spare (SPARE)", "nvme-mi.mi.hsf.spare",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0800,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_pdlu,
          { "Percentage Used (PDLU)", "nvme-mi.mi.hsf.pdlu",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0400,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_ctemp,
          { "Composite Temperature Change (CTEMP)", "nvme-mi.mi.hsf.ctemp",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0200,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_csts,
          { "Controller Status Change (CSTS)", "nvme-mi.mi.hsf.csts",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0100,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_fa,
          { "Firmware Activated (FA)", "nvme-mi.mi.hsf.fa",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0080,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_nac,
          { "Namespace Attribute Changed (NAC)", "nvme-mi.mi.hsf.nac",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0040,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_ceco,
          { "Controller Enable Change Occurred (CECO)", "nvme-mi.mi.hsf.ceco",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0020,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_nssro,
          { "NVM Subsystem Reset Occurred (NSSRO)", "nvme-mi.mi.hsf.nssro",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0010,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_shst,
          { "Shutdown Status (SHST)", "nvme-mi.mi.hsf.shst",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_cfs,
          { "Controller Fatal Status (CFS)", "nvme-mi.mi.hsf.cfs",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_hsf_rdy,
          { "Ready (RDY)", "nvme-mi.mi.hsf.rdy",
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
          { "Controller Status (CSTS)", "nvme-mi.mi.chds.csts",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_csts_tcida,
          { "Telemetry Controller-Initiated Data Available (TCIDA)",
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
            FT_UINT16, BASE_HEX, VALS(mi_shst_vals), 0x000C,
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
            FT_UINT16, BASE_DEC, NULL, 0,
            "Composite temperature of the Controller in Kelvins", HFILL },
        },
        { &hf_nvme_mi_mi_chds_pdlu,
          { "Percentage Used (PDLU)", "nvme-mi.mi.chds.pdlu",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_chds_spare,
          { "Available Spare (SPARE)", "nvme-mi.mi.chds.spare",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Normalized percentage of remaining spare capacity", HFILL },
        },
        { &hf_nvme_mi_mi_chds_cwarn,
          { "Critical Warning (CWARN)", "nvme-mi.mi.chds.cwarn",
            FT_UINT8, BASE_HEX, NULL, 0,
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
          { "Controller Health Status Changed (CHSC)",
            "nvme-mi.mi.chds.chsc",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Controller Health Status Changed Flags (Figure 98)", HFILL },
        },
    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi_mi,
        &ett_nvme_mi_mi_field,
        &ett_nvme_mi_mi_entry,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_mi_mi_truncated,
          { "nvme-mi.mi.truncated", PI_MALFORMED, PI_WARN,
            "MI command payload truncated", EXPFILL },
        },
        { &ei_nvme_mi_mi_orphan_response,
          { "nvme-mi.mi.orphan_response", PI_SEQUENCE, PI_NOTE,
            "MI response without a usable matching request (missing or "
            "truncated); opcode could not be recovered", EXPFILL },
        },
        { &ei_nvme_mi_mi_reserved_dtyp,
          { "nvme-mi.mi.reserved_dtyp", PI_PROTOCOL, PI_NOTE,
            "Data Structure Type is in the Reserved range (06h-FFh)",
            EXPFILL },
        },
        { &ei_nvme_mi_mi_reserved_configid,
          { "nvme-mi.mi.reserved_configid", PI_PROTOCOL, PI_NOTE,
            "Configuration Identifier is in a Reserved range (00h, 05h-BFh)",
            EXPFILL },
        },
        { &ei_nvme_mi_mi_reserved_value,
          { "nvme-mi.mi.reserved_value", PI_PROTOCOL, PI_NOTE,
            "A command-specific field carries a Reserved value", EXPFILL },
        },
    };

    expert_module_t *expert_nvme_mi_mi;

    proto_nvme_mi_mi = proto_register_protocol(
            "NVMe-MI MI Command", "NVMe-MI MI", "nvme-mi.mi");
    proto_register_field_array(proto_nvme_mi_mi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi_mi = expert_register_protocol(proto_nvme_mi_mi);
    expert_register_field_array(expert_nvme_mi_mi, ei, array_length(ei));
}

void
proto_reg_handoff_nvme_mi_mi(void)
{
    dissector_add_uint("nvme-mi.type", NVME_MI_TYPE_MI,
                       create_dissector_handle(dissect_nvme_mi_mi,
                                               proto_nvme_mi_mi));
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
