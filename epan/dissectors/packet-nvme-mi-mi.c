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
#include "packet-nvme.h"
#include "packet-nvme-mi.h"

void proto_register_nvme_mi_mi(void);
void proto_reg_handoff_nvme_mi_mi(void);

static int proto_nvme_mi_mi;

static dissector_handle_t nvme_mi_mi_handle;

static int hf_nvme_mi_mi_opcode;
static int hf_nvme_mi_mi_cdw0;
static int hf_nvme_mi_mi_cdw1;
static int hf_nvme_mi_mi_status;
static int hf_nvme_mi_mi_nmresp;
static int hf_nvme_mi_mi_data;

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

/* VPD Read (05h) / VPD Write (06h) — shared layout */
static int hf_nvme_mi_mi_vpd_dofst;
static int hf_nvme_mi_mi_vpd_dlen;
static int hf_nvme_mi_mi_vpd_data;

/* Configuration Set (03h) Asynchronous Event — request dword 0
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

/* Configuration Get (04h) Asynchronous Event — AE Supported List response
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
static int hf_nvme_mi_mi_ctrlinfo_pcivid;
static int hf_nvme_mi_mi_ctrlinfo_pcidid;
static int hf_nvme_mi_mi_ctrlinfo_pcisvid;
static int hf_nvme_mi_mi_ctrlinfo_pcisdid;
static int hf_nvme_mi_mi_ctrlinfo_pciesn;

/* Optionally Supported / MEB Supported Command List (DTYP 04h/05h) */
static int hf_nvme_mi_mi_cmdlist_numcmd;
static int hf_nvme_mi_mi_cmdlist_ctyp;
static int hf_nvme_mi_mi_cmdlist_nmimt;
static int hf_nvme_mi_mi_cmdlist_opc;

/* NVM Subsystem Health Data Structure (NSHDS) */
static int hf_nvme_mi_mi_nshds_nss;
static int hf_nvme_mi_mi_nshds_nss_atf;
static int hf_nvme_mi_mi_nshds_nss_sfm;
static int hf_nvme_mi_mi_nshds_nss_df;
static int hf_nvme_mi_mi_nshds_nss_rnr;
static int hf_nvme_mi_mi_nshds_nss_p0la;
static int hf_nvme_mi_mi_nshds_nss_p1la;
static int hf_nvme_mi_mi_nshds_nss_snfm;
static int hf_nvme_mi_mi_nshds_sw;
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

/* Shared health-status flag bits — same bit layout in the NVMe-MI 2.1
 * "Composite Controller Status Data Structure (CCSDS)" and "Controller
 * Health Status Changed Flags (CHSCF)" figures. */
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

/* MI command opcodes (NVMe-MI 2.1 "Opcodes for Management Interface Command
 * Set").  Only 00h-07h, 0Ch get field-level
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
    NVME_MI_MI_OPC_SES_RECV   = 0x08,
    NVME_MI_MI_OPC_SES_SEND   = 0x09,
    NVME_MI_MI_OPC_MEB_READ   = 0x0A,
    NVME_MI_MI_OPC_MEB_WRITE  = 0x0B,
    NVME_MI_MI_OPC_SHUTDOWN   = 0x0C,
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

static const value_string mi_dtyp_vals[] = {
    { NVME_MI_DTYP_SUBSYS_INFO, "NVM Subsystem Information" },
    { NVME_MI_DTYP_PORT_INFO,   "Port Information" },
    { NVME_MI_DTYP_CTRL_LIST,   "Controller List" },
    { NVME_MI_DTYP_CTRL_INFO,   "Controller Information" },
    { NVME_MI_DTYP_OSC_LIST,    "Optionally Supported Command List" },
    { NVME_MI_DTYP_MEB_LIST,    "Management Endpoint Buffer Command Support List" },
    { 0, NULL },
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

/* AE Enable ID — Asynchronous Events */
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
    { 0xC0, 0xFF, "Vendor Specific" },
    { 0, 0, NULL },
};

/* SMBus/I2C frequency encoding */
static const value_string mi_sfreq_vals[] = {
    { 0x0, "Obsolete/Reserved" },
    { 0x1, "100 kHz" },
    { 0x2, "400 kHz" },
    { 0x3, "1 MHz" },
    { 0, NULL },
};

/* Maximum VPD access / maximum SMBus frequency (2-Wire Port Specific
 * Data) */
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

/* Reset Type; 01h-FFh reserved */
#define NVME_MI_RSTTYP_MAX 0x00     /* highest valid Reset Type */
static const value_string mi_rsttyp_vals[] = {
    { 0x00, "Reset NVM Subsystem" },
    { 0, NULL },
};

/* Shutdown Type; 02h-FFh reserved */
#define NVME_MI_SHDNTYP_MAX 0x01    /* highest valid Shutdown Type */
static const value_string mi_shdntyp_vals[] = {
    { 0x00, "Normal NVM Subsystem Shutdown" },
    { 0x01, "Abrupt NVM Subsystem Shutdown" },
    { 0, NULL },
};

/*
 * CSTS.SHST shutdown status: reuse packet-nvme.c's shst_table (shared via
 * packet-nvme.h) so the MI CHDS decode and the NVMe Base decode never drift.
 *
 * NMIMT in command-list entries (the Optionally/MEB Supported Command Data
 * Structure entries) uses the same encoding as the
 * message header, so the entry decode reuses mi_type_vals (packet-nvme-mi.h).
 */

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
/*
 * NSHDS SMART Warnings is the bitwise *inverse* of the SMART / Health
 * Information Critical Warning field: a bit is set to '1' when the condition
 * is clear on every Controller in the NVM Subsystem, and cleared to '0' when
 * any Controller asserts it.  The bit positions match CHDS CWARN, but the
 * sense is opposite, so these must not use tfs_set_notset.
 */
static const true_false_string tfs_nshds_sw = { "Normal", "Warning" };
static int * const nshds_sw_fields[] = {
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
 * NSHDS CTEMP encoding: 00h-7Eh = 0-126 °C, 7Fh = 127 °C or
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
    nvme_mi_dissect_truncated(tvb, pinfo, tree, it, &ei_nvme_mi_mi_truncated,
                              hf_nvme_mi_mi_data, off);
}

/* DTYP 00h — NVM Subsystem Information Data Structure */
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

/* DTYP 01h — Port Information Data Structure */
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
    case 0x1:   /* PCIe Port Specific Data */
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
    case 0x2:   /* 2-Wire Port Specific Data */
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

/* DTYP 03h — Controller Information Data Structure */
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
 * (both share the count + (CTYP, OPC) entry format) */
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
        /* NMIMT (CTYP bits 6:3) selects which opcode namespace OPC belongs to
         * -- both tables already exist in-tree, so name the entry from
         * whichever one the command actually lives in instead of leaving it
         * a bare byte. */
        switch ((ctyp & 0x78) >> 3) {
        case NVME_MI_TYPE_MI:
            opc_name = rval_to_str_const(opc, mi_opcode_vals, "Unknown");
            break;
        case NVME_MI_TYPE_ADMIN:
            opc_name = nvme_get_opcode_string(opc, 0);
            break;
        default:
            break;
        }
        if (opc_name)
            proto_item_append_text(opc_it, " (%s)", opc_name);
        pos += 2;
    }
}

/* NVM Subsystem Health Data Structure (NSHDS; 8 bytes) */
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
    proto_tree_add_bitmask(tree, tvb, off + 1, hf_nvme_mi_mi_nshds_sw,
                           ett_nvme_mi_mi_field, nshds_sw_fields, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_nshds_ctemp,
                        tvb, off + 2, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_mi_nshds_pdlu,
                        tvb, off + 3, 1, ENC_NA);
    proto_tree_add_bitmask(tree, tvb, off + 4, hf_nvme_mi_mi_nshds_ccs,
                           ett_nvme_mi_mi_field, hsf_fields,
                           ENC_LITTLE_ENDIAN);
    /* bytes 7:6 reserved */
}

/* Array of 16-byte Controller Health Data Structures (CHDS) */
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
    const char *name = rval_to_str_const(opcode, mi_opcode_vals, "Unknown");

    if (detail)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s: %s)", name, detail);
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", name);
}

static const char *
nvme_mi_mi_configid_name(uint8_t cid)
{
    return rval_to_str_const(cid, mi_configid_vals, "Reserved");
}

/*
 * Decode a request whose only parameter is a type byte in NMD0 bits 31:24
 * with NMD1 reserved (Reset RSTTYP; Shutdown SHDNTYP).  Values above
 * max_valid are in the Reserved range.  Returns
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
 * The AE Enable List sent as Configuration Set (03h) request data and the
 * AE Supported List returned as Configuration Get (04h) response data share
 * one layout: a header (count, version,
 * total length, header length) followed by <count> entries, each a 1-byte
 * length plus a 2-byte info word (flag bit 15, AE ID bits 7:0).  Only the
 * field names differ, so the walk below is driven by this descriptor.
 */
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
    const char *entry_name;
};

static void
dissect_nvme_mi_mi_ae_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           proto_item *it, unsigned off, unsigned len,
                           const struct nvme_mi_mi_ae_list_hf *hf)
{
    proto_tree *ae_tree;
    proto_item *ti;
    uint32_t num, hdr_len, i;
    unsigned pos;

    ti = proto_tree_add_item(tree, hf->list, tvb, off, len, ENC_NA);
    ae_tree = proto_item_add_subtree(ti, ett_nvme_mi_mi);

    /* The list header is 5 bytes; anything shorter is truncated. */
    if (len < 5) {
        nvme_mi_mi_data_truncated(tvb, pinfo, ae_tree, it, off);
        return;
    }

    proto_tree_add_item_ret_uint(ae_tree, hf->num,
                                 tvb, off, 1, ENC_LITTLE_ENDIAN, &num);
    proto_tree_add_item(ae_tree, hf->ver,
                        tvb, off + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ae_tree, hf->total_len,
                        tvb, off + 2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(ae_tree, hf->hdr_len,
                                 tvb, off + 4, 1, ENC_LITTLE_ENDIAN, &hdr_len);

    /* The list body starts at the offset the header declares, not at a fixed
     * 5; a value below the 5 defined header bytes is bogus, so clamp forward
     * to keep the entry walk inside the body. */
    if (hdr_len < 5)
        hdr_len = 5;

    pos = off + hdr_len;
    for (i = 0; i < num; i++) {
        proto_tree *e_tree;
        proto_item *e_ti;
        unsigned elen, entry_len;

        /* Each entry is at least 3 bytes (length + info word).  Stop if the
         * next entry would run past the list data. */
        if (pos + 3 > off + len)
            break;
        elen = tvb_get_uint8(tvb, pos);
        if (elen < 3)
            elen = 3;   /* spec value is 3h; guarantee forward progress */

        /* A bogus length must not drive the entry item past the list data;
         * clamp its displayed length to what remains so a truncated list
         * stops cleanly rather than raising a bounds exception. */
        entry_len = elen;
        if (pos + entry_len > off + len)
            entry_len = off + len - pos;

        e_ti = proto_tree_add_item(ae_tree, hf->entry,
                                   tvb, pos, entry_len, ENC_NA);
        proto_item_set_text(e_ti, "%s %u", hf->entry_name, i);
        e_tree = proto_item_add_subtree(e_ti, ett_nvme_mi_mi_field);
        proto_tree_add_item(e_tree, hf->entry_len,
                            tvb, pos, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(e_tree, hf->flag,
                            tvb, pos + 1, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(e_tree, hf->id,
                            tvb, pos + 1, 2, ENC_LITTLE_ENDIAN);
        pos += elen;
    }
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
        hf_nvme_mi_mi_ae_id,     "AE Enable",
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
        hf_nvme_mi_mi_aes_id,     "AE Supported",
    };

    dissect_nvme_mi_mi_ae_list(tvb, pinfo, tree, it, off, len, &hf);
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

        if (len < 12) {
            nvme_mi_mi_col_append(pinfo, opcode, NULL);
            nvme_mi_mi_data_truncated(tvb, pinfo, mi_tree, it, 1);
            return tvb_captured_length(tvb);
        }

        /* The command dwords are present; persist the response-layout
         * selectors for the response pass. */
        if (trans)
            req = nvme_mi_trans_body_ctx(trans, sizeof(*req));

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
            case NVME_MI_CFGID_AE:
                if (opcode == NVME_MI_MI_OPC_CONFIG_SET)
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
            /* A few commands carry structured Request Data after the command
             * dwords: a Configuration Set of the Asynchronous Event config
             * sends an AE Enable List; VPD Write sends the VPD bytes (opaque,
             * just labeled).  Everything else is an opaque blob. */
            if (opcode == NVME_MI_MI_OPC_CONFIG_SET &&
                tvb_get_uint8(tvb, 4) == NVME_MI_CFGID_AE) {
                dissect_nvme_mi_mi_ae_enable_list(tvb, pinfo, mi_tree, it, 12,
                                                  len - 12);
            } else {
                int data_hf = (opcode == NVME_MI_MI_OPC_VPD_WRITE)
                              ? hf_nvme_mi_mi_vpd_data : hf_nvme_mi_mi_data;
                proto_tree_add_item(mi_tree, data_hf, tvb, 12, -1, ENC_NA);
            }
        }
    } else {
        /* The response carries no opcode; recover it from the matching request
         * (of this same NMIMT).  Without one, the helper notes an orphan
         * response rather than fabricating an opcode-0 item. */
        unsigned opcode;
        it2 = nvme_mi_recover_resp_opcode(tvb, pinfo, mi_tree, it, trans,
                                          NVME_MI_TYPE_MI, hf_nvme_mi_mi_opcode,
                                          &ei_nvme_mi_mi_orphan_response,
                                          &opcode);
        bool opcode_known = (it2 != NULL);
        const struct nvme_mi_mi_req_ctx *req = opcode_known
                ? (const struct nvme_mi_mi_req_ctx *)trans->body_ctx : NULL;
        const char *detail = NULL;
        uint8_t status;

        if (opcode_known) {
            if (req) {
                if (opcode == NVME_MI_MI_OPC_READ_DS)
                    detail = val_to_str_const(req->dtyp, mi_dtyp_vals,
                                              "Reserved");
                else if (opcode == NVME_MI_MI_OPC_CONFIG_SET ||
                         opcode == NVME_MI_MI_OPC_CONFIG_GET)
                    detail = nvme_mi_mi_configid_name(req->configid);
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

        /* The NVMe Management Response field and the Response Data are only
         * defined for a Success Response.  On an error response those same
         * bytes are the Parameter Error Location, the More Processing Required
         * Time, or Reserved, so the shared helper owns them and NMRESP is not
         * rendered over them (NVMe-MI 2.1 "Generic Error Response" /
         * "Invalid Parameter Error Response Fields" / "More Processing
         * Required Response Fields"). */
        bool success = nvme_mi_dissect_resp_status_bytes(tvb, mi_tree, status);

        if (success)
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_nmresp,
                                tvb, 1, 3, ENC_LITTLE_ENDIAN);

        if (success && opcode_known) {
            switch (opcode) {
            case NVME_MI_MI_OPC_READ_DS:
                /* NMRESP bits 15:0 = Response Data Length (Read NVMe-MI
                 * Data Structure NVMe Management Response) */
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_rds_rdl,
                                    tvb, 1, 2, ENC_LITTLE_ENDIAN);
                break;
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

            /* Response Data is only defined for a Success response of a known
             * opcode; everything else (errors, MPR, orphan) renders raw. */
            if (success && opcode_known) {
                switch (opcode) {
                case NVME_MI_MI_OPC_READ_DS:
                    /* The request's DTYP selects the structure layout; without
                     * it (truncated request) fall back to raw. */
                    if (!req) {
                        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                            tvb, 4, -1, ENC_NA);
                        break;
                    }
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
                    break;
                case NVME_MI_MI_OPC_SUBSYS_HSP:
                    nvme_mi_mi_data_nshds(tvb, pinfo, mi_tree, it, 4, dlen);
                    break;
                case NVME_MI_MI_OPC_CTRL_HSP:
                    nvme_mi_mi_data_chds_list(tvb, pinfo, mi_tree, it, 4, dlen);
                    break;
                case NVME_MI_MI_OPC_CONFIG_GET:
                    /* Only the Asynchronous Event configuration returns
                     * Response Data: the AE Supported List. */
                    if (req && req->configid == NVME_MI_CFGID_AE)
                        dissect_nvme_mi_mi_ae_supported_list(tvb, pinfo,
                                mi_tree, it, 4, dlen);
                    else
                        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                            tvb, 4, -1, ENC_NA);
                    break;
                case NVME_MI_MI_OPC_VPD_READ:
                    /* Response Data is the requested window of VPD bytes
                     * (the "VPD Read Response Data" figure). */
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_vpd_data,
                                        tvb, 4, -1, ENC_NA);
                    break;
                default:
                    proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                        tvb, 4, -1, ENC_NA);
                    break;
                }
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
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_opcode_vals), 0,
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
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_mi_status_vals), 0,
            "Response Message Status (NVMe-MI 2.1 'Response Message"
            " Status Values')", HFILL },
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
          { "Clear Status (CS)", "nvme-mi.mi.nshsp.cs",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
            "Clear the Composite Controller Status Flags after copying them"
            " into the response", HFILL },
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
            "Number of CHDS entries in the Response Data",
            HFILL },
        },

        /* Configuration Set (03h) / Configuration Get (04h) */
        { &hf_nvme_mi_mi_cfg_cid,
          { "Configuration Identifier (CID)", "nvme-mi.mi.config.cid",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(mi_configid_vals), 0x000000FF,
            "Configuration being read or written (NVMe-MI 2.1 'NVMe"
            " Management Interface Configuration Identifiers')", HFILL },
        },
        { &hf_nvme_mi_mi_cfg_portid,
          { "Port Identifier (PORTID)", "nvme-mi.mi.config.portid",
            FT_UINT32, BASE_DEC, NULL, 0xFF000000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cfg_sfreq,
          { "SMBus/I2C Frequency (SFREQ)", "nvme-mi.mi.config.sfreq",
            FT_UINT32, BASE_HEX, VALS(mi_sfreq_vals), 0x00000F00,
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
            FT_UINT8, BASE_HEX, VALS(mi_sfreq_vals), 0x0F,
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
            "Starting byte offset into the VPD", HFILL },
        },
        { &hf_nvme_mi_mi_vpd_dlen,
          { "Data Length (DLEN)", "nvme-mi.mi.vpd.dlen",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            "Length in bytes to read from or write to the VPD", HFILL },
        },
        { &hf_nvme_mi_mi_vpd_data,
          { "VPD Data", "nvme-mi.mi.vpd.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            "VPD contents transferred by the command (NVMe-MI 2.1 'VPD"
            " Read Response Data' / 'VPD Write Request Data')",
            HFILL },
        },

        /* Configuration Set (03h) Asynchronous Event — command dword 0 */
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

        /* Configuration Set (03h) Asynchronous Event — AE Enable List */
        { &hf_nvme_mi_mi_ae,
          { "AE Enable List", "nvme-mi.mi.ae",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Asynchronous Event Enable List request data (NVMe-MI 2.1"
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
            "Identifier of the asynchronous event (NVMe-MI 2.1"
            " 'Asynchronous Events')", HFILL },
        },

        /* Configuration Get (04h) Asynchronous Event — AE Supported List */
        { &hf_nvme_mi_mi_aes,
          { "AE Supported List", "nvme-mi.mi.aes",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Asynchronous Event Supported List response data (NVMe-MI 2.1"
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
            "Identifier of the asynchronous event (NVMe-MI 2.1"
            " 'Asynchronous Events')", HFILL },
        },

        /* Reset (07h) */
        { &hf_nvme_mi_mi_reset_rsttyp,
          { "Reset Type (RSTTYP)", "nvme-mi.mi.reset.rsttyp",
            FT_UINT32, BASE_HEX, VALS(mi_rsttyp_vals), 0xFF000000,
            "Type of reset to perform", HFILL },
        },

        /* Shutdown (0Ch) */
        { &hf_nvme_mi_mi_shutdown_shdntyp,
          { "Shutdown Type (SHDNTYP)", "nvme-mi.mi.shutdown.shdntyp",
            FT_UINT32, BASE_HEX, VALS(mi_shdntyp_vals), 0xFF000000,
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
            FT_UINT8, BASE_HEX, VALS(mi_type_vals), 0x78,
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
          { "Composite Controller Status (CCS)", "nvme-mi.mi.nshds.ccs",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Composite Controller Status Flags (NVMe-MI 2.1 'Composite"
            " Controller Status Data Structure (CCSDS)')", HFILL },
        },

        /* Shared health-status flag bits (NVMe-MI 2.1 "Controller Health
         * Status Changed Flags (CHSCF)" / "Composite Controller Status
         * Data Structure (CCSDS)") */
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
            "Controller Health Status Changed Flags (CHSCF)", HFILL },
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
            "MI command payload truncated", EXPFILL }
        },
        { &ei_nvme_mi_mi_orphan_response,
          { "nvme-mi.mi.orphan_response", PI_SEQUENCE, PI_NOTE,
            "MI response without a usable matching request (missing or"
            " truncated); opcode could not be recovered", EXPFILL }
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
        }
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
}

void
proto_reg_handoff_nvme_mi_mi(void)
{
    dissector_add_uint("nvme-mi.type", NVME_MI_TYPE_MI,
                       nvme_mi_mi_handle);
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
