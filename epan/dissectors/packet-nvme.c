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
static int hf_nvme_identify_cntid = -1;
static int hf_nvme_identify_rsvd = -1;
static int hf_nvme_identify_cns = -1;
static int hf_nvme_identify_nvmesetid = -1;
static int hf_nvme_identify_rsvd1 = -1;
static int hf_nvme_identify_uuid_index = -1;
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
static int hf_nvme_identify_ctrl_vid = -1;
static int hf_nvme_identify_ctrl_ssvid = -1;
static int hf_nvme_identify_ctrl_sn = -1;
static int hf_nvme_identify_ctrl_mn = -1;
static int hf_nvme_identify_ctrl_fr = -1;
static int hf_nvme_identify_ctrl_rab = -1;
static int hf_nvme_identify_ctrl_ieee = -1;

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

/* NVMe CQE fields */
static int hf_nvme_cqe_sts = -1;
static int hf_nvme_cqe_sqhd = -1;
static int hf_nvme_cqe_rsvd = -1;
static int hf_nvme_cqe_cid = -1;
static int hf_nvme_cqe_status = -1;
static int hf_nvme_cqe_status_rsvd = -1;

/* tracking Cmd and its respective CQE */
static int hf_nvme_cmd_pkt = -1;
static int hf_nvme_data_req = -1;
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


#define NVME_CQE_SCT_GENERIC     0x0
#define NVME_CQE_SCT_SPECIFIC    0x1
#define NVME_CQE_SCT_MDI         0x2
#define NVME_CQE_SCT_VENDOR      0x7

#define NVME_CQE_SCODE_SUCCESS          0x0
#define NVME_CQE_SCODE_INVALID_OPCODE   0x1
#define NVME_CQE_SCODE_INVALID_FIELD    0x2
#define NVME_CQE_SCODE_CID_CONFLICT     0x3
#define NVME_CQE_SCODE_DATA_XFER_ERR    0x4
#define NVME_CQE_SCODE_CMD_ABORTED      0x5
#define NVME_CQE_SCODE_INTERNAL_ERR     0x6
#define NVME_CQE_SCODE_CMD_ABORT_REQ    0x7
#define NVME_CQE_SCODE_CMD_ABORT_SQD    0x8
#define NVME_CQE_SCODE_CMD_ABORT_FF     0x9
#define NVME_CQE_SCODE_CMD_ABORT_MF     0xa
#define NVME_CQE_SCODE_INVALID_NS       0xb
#define NVME_CQE_SCODE_CMD_SEQ_ERR      0xc

#define NVME_CQE_SCODE_INVALID_SGL_DESC         0xd
#define NVME_CQE_SCODE_INVALID_NUM_SGLS         0xe
#define NVME_CQE_SCODE_INVALID_SGL_LEN          0xf
#define NVME_CQE_SCODE_INVALID_MD_SGL_LEN       0x10
#define NVME_CQE_SCODE_INVALID_SGL_DESC_TYPE    0x11
#define NVME_CQE_SCODE_INVALID_CMB_USE          0x12
#define NVME_CQE_SCODE_INVALID_PRP_OFFSET       0x13
#define NVME_CQE_SCODE_INVALID_ATOMIC_WRITE_EXCEEDED 0x14
#define NVME_CQE_SCODE_INVALID_SGL_OFFSET      0x16
#define NVME_CQE_SCODE_INVALID_SGL_SUB_TYPE    0x17
#define NVME_CQE_SCODE_INVALID_INCONSISTENT_HOSTID   0x18
#define NVME_CQE_SCODE_INVALID_KA_TIMER_EXPIRED      0x19
#define NVME_CQE_SCODE_INVALID_KA_TIMEOUT_INVALID    0x1a

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
    { 0, "Identify Namespace"},
    { 1, "Identify Controller"},
    { 2, "Active Namespace List"},
    { 3, "Namespace Identification Descriptor"},
    {4, "NVM Set List"},
    {0x10, "Allocated Namespace ID List"},
    {0x11, "Identify Namespace Data Structure"},
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
nvme_build_done_cmd_key(wmem_tree_key_t *cmd_key, guint32 *key, guint32 *frame_num)
{
    cmd_key[0].length = 1;
    cmd_key[0].key = key;
    cmd_key[1].length = frame_num ? 1 : 0;
    cmd_key[1].key = frame_num;
    cmd_key[2].length = 0;
    cmd_key[2].key = NULL;
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
    key[2].length = 0;
    key[2].key = NULL;
}

void nvme_add_data_request(struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx,
                                        struct keyed_data_req *req)
{
    wmem_tree_key_t tr_key[4];

    cmd_ctx->data_resp_pkt_num = 0;
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
nvme_add_data_response(struct nvme_q_ctx *q_ctx,
                       struct nvme_cmd_ctx *cmd_ctx, guint32 rkey, guint32 frame_num)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = rkey;

    frame_num = cmd_ctx->data_resp_pkt_num;
    nvme_build_done_cmd_key(cmd_key, &key, frame_num ? &frame_num : NULL);
    wmem_tree_insert32_array(q_ctx->data_responses, cmd_key, (void*)cmd_ctx);
}

struct nvme_cmd_ctx*
nvme_lookup_data_response(struct nvme_q_ctx *q_ctx,
                          guint32 rkey, guint32 frame_num)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = rkey;

    nvme_build_done_cmd_key(cmd_key, &key, frame_num ? &frame_num : NULL);

    return (struct nvme_cmd_ctx*)wmem_tree_lookup32_array(q_ctx->data_responses, cmd_key);
}

void
nvme_add_cmd_cqe_to_done_list(struct nvme_q_ctx *q_ctx,
                              struct nvme_cmd_ctx *cmd_ctx, guint16 cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = cmd_id;
    guint32 frame_num;

    nvme_build_done_cmd_key(cmd_key, &key, &frame_num);

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

    nvme_build_done_cmd_key(cmd_key, &key, &frame_num);

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

static void
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

void nvme_publish_to_data_resp_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    nvme_publish_link(tree, tvb, hf_index, cmd_ctx->data_resp_pkt_num, FALSE);
}

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                          int field_index, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, gboolean visited)
{
    proto_item *ti, *sgl_tree, *type_item, *sub_type_item;
    guint8 sgl_identifier, desc_type, desc_sub_type;
    int offset = 24;

    ti = proto_tree_add_item(cmd_tree, field_index, cmd_tvb, offset,
                             16, ENC_NA);
    sgl_tree = proto_item_add_subtree(ti, ett_data);

    sgl_identifier = tvb_get_guint8(cmd_tvb, offset + 15);
    desc_type = (sgl_identifier & 0xff) >> 4;
    desc_sub_type = sgl_identifier & 0x0f;

    type_item = proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_type,
                                    cmd_tvb, offset + 15, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(type_item, " %s",
                           val_to_str(desc_type, sgl_type_tbl, "Reserved"));

    sub_type_item = proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_sub_type,
                                        cmd_tvb,
                                        offset + 15, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(sub_type_item, " %s",
                           val_to_str(desc_sub_type, sgl_sub_type_tbl, "Reserved"));

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
                                            proto_tree *cmd_tree)
{
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

}

static void dissect_nvme_identify_nslist_resp(tvbuff_t *cmd_tvb,
                                              proto_tree *cmd_tree)
{
    guint32 nsid;
    int off;
    proto_item *item;

    for (off = 0; off < 4096; off += 4) {
        nsid = tvb_get_guint32(cmd_tvb, off, ENC_LITTLE_ENDIAN);
        if (nsid == 0)
            break;

        item = proto_tree_add_item(cmd_tree, hf_nvme_identify_nslist_nsid,
                                   cmd_tvb, off, 4, ENC_LITTLE_ENDIAN);
        proto_item_set_text(item, "nsid[%d]: %d", off / 4, nsid);
    }
}

static void add_group_mask_entry(tvbuff_t *tvb, proto_tree *tree, guint offset, guint bytes, int *array, guint array_len)
{
    proto_item *ti, *grp;
    guint i;

    ti = proto_tree_add_item(tree, array[0], tvb, offset, bytes, ENC_LITTLE_ENDIAN);
    grp =  proto_item_add_subtree(ti, ett_data);

    for (i = 1; i < array_len; i++)
        proto_tree_add_item(grp, array[i], tvb, offset, bytes, ENC_LITTLE_ENDIAN);
}


#define ASPEC(_x_) _x_, array_length(_x_)

static void add_ctrl_x16_bytes( gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "%x (%u bytes)", val, val * 16);
}

static void dissect_nvme_identify_ctrl_resp_nvmeof(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nvmeof, cmd_tvb, 1792, 256, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);

    ti = proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_ioccsz, cmd_tvb, 1792, 4, ENC_LITTLE_ENDIAN);
    ti = proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_iorcsz, cmd_tvb, 1796, 4, ENC_LITTLE_ENDIAN);
    ti = proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_icdoff, cmd_tvb, 1800, 2, ENC_LITTLE_ENDIAN);

    add_group_mask_entry(cmd_tvb, grp, 1802, 1, ASPEC(hf_nvme_identify_ctrl_nvmeof_fcatt));
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_msdbd, cmd_tvb, 1803, 1, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, grp, 1804, 2, ASPEC(hf_nvme_identify_ctrl_nvmeof_ofcs));
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_nvmeof_rsvd, cmd_tvb, 1806, 242, ENC_NA);
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

static void dissect_nvme_identify_ctrl_resp_power_state_descriptor(tvbuff_t *cmd_tvb, proto_tree *tree, guint8 idx)
{
    proto_item *ti;
    proto_tree *grp;
    guint off;

    off = 2048 + idx *32;
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

static void dissect_nvme_identify_ctrl_resp_power_state_descriptors(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti;
    proto_tree *grp;
    guint i;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_psds, cmd_tvb, 2048, 1024, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    for (i = 0; i < 32; i++)
        dissect_nvme_identify_ctrl_resp_power_state_descriptor(cmd_tvb, grp, i);
}


static void add_ctrl_rab(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"G_GUINT64_FORMAT" command%s)", val, ((guint64)1) << val, val ? "s" : "");
}

static void add_ctrl_mdts(gchar *result, guint32 val)
{
    if (val)
        g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"G_GUINT64_FORMAT" pages)", val, ((guint64)1) << val);
    else
        g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x (unlimited)", val);
}

static void add_ctrl_rtd3(gchar *result, guint32 val)
{
    if (!val)
        g_snprintf(result, ITEM_LABEL_LENGTH, "0 (not reported)");
    else
        g_snprintf(result, ITEM_LABEL_LENGTH, "%u (%u microsecond%s)", val, val, (val > 1) ? "%s" : "");
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
    g_snprintf(result, ITEM_LABEL_LENGTH, "%u (%u ms)", val, val * 100);
}

static void dissect_nvme_identify_ctrl_resp_ver(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ver, cmd_tvb,  80, 4, ENC_LITTLE_ENDIAN);
    grp =  proto_item_add_subtree(ti, ett_data);

    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_mjr, cmd_tvb, 82, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_min, cmd_tvb, 81, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_ver_ter, cmd_tvb, 80, 1, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_identify_ctrl_resp_fguid(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_fguid, cmd_tvb, 112, 16, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_vse, cmd_tvb, 112, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_oui, cmd_tvb, 120, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_fguid_ei, cmd_tvb, 123, 5, ENC_LITTLE_ENDIAN);
}

static void dissect_nvme_identify_ctrl_resp_mi(tvbuff_t *cmd_tvb, proto_tree *cmd_tree)
{
    proto_item *ti;
    proto_tree *grp;

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mi, cmd_tvb, 240, 16, ENC_NA);
    grp =  proto_item_add_subtree(ti, ett_data);
    proto_tree_add_item(grp, hf_nvme_identify_ctrl_mi_rsvd, cmd_tvb, 240, 13, ENC_NA);
    add_group_mask_entry(cmd_tvb, grp, 253, 1, ASPEC(hf_nvme_identify_ctrl_mi_nvmsr));
    add_group_mask_entry(cmd_tvb, grp, 254, 1, ASPEC(hf_nvme_identify_ctrl_mi_vwci));
    add_group_mask_entry(cmd_tvb, grp, 255, 1, ASPEC(hf_nvme_identify_ctrl_mi_mec));
}

static void add_ctrl_commands(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u command%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_events(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u event%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_entries(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u entr%s)", val, val+1, val ? "ies" : "y");
}

static void add_ctrl_states(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x: (%u state%s)", val, val+1, val ? "s" : "");
}

static void add_ctrl_hmpre(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%"G_GUINT64_FORMAT" bytes)", val, ((guint64)(val)) * 4096);
}

static void post_add_cap(proto_item *ti, tvbuff_t *tvb, guint off)
{
    guint64 lo = tvb_get_guint64(tvb, off, 0);
    guint64 hi = tvb_get_guint64(tvb, off, 8);
    if (hi) {
        if (!(hi >> 10))
            proto_item_append_text(ti, " (%" G_GUINT64_FORMAT " KiB)", (hi << 54) | (lo >> 10));
        else if (!(hi >> 20))
            proto_item_append_text(ti, " (%" G_GUINT64_FORMAT " MiB)", (hi << 44) | (lo >> 20));
        else if (!(hi >> 30))
            proto_item_append_text(ti, " (%" G_GUINT64_FORMAT " GiB)", (hi << 34) | (lo >> 30));
        else if (!(hi >> 40))
            proto_item_append_text(ti, " (%" G_GUINT64_FORMAT " TiB)", (hi << 24) | (lo >> 40));
        else if (!(hi >> 50))
            proto_item_append_text(ti, " (%" G_GUINT64_FORMAT " PiB)", (hi << 14) | (lo >> 50));
        else if (!(hi >> 60))
            proto_item_append_text(ti, " (%" G_GUINT64_FORMAT " EiB)", (hi << 4) | (lo >> 60));
        else
            proto_item_append_text(ti, " (%" G_GUINT64_FORMAT " ZiB)", hi >> 6);
    } else {
        proto_item_append_text(ti, " (%" G_GUINT64_FORMAT " bytes)", lo);
    }
}

static void add_ctrl_tmt(gchar *result, guint32 val)
{
    if (!val)
        g_snprintf(result, ITEM_LABEL_LENGTH, "0 (not supported)");
    else
        g_snprintf(result, ITEM_LABEL_LENGTH, "%u degrees K", val);
}

static const value_string mmas_type_tbl[] = {
    { 0,  "modification not defined" },
    { 1,  "no modification after sanitize completion" },
    { 2,  "additional modification after sanitize completion" },
    { 0, NULL}
};

static void add_ctrl_pow2_bytes(gchar *result, guint32 val)
{
    g_snprintf(result, ITEM_LABEL_LENGTH, "0x%x (%" G_GUINT64_FORMAT" bytes)", val, ((guint64)1) << val);
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
    g_snprintf(result, ITEM_LABEL_LENGTH, "%u logical block%s", val + 1, val ? "%s" : "");
}

static const value_string sgls_ify_type_tbl[] = {
    { 0,  "SGLs are not supported." },
    { 1, "SGLs are supported without alignment or granularity limitations" },
    { 2, "SGLs are supported with DWORD alignment and granularity limitation" },
    { 3,  "reserved value" },
    { 0, NULL}
};

static void dissect_nvme_identify_ctrl_resp(tvbuff_t *cmd_tvb,
                                            proto_tree *cmd_tree)
{
    proto_item *ti;

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_vid, cmd_tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ssvid, cmd_tvb, 2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_sn, cmd_tvb, 4, 20, ENC_ASCII|ENC_NA);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mn, cmd_tvb, 24, 40, ENC_ASCII|ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_fr, cmd_tvb, 64, 8, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rab, cmd_tvb, 72, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ieee, cmd_tvb, 73, 3, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 76, 1, ASPEC(hf_nvme_identify_ctrl_cmic));
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mdts, cmd_tvb, 77, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_cntlid, cmd_tvb, 78, 2, ENC_LITTLE_ENDIAN);
    dissect_nvme_identify_ctrl_resp_ver(cmd_tvb, cmd_tree);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rtd3r, cmd_tvb, 84, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rtd3e, cmd_tvb, 88, 4, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 92, 4, ASPEC(hf_nvme_identify_ctrl_oaes));
    add_group_mask_entry(cmd_tvb, cmd_tree, 96, 4, ASPEC(hf_nvme_identify_ctrl_ctratt));

    add_group_mask_entry(cmd_tvb, cmd_tree, 100, 2, ASPEC(hf_nvme_identify_ctrl_rrls));
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd0, cmd_tvb, 102, 9, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_cntrltype, cmd_tvb, 111, 1, ENC_LITTLE_ENDIAN);
    dissect_nvme_identify_ctrl_resp_fguid(cmd_tvb, cmd_tree);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_crdt1, cmd_tvb, 128, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_crdt2, cmd_tvb, 130, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_crdt3, cmd_tvb, 132, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd1, cmd_tvb, 134, 106, ENC_NA);
    dissect_nvme_identify_ctrl_resp_mi(cmd_tvb, cmd_tree);
    add_group_mask_entry(cmd_tvb, cmd_tree, 256, 2, ASPEC(hf_nvme_identify_ctrl_oacs));

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_acl, cmd_tvb,  258, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_aerl, cmd_tvb, 259, 1, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 260, 1, ASPEC(hf_nvme_identify_ctrl_frmw));

    add_group_mask_entry(cmd_tvb, cmd_tree, 261, 1, ASPEC(hf_nvme_identify_ctrl_lpa));
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_elpe, cmd_tvb, 262, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_npss, cmd_tvb, 263, 1, ENC_LITTLE_ENDIAN);

    add_group_mask_entry(cmd_tvb, cmd_tree, 264, 1, ASPEC(hf_nvme_identify_ctrl_avscc));
    add_group_mask_entry(cmd_tvb, cmd_tree, 265, 1, ASPEC(hf_nvme_identify_ctrl_apsta));
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_wctemp, cmd_tvb, 266, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_cctemp, cmd_tvb, 268, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mtfa, cmd_tvb, 270, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_hmpre, cmd_tvb, 272, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_hmmin, cmd_tvb, 276, 4, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_tnvmcap, cmd_tvb, 280, 16, ENC_NA);
    post_add_cap(ti, cmd_tvb, 280);
    ti = proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_unvmcap, cmd_tvb, 296, 16, ENC_NA);
    post_add_cap(ti, cmd_tvb, 296);

    add_group_mask_entry(cmd_tvb, cmd_tree, 312, 4, ASPEC(hf_nvme_identify_ctrl_rpmbs));
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_edstt, cmd_tvb, 316, 2, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 318, 1, ASPEC(hf_nvme_identify_ctrl_dsto));

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_fwug, cmd_tvb, 319, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_kas, cmd_tvb, 320, 2, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 320, 2, ASPEC(hf_nvme_identify_ctrl_hctma));

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mntmt, cmd_tvb, 324, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mxtmt, cmd_tvb, 326, 2, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 328, 2, ASPEC(hf_nvme_identify_ctrl_sanicap));

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_hmmminds, cmd_tvb, 332, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_hmmaxd, cmd_tvb, 336, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nsetidmax, cmd_tvb, 338, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_endgidmax, cmd_tvb, 340, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_anatt, cmd_tvb, 342, 1, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 343, 1, ASPEC(hf_nvme_identify_ctrl_anacap));

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_anagrpmax, cmd_tvb, 344, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nanagrpid, cmd_tvb, 348, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_pels, cmd_tvb, 352, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd2, cmd_tvb, 356, 156, ENC_NA);
    add_group_mask_entry(cmd_tvb, cmd_tree, 512, 1, ASPEC(hf_nvme_identify_ctrl_sqes));
    add_group_mask_entry(cmd_tvb, cmd_tree, 513, 1, ASPEC(hf_nvme_identify_ctrl_cqes));

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_maxcmd, cmd_tvb, 514, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nn, cmd_tvb, 516, 4, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 520, 2, ASPEC(hf_nvme_identify_ctrl_oncs));

    add_group_mask_entry(cmd_tvb, cmd_tree, 522, 2, ASPEC(hf_nvme_identify_ctrl_fuses));
    add_group_mask_entry(cmd_tvb, cmd_tree, 524, 1, ASPEC(hf_nvme_identify_ctrl_fna));
    add_group_mask_entry(cmd_tvb, cmd_tree, 525, 1, ASPEC(hf_nvme_identify_ctrl_vwc));

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_awun, cmd_tvb, 526, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_awupf, cmd_tvb, 528, 2, ENC_LITTLE_ENDIAN);
    add_group_mask_entry(cmd_tvb, cmd_tree, 530, 1, ASPEC(hf_nvme_identify_ctrl_nvscc));

    add_group_mask_entry(cmd_tvb, cmd_tree, 531, 1, ASPEC(hf_nvme_identify_ctrl_nwpc));
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_acwu, cmd_tvb, 532, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd3, cmd_tvb, 534, 2, ENC_NA);

    add_group_mask_entry(cmd_tvb, cmd_tree, 536, 4, ASPEC(hf_nvme_identify_ctrl_sgls));
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mnan, cmd_tvb, 540, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd4, cmd_tvb, 544, 224, ENC_NA);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_subnqn, cmd_tvb, 768, 256, ENC_ASCII|ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_rsvd5, cmd_tvb, 1024, 68, ENC_NA);
    dissect_nvme_identify_ctrl_resp_nvmeof(cmd_tvb, cmd_tree);

    dissect_nvme_identify_ctrl_resp_power_state_descriptors(cmd_tvb, cmd_tree);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_vs, cmd_tvb, 3072, 1024, ENC_NA);
}

static void dissect_nvme_identify_resp(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                       struct nvme_cmd_ctx *cmd_ctx)
{
    switch(cmd_ctx->resp_type) {
    case NVME_IDENTIFY_CNS_IDENTIFY_NS:
        dissect_nvme_identify_ns_resp(cmd_tvb, cmd_tree);
        break;
    case NVME_IDENTIFY_CNS_IDENTIFY_CTRL:
        dissect_nvme_identify_ctrl_resp(cmd_tvb, cmd_tree);
        break;
    case NVME_IDENTIFY_CNS_IDENTIFY_NSLIST:
        dissect_nvme_identify_nslist_resp(cmd_tvb, cmd_tree);
        break;
    default:
        break;
    }
}

static void dissect_nvme_identify_cmd(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                                      struct nvme_cmd_ctx *cmd_ctx)
{
    guint32 val;
    proto_item *item;

    cmd_ctx->resp_type = tvb_get_guint16(cmd_tvb, 40, ENC_LITTLE_ENDIAN);
    item = proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_identify_cns, cmd_tvb,
                        40, 1, ENC_LITTLE_ENDIAN, &val);
    proto_item_append_text(item, " %s", val_to_str(val, cns_table, "Reserved"));
    proto_tree_add_item(cmd_tree, hf_nvme_identify_rsvd, cmd_tvb,
                        41, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_cntid, cmd_tvb,
                        42, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_nvmesetid, cmd_tvb,
                        44, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_rsvd1, cmd_tvb,
                        46, 2, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_uuid_index, cmd_tvb,
                        56, 1, ENC_LITTLE_ENDIAN);
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
                           val_to_str(val, dsm_acc_freq_tbl, "Reserved"));

    val = (tvb_get_guint8(cmd_tvb, 52) & 0x30) >> 4;
    item = proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_access_lat, cmd_tvb,
                               52, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(item, " %s",
                           val_to_str(val, dsm_acc_lat_tbl, "Reserved"));

    proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_seq_req, cmd_tvb,
                        52, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dsm_tree, hf_nvme_cmd_dsm_incompressible, cmd_tvb,
                        52, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_cmd_rsvd3, cmd_tvb,
                        53, 3, ENC_NA);
}

void
dissect_nvme_data_response(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, guint len)
{
    proto_tree *cmd_tree;
    proto_item *ti;
    const guint8 *str_opcode;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
    ti = proto_tree_add_item(root_tree, proto_nvme, nvme_tvb, 0,
                             len, ENC_NA);
    cmd_tree = proto_item_add_subtree(ti, ett_data);
    if (q_ctx->qid) { //IOQ
        str_opcode = val_to_str(cmd_ctx->opcode, ioq_opc_tbl,
                                "Unknown IOQ Opcode");
        switch (cmd_ctx->opcode) {
        case NVME_IOQ_OPC_READ:
        case NVME_IOQ_OPC_WRITE:
        default:
            proto_tree_add_bytes_format_value(cmd_tree, hf_nvme_gen_data,
                                              nvme_tvb, 0, len, NULL,
                                              "%s", str_opcode);
            break;
        }
    } else { //AQ
        str_opcode = val_to_str(cmd_ctx->opcode, aq_opc_tbl,
                                "Unknown AQ Opcode");
        switch (cmd_ctx->opcode) {
        case NVME_AQ_OPC_IDENTIFY:
            dissect_nvme_identify_resp(nvme_tvb, cmd_tree, cmd_ctx);
            break;

        default:
            proto_tree_add_bytes_format_value(cmd_tree, hf_nvme_gen_data,
                                              nvme_tvb, 0, len, NULL,
                                              "%s", str_opcode);
            break;
        }
    }
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "NVMe %s: Data", str_opcode);
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
    if (q_ctx->qid)
        proto_item_append_text(opc_item, " %s",
                               val_to_str(cmd_ctx->opcode, ioq_opc_tbl, "Reserved"));
    else
        proto_item_append_text(opc_item, " %s",
                               val_to_str(cmd_ctx->opcode, aq_opc_tbl, "Reserved"));

    nvme_publish_to_data_req_link(cmd_tree, nvme_tvb, hf_nvme_data_req, cmd_ctx);
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

    dissect_nvme_cmd_sgl(nvme_tvb, cmd_tree, hf_nvme_cmd_sgl, q_ctx, cmd_ctx, PINFO_FD_VISITED(pinfo));

    if (q_ctx->qid) { //IOQ
        switch (cmd_ctx->opcode) {
        case NVME_IOQ_OPC_READ:
        case NVME_IOQ_OPC_WRITE:
            dissect_nvme_rw_cmd(nvme_tvb, cmd_tree);
            break;
        default:
            break;
        }
    } else { //AQ
        switch (cmd_ctx->opcode) {
        case NVME_AQ_OPC_IDENTIFY:
            dissect_nvme_identify_cmd(nvme_tvb, cmd_tree, cmd_ctx);
            break;
        default:
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

void
dissect_nvme_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_cmd_ctx *cmd_ctx)
{
    proto_tree *cqe_tree;
    proto_item *ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
    ti = proto_tree_add_item(root_tree, proto_nvme, nvme_tvb, 0,
                             NVME_CQE_SIZE, ENC_NA);
    proto_item_append_text(ti, " (Cqe)");
    cqe_tree = proto_item_add_subtree(ti, ett_data);

    nvme_publish_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_cmd_pkt, cmd_ctx);
    nvme_publish_cmd_latency(cqe_tree, cmd_ctx, hf_nvme_cmd_latency);

    proto_tree_add_item(cqe_tree, hf_nvme_cqe_sts, nvme_tvb,
                        0, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_sqhd, nvme_tvb,
                        8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_rsvd, nvme_tvb,
                        10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_cid, nvme_tvb,
                        12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_status, nvme_tvb,
                        14, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_cqe_status_rsvd, nvme_tvb,
                        14, 2, ENC_LITTLE_ENDIAN);
}

void
proto_register_nvme(void)
{
    static hf_register_info hf[] = {
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
        { &hf_nvme_identify_cntid,
            { "Controller Identifier (CNTID)", "nvme.cmd.identify.cntid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_rsvd,
            { "Reserved", "nvme.cmd.identify.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cns,
            { "Controller or Namespace Structure (CNS)", "nvme.cmd.identify.cns",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_nvmesetid,
            { "NVM Set Identifier (NVMSETID)", "nvme.cmd.identify.nvmesetid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_rsvd1,
            { "Reserved", "nvme.cmd.identify.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_uuid_index,
            { "UUID Index", "nvme.cmd.identify.uuid_index",
               FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL}
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
               FT_BYTES, STR_ASCII, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_eui64,
            { "IEEE Extended Unique Identifier (EUI64)", "nvme.cmd.identify.ns.eui64",
               FT_BYTES, STR_ASCII, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_lbafs,
            { "LBA Formats", "nvme.cmd.identify.ns.lbafs",
               FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_lbaf,
            { "LBA Format", "nvme.cmd.identify.ns.lbaf",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
            { "Extended Data Get Log Page Support", "nvme.cmd.identify.ctrl.lpa.elp.elp",
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
            { "Reserved", "nvme.cmd.identify.ctrl.lpa",
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
            { "Cryptographic Erase Supportred", "nvme.cmd.identify.ctrl.fna.ces",
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

        /* NVMe Response fields */
        { &hf_nvme_cqe_sts,
            { "Cmd specific Status", "nvme.cqe.sts",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_sqhd,
            { "SQ Head Pointer", "nvme.cqe.sqhd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_rsvd,
            { "Reserved", "nvme.cqe.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_cid,
            { "Command ID", "nvme.cqe.cid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_cqe_status,
            { "Status", "nvme.cqe.status",
               FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL}
        },
        { &hf_nvme_cqe_status_rsvd,
            { "Reserved", "nvme.cqe.status.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x1, NULL, HFILL}
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
