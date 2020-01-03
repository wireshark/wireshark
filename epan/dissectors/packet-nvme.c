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
static int hf_nvme_identify_ctrl_mdts = -1;
static int hf_nvme_identify_ctrl_ver = -1;
static int hf_nvme_identify_ctrl_oaes = -1;
static int hf_nvme_identify_ctrl_oacs = -1;
static int hf_nvme_identify_ctrl_acl = -1;
static int hf_nvme_identify_ctrl_aerl = -1;
static int hf_nvme_identify_ctrl_kas = -1;
static int hf_nvme_identify_ctrl_sqes = -1;
static int hf_nvme_identify_ctrl_cqes = -1;
static int hf_nvme_identify_ctrl_maxcmd = -1;
static int hf_nvme_identify_ctrl_nn = -1;
static int hf_nvme_identify_ctrl_oncs = -1;
static int hf_nvme_identify_ctrl_sgls = -1;
static int hf_nvme_identify_ctrl_subnqn = -1;
static int hf_nvme_identify_ctrl_ioccsz = -1;
static int hf_nvme_identify_ctrl_iorcsz = -1;
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
    cmd_key[1].length = 1;
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
    cmd_ctx->remote_key = 0;

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

void nvme_add_data_request(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                           struct nvme_cmd_ctx *cmd_ctx, void *ctx)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = cmd_ctx->remote_key;

    cmd_ctx->data_req_pkt_num = pinfo->num;
    cmd_ctx->data_resp_pkt_num = 0;
    nvme_build_pending_cmd_key(cmd_key, &key);
    wmem_tree_insert32_array(q_ctx->data_requests, cmd_key, (void *)ctx);
}

void* nvme_lookup_data_request(struct nvme_q_ctx *q_ctx, guint32 key)
{
    wmem_tree_key_t cmd_key[3];

    nvme_build_pending_cmd_key(cmd_key, &key);
    return wmem_tree_lookup32_array(q_ctx->data_requests, cmd_key);
}

void
nvme_add_data_response(struct nvme_q_ctx *q_ctx,
                       struct nvme_cmd_ctx *cmd_ctx, guint32 rkey)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = rkey;
    guint32 frame_num;

    nvme_build_done_cmd_key(cmd_key, &key, &frame_num);

    /* Found matching data response packet. Add entries to the matched table
     * for cmd and response packets
     */
    frame_num = cmd_ctx->data_req_pkt_num;
    wmem_tree_insert32_array(q_ctx->data_responses, cmd_key, (void*)cmd_ctx);

    frame_num = cmd_ctx->data_resp_pkt_num;
    wmem_tree_insert32_array(q_ctx->data_responses, cmd_key, (void*)cmd_ctx);
}

void*
nvme_lookup_data_response(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                          guint32 rkey)
{
    wmem_tree_key_t cmd_key[3];
    guint32 key = rkey;
    guint32 frame_num = pinfo->num;

    nvme_build_done_cmd_key(cmd_key, &key, &frame_num);

    return wmem_tree_lookup32_array(q_ctx->data_responses, cmd_key);
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

void
nvme_publish_cqe_to_cmd_link(proto_tree *cqe_tree, tvbuff_t *nvme_tvb,
                          int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    proto_item *cqe_ref_item;
    cqe_ref_item = proto_tree_add_uint(cqe_tree, hf_index,
                             nvme_tvb, 0, 0, cmd_ctx->cmd_pkt_num);
    proto_item_set_generated(cqe_ref_item);
}

void
nvme_publish_data_pdu_to_cmd_link(proto_tree *pdu_tree, tvbuff_t *nvme_tvb,
                           int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    proto_item *cmd_ref_item;
    cmd_ref_item = proto_tree_add_uint(pdu_tree, hf_index,
                             nvme_tvb, 0, 0, cmd_ctx->cmd_pkt_num);
    proto_item_set_generated(cmd_ref_item);
}

void
nvme_publish_cmd_to_cqe_link(proto_tree *cmd_tree, tvbuff_t *cmd_tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    proto_item *cmd_ref_item;

    if (cmd_ctx->cqe_pkt_num) {
        cmd_ref_item = proto_tree_add_uint(cmd_tree, hf_index,
                                 cmd_tvb, 0, 0, cmd_ctx->cqe_pkt_num);
        proto_item_set_generated(cmd_ref_item);
    }
}

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                          int field_index, struct nvme_cmd_ctx *cmd_ctx)
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
        if (cmd_ctx)
            cmd_ctx->remote_key = tvb_get_guint32(cmd_tvb, offset + 11,
                                                  ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_addr, cmd_tvb,
                            offset, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_len, cmd_tvb,
                            offset + 8, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sgl_tree, hf_nvme_cmd_sgl_desc_key, cmd_tvb,
                            offset + 11, 4, ENC_LITTLE_ENDIAN);
        break;
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

static void dissect_nvme_identify_ctrl_resp(tvbuff_t *cmd_tvb,
                                            proto_tree *cmd_tree)
{
    char *sn, *mn;

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_vid, cmd_tvb,
                        0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ssvid, cmd_tvb,
                        2, 2, ENC_LITTLE_ENDIAN);

    sn = (char *)tvb_memcpy(cmd_tvb, wmem_alloc(wmem_packet_scope(), 21), 4, 20);
    sn[20] = '\0';
    proto_tree_add_string(cmd_tree, hf_nvme_identify_ctrl_sn, cmd_tvb,
                          4, 20, sn);

    mn = (char *)tvb_memcpy(cmd_tvb, wmem_alloc(wmem_packet_scope(), 41), 24, 40);
    mn[40] = '\0';
    proto_tree_add_string(cmd_tree, hf_nvme_identify_ctrl_mn, cmd_tvb,
                          24, 40, mn);

    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_mdts, cmd_tvb,
                        77, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ver, cmd_tvb,
                        80, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_oaes, cmd_tvb,
                        92, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_oacs, cmd_tvb,
                        256, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_acl, cmd_tvb,
                        258, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_aerl, cmd_tvb,
                        259, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_kas, cmd_tvb,
                        320, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_sqes, cmd_tvb,
                        512, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_cqes, cmd_tvb,
                        513, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_maxcmd, cmd_tvb,
                        514, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_nn, cmd_tvb,
                        516, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_oncs, cmd_tvb,
                        520, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_sgls, cmd_tvb,
                        536, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_subnqn, cmd_tvb,
                        768, 256, ENC_ASCII | ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_ioccsz, cmd_tvb,
                        1792, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_ctrl_iorcsz, cmd_tvb,
                        1796, 4, ENC_LITTLE_ENDIAN);
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
    cmd_ctx->resp_type = tvb_get_guint16(cmd_tvb, 40, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_cns, cmd_tvb,
                        40, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_rsvd, cmd_tvb,
                        42, 2, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_identify_cntid, cmd_tvb,
                        44, 4, ENC_NA);
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

    nvme_publish_cmd_to_cqe_link(cmd_tree, nvme_tvb, hf_nvme_cqe_pkt, cmd_ctx);

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

    dissect_nvme_cmd_sgl(nvme_tvb, cmd_tree, hf_nvme_cmd_sgl, cmd_ctx);

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

    nvme_publish_cqe_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_cmd_pkt, cmd_ctx);
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
               FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
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
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_rsvd,
            { "Reserved", "nvme.cmd.identify.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_cns,
            { "Controller or Namespace Structure (CNS)", "nvme.cmd.identify.cns",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },

        /* Identify NS response */
        { &hf_nvme_identify_ns_nsze,
            { "Namespace Size (NSZE)", "nvme.cmd.identify.ns.nsze",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ns_flbas,
            { "Formatted LBA Size (FLBAS)", "nvme.cmd.identify.ns.flbas",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
        { &hf_nvme_identify_ctrl_mdts,
            { "Maximum Data Transfer Size (MDTS)", "nvme.cmd.identify.ctrl.mdts",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ver,
            { "Version (VER)", "nvme.cmd.identify.ctrl.ver",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oaes,
            { "Optional Asynchronous Events Supported (OAES)", "nvme.cmd.identify.ctrl.oaes",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oacs,
            { "Optional Admin Command Support (OACS)", "nvme.cmd.identify.ctrl.oacs",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_acl,
            { "Abort Command Limit (ACL)", "nvme.cmd.identify.ctrl.acl",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_aerl,
            { "Asynchronous Event Request Limit (AERL)", "nvme.cmd.identify.ctrl.aerl",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_kas,
            { "Keep Alive Support (KAS)", "nvme.cmd.identify.ctrl.kas",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sqes,
            { "Submission Queue Entry Size (SQES)", "nvme.cmd.identify.ctrl.sqes",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_cqes,
            { "Completion Queue Entry Size (CQES)", "nvme.cmd.identify.ctrl.cqes",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_maxcmd,
            { "Maximum Outstanding Commands (MAXCMD)", "nvme.cmd.identify.ctrl.maxcmd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_nn,
            { "Number of Namespaces (NN)", "nvme.cmd.identify.ctrl.nn",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_oncs,
            { "Optional NVM Command Support (ONCS)", "nvme.cmd.identify.ctrl.oncs",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_sgls,
            { "SGL Support (SGLS)", "nvme.cmd.identify.ctrl.sgls",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_subnqn,
            { "NVM Subsystem NVMe Qualified Name (SUBNQN)", "nvme.cmd.identify.ctrl.subnqn",
               FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_ioccsz,
            { "I/O Queue Command Capsule Supported Size (IOCCSZ)", "nvme.cmd.identify.ctrl.ioccsz",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_identify_ctrl_iorcsz,
            { "I/O Queue Response Capsule Supported Size (IORCSZ)", "nvme.cmd.identify.ctrl.iorcsz",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
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
