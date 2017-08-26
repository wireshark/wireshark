/* packet-nvme.c
 * Routines for NVM Express dissection
 * Copyright 2016
 * Code by Parav Pandit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

    PROTO_ITEM_SET_GENERATED(cmd_ref_item);
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
    PROTO_ITEM_SET_GENERATED(cmd_ref_item);
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
    PROTO_ITEM_SET_GENERATED(cqe_ref_item);
}

void
nvme_publish_cmd_to_cqe_link(proto_tree *cmd_tree, tvbuff_t *cmd_tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx)
{
    proto_item *cmd_ref_item;

    if (cmd_ctx->cqe_pkt_num) {
        cmd_ref_item = proto_tree_add_uint(cmd_tree, hf_index,
                                 cmd_tvb, 0, 0, cmd_ctx->cqe_pkt_num);
        PROTO_ITEM_SET_GENERATED(cmd_ref_item);
    }
}

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                          int field_index)
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
dissect_nvme_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx)
{
    proto_tree *cmd_tree;
    proto_item *ti, *opc_item;
    guint8 opcode;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");
    ti = proto_tree_add_item(root_tree, proto_nvme, nvme_tvb, 0,
                             NVME_CMD_SIZE, ENC_NA);
    proto_item_append_text(ti, " (Cmd)");
    cmd_tree = proto_item_add_subtree(ti, ett_data);

    opcode = tvb_get_guint8(nvme_tvb, 0);
    opc_item = proto_tree_add_item(cmd_tree, hf_nvme_cmd_opc, nvme_tvb,
                        0, 1, ENC_LITTLE_ENDIAN);
    if (q_ctx->qid)
        proto_item_append_text(opc_item, " %s",
                               val_to_str(opcode, ioq_opc_tbl, "Reserved"));
    else
        proto_item_append_text(opc_item, " %s",
                               val_to_str(opcode, aq_opc_tbl, "Reserved"));

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

    dissect_nvme_cmd_sgl(nvme_tvb, cmd_tree, hf_nvme_cmd_sgl);

    switch (opcode) {
    case NVME_IOQ_OPC_READ:
    case NVME_IOQ_OPC_WRITE:
        dissect_nvme_rw_cmd(nvme_tvb, cmd_tree);
        break;
    default:
        break;
    }
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
    };
    static gint *ett[] = {
        &ett_data,
    };

    proto_nvme = proto_register_protocol("NVM Express", "nvme", "nvme");

    proto_register_field_array(proto_nvme, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
