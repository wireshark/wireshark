/* packet-nvme-rdma.c
 * Routines for NVM Express over Fabrics(RDMA) dissection
 * Copyright 2016
 * Code by Parav Pandit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
NVM Express is high speed interface for accessing solid state drives.
NVM Express specifications are maintained by NVM Express industry
association at http://www.nvmexpress.org.

This file adds support to dissect NVM Express over fabrics packets
for RDMA. This adds very basic support for dissecting commands
completions.

Current dissection supports dissection of
(a) NVMe cmd and cqe
(b) NVMe Fabric command and cqe
As part of it, it also calculates cmd completion latencies.

This protocol is similar to iSCSI and SCSI dissection where iSCSI is
transport protocol for carying SCSI commands and responses. Similarly
NVMe Fabrics - RDMA transport protocol carries NVMe commands.

     +----------+
     |   NVMe   |
     +------+---+
            |
+-----------+---------+
|   NVMe Fabrics      |
+----+-----------+----+
     |           |
+----+---+   +---+----+
|  RDMA  |   |   FC   |
+--------+   +--------+

References:
NVMe Express fabrics specification is located at
http://www.nvmexpress.org/wp-content/uploads/NVMe_over_Fabrics_1_0_Gold_20160605.pdf

NVMe Express specification is located at
http://www.nvmexpress.org/wp-content/uploads/NVM-Express-1_2a.pdf

NVM Express RDMA TCP port assigned by IANA that maps to RDMA IP service
TCP port can be found at
http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=NVM+Express

*/
#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>

#include "packet-infiniband.h"
#include "packet-nvme.h"

#define SID_ULP_MASK   0x00000000FF000000
#define SID_PROTO_MASK 0x0000000000FF0000
#define SID_PORT_MASK  0x000000000000FFFF

#define SID_ULP         0x01
#define SID_PROTO_TCP   0x06
#define NVME_RDMA_TCP_PORT_RANGE    "4420" /* IANA registered */

#define SID_MASK (SID_ULP_MASK | SID_PROTO_MASK)
#define SID_ULP_TCP ((SID_ULP << 3 * 8) | (SID_PROTO_TCP << 2 * 8))

#define NVME_FABRICS_RDMA "NVMe Fabrics RDMA"

#define NVME_FABRIC_CMD_SIZE NVME_CMD_SIZE
#define NVME_FABRIC_CQE_SIZE NVME_CQE_SIZE

struct nvme_rdma_cmd_ctx;

/* The idea of RDMA context matching is as follows:
 * addresses, sizes, and keys are registred with nvme_add_data_request()
 * at RDMA request, the packet is matched to queue (this is already done)
 * at RDMA request, we see address, size, key, and find command with nvme_lookup_data_request()
 * we store comand context and packet sequence in the queue
 * the next RDMA transfer with the same sequence number will find a macth from queue to the command
 * knowing command context, we can decode the buffer
 * We expect all RDMA transfers to be done in order, so storing in queue context is OK
 */
struct nvme_rdma_q_ctx {
    struct nvme_q_ctx n_q_ctx;
    struct {
        struct nvme_rdma_cmd_ctx *cmd_ctx;
        guint32 first_psn;
        guint32 psn;
    } rdma_ctx;
};

struct nvme_rdma_cmd_ctx {
    struct nvme_cmd_ctx n_cmd_ctx;
};

void proto_reg_handoff_nvme_rdma(void);
void proto_register_nvme_rdma(void);

static int proto_nvme_rdma = -1;
static dissector_handle_t ib_handler;
static int proto_ib = -1;

/* NVMe Fabrics RDMA CM Private data */
static int hf_nvmeof_rdma_cm_req_recfmt = -1;
static int hf_nvmeof_rdma_cm_req_qid = -1;
static int hf_nvmeof_rdma_cm_req_hrqsize = -1;
static int hf_nvmeof_rdma_cm_req_hsqsize = -1;
static int hf_nvmeof_rdma_cm_req_cntlid = -1;
static int hf_nvmeof_rdma_cm_req_reserved = -1;

static int hf_nvmeof_rdma_cm_rsp_recfmt = -1;
static int hf_nvmeof_rdma_cm_rsp_crqsize = -1;
static int hf_nvmeof_rdma_cm_rsp_reserved = -1;

static int hf_nvmeof_rdma_cm_rej_recfmt = -1;
static int hf_nvmeof_rdma_cm_rej_status = -1;

/* Data Transfers */
static int hf_nvmeof_from_host_unknown_data = -1;
static int hf_nvmeof_read_to_host_req = -1;
static int hf_nvmeof_read_to_host_unmatched = -1;
static int hf_nvmeof_read_from_host_resp = -1;
static int hf_nvmeof_read_from_host_prev = -1;
static int hf_nvmeof_read_from_host_next = -1;
static int hf_nvmeof_read_from_host_unmatched = -1;
static int hf_nvmeof_write_to_host_req = -1;
static int hf_nvmeof_write_to_host_prev = -1;
static int hf_nvmeof_write_to_host_next = -1;
static int hf_nvmeof_write_to_host_unmatched = -1;
static int hf_nvmeof_to_host_unknown_data = -1;

/* Tracking commands, transfers and CQEs */
static int hf_nvmeof_data_resp = -1;
static int hf_nvmeof_cmd_qid = -1;


/* Initialize the subtree pointers */
static gint ett_cm = -1;
static gint ett_data = -1;

static range_t *gPORT_RANGE;

static struct nvme_rdma_cmd_ctx* nvme_cmd_to_nvme_rdma_cmd(struct nvme_cmd_ctx *nvme_cmd)
{
    return (struct nvme_rdma_cmd_ctx*)(((char *)nvme_cmd) - offsetof(struct nvme_rdma_cmd_ctx, n_cmd_ctx));
}

static conversation_infiniband_data *get_conversion_data(conversation_t *conv)
{
    conversation_infiniband_data *conv_data;

    conv_data = (conversation_infiniband_data *)conversation_get_proto_data(conv, proto_ib);
    if (!conv_data)
        return NULL;

    if ((conv_data->service_id & SID_MASK) != SID_ULP_TCP)
        return NULL;   /* the service id doesn't match that of TCP ULP - nothing for us to do here */

    if (!(value_is_in_range(gPORT_RANGE, (guint32)(conv_data->service_id & SID_PORT_MASK))))
        return NULL;   /* the port doesn't match that of NVM Express Fabrics - nothing for us to do here */
    return conv_data;
}

static conversation_t*
find_ib_conversation(packet_info *pinfo, conversation_infiniband_data **uni_conv_data)
{
    conversation_t *conv;
    conversation_infiniband_data *conv_data;

    conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->dst,
                             ENDPOINT_IBQP, pinfo->destport, pinfo->destport,
                             NO_ADDR_B|NO_PORT_B);
    if (!conv)
        return NULL;   /* nothing to do with no conversation context */

    conv_data = get_conversion_data(conv);
    *uni_conv_data = conv_data;
    if (!conv_data)
        return NULL;

    /* now that we found unidirectional conversation, find bidirectional
     * conversation, so that we can relate to nvme q.
     */
    return find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                             ENDPOINT_IBQP, pinfo->srcport, pinfo->destport, 0);
}

static guint16 find_nvme_qid(packet_info *pinfo)
{
    conversation_t *conv;
    conversation_infiniband_data *conv_data;
    guint16 qid;

    conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->dst,
                             ENDPOINT_IBQP, pinfo->destport, pinfo->destport,
                             NO_ADDR_B|NO_PORT_B);
    if (!conv)
        return 0;   /* nothing to do with no conversation context */

    conv_data = get_conversion_data(conv);
    if (!conv_data)
        return 0;

    if (conv_data->client_to_server == FALSE) {
        memcpy(&qid, &conv_data->mad_private_data[178], 2);
        return qid;
    }
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->src,
                             ENDPOINT_IBQP, conv_data->src_qp, conv_data->src_qp,
                             NO_ADDR_B|NO_PORT_B);
    if (!conv)
        return 0;
    conv_data = get_conversion_data(conv);
    if (!conv_data)
        return 0;
    memcpy(&qid, &conv_data->mad_private_data[178], 2);
    return qid;
}

static struct nvme_rdma_q_ctx*
find_add_q_ctx(packet_info *pinfo, conversation_t *conv)
{
    struct nvme_rdma_q_ctx *q_ctx;
    guint16 qid;

    q_ctx = (struct nvme_rdma_q_ctx*)conversation_get_proto_data(conv, proto_nvme_rdma);
    if (!q_ctx) {
        qid = find_nvme_qid(pinfo);
        q_ctx = wmem_new0(wmem_file_scope(), struct nvme_rdma_q_ctx);
        q_ctx->n_q_ctx.pending_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.done_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_requests = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_responses = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_offsets = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.qid = qid;
        conversation_add_proto_data(conv, proto_nvme_rdma, q_ctx);
    }
    return q_ctx;
}

static conversation_infiniband_data*
find_ib_cm_conversation(packet_info *pinfo)
{
    conversation_t *conv;

    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                             ENDPOINT_IBQP, pinfo->srcport, pinfo->destport, 0);
    if (!conv)
        return NULL;

    return get_conversion_data(conv);
}

static void add_rdma_cm_qid(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%x (%s)", val, val ? "IOQ" : "AQ");
}

static void add_zero_base(gchar *result, guint32 val)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u", val+1);
}

static void dissect_rdma_cm_req_packet(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree *cm_tree;
    proto_item *ti;
    /* NVME-RDMA connect private data starts at offset 0 of RDMA-CM
     * private data
     */

    /* create display subtree for private data */
    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, 0, 32, ENC_NA);
    cm_tree = proto_item_add_subtree(ti, ett_cm);

    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_req_recfmt, tvb,
                        0, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_req_qid, tvb,
                        2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_req_hrqsize, tvb,
                        4, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_req_hsqsize, tvb,
                        6, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_req_cntlid, tvb,
                        8, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_req_reserved, tvb,
                        10, 22, ENC_NA);
}

static void dissect_rdma_cm_rsp_packet(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree *cm_tree;
    proto_item *ti;

    /* create display subtree for the private datat that start at offset 0 */
    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, 0, 32, ENC_NA);
    cm_tree = proto_item_add_subtree(ti, ett_cm);

    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_rsp_recfmt, tvb,
            0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_rsp_crqsize, tvb,
            2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_rsp_reserved, tvb,
            4, 28, ENC_NA);
}

static void dissect_rdma_cm_rej_packet(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree *cm_tree;
    proto_item *ti;

    /* create display subtree for the private datat that start at offset 0 */
    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, 0, 4, ENC_NA);
    cm_tree = proto_item_add_subtree(ti, ett_cm);

    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_rej_recfmt, tvb,
            0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvmeof_rdma_cm_rej_status, tvb,
            2, 2, ENC_LITTLE_ENDIAN);
}

static int dissect_rdma_cm_packet(tvbuff_t *tvb, proto_tree *tree,
                                  guint16 cm_attribute_id)
{
    switch (cm_attribute_id) {
    case ATTR_CM_REQ:
        dissect_rdma_cm_req_packet(tvb, tree);
        break;
    case ATTR_CM_REP:
        dissect_rdma_cm_rsp_packet(tvb, tree);
        break;
    case ATTR_CM_REJ:
        dissect_rdma_cm_rej_packet(tvb, tree);
        break;
    default:
        break;
    }
    return TRUE;
}

static int
dissect_nvme_ib_cm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    /* infiniband dissector dissects RDMA-CM header and passes RDMA-CM
     * private data for further decoding, so we start at RDMA-CM
     * private data here
     */
    conversation_infiniband_data *conv_data = NULL;
    struct infinibandinfo *info = (struct infinibandinfo *)data;

    conv_data = find_ib_cm_conversation(pinfo);
    if (!conv_data)
        return FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_RDMA);
    return dissect_rdma_cm_packet(tvb, tree, info->cm_attribute_id);
}


static struct nvme_rdma_cmd_ctx*
bind_cmd_to_qctx(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                 guint16 cmd_id)
{
   struct nvme_rdma_cmd_ctx *ctx;

   if (!PINFO_FD_VISITED(pinfo)) {
       ctx = wmem_new0(wmem_file_scope(), struct nvme_rdma_cmd_ctx);

       nvme_add_cmd_to_pending_list(pinfo, q_ctx,
                                    &ctx->n_cmd_ctx, (void*)ctx, cmd_id);
    } else {
        /* Already visited this frame */
        ctx = (struct nvme_rdma_cmd_ctx*)
                  nvme_lookup_cmd_in_done_list(pinfo, q_ctx, cmd_id);
        /* if we have already visited frame but haven't found completion yet,
         * we won't find cmd in done q, so allocate a dummy ctx for doing
         * rest of the processing.
         */
        if (!ctx)
            ctx = wmem_new0(wmem_file_scope(), struct nvme_rdma_cmd_ctx);
    }
    return ctx;
}

static void
dissect_nvme_rdma_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                      proto_tree *nvme_tree, struct nvme_rdma_q_ctx *q_ctx)
{
    struct nvme_rdma_cmd_ctx *cmd_ctx;
    guint16 cmd_id;
    guint8 opcode;

    opcode = tvb_get_guint8(nvme_tvb, 0);
    cmd_id = tvb_get_guint16(nvme_tvb, 2, ENC_LITTLE_ENDIAN);
    cmd_ctx = bind_cmd_to_qctx(pinfo, &q_ctx->n_q_ctx, cmd_id);
    if (opcode == NVME_FABRIC_OPC) {
        cmd_ctx->n_cmd_ctx.fabric = TRUE;
        dissect_nvmeof_fabric_cmd(nvme_tvb, pinfo, nvme_tree, &q_ctx->n_q_ctx, &cmd_ctx->n_cmd_ctx, 0, TRUE);
    } else {
        cmd_ctx->n_cmd_ctx.fabric = FALSE;
        dissect_nvme_cmd(nvme_tvb, pinfo, root_tree, &q_ctx->n_q_ctx, &cmd_ctx->n_cmd_ctx);
    }
}

static void dissect_rdma_read_transfer(tvbuff_t *data_tvb, packet_info *pinfo, proto_tree *data_tree,
                       struct nvme_rdma_q_ctx *q_ctx, struct nvme_rdma_cmd_ctx *rdma_cmd, guint len)
{
    if (rdma_cmd->n_cmd_ctx.fabric == TRUE)
        dissect_nvmeof_cmd_data(data_tvb, pinfo, data_tree, 0, &q_ctx->n_q_ctx, &rdma_cmd->n_cmd_ctx, len);
    else
        dissect_nvme_data_response(data_tvb, pinfo, data_tree, &q_ctx->n_q_ctx, &rdma_cmd->n_cmd_ctx, len, FALSE);
}

static void
dissect_nvme_from_host(tvbuff_t *nvme_tvb, packet_info *pinfo,
                       proto_tree *root_tree, proto_tree *nvme_tree,
                       struct infinibandinfo *info,
                       struct nvme_rdma_q_ctx *q_ctx,
                       guint len)

{
    switch (info->opCode) {
    case RC_RDMA_READ_RESPONSE_FIRST:
    case RC_RDMA_READ_RESPONSE_MIDDLE:
    case RC_RDMA_READ_RESPONSE_LAST:
    case RC_RDMA_READ_RESPONSE_ONLY:
    {
        struct nvme_cmd_ctx *cmd = NULL;
        guint idx = 0;
        if (info->opCode == RC_RDMA_READ_RESPONSE_FIRST || info->opCode == RC_RDMA_READ_RESPONSE_ONLY) {
            cmd = nvme_lookup_data_tr_pkt(&q_ctx->n_q_ctx, 0, info->packet_seq_num);
            if (cmd && !PINFO_FD_VISITED(pinfo)) {
                q_ctx->rdma_ctx.cmd_ctx = nvme_cmd_to_nvme_rdma_cmd(cmd);
                q_ctx->rdma_ctx.psn = q_ctx->rdma_ctx.first_psn = info->packet_seq_num;
                cmd->tr_bytes = 0;
                cmd->first_tr_psn = info->packet_seq_num;
                cmd->data_tr_pkt_num[0] = pinfo->num;
            }
        } else {
            if (!PINFO_FD_VISITED(pinfo)) {
                if (q_ctx->rdma_ctx.cmd_ctx && (q_ctx->rdma_ctx.psn + 1) == info->packet_seq_num) {
                    idx = info->packet_seq_num - q_ctx->rdma_ctx.first_psn;
                    q_ctx->rdma_ctx.psn++;
                    cmd = &q_ctx->rdma_ctx.cmd_ctx->n_cmd_ctx;
                    if (idx < NVME_CMD_MAX_TRS)
                        cmd->data_tr_pkt_num[idx] = pinfo->num;
                    nvme_add_data_tr_pkt(&q_ctx->n_q_ctx, cmd, 0, info->packet_seq_num);
                    nvme_add_data_tr_off(&q_ctx->n_q_ctx, cmd->tr_bytes, pinfo->num);
                }
            } else {
                cmd = nvme_lookup_data_tr_pkt(&q_ctx->n_q_ctx, 0, info->packet_seq_num);
                if (cmd)
                    idx = info->packet_seq_num - cmd->first_tr_psn;
            }
        }
        if (cmd) {
            proto_item *ti = proto_tree_add_item(nvme_tree, hf_nvmeof_read_from_host_resp, nvme_tvb, 0, len, ENC_NA);
            proto_tree *rdma_tree = proto_item_add_subtree(ti, ett_data);
            nvme_publish_to_cmd_link(rdma_tree, nvme_tvb, hf_nvmeof_cmd_pkt, cmd);
            nvme_publish_to_data_req_link(rdma_tree, nvme_tvb, hf_nvmeof_data_req, cmd);
            if (idx && (idx-1) < NVME_CMD_MAX_TRS)
                nvme_publish_link(rdma_tree, nvme_tvb, hf_nvmeof_read_from_host_prev , cmd->data_tr_pkt_num[idx-1], FALSE);
            if ((idx + 1) < NVME_CMD_MAX_TRS)
                nvme_publish_link(rdma_tree, nvme_tvb, hf_nvmeof_read_from_host_next , cmd->data_tr_pkt_num[idx+1], FALSE);

            dissect_rdma_read_transfer(nvme_tvb, pinfo, rdma_tree, q_ctx, nvme_cmd_to_nvme_rdma_cmd(cmd), len);
            if (!PINFO_FD_VISITED(pinfo))
                 cmd->tr_bytes += len;
        } else {
            proto_tree_add_item(nvme_tree, hf_nvmeof_read_from_host_unmatched,
                                    nvme_tvb, 0, len, ENC_NA);
        }
        break;
    }
    case RC_SEND_ONLY:
        if (len >= NVME_FABRIC_CMD_SIZE)
            dissect_nvme_rdma_cmd(nvme_tvb, pinfo, root_tree, nvme_tree, q_ctx);
        else
            proto_tree_add_item(nvme_tree, hf_nvmeof_from_host_unknown_data,
                            nvme_tvb, 0, len, ENC_NA);
        break;
    default:
        proto_tree_add_item(nvme_tree, hf_nvmeof_from_host_unknown_data, nvme_tvb,
                0, len, ENC_NA);
        break;
    }
}

static void
dissect_nvme_rdma_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo,
                      proto_tree *root_tree, proto_tree *nvme_tree,
                      struct nvme_rdma_q_ctx *q_ctx)
{
    struct nvme_rdma_cmd_ctx *cmd_ctx;
    guint16 cmd_id;

    cmd_id = tvb_get_guint16(nvme_tvb, 12, ENC_LITTLE_ENDIAN);

    if (!PINFO_FD_VISITED(pinfo)) {

        cmd_ctx = (struct nvme_rdma_cmd_ctx*)
                      nvme_lookup_cmd_in_pending_list(&q_ctx->n_q_ctx, cmd_id);
        if (!cmd_ctx)
            goto not_found;

        /* we have already seen this cqe, or an identical one */
        if (cmd_ctx->n_cmd_ctx.cqe_pkt_num)
            goto not_found;

        cmd_ctx->n_cmd_ctx.cqe_pkt_num = pinfo->num;
        nvme_add_cmd_cqe_to_done_list(&q_ctx->n_q_ctx, &cmd_ctx->n_cmd_ctx, cmd_id);
    } else {
        /* Already visited this frame */
        cmd_ctx = (struct nvme_rdma_cmd_ctx*)
                        nvme_lookup_cmd_in_done_list(pinfo, &q_ctx->n_q_ctx, cmd_id);
        if (!cmd_ctx)
            goto not_found;
    }

    nvme_update_cmd_end_info(pinfo, &cmd_ctx->n_cmd_ctx);

    if (cmd_ctx->n_cmd_ctx.fabric)
        dissect_nvmeof_fabric_cqe(nvme_tvb, pinfo, nvme_tree, &cmd_ctx->n_cmd_ctx, 0);
    else
        dissect_nvme_cqe(nvme_tvb, pinfo, root_tree, &q_ctx->n_q_ctx, &cmd_ctx->n_cmd_ctx);
    return;

not_found:
    proto_tree_add_item(nvme_tree, hf_nvmeof_to_host_unknown_data, nvme_tvb,
                        0, NVME_FABRIC_CQE_SIZE, ENC_NA);
}

static void
dissect_nvme_to_host(tvbuff_t *nvme_tvb, packet_info *pinfo,
                     proto_tree *root_tree, proto_tree *nvme_tree,
                     struct infinibandinfo *info,
                     struct nvme_rdma_q_ctx *q_ctx, guint len)
{
    switch (info->opCode) {
    case RC_RDMA_READ_REQUEST:
    {
        struct keyed_data_req req = {
            .addr = info->reth_remote_address,
            .key = info->reth_remote_key,
            .size = info->reth_dma_length
        };
        struct nvme_cmd_ctx *cmd = NULL;
        if (!PINFO_FD_VISITED(pinfo)) {
            cmd = nvme_lookup_data_request(&q_ctx->n_q_ctx, &req);
            if (cmd)
                 nvme_add_data_tr_pkt(&q_ctx->n_q_ctx, cmd, 0, info->packet_seq_num);
        } else {
            cmd = nvme_lookup_data_tr_pkt(&q_ctx->n_q_ctx, 0, info->packet_seq_num);
        }
        if (cmd) {
            proto_item *ti = proto_tree_add_item(nvme_tree,
                    hf_nvmeof_read_to_host_req, nvme_tvb, 0, 0, ENC_NA);
            proto_tree *rdma_tree = proto_item_add_subtree(ti, ett_data);
            cmd->data_req_pkt_num = pinfo->num;
            nvme_publish_to_data_resp_link(rdma_tree, nvme_tvb,
                                    hf_nvmeof_data_resp, cmd);
            nvme_publish_to_cmd_link(rdma_tree, nvme_tvb,
                                     hf_nvmeof_cmd_pkt, cmd);
            nvme_update_transfer_request(pinfo, cmd, &q_ctx->n_q_ctx);
        } else {
            proto_tree_add_item(nvme_tree, hf_nvmeof_read_to_host_unmatched,
                                nvme_tvb, 0, len, ENC_NA);
        }
        break;
    }
    case RC_SEND_ONLY:
    case RC_SEND_ONLY_INVAL:
        if (len == NVME_FABRIC_CQE_SIZE)
            dissect_nvme_rdma_cqe(nvme_tvb, pinfo, root_tree, nvme_tree, q_ctx);
        else
            proto_tree_add_item(nvme_tree, hf_nvmeof_to_host_unknown_data, nvme_tvb,
                    0, len, ENC_NA);
        break;
    case RC_RDMA_WRITE_ONLY:
    case RC_RDMA_WRITE_FIRST:
    case RC_RDMA_WRITE_LAST:
    case RC_RDMA_WRITE_MIDDLE:
    {
        struct nvme_cmd_ctx *cmd = NULL;
        guint idx = 0;
        if (info->opCode == RC_RDMA_WRITE_ONLY || info->opCode == RC_RDMA_WRITE_FIRST) {
            struct keyed_data_req req = {
                .addr = info->reth_remote_address,
                .key =  info->reth_remote_key,
                .size = info->reth_dma_length
            };
            if (!PINFO_FD_VISITED(pinfo)) {
                cmd = nvme_lookup_data_request(&q_ctx->n_q_ctx, &req);
                if (cmd) {
                    nvme_add_data_tr_pkt(&q_ctx->n_q_ctx, cmd, 0, info->packet_seq_num);
                    cmd->first_tr_psn = info->packet_seq_num;
                    cmd->data_tr_pkt_num[0] = pinfo->num;
                    q_ctx->rdma_ctx.cmd_ctx = nvme_cmd_to_nvme_rdma_cmd(cmd);
                    q_ctx->rdma_ctx.first_psn = q_ctx->rdma_ctx.psn = info->packet_seq_num;
                }
            } else {
                cmd = nvme_lookup_data_tr_pkt(&q_ctx->n_q_ctx, 0, info->packet_seq_num);
            }
        } else {
            if (PINFO_FD_VISITED(pinfo)) {
                cmd = nvme_lookup_data_tr_pkt(&q_ctx->n_q_ctx, 0, info->packet_seq_num);
                if (cmd)
                    idx = info->packet_seq_num - cmd->first_tr_psn;
            } else  if (q_ctx->rdma_ctx.cmd_ctx && (q_ctx->rdma_ctx.psn + 1) == info->packet_seq_num) {
                idx = info->packet_seq_num - q_ctx->rdma_ctx.first_psn;
                q_ctx->rdma_ctx.psn++;
                cmd = &q_ctx->rdma_ctx.cmd_ctx->n_cmd_ctx;
                if (idx < NVME_CMD_MAX_TRS)
                    cmd->data_tr_pkt_num[idx] = pinfo->num;
                nvme_add_data_tr_pkt(&q_ctx->n_q_ctx, cmd, 0, info->packet_seq_num);
                nvme_add_data_tr_off(&q_ctx->n_q_ctx, cmd->tr_bytes, pinfo->num);
            }
        }
        if (cmd) {
                proto_item *ti = proto_tree_add_item(nvme_tree, hf_nvmeof_write_to_host_req, nvme_tvb, 0, 0, ENC_NA);
            proto_tree *rdma_tree = proto_item_add_subtree(ti, ett_data);
            nvme_publish_to_cmd_link(rdma_tree, nvme_tvb, hf_nvmeof_cmd_pkt, cmd);
            if (idx && (idx-1) < NVME_CMD_MAX_TRS)
                nvme_publish_link(rdma_tree, nvme_tvb, hf_nvmeof_write_to_host_prev , cmd->data_tr_pkt_num[idx-1], FALSE);
            if ((idx + 1) < NVME_CMD_MAX_TRS)
                nvme_publish_link(rdma_tree, nvme_tvb, hf_nvmeof_write_to_host_next , cmd->data_tr_pkt_num[idx+1], FALSE);
            dissect_nvme_data_response(nvme_tvb, pinfo, root_tree, &q_ctx->n_q_ctx, cmd, len, FALSE);
            if (!PINFO_FD_VISITED(pinfo))
                 cmd->tr_bytes += len;
        } else {
            proto_tree_add_item(nvme_tree, hf_nvmeof_write_to_host_unmatched, nvme_tvb, 0, len, ENC_NA);
        }
        break;
    }
    default:
        proto_tree_add_item(nvme_tree, hf_nvmeof_to_host_unknown_data, nvme_tvb,
                0, len, ENC_NA);
        break;
    }
}

static int
dissect_nvme_ib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct infinibandinfo *info = (struct infinibandinfo *)data;
    conversation_infiniband_data *conv_data = NULL;
    conversation_t *conv;
    proto_tree *nvme_tree;
    proto_item *ti;
    struct nvme_rdma_q_ctx *q_ctx;
    guint len = tvb_reported_length(tvb);

    conv = find_ib_conversation(pinfo, &conv_data);
    if (!conv)
        return FALSE;

    q_ctx = find_add_q_ctx(pinfo, conv);
    if (!q_ctx)
        return FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_RDMA);

    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, 0, len, ENC_NA);
    nvme_tree = proto_item_add_subtree(ti, ett_data);

    nvme_publish_qid(nvme_tree, hf_nvmeof_cmd_qid, q_ctx->n_q_ctx.qid);

    if (conv_data->client_to_server)
        dissect_nvme_from_host(tvb, pinfo, tree, nvme_tree, info, q_ctx, len);
    else
        dissect_nvme_to_host(tvb, pinfo, tree, nvme_tree, info, q_ctx, len);

    return TRUE;
}

void
proto_register_nvme_rdma(void)
{
    module_t *nvme_rdma_module;
    static hf_register_info hf[] = {
        /* IB RDMA CM fields */
        { &hf_nvmeof_rdma_cm_req_recfmt,
            { "Record Format", "nvme-rdma.cm.req.recfmt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_req_qid,
            { "Queue Id", "nvme-rdma.cm.req.qid",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_rdma_cm_qid), 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_req_hrqsize,
            { "RDMA QP Host Receive Queue Size", "nvme-rdma.cm.req.hrqsize",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_req_hsqsize,
            { "RDMA QP Host Send Queue Size", "nvme-rdma.cm.req.hsqsize",
               FT_UINT16, BASE_CUSTOM, CF_FUNC(add_zero_base), 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_req_cntlid,
            { "Controller ID", "nvme-rdma.cm.req.cntlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_req_reserved,
            { "Reserved", "nvme-rdma.cm.req.reserved",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_rsp_recfmt,
            { "Record Format", "nvme-rdma.cm.rsp.recfmt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_rsp_crqsize,
            { "RDMA QP Controller Receive Queue Size", "nvme-rdma.cm.rsp.crqsize",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_rsp_reserved,
            { "Reserved", "nvme-rdma.cm.rsp.reserved",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_rej_recfmt,
            { "Record Format", "nvme-rdma.cm.rej.recfmt",
               FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_rdma_cm_rej_status,
            { "Status", "nvme-rdma.cm.rej.status",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_from_host_unknown_data,
            { "Dissection unsupported", "nvme-rdma.unknown_data",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_read_to_host_req,
            { "RDMA Read Request Sent to Host", "nvme-rdma.read_to_host_req",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_read_to_host_unmatched,
            { "RDMA Read Request Sent to Host (no Command Match)", "nvme-rdma.read_to_host_req",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_read_from_host_resp,
            { "RDMA Read Transfer Sent from Host", "nvme-rdma.read_from_host_resp",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_read_from_host_prev,
            { "Previous Read Transfer", "nvme-rdma.read_from_host_prev",
               FT_FRAMENUM, BASE_NONE, NULL, 0x0, "Previous read transfer is in this frame", HFILL}
        },
        { &hf_nvmeof_read_from_host_next,
            { "Next Read Transfer", "nvme-rdma.read_from_host_next",
               FT_FRAMENUM, BASE_NONE, NULL, 0x0, "Next read transfer is in this frame", HFILL}
        },
        { &hf_nvmeof_read_from_host_unmatched,
            { "RDMA Read Transfer Sent from Host (no Command Match)", "nvme-rdma.read_from_host_resp",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_write_to_host_req,
            { "RDMA Write Request Sent to Host", "nvme-rdma.write_to_host_req",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_write_to_host_prev,
            { "Previous Write Transfer", "nvme-rdma.write_to_host_prev",
               FT_FRAMENUM, BASE_NONE, NULL, 0x0, "Previous write transfer is in this frame", HFILL}
        },
        { &hf_nvmeof_write_to_host_next,
            { "Next Write Transfer", "nvme-rdma.write_to_host_next",
               FT_FRAMENUM, BASE_NONE, NULL, 0x0, "Next write transfer is in this frame", HFILL}
        },
        { &hf_nvmeof_write_to_host_unmatched,
            { "RDMA Write Request Sent to Host (no Command Match)", "nvme-rdma.write_to_host_req",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_to_host_unknown_data,
            { "Dissection unsupported", "nvme-rdma.unknown_data",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvmeof_data_resp,
            { "DATA Transfer Response", "nvme-rdma.data_resp",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "DATA transfer response for this transaction is in this frame", HFILL }
        },
        { &hf_nvmeof_cmd_qid,
            { "Cmd Qid", "nvme-rdma.cmd.qid",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              "Qid on which command is issued", HFILL }
        },
    };
    static gint *ett[] = {
        &ett_cm,
        &ett_data,
    };

    proto_nvme_rdma = proto_register_protocol("NVM Express Fabrics RDMA",
                                              NVME_FABRICS_RDMA, "nvme-rdma");

    proto_register_field_array(proto_nvme_rdma, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    nvme_rdma_module = prefs_register_protocol(proto_nvme_rdma, NULL);

    range_convert_str(wmem_epan_scope(), &gPORT_RANGE, NVME_RDMA_TCP_PORT_RANGE, MAX_TCP_PORT);
    prefs_register_range_preference(nvme_rdma_module,
                                    "subsystem_ports",
                                    "Subsystem Ports Range",
                                    "Range of NVMe Subsystem ports"
                                    "(default " NVME_RDMA_TCP_PORT_RANGE ")",
                                    &gPORT_RANGE, MAX_TCP_PORT);
}

void
proto_reg_handoff_nvme_rdma(void)
{
    heur_dissector_add("infiniband.mad.cm.private", dissect_nvme_ib_cm,
                       "NVMe Fabrics RDMA CM packets",
                       "nvme_rdma_cm_private", proto_nvme_rdma, HEURISTIC_ENABLE);
    heur_dissector_add("infiniband.payload", dissect_nvme_ib,
                       "NVMe Fabrics RDMA packets",
                       "nvme_rdma", proto_nvme_rdma, HEURISTIC_ENABLE);
    ib_handler = find_dissector_add_dependency("infiniband", proto_nvme_rdma);
    proto_ib = dissector_handle_get_protocol_index(ib_handler);
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
