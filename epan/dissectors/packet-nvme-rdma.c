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

#define NVME_FABRIC_OPC 0x7F

#define NVME_FCTYPE_CONNECT   0x1
#define NVME_FCTYPE_AUTH_RECV 0x6
#define NVME_FCTYPE_PROP_GET  0x4
#define NVME_FCTYPE_PROP_SET  0x0

static const value_string fctype_tbl[] = {
    { NVME_FCTYPE_CONNECT,       "Connect"},
    { NVME_FCTYPE_PROP_GET,      "Property Get"},
    { NVME_FCTYPE_PROP_SET,      "Property Set"},
    { NVME_FCTYPE_AUTH_RECV,     "Authentication Recv"},
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

struct nvme_rdma_q_ctx {
    struct nvme_q_ctx n_q_ctx;
};

struct nvme_rdma_cmd_ctx {
    struct nvme_cmd_ctx n_cmd_ctx;
    guint8 fctype;    /* fabric cmd type */
};

void proto_reg_handoff_nvme_rdma(void);
void proto_register_nvme_rdma(void);

static int proto_nvme_rdma = -1;
static dissector_handle_t ib_handler;
static int proto_ib = -1;

/* NVMe Fabrics RDMA CM Private data */
static int hf_nvme_rdma_cm_req_recfmt = -1;
static int hf_nvme_rdma_cm_req_qid = -1;
static int hf_nvme_rdma_cm_req_hrqsize = -1;
static int hf_nvme_rdma_cm_req_hsqsize = -1;
static int hf_nvme_rdma_cm_req_reserved = -1;

static int hf_nvme_rdma_cm_rsp_recfmt = -1;
static int hf_nvme_rdma_cm_rsp_crqsize = -1;
static int hf_nvme_rdma_cm_rsp_reserved = -1;

static int hf_nvme_rdma_cm_rej_recfmt = -1;
static int hf_nvme_rdma_cm_rej_status = -1;
static int hf_nvme_rdma_cm_rej_reserved = -1;

/* NVMe Fabric Cmd */
static int hf_nvme_rdma_cmd = -1;
static int hf_nvme_rdma_from_host_unknown_data = -1;

static int hf_nvme_rdma_cmd_opc = -1;
static int hf_nvme_rdma_cmd_rsvd = -1;
static int hf_nvme_rdma_cmd_cid = -1;
static int hf_nvme_rdma_cmd_fctype = -1;
static int hf_nvme_rdma_cmd_connect_rsvd1 = -1;
static int hf_nvme_rdma_cmd_connect_sgl1 = -1;
static int hf_nvme_rdma_cmd_connect_recfmt = -1;
static int hf_nvme_rdma_cmd_connect_qid = -1;
static int hf_nvme_rdma_cmd_connect_sqsize = -1;
static int hf_nvme_rdma_cmd_connect_cattr = -1;
static int hf_nvme_rdma_cmd_connect_rsvd2 = -1;
static int hf_nvme_rdma_cmd_connect_kato = -1;
static int hf_nvme_rdma_cmd_connect_rsvd3 = -1;
static int hf_nvme_rdma_cmd_data = -1;
static int hf_nvme_rdma_cmd_connect_data_hostid = -1;
static int hf_nvme_rdma_cmd_connect_data_cntlid = -1;
static int hf_nvme_rdma_cmd_connect_data_rsvd = -1;
static int hf_nvme_rdma_cmd_connect_data_subnqn = -1;
static int hf_nvme_rdma_cmd_connect_data_hostnqn = -1;
static int hf_nvme_rdma_cmd_connect_data_rsvd1 = -1;

static int hf_nvme_rdma_cmd_prop_attr_rsvd = -1;
static int hf_nvme_rdma_cmd_prop_attr_rsvd1 = -1;
static int hf_nvme_rdma_cmd_prop_attr_size = -1;
static int hf_nvme_rdma_cmd_prop_attr_rsvd2 = -1;
static int hf_nvme_rdma_cmd_prop_attr_offset = -1;
static int hf_nvme_rdma_cmd_prop_attr_get_rsvd3 = -1;
static int hf_nvme_rdma_cmd_prop_attr_set_4B_value = -1;
static int hf_nvme_rdma_cmd_prop_attr_set_4B_value_rsvd = -1;
static int hf_nvme_rdma_cmd_prop_attr_set_8B_value = -1;
static int hf_nvme_rdma_cmd_prop_attr_set_rsvd3 = -1;

static int hf_nvme_rdma_cmd_generic_rsvd1 = -1;
static int hf_nvme_rdma_cmd_generic_field = -1;

/* NVMe Fabric CQE */
static int hf_nvme_rdma_cqe = -1;
static int hf_nvme_rdma_cqe_sts = -1;
static int hf_nvme_rdma_cqe_sqhd = -1;
static int hf_nvme_rdma_cqe_rsvd = -1;
static int hf_nvme_rdma_cqe_cid = -1;
static int hf_nvme_rdma_cqe_status = -1;
static int hf_nvme_rdma_cqe_status_rsvd = -1;

static int hf_nvme_rdma_cqe_connect_cntlid = -1;
static int hf_nvme_rdma_cqe_connect_authreq = -1;
static int hf_nvme_rdma_cqe_connect_rsvd = -1;
static int hf_nvme_rdma_cqe_prop_set_rsvd = -1;

static int hf_nvme_rdma_to_host_unknown_data = -1;

/* tracking Cmd and its respective CQE */
static int hf_nvme_rdma_cmd_pkt = -1;
static int hf_nvme_rdma_cqe_pkt = -1;
static int hf_nvme_rdma_cmd_latency = -1;
static int hf_nvme_rdma_cmd_qid = -1;

/* Initialize the subtree pointers */
static gint ett_cm = -1;
static gint ett_data = -1;

static range_t *gPORT_RANGE;

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
        q_ctx = wmem_new(wmem_file_scope(), struct nvme_rdma_q_ctx);
        q_ctx->n_q_ctx.pending_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.done_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_requests = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_responses = wmem_tree_new(wmem_file_scope());
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

static void dissect_rdma_cm_req_packet(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree *cm_tree;
    proto_item *ti, *qid_item;
    /* private data is at offset of 36 bytes */
    int offset = 36;
    guint16 qid;

    /* create display subtree for private data */
    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, offset, 32, ENC_NA);
    cm_tree = proto_item_add_subtree(ti, ett_cm);

    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_recfmt, tvb,
                        offset + 0, 2, ENC_LITTLE_ENDIAN);

    qid_item = proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_qid, tvb,
                                   offset + 2, 2, ENC_LITTLE_ENDIAN);
    qid = tvb_get_guint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
    proto_item_append_text(qid_item, " %s", qid ? "IOQ" : "AQ");

    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_hrqsize, tvb,
                        offset + 4, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_hsqsize, tvb,
                        offset + 6, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_req_reserved, tvb,
                        offset + 8, 24, ENC_NA);
}

static void dissect_rdma_cm_rsp_packet(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree *cm_tree;
    proto_item *ti;

    /* create display subtree for the private datat that start at offset 0 */
    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, 0, 32, ENC_NA);
    cm_tree = proto_item_add_subtree(ti, ett_cm);

    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rsp_recfmt, tvb,
            0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rsp_crqsize, tvb,
            2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rsp_reserved, tvb,
            4, 28, ENC_NA);
}

static void dissect_rdma_cm_rej_packet(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree *cm_tree;
    proto_item *ti;

    /* create display subtree for the private datat that start at offset 0 */
    ti = proto_tree_add_item(tree, proto_nvme_rdma, tvb, 0, 32, ENC_NA);
    cm_tree = proto_item_add_subtree(ti, ett_cm);

    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rej_recfmt, tvb,
            0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rej_status, tvb,
            2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cm_tree, hf_nvme_rdma_cm_rej_reserved, tvb,
            4, 28, ENC_NA);
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
    conversation_infiniband_data *conv_data = NULL;
    struct infinibandinfo *info = (struct infinibandinfo *)data;

    conv_data = find_ib_cm_conversation(pinfo);
    if (!conv_data)
        return FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_RDMA);
    return dissect_rdma_cm_packet(tvb, tree, info->cm_attribute_id);
}

static void dissect_nvme_fabric_connect_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
{
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_rsvd1, cmd_tvb,
                        5, 19, ENC_NA);
    dissect_nvme_cmd_sgl(cmd_tvb, cmd_tree, hf_nvme_rdma_cmd_connect_sgl1, NULL);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_recfmt, cmd_tvb,
                        40, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_qid, cmd_tvb,
                        42, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_sqsize, cmd_tvb,
                        44, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_cattr, cmd_tvb,
                        46, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_rsvd2, cmd_tvb,
                        47, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_kato, cmd_tvb,
                        48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_connect_rsvd3, cmd_tvb,
                        52, 12, ENC_NA);
}

static guint8 dissect_nvme_fabric_prop_cmd_common(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
{
    proto_item *attr_item, *offset_item;
    guint32 offset;
    guint8 attr;

    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_rsvd, cmd_tvb,
                        5, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_rsvd1, cmd_tvb,
                        40, 1, ENC_LITTLE_ENDIAN);
    attr_item = proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_size, cmd_tvb,
                                    40, 1, ENC_LITTLE_ENDIAN);
    attr = tvb_get_guint8(cmd_tvb, 40) & 0x7;
    proto_item_append_text(attr_item, " %s",
                           val_to_str(attr, attr_size_tbl, "Reserved"));

    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_rsvd2, cmd_tvb,
                        41, 3, ENC_NA);

    offset_item = proto_tree_add_item_ret_uint(cmd_tree, hf_nvme_rdma_cmd_prop_attr_offset,
                                      cmd_tvb, 44, 4, ENC_LITTLE_ENDIAN, &offset);
    proto_item_append_text(offset_item, " %s",
                           val_to_str(offset, prop_offset_tbl, "Unknown Property"));
    return attr;
}

static void dissect_nvme_fabric_prop_get_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
{
    dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_get_rsvd3, cmd_tvb,
                        48, 16, ENC_NA);
}

static void dissect_nvme_fabric_prop_set_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
{
    guint8 attr;

    attr = dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb);
    if (attr == 0) {
        proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_set_4B_value, cmd_tvb,
                            48, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_set_4B_value_rsvd, cmd_tvb,
                            52, 4, ENC_LITTLE_ENDIAN);
    } else {
        proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_set_8B_value, cmd_tvb,
                            48, 8, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_prop_attr_set_rsvd3, cmd_tvb,
                        56, 8, ENC_NA);
}

static void dissect_nvme_fabric_generic_cmd(proto_tree *cmd_tree, tvbuff_t *cmd_tvb)
{
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_generic_rsvd1, cmd_tvb,
                        5, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_generic_field, cmd_tvb,
                        40, 24, ENC_NA);
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
dissect_nvme_fabric_cmd(tvbuff_t *nvme_tvb, proto_tree *nvme_tree,
                        struct nvme_rdma_cmd_ctx *cmd_ctx)
{
    proto_tree *cmd_tree;
    proto_item *ti, *opc_item, *fctype_item;
    guint8 fctype;

    fctype = tvb_get_guint8(nvme_tvb, 4);
    cmd_ctx->fctype = fctype;

    ti = proto_tree_add_item(nvme_tree, hf_nvme_rdma_cmd, nvme_tvb, 0,
                             NVME_FABRIC_CMD_SIZE, ENC_NA);
    cmd_tree = proto_item_add_subtree(ti, ett_data);

    opc_item = proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_opc, nvme_tvb,
                                   0, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(opc_item, "%s", " Fabric Cmd");

    nvme_publish_cmd_to_cqe_link(cmd_tree, nvme_tvb, hf_nvme_rdma_cqe_pkt,
                                 &cmd_ctx->n_cmd_ctx);

    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_rsvd, nvme_tvb,
                        1, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_cid, nvme_tvb,
                        2, 2, ENC_LITTLE_ENDIAN);

    fctype_item = proto_tree_add_item(cmd_tree, hf_nvme_rdma_cmd_fctype,
                                      nvme_tvb,
                                      4, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(fctype_item, " %s",
                           val_to_str(fctype, fctype_tbl, "Unknown FcType"));

    switch(fctype) {
    case NVME_FCTYPE_CONNECT:
        dissect_nvme_fabric_connect_cmd(cmd_tree, nvme_tvb);
        break;
    case NVME_FCTYPE_PROP_GET:
        dissect_nvme_fabric_prop_get_cmd(cmd_tree, nvme_tvb);
        break;
    case NVME_FCTYPE_PROP_SET:
        dissect_nvme_fabric_prop_set_cmd(cmd_tree, nvme_tvb);
        break;
    case NVME_FCTYPE_AUTH_RECV:
    default:
        dissect_nvme_fabric_generic_cmd(cmd_tree, nvme_tvb);
        break;
    }
}

static void
dissect_nvme_fabric_connect_cmd_data(tvbuff_t *data_tvb, proto_tree *data_tree,
                                     guint offset)
{
    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_hostid, data_tvb,
                        offset, 16, ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_cntlid, data_tvb,
                        offset + 16, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_rsvd, data_tvb,
                        offset + 18, 238, ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_subnqn, data_tvb,
                        offset + 256, 256, ENC_ASCII | ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_hostnqn, data_tvb,
                        offset + 512, 256, ENC_ASCII | ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_rdma_cmd_connect_data_rsvd1, data_tvb,
                        offset + 768, 256, ENC_NA);
}

static void
dissect_nvme_fabric_data(tvbuff_t *nvme_tvb, proto_tree *nvme_tree,
                         guint len, guint8 fctype)
{
    proto_tree *data_tree;
    proto_item *ti;

    ti = proto_tree_add_item(nvme_tree, hf_nvme_rdma_cmd_data, nvme_tvb, 0,
                             len, ENC_NA);
    data_tree = proto_item_add_subtree(ti, ett_data);

    switch (fctype) {
    case NVME_FCTYPE_CONNECT:
        dissect_nvme_fabric_connect_cmd_data(nvme_tvb, data_tree,
                                             NVME_FABRIC_CMD_SIZE);
        break;
    default:
        proto_tree_add_item(data_tree, hf_nvme_rdma_from_host_unknown_data,
                            nvme_tvb, 0, len, ENC_NA);
        break;
    }
}

static void
dissect_nvme_rdma_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                      proto_tree *nvme_tree, struct nvme_rdma_q_ctx *q_ctx,
                      guint len)
{
    struct nvme_rdma_cmd_ctx *cmd_ctx;
    guint16 cmd_id;
    guint8 opcode;

    opcode = tvb_get_guint8(nvme_tvb, 0);
    cmd_id = tvb_get_guint16(nvme_tvb, 2, ENC_LITTLE_ENDIAN);
    cmd_ctx = bind_cmd_to_qctx(pinfo, &q_ctx->n_q_ctx, cmd_id);
    if (opcode == NVME_FABRIC_OPC) {
        cmd_ctx->n_cmd_ctx.fabric = TRUE;
        dissect_nvme_fabric_cmd(nvme_tvb, nvme_tree, cmd_ctx);
        len -= NVME_FABRIC_CMD_SIZE;
        if (len)
            dissect_nvme_fabric_data(nvme_tvb, nvme_tree, len, cmd_ctx->fctype);
    } else {
        cmd_ctx->n_cmd_ctx.fabric = FALSE;
        dissect_nvme_cmd(nvme_tvb, pinfo, root_tree, &q_ctx->n_q_ctx,
                         &cmd_ctx->n_cmd_ctx);
        if (cmd_ctx->n_cmd_ctx.remote_key) {
            nvme_add_data_request(pinfo, &q_ctx->n_q_ctx,
                                  &cmd_ctx->n_cmd_ctx, (void*)cmd_ctx);
        }
    }
}

static void
dissect_nvme_from_host(tvbuff_t *nvme_tvb, packet_info *pinfo,
                       proto_tree *root_tree, proto_tree *nvme_tree,
                       struct infinibandinfo *info,
                       struct nvme_rdma_q_ctx *q_ctx,
                       guint len)

{
    switch (info->opCode) {
    case RC_SEND_ONLY:
        if (len >= NVME_FABRIC_CMD_SIZE)
            dissect_nvme_rdma_cmd(nvme_tvb, pinfo, root_tree, nvme_tree, q_ctx, len);
        else
            proto_tree_add_item(nvme_tree, hf_nvme_rdma_from_host_unknown_data, nvme_tvb,
                    0, len, ENC_NA);
        break;
    default:
        proto_tree_add_item(nvme_tree, hf_nvme_rdma_from_host_unknown_data, nvme_tvb,
                0, len, ENC_NA);
        break;
    }
}

static void
dissect_nvme_rdma_cqe_status_8B(proto_tree *cqe_tree, tvbuff_t *cqe_tvb,
                                  struct nvme_rdma_cmd_ctx *cmd_ctx)
{
    switch (cmd_ctx->fctype) {
    case NVME_FCTYPE_CONNECT:
        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_connect_cntlid, cqe_tvb,
                            0, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_connect_authreq, cqe_tvb,
                            2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_connect_rsvd, cqe_tvb,
                            4, 4, ENC_NA);
        break;
    case NVME_FCTYPE_PROP_GET:
        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_sts, cqe_tvb,
                            0, 8, ENC_LITTLE_ENDIAN);
        break;
    case NVME_FCTYPE_PROP_SET:
        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_prop_set_rsvd, cqe_tvb,
                            0, 8, ENC_NA);
        break;
    case NVME_FCTYPE_AUTH_RECV:
    default:
        proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_sts, cqe_tvb,
                            0, 8, ENC_LITTLE_ENDIAN);
        break;
    };
}

static void
dissect_nvme_fabric_cqe(tvbuff_t *nvme_tvb,
                        proto_tree *nvme_tree,
                        struct nvme_rdma_cmd_ctx *cmd_ctx)
{
    proto_tree *cqe_tree;
    proto_item *ti;

    ti = proto_tree_add_item(nvme_tree, hf_nvme_rdma_cqe, nvme_tvb,
                             0, NVME_FABRIC_CQE_SIZE, ENC_NA);
    proto_item_append_text(ti, " (For Cmd: %s)", val_to_str(cmd_ctx->fctype,
                                                fctype_tbl, "Unknown Cmd"));

    cqe_tree = proto_item_add_subtree(ti, ett_data);

    nvme_publish_cqe_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_rdma_cmd_pkt,
                                 &cmd_ctx->n_cmd_ctx);
    nvme_publish_cmd_latency(cqe_tree, &cmd_ctx->n_cmd_ctx, hf_nvme_rdma_cmd_latency);

    dissect_nvme_rdma_cqe_status_8B(cqe_tree, nvme_tvb, cmd_ctx);

    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_sqhd, nvme_tvb,
                        8, 2, ENC_NA);
    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_rsvd, nvme_tvb,
                        10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_cid, nvme_tvb,
                        12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_status, nvme_tvb,
                        14, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_rdma_cqe_status_rsvd, nvme_tvb,
                        14, 2, ENC_LITTLE_ENDIAN);
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
        dissect_nvme_fabric_cqe(nvme_tvb, nvme_tree, cmd_ctx);
    else
        dissect_nvme_cqe(nvme_tvb, pinfo, root_tree, &cmd_ctx->n_cmd_ctx);
    return;

not_found:
    proto_tree_add_item(nvme_tree, hf_nvme_rdma_to_host_unknown_data, nvme_tvb,
                        0, NVME_FABRIC_CQE_SIZE, ENC_NA);
}

static void
dissect_nvme_to_host(tvbuff_t *nvme_tvb, packet_info *pinfo,
                     proto_tree *root_tree, proto_tree *nvme_tree,
                     struct infinibandinfo *info,
                     struct nvme_rdma_q_ctx *q_ctx, guint len)
{
    struct nvme_rdma_cmd_ctx *cmd_ctx;

    switch (info->opCode) {
    case RC_SEND_ONLY:
    case RC_SEND_ONLY_INVAL:
        if (len == NVME_FABRIC_CQE_SIZE)
            dissect_nvme_rdma_cqe(nvme_tvb, pinfo, root_tree, nvme_tree, q_ctx);
        else
            proto_tree_add_item(nvme_tree, hf_nvme_rdma_to_host_unknown_data, nvme_tvb,
                    0, len, ENC_NA);
        break;
    case RC_RDMA_WRITE_ONLY:
    case RC_RDMA_WRITE_FIRST:
        if (!PINFO_FD_VISITED(pinfo)) {
            cmd_ctx = (struct nvme_rdma_cmd_ctx*)
                       nvme_lookup_data_request(&q_ctx->n_q_ctx,
                                                info->reth_remote_key);
            if (cmd_ctx) {
                cmd_ctx->n_cmd_ctx.data_resp_pkt_num = pinfo->num;
                nvme_add_data_response(&q_ctx->n_q_ctx, &cmd_ctx->n_cmd_ctx,
                                       info->reth_remote_key);
            }
        } else {
            cmd_ctx = (struct nvme_rdma_cmd_ctx*)
                       nvme_lookup_data_response(pinfo, &q_ctx->n_q_ctx,
                                                 info->reth_remote_key);
        }
        if (cmd_ctx)
            dissect_nvme_data_response(nvme_tvb, pinfo, root_tree, &q_ctx->n_q_ctx,
                                       &cmd_ctx->n_cmd_ctx, len);
        break;
    default:
        proto_tree_add_item(nvme_tree, hf_nvme_rdma_to_host_unknown_data, nvme_tvb,
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

    nvme_publish_qid(nvme_tree, hf_nvme_rdma_cmd_qid, q_ctx->n_q_ctx.qid);

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
        { &hf_nvme_rdma_cm_req_recfmt,
            { "Recfmt", "nvme-rdma.cm.req.recfmt",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_req_qid,
            { "Qid", "nvme-rdma.cm.req.qid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_req_hrqsize,
            { "HrqSize", "nvme-rdma.cm.req.hrqsize",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_req_hsqsize,
            { "HsqSize", "nvme-rdma.cm.req.hsqsize",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_req_reserved,
            { "Reserved", "nvme-rdma.cm.req.reserved",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_rsp_recfmt,
            { "Recfmt", "nvme-rdma.cm.rsp.recfmt",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_rsp_crqsize,
            { "CrqSize", "nvme-rdma.cm.rsp.crqsize",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_rsp_reserved,
            { "Reserved", "nvme-rdma.cm.rsp.reserved",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_rej_recfmt,
            { "Recfmt", "nvme-rdma.cm.rej.recfmt",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_rej_status,
            { "Status", "nvme-rdma.cm.rej.status",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cm_rej_reserved,
            { "Reserved", "nvme-rdma.cm.rej.reserved",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* IB RDMA NVMe Command fields */
        { &hf_nvme_rdma_cmd,
            { "Cmd", "nvme-rdma.cmd",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_from_host_unknown_data,
            { "Dissection unsupported", "nvme-rdma.unknown_data",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_opc,
            { "Opcode", "nvme-rdma.cmd.opc",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_rsvd,
            { "Reserved", "nvme-rdma.cmd.rsvd",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_cid,
            { "Command ID", "nvme-rdma.cmd.cid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_fctype,
            { "Fabric Cmd Type", "nvme-rdma.cmd.fctype",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_rsvd1,
            { "Reserved", "nvme-rdma.cmd.connect.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_sgl1,
            { "SGL1", "nvme-rdma.cmd.connect.sgl1",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_recfmt,
            { "Record Format", "nvme-rdma.cmd.connect.recfmt",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_qid,
            { "Queue ID", "nvme-rdma.cmd.connect.qid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_sqsize,
            { "SQ Size", "nvme-rdma.cmd.connect.sqsize",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_cattr,
            { "Connect Attributes", "nvme-rdma.cmd.connect.cattr",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_rsvd2,
            { "Reserved", "nvme-rdma.cmd.connect.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_kato,
            { "Keep Alive Timeout", "nvme-rdma.cmd.connect.kato",
               FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_rsvd3,
            { "Reserved", "nvme-rdma.cmd.connect.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_data,
            { "Data", "nvme-rdma.cmd.data",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_data_hostid,
            { "Host Identifier", "nvme-rdma.cmd.connect.data.hostid",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_data_cntlid,
            { "Controller ID", "nvme-rdma.cmd.connect.data.cntrlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_data_rsvd,
            { "Reserved", "nvme-rdma.cmd.connect.data.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_data_subnqn,
            { "Subsystem NQN", "nvme-rdma.cmd.connect.data.subnqn",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_data_hostnqn,
            { "Host NQN", "nvme-rdma.cmd.connect.data.hostnqn",
               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_connect_data_rsvd1,
            { "Reserved", "nvme-rdma.cmd.connect.data.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_rsvd,
            { "Reserved", "nvme-rdma.cmd.prop_attr.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_rsvd1,
            { "Reserved", "nvme-rdma.cmd.prop_attr.rsvd1",
               FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_size,
            { "Property Size", "nvme-rdma.cmd.prop_attr.size",
               FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_rsvd2,
            { "Reserved", "nvme-rdma.cmd.prop_attr.rsvd2",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_offset,
            { "Offset", "nvme-rdma.cmd.prop_attr.offset",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_get_rsvd3,
            { "Reserved", "nvme-rdma.cmd.prop_attr.get.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_set_4B_value,
            { "Value", "nvme-rdma.cmd.prop_attr.set.value.4B",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_set_4B_value_rsvd,
            { "Reserved", "nvme-rdma.cmd.prop_attr.set.value.rsvd",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_set_8B_value,
            { "Value", "nvme-rdma.cmd.prop_attr.set.value.8B",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_prop_attr_set_rsvd3,
            { "Reserved", "nvme-rdma.cmd.prop_attr.set.rsvd3",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_generic_rsvd1,
            { "Reserved", "nvme-rdma.cmd.generic.rsvd1",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_generic_field,
            { "Fabric Cmd specific field", "nvme-rdma.cmd.generic.field",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        /* IB RDMA NVMe Response fields */
        { &hf_nvme_rdma_cqe,
            { "Cqe", "nvme-rdma.cqe",
               FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_sts,
            { "Cmd specific Status", "nvme-rdma.cqe.sts",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_sqhd,
            { "SQ Head Pointer", "nvme-rdma.cqe.sqhd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_rsvd,
            { "Reserved", "nvme-rdma.cqe.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_cid,
            { "Command ID", "nvme-rdma.cqe.cid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_status,
            { "Status", "nvme-rdma.cqe.status",
               FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_status_rsvd,
            { "Reserved", "nvme-rdma.cqe.status.rsvd",
               FT_UINT16, BASE_HEX, NULL, 0x1, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_connect_cntlid,
            { "Controller ID", "nvme-rdma.cqe.connect.cntrlid",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_connect_authreq,
            { "Authentication Required", "nvme-rdma.cqe.connect.authreq",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_connect_rsvd,
            { "Reserved", "nvme-rdma.cqe.connect.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cqe_prop_set_rsvd,
            { "Reserved", "nvme-rdma.cqe.prop_set.rsvd",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_to_host_unknown_data,
            { "Dissection unsupported", "nvme-rdma.unknown_data",
               FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_nvme_rdma_cmd_pkt,
            { "Fabric Cmd in", "nvme-rdma.cmd_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cmd for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_rdma_cqe_pkt,
            { "Fabric Cqe in", "nvme-rdma.cqe_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cqe for this transaction is in this frame", HFILL }
        },
        { &hf_nvme_rdma_cmd_latency,
            { "Cmd Latency", "nvme-rdma.cmd_latency",
              FT_DOUBLE, BASE_NONE, NULL, 0x0,
              "The time between the command and completion, in usec", HFILL }
        },
        { &hf_nvme_rdma_cmd_qid,
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
    //nvme_rdma_module = prefs_register_protocol(proto_nvme_rdma, proto_reg_handoff_nvme_rdma);
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
