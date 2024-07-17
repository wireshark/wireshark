/* packet-nvme-tcp.c
 * Routines for NVM Express over Fabrics(TCP) dissection
 * Code by Solganik Alexander <solganik@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Copyright (C) 2019 Lightbits Labs Ltd. - All Rights Reserved
*/

/*
 NVM Express is high speed interface for accessing solid state drives.
 NVM Express specifications are maintained by NVM Express industry
 association at http://www.nvmexpress.org.

 This file adds support to dissect NVM Express over fabrics packets
 for TCP. This adds very basic support for dissecting commands
 completions.

 Current dissection supports dissection of
 (a) NVMe cmd and cqe
 (b) NVMe Fabric command and cqe
 As part of it, it also calculates cmd completion latencies.

 NVM Express TCP TCP port assigned by IANA that maps to NVMe-oF service
 TCP port can be found at
 http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=NVM+Express

 */

#include "config.h"
#include <stdlib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>
#include <epan/crc32-tvb.h>
#include "packet-tcp.h"
#include "packet-nvme.h"

#include "packet-tls.h"
#include "packet-tls-utils.h"

static int proto_nvme_tcp;
static dissector_handle_t nvmet_tcp_handle;
static dissector_handle_t nvmet_tls_handle;

#define NVME_TCP_PORT_RANGE    "4420" /* IANA registered */

#define NVME_FABRICS_TCP "NVMe/TCP"
#define NVME_TCP_HEADER_SIZE 8
#define PDU_LEN_OFFSET_FROM_HEADER 4
static range_t *gPORT_RANGE;
static bool nvme_tcp_check_hdgst;
static bool nvme_tcp_check_ddgst;
#define NVME_TCP_DATA_PDU_SIZE 24

enum nvme_tcp_pdu_type {
    nvme_tcp_icreq = 0x0,
    nvme_tcp_icresp = 0x1,
    nvme_tcp_h2c_term = 0x2,
    nvme_tcp_c2h_term = 0x3,
    nvme_tcp_cmd = 0x4,
    nvme_tcp_rsp = 0x5,
    nvme_tcp_h2c_data = 0x6,
    nvme_tcp_c2h_data = 0x7,
    nvme_tcp_r2t = 0x9,
};

static const value_string nvme_tcp_pdu_type_vals[] = {
    { nvme_tcp_icreq, "ICReq" },
    { nvme_tcp_icresp, "ICResp" },
    { nvme_tcp_h2c_term, "H2CTerm" },
    { nvme_tcp_c2h_term, "C2HTerm" },
    { nvme_tcp_cmd, "CapsuleCommand" },
    { nvme_tcp_rsp, "CapsuleResponse" },
    { nvme_tcp_h2c_data, "H2CData" },
    { nvme_tcp_c2h_data, "C2HData" },
    { nvme_tcp_r2t, "Ready To Transfer" },
    { 0, NULL }
};

static const value_string nvme_tcp_termreq_fes[] = {
    {0x0, "Reserved"                        },
    {0x1, "Invalid PDU Header Field"        },
    {0x2, "PDU Sequence Error"              },
    {0x3, "Header Digest Error"             },
    {0x4, "Data Transfer Out of Range"      },
    {0x5, "R2T Limit Exceeded"              },
    {0x6, "Unsupported Parameter"           },
    {0,   NULL                              },
};

enum nvme_tcp_fatal_error_status
{
    NVME_TCP_FES_INVALID_PDU_HDR =      0x01,
    NVME_TCP_FES_PDU_SEQ_ERR =          0x02,
    NVME_TCP_FES_HDR_DIGEST_ERR =       0x03,
    NVME_TCP_FES_DATA_OUT_OF_RANGE =    0x04,
    NVME_TCP_FES_R2T_LIMIT_EXCEEDED =   0x05,
    NVME_TCP_FES_DATA_LIMIT_EXCEEDED =  0x05,
    NVME_TCP_FES_UNSUPPORTED_PARAM =    0x06,
};

enum nvme_tcp_pdu_flags {
    NVME_TCP_F_HDGST         = (1 << 0),
    NVME_TCP_F_DDGST         = (1 << 1),
    NVME_TCP_F_DATA_LAST     = (1 << 2),
    NVME_TCP_F_DATA_SUCCESS  = (1 << 3),
};


enum nvme_tcp_digest_option {
    NVME_TCP_HDR_DIGEST_ENABLE = (1 << 0),
    NVME_TCP_DATA_DIGEST_ENABLE = (1 << 1),
};


#define NVME_FABRIC_CMD_SIZE NVME_CMD_SIZE
#define NVME_FABRIC_CQE_SIZE NVME_CQE_SIZE
#define NVME_TCP_DIGEST_LENGTH  4

struct nvme_tcp_q_ctx {
    struct nvme_q_ctx n_q_ctx;
};

struct nvme_tcp_cmd_ctx {
    struct nvme_cmd_ctx n_cmd_ctx;
};

void proto_reg_handoff_nvme_tcp(void);
void proto_register_nvme_tcp(void);


static int hf_nvme_tcp_type;
static int hf_nvme_tcp_flags;
static int hf_pdu_flags_hdgst;
static int hf_pdu_flags_ddgst;
static int hf_pdu_flags_data_last;
static int hf_pdu_flags_data_success;

static int * const nvme_tcp_pdu_flags[] = {
    &hf_pdu_flags_hdgst,
    &hf_pdu_flags_ddgst,
    &hf_pdu_flags_data_last,
    &hf_pdu_flags_data_success,
    NULL
};

static int hf_nvme_tcp_hdgst;
static int hf_nvme_tcp_ddgst;
static int hf_nvme_tcp_hlen;
static int hf_nvme_tcp_pdo;
static int hf_nvme_tcp_plen;
static int hf_nvme_tcp_hdgst_status;
static int hf_nvme_tcp_ddgst_status;

/* NVMe tcp icreq/icresp fields */
static int hf_nvme_tcp_icreq;
static int hf_nvme_tcp_icreq_pfv;
static int hf_nvme_tcp_icreq_maxr2t;
static int hf_nvme_tcp_icreq_hpda;
static int hf_nvme_tcp_icreq_digest;
static int hf_nvme_tcp_icresp;
static int hf_nvme_tcp_icresp_pfv;
static int hf_nvme_tcp_icresp_cpda;
static int hf_nvme_tcp_icresp_digest;
static int hf_nvme_tcp_icresp_maxdata;

/* NVMe tcp c2h/h2c termreq fields */
static int hf_nvme_tcp_c2htermreq;
static int hf_nvme_tcp_c2htermreq_fes;
static int hf_nvme_tcp_c2htermreq_phfo;
static int hf_nvme_tcp_c2htermreq_phd;
static int hf_nvme_tcp_c2htermreq_upfo;
static int hf_nvme_tcp_c2htermreq_reserved;
static int hf_nvme_tcp_c2htermreq_data;
static int hf_nvme_tcp_h2ctermreq;
static int hf_nvme_tcp_h2ctermreq_fes;
static int hf_nvme_tcp_h2ctermreq_phfo;
static int hf_nvme_tcp_h2ctermreq_phd;
static int hf_nvme_tcp_h2ctermreq_upfo;
static int hf_nvme_tcp_h2ctermreq_reserved;
static int hf_nvme_tcp_h2ctermreq_data;

/* NVMe fabrics command */
static int hf_nvme_fabrics_cmd_cid;

/* NVMe fabrics command data*/
static int hf_nvme_fabrics_cmd_data;
static int hf_nvme_tcp_unknown_data;

static int hf_nvme_tcp_r2t_pdu;
static int hf_nvme_tcp_r2t_offset;
static int hf_nvme_tcp_r2t_length;
static int hf_nvme_tcp_r2t_resvd;

/* tracking Cmd and its respective CQE */
static int hf_nvme_tcp_cmd_pkt;
static int hf_nvme_fabrics_cmd_qid;

/* Data response fields */
static int hf_nvme_tcp_data_pdu;
static int hf_nvme_tcp_pdu_ttag;
static int hf_nvme_tcp_data_pdu_data_offset;
static int hf_nvme_tcp_data_pdu_data_length;
static int hf_nvme_tcp_data_pdu_data_resvd;

static int ett_nvme_tcp;

static unsigned
get_nvme_tcp_pdu_len(packet_info *pinfo _U_,
                     tvbuff_t *tvb,
                     int offset,
                     void* data _U_)
{
    return tvb_get_letohl(tvb, offset + PDU_LEN_OFFSET_FROM_HEADER);
}

static void
dissect_nvme_tcp_icreq(tvbuff_t *tvb,
                       packet_info *pinfo,
                       int offset,
                       proto_tree *tree)
{
    proto_item *tf;
    proto_item *icreq_tree;

    col_set_str(pinfo->cinfo, COL_INFO, "Initialize Connection Request");
    tf = proto_tree_add_item(tree, hf_nvme_tcp_icreq, tvb, offset, 8, ENC_NA);
    icreq_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_pfv, tvb, offset, 2,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_hpda, tvb, offset + 2, 1,
            ENC_NA);
    proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_digest, tvb, offset + 3,
            1, ENC_NA);
    proto_tree_add_item(icreq_tree, hf_nvme_tcp_icreq_maxr2t, tvb, offset + 4,
            4, ENC_LITTLE_ENDIAN);
}

static void
dissect_nvme_tcp_icresp(tvbuff_t *tvb,
                        packet_info *pinfo,
                        int offset,
                        proto_tree *tree)
{
    proto_item *tf;
    proto_item *icresp_tree;

    col_set_str(pinfo->cinfo, COL_INFO, "Initialize Connection Response");
    tf = proto_tree_add_item(tree, hf_nvme_tcp_icresp, tvb, offset, 8, ENC_NA);
    icresp_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_pfv, tvb, offset, 2,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_cpda, tvb, offset + 2,
            1, ENC_NA);
    proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_digest, tvb, offset + 3,
            1, ENC_NA);
    proto_tree_add_item(icresp_tree, hf_nvme_tcp_icresp_maxdata, tvb,
            offset + 4, 4, ENC_LITTLE_ENDIAN);
}

static struct nvme_tcp_cmd_ctx*
bind_cmd_to_qctx(packet_info *pinfo,
                 struct nvme_q_ctx *q_ctx,
                 uint16_t cmd_id)
{
    struct nvme_tcp_cmd_ctx *ctx;

    /* wireshark will dissect same packet multiple times
     * when display is refreshed*/
    if (!PINFO_FD_VISITED(pinfo)) {
        ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_cmd_ctx);
        nvme_add_cmd_to_pending_list(pinfo, q_ctx, &ctx->n_cmd_ctx, (void*) ctx,
                cmd_id);
    } else {
        /* Already visited this frame */
        ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_cmd_in_done_list(pinfo,
                q_ctx, cmd_id);
        /* if we have already visited frame but haven't found completion yet,
         * we won't find cmd in done q, so allocate a dummy ctx for doing
         * rest of the processing.
         */
        if (!ctx)
            ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_cmd_ctx);
    }

    return ctx;
}

static void
dissect_nvme_tcp_command(tvbuff_t *tvb,
                         packet_info *pinfo,
                         proto_tree *root_tree,
                         proto_tree *nvme_tcp_tree,
                         proto_item *nvme_tcp_ti,
                         struct nvme_tcp_q_ctx *queue, int offset,
                         uint32_t incapsuled_data_size,
                         uint32_t data_offset)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    uint16_t cmd_id;
    uint8_t opcode;
    const char *cmd_string;

    opcode = tvb_get_uint8(tvb, offset);
    cmd_id = tvb_get_uint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
    cmd_ctx = bind_cmd_to_qctx(pinfo, &queue->n_q_ctx, cmd_id);

    /* if record did not contain connect command we wont know qid,
     * so lets guess if this is an admin queue */
    if ((queue->n_q_ctx.qid == UINT16_MAX) && !nvme_is_io_queue_opcode(opcode))
        queue->n_q_ctx.qid = 0;

    if (opcode == NVME_FABRIC_OPC) {
        cmd_ctx->n_cmd_ctx.fabric = true;
        dissect_nvmeof_fabric_cmd(tvb, pinfo, nvme_tcp_tree, &queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, offset, false);
        if (cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype == NVME_FCTYPE_CONNECT)
            queue->n_q_ctx.qid = cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.cnct.qid;
        cmd_string = get_nvmeof_cmd_string(cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype);
        proto_item_append_text(nvme_tcp_ti,
                ", Fabrics Type: %s (0x%02x) Cmd ID: 0x%04x", cmd_string,
                cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype, cmd_id);
        if (incapsuled_data_size > 0) {
            proto_tree *data_tree;
            proto_item *ti;

            ti = proto_tree_add_item(nvme_tcp_tree, hf_nvme_fabrics_cmd_data, tvb, offset, incapsuled_data_size, ENC_NA);
            data_tree = proto_item_add_subtree(ti, ett_nvme_tcp);
            dissect_nvmeof_cmd_data(tvb, pinfo, data_tree, offset + NVME_FABRIC_CMD_SIZE + data_offset, &queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, incapsuled_data_size);
        }
        return;
    }

    /* In case of incapsuled nvme command tcp length is only a header */
    proto_item_set_len(nvme_tcp_ti, NVME_TCP_HEADER_SIZE);
    tvbuff_t *nvme_tvbuff;
    cmd_ctx->n_cmd_ctx.fabric = false;
    nvme_tvbuff = tvb_new_subset_remaining(tvb, NVME_TCP_HEADER_SIZE);
    cmd_string = nvme_get_opcode_string(opcode, queue->n_q_ctx.qid);
    dissect_nvme_cmd(nvme_tvbuff, pinfo, root_tree, &queue->n_q_ctx,
            &cmd_ctx->n_cmd_ctx);
    proto_item_append_text(nvme_tcp_ti,
            ", NVMe Opcode: %s (0x%02x) Cmd ID: 0x%04x", cmd_string, opcode,
            cmd_id);

    /* This is an inline write */
    if (incapsuled_data_size > 0) {
        tvbuff_t *nvme_data;

        nvme_data = tvb_new_subset_remaining(tvb, offset +
                NVME_CMD_SIZE + data_offset);
        dissect_nvme_data_response(nvme_data, pinfo, root_tree, &queue->n_q_ctx,
                &cmd_ctx->n_cmd_ctx, incapsuled_data_size, true);
    }
}

static uint32_t
dissect_nvme_tcp_data_pdu(tvbuff_t *tvb,
                          packet_info *pinfo,
                          int offset,
                          proto_tree *tree) {
    uint32_t data_length;
    proto_item *tf;
    proto_item *data_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe");

    tf = proto_tree_add_item(tree, hf_nvme_tcp_data_pdu, tvb, offset,
            NVME_TCP_DATA_PDU_SIZE - NVME_TCP_HEADER_SIZE, ENC_NA);
    data_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_cid, tvb, offset, 2,
            ENC_LITTLE_ENDIAN);

    proto_tree_add_item(data_tree, hf_nvme_tcp_pdu_ttag, tvb, offset + 2, 2,
            ENC_LITTLE_ENDIAN);

    proto_tree_add_item(data_tree, hf_nvme_tcp_data_pdu_data_offset, tvb,
            offset + 4, 4, ENC_LITTLE_ENDIAN);

    data_length = tvb_get_uint32(tvb, offset + 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_nvme_tcp_data_pdu_data_length, tvb,
            offset + 8, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(data_tree, hf_nvme_tcp_data_pdu_data_resvd, tvb,
            offset + 12, 4, ENC_NA);

    return data_length;
}

static void
dissect_nvme_tcp_c2h_data(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *root_tree,
                          proto_tree *nvme_tcp_tree,
                          proto_item *nvme_tcp_ti,
                          struct nvme_tcp_q_ctx *queue,
                          int offset,
                          uint32_t data_offset)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    uint32_t cmd_id;
    uint32_t data_length;
    tvbuff_t *nvme_data;
    const char *cmd_string;

    cmd_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    data_length = dissect_nvme_tcp_data_pdu(tvb, pinfo, offset, nvme_tcp_tree);

    /* This can identify our packet uniquely  */
    if (!PINFO_FD_VISITED(pinfo)) {
        cmd_ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_cmd_in_pending_list(
                &queue->n_q_ctx, cmd_id);
        if (!cmd_ctx) {
            proto_tree_add_item(root_tree, hf_nvme_tcp_unknown_data, tvb, offset + 16,
                                data_length, ENC_NA);
            return;
        }

        /* In order to later lookup for command context lets add this command
         * to data responses */
        cmd_ctx->n_cmd_ctx.data_tr_pkt_num[0] = pinfo->num;
        nvme_add_data_tr_pkt(&queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, cmd_id, pinfo->num);
    } else {
        cmd_ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_data_tr_pkt(&queue->n_q_ctx,
                                cmd_id, pinfo->num);
        if (!cmd_ctx) {
            proto_tree_add_item(root_tree, hf_nvme_tcp_unknown_data, tvb, offset + 16,
                                data_length, ENC_NA);
            return;
        }
    }

    nvme_publish_to_cmd_link(nvme_tcp_tree, tvb,
            hf_nvme_tcp_cmd_pkt, &cmd_ctx->n_cmd_ctx);

    if (cmd_ctx->n_cmd_ctx.fabric) {
        cmd_string = get_nvmeof_cmd_string(cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype);
        proto_item_append_text(nvme_tcp_ti,
                ", C2HData Fabrics Type: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
                cmd_string, cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype, cmd_id, data_length);
    } else {
        cmd_string = nvme_get_opcode_string(cmd_ctx->n_cmd_ctx.opcode,
                queue->n_q_ctx.qid);
        proto_item_append_text(nvme_tcp_ti,
                ", C2HData Opcode: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
                cmd_string, cmd_ctx->n_cmd_ctx.opcode, cmd_id, data_length);
    }

    nvme_data = tvb_new_subset_remaining(tvb, NVME_TCP_DATA_PDU_SIZE + data_offset);

    dissect_nvme_data_response(nvme_data, pinfo, root_tree, &queue->n_q_ctx,
            &cmd_ctx->n_cmd_ctx, data_length, false);

}

static void nvme_tcp_build_cmd_key(uint32_t *frame_num, uint32_t *cmd_id, wmem_tree_key_t *key)
{
    key[0].key = frame_num;
    key[0].length = 1;
    key[1].key = cmd_id;
    key[1].length = 1;
    key[2].key = NULL;
    key[2].length = 0;
}

static void nvme_tcp_add_data_request(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
        struct nvme_tcp_cmd_ctx *cmd_ctx, uint16_t cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    uint32_t cmd_id_key = cmd_id;

    nvme_tcp_build_cmd_key(&pinfo->num, &cmd_id_key, cmd_key);
    cmd_ctx->n_cmd_ctx.data_req_pkt_num = pinfo->num;
    cmd_ctx->n_cmd_ctx.data_tr_pkt_num[0] = 0;
    wmem_tree_insert32_array(q_ctx->data_requests, cmd_key, (void *)cmd_ctx);
}

static struct nvme_tcp_cmd_ctx* nvme_tcp_lookup_data_request(packet_info *pinfo,
        struct nvme_q_ctx *q_ctx,
        uint16_t cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    uint32_t cmd_id_key = cmd_id;

    nvme_tcp_build_cmd_key(&pinfo->num, &cmd_id_key, cmd_key);
    return (struct nvme_tcp_cmd_ctx*)wmem_tree_lookup32_array(q_ctx->data_requests, cmd_key);
}

static void
dissect_nvme_tcp_h2c_data(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *root_tree,
                          proto_tree *nvme_tcp_tree,
                          proto_item *nvme_tcp_ti,
                          struct nvme_tcp_q_ctx *queue,
                          int offset,
                          uint32_t data_offset)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    uint16_t cmd_id;
    uint32_t data_length;
    tvbuff_t *nvme_data;
    const char *cmd_string;

    cmd_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    data_length = dissect_nvme_tcp_data_pdu(tvb, pinfo, offset, nvme_tcp_tree);

    if (!PINFO_FD_VISITED(pinfo)) {
        cmd_ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_cmd_in_pending_list(
                &queue->n_q_ctx, cmd_id);
        if (!cmd_ctx) {
            proto_tree_add_item(root_tree, hf_nvme_tcp_unknown_data, tvb, offset + 16,
                        data_length, ENC_NA);
            return;
        }

        /* Fill this for "adding data request call,
         * this will be the key to fetch data request later */
        nvme_tcp_add_data_request(pinfo, &queue->n_q_ctx, cmd_ctx, cmd_id);
    } else {
        cmd_ctx = nvme_tcp_lookup_data_request(pinfo, &queue->n_q_ctx, cmd_id);
        if (!cmd_ctx) {
            proto_tree_add_item(root_tree, hf_nvme_tcp_unknown_data, tvb, offset + 16,
                        data_length, ENC_NA);
            return;
        }
    }

    nvme_publish_to_cmd_link(nvme_tcp_tree, tvb,
                hf_nvme_tcp_cmd_pkt, &cmd_ctx->n_cmd_ctx);

    /* fabrics commands should not have h2cdata*/
    if (cmd_ctx->n_cmd_ctx.fabric) {
        cmd_string = get_nvmeof_cmd_string(cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype);
        proto_item_append_text(nvme_tcp_ti,
                ", H2CData Fabrics Type: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
                cmd_string, cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype, cmd_id, data_length);
        proto_tree_add_item(root_tree, hf_nvme_tcp_unknown_data, tvb, offset + 16,
                    data_length, ENC_NA);
        return;
    }

    cmd_string = nvme_get_opcode_string(cmd_ctx->n_cmd_ctx.opcode,
            queue->n_q_ctx.qid);
    proto_item_append_text(nvme_tcp_ti,
            ", H2CData Opcode: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
            cmd_string, cmd_ctx->n_cmd_ctx.opcode, cmd_id, data_length);

    nvme_data = tvb_new_subset_remaining(tvb, NVME_TCP_DATA_PDU_SIZE + data_offset);
    dissect_nvme_data_response(nvme_data, pinfo, root_tree, &queue->n_q_ctx,
            &cmd_ctx->n_cmd_ctx, data_length, false);
}

static void
dissect_nvme_tcp_h2ctermreq(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, uint32_t packet_len, int offset)
{
    proto_item *tf;
    proto_item *h2ctermreq_tree;
    uint16_t fes;

    col_set_str(pinfo->cinfo, COL_INFO,
                "Host to Controller Termination Request");
    tf = proto_tree_add_item(tree, hf_nvme_tcp_h2ctermreq,
                             tvb, offset, 8, ENC_NA);
    h2ctermreq_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(h2ctermreq_tree, hf_nvme_tcp_h2ctermreq_fes,
                        tvb, offset + 8, 2, ENC_LITTLE_ENDIAN);
    fes = tvb_get_uint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
    switch (fes) {
    case NVME_TCP_FES_INVALID_PDU_HDR:
        proto_tree_add_item(h2ctermreq_tree, hf_nvme_tcp_h2ctermreq_phfo,
                            tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_TCP_FES_HDR_DIGEST_ERR:
        proto_tree_add_item(h2ctermreq_tree, hf_nvme_tcp_h2ctermreq_phd,
                            tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_TCP_FES_UNSUPPORTED_PARAM:
        proto_tree_add_item(h2ctermreq_tree, hf_nvme_tcp_h2ctermreq_upfo,
                            tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
        break;
    default:
        proto_tree_add_item(h2ctermreq_tree, hf_nvme_tcp_h2ctermreq_reserved,
                            tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
        break;
    }
    proto_tree_add_item(h2ctermreq_tree, hf_nvme_tcp_h2ctermreq_data,
                        tvb, offset + 24, packet_len - 24, ENC_NA);
}

static void
dissect_nvme_tcp_c2htermreq(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, uint32_t packet_len, int offset)
{
    proto_item *tf;
    proto_item *c2htermreq_tree;
    uint16_t fes;

    col_set_str(pinfo->cinfo, COL_INFO,
                "Controller to Host Termination Request");
    tf = proto_tree_add_item(tree, hf_nvme_tcp_c2htermreq,
                             tvb, offset, 8, ENC_NA);
    c2htermreq_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(tree, hf_nvme_tcp_c2htermreq_fes, tvb, offset + 8, 2,
                        ENC_LITTLE_ENDIAN);
    fes = tvb_get_uint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
    switch (fes) {
    case NVME_TCP_FES_INVALID_PDU_HDR:
        proto_tree_add_item(c2htermreq_tree, hf_nvme_tcp_c2htermreq_phfo,
                            tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_TCP_FES_HDR_DIGEST_ERR:
        proto_tree_add_item(c2htermreq_tree, hf_nvme_tcp_c2htermreq_phd,
                            tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
        break;
    case NVME_TCP_FES_UNSUPPORTED_PARAM:
        proto_tree_add_item(c2htermreq_tree, hf_nvme_tcp_c2htermreq_upfo,
                            tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
        break;
    default:
        proto_tree_add_item(c2htermreq_tree, hf_nvme_tcp_c2htermreq_reserved,
                            tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
        break;
    }
    proto_tree_add_item(c2htermreq_tree, hf_nvme_tcp_c2htermreq_data,
                        tvb, offset + 24, packet_len - 24, ENC_NA);
}

static void
dissect_nvme_tcp_cqe(tvbuff_t *tvb,
                     packet_info *pinfo,
                     proto_tree *root_tree,
                     proto_tree *nvme_tree,
                     proto_item *ti,
                     struct nvme_tcp_q_ctx *queue,
                     int offset)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    uint16_t cmd_id;
    const char *cmd_string;

    cmd_id = tvb_get_uint16(tvb, offset + 12, ENC_LITTLE_ENDIAN);

    /* wireshark will dissect packet several times when display is refreshed
     * we need to track state changes only once */
    if (!PINFO_FD_VISITED(pinfo)) {
        cmd_ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_cmd_in_pending_list(
                &queue->n_q_ctx, cmd_id);
        if (!cmd_ctx || cmd_ctx->n_cmd_ctx.cqe_pkt_num) {
            proto_tree_add_item(nvme_tree, hf_nvme_tcp_unknown_data, tvb, offset,
                                NVME_FABRIC_CQE_SIZE, ENC_NA);
            return;
        }

        cmd_ctx->n_cmd_ctx.cqe_pkt_num = pinfo->num;
        nvme_add_cmd_cqe_to_done_list(&queue->n_q_ctx, &cmd_ctx->n_cmd_ctx,
                cmd_id);

    } else {
        cmd_ctx = (struct nvme_tcp_cmd_ctx *) nvme_lookup_cmd_in_done_list(pinfo,
                                                                           &queue->n_q_ctx, cmd_id);
        if (!cmd_ctx) {
            proto_tree_add_item(nvme_tree, hf_nvme_tcp_unknown_data, tvb, offset,
                                NVME_FABRIC_CQE_SIZE, ENC_NA);
            return;
        }
    }

    nvme_update_cmd_end_info(pinfo, &cmd_ctx->n_cmd_ctx);

    if (cmd_ctx->n_cmd_ctx.fabric) {
        cmd_string = get_nvmeof_cmd_string(cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype);
        proto_item_append_text(ti,
                ", Cqe Fabrics Cmd: %s (0x%02x) Cmd ID: 0x%04x", cmd_string,
               cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype , cmd_id);

        dissect_nvmeof_fabric_cqe(tvb, pinfo, nvme_tree, &cmd_ctx->n_cmd_ctx, offset);
    } else {
        tvbuff_t *nvme_tvb;
        proto_item_set_len(ti, NVME_TCP_HEADER_SIZE);
        cmd_string = nvme_get_opcode_string(cmd_ctx->n_cmd_ctx.opcode,
                queue->n_q_ctx.qid);

        proto_item_append_text(ti, ", Cqe NVMe Cmd: %s (0x%02x) Cmd ID: 0x%04x",
                cmd_string, cmd_ctx->n_cmd_ctx.opcode, cmd_id);
        /* get incapsuled nvme command */
        nvme_tvb = tvb_new_subset_remaining(tvb, NVME_TCP_HEADER_SIZE);
        dissect_nvme_cqe(nvme_tvb, pinfo, root_tree, &queue->n_q_ctx, &cmd_ctx->n_cmd_ctx);
    }
}

static void
dissect_nvme_tcp_r2t(tvbuff_t *tvb,
                     packet_info *pinfo,
                     int offset,
                     proto_tree *tree)
{
    proto_item *tf;
    proto_item *r2t_tree;

    tf = proto_tree_add_item(tree, hf_nvme_tcp_r2t_pdu, tvb, offset, -1,
            ENC_NA);
    r2t_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "Ready To Transfer");

    proto_tree_add_item(r2t_tree, hf_nvme_fabrics_cmd_cid, tvb, offset, 2,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(r2t_tree, hf_nvme_tcp_pdu_ttag, tvb, offset + 2, 2,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(r2t_tree, hf_nvme_tcp_r2t_offset, tvb, offset + 4, 4,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(r2t_tree, hf_nvme_tcp_r2t_length, tvb, offset + 8, 4,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(r2t_tree, hf_nvme_tcp_r2t_resvd, tvb, offset + 12, 4,
            ENC_NA);
}

static int
dissect_nvme_tcp_pdu(tvbuff_t *tvb,
                     packet_info *pinfo,
                     proto_tree *tree,
                     void* data _U_)
{
    conversation_t *conversation;
    struct nvme_tcp_q_ctx *q_ctx;
    proto_item *ti;
    int offset = 0;
    int nvme_tcp_pdu_offset;
    proto_tree *nvme_tcp_tree;
    unsigned packet_type;
    uint8_t hlen, pdo;
    uint8_t pdu_flags;
    uint32_t plen;
    uint32_t incapsuled_data_size;
    uint32_t pdu_data_offset = 0;

    conversation = find_or_create_conversation(pinfo);
    q_ctx = (struct nvme_tcp_q_ctx *)
            conversation_get_proto_data(conversation, proto_nvme_tcp);

    if (!q_ctx) {
        q_ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_q_ctx);
        q_ctx->n_q_ctx.pending_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.done_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_requests = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_responses = wmem_tree_new(wmem_file_scope());
        /* Initially set to non-0 so that by default queues are io queues
         * this is required to be able to dissect correctly even
         * if we miss connect command*/
        q_ctx->n_q_ctx.qid = UINT16_MAX;
        conversation_add_proto_data(conversation, proto_nvme_tcp, q_ctx);
    }

    ti = proto_tree_add_item(tree, proto_nvme_tcp, tvb, 0, -1, ENC_NA);
    nvme_tcp_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

    if (q_ctx->n_q_ctx.qid != UINT16_MAX)
        nvme_publish_qid(nvme_tcp_tree, hf_nvme_fabrics_cmd_qid,
                q_ctx->n_q_ctx.qid);

    packet_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_type, tvb, offset, 1,
            ENC_NA);

    pdu_flags = tvb_get_uint8(tvb, offset + 1);
    proto_tree_add_bitmask_value(nvme_tcp_tree, tvb, 0, hf_nvme_tcp_flags,
            ett_nvme_tcp, nvme_tcp_pdu_flags, (uint64_t)pdu_flags);

    hlen = tvb_get_int8(tvb, offset + 2);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_hlen, tvb, offset + 2, 1,
            ENC_NA);

    pdo = tvb_get_int8(tvb, offset + 3);
    proto_tree_add_uint(nvme_tcp_tree, hf_nvme_tcp_pdo, tvb, offset + 3, 1,
            pdo);
    plen = tvb_get_letohl(tvb, offset + 4);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_plen, tvb, offset + 4, 4,
            ENC_LITTLE_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);

    if (pdu_flags & NVME_TCP_F_HDGST) {
        unsigned hdgst_flags = PROTO_CHECKSUM_NO_FLAGS;
        uint32_t crc = 0;

        if (nvme_tcp_check_hdgst) {
            hdgst_flags = PROTO_CHECKSUM_VERIFY;
            crc = ~crc32c_tvb_offset_calculate(tvb, 0, hlen, ~0);
        }
        proto_tree_add_checksum(nvme_tcp_tree, tvb, hlen, hf_nvme_tcp_hdgst,
                    hf_nvme_tcp_hdgst_status, NULL, pinfo,
                    crc, ENC_NA, hdgst_flags);
        pdu_data_offset = NVME_TCP_DIGEST_LENGTH;
    }

    nvme_tcp_pdu_offset = offset + NVME_TCP_HEADER_SIZE;
    incapsuled_data_size = plen - hlen - pdu_data_offset;

    /* check for overflow (invalid packet)*/
    if (incapsuled_data_size > tvb_reported_length(tvb)) {
        proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_unknown_data,
                               tvb, NVME_TCP_HEADER_SIZE, -1, ENC_NA);
        return tvb_reported_length(tvb);
    }

    if (pdu_flags & NVME_TCP_F_DDGST) {
        unsigned ddgst_flags = PROTO_CHECKSUM_NO_FLAGS;
        uint32_t crc = 0;

        /* Check that data has enough space (invalid packet) */
        if (incapsuled_data_size <= NVME_TCP_DIGEST_LENGTH) {
            proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_unknown_data,
                                           tvb, NVME_TCP_HEADER_SIZE, -1, ENC_NA);
            return tvb_reported_length(tvb);
        }

        incapsuled_data_size -= NVME_TCP_DIGEST_LENGTH;
        if (nvme_tcp_check_ddgst) {
            ddgst_flags = PROTO_CHECKSUM_VERIFY;
            crc = ~crc32c_tvb_offset_calculate(tvb, pdo,
                                               incapsuled_data_size, ~0);
        }
        proto_tree_add_checksum(nvme_tcp_tree, tvb,
                         plen - NVME_TCP_DIGEST_LENGTH, hf_nvme_tcp_ddgst,
                         hf_nvme_tcp_ddgst_status, NULL, pinfo,
                         crc, ENC_NA, ddgst_flags);
    }

    switch (packet_type) {
    case nvme_tcp_icreq:
        dissect_nvme_tcp_icreq(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree);
        proto_item_set_len(ti, hlen);
        break;
    case nvme_tcp_icresp:
        dissect_nvme_tcp_icresp(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree);
        proto_item_set_len(ti, hlen);
        break;
    case nvme_tcp_cmd:
        dissect_nvme_tcp_command(tvb, pinfo, tree, nvme_tcp_tree, ti, q_ctx,
                nvme_tcp_pdu_offset, incapsuled_data_size, pdu_data_offset);
        break;
    case nvme_tcp_rsp:
        dissect_nvme_tcp_cqe(tvb, pinfo, tree, nvme_tcp_tree, ti, q_ctx,
                nvme_tcp_pdu_offset);
        proto_item_set_len(ti, NVME_TCP_HEADER_SIZE);
        break;
    case nvme_tcp_c2h_data:
        dissect_nvme_tcp_c2h_data(tvb, pinfo, tree, nvme_tcp_tree, ti, q_ctx,
                nvme_tcp_pdu_offset, pdu_data_offset);
        proto_item_set_len(ti, NVME_TCP_DATA_PDU_SIZE);
        break;
    case nvme_tcp_h2c_data:
        dissect_nvme_tcp_h2c_data(tvb, pinfo, tree, nvme_tcp_tree, ti, q_ctx,
                nvme_tcp_pdu_offset, pdu_data_offset);
        proto_item_set_len(ti, NVME_TCP_DATA_PDU_SIZE);
        break;
    case nvme_tcp_r2t:
        dissect_nvme_tcp_r2t(tvb, pinfo, nvme_tcp_pdu_offset, nvme_tcp_tree);
        break;
    case nvme_tcp_h2c_term:
        dissect_nvme_tcp_h2ctermreq(tvb, pinfo, tree, plen, offset);
        break;
    case nvme_tcp_c2h_term:
        dissect_nvme_tcp_c2htermreq(tvb, pinfo, tree, plen, offset);
        break;
    default:
        proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_unknown_data, tvb,
                offset, plen, ENC_NA);
        break;
    }

    return tvb_reported_length(tvb);
}

static int
dissect_nvme_tcp(tvbuff_t *tvb,
                 packet_info *pinfo,
                 proto_tree *tree,
                 void *data)
{
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);
    tcp_dissect_pdus(tvb, pinfo, tree, true, NVME_TCP_HEADER_SIZE,
            get_nvme_tcp_pdu_len, dissect_nvme_tcp_pdu, data);

    return tvb_reported_length(tvb);
}

void proto_register_nvme_tcp(void) {

    static hf_register_info hf[] = {
       { &hf_nvme_tcp_type,
           { "Pdu Type", "nvme-tcp.type",
             FT_UINT8, BASE_DEC, VALS(nvme_tcp_pdu_type_vals),
             0x0, NULL, HFILL } },
       { &hf_nvme_tcp_flags,
           { "Pdu Specific Flags", "nvme-tcp.flags",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_pdu_flags_hdgst,
           { "PDU Header Digest", "nvme-tcp.flags.pdu.hdgst",
             FT_BOOLEAN, 8, TFS(&tfs_set_notset),
             NVME_TCP_F_HDGST, NULL, HFILL} },
       { &hf_pdu_flags_ddgst,
           { "PDU Data Digest", "nvme-tcp.flags.pdu.ddgst",
             FT_BOOLEAN, 8, TFS(&tfs_set_notset),
             NVME_TCP_F_DDGST, NULL, HFILL} },
       { &hf_pdu_flags_data_last,
           { "PDU Data Last", "nvme-tcp.flags.pdu.data_last",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset),
              NVME_TCP_F_DATA_LAST, NULL, HFILL} },
       { &hf_pdu_flags_data_success,
          { "PDU Data Success", "nvme-tcp.flags.pdu.data_success",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset),
            NVME_TCP_F_DATA_SUCCESS, NULL, HFILL} },
       { &hf_nvme_tcp_hdgst,
           { "PDU Header Digest", "nvme-tcp.hdgst",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_nvme_tcp_ddgst,
           { "PDU Data Digest", "nvme-tcp.ddgst",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_nvme_tcp_hdgst_status,
          { "Header Digest Status",    "nvme-tcp.hdgst.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals),
            0x0, NULL, HFILL }},
        { &hf_nvme_tcp_ddgst_status,
          { "Data Digest Status",    "nvme-tcp.ddgst.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals),
            0x0, NULL, HFILL }},
       { &hf_nvme_tcp_hlen,
           { "Pdu Header Length", "nvme-tcp.hlen",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_pdo,
           { "Pdu Data Offset", "nvme-tcp.pdo",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_plen,
           { "Packet Length", "nvme-tcp.plen",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq,
           { "ICReq", "nvme-tcp.icreq",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq_pfv,
           { "Pdu Version Format", "nvme-tcp.icreq.pfv",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq_maxr2t,
           { "Maximum r2ts per request", "nvme-tcp.icreq.maxr2t",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq_hpda,
           { "Host Pdu data alignment", "nvme-tcp.icreq.hpda",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icreq_digest,
           { "Digest Types Enabled", "nvme-tcp.icreq.digest",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp,
           { "ICResp", "nvme-tcp.icresp",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp_pfv,
           { "Pdu Version Format", "nvme-tcp.icresp.pfv",
             FT_UINT16, BASE_DEC, NULL, 0x0,
             NULL, HFILL } },
       { &hf_nvme_tcp_icresp_cpda,
           { "Controller Pdu data alignment", "nvme-tcp.icresp.cpda",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp_digest,
           { "Digest types enabled", "nvme-tcp.icresp.digest",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp_maxdata,
           { "Maximum data capsules per r2t supported", "nvme-tcp.icresp.maxdata",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       /* NVMe tcp c2h/h2c termreq fields */
       { &hf_nvme_tcp_c2htermreq,
           { "C2HTermReq", "nvme-tcp.c2htermreq",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_fes,
           { "Fatal error status", "nvme-tcp.c2htermreq.fes",
             FT_UINT16, BASE_HEX, VALS(nvme_tcp_termreq_fes),
             0x0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_phfo,
           { "PDU header field offset", "nvme-tcp.c2htermreq.phfo",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_phd,
           { "PDU header digest", "nvme-tcp.c2htermreq.phd",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_upfo,
           { "Unsupported parameter field offset", "nvme-tcp.c2htermreq.upfo",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_reserved,
           { "Reserved", "nvme-tcp.c2htermreq.reserved",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_data,
           { "Terminated PDU header", "nvme-tcp.c2htermreq.data",
             FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq,
           { "H2CTermReq", "nvme-tcp.h2ctermreq",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_fes,
           { "Fatal error status", "nvme-tcp.h2ctermreq.fes",
             FT_UINT16, BASE_HEX, VALS(nvme_tcp_termreq_fes),
             0x0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_phfo,
           { "PDU header field offset", "nvme-tcp.h2ctermreq.phfo",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_phd,
           { "PDU header digest", "nvme-tcp.h2ctermreq.phd",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_upfo,
           { "Unsupported parameter field offset", "nvme-tcp.h2ctermreq.upfo",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_reserved,
           { "Reserved", "nvme-tcp.h2ctermreq.reserved",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_data,
           { "Terminated PDU header", "nvme-tcp.h2ctermreq.data",
             FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_cid,
           { "Command ID", "nvme-tcp.cmd.cid",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_unknown_data,
           { "Unknown Data", "nvme-tcp.unknown_data",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       /* NVMe command data */
       { &hf_nvme_fabrics_cmd_data,
           { "Data", "nvme-tcp.cmd.data",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_cmd_pkt,
            { "Cmd in", "nvme-tcp.cmd_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cmd for this transaction is in this frame", HFILL } },
       { &hf_nvme_fabrics_cmd_qid,
           { "Cmd Qid", "nvme-tcp.cmd.qid",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             "Qid on which command is issued", HFILL } },
      /* NVMe TCP data response */
      { &hf_nvme_tcp_data_pdu,
           { "NVMe/TCP Data PDU", "nvme-tcp.data",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_nvme_tcp_pdu_ttag,
           { "Transfer Tag", "nvme-tcp.ttag",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             "Transfer tag (controller generated)", HFILL } },
      { &hf_nvme_tcp_data_pdu_data_offset,
           { "Data Offset", "nvme-tcp.data.offset",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             "Offset from the start of the command data", HFILL } },
      { &hf_nvme_tcp_data_pdu_data_length,
           { "Data Length", "nvme-tcp.data.length",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             "Length of the data stream", HFILL } },
      { &hf_nvme_tcp_data_pdu_data_resvd,
           { "Reserved", "nvme-tcp.data.rsvd",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      /* NVMEe TCP R2T pdu */
      { &hf_nvme_tcp_r2t_pdu,
           { "R2T", "nvme-tcp.r2t",
              FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_nvme_tcp_r2t_offset,
           { "R2T Offset", "nvme-tcp.r2t.offset",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             "Offset from the start of the command data", HFILL } },
      { &hf_nvme_tcp_r2t_length,
           { "R2T Length", "nvme-tcp.r2t.length",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             "Length of the data stream", HFILL } },
      { &hf_nvme_tcp_r2t_resvd,
           { "Reserved", "nvme-tcp.r2t.rsvd",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } }
    };

    static int *ett[] = {
        &ett_nvme_tcp
    };

    proto_nvme_tcp = proto_register_protocol("NVM Express Fabrics TCP",
            NVME_FABRICS_TCP, "nvme-tcp");

    proto_register_field_array(proto_nvme_tcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    nvmet_tcp_handle = register_dissector("nvme-tcp", dissect_nvme_tcp,
            proto_nvme_tcp);
    nvmet_tls_handle = register_dissector_with_description("nvme-tls",
            "NVMe-over-TCP with TLS", dissect_nvme_tcp, proto_nvme_tcp);
}

void proto_reg_handoff_nvme_tcp(void) {
    module_t *nvme_tcp_module;
    nvme_tcp_module = prefs_register_protocol(proto_nvme_tcp, NULL);
    range_convert_str(wmem_epan_scope(), &gPORT_RANGE, NVME_TCP_PORT_RANGE,
            MAX_TCP_PORT);
    prefs_register_range_preference(nvme_tcp_module,
                                    "subsystem_ports",
                                    "Subsystem Ports Range",
                                    "Range of NVMe Subsystem ports"
                                    "(default " NVME_TCP_PORT_RANGE ")",
                                    &gPORT_RANGE,
                                    MAX_TCP_PORT);
    prefs_register_bool_preference(nvme_tcp_module, "check_hdgst",
        "Validate PDU header digest",
        "Whether to validate the PDU header digest or not.",
        &nvme_tcp_check_hdgst);
    prefs_register_bool_preference(nvme_tcp_module, "check_ddgst",
            "Validate PDU data digest",
            "Whether to validate the PDU data digest or not.",
            &nvme_tcp_check_ddgst);
    ssl_dissector_add(0, nvmet_tls_handle);
    dissector_add_uint_range("tcp.port", gPORT_RANGE, nvmet_tcp_handle);
    dissector_add_uint_range("tls.port", gPORT_RANGE, nvmet_tls_handle);
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
