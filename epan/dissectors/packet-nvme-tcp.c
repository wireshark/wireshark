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
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>
#include "packet-tcp.h"
#include "packet-nvme.h"

#include "packet-tls.h"

static int proto_nvme_tcp;
static dissector_handle_t nvmet_tcp_handle;
static dissector_handle_t nvmet_tls_handle;

#define NVME_TCP_PORT_RANGE    "4420,8009" /* IANA registered */

#define NVME_TCP_HEADER_SIZE 8
#define PDU_LEN_OFFSET_FROM_HEADER 4
/* pinfo->pool key: an NVMe/TCP PDU was dissected in this frame. */
#define NVME_TCP_PDU_IN_FRAME 0
/* file-scope key: the queue id at the start of the PDU at this offset in the
 * frame, plus 1; above any command id, which is the other key kind. */
#define NVME_TCP_PDU_QID_BASE 0x10000
static range_t *gPORT_RANGE;
static bool nvme_tcp_check_hdgst;
static bool nvme_tcp_check_ddgst;
#define NVME_TCP_DATA_PDU_SIZE 24
/* NVMe/TCP 1.3 Figure 30: a Command Capsule header is a fixed 72 bytes (48h) --
 * the 8-byte common header and the 64-byte command capsule SQE. */
#define NVME_TCP_CMD_PDU_SIZE (NVME_TCP_HEADER_SIZE + NVME_CMD_SIZE)
/* H2CTermReq/C2HTermReq header: the 8-byte common header, FES at offset 8,
 * FEI at offset 10 and reserved bytes out to offset 24, where the terminated
 * PDU's header starts. */
#define NVME_TCP_TERMREQ_PDU_SIZE 24

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
    nvme_tcp_kdreq = 0xa,
    nvme_tcp_kdresp = 0xb,
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
    { nvme_tcp_kdreq, "Kickstart Discovery Request" },
    { nvme_tcp_kdresp, "Kickstart Discovery Response" },
    { 0, NULL }
};

/* H2CTermReq (Figure 28), detected by the host. */
static const value_string nvme_tcp_h2ctermreq_fes[] = {
    {0x0, "Reserved"                        },
    {0x1, "Invalid PDU Header Field"        },
    {0x2, "PDU Sequence Error"              },
    {0x3, "Header Digest Error"             },
    {0x4, "Data Transfer Out of Range"      },
    {0x5, "R2T Limit Exceeded"              },
    {0x6, "Unsupported Parameter"           },
    {0,   NULL                              },
};

/* C2HTermReq (Figure 29), detected by the controller. */
static const value_string nvme_tcp_c2htermreq_fes[] = {
    {0x0, "Reserved"                        },
    {0x1, "Invalid PDU Header Field"        },
    {0x2, "PDU Sequence Error"              },
    {0x3, "Header Digest Error"             },
    {0x4, "Data Transfer Out of Range"      },
    {0x5, "Data Transfer Limit Exceeded"    },
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


#define NVME_FABRIC_CQE_SIZE NVME_CQE_SIZE
#define NVME_TCP_DIGEST_LENGTH  4

struct nvme_tcp_q_ctx {
    struct nvme_q_ctx n_q_ctx;
    /* H2CData requests, keyed [frame][cid]; kept apart from
     * n_q_ctx.data_requests (keyed SGL descriptors, other key shape) */
    wmem_tree_t *h2c_requests;
    /* Frame -> the queue id learned in it, plus 1, from a Connect or the
     * guess made without one; filled on the first pass.  n_q_ctx.qid is
     * reset from it for every PDU, so a frame decodes under the same queue
     * type on every pass. */
    wmem_tree_t *qid_by_frame;
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

static expert_field ei_nvme_tcp_termreq_short;

static unsigned
get_nvme_tcp_pdu_len(packet_info *pinfo _U_,
                     tvbuff_t *tvb,
                     int offset,
                     void* data _U_)
{
    uint32_t plen = tvb_get_letohl(tvb, offset + PDU_LEN_OFFSET_FROM_HEADER);

    /* PLEN counts the 8-byte common header (NVMe/TCP 1.3 Figure 25), so 0 is
     * malformed, but tcp_dissect_pdus() reads 0 as "one more segment" and
     * would hold every later segment in a reassembly that never completes.
     * Hand it 1 instead, which takes the bounds error that PLEN 1-7 get. */
    return plen ? plen : 1;
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

    /* Revisits find the command context recorded on the first pass. */
    if (!PINFO_FD_VISITED(pinfo)) {
        ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_cmd_ctx);
        nvme_add_cmd_to_pending_list(pinfo, q_ctx, &ctx->n_cmd_ctx, (void*) ctx,
                cmd_id);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_tcp, cmd_id, ctx);
    } else {
        ctx = (struct nvme_tcp_cmd_ctx*) p_get_proto_data(wmem_file_scope(),
                pinfo, proto_nvme_tcp, cmd_id);
        /* Only when the first pass never got this far. */
        if (!ctx)
            ctx = wmem_new0(pinfo->pool, struct nvme_tcp_cmd_ctx);
    }

    return ctx;
}

/* The queue id in effect after frame's own PDUs, or UINT16_MAX (unknown,
 * read as I/O) when none was learned by then. */
static uint16_t
nvme_tcp_qid_at(struct nvme_tcp_q_ctx *queue, uint32_t frame)
{
    void *qid = wmem_tree_lookup32_le(queue->qid_by_frame, frame);

    return qid ? (uint16_t)(GPOINTER_TO_UINT(qid) - 1) : UINT16_MAX;
}

static void
nvme_tcp_learn_qid(packet_info *pinfo, struct nvme_tcp_q_ctx *queue,
                   uint16_t qid)
{
    if (!PINFO_FD_VISITED(pinfo))
        wmem_tree_insert32(queue->qid_by_frame, pinfo->num,
                           GUINT_TO_POINTER((unsigned)qid + 1));
    queue->n_q_ctx.qid = qid;
}

/* Geometry of a data-carrying PDU (NVMe/TCP 1.3 Figure 25). PDO places the
 * data inside this PDU; the Data Offset field places it in the command buffer. */
struct nvme_tcp_pdu_geom {
    uint8_t  hlen;       /* header length, Figure 25 byte 2 */
    uint8_t  pdo;        /* PDU Data Offset, Figure 25 byte 3 */
    uint32_t plen;       /* total PDU length, Figure 25 bytes 7:4 */
    unsigned hdgst_len;  /* 0, or the header digest this PDU carries */
    unsigned ddgst_len;  /* 0, or the data digest this PDU carries */
    /* Data span from nvme_tcp_resolve_data_span(), shared by the digest
     * check and the handler. */
    bool     data_span_known;
    unsigned data_start;
    uint32_t data_length;
};

static void
dissect_nvme_tcp_command(tvbuff_t *tvb,
                         packet_info *pinfo,
                         proto_tree *root_tree,
                         proto_tree *nvme_tcp_tree,
                         proto_item *nvme_tcp_ti,
                         struct nvme_tcp_q_ctx *queue, int offset,
                         uint32_t incapsuled_data_size,
                         const struct nvme_tcp_pdu_geom *geom)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    uint16_t cmd_id;
    uint8_t opcode;
    const char *cmd_string;
    /* In-capsule data is padded like transfer data (Figure 30); without a
     * resolved span it starts after the SQE and header digest. */
    bool span_known = geom->data_span_known;
    unsigned data_start = span_known ? geom->data_start
            : (unsigned)(offset + NVME_CMD_SIZE + geom->hdgst_len);
    uint32_t data_len = span_known ? geom->data_length : incapsuled_data_size;

    opcode = tvb_get_uint8(tvb, offset);
    cmd_id = tvb_get_uint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
    cmd_ctx = bind_cmd_to_qctx(pinfo, &queue->n_q_ctx, cmd_id);

    /* if record did not contain connect command we won't know qid,
     * so let's guess if this is an admin queue */
    if ((queue->n_q_ctx.qid == UINT16_MAX) &&
        nvme_cmd_implies_admin_queue(tvb, offset))
        nvme_tcp_learn_qid(pinfo, queue, 0);

    if (opcode == NVME_FABRIC_OPC) {
        cmd_ctx->n_cmd_ctx.fabric = true;
        dissect_nvmeof_fabric_cmd(tvb, pinfo, nvme_tcp_tree, &queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, offset, false);
        if (cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype == NVME_FCTYPE_CONNECT)
            nvme_tcp_learn_qid(pinfo, queue,
                               cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.cnct.qid);
        cmd_string = get_nvmeof_cmd_string(cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype);
        proto_item_append_text(nvme_tcp_ti,
                ", Fabrics Type: %s (0x%02x) Cmd ID: 0x%04x", cmd_string,
                cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype, cmd_id);
        if (incapsuled_data_size > 0) {
            proto_tree *data_tree;
            proto_item *ti;

            ti = proto_tree_add_item(nvme_tcp_tree, hf_nvme_fabrics_cmd_data, tvb, data_start, data_len, ENC_NA);
            data_tree = proto_item_add_subtree(ti, ett_nvme_tcp);
            dissect_nvmeof_cmd_data(tvb, pinfo, data_tree, data_start, &queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, data_len);
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

        nvme_data = span_known
                ? tvb_new_subset_length(tvb, data_start, data_len)
                : tvb_new_subset_remaining(tvb, data_start);
        /* In-capsule write data travels host to controller, so it is the
         * host's bytes and not the controller describing itself.  No origin
         * is claimed for it either: this path keeps no transfer offset. */
        dissect_nvme_data_response(nvme_data, pinfo, root_tree, &queue->n_q_ctx,
                &cmd_ctx->n_cmd_ctx, data_len, true,
                NVME_DATA_DIR_HOST_TO_CONTROLLER, NVME_DATA_ORIGIN_NONE);
    }
}

static uint32_t
dissect_nvme_tcp_data_pdu(tvbuff_t *tvb,
                          packet_info *pinfo,
                          int offset,
                          proto_tree *tree,
                          uint32_t *datao) {
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

    /* Data Offset: this data's place in the command buffer (Figures 32/33). */
    proto_tree_add_item_ret_uint(data_tree, hf_nvme_tcp_data_pdu_data_offset, tvb,
            offset + 4, 4, ENC_LITTLE_ENDIAN, datao);

    data_length = tvb_get_uint32(tvb, offset + 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_nvme_tcp_data_pdu_data_length, tvb,
            offset + 8, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(data_tree, hf_nvme_tcp_data_pdu_data_resvd, tvb,
            offset + 12, 4, ENC_NA);

    return data_length;
}

/* Data start of a PDU whose header describes a usable span, else false.
 * HLEN is fixed per type (Figures 30, 32, 33); PDO is dword aligned
 * (Figures 26/27). */
static bool
nvme_tcp_data_span(const struct nvme_tcp_pdu_geom *geom,
                   uint8_t expected_hlen, uint32_t data_length,
                   unsigned *data_start)
{
    unsigned first = (unsigned)geom->hlen + geom->hdgst_len;

    if (geom->hlen != expected_hlen)
        return false;
    /* 4 here is a dword, not a digest: the alignment the padding satisfies is
     * counted in dwords, so a conformant offset is a multiple of four. */
    if (geom->pdo < first || (geom->pdo % 4) != 0)
        return false;
    if (data_length == 0)
        return false;
    /* The data and any data digest have to fit inside the length the PDU
     * declares; the caller checks the bytes are captured. */
    if ((uint64_t)geom->pdo + data_length + geom->ddgst_len > geom->plen)
        return false;

    *data_start = geom->pdo;
    return true;
}

/* Resolve the data span once, before the data digest reads it. Data
 * transfers state their data length; a command capsule's data runs to the
 * data digest (Figure 30). A span that is not fully captured is not
 * resolved. */
static void
nvme_tcp_resolve_data_span(tvbuff_t *tvb, int pdu_offset, unsigned packet_type,
                           struct nvme_tcp_pdu_geom *geom)
{
    uint32_t data_length;
    unsigned data_start;
    uint8_t expected_hlen;

    geom->data_span_known = false;
    geom->data_start      = 0;
    geom->data_length     = 0;

    switch (packet_type) {
    case nvme_tcp_h2c_data:
    case nvme_tcp_c2h_data:
        expected_hlen = NVME_TCP_DATA_PDU_SIZE;
        if (!tvb_bytes_exist(tvb, pdu_offset + 8, 4))
            return;
        data_length = tvb_get_uint32(tvb, pdu_offset + 8, ENC_LITTLE_ENDIAN);
        break;
    case nvme_tcp_cmd:
        expected_hlen = NVME_TCP_CMD_PDU_SIZE;
        if ((uint64_t)geom->pdo + geom->ddgst_len >= geom->plen)
            return;
        data_length = geom->plen - geom->ddgst_len - geom->pdo;
        break;
    default:
        return;
    }

    if (!nvme_tcp_data_span(geom, expected_hlen, data_length, &data_start))
        return;
    if (!tvb_bytes_exist(tvb, data_start, data_length))
        return;

    geom->data_span_known = true;
    geom->data_start      = data_start;
    geom->data_length     = data_length;
}

/* A data transfer's data: the resolved span, or else everything after the
 * header and its digest. */
static tvbuff_t *
nvme_tcp_data_tvb(tvbuff_t *tvb, const struct nvme_tcp_pdu_geom *geom)
{
    if (geom->data_span_known)
        return tvb_new_subset_length(tvb, geom->data_start, geom->data_length);
    return tvb_new_subset_remaining(tvb, NVME_TCP_DATA_PDU_SIZE + geom->hdgst_len);
}

/* The data of a data PDU whose command is not known, shown raw where the
 * header puts it (PDO, after any header digest and padding). */
static void
nvme_tcp_add_unknown_data(proto_tree *tree, tvbuff_t *tvb,
                          const struct nvme_tcp_pdu_geom *geom,
                          uint32_t data_length)
{
    unsigned start = geom->data_span_known ? geom->data_start
            : NVME_TCP_DATA_PDU_SIZE + geom->hdgst_len;
    uint32_t len = geom->data_span_known ? geom->data_length : data_length;

    proto_tree_add_item(tree, hf_nvme_tcp_unknown_data, tvb, start, len, ENC_NA);
}

static void
dissect_nvme_tcp_c2h_data(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *root_tree,
                          proto_tree *nvme_tcp_tree,
                          proto_item *nvme_tcp_ti,
                          struct nvme_tcp_q_ctx *queue,
                          int offset,
                          uint8_t pdu_flags,
                          const struct nvme_tcp_pdu_geom *geom)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    uint32_t cmd_id;
    uint32_t data_length;
    uint32_t datao = 0;
    bool span_known;
    tvbuff_t *nvme_data;
    const char *cmd_string;

    cmd_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    data_length = dissect_nvme_tcp_data_pdu(tvb, pinfo, offset, nvme_tcp_tree,
            &datao);

    /* This can identify our packet uniquely  */
    if (!PINFO_FD_VISITED(pinfo)) {
        cmd_ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_cmd_in_pending_list(
                &queue->n_q_ctx, cmd_id);
        /* A completed command's CID may be reused (NVMe/TCP 1.3 3.3.2.1). */
        if (!cmd_ctx || cmd_ctx->n_cmd_ctx.cqe_pkt_num) {
            nvme_tcp_add_unknown_data(root_tree, tvb, geom, data_length);
            return;
        }

        /* In order to later lookup for command context lets add this command
         * to data responses */
        cmd_ctx->n_cmd_ctx.data_tr_pkt_num[0] = pinfo->num;
        nvme_add_data_tr_pkt(&queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, cmd_id, pinfo->num);

        /* LAST_PDU with SUCCESS completes the command (Figure 33, 3.3.2.1). */
        if ((pdu_flags & (NVME_TCP_F_DATA_SUCCESS | NVME_TCP_F_DATA_LAST)) ==
                (NVME_TCP_F_DATA_SUCCESS | NVME_TCP_F_DATA_LAST)) {
            nvme_update_cmd_end_info(pinfo, &cmd_ctx->n_cmd_ctx);
            nvme_add_cmd_cqe_to_done_list(&queue->n_q_ctx, &cmd_ctx->n_cmd_ctx,
                    cmd_id);
        }
    } else {
        cmd_ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_data_tr_pkt(&queue->n_q_ctx,
                                cmd_id, pinfo->num);
        if (!cmd_ctx) {
            nvme_tcp_add_unknown_data(root_tree, tvb, geom, data_length);
            return;
        }
    }

    /* Data belongs to its command's queue type. */
    queue->n_q_ctx.qid = nvme_tcp_qid_at(queue, cmd_ctx->n_cmd_ctx.cmd_pkt_num);
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

    /* Controller response data; retained only from a resolved span placed
     * by its Data Offset. */
    span_known = geom->data_span_known;
    nvme_data = nvme_tcp_data_tvb(tvb, geom);

    /* NVMe/TCP 1.3 Figure 33: an initial non-final Security Receive is a
     * legal Level 0 prefix. */
    bool level0_prefix = span_known && queue->n_q_ctx.qid == 0 &&
                         cmd_ctx->n_cmd_ctx.opcode == NVME_AQ_OPC_SECURITY_RECV &&
                         datao == 0 &&
                         !(pdu_flags & (NVME_TCP_F_DATA_LAST | NVME_TCP_F_DATA_SUCCESS));
    struct nvme_data_origin origin = {
        .prov = span_known ? NVME_DATA_PROV_RESPONSE : NVME_DATA_PROV_NONE,
        .window = span_known ? NVME_DATA_WINDOW_EXPLICIT : NVME_DATA_WINDOW_UNKNOWN,
        .offset = span_known ? datao : 0,
        .level0_prefix = level0_prefix,
    };

    dissect_nvme_data_response(nvme_data, pinfo, root_tree, &queue->n_q_ctx,
            &cmd_ctx->n_cmd_ctx, data_length, false,
            NVME_DATA_DIR_CONTROLLER_TO_HOST,
            origin);

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

static void nvme_tcp_add_data_request(packet_info *pinfo, struct nvme_tcp_q_ctx *q_ctx,
        struct nvme_tcp_cmd_ctx *cmd_ctx, uint16_t cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    uint32_t cmd_id_key = cmd_id;

    nvme_tcp_build_cmd_key(&pinfo->num, &cmd_id_key, cmd_key);
    cmd_ctx->n_cmd_ctx.data_req_pkt_num = pinfo->num;
    cmd_ctx->n_cmd_ctx.data_tr_pkt_num[0] = 0;
    wmem_tree_insert32_array(q_ctx->h2c_requests, cmd_key, (void *)cmd_ctx);
}

static struct nvme_tcp_cmd_ctx* nvme_tcp_lookup_data_request(packet_info *pinfo,
        struct nvme_tcp_q_ctx *q_ctx,
        uint16_t cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    uint32_t cmd_id_key = cmd_id;

    nvme_tcp_build_cmd_key(&pinfo->num, &cmd_id_key, cmd_key);
    return (struct nvme_tcp_cmd_ctx*)wmem_tree_lookup32_array(q_ctx->h2c_requests, cmd_key);
}

static void
dissect_nvme_tcp_h2c_data(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *root_tree,
                          proto_tree *nvme_tcp_tree,
                          proto_item *nvme_tcp_ti,
                          struct nvme_tcp_q_ctx *queue,
                          int offset,
                          const struct nvme_tcp_pdu_geom *geom)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    uint16_t cmd_id;
    uint32_t data_length;
    uint32_t datao = 0;
    bool span_known;
    tvbuff_t *nvme_data;
    const char *cmd_string;

    cmd_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    data_length = dissect_nvme_tcp_data_pdu(tvb, pinfo, offset, nvme_tcp_tree,
            &datao);

    if (!PINFO_FD_VISITED(pinfo)) {
        cmd_ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_cmd_in_pending_list(
                &queue->n_q_ctx, cmd_id);
        /* As for C2HData: data for a completed command is not its data
         * (NVMe/TCP 1.3 section 3.3.2.2). */
        if (!cmd_ctx || cmd_ctx->n_cmd_ctx.cqe_pkt_num) {
            nvme_tcp_add_unknown_data(root_tree, tvb, geom, data_length);
            return;
        }

        /* Fill this for "adding data request call,
         * this will be the key to fetch data request later */
        nvme_tcp_add_data_request(pinfo, queue, cmd_ctx, cmd_id);
    } else {
        cmd_ctx = nvme_tcp_lookup_data_request(pinfo, queue, cmd_id);
        if (!cmd_ctx) {
            nvme_tcp_add_unknown_data(root_tree, tvb, geom, data_length);
            return;
        }
    }

    /* Data belongs to its command's queue type. */
    queue->n_q_ctx.qid = nvme_tcp_qid_at(queue, cmd_ctx->n_cmd_ctx.cmd_pkt_num);
    nvme_publish_to_cmd_link(nvme_tcp_tree, tvb,
                hf_nvme_tcp_cmd_pkt, &cmd_ctx->n_cmd_ctx);

    /* fabrics commands should not have h2cdata*/
    if (cmd_ctx->n_cmd_ctx.fabric) {
        cmd_string = get_nvmeof_cmd_string(cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype);
        proto_item_append_text(nvme_tcp_ti,
                ", H2CData Fabrics Type: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
                cmd_string, cmd_ctx->n_cmd_ctx.cmd_ctx.fabric_cmd.fctype, cmd_id, data_length);
        nvme_tcp_add_unknown_data(root_tree, tvb, geom, data_length);
        return;
    }

    cmd_string = nvme_get_opcode_string(cmd_ctx->n_cmd_ctx.opcode,
            queue->n_q_ctx.qid);
    proto_item_append_text(nvme_tcp_ti,
            ", H2CData Opcode: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
            cmd_string, cmd_ctx->n_cmd_ctx.opcode, cmd_id, data_length);

    /* The span the data digest covered, or the remainder. */
    span_known = geom->data_span_known;
    nvme_data = nvme_tcp_data_tvb(tvb, geom);
    /* Host write data: placed by Data Offset (Figure 32), never retained. */
    dissect_nvme_data_response(nvme_data, pinfo, root_tree, &queue->n_q_ctx,
            &cmd_ctx->n_cmd_ctx, data_length, false,
            NVME_DATA_DIR_HOST_TO_CONTROLLER,
            span_known
            ? (struct nvme_data_origin){
                .prov = NVME_DATA_PROV_NONE,
                .window = NVME_DATA_WINDOW_EXPLICIT,
                .offset = datao,
            }
            : NVME_DATA_ORIGIN_NONE);
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

    /* tcp_dissect_pdus() only guarantees PLEN >= NVME_TCP_HEADER_SIZE, so a
     * short PLEN would underflow the trailing data length below. */
    if (packet_len < NVME_TCP_TERMREQ_PDU_SIZE) {
        proto_tree_add_expert_format_remaining(h2ctermreq_tree, pinfo,
                &ei_nvme_tcp_termreq_short, tvb, offset,
                "PDU length %u is shorter than the %u byte Termination Request header",
                packet_len, NVME_TCP_TERMREQ_PDU_SIZE);
        return;
    }

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
                        tvb, offset + NVME_TCP_TERMREQ_PDU_SIZE,
                        packet_len - NVME_TCP_TERMREQ_PDU_SIZE, ENC_NA);
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

    /* tcp_dissect_pdus() only guarantees PLEN >= NVME_TCP_HEADER_SIZE, so a
     * short PLEN would underflow the trailing data length below. */
    if (packet_len < NVME_TCP_TERMREQ_PDU_SIZE) {
        proto_tree_add_expert_format_remaining(c2htermreq_tree, pinfo,
                &ei_nvme_tcp_termreq_short, tvb, offset,
                "PDU length %u is shorter than the %u byte Termination Request header",
                packet_len, NVME_TCP_TERMREQ_PDU_SIZE);
        return;
    }

    proto_tree_add_item(c2htermreq_tree, hf_nvme_tcp_c2htermreq_fes, tvb, offset + 8, 2,
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
                        tvb, offset + NVME_TCP_TERMREQ_PDU_SIZE,
                        packet_len - NVME_TCP_TERMREQ_PDU_SIZE, ENC_NA);
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
                                                                           &queue->n_q_ctx, cmd_id,
                                                                           true);
        if (!cmd_ctx) {
            proto_tree_add_item(nvme_tree, hf_nvme_tcp_unknown_data, tvb, offset,
                                NVME_FABRIC_CQE_SIZE, ENC_NA);
            return;
        }
    }

    /* A completion belongs to its command's queue type. */
    queue->n_q_ctx.qid = nvme_tcp_qid_at(queue, cmd_ctx->n_cmd_ctx.cmd_pkt_num);
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
    unsigned offset = 0;
    int nvme_tcp_pdu_offset;
    proto_tree *nvme_tcp_tree;
    unsigned packet_type;
    uint8_t hlen, pdo;
    uint8_t pdu_flags;
    uint32_t plen;
    uint32_t incapsuled_data_size;
    uint32_t pdu_data_offset = 0;
    struct nvme_tcp_pdu_geom geom;

    /* Whatever TCP hands the heuristic after this PDU starts at the next
     * PDU header (see dissect_nvme_tcp_heur). */
    p_set_proto_data(pinfo->pool, pinfo, proto_nvme_tcp, NVME_TCP_PDU_IN_FRAME,
                     GUINT_TO_POINTER(1));

    conversation = find_or_create_conversation(pinfo);
    q_ctx = (struct nvme_tcp_q_ctx *)
            conversation_get_proto_data(conversation, proto_nvme_tcp);

    if (!q_ctx) {
        q_ctx = wmem_new0(wmem_file_scope(), struct nvme_tcp_q_ctx);
        q_ctx->n_q_ctx.pending_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.done_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->h2c_requests = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_responses = wmem_tree_new(wmem_file_scope());
        q_ctx->qid_by_frame = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_nvme_tcp, q_ctx);
    }

    /* The queue id as this PDU starts, UINT16_MAX (I/O) until one is learned.
     * The first pass keeps it per PDU: a later PDU of the frame may learn it,
     * and the earlier ones must decode the same way on every pass. */
    uint32_t qid_key = NVME_TCP_PDU_QID_BASE + (uint32_t)tvb_raw_offset(tvb);
    void *qid_kept = p_get_proto_data(wmem_file_scope(), pinfo, proto_nvme_tcp, qid_key);

    if (qid_kept) {
        q_ctx->n_q_ctx.qid = (uint16_t)(GPOINTER_TO_UINT(qid_kept) - 1);
    } else {
        q_ctx->n_q_ctx.qid = nvme_tcp_qid_at(q_ctx, pinfo->num);
        if (!PINFO_FD_VISITED(pinfo))
            p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_tcp, qid_key,
                             GUINT_TO_POINTER((unsigned)q_ctx->n_q_ctx.qid + 1));
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
    proto_tree_add_bitmask_value(nvme_tcp_tree, tvb, offset + 1, hf_nvme_tcp_flags,
            ett_nvme_tcp, nvme_tcp_pdu_flags, (uint64_t)pdu_flags);

    hlen = tvb_get_uint8(tvb, offset + 2);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_hlen, tvb, offset + 2, 1,
            ENC_NA);

    pdo = tvb_get_uint8(tvb, offset + 3);
    proto_tree_add_uint(nvme_tcp_tree, hf_nvme_tcp_pdo, tvb, offset + 3, 1,
            pdo);
    proto_tree_add_item_ret_uint(nvme_tcp_tree, hf_nvme_tcp_plen, tvb, offset + 4, 4,
            ENC_LITTLE_ENDIAN, &plen);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe/TCP");

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

    /* The data digest covers the data alone, not the padding (NVMe/TCP 1.3
     * 3.3, 3.3.1.1). */
    geom.hlen      = hlen;
    geom.pdo       = pdo;
    geom.plen      = plen;
    geom.hdgst_len = pdu_data_offset;
    geom.ddgst_len = (pdu_flags & NVME_TCP_F_DDGST) ? NVME_TCP_DIGEST_LENGTH : 0;
    geom.data_span_known = false;
    geom.data_start      = 0;
    geom.data_length     = 0;
    nvme_tcp_resolve_data_span(tvb, nvme_tcp_pdu_offset, packet_type, &geom);

    if (pdu_flags & NVME_TCP_F_DDGST) {
        unsigned ddgst_flags = PROTO_CHECKSUM_NO_FLAGS;
        unsigned ddgst_offset;
        uint32_t crc = 0;

        /* Check that data has enough space (invalid packet) */
        if (incapsuled_data_size <= NVME_TCP_DIGEST_LENGTH) {
            proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_unknown_data,
                                           tvb, NVME_TCP_HEADER_SIZE, -1, ENC_NA);
            return tvb_reported_length(tvb);
        }

        incapsuled_data_size -= NVME_TCP_DIGEST_LENGTH;

        /* The digest follows a resolved span, else it ends the PDU and covers
         * everything from PDO. */
        if (geom.data_span_known) {
            ddgst_offset = geom.data_start + geom.data_length;
            if (nvme_tcp_check_ddgst) {
                ddgst_flags = PROTO_CHECKSUM_VERIFY;
                crc = ~crc32c_tvb_offset_calculate(tvb, geom.data_start,
                                                   geom.data_length, ~0);
            }
        } else {
            ddgst_offset = plen - NVME_TCP_DIGEST_LENGTH;
            if (nvme_tcp_check_ddgst &&
                tvb_bytes_exist(tvb, pdo, incapsuled_data_size)) {
                ddgst_flags = PROTO_CHECKSUM_VERIFY;
                crc = ~crc32c_tvb_offset_calculate(tvb, pdo,
                                                   incapsuled_data_size, ~0);
            }
        }
        /* A digest the capture cut is not shown, so binding below still runs. */
        if (tvb_bytes_exist(tvb, ddgst_offset, NVME_TCP_DIGEST_LENGTH)) {
            proto_tree_add_checksum(nvme_tcp_tree, tvb,
                             ddgst_offset, hf_nvme_tcp_ddgst,
                             hf_nvme_tcp_ddgst_status, NULL, pinfo,
                             crc, ENC_NA, ddgst_flags);
        }
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
                nvme_tcp_pdu_offset, incapsuled_data_size, &geom);
        break;
    case nvme_tcp_rsp:
        dissect_nvme_tcp_cqe(tvb, pinfo, tree, nvme_tcp_tree, ti, q_ctx,
                nvme_tcp_pdu_offset);
        proto_item_set_len(ti, NVME_TCP_HEADER_SIZE);
        break;
    case nvme_tcp_c2h_data:
        dissect_nvme_tcp_c2h_data(tvb, pinfo, tree, nvme_tcp_tree, ti, q_ctx,
                nvme_tcp_pdu_offset, pdu_flags, &geom);
        proto_item_set_len(ti, NVME_TCP_DATA_PDU_SIZE);
        break;
    case nvme_tcp_h2c_data:
        dissect_nvme_tcp_h2c_data(tvb, pinfo, tree, nvme_tcp_tree, ti, q_ctx,
                nvme_tcp_pdu_offset, &geom);
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
        // TODO: nvme_tcp_kdreq, nvme_tcp_kdresp
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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe/TCP");
    tcp_dissect_pdus(tvb, pinfo, tree, true, NVME_TCP_HEADER_SIZE,
            get_nvme_tcp_pdu_len, dissect_nvme_tcp_pdu, data);

    return tvb_reported_length(tvb);
}

static bool
test_nvme(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint8_t pdu_type, hlen;
    uint32_t plen;

    /* Distinguishes NVMe/TCP from TLS and finds PDU starts: every PDU type
     * has a fixed HLEN (NVMe/TCP 1.3 Figures 26-37); other types are reserved. */
    if (tvb_captured_length_remaining(tvb, offset) < NVME_TCP_HEADER_SIZE) {
        return false;
    }

    pdu_type = tvb_get_uint8(tvb, offset);
    hlen = tvb_get_uint8(tvb, offset + 2);
    plen = tvb_get_uint32(tvb, offset + PDU_LEN_OFFSET_FROM_HEADER,
                          ENC_LITTLE_ENDIAN);

    switch (pdu_type) {
    case nvme_tcp_icreq:
    case nvme_tcp_icresp:
        /* Figures 26 and 27: HLEN and PLEN are both 128. */
        return hlen == 128 && plen == 128;
    case nvme_tcp_h2c_term:
    case nvme_tcp_c2h_term:
        /* Figures 28 and 29: PLEN is at most 152. */
        return hlen == NVME_TCP_TERMREQ_PDU_SIZE && plen >= hlen && plen <= 152;
    case nvme_tcp_cmd:
        /* Figure 30 */
        return hlen == NVME_TCP_CMD_PDU_SIZE && plen >= hlen;
    case nvme_tcp_rsp:
    case nvme_tcp_r2t:
        /* Figures 31 and 34: no data, so PLEN is HLEN plus any HDGST. */
        return hlen == 24 &&
            (plen == 24 || plen == 24 + NVME_TCP_DIGEST_LENGTH);
    case nvme_tcp_h2c_data:
    case nvme_tcp_c2h_data:
        /* Figures 32 and 33 */
        return hlen == NVME_TCP_DATA_PDU_SIZE && plen >= hlen;
    case nvme_tcp_kdreq:
        /* Figure 35 */
        return hlen == 12 && plen >= hlen;
    case nvme_tcp_kdresp:
        /* Figure 37 */
        return hlen == 10 && plen >= hlen;
    default:
        return false;
    }
}

static int
dissect_nvme_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    /* PDU types (< 20) and TLS content types (>= 20, RFC 9443) share the first
     * byte. A tail after a PDU completed in this frame may be too short to
     * test, so accept it. */
    if (tvb_reported_length(tvb) < NVME_TCP_HEADER_SIZE &&
        p_get_proto_data(pinfo->pool, pinfo, proto_nvme_tcp, NVME_TCP_PDU_IN_FRAME)) {
        return dissect_nvme_tcp(tvb, pinfo, tree, data);
    }

    if (!test_nvme(pinfo, tvb, 0, data)) {
        return 0;
        /* The TLS heuristic dissector should catch the TLS version. */
    }

    /* Only ICReq/ICResp pin the connection (NVMe/TCP 1.3 3.1); a
     * mid-connection capture is tested segment by segment. */
    uint8_t pdu_type = tvb_get_uint8(tvb, 0);
    if (pdu_type == nvme_tcp_icreq || pdu_type == nvme_tcp_icresp) {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector_from_frame_number(conversation, pinfo->num,
                                                     nvmet_tls_handle);
    }

    return dissect_nvme_tcp(tvb, pinfo, tree, data);
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
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp_digest,
           { "Digest types enabled", "nvme-tcp.icresp.digest",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_icresp_maxdata,
           { "Maximum H2CData PDU data length", "nvme-tcp.icresp.maxdata",
             FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&units_byte_bytes), 0x0, NULL, HFILL } },
       /* NVMe tcp c2h/h2c termreq fields */
       { &hf_nvme_tcp_c2htermreq,
           { "C2HTermReq", "nvme-tcp.c2htermreq",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_fes,
           { "Fatal error status", "nvme-tcp.c2htermreq.fes",
             FT_UINT16, BASE_HEX, VALS(nvme_tcp_c2htermreq_fes),
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
             FT_UINT16, BASE_HEX, VALS(nvme_tcp_h2ctermreq_fes),
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

    static ei_register_info ei[] = {
        { &ei_nvme_tcp_termreq_short,
            { "nvme-tcp.termreq_too_short", PI_MALFORMED, PI_ERROR,
              "Termination Request PDU is shorter than its header", EXPFILL } },
    };

    expert_module_t *expert_nvme_tcp;

    proto_nvme_tcp = proto_register_protocol("NVM Express Fabrics TCP",
            "NVMe/TCP", "nvme-tcp");

    proto_register_field_array(proto_nvme_tcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_tcp = expert_register_protocol(proto_nvme_tcp);
    expert_register_field_array(expert_nvme_tcp, ei, array_length(ei));

    /* These names actually work for their purpose. Note if we're already
     * over TLS we don't need to do heuristics (it can't be more TLS instead
     * instead, and since we managed to decrypt the TLS we shouldn't have
     * missing frames and thus aren't in the middle of a PDU.)
     */
    nvmet_tcp_handle = register_dissector("nvme-tcp", dissect_nvme_tcp_heur,
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
