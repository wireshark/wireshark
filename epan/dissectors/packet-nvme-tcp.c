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
#include <errno.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>
#include <epan/crc32-tvb.h>
#include "packet-tcp.h"
#include "packet-nvme.h"

static int proto_nvme_tcp = -1;
static dissector_handle_t nvmet_tcp_handle;
#define NVME_TCP_PORT_RANGE    "4420" /* IANA registered */

#define NVME_FABRICS_TCP "NVMe/TCP"
#define NVME_TCP_HEADER_SIZE 8
#define PDU_LEN_OFFSET_FROM_HEADER 4
static range_t *gPORT_RANGE;
static gboolean nvme_tcp_check_hdgst = FALSE;
static gboolean nvme_tcp_check_ddgst = FALSE;
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

enum nvmf_capsule_command {
    nvme_fabrics_type_property_set = 0x00,
    nvme_fabrics_type_connect = 0x01,
    nvme_fabrics_type_property_get = 0x04,
};

static const value_string nvme_fabrics_cmd_type_vals[] = {
    { nvme_fabrics_type_connect, "Connect" },
    { nvme_fabrics_type_property_get, "Property Get" },
    { nvme_fabrics_type_property_set, "Property Set" },
    { 0, NULL }
};

static const value_string attr_size_tbl[] = {
    { 0, "4 bytes" },
    { 1, "8 bytes" },
    { 0, NULL }
};

static const value_string prop_offset_tbl[] = {
    { 0x0, "Controller Capabilities" },
    { 0x8, "Version" },
    { 0xc, "Reserved" },
    { 0x10, "Reserved" },
    { 0x14, "Controller Configuration" },
    { 0x18, "Reserved" },
    { 0x1c, "Controller Status" },
    { 0x20, "NVM Subsystem Reset" },
    { 0x24, "Reserved" },
    { 0x28, "Reserved" },
    { 0x30, "Reserved" },
    { 0x38, "Reserved" },
    { 0x3c, "Reserved" },
    { 0x40, "Reserved" },
    { 0, NULL }
};

enum nvme_tcp_digest_option {
    NVME_TCP_HDR_DIGEST_ENABLE = (1 << 0),
    NVME_TCP_DATA_DIGEST_ENABLE = (1 << 1),
};

/*
 * Fabrics subcommands.
 */
enum nvmf_fabrics_opcode {
    nvme_fabrics_command = 0x7f,
};

#define NVME_FABRIC_CMD_SIZE NVME_CMD_SIZE
#define NVME_FABRIC_CQE_SIZE NVME_CQE_SIZE
#define NVME_TCP_DIGEST_LENGTH  4

struct nvme_tcp_q_ctx {
    struct nvme_q_ctx n_q_ctx;
};

struct nvme_tcp_cmd_ctx {
    struct nvme_cmd_ctx n_cmd_ctx;
    guint8 fctype; /* fabric cmd type */
};

void proto_reg_handoff_nvme_tcp(void);
void proto_register_nvme_tcp(void);


static int hf_nvme_tcp_type = -1;
static int hf_nvme_tcp_flags = -1;
static int hf_pdu_flags_hdgst = -1;
static int hf_pdu_flags_ddgst = -1;
static int hf_pdu_flags_data_last = -1;
static int hf_pdu_flags_data_success = -1;

static int * const nvme_tcp_pdu_flags[] = {
    &hf_pdu_flags_hdgst,
    &hf_pdu_flags_ddgst,
    &hf_pdu_flags_data_last,
    &hf_pdu_flags_data_success,
    NULL
};

static int hf_nvme_tcp_hdgst = -1;
static int hf_nvme_tcp_ddgst = -1;
static int hf_nvme_tcp_hlen = -1;
static int hf_nvme_tcp_pdo = -1;
static int hf_nvme_tcp_plen = -1;
static int hf_nvme_tcp_hdgst_status = -1;
static int hf_nvme_tcp_ddgst_status = -1;

/* NVMe tcp icreq/icresp fields */
static int hf_nvme_tcp_icreq = -1;
static int hf_nvme_tcp_icreq_pfv = -1;
static int hf_nvme_tcp_icreq_maxr2t = -1;
static int hf_nvme_tcp_icreq_hpda = -1;
static int hf_nvme_tcp_icreq_digest = -1;
static int hf_nvme_tcp_icresp = -1;
static int hf_nvme_tcp_icresp_pfv = -1;
static int hf_nvme_tcp_icresp_cpda = -1;
static int hf_nvme_tcp_icresp_digest = -1;
static int hf_nvme_tcp_icresp_maxdata = -1;

/* NVMe tcp c2h/h2c termreq fields */
static int hf_nvme_tcp_c2htermreq = -1;
static int hf_nvme_tcp_c2htermreq_fes = -1;
static int hf_nvme_tcp_c2htermreq_phfo = -1;
static int hf_nvme_tcp_c2htermreq_phd = -1;
static int hf_nvme_tcp_c2htermreq_upfo = -1;
static int hf_nvme_tcp_c2htermreq_reserved = -1;
static int hf_nvme_tcp_c2htermreq_data = -1;
static int hf_nvme_tcp_h2ctermreq = -1;
static int hf_nvme_tcp_h2ctermreq_fes = -1;
static int hf_nvme_tcp_h2ctermreq_phfo = -1;
static int hf_nvme_tcp_h2ctermreq_phd = -1;
static int hf_nvme_tcp_h2ctermreq_upfo = -1;
static int hf_nvme_tcp_h2ctermreq_reserved = -1;
static int hf_nvme_tcp_h2ctermreq_data = -1;

/* NVMe fabrics command */
static int hf_nvme_fabrics_cmd = -1;
static int hf_nvme_fabrics_cmd_opc = -1;
static int hf_nvme_fabrics_cmd_rsvd1 = -1;
static int hf_nvme_fabrics_cmd_cid = -1;
static int hf_nvme_fabrics_cmd_fctype = -1;
static int hf_nvme_fabrics_cmd_generic_rsvd1 = -1;
static int hf_nvme_fabrics_cmd_generic_field = -1;

/* NVMe fabrics connect command  */
static int hf_nvme_fabrics_cmd_connect_rsvd2 = -1;
static int hf_nvme_fabrics_cmd_connect_sgl1 = -1;
static int hf_nvme_fabrics_cmd_connect_recfmt = -1;
static int hf_nvme_fabrics_cmd_connect_qid = -1;
static int hf_nvme_fabrics_cmd_connect_sqsize = -1;
static int hf_nvme_fabrics_cmd_connect_cattr = -1;
static int hf_nvme_fabrics_cmd_connect_rsvd3 = -1;
static int hf_nvme_fabrics_cmd_connect_kato = -1;
static int hf_nvme_fabrics_cmd_connect_rsvd4 = -1;

static int hf_nvme_tcp_unknown_data = -1;

/* NVMe fabrics connect command data*/
static int hf_nvme_fabrics_cmd_data = -1;
static int hf_nvme_fabrics_cmd_connect_data_hostid = -1;
static int hf_nvme_fabrics_cmd_connect_data_cntlid = -1;
static int hf_nvme_fabrics_cmd_connect_data_rsvd4 = -1;
static int hf_nvme_fabrics_cmd_connect_data_subnqn = -1;
static int hf_nvme_fabrics_cmd_connect_data_hostnqn = -1;
static int hf_nvme_fabrics_cmd_connect_data_rsvd5 = -1;

static int hf_nvme_tcp_r2t_pdu = -1;
static int hf_nvme_tcp_r2t_offset = -1;
static int hf_nvme_tcp_r2t_length = -1;
static int hf_nvme_tcp_r2t_resvd = -1;

static int hf_nvme_fabrics_cmd_prop_attr_rsvd1 = -1;
static int hf_nvme_fabrics_cmd_prop_attr_size = -1;
static int hf_nvme_fabrics_cmd_prop_attr_rsvd2 = -1;
static int hf_nvme_fabrics_cmd_prop_attr_offset = -1;
static int hf_nvme_fabrics_cmd_prop_attr_rsvd3 = -1;
static int hf_nvme_fabrics_cmd_prop_attr_get_rsvd4 = -1;
static int hf_nvme_fabrics_cmd_prop_attr_set_4B_value = -1;
static int hf_nvme_fabrics_cmd_prop_attr_set_4B_value_rsvd = -1;
static int hf_nvme_fabrics_cmd_prop_attr_set_8B_value = -1;
static int hf_nvme_fabrics_cmd_prop_attr_set_rsvd3 = -1;

/* tracking Cmd and its respective CQE */
static int hf_nvme_fabrics_cmd_pkt = -1;
static int hf_nvme_tcp_cmd_pkt = -1;
static int hf_nvme_fabrics_cqe_pkt = -1;
static int hf_nvme_fabrics_cmd_latency = -1;
static int hf_nvme_fabrics_cmd_qid = -1;

/* NVMe Fabric CQE */
static int hf_nvme_fabrics_cqe = -1;
static int hf_nvme_fabrics_cqe_sts = -1;
static int hf_nvme_fabrics_cqe_sqhd = -1;
static int hf_nvme_fabrics_cqe_rsvd = -1;
static int hf_nvme_fabrics_cqe_status = -1;
static int hf_nvme_fabrics_cqe_status_rsvd = -1;

static int hf_nvme_fabrics_cqe_connect_cntlid = -1;
static int hf_nvme_fabrics_cqe_connect_authreq = -1;
static int hf_nvme_fabrics_cqe_connect_rsvd = -1;
static int hf_nvme_fabrics_cqe_prop_set_rsvd = -1;

/* Data response fields */
static int hf_nvme_tcp_data_pdu = -1;
static int hf_nvme_tcp_pdu_ttag = -1;
static int hf_nvme_tcp_data_pdu_data_offset = -1;
static int hf_nvme_tcp_data_pdu_data_length = -1;
static int hf_nvme_tcp_data_pdu_data_resvd = -1;

static gint ett_nvme_tcp = -1;

static guint
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

static void
dissect_nvme_fabric_connect_cmd_data(tvbuff_t *data_tvb,
                                     proto_tree *data_tree,
                                     guint offset)
{
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_hostid,
            data_tvb, offset, 16, ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_cntlid,
            data_tvb, offset + 16, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_rsvd4,
            data_tvb, offset + 18, 238, ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_subnqn,
            data_tvb, offset + 256, 256, ENC_ASCII | ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_hostnqn,
            data_tvb, offset + 512, 256, ENC_ASCII | ENC_NA);
    proto_tree_add_item(data_tree, hf_nvme_fabrics_cmd_connect_data_rsvd5,
            data_tvb, offset + 768, 256, ENC_NA);
}

static void
dissect_nvme_fabric_data(tvbuff_t *nvme_tvb,
                         proto_tree *nvme_tree,
                         guint32 len,
                         guint8 fctype,
                         int offset)
{
    proto_tree *data_tree;
    proto_item *ti;

    ti = proto_tree_add_item(nvme_tree, hf_nvme_fabrics_cmd_data, nvme_tvb,
            offset, len, ENC_NA);
    data_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

    switch (fctype) {
    case nvme_fabrics_type_connect:
        dissect_nvme_fabric_connect_cmd_data(nvme_tvb, data_tree, offset);
        break;
    default:
        proto_tree_add_item(data_tree, hf_nvme_tcp_unknown_data, nvme_tvb, offset,
                len, ENC_NA);
        break;
    }
}

static void
dissect_nvme_fabric_generic_cmd(proto_tree *cmd_tree,
                                tvbuff_t *cmd_tvb,
                                int offset)
{
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_generic_rsvd1, cmd_tvb,
            offset + 5, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_generic_field, cmd_tvb,
            offset + 40, 24, ENC_NA);
}

static void
dissect_nvme_fabric_connect_cmd(struct nvme_tcp_q_ctx *queue,
                                proto_tree *cmd_tree,
                                tvbuff_t *cmd_tvb,
                                int offset)
{
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_rsvd2, cmd_tvb,
            offset + 5, 19, ENC_NA);
    dissect_nvme_cmd_sgl(cmd_tvb, cmd_tree, hf_nvme_fabrics_cmd_connect_sgl1,
            NULL);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_recfmt, cmd_tvb,
            offset + 40, 2, ENC_LITTLE_ENDIAN);

    queue->n_q_ctx.qid = tvb_get_guint16(cmd_tvb, offset + 42,
            ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_qid, cmd_tvb,
            offset + 42, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_sqsize, cmd_tvb,
            offset + 44, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_cattr, cmd_tvb,
            offset + 46, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_rsvd3, cmd_tvb,
            offset + 47, 1, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_kato, cmd_tvb,
            offset + 48, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_connect_rsvd4, cmd_tvb,
            offset + 52, 12, ENC_NA);
}

static guint8
dissect_nvme_fabric_prop_cmd_common(proto_tree *cmd_tree,
                                    tvbuff_t *cmd_tvb,
                                    int offset)
{
    proto_item *attr_item, *offset_item;
    guint32 offset_in_string;
    guint8 attr;

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_rsvd1, cmd_tvb,
            offset + 5, 35, ENC_NA);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_rsvd2, cmd_tvb,
            offset + 40, 1, ENC_LITTLE_ENDIAN);
    attr_item = proto_tree_add_item(cmd_tree,
            hf_nvme_fabrics_cmd_prop_attr_size, cmd_tvb, offset + 40, 1,
            ENC_LITTLE_ENDIAN);
    attr = tvb_get_guint8(cmd_tvb, offset + 40) & 0x7;
    proto_item_append_text(attr_item, "%s",
                           val_to_str_const(attr, attr_size_tbl, "Reserved"));

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_rsvd3, cmd_tvb,
            offset + 41, 3, ENC_NA);

    offset_item = proto_tree_add_item_ret_uint(cmd_tree,
            hf_nvme_fabrics_cmd_prop_attr_offset, cmd_tvb, offset + 44, 4,
            ENC_LITTLE_ENDIAN, &offset_in_string);
    proto_item_append_text(offset_item, "%s",
                           val_to_str_const(offset_in_string, prop_offset_tbl, "Unknown Property"));
    return attr;
}

static void
dissect_nvme_fabric_prop_get_cmd(proto_tree *cmd_tree,
                                 tvbuff_t *cmd_tvb,
                                 int offset)
{
    dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb, offset);
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_get_rsvd4,
            cmd_tvb, offset + 48, 16, ENC_NA);
}

static void
dissect_nvme_fabric_prop_set_cmd(proto_tree *cmd_tree,
                                 tvbuff_t *cmd_tvb,
                                 int offset)
{
    guint8 attr;

    attr = dissect_nvme_fabric_prop_cmd_common(cmd_tree, cmd_tvb, offset);
    if (attr == 0) {
        proto_tree_add_item(cmd_tree,
                hf_nvme_fabrics_cmd_prop_attr_set_4B_value, cmd_tvb,
                offset + 48, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cmd_tree,
                hf_nvme_fabrics_cmd_prop_attr_set_4B_value_rsvd, cmd_tvb,
                offset + 52, 4, ENC_LITTLE_ENDIAN);
    } else {
        proto_tree_add_item(cmd_tree,
                hf_nvme_fabrics_cmd_prop_attr_set_8B_value, cmd_tvb,
                offset + 48, 8, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_prop_attr_set_rsvd3,
            cmd_tvb, offset + 56, 8, ENC_NA);
}

static void
dissect_nvme_fabric_cmd(tvbuff_t *nvme_tvb,
                        proto_tree *nvme_tree,
                        struct nvme_tcp_q_ctx *queue,
                        struct nvme_tcp_cmd_ctx *cmd_ctx,
                        int offset)
{
    proto_tree *cmd_tree;
    proto_item *ti, *opc_item;
    guint8 fctype;

    fctype = tvb_get_guint8(nvme_tvb, offset + 4);
    cmd_ctx->fctype = fctype;

    ti = proto_tree_add_item(nvme_tree, hf_nvme_fabrics_cmd, nvme_tvb,
            NVME_TCP_HEADER_SIZE,
            NVME_FABRIC_CMD_SIZE, ENC_NA);
    cmd_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

    opc_item = proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_opc, nvme_tvb,
            offset, 1, ENC_NA);
    proto_item_append_text(opc_item, "%s", " Fabric Cmd");

    nvme_publish_cmd_to_cqe_link(cmd_tree, nvme_tvb, hf_nvme_fabrics_cqe_pkt,
            &cmd_ctx->n_cmd_ctx);

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_rsvd1, nvme_tvb,
            offset + 1, 1, ENC_NA);

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_cid, nvme_tvb, offset + 2,
            2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(cmd_tree, hf_nvme_fabrics_cmd_fctype,
            nvme_tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);

    switch (fctype) {
    case nvme_fabrics_type_connect:
        dissect_nvme_fabric_connect_cmd(queue, cmd_tree, nvme_tvb, offset);
        break;
    case nvme_fabrics_type_property_get:
        dissect_nvme_fabric_prop_get_cmd(cmd_tree, nvme_tvb, offset);
        break;
    case nvme_fabrics_type_property_set:
        dissect_nvme_fabric_prop_set_cmd(cmd_tree, nvme_tvb, offset);
        break;
    default:
        dissect_nvme_fabric_generic_cmd(cmd_tree, nvme_tvb, offset);
        break;
    }
}

static struct nvme_tcp_cmd_ctx*
bind_cmd_to_qctx(packet_info *pinfo,
                 struct nvme_q_ctx *q_ctx,
                 guint16 cmd_id)
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
                         guint32 incapsuled_data_size,
                         guint32 data_offset)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    guint16 cmd_id;
    guint8 opcode;
    const gchar *cmd_string;

    opcode = tvb_get_guint8(tvb, offset);
    cmd_id = tvb_get_guint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
    cmd_ctx = bind_cmd_to_qctx(pinfo, &queue->n_q_ctx, cmd_id);

    /* if record did not contain connect command we wont know qid,
     * so lets guess if this is an admin queue */
    if ((queue->n_q_ctx.qid == G_MAXUINT16) && !nvme_is_io_queue_opcode(opcode))
        queue->n_q_ctx.qid = 0;

    if (opcode == nvme_fabrics_command) {
        guint8 fctype;

        cmd_ctx->n_cmd_ctx.fabric = TRUE;
        fctype = tvb_get_guint8(tvb, offset + 4);
        dissect_nvme_fabric_cmd(tvb, nvme_tcp_tree, queue, cmd_ctx, offset);
        cmd_string = val_to_str_const(fctype, nvme_fabrics_cmd_type_vals,
                "Unknown FcType");
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "Fabrics %s Request",
                cmd_string);
        proto_item_append_text(nvme_tcp_ti,
                ", Fabrics Type: %s (0x%02x) Cmd ID: 0x%04x", cmd_string,
                fctype, cmd_id);

        if (incapsuled_data_size > 0) {
            dissect_nvme_fabric_data(tvb, nvme_tcp_tree, incapsuled_data_size,
                  cmd_ctx->fctype, offset + NVME_FABRIC_CMD_SIZE + data_offset);
        }
        return;
    }

    /* In case of incapsuled nvme command tcp length is only a header */
    proto_item_set_len(nvme_tcp_ti, NVME_TCP_HEADER_SIZE);
    tvbuff_t *nvme_tvbuff;
    cmd_ctx->n_cmd_ctx.fabric = FALSE;
    nvme_tvbuff = tvb_new_subset_remaining(tvb, NVME_TCP_HEADER_SIZE);
    cmd_string = nvme_get_opcode_string(opcode, queue->n_q_ctx.qid);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "NVMe %s", cmd_string);
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
                &cmd_ctx->n_cmd_ctx, incapsuled_data_size);
    }
}

static void
dissect_nvme_fabrics_cqe_status_8B(proto_tree *cqe_tree,
                                   tvbuff_t *cqe_tvb,
                                   struct nvme_tcp_cmd_ctx *cmd_ctx,
                                   int offset)
{
    switch (cmd_ctx->fctype) {
    case nvme_fabrics_type_connect:
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_connect_cntlid,
                cqe_tvb, offset + 0, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_connect_authreq,
                cqe_tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_connect_rsvd, cqe_tvb,
                offset + 4, 4, ENC_NA);
        break;
    case nvme_fabrics_type_property_get:
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_sts, cqe_tvb,
                offset + 0, 8, ENC_LITTLE_ENDIAN);
        break;
    case nvme_fabrics_type_property_set:
        proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_prop_set_rsvd,
                cqe_tvb, offset + 0, 8, ENC_NA);
        break;
    };
}

static void
dissect_nvme_fabric_cqe(tvbuff_t *nvme_tvb,
                        packet_info *pinfo,
                        proto_tree *nvme_tree,
                        struct nvme_tcp_cmd_ctx *cmd_ctx,
                        const gchar *fctype_cmd,
                        int offset)
{
    proto_tree *cqe_tree;
    proto_item *ti;

    ti = proto_tree_add_item(nvme_tree, hf_nvme_fabrics_cqe, nvme_tvb, offset,
            NVME_FABRIC_CQE_SIZE, ENC_NA);

    proto_item_append_text(ti, " (For Cmd: %s)",
            val_to_str_const(cmd_ctx->fctype, nvme_fabrics_cmd_type_vals,
                    "Unknown Cmd"));

    col_add_fstr(pinfo->cinfo, COL_INFO, "Fabrics %s Response", fctype_cmd);

    cqe_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

    nvme_publish_cqe_to_cmd_link(cqe_tree, nvme_tvb, hf_nvme_fabrics_cmd_pkt,
            &cmd_ctx->n_cmd_ctx);
    nvme_publish_cmd_latency(cqe_tree, &cmd_ctx->n_cmd_ctx,
            hf_nvme_fabrics_cmd_latency);

    dissect_nvme_fabrics_cqe_status_8B(cqe_tree, nvme_tvb, cmd_ctx, offset);

    proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_sqhd, nvme_tvb,
            offset + 8, 2, ENC_NA);
    proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_rsvd, nvme_tvb,
            offset + 10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cmd_cid, nvme_tvb,
            offset + 12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_status, nvme_tvb,
            offset + 14, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(cqe_tree, hf_nvme_fabrics_cqe_status_rsvd, nvme_tvb,
            offset + 14, 2, ENC_LITTLE_ENDIAN);
}

static guint32
dissect_nvme_tcp_data_pdu(tvbuff_t *tvb,
                          packet_info *pinfo,
                          int offset,
                          proto_tree *tree) {
    guint32 data_length;
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

    data_length = tvb_get_guint32(tvb, offset + 8, ENC_LITTLE_ENDIAN);
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
                          guint32 data_offset)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    guint32 cmd_id;
    guint32 data_length;
    tvbuff_t *nvme_data;
    const gchar *cmd_string;

    cmd_id = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
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
        cmd_ctx->n_cmd_ctx.data_resp_pkt_num = pinfo->num;
        nvme_add_data_response(&queue->n_q_ctx, &cmd_ctx->n_cmd_ctx, cmd_id);
    } else {
        cmd_ctx = (struct nvme_tcp_cmd_ctx*) nvme_lookup_data_response(pinfo,
                &queue->n_q_ctx, cmd_id);
        if (!cmd_ctx) {
            proto_tree_add_item(root_tree, hf_nvme_tcp_unknown_data, tvb, offset + 16,
                                data_length, ENC_NA);
            return;
        }
    }

    nvme_publish_data_pdu_to_cmd_link(nvme_tcp_tree, tvb,
            hf_nvme_tcp_cmd_pkt, &cmd_ctx->n_cmd_ctx);

    if (cmd_ctx->n_cmd_ctx.fabric) {
        cmd_string = val_to_str_const(cmd_ctx->fctype, nvme_fabrics_cmd_type_vals,
                "Unknown FcType");
        proto_item_append_text(nvme_tcp_ti,
                ", C2HData Fabrics Type: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
                cmd_string, cmd_ctx->fctype, cmd_id, data_length);
    } else {
        cmd_string = nvme_get_opcode_string(cmd_ctx->n_cmd_ctx.opcode,
                queue->n_q_ctx.qid);
        proto_item_append_text(nvme_tcp_ti,
                ", C2HData Opcode: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
                cmd_string, cmd_ctx->n_cmd_ctx.opcode, cmd_id, data_length);
    }

    nvme_data = tvb_new_subset_remaining(tvb, NVME_TCP_DATA_PDU_SIZE + data_offset);

    dissect_nvme_data_response(nvme_data, pinfo, root_tree, &queue->n_q_ctx,
            &cmd_ctx->n_cmd_ctx, data_length);

}

static void nvme_tcp_build_cmd_key(guint32 *frame_num, guint32 *cmd_id, wmem_tree_key_t *key)
{
    key[0].key = frame_num;
    key[0].length = 1;
    key[1].key = cmd_id;
    key[1].length = 1;
    key[2].key = NULL;
    key[2].length = 0;
}

static void nvme_tcp_add_data_request(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
        struct nvme_tcp_cmd_ctx *cmd_ctx, guint16 cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    guint32 cmd_id_key = cmd_id;

    nvme_tcp_build_cmd_key(&pinfo->num, &cmd_id_key, cmd_key);
    cmd_ctx->n_cmd_ctx.data_req_pkt_num = pinfo->num;
    cmd_ctx->n_cmd_ctx.data_resp_pkt_num = 0;
    wmem_tree_insert32_array(q_ctx->data_requests, cmd_key, (void *)cmd_ctx);
}

static struct nvme_tcp_cmd_ctx* nvme_tcp_lookup_data_request(packet_info *pinfo,
        struct nvme_q_ctx *q_ctx,
        guint16 cmd_id)
{
    wmem_tree_key_t cmd_key[3];
    guint32 cmd_id_key = cmd_id;

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
                          guint32 data_offset)
{
    struct nvme_tcp_cmd_ctx *cmd_ctx;
    guint16 cmd_id;
    guint32 data_length;
    tvbuff_t *nvme_data;
    const gchar *cmd_string;

    cmd_id = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
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

    nvme_publish_data_pdu_to_cmd_link(nvme_tcp_tree, tvb,
                hf_nvme_tcp_cmd_pkt, &cmd_ctx->n_cmd_ctx);

    /* fabrics commands should not have h2cdata*/
    if (cmd_ctx->n_cmd_ctx.fabric) {
        cmd_string = val_to_str_const(cmd_ctx->fctype, nvme_fabrics_cmd_type_vals,
                "Unknown FcType");
        proto_item_append_text(nvme_tcp_ti,
                ", H2CData Fabrics Type: %s (0x%02x), Cmd ID: 0x%04x, Len: %u",
                cmd_string, cmd_ctx->fctype, cmd_id, data_length);
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
            &cmd_ctx->n_cmd_ctx, data_length);
}

static void
dissect_nvme_tcp_h2ctermreq(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, guint32 packet_len, int offset)
{
    proto_item *tf;
    proto_item *h2ctermreq_tree;
    guint16 fes;

    col_set_str(pinfo->cinfo, COL_INFO,
                "Host to Controller Termination Request");
    tf = proto_tree_add_item(tree, hf_nvme_tcp_h2ctermreq,
                             tvb, offset, 8, ENC_NA);
    h2ctermreq_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(h2ctermreq_tree, hf_nvme_tcp_h2ctermreq_fes,
                        tvb, offset + 8, 2, ENC_LITTLE_ENDIAN);
    fes = tvb_get_guint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
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
                            proto_tree *tree, guint32 packet_len, int offset)
{
    proto_item *tf;
    proto_item *c2htermreq_tree;
    guint16 fes;

    col_set_str(pinfo->cinfo, COL_INFO,
                "Controller to Host Termination Request");
    tf = proto_tree_add_item(tree, hf_nvme_tcp_c2htermreq,
                             tvb, offset, 8, ENC_NA);
    c2htermreq_tree = proto_item_add_subtree(tf, ett_nvme_tcp);

    proto_tree_add_item(tree, hf_nvme_tcp_c2htermreq_fes, tvb, offset + 8, 2,
                        ENC_LITTLE_ENDIAN);
    fes = tvb_get_guint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
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
    guint16 cmd_id;
    const gchar *cmd_string;

    cmd_id = tvb_get_guint16(tvb, offset + 12, ENC_LITTLE_ENDIAN);

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
        cmd_string = val_to_str_const(cmd_ctx->fctype, nvme_fabrics_cmd_type_vals,
                "Unknown Cmd");
        proto_item_append_text(ti,
                ", Cqe Fabrics Cmd: %s (0x%02x) Cmd ID: 0x%04x", cmd_string,
                cmd_ctx->fctype, cmd_id);

        dissect_nvme_fabric_cqe(tvb, pinfo, nvme_tree, cmd_ctx, cmd_string,
                offset);
    } else {
        tvbuff_t *nvme_tvb;
        proto_item_set_len(ti, NVME_TCP_HEADER_SIZE);
        cmd_string = nvme_get_opcode_string(cmd_ctx->n_cmd_ctx.opcode,
                queue->n_q_ctx.qid);

        proto_item_append_text(ti, ", Cqe NVMe Cmd: %s (0x%02x) Cmd ID: 0x%04x",
                cmd_string, cmd_ctx->n_cmd_ctx.opcode, cmd_id);
        /* get incapsuled nvme command */
        nvme_tvb = tvb_new_subset_remaining(tvb, NVME_TCP_HEADER_SIZE);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " | ", "NVMe %s: Response",
                cmd_string);
        dissect_nvme_cqe(nvme_tvb, pinfo, root_tree, &cmd_ctx->n_cmd_ctx);
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
    guint packet_type;
    guint8 hlen, pdo;
    guint8 pdu_flags;
    guint32 plen;
    guint32 incapsuled_data_size;
    guint32 pdu_data_offset = 0;

    conversation = find_or_create_conversation(pinfo);
    q_ctx = (struct nvme_tcp_q_ctx *)
            conversation_get_proto_data(conversation, proto_nvme_tcp);

    if (!q_ctx) {
        q_ctx = (struct nvme_tcp_q_ctx *) wmem_alloc0(wmem_file_scope(),
                sizeof(struct nvme_tcp_q_ctx));
        q_ctx->n_q_ctx.pending_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.done_cmds = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_requests = wmem_tree_new(wmem_file_scope());
        q_ctx->n_q_ctx.data_responses = wmem_tree_new(wmem_file_scope());
        /* Initially set to non-0 so that by default queues are io queues
         * this is required to be able to dissect correctly even
         * if we miss connect command*/
        q_ctx->n_q_ctx.qid = G_MAXUINT16;
        conversation_add_proto_data(conversation, proto_nvme_tcp, q_ctx);
    }

    ti = proto_tree_add_item(tree, proto_nvme_tcp, tvb, 0, -1, ENC_NA);
    nvme_tcp_tree = proto_item_add_subtree(ti, ett_nvme_tcp);

    if (q_ctx->n_q_ctx.qid != G_MAXUINT16)
        nvme_publish_qid(nvme_tcp_tree, hf_nvme_fabrics_cmd_qid,
                q_ctx->n_q_ctx.qid);

    packet_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_type, tvb, offset, 1,
            ENC_NA);

    pdu_flags = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_bitmask_value(nvme_tcp_tree, tvb, 0, hf_nvme_tcp_flags,
            ett_nvme_tcp, nvme_tcp_pdu_flags, (guint64)pdu_flags);

    hlen = tvb_get_gint8(tvb, offset + 2);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_hlen, tvb, offset + 2, 1,
            ENC_NA);

    pdo = tvb_get_gint8(tvb, offset + 3);
    proto_tree_add_uint(nvme_tcp_tree, hf_nvme_tcp_pdo, tvb, offset + 3, 1,
            pdo);
    plen = tvb_get_letohl(tvb, offset + 4);
    proto_tree_add_item(nvme_tcp_tree, hf_nvme_tcp_plen, tvb, offset + 4, 4,
            ENC_LITTLE_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NVME_FABRICS_TCP);

    if (pdu_flags & NVME_TCP_F_HDGST) {
        guint hdgst_flags = PROTO_CHECKSUM_NO_FLAGS;
        guint32 crc = 0;

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
        guint ddgst_flags = PROTO_CHECKSUM_NO_FLAGS;
        guint32 crc = 0;

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
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, NVME_TCP_HEADER_SIZE,
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
           { "PDU Data Digest", "nvme-tcp.hdgst",
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
           { "Maximum data capsules per r2t supported",
                   "nvme-tcp.icresp.maxdata",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
       /* NVMe tcp c2h/h2c termreq fields */
       { &hf_nvme_tcp_c2htermreq,
           { "C2HTermReq", "nvme-tcp.c2htermreq",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_fes,
           { "Fatal error status", "nvme-tcp.c2htermreq.fes",
             FT_UINT16, BASE_HEX, VALS(nvme_tcp_termreq_fes),
             0xffff, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_phfo,
           { "PDU header field offset", "nvme-tcp.c2htermreq.phfo",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_phd,
           { "PDU header digest", "nvme-tcp.c2htermreq.phd",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_c2htermreq_upfo,
           { "Unsupported pararmeter field offset", "nvme-tcp.c2htermreq.upfo",
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
             0xffff, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_phfo,
           { "PDU header field offset", "nvme-tcp.h2ctermreq.phfo",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_phd,
           { "PDU header digest", "nvme-tcp.h2ctermreq.phd",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_upfo,
           { "Unsupported pararmeter field offset", "nvme-tcp.h2ctermreq.upfo",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_reserved,
           { "Reserved", "nvme-tcp.h2ctermreq.reserved",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
       { &hf_nvme_tcp_h2ctermreq_data,
           { "Terminated PDU header", "nvme-tcp.h2ctermreq.data",
             FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
       /* NVMe fabrics command */
       { &hf_nvme_fabrics_cmd,
           { "NVM Express Fabrics (Cmd)", "nvme-tcp.cmd",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_opc,
           { "Opcode", "nvme-tcp.cmd.opc",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_rsvd1,
           { "Reserved", "nvme-tcp.cmd.rsvd",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_cid,
           { "Command ID", "nvme-tcp.cmd.cid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_fctype,
           { "Fabric Cmd Type", "nvme-tcp.cmd.fctype",
            FT_UINT8, BASE_HEX, VALS(nvme_fabrics_cmd_type_vals),
            0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_generic_rsvd1,
           { "Reserved", "nvme-tcp.cmd.generic.rsvd1",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_generic_field,
           { "Fabric Cmd specific field", "nvme-tcp.cmd.generic.field",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

       /* NVMe connect command fields */
       { &hf_nvme_fabrics_cmd_connect_rsvd2,
           { "Reserved","nvme-tcp.cmd.connect.rsvd1",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_sgl1,
           { "SGL1", "nvme-tcp.cmd.connect.sgl1",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_recfmt,
           { "Record Format", "nvme-tcp.cmd.connect.recfmt",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_qid,
           { "Queue ID", "nvme-tcp.cmd.connect.qid",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_sqsize,
           { "SQ Size", "nvme-tcp.cmd.connect.sqsize",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_cattr,
           { "Connect Attributes", "nvme-tcp.cmd.connect.cattr",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       {&hf_nvme_fabrics_cmd_connect_rsvd3,
           { "Reserved", "nvme-tcp.cmd.connect.rsvd2",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_kato,
           { "Keep Alive Timeout", "nvme-tcp.cmd.connect.kato",
             FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
             &units_milliseconds, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_rsvd4,
           { "Reserved", "nvme-tcp.cmd.connect.rsvd4", FT_BYTES,
             BASE_NONE, NULL, 0x0, NULL, HFILL } },
       /* NVMe command data */
       { &hf_nvme_fabrics_cmd_data,
           { "Data", "nvme-tcp.cmd.data",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_data_hostid,
           { "Host Identifier",
             "nvme-tcp.cmd.connect.data.hostid", FT_GUID,
             BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_data_cntlid,
           { "Controller ID", "nvme-tcp.cmd.connect.data.cntrlid",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_data_rsvd4,
           { "Reserved", "nvme-tcp.cmd.connect.data.rsvd4",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_data_subnqn,
           { "Subsystem NQN", "nvme-tcp.cmd.connect.data.subnqn",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_data_hostnqn,
           { "Host NQN", "nvme-tcp.cmd.connect.data.hostnqn",
             FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_connect_data_rsvd5,
           { "Reserved", "nvme-tcp.cmd.connect.data.rsvd5",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_tcp_unknown_data,
           { "Unknown Data", "nvme-tcp.unknown_data",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_rsvd1,
           { "Reserved", "nvme-tcp.cmd.prop_attr.rsvd1",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_rsvd2,
           { "Reserved", "nvme-tcp.cmd.prop_attr.rsvd2",
             FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_size,
           { "Property Size", "nvme-tcp.cmd.prop_attr.size",
             FT_UINT8, BASE_HEX, NULL, 0x7, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_rsvd3,
           { "Reserved", "nvme-tcp.cmd.prop_attr.rsvd3",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_offset,
           { "Offset", "nvme-tcp.cmd.prop_attr.offset",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_get_rsvd4,
           { "Reserved", "nvme-tcp.cmd.prop_attr.get.rsvd4",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_set_4B_value,
           { "Value", "nvme-tcp.cmd.prop_attr.set.value.4B",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_set_4B_value_rsvd,
           { "Reserved", "nvme-tcp.cmd.prop_attr.set.value.rsvd",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_set_8B_value,
           { "Value", "nvme-tcp.cmd.prop_attr.set.value.8B",
             FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_prop_attr_set_rsvd3,
           { "Reserved", "nvme-tcp.cmd.prop_attr.set.rsvd3",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       /* NVMe Response fields */
       { &hf_nvme_fabrics_cqe,
           { "Cqe", "nvme-tcp.cqe",
             FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_sts,
           { "Cmd specific Status", "nvme-tcp.cqe.sts",
             FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_sqhd,
           { "SQ Head Pointer", "nvme-tcp.cqe.sqhd",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_rsvd,
           { "Reserved", "nvme-tcp.cqe.rsvd",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_status,
           { "Status", "nvme-tcp.cqe.status",
             FT_UINT16, BASE_HEX, NULL, 0xfffe, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_status_rsvd,
           { "Reserved", "nvme-tcp.cqe.status.rsvd",
             FT_UINT16, BASE_HEX, NULL, 0x1, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_connect_cntlid,
           { "Controller ID", "nvme-tcp.cqe.connect.cntrlid",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_connect_authreq,
           { "Authentication Required", "nvme-tcp.cqe.connect.authreq",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_connect_rsvd,
           { "Reserved", "nvme-tcp.cqe.connect.rsvd",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cqe_prop_set_rsvd,
           { "Reserved", "nvme-tcp.cqe.prop_set.rsvd",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
       { &hf_nvme_fabrics_cmd_pkt,
           { "Fabric Cmd in", "nvme-tcp.cmd_pkt",
             FT_FRAMENUM, BASE_NONE, NULL, 0,
             "The Cmd for this transaction is in this frame", HFILL } },
       { &hf_nvme_tcp_cmd_pkt,
            { "Cmd in", "nvme-tcp.cmd_pkt",
              FT_FRAMENUM, BASE_NONE, NULL, 0,
              "The Cmd for this transaction is in this frame", HFILL } },
       { &hf_nvme_fabrics_cqe_pkt,
           { "Fabric Cqe in", "nvme-tcp.cqe_pkt",
             FT_FRAMENUM, BASE_NONE, NULL, 0,
             "The Cqe for this transaction is in this frame", HFILL } },
       { &hf_nvme_fabrics_cmd_latency,
           { "Cmd Latency", "nvme-tcp.cmd_latency",
             FT_DOUBLE, BASE_NONE, NULL, 0x0,
             "The time between the command and completion, in usec", HFILL } },
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

    static gint *ett[] = {
        &ett_nvme_tcp
    };

    proto_nvme_tcp = proto_register_protocol("NVM Express Fabrics TCP",
            NVME_FABRICS_TCP, "nvme-tcp");

    proto_register_field_array(proto_nvme_tcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    nvmet_tcp_handle = register_dissector("nvme-tcp", dissect_nvme_tcp,
            proto_nvme_tcp);
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
    dissector_add_uint_range("tcp.port", gPORT_RANGE, nvmet_tcp_handle);
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
