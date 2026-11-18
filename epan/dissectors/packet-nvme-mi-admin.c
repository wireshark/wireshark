/* packet-nvme-mi-admin.c
 * NVMe-MI Admin Command dissector (NMIMT=2, NVMe-MI 2.2 section 6)
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
 * The request carries a 64-byte SQE; CDW10-15 are decoded by packet-nvme.c
 * and only the MI-specific bytes 24-39 here (NVMe-MI 2.2 Figure 139).
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-nvme.h"
#include "packet-tcg-storage.h"
#include "packet-nvme-mi.h"

void proto_register_nvme_mi_admin(void);
void proto_reg_handoff_nvme_mi_admin(void);

static int proto_nvme_mi_admin;

static dissector_handle_t nvme_mi_admin_handle;

static int hf_nvme_mi_admin_opcode;
static int hf_nvme_mi_admin_rae_handling;
static int hf_nvme_mi_admin_status;
static int hf_nvme_mi_admin_flags;
static int hf_nvme_mi_admin_flags_dlenv;
static int hf_nvme_mi_admin_flags_dofstv;
static int hf_nvme_mi_admin_flags_ish;
static int hf_nvme_mi_admin_flags_reserved;
static int hf_nvme_mi_admin_ctrl_id;
static int hf_nvme_mi_admin_nsid;
static int hf_nvme_mi_admin_cdw2;
static int hf_nvme_mi_admin_cdw3;
static int hf_nvme_mi_admin_mptr;
static int hf_nvme_mi_admin_doff;
static int hf_nvme_mi_admin_dlen;
static int hf_nvme_mi_admin_resv0;
static int hf_nvme_mi_admin_resv1;
static int hf_nvme_mi_admin_reserved;
static int hf_nvme_mi_admin_resp_rsvd;
static int hf_nvme_mi_admin_data;
static int hf_nvme_mi_admin_data_excess;
static int hf_nvme_mi_admin_surplus;
static int hf_nvme_mi_admin_cqe_dw0;
static int hf_nvme_mi_admin_cqe_dw1;
static int hf_nvme_mi_admin_cqe_dw3;
static int hf_nvme_mi_admin_cqe_dw3_cid;
static int hf_nvme_mi_admin_tper_reset_applied;
static int hf_nvme_mi_admin_security_state_integrity;

static int ett_nvme_mi_admin;
static int ett_nvme_mi_admin_flags;
static int ett_nvme_mi_admin_reserved;
static int ett_nvme_mi_admin_sqe;
static int ett_nvme_mi_admin_data;

static expert_field ei_nvme_mi_admin_truncated;
static expert_field ei_nvme_mi_admin_orphan_response;
static expert_field ei_nvme_mi_admin_short_cqe;
static expert_field ei_nvme_mi_admin_prohibited_opcode;
static expert_field ei_nvme_mi_admin_prohibited_lid;
static expert_field ei_nvme_mi_admin_prohibited_fid;
static expert_field ei_nvme_mi_admin_reserved_opcode;
static expert_field ei_nvme_mi_admin_unexpected_request_data;
static expert_field ei_nvme_mi_admin_meb_inline_data;
static expert_field ei_nvme_mi_admin_invalid_dofst;
static expert_field ei_nvme_mi_admin_invalid_dlen;
static expert_field ei_nvme_mi_admin_short_response;
static expert_field ei_nvme_mi_admin_unexpected_response_data;
static expert_field ei_nvme_mi_admin_error_surplus;
static expert_field ei_nvme_mi_admin_cid_nonzero;

/* Command Flags (NVMe-MI 2.2 Figure 139); DLENV/DOFSTV are not used. */
#define NVME_MI_ADMIN_FLAG_DLENV  0x01
#define NVME_MI_ADMIN_FLAG_DOFSTV 0x02
#define NVME_MI_ADMIN_FLAG_ISH    0x04

/* Request context kept in nvme_mi_transaction.body_ctx for the response. */
struct nvme_mi_admin_req_ctx {
    struct nvme_cmd_ctx cmd;
    uint32_t dofst;    /* Data Offset (NVMe-MI 2.2 Figure 139) */
    uint32_t dlen;     /* Data Length (NVMe-MI 2.2 Figure 139) */
    bool window_valid; /* Response Data in a window meeting Figure 139 */
    bool no_response_data; /* DTD 00b/01b, or Get Features SEL 011b */
    /* Security Send/Receive transfer contract, without integrity. */
    bool security_contract_valid;
    bool request_data_complete; /* All Request Data captured */
};

/* Admin opcodes Prohibited over the out-of-band mechanism (NVMe-MI 2.2
 * Figure 137). */
static bool
nvme_mi_admin_opcode_prohibited(uint8_t opcode)
{
    static const uint8_t prohibited[] = {
        NVME_AQ_OPC_DELETE_SQ, NVME_AQ_OPC_CREATE_SQ, NVME_AQ_OPC_DELETE_CQ,
        NVME_AQ_OPC_CREATE_CQ, NVME_AQ_OPC_ABORT, NVME_AQ_OPC_ASYNC_EVE_REQ,
        NVME_AQ_OPC_KEEP_ALIVE, NVME_AQ_OPC_DIRECTIVE_SEND,
        NVME_AQ_OPC_DIRECTIVE_RECV, NVME_AQ_OPC_MI_SEND, NVME_AQ_OPC_MI_RECV,
        NVME_AQ_OPC_DISC_INFO_MGMT, NVME_AQ_OPC_FABRIC_ZONING_RECV,
        NVME_AQ_OPC_FABRIC_ZONING_LOOKUP, NVME_AQ_OPC_FABRIC_ZONING_SEND,
        NVME_AQ_OPC_CROSS_CTRL_RESET, NVME_AQ_OPC_SEND_DISC_LOG_PAGE,
        NVME_AQ_OPC_TRACK_SEND, NVME_AQ_OPC_TRACK_RECV,
        NVME_AQ_OPC_MIGRATION_SEND, NVME_AQ_OPC_MIGRATION_RECV,
        NVME_AQ_OPC_CTRL_DATA_QUEUE, NVME_AQ_OPC_DBBUF_CONFIG, NVME_FABRIC_OPC,
        NVME_AQ_OPC_LOAD_PROGRAM, NVME_AQ_OPC_PROG_ACTIVATION_MGMT,
        NVME_AQ_OPC_MEM_RANGE_SET_MGMT,
    };

    for (unsigned i = 0; i < array_length(prohibited); i++) {
        if (prohibited[i] == opcode)
            return true;
    }
    return false;
}

/* MI 2.2 Figure 144: prohibited on every Management Endpoint. */
static bool
nvme_mi_admin_lid_prohibited(uint8_t lid)
{
    return lid == 0x1e || lid == 0x1f;
}

/* MI 2.2 Figure 148: Set Features prohibited on every Management Endpoint.
 * 19h and 1Ch are prohibited only on an Enclosure, which a capture does not
 * establish, so they are not flagged. */
static bool
nvme_mi_admin_set_fid_prohibited(uint8_t fid)
{
    switch (fid) {
    case 0x01: case 0x03: case 0x05: case 0x06: case 0x07: case 0x08:
    case 0x09: case 0x0a: case 0x0b: case 0x0d: case 0x0f: case 0x12:
    case 0x13: case 0x14: case 0x15: case 0x16: case 0x18: case 0x1d:
    case 0x1e: case 0x21: case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85:
        return true;
    default:
        return false;
    }
}

/* Base 2.3 Figure 142: opcode bits 1:0 give the data transfer direction. */
enum nvme_mi_admin_transfer {
    ADMIN_TRANSFER_NONE,
    ADMIN_TRANSFER_REQUEST,
    ADMIN_TRANSFER_RESPONSE,
    ADMIN_TRANSFER_BIDIRECTIONAL
};

/* Base 2.4 Figure 92: a command transfers data as its options specify, or
 * none, so whether DLEN may be 0h depends on the command dwords. */
enum nvme_mi_admin_data_rule {
    ADMIN_DATA_UNKNOWN, /* not decidable from the dwords: no check */
    ADMIN_DATA_NONE,    /* no data: DLEN shall be 0h */
    ADMIN_DATA_SOME,    /* data: DLEN shall not be 0h */
    ADMIN_DATA_EXACT,   /* Request Data of a required length */
};

/* *get_size: the fixed Get Features completion data size, else 0. */
static enum nvme_mi_admin_data_rule
nvme_mi_admin_data_rule(tvbuff_t *tvb, uint8_t opcode, uint64_t *required,
                        const char **what, uint32_t *get_size)
{
    uint32_t cdw10 = tvb_get_letohl(tvb, 40);
    uint32_t cdw11 = tvb_get_letohl(tvb, 44);
    uint32_t sel8 = cdw10 & 0xff;

    *get_size = 0;

    switch (opcode) {
    case NVME_AQ_OPC_FW_IMG_DOWNLOAD:
        /* Base 2.4 Figure 191: NUMD is 0's based. */
        *required = ((uint64_t)cdw10 + 1) * 4;
        *what = "Firmware Image Download NUMD";
        return ADMIN_DATA_EXACT;
    case NVME_AQ_OPC_NS_ATTACH:
        /* Base 2.4 Figure 443: Attach and Detach carry a 4096-byte Controller
         * List. */
        if ((cdw10 & 0xf) > 1)
            return ADMIN_DATA_UNKNOWN;
        *required = 4096;
        *what = "Namespace Attachment Controller List";
        return ADMIN_DATA_EXACT;
    case NVME_AQ_OPC_NS_MGMT:
        /* Base 2.4 Figures 446, 448: only Create transfers a data structure. */
        switch (cdw10 & 0xf) {
        case 0x0:
            *required = 4096;
            *what = "Namespace Management Create data structure";
            return ADMIN_DATA_EXACT;
        case 0x1:
        case 0x2:
            *what = "Namespace Management Delete or Restore";
            return ADMIN_DATA_NONE;
        default:
            return ADMIN_DATA_UNKNOWN;
        }
    case NVME_AQ_OPC_CREATE_EXP_NVM_SUBSYS:
        /* Base 2.4 Figure 375: SEL 00h-05h return data; 06h+ reserved or VS. */
        *what = "Manage Exported NVM Subsystem Receive SEL";
        return sel8 <= 0x05 ? ADMIN_DATA_SOME : ADMIN_DATA_UNKNOWN;
    case NVME_AQ_OPC_MANAGE_EXP_NVM_SUBSYS:
        /* Base 2.4 Figures 397-398: Delete names the subsystem in the data
         * buffer only while ESUBIDV is cleared. */
        *what = "Manage Exported NVM Subsystem Send SEL";
        if (sel8 == 0x01)
            return (tvb_get_letohl(tvb, 56) & 0x80) ? ADMIN_DATA_UNKNOWN
                                                    : ADMIN_DATA_SOME;
        return (sel8 >= 0x02 && sel8 <= 0x06) ? ADMIN_DATA_SOME
                                              : ADMIN_DATA_UNKNOWN;
    case NVME_AQ_OPC_MANAGE_EXP_NS:
        /* Base 2.4 Figures 369, 372 and 373. */
        *what = "Manage Exported Namespace SEL";
        return (sel8 == 0x01 || sel8 == 0x02) ? ADMIN_DATA_SOME
                                              : ADMIN_DATA_UNKNOWN;
    case NVME_AQ_OPC_MANAGE_EXP_PORT:
        /* Base 2.4 Figure 618. */
        *what = "Manage Exported Port SEL";
        return (sel8 == 0x01 || sel8 == 0x02) ? ADMIN_DATA_SOME
                                              : ADMIN_DATA_UNKNOWN;
    case NVME_AQ_OPC_SECURITY_SEND:
        /* Base 2.4 Figure 462: TL as in SPC-5, where 0h transfers no data. */
        *required = cdw11;
        *what = "Security Send Transfer Length";
        return ADMIN_DATA_EXACT;
    case NVME_AQ_OPC_SECURITY_RECV:
        /* Base 2.4 Figure 458: AL 0h transfers no data (SPC-5). */
        *what = "Security Receive Allocation Length";
        return cdw11 ? ADMIN_DATA_SOME : ADMIN_DATA_UNKNOWN;
    case NVME_AQ_OPC_GET_LBA_STATUS:
        /* NVM CS 1.3 Figure 137: MNDW is 0's based. */
        *what = "Get LBA Status MNDW";
        return ADMIN_DATA_SOME;
    case NVME_AQ_OPC_SET_FEATURES:
    case NVME_AQ_OPC_GET_FEATURES: {
        bool get = opcode == NVME_AQ_OPC_GET_FEATURES;
        uint32_t sz;

        *what = get ? "Get Features FID and SEL" : "Set Features FID";
        switch (nvme_feature_transfer((uint8_t)sel8, get, (cdw10 >> 8) & 0x7,
                                      cdw11, tvb_get_letohl(tvb, 52), &sz)) {
        case NVME_FEAT_XFER_NONE:
            return ADMIN_DATA_NONE;
        case NVME_FEAT_XFER_DATA:
            if (!get && sz) {
                *required = sz;
                return ADMIN_DATA_EXACT;
            }
            if (get)
                *get_size = sz;
            return ADMIN_DATA_SOME;
        default:
            return ADMIN_DATA_UNKNOWN;
        }
    }
    default:
        return ADMIN_DATA_UNKNOWN;
    }
}

/* Hide the raw item when the "Data" subtree decoded something, else hide
 * the empty subtree. */
static void
nvme_mi_admin_hide_raw_or_structured(proto_item *raw_it, proto_item *sub_it,
                                     proto_tree *data_tree, bool handled)
{
    bool rendered = nvme_data_tree_has_fields(data_tree);

    if (handled && rendered)
        proto_item_set_hidden(raw_it);
    else if (!rendered)
        proto_item_set_hidden(sub_it);
}

static void
nvme_mi_admin_mark_security_state_integrity(proto_tree *admin_tree, tvbuff_t *tvb)
{
    proto_item *marker = proto_tree_add_boolean(admin_tree,
        hf_nvme_mi_admin_security_state_integrity, tvb, 0, 0, TRUE);
    proto_item_set_generated(marker);
    proto_item_set_hidden(marker);
}

/* SIIS 1.20 Table 24: AL counts bytes for SECP 00h-03h only. */
static bool
nvme_mi_admin_secp_al_is_bytes(uint8_t secp)
{
    return secp <= 0x03;
}

/* Security Send/Receive request: record the transfer contract and the TCG
 * scope (MI 2.2 Figure 139).  Returns true for an invalid Security Send. */
static bool
nvme_mi_admin_security_req(tvbuff_t *tvb, proto_tree *admin_tree,
                           struct nvme_mi_admin_req_ctx *req,
                           struct nvme_mi_transaction *trans, uint16_t ctlid,
                           unsigned len, bool integrity_ok, bool meb)
{
    bool send = req->cmd.opcode == NVME_AQ_OPC_SECURITY_SEND;
    bool send_invalid = false;
    uint32_t xfer_len = req->cmd.cmd_ctx.security.xfer_len;

    req->cmd.cmd_ctx.security.scope = trans ? trans->endpoint : NULL;
    req->cmd.cmd_ctx.security.controller = ctlid;
    if (send) {
        send_invalid = req->dofst != 0 ||
            (!meb && req->dlen != len - 64) ||
            req->dlen != xfer_len || req->dlen == 0 || (req->dlen & 3) ||
            req->dlen > 4096;
        req->security_contract_valid = !send_invalid;
    } else {
        /* AL is an allocation limit, not the actual completion-data size;
         * for SECP 00h-03h it bounds the Figure 139 window from above. */
        req->security_contract_valid =
            !(req->dofst & 3) && !(req->dlen & 3) &&
            req->dlen != 0 && req->dlen <= 4096 &&
            req->dofst < xfer_len && (uint64_t)req->dofst + req->dlen <= xfer_len;
        req->window_valid = req->window_valid && req->dofst < xfer_len &&
                            (uint64_t)req->dofst + req->dlen <= xfer_len;
    }
    req->cmd.cmd_ctx.security.state_valid =
        integrity_ok && req->security_contract_valid;
    req->request_data_complete = !meb && tvb_captured_length(tvb) >= len;
    if (send && len > 64 && !integrity_ok &&
        req->cmd.cmd_ctx.security.scope && req->security_contract_valid &&
        req->request_data_complete &&
        tcg_storage_selector_may_advance_state(true,
            req->cmd.cmd_ctx.security.secp, req->cmd.cmd_ctx.security.spsp))
        nvme_mi_admin_mark_security_state_integrity(admin_tree, tvb);
    return send_invalid;
}

/* Security Send completion without Response Data: a TPer Reset (Opal SSC
 * 2.30 3.2.3) resets the TCG state of its scope. */
static void
nvme_mi_admin_security_send_completed(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *admin_tree,
                                      struct nvme_mi_admin_req_ctx *req,
                                      bool mics_ok)
{
    struct nvme_security_info sec = nvme_security_info_of(&req->cmd, true);

    sec.state_valid &= mics_ok;
    /* TCG applies the reset on the first pass only. */
    if (!tcg_storage_security_send_completed(pinfo, &sec, true))
        return;
    proto_item *applied = proto_tree_add_boolean(admin_tree,
        hf_nvme_mi_admin_tper_reset_applied, tvb, 0, 0, sec.state_valid);
    proto_item_set_generated(applied);
    if (!mics_ok)
        nvme_mi_admin_mark_security_state_integrity(admin_tree, tvb);
}

/* A Security Send completed with an error transfers no data (SIIS 1.20
 * Table 25), so TCG undoes what its request advanced.  Only a trusted
 * response decides, and a Replay only when it is the response of record:
 * the original was never seen, or was a More Processing Required. */
static void
nvme_mi_admin_security_send_failed(packet_info *pinfo,
                                   const struct nvme_mi_transaction *trans,
                                   const struct nvme_mi_admin_req_ctx *req,
                                   bool replay, bool integrity_ok)
{
    if (req && !replay && integrity_ok &&
        req->cmd.opcode == NVME_AQ_OPC_SECURITY_SEND &&
        req->cmd.cmd_ctx.security.state_valid)
        tcg_storage_security_send_failed(pinfo, trans->req_frame, 0);
}

/* An Abort answered with CPAS 01b ended 'trans' before it affected the NVM
 * Subsystem (NVMe-MI 'Control Primitives'), so a Security Send in it did
 * nothing, as one that failed. */
void
nvme_mi_admin_command_aborted(packet_info *pinfo,
                              const struct nvme_mi_transaction *trans)
{
    if (trans->nmimt == NVME_MI_TYPE_ADMIN && trans->req_integrity_ok)
        nvme_mi_admin_security_send_failed(pinfo, trans, trans->body_ctx,
                                           false, true);
}

/* Security Send/Receive Response Data: narrow the request's state
 * eligibility to this response.  A Replay never advances TCG state. */
static void
nvme_mi_admin_security_resp(tvbuff_t *tvb, proto_tree *admin_tree,
                            const struct nvme_mi_admin_req_ctx *req,
                            struct nvme_cmd_ctx *data_cmd, bool completion_ok,
                            bool mics_ok, unsigned data_len, unsigned sel_len)
{
    /* Figure 139: DLEN selects exactly the bytes returned. */
    bool response_ok = completion_ok && data_len == req->dlen;
    data_cmd->cmd_ctx.security.state_valid =
        req->cmd.cmd_ctx.security.state_valid && mics_ok && response_ok;
    if (req->cmd.opcode == NVME_AQ_OPC_SECURITY_RECV &&
        response_ok && !mics_ok && !req->dofst &&
        req->security_contract_valid &&
        req->cmd.cmd_ctx.security.scope &&
        tvb_captured_length(tvb) >= 16 + sel_len &&
        tcg_storage_selector_may_advance_state(false,
            req->cmd.cmd_ctx.security.secp,
            req->cmd.cmd_ctx.security.spsp))
        nvme_mi_admin_mark_security_state_integrity(admin_tree, tvb);
}

static int
dissect_nvme_mi_admin_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *admin_tree,
                              proto_item *it, unsigned len,
                              struct nvme_mi_transaction *trans, bool integrity_ok,
                              bool meb)
{
    static int * const nvme_mi_admin_flags[] = {
        &hf_nvme_mi_admin_flags_ish,
        &hf_nvme_mi_admin_flags_dofstv,
        &hf_nvme_mi_admin_flags_dlenv,
        NULL,
    };

    if (len < 1) {
        expert_add_info(pinfo, it, &ei_nvme_mi_admin_truncated);
        return tvb_captured_length(tvb);
    }

    uint8_t opcode;
    proto_item *opc_it;
    opc_it = proto_tree_add_item_ret_uint8(admin_tree, hf_nvme_mi_admin_opcode,
                                           tvb, 0, 1, ENC_NA, &opcode);
    const char *opname = nvme_get_opcode_string(opcode, 0);
    proto_item_append_text(opc_it, " (%s)", opname);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", opname);
    if (nvme_mi_admin_opcode_prohibited(opcode))
        expert_add_info(pinfo, opc_it, &ei_nvme_mi_admin_prohibited_opcode);
    else if (nvme_admin_opcode_is_reserved(opcode))
        expert_add_info(pinfo, opc_it, &ei_nvme_mi_admin_reserved_opcode);

    /* The message must report the full 64-byte SQE. */
    if (len < 64) {
        nvme_mi_dissect_truncated(tvb, pinfo, admin_tree, it,
                                  &ei_nvme_mi_admin_truncated,
                                  hf_nvme_mi_admin_data, 1);
        return tvb_captured_length(tvb);
    }

    uint8_t sel_id = tvb_get_uint8(tvb, 40); /* LID or FID */
    if (opcode == NVME_AQ_OPC_GET_LOG_PAGE) {
        if (nvme_mi_admin_lid_prohibited(sel_id))
            expert_add_info(pinfo, opc_it, &ei_nvme_mi_admin_prohibited_lid);
        /* Endpoint policy, not an anomaly: shown on CDW10, not as an
         * expert info. */
        proto_item *rae_it = proto_tree_add_string(admin_tree,
            hf_nvme_mi_admin_rae_handling, tvb, 40, 4,
            "Management Endpoint ignores RAE; if RAE is supported and this"
            " log page is used with Asynchronous Events, it processes the"
            " command as if RAE=1 (NVMe-MI 'List of NVMe Admin Commands"
            " Supported using the Out-of-Band Mechanism', note 2)");
        proto_item_set_generated(rae_it);
    } else if (opcode == NVME_AQ_OPC_SET_FEATURES &&
             nvme_mi_admin_set_fid_prohibited(sel_id))
        expert_add_info(pinfo, opc_it, &ei_nvme_mi_admin_prohibited_fid);

    /* Parsed into packet scope, published once every selector is read. */
    struct nvme_mi_admin_req_ctx *req =
        wmem_new0(pinfo->pool, struct nvme_mi_admin_req_ctx);
    req->cmd.opcode = opcode;

    /* NVMe-MI envelope fields (NVMe-MI 2.2 Figure 139). */
    uint64_t flags;
    proto_item *flags_it = proto_tree_add_bitmask_ret_uint64(admin_tree, tvb, 1,
                           hf_nvme_mi_admin_flags,
                           ett_nvme_mi_admin_flags, nvme_mi_admin_flags,
                           ENC_NA, &flags);
    /* Not used; ignored by the Management Endpoint in implementations
     * compliant with NVMe-MI later than 1.1 (Figure 139). */
    if (flags & (NVME_MI_ADMIN_FLAG_DOFSTV | NVME_MI_ADMIN_FLAG_DLENV))
        proto_item_append_text(flags_it, " (DOFSTV/DLENV are not used; ignored by"
                               " the Management Endpoint in implementations"
                               " compliant with NVMe-MI later than 1.1)");
    proto_tree_add_item(admin_tree, hf_nvme_mi_admin_flags_reserved,
                        tvb, 1, 1, ENC_NA);

    uint32_t ctlid;
    proto_tree_add_item_ret_uint(admin_tree, hf_nvme_mi_admin_ctrl_id,
                                 tvb, 2, 2, ENC_LITTLE_ENDIAN, &ctlid);
    proto_item *doff_it = proto_tree_add_item_ret_uint(admin_tree,
                                 hf_nvme_mi_admin_doff,
                                 tvb, 24, 4, ENC_LITTLE_ENDIAN, &req->dofst);
    proto_item *dlen_it = proto_tree_add_item_ret_uint(admin_tree,
                                 hf_nvme_mi_admin_dlen,
                                 tvb, 28, 4, ENC_LITTLE_ENDIAN, &req->dlen);
    enum nvme_mi_admin_transfer transfer = (enum nvme_mi_admin_transfer)(opcode & 3);
    /* MI 2.2 Figure 139: DOFST and DLEN are dword-aligned and DLEN is at
     * most 4096; DLEN sizes any Request Data the message carries. */
    bool dlen_flagged = true;
    if (req->dofst & 0x3)
        expert_add_info_format(pinfo, doff_it, &ei_nvme_mi_admin_invalid_dofst,
                               "Data Offset %u is not dword-aligned"
                               " (bits 1:0 must be cleared to 00b)", req->dofst);
    if (req->dlen & 0x3)
        expert_add_info_format(pinfo, dlen_it, &ei_nvme_mi_admin_invalid_dlen,
                               "Data Length %u is not dword-aligned"
                               " (bits 1:0 must be cleared to 00b)", req->dlen);
    else if (req->dlen > 4096)
        expert_add_info_format(pinfo, dlen_it, &ei_nvme_mi_admin_invalid_dlen,
                               "Data Length %u exceeds the 4096-byte maximum",
                               req->dlen);
    else if (!nvme_admin_opcode_is_reserved(opcode) &&
             opcode != NVME_AQ_OPC_GET_FEATURES &&
             opcode != NVME_AQ_OPC_SET_FEATURES &&
             transfer == ADMIN_TRANSFER_NONE && req->dlen != 0)
        expert_add_info_format(pinfo, dlen_it, &ei_nvme_mi_admin_invalid_dlen,
                               "Data Length %u is nonzero for an Admin command"
                               " defined to transfer no data", req->dlen);
    else if (!meb && transfer == ADMIN_TRANSFER_REQUEST && req->dlen > len - 64)
        expert_add_info_format(pinfo, dlen_it, &ei_nvme_mi_admin_invalid_dlen,
                               "Data Length %u must equal the %u-byte NVMe"
                               " Request Data field", req->dlen, len - 64);
    else if (!meb && len - 64 > req->dlen)
        expert_add_info_format(pinfo, dlen_it, &ei_nvme_mi_admin_invalid_dlen,
                               "Data Length %u is shorter than the %u-byte NVMe"
                               " Request Data field the message carries",
                               req->dlen, len - 64);
    else
        dlen_flagged = false;
    bool response_transfer =
        transfer == ADMIN_TRANSFER_RESPONSE ||
        transfer == ADMIN_TRANSFER_BIDIRECTIONAL;
    bool transfer_semantics_known =
        opcode < 0xc0 && !nvme_admin_opcode_is_reserved(opcode) &&
        opcode != NVME_AQ_OPC_GET_FEATURES &&
        opcode != NVME_AQ_OPC_SET_FEATURES;
    /* Set Features never returns Response Data, nor does any command,
     * vendor specific included, with data transfer 00b or 01b (Base 2.4
     * Figure 92). */
    bool dofst_rule_known = transfer_semantics_known ||
                            opcode == NVME_AQ_OPC_SET_FEATURES ||
                            opcode >= 0xc0;
    if (dofst_rule_known && !response_transfer && req->dofst != 0)
        expert_add_info_format(pinfo, doff_it, &ei_nvme_mi_admin_invalid_dofst,
                               "Data Offset %u is nonzero for an Admin command"
                               " that does not transfer Response Data",
                               req->dofst);
    if (len > 64 &&
        (transfer == ADMIN_TRANSFER_NONE ||
         transfer == ADMIN_TRANSFER_RESPONSE)) {
        proto_tree_add_expert(admin_tree, pinfo, &ei_nvme_mi_admin_unexpected_request_data,
                              tvb, 64, tvb_captured_length_remaining(tvb, 64));
    }
    /* A Success Response owes DLEN bytes from a valid window.  Get Features
     * windows are validated against the Feature's size below. */
    req->window_valid = transfer == ADMIN_TRANSFER_RESPONSE &&
                        opcode != NVME_AQ_OPC_GET_FEATURES &&
                        !(req->dofst & 3) && !(req->dlen & 3) &&
                        req->dlen != 0 && req->dlen <= 4096;
    if (transfer_semantics_known && opcode == NVME_AQ_OPC_IDENTIFY) {
        if (req->dofst >= 4096) {
            expert_add_info_format(pinfo, doff_it,
                                   &ei_nvme_mi_admin_invalid_dofst,
                                   "Data Offset %u is outside the 4096-byte"
                                   " Identify completion data", req->dofst);
            req->window_valid = false;
        } else if (req->dlen == 0) {
            expert_add_info_format(pinfo, dlen_it,
                                   &ei_nvme_mi_admin_invalid_dlen,
                                   "Data Length is zero for the 4096-byte"
                                   " Identify completion data");
            req->window_valid = false;
        } else if ((uint64_t)req->dofst + req->dlen > 4096) {
            expert_add_info_format(pinfo, dlen_it,
                                   &ei_nvme_mi_admin_invalid_dlen,
                                   "Data Offset %u plus Data Length %u exceeds"
                                   " the 4096-byte Identify completion data",
                                   req->dofst, req->dlen);
            req->window_valid = false;
        }
    }
    /* Base 2.3 Figures 201 and 202: NUMD, not DLEN, sizes a log page. */
    if (transfer_semantics_known && opcode == NVME_AQ_OPC_GET_LOG_PAGE) {
        uint64_t completion_data_len =
            ((uint64_t)((tvb_get_letohl(tvb, 40) >> 16) |
                        ((tvb_get_letohl(tvb, 44) & 0xffff) << 16)) + 1) * 4;
        if (req->dofst >= completion_data_len) {
            expert_add_info_format(pinfo, doff_it,
                                   &ei_nvme_mi_admin_invalid_dofst,
                                   "Data Offset %u is outside the %"
                                   PRIu64 "-byte Get Log Page completion data",
                                   req->dofst, completion_data_len);
            req->window_valid = false;
        } else if (req->dlen == 0) {
            expert_add_info_format(pinfo, dlen_it,
                                   &ei_nvme_mi_admin_invalid_dlen,
                                   "Data Length is zero for Get Log Page"
                                   " completion data");
            req->window_valid = false;
        } else if ((uint64_t)req->dofst + req->dlen > completion_data_len) {
            expert_add_info_format(pinfo, dlen_it,
                                   &ei_nvme_mi_admin_invalid_dlen,
                                   "Data Offset %u plus Data Length %u exceeds"
                                   " the %" PRIu64 "-byte Get Log Page"
                                   " completion data",
                                   req->dofst, req->dlen, completion_data_len);
            req->window_valid = false;
        }
    }
    /* NVM CS 1.3 Figure 137: MNDW, 0's based, caps the completion data. */
    if (transfer_semantics_known && opcode == NVME_AQ_OPC_GET_LBA_STATUS) {
        uint64_t max_bytes = ((uint64_t)tvb_get_letohl(tvb, 48) + 1) * 4;
        if (req->dofst >= max_bytes) {
            expert_add_info_format(pinfo, doff_it,
                                   &ei_nvme_mi_admin_invalid_dofst,
                                   "Data Offset %u is outside the %" PRIu64
                                   "-byte maximum Get LBA Status completion"
                                   " data", req->dofst, max_bytes);
            req->window_valid = false;
        } else if (!dlen_flagged && req->dlen != 0 &&
                   (uint64_t)req->dofst + req->dlen > max_bytes) {
            expert_add_info_format(pinfo, dlen_it,
                                   &ei_nvme_mi_admin_invalid_dlen,
                                   "Data Offset %u plus Data Length %u exceeds"
                                   " the %" PRIu64 "-byte maximum Get LBA"
                                   " Status completion data",
                                   req->dofst, req->dlen, max_bytes);
            req->window_valid = false;
        }
    }
    /* MI 2.2 Figure 139: DLEN against the data the command dwords define. */
    bool get_window_ok = false;
    uint32_t get_size = 0;
    uint64_t required = 0;
    const char *what = NULL;
    enum nvme_mi_admin_data_rule rule =
        nvme_mi_admin_data_rule(tvb, opcode, &required, &what, &get_size);
    if (!dlen_flagged) {
        switch (rule) {
        case ADMIN_DATA_NONE:
            if (req->dlen != 0)
                expert_add_info_format(pinfo, dlen_it,
                                       &ei_nvme_mi_admin_invalid_dlen,
                                       "Data Length %u is nonzero; the %s"
                                       " transfers no data", req->dlen, what);
            break;
        case ADMIN_DATA_SOME:
            if (req->dlen == 0)
                expert_add_info_format(pinfo, dlen_it,
                                       &ei_nvme_mi_admin_invalid_dlen,
                                       "Data Length is zero; the %s defines a"
                                       " data transfer", what);
            break;
        case ADMIN_DATA_EXACT:
            if (req->dlen != required)
                expert_add_info_format(pinfo, dlen_it,
                                       &ei_nvme_mi_admin_invalid_dlen,
                                       "Data Length %u does not equal the %"
                                       PRIu64 " bytes of NVMe Request Data the"
                                       " %s requires", req->dlen, required,
                                       what);
            break;
        case ADMIN_DATA_UNKNOWN:
            break;
        }
    }
    if (opcode == NVME_AQ_OPC_GET_FEATURES) {
        if (rule == ADMIN_DATA_NONE && req->dofst != 0) {
            expert_add_info_format(pinfo, doff_it,
                                   &ei_nvme_mi_admin_invalid_dofst,
                                   "Data Offset %u is nonzero; the %s returns"
                                   " no Response Data", req->dofst, what);
        } else if (rule == ADMIN_DATA_SOME && get_size) {
            if (req->dofst >= get_size)
                expert_add_info_format(pinfo, doff_it,
                                       &ei_nvme_mi_admin_invalid_dofst,
                                       "Data Offset %u is outside the %u-byte"
                                       " %s completion data", req->dofst,
                                       get_size, what);
            else if (!dlen_flagged && req->dlen != 0 &&
                     (uint64_t)req->dofst + req->dlen > get_size)
                expert_add_info_format(pinfo, dlen_it,
                                       &ei_nvme_mi_admin_invalid_dlen,
                                       "Data Offset %u plus Data Length %u"
                                       " exceeds the %u-byte %s completion"
                                       " data", req->dofst, req->dlen,
                                       get_size, what);
            else if (!dlen_flagged && req->dlen != 0 && !(req->dofst & 3))
                get_window_ok = true;
        }
    }
    req->window_valid |= get_window_ok;
    req->no_response_data = transfer == ADMIN_TRANSFER_REQUEST ||
                            transfer == ADMIN_TRANSFER_NONE ||
                            (opcode == NVME_AQ_OPC_GET_FEATURES &&
                             ((tvb_get_letohl(tvb, 40) >> 8) & 0x7) == 3);
    /* One eight-byte Reserved run with dword aliases (Figure 139). */
    proto_item *reserved = proto_tree_add_item(admin_tree, hf_nvme_mi_admin_reserved,
                                               tvb, 32, 8, ENC_LITTLE_ENDIAN);
    proto_tree *reserved_tree = proto_item_add_subtree(reserved, ett_nvme_mi_admin_reserved);
    proto_tree_add_item(reserved_tree, hf_nvme_mi_admin_resv0,
                        tvb, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(reserved_tree, hf_nvme_mi_admin_resv1,
                        tvb, 36, 4, ENC_LITTLE_ENDIAN);

    /* The tunneled SQE, labelled as in packet-nvme.c. */
    proto_tree *sqe_tree = proto_tree_add_subtree(admin_tree, tvb, 0, 64,
                                                  ett_nvme_mi_admin_sqe, NULL,
                                                  "Submission Queue Entry");
    proto_tree_add_item(sqe_tree, hf_nvme_mi_admin_nsid,
                        tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sqe_tree, hf_nvme_mi_admin_cdw2,
                        tvb, 8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sqe_tree, hf_nvme_mi_admin_cdw3,
                        tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sqe_tree, hf_nvme_mi_admin_mptr,
                        tvb, 16, 8, ENC_LITTLE_ENDIAN);

    /* CDW10-15, shared with the NVMe transports. */
    nvme_dissect_admin_sqe_cdws(tvb, pinfo, sqe_tree, &req->cmd);

    bool security_send_invalid = false;
    if (opcode == NVME_AQ_OPC_SECURITY_SEND ||
        opcode == NVME_AQ_OPC_SECURITY_RECV)
        security_send_invalid =
            nvme_mi_admin_security_req(tvb, admin_tree, req,
                                       trans, (uint16_t)ctlid, len,
                                       integrity_ok, meb);
    if (opcode == NVME_AQ_OPC_SECURITY_RECV &&
        nvme_mi_admin_secp_al_is_bytes(req->cmd.cmd_ctx.security.secp) &&
        req->cmd.cmd_ctx.security.xfer_len != 0) {
        uint32_t al = req->cmd.cmd_ctx.security.xfer_len;
        if (req->dofst >= al)
            expert_add_info_format(pinfo, doff_it,
                                   &ei_nvme_mi_admin_invalid_dofst,
                                   "Data Offset %u is outside the %u-byte"
                                   " Security Receive Allocation Length",
                                   req->dofst, al);
        else if (!dlen_flagged && req->dlen != 0 &&
                 (uint64_t)req->dofst + req->dlen > al)
            expert_add_info_format(pinfo, dlen_it,
                                   &ei_nvme_mi_admin_invalid_dlen,
                                   "Data Offset %u plus Data Length %u exceeds"
                                   " the %u-byte Security Receive Allocation"
                                   " Length", req->dofst, req->dlen, al);
    }
    /* The Persistent Event Log reporting context is per NVM subsystem, so
     * per endpoint (Base 2.3 section 5.2.12.1.14). */
    if (opcode == NVME_AQ_OPC_GET_LOG_PAGE)
        req->cmd.cmd_ctx.get_logpage.scope = trans ? trans->endpoint : NULL;

    /* Publish before the request data, which may throw. */
    nvme_mi_trans_publish_body_ctx(pinfo, trans, req, sizeof(*req));

    if (len > 64 && (security_send_invalid || meb)) {
        proto_item *data_it = proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                                  tvb, 64, -1, ENC_NA);
        if (meb && (transfer == ADMIN_TRANSFER_REQUEST ||
                    transfer == ADMIN_TRANSFER_BIDIRECTIONAL))
            expert_add_info(pinfo, data_it, &ei_nvme_mi_admin_meb_inline_data);
    } else if (len > 64) {
        /* DOFST applies to Response Data only (Figure 139). */
        unsigned data_len = len - 64;
        proto_item *data_it = proto_tree_add_item(admin_tree,
                                                  hf_nvme_mi_admin_data,
                                                  tvb, 64, -1, ENC_NA);
        tvbuff_t *data_tvb = tvb_new_subset_length(tvb, 64, data_len);
        proto_item *data_sub_it;
        proto_tree *data_tree =
            proto_tree_add_subtree(admin_tree, data_tvb, 0, data_len,
                                   ett_nvme_mi_admin_data,
                                   &data_sub_it, "Data");
        /* The host's own bytes: no provenance.  TCG state a Security Send
         * advances is undone if its response reports an error.  One MCTP
         * message ends in a frame, so the Send is that frame's, ordinal 0. */
        if (req->cmd.opcode == NVME_AQ_OPC_SECURITY_SEND)
            req->cmd.cmd_ctx.security.request_frame = pinfo->num;
        bool handled = nvme_dissect_admin_data_resp(data_tvb, pinfo, data_tree, &req->cmd,
                                     0, data_len,
                                     NVME_DATA_ORIGIN_NONE,
                                     NVME_DATA_DIR_HOST_TO_CONTROLLER);
        nvme_mi_admin_hide_raw_or_structured(data_it, data_sub_it, data_tree,
                                             handled);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nvme_mi_admin_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *admin_tree,
                               proto_item *it, unsigned len,
                               struct nvme_mi_transaction *trans, bool integrity_ok,
                               bool replay, bool replay_response, bool meb)
{
    /* Opcode from the matching request; opc_resp_it may be NULL. */
    unsigned opcode;
    proto_item *opc_resp_it;
    bool opcode_known =
        nvme_mi_recover_resp_opcode(tvb, pinfo, admin_tree, it, trans,
                                    NVME_MI_TYPE_ADMIN,
                                    hf_nvme_mi_admin_opcode,
                                    &ei_nvme_mi_admin_orphan_response,
                                    &opcode, &opc_resp_it);
    if (opcode_known) {
        const char *opname = nvme_get_opcode_string((uint8_t)opcode, 0);
        proto_item_append_text(opc_resp_it, " (%s)", opname);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", opname);
    }

    if (len < 1) {
        expert_add_info(pinfo, it, &ei_nvme_mi_admin_truncated);
        return tvb_captured_length(tvb);
    }

    uint8_t status;
    proto_tree_add_item_ret_uint8(admin_tree, hf_nvme_mi_admin_status,
                                  tvb, 0, 1, ENC_NA, &status);

    if (len < 4) {
        nvme_mi_dissect_truncated(tvb, pinfo, admin_tree, it,
                                  &ei_nvme_mi_admin_truncated,
                                  hf_nvme_mi_admin_data, 1);
        return tvb_captured_length(tvb);
    }

    /* Only a Success Response carries the Admin body. */
    bool success = nvme_mi_dissect_resp_status_bytes(tvb, pinfo, admin_tree,
                                                     status);
    if (success)
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_resp_rsvd,
                            tvb, 1, 3, ENC_LITTLE_ENDIAN);

    if (success && len >= 16) {
        /* Structured DW0 decode needs the request and the status word. */
        struct nvme_mi_admin_req_ctx *req =
            (opcode_known && tvb_bytes_exist(tvb, 14, 2))
                ? (struct nvme_mi_admin_req_ctx *)trans->body_ctx : NULL;
        /* SCT and SC indicate CQE success; M, CRD and DNR do not change it. */
        bool cqe_success = req &&
                           (tvb_get_letohs(tvb, 14) & 0x0ffe) == 0;
        /* This is the non-integrity half of Security state eligibility. */
        bool completion_ok = !replay && cqe_success;
        bool mics_ok = req && integrity_ok && trans->req_integrity_ok;
        /* The response's own decode changes this copy, not the request's
         * context, which later frames and passes read. */
        struct nvme_cmd_ctx cqe_cmd = { 0 };
        if (req)
            cqe_cmd = req->cmd;

        if (!cqe_success)
            nvme_mi_admin_security_send_failed(pinfo, trans, req,
                                               replay && !replay_response,
                                               integrity_ok);

        proto_item *cqe_dw0 = proto_tree_add_item(admin_tree,
                                               hf_nvme_mi_admin_cqe_dw0,
                                               tvb, 4, 4, ENC_LITTLE_ENDIAN);
        if (req) {
            /* The status word selects the Set Features rendering. */
            proto_item_set_hidden(cqe_dw0);
            nvme_dissect_admin_cqe_dw0(tvb, 4, admin_tree,
                                       tvb_get_uint16(tvb, 14, ENC_LITTLE_ENDIAN),
                                       &cqe_cmd);
        }

        /* CQE DW1 is Command Specific (NVMe Base 2.3 Figure 96). */
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe_dw1,
                            tvb, 8, 4, ENC_LITTLE_ENDIAN);
        if (req)
            nvme_dissect_admin_cqe_dw1(tvb, 8, admin_tree,
                                       tvb_get_uint16(tvb, 14, ENC_LITTLE_ENDIAN),
                                       &cqe_cmd);

        /* CQE DW3: CID and status (NVMe Base 2.3 Figure 96). */
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe_dw3,
                            tvb, 12, 4, ENC_LITTLE_ENDIAN);
        uint32_t cid;
        proto_item *cid_it =
            proto_tree_add_item_ret_uint(admin_tree,
                                         hf_nvme_mi_admin_cqe_dw3_cid,
                                         tvb, 12, 4, ENC_LITTLE_ENDIAN, &cid);
        if (cid != 0)
            expert_add_info(pinfo, cid_it, &ei_nvme_mi_admin_cid_nonzero);
        if (req)
            nvme_dissect_admin_cqe_status(tvb, pinfo, admin_tree, 14, req->cmd.opcode);
        else
            nvme_dissect_cqe_status(tvb, pinfo, admin_tree, 14, false);

        /* Opal SSC 2.30 3.2.3: a TPer Reset completes with no Response Data. */
        if (len == 16 && completion_ok &&
            req->cmd.opcode == NVME_AQ_OPC_SECURITY_SEND &&
            req->security_contract_valid && req->request_data_complete)
            nvme_mi_admin_security_send_completed(tvb, pinfo, admin_tree,
                                                  req, mics_ok);

        proto_item *data_it = NULL;
        /* The item that shows the Response Data while data_it is hidden. */
        proto_item *data_vis_it = NULL;
        if (len > 16) {
            /* MEB data is not present inline; keep any such bytes raw. */
            unsigned data_len = len - 16;
            data_it = proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                          tvb, 16, -1, ENC_NA);
            data_vis_it = data_it;
            if (req && !meb) {
                unsigned off = req->dofst;
                /* Base 2.4 Figure 92: data transfer 00b and 01b return no
                 * data to the host; nor does Get Features SEL 011b. */
                bool no_data_defined = req->no_response_data &&
                    !nvme_admin_opcode_is_reserved(req->cmd.opcode);
                /* Bytes past DLEN were never selected (Figure 139). */
                unsigned sel_len = no_data_defined ? 0 :
                                   (!req->no_response_data &&
                                    data_len > req->dlen)
                                       ? req->dlen : data_len;
                proto_item *excess_it = NULL;

                /* Decode only the selected bytes; DLEN 0 selects nothing. */
                if (sel_len) {
                    /* A copy, so every dissection starts from the same state. */
                    struct nvme_cmd_ctx data_cmd = cqe_cmd;
                    if (req->cmd.opcode == NVME_AQ_OPC_SECURITY_SEND ||
                        req->cmd.opcode == NVME_AQ_OPC_SECURITY_RECV)
                        nvme_mi_admin_security_resp(tvb, admin_tree, req,
                                                    &data_cmd, completion_ok,
                                                    mics_ok, data_len, sel_len);
                    tvbuff_t *data_tvb = tvb_new_subset_length(tvb, 16, sel_len);
                    proto_item *data_sub_it;
                    proto_tree *data_tree =
                        proto_tree_add_subtree(admin_tree, data_tvb, 0, sel_len,
                                               ett_nvme_mi_admin_data,
                                               &data_sub_it, "Data");
                    struct nvme_data_origin origin = {
                        .prov = integrity_ok
                                    ? NVME_DATA_PROV_RESPONSE
                                    : NVME_DATA_PROV_NONE,
                        .window = NVME_DATA_WINDOW_EXPLICIT,
                        .offset = off,
                        .level0_prefix =
                            req->cmd.opcode == NVME_AQ_OPC_SECURITY_RECV &&
                            !req->no_response_data && req->dofst == 0 &&
                            req->dlen != 0 &&
                            req->dlen < req->cmd.cmd_ctx.security.xfer_len &&
                            data_len >= req->dlen,
                    };
                    /* Response integrity alone selects provenance. */
                    bool handled = nvme_dissect_admin_data_resp(data_tvb, pinfo, data_tree,
                                                 &data_cmd, off, sel_len,
                                                 origin,
                                                 NVME_DATA_DIR_CONTROLLER_TO_HOST);
                    nvme_mi_admin_hide_raw_or_structured(data_it,
                                                         data_sub_it,
                                                         data_tree,
                                                         handled);

                    /* The surplus, when the raw alias above is hidden. */
                    if (proto_item_is_hidden(data_it)) {
                        data_vis_it = data_sub_it;
                        if (sel_len < data_len)
                            excess_it = proto_tree_add_bytes_format(admin_tree,
                                hf_nvme_mi_admin_data_excess, tvb,
                                16 + sel_len, data_len - sel_len, NULL,
                                "Excess Data: %u bytes beyond the %u the"
                                " request's Data Length selected",
                                data_len - sel_len, req->dlen);
                    }
                }

                if (no_data_defined &&
                    req->cmd.opcode == NVME_AQ_OPC_GET_FEATURES)
                    expert_add_info_format(pinfo, data_it,
                                           &ei_nvme_mi_admin_unexpected_response_data,
                                           "NVMe Response Data is %u bytes for"
                                           " Get Features with Select 011b,"
                                           " which returns capabilities in"
                                           " CQE DW0 and no Response Data",
                                           data_len);
                else if (no_data_defined)
                    expert_add_info_format(pinfo, data_it,
                                           &ei_nvme_mi_admin_unexpected_response_data,
                                           "NVMe Response Data is %u bytes for"
                                           " an opcode whose data transfer"
                                           " bits 1:0 (%u%ub) return no data",
                                           data_len,
                                           (req->cmd.opcode >> 1) & 1,
                                           req->cmd.opcode & 1);
                else if (sel_len < data_len)
                    expert_add_info_format(pinfo,
                                           excess_it ? excess_it : data_it,
                                           &ei_nvme_mi_admin_invalid_dlen,
                                           "NVMe Response Data is %u bytes,"
                                           " more than the %u bytes the"
                                           " request's Data Length selected",
                                           data_len, req->dlen);
            } else if (req && meb && data_len) {
                expert_add_info_format(pinfo, data_it, &ei_nvme_mi_admin_meb_inline_data,
                                       "Response Data carried inline although the"
                                       " request set MEB to 1 (NVMe-MI 'NVMe-MI"
                                       " Message Fields', section 4.2.3)");
            }
        }

        /* A successful valid window owes exactly DLEN bytes (Figure 139). */
        if (req && !meb && req->window_valid && len - 16 < req->dlen &&
            cqe_success)
            expert_add_info_format(pinfo, data_vis_it ? data_vis_it : it,
                                   &ei_nvme_mi_admin_short_response,
                                   "NVMe Response Data is %u bytes, fewer"
                                   " than the %u bytes the request's Data"
                                   " Length selected", len - 16, req->dlen);
    } else {
        /* Error and MPR responses are 4 bytes (MI 2.2 Figures 30-34). */
        if (success)
            expert_add_info(pinfo, it, &ei_nvme_mi_admin_short_cqe);
        else if (status != NVME_MI_STATUS_MORE_PROCESSING_REQUIRED)
            nvme_mi_admin_security_send_failed(pinfo, trans,
                opcode_known ? (struct nvme_mi_admin_req_ctx *)trans->body_ctx : NULL,
                replay && !replay_response, integrity_ok);
        if (len > 4 && !success &&
            nvme_mi_status_has_response_format(status)) {
            proto_item *surplus = proto_tree_add_item(admin_tree,
                    hf_nvme_mi_admin_surplus, tvb, 4, -1, ENC_NA);
            expert_add_info_format(pinfo, surplus,
                                   &ei_nvme_mi_admin_error_surplus,
                                   "%u bytes follow the 4-byte %s Response",
                                   len - 4,
                                   rval_to_str_const(status,
                                                     nvme_mi_status_vals,
                                                     "Error"));
        } else if (len > 4) {
            /* Success too short for the CQE, or a Reserved or Vendor
             * Specific Status whose layout the spec does not fix. */
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                tvb, 4, -1, ENC_NA);
        }
    }

    return tvb_captured_length(tvb);
}

/* integrity_ok selects data provenance; replay suppresses TCG state. */
static int
dissect_nvme_mi_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      void *data)
{
    struct nvme_mi_dissect_ctx *ctx = (struct nvme_mi_dissect_ctx *)data;
    proto_tree *admin_tree;
    proto_item *it;
    unsigned len = tvb_reported_length(tvb);

    if (!ctx)
        return 0;

    it = proto_tree_add_item(tree, proto_nvme_mi_admin, tvb, 0, -1, ENC_NA);
    admin_tree = proto_item_add_subtree(it, ett_nvme_mi_admin);
    proto_item_set_text(it, "NVMe Admin %s", ctx->resp ? "response" : "request");

    if (ctx->resp)
        return dissect_nvme_mi_admin_response(tvb, pinfo, admin_tree, it, len, ctx->trans,
                                              ctx->integrity_ok, ctx->replay,
                                              ctx->replay_response, ctx->meb);

    /* Request */
    return dissect_nvme_mi_admin_request(tvb, pinfo, admin_tree, it, len, ctx->trans,
                                         ctx->integrity_ok, ctx->meb);
}

void
proto_register_nvme_mi_admin(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        { &hf_nvme_mi_admin_reserved,
          { "Reserved", "nvme-mi.admin.reserved",
            FT_UINT64, BASE_HEX, NULL, 0,
            "NVMe-MI 'NVMe Admin Command Request Description' bytes 43:36",
            HFILL } },
        { &hf_nvme_mi_admin_flags_reserved,
          { "Reserved", "nvme-mi.admin.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL } },
        { &hf_nvme_mi_admin_opcode,
          { "Opcode", "nvme-mi.admin.opcode",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Admin Command Opcode", HFILL },
        },
        { &hf_nvme_mi_admin_rae_handling,
          { "RAE handling", "nvme-mi.admin.rae_handling",
            FT_STRING, BASE_NONE, NULL, 0,
            "How a Management Endpoint treats the Get Log Page Retain"
            " Asynchronous Event bit", HFILL },
        },
        { &hf_nvme_mi_admin_status,
          { "Status", "nvme-mi.admin.status",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_mi_status_vals), 0,
            "Response Message Status", HFILL },
        },
        { &hf_nvme_mi_admin_flags,
          { "Command Flags", "nvme-mi.admin.flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_flags_ish,
          { "Ignore Shutdown (ISH)", "nvme-mi.admin.flags.ish",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), NVME_MI_ADMIN_FLAG_ISH,
            "Effect specified in NVMe-MI section 8.5; no effect on CSTS.SHST",
            HFILL },
        },
        { &hf_nvme_mi_admin_flags_dofstv,
          { "Data Offset Valid (DOFSTV)", "nvme-mi.admin.flags.dofstv",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), NVME_MI_ADMIN_FLAG_DOFSTV,
            "Not used; ignored by the Management Endpoint in implementations"
            " compliant with NVMe-MI later than 1.1"
            " (NVMe-MI 'NVMe Admin Command Request Description')", HFILL },
        },
        { &hf_nvme_mi_admin_flags_dlenv,
          { "Data Length Valid (DLENV)", "nvme-mi.admin.flags.dlenv",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), NVME_MI_ADMIN_FLAG_DLENV,
            "Not used; ignored by the Management Endpoint in implementations"
            " compliant with NVMe-MI later than 1.1"
            " (NVMe-MI 'NVMe Admin Command Request Description')", HFILL },
        },
        { &hf_nvme_mi_admin_ctrl_id,
          { "Controller ID", "nvme-mi.admin.ctrl-id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        /* SQE fields use the packet-nvme.c labels. */
        { &hf_nvme_mi_admin_nsid,
          { "Namespace Id", "nvme-mi.admin.nsid",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Command Dword 1 (NSID)", HFILL },
        },
        { &hf_nvme_mi_admin_cdw2,
          { "DWORD2", "nvme-mi.admin.cdw2",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Command Dword 2", HFILL },
        },
        { &hf_nvme_mi_admin_cdw3,
          { "DWORD3", "nvme-mi.admin.cdw3",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Command Dword 3", HFILL },
        },
        { &hf_nvme_mi_admin_mptr,
          { "Metadata Pointer", "nvme-mi.admin.mptr",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Reserved over the out-of-band mechanism (NVMe-MI section 6)",
            HFILL },
        },
        { &hf_nvme_mi_admin_doff,
          { "Data Offset", "nvme-mi.admin.doff",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_dlen,
          { "Data Length", "nvme-mi.admin.dlen",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_resv0,
          { "Reserved", "nvme-mi.admin.reserved0",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_resv1,
          { "Reserved", "nvme-mi.admin.reserved1",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_resp_rsvd,
          { "Reserved", "nvme-mi.admin.resp_reserved",
            FT_UINT24, BASE_HEX, NULL, 0,
            "Reserved bytes between Status and the CQE dwords", HFILL },
        },
        /* CQE DW0, DW1 and DW3; DW2 is not carried over NVMe-MI. */
        { &hf_nvme_mi_admin_cqe_dw0,
          { "Completion Queue Entry dword 0", "nvme-mi.admin.cqe_dw0",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Command-specific result (CQE DW0)", HFILL },
        },
        { &hf_nvme_mi_admin_cqe_dw1,
          { "Completion Queue Entry dword 1", "nvme-mi.admin.cqe_dw1",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Command specific (CQE DW1)", HFILL },
        },
        { &hf_nvme_mi_admin_cqe_dw3,
          { "Completion Queue Entry dword 3", "nvme-mi.admin.cqe_dw3",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Phase tag, status (SCT/SC/M/DNR) and command identifier"
            " (CQE DW3)", HFILL },
        },
        /* Command Identifier: CQE DW3 bits 15:00 (NVMe Base 2.3 Figure 96). */
        { &hf_nvme_mi_admin_cqe_dw3_cid,
          { "Command Id (CID)", "nvme-mi.admin.cqe_dw3.cid",
            FT_UINT32, BASE_HEX, NULL, 0x0000ffff,
            "Command Identifier; cleared to 0h over NVMe-MI", HFILL },
        },
        { &hf_nvme_mi_admin_tper_reset_applied,
          { "TPer Reset applied", "nvme-mi.admin.tper_reset_applied",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "TCG state of every ComID in scope was reset (Opal SSC 3.2.3)",
            HFILL },
        },
        { &hf_nvme_mi_admin_security_state_integrity,
          { "Security state integrity unverified",
            "nvme-mi.admin.security_state_integrity",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "Tracked Security state was not advanced because MIC integrity"
            " was unverified", HFILL },
        },
        { &hf_nvme_mi_admin_data,
          { "Data", "nvme-mi.admin.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_data_excess,
          { "Excess Data", "nvme-mi.admin.data_excess",
            FT_BYTES, SEP_SPACE, NULL, 0,
            "NVMe Response Data beyond the request's Data Length", HFILL },
        },
        { &hf_nvme_mi_admin_surplus,
          { "Surplus Data", "nvme-mi.admin.surplus",
            FT_BYTES, SEP_SPACE, NULL, 0,
            "Bytes after the 4-byte Response Message of a non-Success"
            " Status", HFILL },
        },
    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi_admin,
        &ett_nvme_mi_admin_flags,
        &ett_nvme_mi_admin_reserved,
        &ett_nvme_mi_admin_sqe,
        &ett_nvme_mi_admin_data,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_mi_admin_truncated,
          { "nvme-mi.admin.truncated", PI_MALFORMED, PI_WARN,
            "Admin command payload truncated", EXPFILL }
        },
        { &ei_nvme_mi_admin_orphan_response,
          { "nvme-mi.admin.orphan_response", PI_SEQUENCE, PI_NOTE,
            "Admin response without a usable matching request; opcode could"
            " not be recovered", EXPFILL }
        },
        { &ei_nvme_mi_admin_short_cqe,
          { "nvme-mi.admin.short_cqe", PI_MALFORMED, PI_WARN,
            "Success Response shorter than the 16-byte status + CQE dwords"
            " block", EXPFILL }
        },
        { &ei_nvme_mi_admin_prohibited_opcode,
          { "nvme-mi.admin.prohibited_opcode", PI_PROTOCOL, PI_WARN,
            "Admin opcode is prohibited for both NVMe Storage Devices and"
            " NVMe Enclosures (NVMe-MI 'List of NVMe Admin Commands Supported"
            " using the Out-of-Band Mechanism')", EXPFILL }
        },
        { &ei_nvme_mi_admin_prohibited_lid,
          { "nvme-mi.admin.prohibited_lid", PI_PROTOCOL, PI_WARN,
            "Log page is prohibited on NVMe-MI Management Endpoints"
            " (NVMe-MI 'Management Endpoint - Log Page Support')", EXPFILL }
        },
        { &ei_nvme_mi_admin_prohibited_fid,
          { "nvme-mi.admin.prohibited_fid", PI_PROTOCOL, PI_WARN,
            "Set Features of this Feature is prohibited on NVMe-MI Management"
            " Endpoints (NVMe-MI 'Management Endpoint - Feature Support')", EXPFILL }
        },
        { &ei_nvme_mi_admin_reserved_opcode,
          { "nvme-mi.admin.reserved_opcode", PI_PROTOCOL, PI_WARN,
            "Reserved or unlisted Admin opcode (NVMe Base 'Opcodes for Admin"
            " Commands'; NVMe-MI 'List of NVMe Admin Commands Supported using"
            " the Out-of-Band Mechanism')", EXPFILL }
        },
        { &ei_nvme_mi_admin_meb_inline_data,
          { "nvme-mi.admin.meb_inline_data", PI_PROTOCOL, PI_NOTE,
            "Request Data carried inline with MEB set to 1: MEB 1 places"
            " Request Data in the Management Endpoint Buffer, and is"
            " prohibited where there is none (NVMe-MI 'NVMe-MI Message"
            " Fields', section 4.2.3)", EXPFILL }
        },
        { &ei_nvme_mi_admin_unexpected_request_data,
          { "nvme-mi.admin.unexpected_request_data", PI_PROTOCOL, PI_WARN,
            "Command is not defined to transfer NVMe Request Data"
            " (NVMe-MI 'NVMe Admin Command Request Description')", EXPFILL }
        },
        { &ei_nvme_mi_admin_invalid_dofst,
          { "nvme-mi.admin.invalid_dofst", PI_PROTOCOL, PI_WARN,
            "Data Offset must be dword-aligned and must select a window inside"
            " the command's completion data; a Management Endpoint returns"
            " Invalid Parameter (NVMe-MI 'NVMe Admin Command Request"
            " Description')", EXPFILL }
        },
        { &ei_nvme_mi_admin_invalid_dlen,
          { "nvme-mi.admin.invalid_dlen", PI_PROTOCOL, PI_WARN,
            "Data Length must be dword-aligned, at most 4096 bytes, and must"
            " account for the data the message actually carries; a Management"
            " Endpoint returns Invalid Parameter or Invalid Command Input Data"
            " Size (NVMe-MI 'NVMe Admin Command Request Description')",
            EXPFILL }
        },
        { &ei_nvme_mi_admin_short_response,
          { "nvme-mi.admin.short_response", PI_PROTOCOL, PI_NOTE,
            "A Success Response carries fewer NVMe Response Data bytes than"
            " the request's Data Length selected; the Management Endpoint"
            " shall return DLEN bytes of the command's completion data"
            " (NVMe-MI 'NVMe Admin Command Request Description')",
            EXPFILL }
        },
        { &ei_nvme_mi_admin_unexpected_response_data,
          { "nvme-mi.admin.unexpected_response_data", PI_PROTOCOL, PI_WARN,
            "NVMe Response Data for an opcode whose data transfer bits 1:0"
            " (00b or 01b) return no data to the host (NVMe Base"
            " 'Command Dword 0')", EXPFILL }
        },
        { &ei_nvme_mi_admin_error_surplus,
          { "nvme-mi.admin.error_surplus", PI_MALFORMED, PI_WARN,
            "Bytes follow a 4-byte Response Message whose format the Status"
            " defines", EXPFILL }
        },
        { &ei_nvme_mi_admin_cid_nonzero,
          { "nvme-mi.admin.cid_nonzero", PI_PROTOCOL, PI_WARN,
            "Command Identifier is not 0h; it shall be cleared to 0h"
            " (NVMe-MI 'NVMe Admin Command Response Description')", EXPFILL }
        },
    };

    expert_module_t *expert_nvme_mi_admin;

    proto_nvme_mi_admin = proto_register_protocol(
            "NVMe-MI Admin Command", "NVMe-MI Admin", "nvme-mi.admin");
    proto_register_field_array(proto_nvme_mi_admin, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi_admin = expert_register_protocol(proto_nvme_mi_admin);
    expert_register_field_array(expert_nvme_mi_admin, ei, array_length(ei));

    nvme_mi_admin_handle = register_dissector_with_description(
            "nvme-mi.admin", "NVMe-MI Admin Command",
            dissect_nvme_mi_admin, proto_nvme_mi_admin);
}

void
proto_reg_handoff_nvme_mi_admin(void)
{
    dissector_add_uint("nvme-mi.type", NVME_MI_TYPE_ADMIN,
                       nvme_mi_admin_handle);
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
