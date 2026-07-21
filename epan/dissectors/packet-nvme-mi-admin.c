/* packet-nvme-mi-admin.c
 * NVMe-MI Admin Command dissector (NMIMT=2, NVMe-MI 2.1 §6)
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
 * An NVMe-MI Admin command request carries a full 64-byte NVMe Submission
 * Queue Entry (SQE).  From the opcode byte (offset 0) and CDW10-CDW15 (offset
 * 40) onward the layout is identical to a standard NVMe SQE, so the
 * opcode-specific command-dword decode is delegated to the shared
 * nvme_dissect_admin_sqe_cdws() helper in packet-nvme.c -- the same decode the
 * NVMe/TCP and NVMe/RDMA transports use.  The bytes that differ from a standard
 * SQE (Data Offset/Length at 24-31, Reserved at 32-39) are decoded here.
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-nvme.h"
#include "packet-nvme-mi.h"

void proto_register_nvme_mi_admin(void);
void proto_reg_handoff_nvme_mi_admin(void);

static int proto_nvme_mi_admin;

static int hf_nvme_mi_admin_opcode;
static int hf_nvme_mi_admin_status;
static int hf_nvme_mi_admin_flags;
static int hf_nvme_mi_admin_flags_doff;
static int hf_nvme_mi_admin_flags_dlen;
static int hf_nvme_mi_admin_ctrl_id;
static int hf_nvme_mi_admin_nsid;
static int hf_nvme_mi_admin_cdw2;
static int hf_nvme_mi_admin_cdw3;
static int hf_nvme_mi_admin_mptr;
static int hf_nvme_mi_admin_doff;
static int hf_nvme_mi_admin_dlen;
static int hf_nvme_mi_admin_resv0;
static int hf_nvme_mi_admin_resv1;
static int hf_nvme_mi_admin_data;
static int hf_nvme_mi_admin_cqe1;
static int hf_nvme_mi_admin_cqe2;
static int hf_nvme_mi_admin_cqe3;

/*
 * Hidden raw-dword aliases (nvme-mi.admin.sqe1..5, sqe10..15) preserved from
 * the pre-split layout so display filters/columns written against the old
 * field names keep resolving; the visible tree uses the structured NSID/MPTR
 * and shared CDW10-15 decode.  See nvme_mi_admin_add_sqe_aliases().
 */
static int hf_nvme_mi_admin_sqe1;
static int hf_nvme_mi_admin_sqe2;
static int hf_nvme_mi_admin_sqe3;
static int hf_nvme_mi_admin_sqe4;
static int hf_nvme_mi_admin_sqe5;
static int hf_nvme_mi_admin_sqe10;
static int hf_nvme_mi_admin_sqe11;
static int hf_nvme_mi_admin_sqe12;
static int hf_nvme_mi_admin_sqe13;
static int hf_nvme_mi_admin_sqe14;
static int hf_nvme_mi_admin_sqe15;

static int ett_nvme_mi_admin;
static int ett_nvme_mi_admin_flags;
static int ett_nvme_mi_admin_sqe;

static expert_field ei_nvme_mi_admin_truncated;
static expert_field ei_nvme_mi_admin_orphan_response;
static expert_field ei_nvme_mi_admin_short_cqe;
static expert_field ei_nvme_mi_admin_prohibited_opcode;

/* Command Flags byte (request offset 1): Data Offset / Data Length present. */
#define NVME_MI_ADMIN_FLAG_DLEN 0x01
#define NVME_MI_ADMIN_FLAG_DOFF 0x02

/*
 * Per-transaction request context hung off nvme_mi_transaction.body_ctx
 * (wmem_file_scope).  Wraps the shared struct nvme_cmd_ctx that
 * nvme_dissect_admin_sqe_cdws() populates on the request pass so the
 * response-side decode (added in later MRs) can recover the opcode-specific
 * request parameters.
 */
struct nvme_mi_admin_req_ctx {
    struct nvme_cmd_ctx cmd;
};

/*
 * Admin opcodes that NVMe-MI 2.1 Figure 134 marks Prohibited over the
 * Management Interface.  The shared aq_opc_tbl names them (they are valid NVMe
 * Admin opcodes), so the dissector flags separately that they are illegal on
 * this transport -- useful for spotting non-compliant endpoints.
 */
static bool
nvme_mi_admin_opcode_prohibited(uint8_t opcode)
{
    switch (opcode) {
    case NVME_AQ_OPC_DELETE_SQ:     /* 00h */
    case NVME_AQ_OPC_CREATE_SQ:     /* 01h */
    case NVME_AQ_OPC_DELETE_CQ:     /* 04h */
    case NVME_AQ_OPC_CREATE_CQ:     /* 05h */
    case NVME_AQ_OPC_ABORT:         /* 08h */
    case NVME_AQ_OPC_ASYNC_EVE_REQ: /* 0Ch */
    case NVME_AQ_OPC_KEEP_ALIVE:    /* 18h */
    case 0x7c:                      /* Doorbell Buffer Config */
        return true;
    default:
        return false;
    }
}

/*
 * Add the hidden legacy raw-dword aliases over the 64-byte SQE.  Each aliases
 * one command dword the visible tree now decodes structurally (sqe1=NSID,
 * sqe4/sqe5=the two halves of the 64-bit MPTR, sqe10-15=the opcode-specific
 * CDW10-15) so old display filters resolve without cluttering the tree.
 */
static void
nvme_mi_admin_add_sqe_aliases(tvbuff_t *tvb, proto_tree *tree)
{
    static const struct { int *hf; int off; } aliases[] = {
        { &hf_nvme_mi_admin_sqe1,   4 }, { &hf_nvme_mi_admin_sqe2,   8 },
        { &hf_nvme_mi_admin_sqe3,  12 }, { &hf_nvme_mi_admin_sqe4,  16 },
        { &hf_nvme_mi_admin_sqe5,  20 }, { &hf_nvme_mi_admin_sqe10, 40 },
        { &hf_nvme_mi_admin_sqe11, 44 }, { &hf_nvme_mi_admin_sqe12, 48 },
        { &hf_nvme_mi_admin_sqe13, 52 }, { &hf_nvme_mi_admin_sqe14, 56 },
        { &hf_nvme_mi_admin_sqe15, 60 },
    };
    unsigned i;

    for (i = 0; i < array_length(aliases); i++) {
        proto_item *ai = proto_tree_add_item(tree, *aliases[i].hf, tvb,
                                             aliases[i].off, 4,
                                             ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ai);
    }
}

/*
 * Body worker.  Kept separate from the registered wrapper so a future in-band
 * NVMe-MI Send/Receive decode (NVMe Admin opcodes 1Dh/1Eh tunnel the same
 * bytes) can call it directly with an explicit direction and a NULL
 * transaction.
 */
static int
dissect_nvme_mi_admin_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           bool resp, struct nvme_mi_transaction *trans)
{
    static int * const nvme_mi_admin_flags[] = {
        &hf_nvme_mi_admin_flags_doff,
        &hf_nvme_mi_admin_flags_dlen,
        NULL,
    };
    proto_tree *admin_tree;
    proto_item *it, *it2;
    unsigned len = tvb_reported_length(tvb);

    it = proto_tree_add_item(tree, proto_nvme_mi_admin, tvb, 0, -1, ENC_NA);
    admin_tree = proto_item_add_subtree(it, ett_nvme_mi_admin);
    proto_item_set_text(it, "NVMe Admin %s", resp ? "response" : "request");

    if (resp) {
        /* The response carries no opcode; recover it from the matching request
         * (of this same NMIMT).  Without one, the helper notes an orphan
         * response rather than fabricating an opcode-0 item. */
        unsigned opcode;
        it2 = nvme_mi_recover_resp_opcode(tvb, pinfo, admin_tree, it, trans,
                                          NVME_MI_TYPE_ADMIN,
                                          hf_nvme_mi_admin_opcode,
                                          &ei_nvme_mi_admin_orphan_response,
                                          &opcode);
        if (it2) {
            const char *opname = nvme_get_opcode_string((uint8_t)opcode, 0);
            proto_item_append_text(it2, " (%s)", opname);
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

        if (status == NVME_MI_STATUS_INVALID_PARAMETER)
            nvme_mi_dissect_invalid_param_resp(tvb, admin_tree);

        if (len >= 16) {
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe1,
                                tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe2,
                                tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe3,
                                tvb, 12, 4, ENC_LITTLE_ENDIAN);
            if (len > 16)
                proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                    tvb, 16, -1, ENC_NA);
        } else {
            /* A Success Response carries the full 16-byte status + CQE
             * dwords block; error and MPR responses are legitimately the
             * 4-byte short form. */
            if (status == NVME_MI_STATUS_SUCCESS)
                expert_add_info(pinfo, it, &ei_nvme_mi_admin_short_cqe);
            if (len > 4)
                proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                    tvb, 4, -1, ENC_NA);
        }

        return tvb_captured_length(tvb);
    }

    /* Request */
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

    /* Record the request opcode for the matching response. */
    if (trans) {
        trans->opcode = opcode;
        trans->req_parsed = true;
    }

    /* The fixed part of an Admin request is the full 64-byte SQE.  For
     * anything shorter, flag the truncation and show the remaining bytes raw
     * instead of throwing mid-tree. */
    if (len < 64) {
        nvme_mi_dissect_truncated(tvb, pinfo, admin_tree, it,
                                  &ei_nvme_mi_admin_truncated,
                                  hf_nvme_mi_admin_data, 1);
        return tvb_captured_length(tvb);
    }

    /* Persist the per-opcode request context for the response pass.  The
     * shared CDW decoder populates req->cmd in place; later MRs read it back
     * when dissecting the matching response. */
    struct nvme_mi_admin_req_ctx *req;
    if (trans) {
        if (!trans->body_ctx)
            trans->body_ctx = wmem_new0(wmem_file_scope(),
                                        struct nvme_mi_admin_req_ctx);
        req = (struct nvme_mi_admin_req_ctx *)trans->body_ctx;
    } else {
        /* No transaction (orphan request or external caller): a throwaway
         * packet-scope context is enough to drive the CDW decode. */
        req = wmem_new0(pinfo->pool, struct nvme_mi_admin_req_ctx);
    }
    req->cmd.opcode = opcode;

    /* NVMe-MI envelope fields: the SQE positions NVMe-MI repurposes for its
     * own meaning (Command Flags, Controller ID in place of CID, Data
     * Offset/Length in place of PRP1, and the following reserved dwords). */
    proto_tree_add_bitmask(admin_tree, tvb, 1, hf_nvme_mi_admin_flags,
                           ett_nvme_mi_admin_flags, nvme_mi_admin_flags,
                           ENC_NA);
    proto_tree_add_item(admin_tree, hf_nvme_mi_admin_ctrl_id,
                        tvb, 2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(admin_tree, hf_nvme_mi_admin_doff,
                        tvb, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(admin_tree, hf_nvme_mi_admin_dlen,
                        tvb, 28, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(admin_tree, hf_nvme_mi_admin_resv0,
                        tvb, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(admin_tree, hf_nvme_mi_admin_resv1,
                        tvb, 36, 4, ENC_LITTLE_ENDIAN);

    /* The tunneled NVMe command content gets its own subtree so the NVMe-MI
     * envelope (above) and the NVMe Submission Queue Entry (the dwords the
     * command itself defines) read as two distinct layers.  The command-dword
     * fields use the same labels as packet-nvme.c so the pass-through dwords
     * and the shared CDW10-15 decode below are consistent. */
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

    /* Opcode-specific CDW10-CDW15 decode, shared with the NVMe transports.
     * The 64-byte MI request payload is laid out as a standard SQE from the
     * opcode byte onward, so the helper consumes this tvb directly. */
    nvme_dissect_admin_sqe_cdws(tvb, pinfo, sqe_tree, &req->cmd);

    /* Hidden raw-dword aliases for pre-split display-filter compatibility. */
    nvme_mi_admin_add_sqe_aliases(tvb, admin_tree);

    if (len > 64)
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                            tvb, 64, -1, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_nvme_mi_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      void *data)
{
    struct nvme_mi_dissect_ctx *ctx = (struct nvme_mi_dissect_ctx *)data;

    if (!ctx)
        return 0;

    return dissect_nvme_mi_admin_body(tvb, pinfo, tree, ctx->resp, ctx->trans);
}

void
proto_register_nvme_mi_admin(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        { &hf_nvme_mi_admin_opcode,
          { "Opcode", "nvme-mi.admin.opcode",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Admin Command Opcode (NVMe-MI 2.1 Figure 134)", HFILL },
        },
        { &hf_nvme_mi_admin_status,
          { "Status", "nvme-mi.admin.status",
            FT_UINT8, BASE_HEX, VALS(nvme_mi_status_vals), 0,
            "Response Message Status (NVMe-MI 2.1 Figure 29)", HFILL },
        },
        { &hf_nvme_mi_admin_flags,
          { "Command Flags", "nvme-mi.admin.flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_flags_dlen,
          { "Use Data Length", "nvme-mi.admin.flags.dlen",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), NVME_MI_ADMIN_FLAG_DLEN,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_flags_doff,
          { "Use Data Offset", "nvme-mi.admin.flags.doff",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), NVME_MI_ADMIN_FLAG_DOFF,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_ctrl_id,
          { "Controller ID", "nvme-mi.admin.ctrl-id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        /* The Submission Queue Entry content fields use the same labels as
         * packet-nvme.c (Namespace Id, DWORDn, Metadata Pointer) so the
         * tunneled NVMe command reads consistently with the shared CDW10-15
         * decode and with the other NVMe transports. */
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
            NULL, HFILL },
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
          { "Reserved", "nvme-mi.admin.reserved",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_resv1,
          { "Reserved", "nvme-mi.admin.reserved",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        /* The MI response carries CQE dwords 0, 1 and 3 — DW2 (SQ head
         * pointer / SQ ID) is meaningless over MCTP and omitted.  The
         * cqe1/cqe2/cqe3 abbreviations predate this and are kept so existing
         * display filters stay valid. */
        { &hf_nvme_mi_admin_cqe1,
          { "Completion Queue Entry dword 0", "nvme-mi.admin.cqe1",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Command-specific result (CQE DW0)", HFILL },
        },
        { &hf_nvme_mi_admin_cqe2,
          { "Completion Queue Entry dword 1", "nvme-mi.admin.cqe2",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Reserved in Admin completions (CQE DW1)", HFILL },
        },
        { &hf_nvme_mi_admin_cqe3,
          { "Completion Queue Entry dword 3", "nvme-mi.admin.cqe3",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Phase tag, status (SCT/SC/M/DNR) and command identifier "
            "(CQE DW3)", HFILL },
        },
        { &hf_nvme_mi_admin_data,
          { "Data", "nvme-mi.admin.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },
        /*
         * Hidden raw-dword aliases (added per item via proto_item_set_hidden)
         * preserving the pre-split nvme-mi.admin.sqe* filter names.  The visible
         * tree decodes these dwords structurally (NSID, MPTR, CDW10-15); these
         * exist only so old display filters/columns keep resolving.
         */
        { &hf_nvme_mi_admin_sqe1,
          { "SQE dword 1 (NSID)", "nvme-mi.admin.sqe1",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for nvme-mi.admin.nsid", HFILL },
        },
        { &hf_nvme_mi_admin_sqe2,
          { "SQE dword 2", "nvme-mi.admin.sqe2",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for nvme-mi.admin.cdw2", HFILL },
        },
        { &hf_nvme_mi_admin_sqe3,
          { "SQE dword 3", "nvme-mi.admin.sqe3",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for nvme-mi.admin.cdw3", HFILL },
        },
        { &hf_nvme_mi_admin_sqe4,
          { "SQE dword 4 (MPTR low)", "nvme-mi.admin.sqe4",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for the low dword of nvme-mi.admin.mptr", HFILL },
        },
        { &hf_nvme_mi_admin_sqe5,
          { "SQE dword 5 (MPTR high)", "nvme-mi.admin.sqe5",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for the high dword of nvme-mi.admin.mptr", HFILL },
        },
        { &hf_nvme_mi_admin_sqe10,
          { "SQE dword 10", "nvme-mi.admin.sqe10",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for Command Dword 10 (now decoded as nvme.cmd.*)",
            HFILL },
        },
        { &hf_nvme_mi_admin_sqe11,
          { "SQE dword 11", "nvme-mi.admin.sqe11",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for Command Dword 11 (now decoded as nvme.cmd.*)",
            HFILL },
        },
        { &hf_nvme_mi_admin_sqe12,
          { "SQE dword 12", "nvme-mi.admin.sqe12",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for Command Dword 12 (now decoded as nvme.cmd.*)",
            HFILL },
        },
        { &hf_nvme_mi_admin_sqe13,
          { "SQE dword 13", "nvme-mi.admin.sqe13",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for Command Dword 13 (now decoded as nvme.cmd.*)",
            HFILL },
        },
        { &hf_nvme_mi_admin_sqe14,
          { "SQE dword 14", "nvme-mi.admin.sqe14",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for Command Dword 14 (now decoded as nvme.cmd.*)",
            HFILL },
        },
        { &hf_nvme_mi_admin_sqe15,
          { "SQE dword 15", "nvme-mi.admin.sqe15",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Deprecated alias for Command Dword 15 (now decoded as nvme.cmd.*)",
            HFILL },
        },
    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi_admin,
        &ett_nvme_mi_admin_flags,
        &ett_nvme_mi_admin_sqe,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_mi_admin_truncated,
          { "nvme-mi.admin.truncated", PI_MALFORMED, PI_WARN,
            "Admin command payload truncated", EXPFILL },
        },
        { &ei_nvme_mi_admin_orphan_response,
          { "nvme-mi.admin.orphan_response", PI_SEQUENCE, PI_NOTE,
            "Admin response without a usable matching request (missing or "
            "truncated); opcode could not be recovered", EXPFILL },
        },
        { &ei_nvme_mi_admin_short_cqe,
          { "nvme-mi.admin.short_cqe", PI_MALFORMED, PI_WARN,
            "Success Response shorter than the 16-byte status + CQE dwords "
            "block", EXPFILL },
        },
        { &ei_nvme_mi_admin_prohibited_opcode,
          { "nvme-mi.admin.prohibited_opcode", PI_PROTOCOL, PI_WARN,
            "Admin opcode is Prohibited over the Management Interface "
            "(NVMe-MI 2.1 Figure 134)", EXPFILL },
        },
    };

    expert_module_t *expert_nvme_mi_admin;

    proto_nvme_mi_admin = proto_register_protocol(
            "NVMe-MI Admin Command", "NVMe-MI Admin", "nvme-mi.admin");
    proto_register_field_array(proto_nvme_mi_admin, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi_admin = expert_register_protocol(proto_nvme_mi_admin);
    expert_register_field_array(expert_nvme_mi_admin, ei, array_length(ei));
}

void
proto_reg_handoff_nvme_mi_admin(void)
{
    dissector_add_uint("nvme-mi.type", NVME_MI_TYPE_ADMIN,
                       create_dissector_handle(dissect_nvme_mi_admin,
                                               proto_nvme_mi_admin));
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
