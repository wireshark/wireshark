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

static dissector_handle_t nvme_mi_admin_handle;

static int hf_nvme_mi_admin_opcode;
static int hf_nvme_mi_admin_status;
static int hf_nvme_mi_admin_flags;
static int hf_nvme_mi_admin_flags_dlenv;
static int hf_nvme_mi_admin_flags_dofstv;
static int hf_nvme_mi_admin_flags_ish;
static int hf_nvme_mi_admin_ctrl_id;
static int hf_nvme_mi_admin_nsid;
static int hf_nvme_mi_admin_cdw2;
static int hf_nvme_mi_admin_cdw3;
static int hf_nvme_mi_admin_mptr;
static int hf_nvme_mi_admin_doff;
static int hf_nvme_mi_admin_dlen;
static int hf_nvme_mi_admin_resv0;
static int hf_nvme_mi_admin_resv1;
static int hf_nvme_mi_admin_resp_rsvd;
static int hf_nvme_mi_admin_data;
static int hf_nvme_mi_admin_cqe_dw0;
static int hf_nvme_mi_admin_cqe_dw1;
static int hf_nvme_mi_admin_cqe_dw3;

static int ett_nvme_mi_admin;
static int ett_nvme_mi_admin_flags;
static int ett_nvme_mi_admin_sqe;
static int ett_nvme_mi_admin_data;

static expert_field ei_nvme_mi_admin_truncated;
static expert_field ei_nvme_mi_admin_orphan_response;
static expert_field ei_nvme_mi_admin_short_cqe;
static expert_field ei_nvme_mi_admin_prohibited_opcode;
static expert_field ei_nvme_mi_admin_obsolete_flag;
static expert_field ei_nvme_mi_admin_invalid_dofst;
static expert_field ei_nvme_mi_admin_invalid_dlen;

/*
 * Command Flags byte (request offset 1, NVMe-MI 2.1 "NVMe Admin Command
 * Request Description").  DLENV/DOFSTV
 * (bits 0/1) are obsolete: "not used and shall be ignored by the Management
 * Endpoint for implementations compliant with versions ... later than 1.1".
 * ISH (bit 2, Ignore Shutdown) is the only active flag.
 */
#define NVME_MI_ADMIN_FLAG_DLENV  0x01
#define NVME_MI_ADMIN_FLAG_DOFSTV 0x02
#define NVME_MI_ADMIN_FLAG_ISH    0x04

/*
 * Per-transaction request context hung off nvme_mi_transaction.body_ctx
 * (wmem_file_scope).  Wraps the shared struct nvme_cmd_ctx that
 * nvme_dissect_admin_sqe_cdws() populates on the request pass so the
 * response-side decode (added in later MRs) can recover the opcode-specific
 * request parameters.  The Data Offset/Length (DOFST/DLEN) the request selects
 * are saved alongside so the response can slice its data payload into the
 * shared NVMe data decoders at the requested offset (NVMe-MI 2.1 "Request
 * and Response Data").
 */
struct nvme_mi_admin_req_ctx {
    struct nvme_cmd_ctx cmd;
    uint32_t dofst;    /* request Data Offset ("NVMe Admin Command Request
                        * Description"); DOFSTV is obsolete and ignored, so
                        * this is always meaningful */
    uint32_t dlen;     /* request Data Length ("NVMe Admin Command Request
                        * Description"); DLENV obsolete */
};

/*
 * Admin opcodes that the NVMe-MI 2.1 "List of NVMe Admin Commands Supported
 * using the Out-of-Band Mechanism" table marks Prohibited over the
 * Management Interface.  The shared aq_opc_tbl names them (they are valid NVMe
 * Admin opcodes), so the dissector flags separately that they are illegal on
 * this transport -- useful for spotting non-compliant endpoints.
 */
static bool
nvme_mi_admin_opcode_prohibited(uint8_t opcode)
{
    switch (opcode) {
    case NVME_AQ_OPC_DELETE_SQ:            /* 00h */
    case NVME_AQ_OPC_CREATE_SQ:            /* 01h */
    case NVME_AQ_OPC_DELETE_CQ:            /* 04h */
    case NVME_AQ_OPC_CREATE_CQ:            /* 05h */
    case NVME_AQ_OPC_ABORT:                /* 08h */
    case NVME_AQ_OPC_ASYNC_EVE_REQ:        /* 0Ch */
    case NVME_AQ_OPC_KEEP_ALIVE:           /* 18h */
    case NVME_AQ_OPC_DIRECTIVE_SEND:       /* 19h */
    case NVME_AQ_OPC_DIRECTIVE_RECV:       /* 1Ah */
    case NVME_AQ_OPC_MI_SEND:              /* 1Dh */
    case NVME_AQ_OPC_MI_RECV:              /* 1Eh */
    case NVME_AQ_OPC_DISC_INFO_MGMT:       /* 21h */
    case NVME_AQ_OPC_FABRIC_ZONING_RECV:   /* 22h */
    case NVME_AQ_OPC_FABRIC_ZONING_LOOKUP: /* 25h */
    case NVME_AQ_OPC_FABRIC_ZONING_SEND:   /* 29h */
    case NVME_AQ_OPC_CROSS_CTRL_RESET:     /* 38h */
    case NVME_AQ_OPC_SEND_DISC_LOG_PAGE:   /* 39h */
    case NVME_AQ_OPC_TRACK_SEND:           /* 3Dh */
    case NVME_AQ_OPC_TRACK_RECV:           /* 3Eh */
    case NVME_AQ_OPC_MIGRATION_SEND:       /* 41h */
    case NVME_AQ_OPC_MIGRATION_RECV:       /* 42h */
    case NVME_AQ_OPC_CTRL_DATA_QUEUE:      /* 45h */
    case NVME_AQ_OPC_DBBUF_CONFIG:         /* 7Ch */
    case NVME_FABRIC_OPC:                  /* 7Fh */
    case NVME_AQ_OPC_LOAD_PROGRAM:         /* 85h */
    case NVME_AQ_OPC_PROG_ACTIVATION_MGMT: /* 88h */
    case NVME_AQ_OPC_MEM_RANGE_SET_MGMT:   /* 89h */
        return true;
    default:
        return false;
    }
}

/*
 * Show exactly one of the two renderings of the Data payload: the raw bytes
 * item, or the "Data" subtree the shared NVMe decoder just filled in.
 *
 * nvme_dissect_admin_data_resp() returns true when the opcode *has* a
 * structured decoder, not when that decoder produced a field -- so its return
 * value cannot decide this.  A structured decoder legitimately renders nothing
 * for a window that lands past every field it knows (NVMe-MI 2.1 Figure 114
 * allows a 2-Wire MTU as small as 64 bytes, so a BMC reading the 4096-byte
 * Identify structure gets many such windows) or for a sub-structure it does
 * not handle.  Hiding the raw item then leaves an empty Data node and no
 * payload bytes anywhere in the tree, so key off what actually landed in the
 * subtree.
 */
static void
nvme_mi_admin_hide_raw_or_structured(proto_item *raw_it, proto_item *sub_it,
                                     proto_tree *data_tree)
{
    if (data_tree && data_tree->first_child)
        proto_item_set_hidden(raw_it);
    else
        proto_item_set_hidden(sub_it);
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
        &hf_nvme_mi_admin_flags_ish,
        &hf_nvme_mi_admin_flags_dofstv,
        &hf_nvme_mi_admin_flags_dlenv,
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

        /* On an error response bytes 3:1 are the Parameter Error Location, the
         * More Processing Required Time, or Reserved; the shared helper owns
         * them (NVMe-MI 2.1 "Generic Error Response" / "Invalid Parameter
         * Error Response Fields" / "More Processing Required Response
         * Fields").  Only a Success Response reaches the Admin-specific
         * layout, whose bytes 3:1 are Reserved (the "NVMe Admin Command
         * Response Description" figure, message bytes 7:5). */
        if (nvme_mi_dissect_resp_status_bytes(tvb, admin_tree, status))
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_resp_rsvd,
                                tvb, 1, 3, ENC_LITTLE_ENDIAN);

        if (len >= 16) {
            /* When the matching request was recovered (it2 != NULL) its saved
             * per-opcode context lets the command-specific completion result
             * (CQE DW0) decode with the same NVMe field names packet-nvme.c
             * uses; otherwise DW0 stays a raw dword.  The raw cqe_dw0 alias is
             * kept as a filterable hidden item on that path either way.
             * The structured path peeks the CQE status word at bytes 15:14
             * directly, so it also requires those bytes to actually be
             * captured (a snaplen-sliced frame can report 16+ bytes while
             * capturing fewer). */
            struct nvme_mi_admin_req_ctx *req =
                (it2 && tvb_bytes_exist(tvb, 14, 2))
                    ? (struct nvme_mi_admin_req_ctx *)trans->body_ctx : NULL;

            proto_item *cqe_dw0 = proto_tree_add_item(admin_tree,
                                                   hf_nvme_mi_admin_cqe_dw0,
                                                   tvb, 4, 4, ENC_LITTLE_ENDIAN);
            if (req) {
                /* Hide the raw alias; the structured DW0 decode takes over.
                 * The CQE status word (DW3 + 2) selects the Set Features
                 * success/error rendering, so it is only read on this path. */
                proto_item_set_hidden(cqe_dw0);
                nvme_dissect_admin_cqe_dw0(tvb, 4, admin_tree,
                                           tvb_get_uint16(tvb, 14, ENC_LITTLE_ENDIAN),
                                           &req->cmd);
            }

            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe_dw1,
                                tvb, 8, 4, ENC_LITTLE_ENDIAN);

            /* CQE DW3: keep the raw dword (it also carries the phase tag) and
             * decode the NVMe status word (SCT/SC/M/DNR) in its upper half via
             * the shared helper, at the standard CQE status offset (DW3 + 2). */
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe_dw3,
                                tvb, 12, 4, ENC_LITTLE_ENDIAN);
            nvme_dissect_cqe_status(tvb, pinfo, 14, admin_tree);

            if (len > 16) {
                /* The response data payload is a slice of the command's logical
                 * data structure beginning at the request's Data Offset
                 * (DOFST).  When the matching request was recovered, hand the
                 * slice to the shared NVMe Admin data decoder at that offset so
                 * Identify / Get Log Page / Get-Set Features render structured
                 * fields instead of a raw blob; the raw alias is kept (hidden
                 * on success) for display-filter compatibility.  'len - 16' is
                 * the number of bytes actually present, so a truncated capture
                 * still stops cleanly regardless of the requested DLEN. */
                unsigned data_len = len - 16;
                proto_item *data_it = proto_tree_add_item(admin_tree,
                                                          hf_nvme_mi_admin_data,
                                                          tvb, 16, -1, ENC_NA);
                if (req) {
                    unsigned off = req->dofst;
                    tvbuff_t *data_tvb = tvb_new_subset_length(tvb, 16, data_len);
                    proto_item *data_sub_it;
                    proto_tree *data_tree =
                        proto_tree_add_subtree(admin_tree, data_tvb, 0, data_len,
                                               ett_nvme_mi_admin_data,
                                               &data_sub_it, "Data");
                    nvme_dissect_admin_data_resp(data_tvb, pinfo, data_tree,
                                                 &req->cmd, off, data_len);
                    nvme_mi_admin_hide_raw_or_structured(data_it, data_sub_it,
                                                         data_tree);
                }
            }
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
        req = nvme_mi_trans_body_ctx(trans, sizeof(*req));
    } else {
        /* No transaction (orphan request or external caller): a throwaway
         * packet-scope context is enough to drive the CDW decode. */
        req = wmem_new0(pinfo->pool, struct nvme_mi_admin_req_ctx);
    }
    req->cmd.opcode = opcode;

    /* NVMe-MI envelope fields: the SQE positions NVMe-MI repurposes for its
     * own meaning (Command Flags, Controller ID in place of CID, Data
     * Offset/Length in place of PRP1, and the following reserved dwords).
     *
     * DOFSTV/DLENV (Command Flags bits 1:0) are obsolete and shall be ignored
     * by 2.1-compliant Management Endpoints (NVMe-MI 2.1 "NVMe Admin Command
     * Request Description"), so the Data Offset/Length fields are always
     * meaningful.  They are captured as they are added to the tree so the
     * response pass can slice its data payload into the shared NVMe decoders
     * at the requested offset; DOFST is 0h for commands that do not transfer
     * Response Data, which yields the correct offset-0 slice. */
    uint64_t flags;
    proto_item *flags_it = proto_tree_add_bitmask_ret_uint64(admin_tree, tvb, 1,
                           hf_nvme_mi_admin_flags,
                           ett_nvme_mi_admin_flags, nvme_mi_admin_flags,
                           ENC_NA, &flags);
    if (flags & (NVME_MI_ADMIN_FLAG_DOFSTV | NVME_MI_ADMIN_FLAG_DLENV))
        expert_add_info(pinfo, flags_it, &ei_nvme_mi_admin_obsolete_flag);

    proto_tree_add_item(admin_tree, hf_nvme_mi_admin_ctrl_id,
                        tvb, 2, 2, ENC_LITTLE_ENDIAN);
    proto_item *doff_it = proto_tree_add_item_ret_uint(admin_tree,
                                 hf_nvme_mi_admin_doff,
                                 tvb, 24, 4, ENC_LITTLE_ENDIAN, &req->dofst);
    proto_item *dlen_it = proto_tree_add_item_ret_uint(admin_tree,
                                 hf_nvme_mi_admin_dlen,
                                 tvb, 28, 4, ENC_LITTLE_ENDIAN, &req->dlen);
    /* A Management Endpoint rejects a misaligned DOFST/DLEN or a DLEN above
     * 4096 with Invalid Parameter (NVMe-MI 2.1 "NVMe Admin Command Request
     * Description"); surface those so a non-compliant requester is visible. */
    if (req->dofst & 0x3)
        expert_add_info(pinfo, doff_it, &ei_nvme_mi_admin_invalid_dofst);
    if (req->dlen & 0x3)
        expert_add_info_format(pinfo, dlen_it, &ei_nvme_mi_admin_invalid_dlen,
                               "Data Length %u is not dword-aligned"
                               " (bits 1:0 must be cleared to 00b)", req->dlen);
    else if (req->dlen > 4096)
        expert_add_info_format(pinfo, dlen_it, &ei_nvme_mi_admin_invalid_dlen,
                               "Data Length %u exceeds the 4096-byte maximum",
                               req->dlen);
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

    if (len > 64) {
        /* Inline request data (offset 64 onward) is a slice of the command's
         * logical data structure beginning at the request's Data Offset
         * (DOFST), same as the response-side dispatch above.  For Set
         * Features this routes through the shared packet-nvme.c per-FID
         * transfer decoder (e.g. the Host Metadata structure written for FID
         * 7Dh/7Eh/7Fh, the LBA Range / APST / Timestamp / Host Behavior
         * structures for the others); other opcodes keep the raw Data blob. */
        unsigned data_len = len - 64;
        proto_item *data_it = proto_tree_add_item(admin_tree,
                                                  hf_nvme_mi_admin_data,
                                                  tvb, 64, -1, ENC_NA);
        unsigned off = req->dofst;
        tvbuff_t *data_tvb = tvb_new_subset_length(tvb, 64, data_len);
        proto_item *data_sub_it;
        proto_tree *data_tree =
            proto_tree_add_subtree(admin_tree, data_tvb, 0, data_len,
                                   ett_nvme_mi_admin_data,
                                   &data_sub_it, "Data");
        nvme_dissect_admin_data_resp(data_tvb, pinfo, data_tree, &req->cmd,
                                     off, data_len);
        nvme_mi_admin_hide_raw_or_structured(data_it, data_sub_it, data_tree);
    }

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
            "Admin Command Opcode (NVMe-MI 2.1 'List of NVMe Admin"
            " Commands Supported using the Out-of-Band Mechanism')", HFILL },
        },
        { &hf_nvme_mi_admin_status,
          { "Status", "nvme-mi.admin.status",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_mi_status_vals), 0,
            "Response Message Status (NVMe-MI 2.1 'Response Message"
            " Status Values')", HFILL },
        },
        { &hf_nvme_mi_admin_flags,
          { "Command Flags", "nvme-mi.admin.flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_flags_ish,
          { "Ignore Shutdown (ISH)", "nvme-mi.admin.flags.ish",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), NVME_MI_ADMIN_FLAG_ISH,
            "Effect specified in NVMe-MI 2.1 §8.5; no effect on CSTS.SHST",
            HFILL },
        },
        { &hf_nvme_mi_admin_flags_dofstv,
          { "Data Offset Valid (DOFSTV)", "nvme-mi.admin.flags.dofstv",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), NVME_MI_ADMIN_FLAG_DOFSTV,
            "Obsolete: not used and shall be ignored by Management Endpoints"
            " compliant with NVMe-MI later than 1.1 (the 'NVMe Admin"
            " Command Request Description' figure)", HFILL },
        },
        { &hf_nvme_mi_admin_flags_dlenv,
          { "Data Length Valid (DLENV)", "nvme-mi.admin.flags.dlenv",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), NVME_MI_ADMIN_FLAG_DLENV,
            "Obsolete: not used and shall be ignored by Management Endpoints"
            " compliant with NVMe-MI later than 1.1 (the 'NVMe Admin"
            " Command Request Description' figure)", HFILL },
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
            "Reserved over NVMe-MI: the MPTR and PRP2 fields are reserved for"
            " commands sent using the out-of-band mechanism (NVMe-MI 2.1 \u00a76)",
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
        /* The MI response carries CQE dwords 0, 1 and 3 — DW2 (SQ head
         * pointer / SQ ID) is meaningless over MCTP and omitted (NVMe-MI 2.1
         * "NVMe Admin Command Response Description").  The filter suffixes
         * match the CQE dword numbers. */
        { &hf_nvme_mi_admin_cqe_dw0,
          { "Completion Queue Entry dword 0", "nvme-mi.admin.cqe_dw0",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Command-specific result (CQE DW0)", HFILL },
        },
        { &hf_nvme_mi_admin_cqe_dw1,
          { "Completion Queue Entry dword 1", "nvme-mi.admin.cqe_dw1",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Reserved in Admin completions (CQE DW1)", HFILL },
        },
        { &hf_nvme_mi_admin_cqe_dw3,
          { "Completion Queue Entry dword 3", "nvme-mi.admin.cqe_dw3",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Phase tag, status (SCT/SC/M/DNR) and command identifier"
            " (CQE DW3)", HFILL },
        },
        { &hf_nvme_mi_admin_data,
          { "Data", "nvme-mi.admin.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },
    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi_admin,
        &ett_nvme_mi_admin_flags,
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
            "Admin response without a usable matching request (missing or"
            " truncated); opcode could not be recovered", EXPFILL }
        },
        { &ei_nvme_mi_admin_short_cqe,
          { "nvme-mi.admin.short_cqe", PI_MALFORMED, PI_WARN,
            "Success Response shorter than the 16-byte status + CQE dwords"
            " block", EXPFILL }
        },
        { &ei_nvme_mi_admin_prohibited_opcode,
          { "nvme-mi.admin.prohibited_opcode", PI_PROTOCOL, PI_WARN,
            "Admin opcode is Prohibited over the Management Interface"
            " (NVMe-MI 2.1 'List of NVMe Admin Commands Supported using"
            " the Out-of-Band Mechanism')", EXPFILL }
        },
        { &ei_nvme_mi_admin_obsolete_flag,
          { "nvme-mi.admin.obsolete_flag", PI_PROTOCOL, PI_COMMENT,
            "DOFSTV/DLENV Command Flags bits are obsolete and shall be ignored"
            " by Management Endpoints compliant with NVMe-MI later than 1.1"
            " (the 'NVMe Admin Command Request Description' figure)", EXPFILL },
        },
        { &ei_nvme_mi_admin_invalid_dofst,
          { "nvme-mi.admin.invalid_dofst", PI_PROTOCOL, PI_WARN,
            "Data Offset is not dword-aligned (bits 1:0 must be cleared to"
            " 00b); a Management Endpoint returns Invalid Parameter (NVMe-MI"
            " 2.1 'NVMe Admin Command Request Description')", EXPFILL },
        },
        { &ei_nvme_mi_admin_invalid_dlen,
          { "nvme-mi.admin.invalid_dlen", PI_PROTOCOL, PI_WARN,
            "Data Length must be dword-aligned and at most 4096 bytes; a"
            " Management Endpoint returns Invalid Parameter (NVMe-MI 2.1"
            " 'NVMe Admin Command Request Description')", EXPFILL },
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
