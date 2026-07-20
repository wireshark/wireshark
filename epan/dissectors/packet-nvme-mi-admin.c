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
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
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
static int hf_nvme_mi_admin_sqe1;
static int hf_nvme_mi_admin_sqe2;
static int hf_nvme_mi_admin_sqe3;
static int hf_nvme_mi_admin_sqe4;
static int hf_nvme_mi_admin_sqe5;
static int hf_nvme_mi_admin_doff;
static int hf_nvme_mi_admin_dlen;
static int hf_nvme_mi_admin_resv0;
static int hf_nvme_mi_admin_resv1;
static int hf_nvme_mi_admin_sqe10;
static int hf_nvme_mi_admin_sqe11;
static int hf_nvme_mi_admin_sqe12;
static int hf_nvme_mi_admin_sqe13;
static int hf_nvme_mi_admin_sqe14;
static int hf_nvme_mi_admin_sqe15;
static int hf_nvme_mi_admin_data;
static int hf_nvme_mi_admin_cqe1;
static int hf_nvme_mi_admin_cqe2;
static int hf_nvme_mi_admin_cqe3;

static int ett_nvme_mi_admin;
static int ett_nvme_mi_admin_flags;

static expert_field ei_nvme_mi_admin_truncated;
static expert_field ei_nvme_mi_admin_orphan_response;

/* Same opcode namespace as packet-nvme.c's aq_opc_tbl; kept in sync by hand
 * until the two dissectors share one exported table. */
static const value_string admin_opcode_vals[] = {
    { 0x00, "Delete I/O Submission Queue" },
    { 0x01, "Create I/O Submission Queue" },
    { 0x02, "Get Log Page" },
    { 0x04, "Delete I/O Completion Queue" },
    { 0x05, "Create I/O Completion Queue" },
    { 0x06, "Identify" },
    { 0x08, "Abort" },
    { 0x09, "Set Features" },
    { 0x0a, "Get Features" },
    { 0x0c, "Asynchronous Event Request" },
    { 0x0d, "Namespace Management" },
    { 0x10, "Firmware Commit" },
    { 0x11, "Firmware Image Download" },
    { 0x15, "Namespace Attachment" },
    { 0x18, "Keep Alive" },
    { 0x80, "Format NVM" },
    { 0x81, "Security Send" },
    { 0x82, "Security Receive" },
    { 0, NULL },
};

static int
dissect_nvme_mi_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      void *data)
{
    static int * const nvme_mi_admin_flags[] = {
        &hf_nvme_mi_admin_flags_doff,
        &hf_nvme_mi_admin_flags_dlen,
        NULL,
    };
    struct nvme_mi_dissect_ctx *ctx = (struct nvme_mi_dissect_ctx *)data;
    proto_tree *admin_tree;
    proto_item *it, *it2;

    if (!ctx)
        return 0;

    bool resp = ctx->resp;
    struct nvme_mi_transaction *trans = ctx->trans;
    unsigned len = tvb_reported_length(tvb);

    it = proto_tree_add_item(tree, proto_nvme_mi_admin, tvb, 0, -1, ENC_NA);
    admin_tree = proto_item_add_subtree(it, ett_nvme_mi_admin);
    proto_item_set_text(it, "NVMe Admin %s", resp ? "response" : "request");

    if (resp) {
        /* The response carries no opcode; recover it from the request.  When
         * there is no matching request (or it was too truncated to record an
         * opcode), say so rather than fabricating an opcode-0 item. */
        if (trans && trans->req_parsed) {
            it2 = proto_tree_add_uint(admin_tree, hf_nvme_mi_admin_opcode,
                                      tvb, 0, 0, trans->opcode);
            proto_item_set_generated(it2);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                            val_to_str_const(trans->opcode, admin_opcode_vals,
                                             "Unknown"));
        } else {
            expert_add_info(pinfo, it, &ei_nvme_mi_admin_orphan_response);
        }

        if (len < 1) {
            expert_add_info(pinfo, it, &ei_nvme_mi_admin_truncated);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_status,
                            tvb, 0, 1, ENC_NA);

        if (len >= 16) {
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe1,
                                tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe2,
                                tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe3,
                                tvb, 12, 4, ENC_LITTLE_ENDIAN);
        }

        if (len > 16)
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                tvb, 16, -1, ENC_NA);
    } else {
        if (len < 1) {
            expert_add_info(pinfo, it, &ei_nvme_mi_admin_truncated);
            return tvb_captured_length(tvb);
        }

        uint8_t opcode;
        proto_tree_add_item_ret_uint8(admin_tree, hf_nvme_mi_admin_opcode,
                                      tvb, 0, 1, ENC_NA, &opcode);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                        val_to_str_const(opcode, admin_opcode_vals,
                                         "Unknown"));
        /* Record the request opcode for the matching response. */
        if (trans) {
            trans->opcode = opcode;
            trans->req_parsed = true;
        }

        /* The fixed part of an Admin request is the full 64-byte SQE.  For
         * anything shorter, flag the truncation and show the remaining bytes
         * raw instead of throwing mid-tree. */
        if (len < 64) {
            expert_add_info(pinfo, it, &ei_nvme_mi_admin_truncated);
            if (len > 1)
                proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                    tvb, 1, -1, ENC_NA);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_bitmask(admin_tree, tvb, 1, hf_nvme_mi_admin_flags,
                               ett_nvme_mi_admin_flags, nvme_mi_admin_flags,
                               ENC_NA);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_ctrl_id,
                            tvb, 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe1,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe2,
                            tvb, 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe3,
                            tvb, 12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe4,
                            tvb, 16, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe5,
                            tvb, 20, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_doff,
                            tvb, 24, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_dlen,
                            tvb, 28, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_resv0,
                            tvb, 32, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_resv1,
                            tvb, 36, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe10,
                            tvb, 40, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe11,
                            tvb, 44, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe12,
                            tvb, 48, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe13,
                            tvb, 52, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe14,
                            tvb, 56, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_sqe15,
                            tvb, 60, 4, ENC_LITTLE_ENDIAN);

        if (len > 64)
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                tvb, 64, -1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_nvme_mi_admin(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        { &hf_nvme_mi_admin_opcode,
          { "Opcode", "nvme-mi.admin.opcode",
            FT_UINT8, BASE_HEX, VALS(admin_opcode_vals), 0,
            NULL, HFILL },
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
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x1,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_flags_doff,
          { "Use Data Offset", "nvme-mi.admin.flags.doff",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x2,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_ctrl_id,
          { "Controller ID", "nvme-mi.admin.ctrl-id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe1,
          { "Submission Queue Entry dword 1", "nvme-mi.admin.sqe1",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe2,
          { "Submission Queue Entry dword 2", "nvme-mi.admin.sqe2",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe3,
          { "Submission Queue Entry dword 3", "nvme-mi.admin.sqe3",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe4,
          { "Submission Queue Entry dword 4", "nvme-mi.admin.sqe4",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe5,
          { "Submission Queue Entry dword 5", "nvme-mi.admin.sqe5",
            FT_UINT32, BASE_HEX, NULL, 0,
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
        { &hf_nvme_mi_admin_sqe10,
          { "Submission Queue Entry dword 10", "nvme-mi.admin.sqe10",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe11,
          { "Submission Queue Entry dword 11", "nvme-mi.admin.sqe11",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe12,
          { "Submission Queue Entry dword 12", "nvme-mi.admin.sqe12",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe13,
          { "Submission Queue Entry dword 13", "nvme-mi.admin.sqe13",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe14,
          { "Submission Queue Entry dword 14", "nvme-mi.admin.sqe14",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_sqe15,
          { "Submission Queue Entry dword 15", "nvme-mi.admin.sqe15",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_cqe1,
          { "Completion Queue Entry dword 1", "nvme-mi.admin.cqe1",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_cqe2,
          { "Completion Queue Entry dword 2", "nvme-mi.admin.cqe2",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_cqe3,
          { "Completion Queue Entry dword 3", "nvme-mi.admin.cqe3",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
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
