/* packet-nvme-mi-mi.c
 * NVMe-MI MI Command dissector (NMIMT=1, NVMe-MI 2.1 §5)
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
#include <wsutil/array.h>
#include "packet-nvme-mi.h"

void proto_register_nvme_mi_mi(void);
void proto_reg_handoff_nvme_mi_mi(void);

static int proto_nvme_mi_mi;

static int hf_nvme_mi_mi_opcode;
static int hf_nvme_mi_mi_cdw0;
static int hf_nvme_mi_mi_cdw1;
static int hf_nvme_mi_mi_status;
static int hf_nvme_mi_mi_nmresp;
static int hf_nvme_mi_mi_data;

static int ett_nvme_mi_mi;

static expert_field ei_nvme_mi_mi_truncated;
static expert_field ei_nvme_mi_mi_orphan_response;

static const value_string mi_opcode_vals[] = {
    { 0x00, "Read NVMe-MI Data Structure" },
    { 0x01, "NVM Subsystem Health Status Poll" },
    { 0x02, "Controller Health Status Poll" },
    { 0x03, "Configuration Set" },
    { 0x04, "Configuration Get" },
    { 0, NULL },
};

static int
dissect_nvme_mi_mi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   void *data)
{
    struct nvme_mi_dissect_ctx *ctx = (struct nvme_mi_dissect_ctx *)data;
    proto_item *it, *it2;
    proto_tree *mi_tree;

    if (!ctx)
        return 0;

    bool resp = ctx->resp;
    struct nvme_mi_transaction *trans = ctx->trans;
    unsigned len = tvb_reported_length(tvb);

    it = proto_tree_add_item(tree, proto_nvme_mi_mi, tvb, 0, -1, ENC_NA);
    mi_tree = proto_item_add_subtree(it, ett_nvme_mi_mi);

    if (!resp) {
        uint8_t opcode;

        if (len < 1) {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_item_ret_uint8(mi_tree, hf_nvme_mi_mi_opcode, tvb, 0, 1, ENC_NA, &opcode);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                        val_to_str_const(opcode, mi_opcode_vals, "Unknown"));
        /* Record the request opcode so the matching response (which carries
         * no opcode of its own) can display it. */
        if (trans) {
            trans->opcode = opcode;
            trans->req_parsed = true;
        }

        if (len < 12) {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
            if (len > 1)
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                    tvb, 1, -1, ENC_NA);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw0,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw1,
                            tvb, 8, 4, ENC_LITTLE_ENDIAN);

        if (len > 12)
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                tvb, 12, -1, ENC_NA);
    } else {
        /* The response carries no opcode; recover it from the request.  When
         * there is no matching request (or it was too truncated to record an
         * opcode), say so rather than fabricating an opcode-0 item. */
        if (trans && trans->req_parsed) {
            it2 = proto_tree_add_uint(mi_tree, hf_nvme_mi_mi_opcode,
                                      tvb, 0, 0, trans->opcode);
            proto_item_set_generated(it2);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                            val_to_str_const(trans->opcode, mi_opcode_vals,
                                             "Unknown"));
        } else {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_orphan_response);
        }

        if (len < 1) {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_status,
                            tvb, 0, 1, ENC_NA);

        if (len < 4) {
            expert_add_info(pinfo, it, &ei_nvme_mi_mi_truncated);
            if (len > 1)
                proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                    tvb, 1, -1, ENC_NA);
            return tvb_captured_length(tvb);
        }

        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_nmresp,
                            tvb, 1, 3, ENC_LITTLE_ENDIAN);

        if (len > 4)
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                tvb, 4, -1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_nvme_mi_mi(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        { &hf_nvme_mi_mi_opcode,
          { "Opcode", "nvme-mi.mi.opcode",
            FT_UINT8, BASE_HEX, VALS(mi_opcode_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cdw0,
          { "Command dword 0", "nvme-mi.mi.cdw0",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_cdw1,
          { "Command dword 1", "nvme-mi.mi.cdw1",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_status,
          { "Status", "nvme-mi.mi.status",
            FT_UINT8, BASE_HEX, VALS(nvme_mi_status_vals), 0,
            "Response Message Status (NVMe-MI 2.1 Figure 29)", HFILL },
        },
        { &hf_nvme_mi_mi_nmresp,
          { "Management Response", "nvme-mi.mi.nmresp",
            FT_UINT24, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mi_data,
          { "Data", "nvme-mi.mi.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },
    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi_mi,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_mi_mi_truncated,
          { "nvme-mi.mi.truncated", PI_MALFORMED, PI_WARN,
            "MI command payload truncated", EXPFILL },
        },
        { &ei_nvme_mi_mi_orphan_response,
          { "nvme-mi.mi.orphan_response", PI_SEQUENCE, PI_NOTE,
            "MI response without a usable matching request (missing or "
            "truncated); opcode could not be recovered", EXPFILL },
        },
    };

    expert_module_t *expert_nvme_mi_mi;

    proto_nvme_mi_mi = proto_register_protocol(
            "NVMe-MI MI Command", "NVMe-MI MI", "nvme-mi.mi");
    proto_register_field_array(proto_nvme_mi_mi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi_mi = expert_register_protocol(proto_nvme_mi_mi);
    expert_register_field_array(expert_nvme_mi_mi, ei, array_length(ei));
}

void
proto_reg_handoff_nvme_mi_mi(void)
{
    dissector_add_uint("nvme-mi.type", NVME_MI_TYPE_MI,
                       create_dissector_handle(dissect_nvme_mi_mi,
                                               proto_nvme_mi_mi));
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
