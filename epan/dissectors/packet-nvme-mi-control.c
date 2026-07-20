/* packet-nvme-mi-control.c
 * NVMe-MI Control Primitive dissector (NMIMT=0, NVMe-MI 2.1 §4.2.1)
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

void proto_register_nvme_mi_control(void);
void proto_reg_handoff_nvme_mi_control(void);

static int proto_nvme_mi_control;

static int hf_nvme_mi_ctl_opcode;
static int hf_nvme_mi_ctl_status;
static int hf_nvme_mi_ctl_tag;
static int hf_nvme_mi_ctl_cpsp;
static int hf_nvme_mi_ctl_cpsr;
/* Get State CPSP */
static int hf_nvme_mi_ctl_cesf;
/* Abort CPSR */
static int hf_nvme_mi_ctl_cpas;
/* Get State CPSR — Management Endpoint State (MES) flag bits */
static int hf_nvme_mi_ctl_mes_pflg;
static int hf_nvme_mi_ctl_mes_nssro;
static int hf_nvme_mi_ctl_mes_bpopl;
static int hf_nvme_mi_ctl_mes_buemt;
static int hf_nvme_mi_ctl_mes_ospsn;
static int hf_nvme_mi_ctl_mes_umep;
static int hf_nvme_mi_ctl_mes_itu;
static int hf_nvme_mi_ctl_mes_udstid;
static int hf_nvme_mi_ctl_mes_bhvs;
static int hf_nvme_mi_ctl_mes_utunt;
static int hf_nvme_mi_ctl_mes_bmice;
static int hf_nvme_mi_ctl_mes_cmnics;
static int hf_nvme_mi_ctl_mes_ssta;
/* Replay CPSP / CPSR */
static int hf_nvme_mi_ctl_rro;
static int hf_nvme_mi_ctl_rr;

static int ett_nvme_mi_control;
static int ett_nvme_mi_ctl_cpsp;
static int ett_nvme_mi_ctl_cpsr;

static expert_field ei_nvme_mi_ctl_truncated;
static expert_field ei_nvme_mi_ctl_reserved_opcode;
static expert_field ei_nvme_mi_ctl_orphan_response;
static expert_field ei_nvme_mi_ctl_tag_mismatch;

/* Control Primitive opcodes (NVMe-MI 2.1 Figure 38, §4.2.1).
 * 05h..EFh are reserved; F0h..FFh are vendor specific. */
enum nvme_mi_cp_opc {
    NVME_MI_CP_OPC_PAUSE     = 0x00,
    NVME_MI_CP_OPC_RESUME    = 0x01,
    NVME_MI_CP_OPC_ABORT     = 0x02,
    NVME_MI_CP_OPC_GET_STATE = 0x03,
    NVME_MI_CP_OPC_REPLAY    = 0x04,
    NVME_MI_CP_OPC_RESERVED_FIRST  = 0x05,
    NVME_MI_CP_OPC_RESERVED_LAST   = 0xEF,
};

static const value_string cp_opcode_vals[] = {
    { NVME_MI_CP_OPC_PAUSE,     "Pause" },
    { NVME_MI_CP_OPC_RESUME,    "Resume" },
    { NVME_MI_CP_OPC_ABORT,     "Abort" },
    { NVME_MI_CP_OPC_GET_STATE, "Get State" },
    { NVME_MI_CP_OPC_REPLAY,    "Replay" },
    { 0, NULL },
};

/* CPAS — Command Processing Abort Status (Abort CPSR, NVMe-MI 2.1 §4.2.1.3) */
static const value_string cpas_vals[] = {
    { 0, "Aborted after processing completed / no command in slot" },
    { 1, "Aborted before processing began" },
    { 2, "Aborted after processing partially completed" },
    { 3, "Reserved" },
    { 0, NULL },
};

/* SSTA — Slot Servicing State (Get State CPSR MES bits 1:0, §4.2.1.4) */
static const value_string ssta_vals[] = {
    { 0, "Idle" },
    { 1, "Receive" },
    { 2, "Process" },
    { 3, "Transmit" },
    { 0, NULL },
};

static int * const cpsr_abort_fields[]    = { &hf_nvme_mi_ctl_cpas, NULL };
static int * const cpsp_getstate_fields[] = { &hf_nvme_mi_ctl_cesf, NULL };
static int * const cpsr_mes_fields[] = {
    &hf_nvme_mi_ctl_mes_pflg,
    &hf_nvme_mi_ctl_mes_nssro,
    &hf_nvme_mi_ctl_mes_bpopl,
    &hf_nvme_mi_ctl_mes_buemt,
    &hf_nvme_mi_ctl_mes_ospsn,
    &hf_nvme_mi_ctl_mes_umep,
    &hf_nvme_mi_ctl_mes_itu,
    &hf_nvme_mi_ctl_mes_udstid,
    &hf_nvme_mi_ctl_mes_bhvs,
    &hf_nvme_mi_ctl_mes_utunt,
    &hf_nvme_mi_ctl_mes_bmice,
    &hf_nvme_mi_ctl_mes_cmnics,
    &hf_nvme_mi_ctl_mes_ssta,
    NULL,
};
static int * const cpsp_replay_fields[] = { &hf_nvme_mi_ctl_rro, NULL };
static int * const cpsr_replay_fields[] = { &hf_nvme_mi_ctl_rr, NULL };

/* Add the 2-byte CPSP/CPSR at payload offset 2, decoded via the given bitmask
 * field array, or rendered as a raw 16-bit value when fields is NULL. */
static void
dissect_nvme_mi_ctl_cpsx(proto_tree *tree, tvbuff_t *tvb, int hf, int ett,
                         int * const *fields)
{
    if (fields)
        proto_tree_add_bitmask(tree, tvb, 2, hf, ett, fields,
                               ENC_LITTLE_ENDIAN);
    else
        proto_tree_add_item(tree, hf, tvb, 2, 2, ENC_LITTLE_ENDIAN);
}

static int
dissect_nvme_mi_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        void *data)
{
    struct nvme_mi_dissect_ctx *ctx = (struct nvme_mi_dissect_ctx *)data;
    int * const *fields = NULL;
    proto_item *it, *it2;
    proto_tree *ctl_tree;
    uint8_t     opcode = 0;
    uint8_t     tag = 0;

    if (!ctx)
        return 0;

    bool resp = ctx->resp;
    struct nvme_mi_transaction *trans = ctx->trans;

    it = proto_tree_add_item(tree, proto_nvme_mi_control, tvb, 0, -1, ENC_NA);
    ctl_tree = proto_item_add_subtree(it, ett_nvme_mi_control);
    proto_item_set_text(it, "NVMe-MI Control Primitive %s",
                        resp ? "response" : "request");

    if (tvb_reported_length(tvb) < 4) {
        /* Best-effort COL_INFO for a truncated response whose request we saw. */
        if (resp && trans && trans->req_parsed)
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                            val_to_str_const(trans->opcode, cp_opcode_vals,
                                             "Unknown"));
        expert_add_info(pinfo, it, &ei_nvme_mi_ctl_truncated);
        return tvb_captured_length(tvb);
    }

    if (resp) {
        /* The response carries no opcode; recover it from the matched request.
         * Without a usable matching request (missing, or too truncated to
         * record opcode and tag) we cannot know which CPSR layout applies, so
         * render the raw value rather than guessing the primitive. */
        if (trans && trans->req_parsed) {
            opcode = (uint8_t)trans->opcode;
            it2 = proto_tree_add_uint(ctl_tree, hf_nvme_mi_ctl_opcode,
                                      tvb, 0, 0, opcode);
            proto_item_set_generated(it2);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                            val_to_str_const(opcode, cp_opcode_vals,
                                             "Unknown"));
        } else {
            expert_add_info(pinfo, it, &ei_nvme_mi_ctl_orphan_response);
        }

        proto_tree_add_item(ctl_tree, hf_nvme_mi_ctl_status, tvb, 0, 1, ENC_NA);
        proto_tree_add_item_ret_uint8(ctl_tree, hf_nvme_mi_ctl_tag, tvb, 1, 1, ENC_NA, &tag);

        /* The response tag must echo the request tag (NVMe-MI 2.1 §4.2.1). */
        if (trans && trans->req_parsed && tag != trans->cp_tag)
            expert_add_info(pinfo, it, &ei_nvme_mi_ctl_tag_mismatch);

        switch (opcode) {
        case NVME_MI_CP_OPC_ABORT:
            fields = cpsr_abort_fields;
            break;
        case NVME_MI_CP_OPC_GET_STATE:
            fields = cpsr_mes_fields;
            break;
        case NVME_MI_CP_OPC_REPLAY:
            fields = cpsr_replay_fields;
            break;
        default:
            /* Pause/Resume CPSR is reserved (Pause has obsolete must-be-1
             * bits, rendered raw); unknown/vendor opcodes and orphan
             * responses also land here. */
            break;
        }
    } else {
        proto_item *opc_it;

        opc_it = proto_tree_add_item_ret_uint8(ctl_tree, hf_nvme_mi_ctl_opcode,
                                     tvb, 0, 1, ENC_NA, &opcode);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                        val_to_str_const(opcode, cp_opcode_vals, "Unknown"));

        if (opcode >= NVME_MI_CP_OPC_RESERVED_FIRST &&
            opcode <= NVME_MI_CP_OPC_RESERVED_LAST)
            expert_add_info(pinfo, opc_it, &ei_nvme_mi_ctl_reserved_opcode);

        proto_tree_add_item_ret_uint8(ctl_tree, hf_nvme_mi_ctl_tag, tvb, 1, 1, ENC_NA, &tag);

        /* Record opcode and tag so the matching response can pick the correct
         * CPSR layout and validate its echoed tag. */
        if (trans) {
            trans->opcode = opcode;
            trans->cp_tag = tag;
            trans->req_parsed = true;
        }

        switch (opcode) {
        case NVME_MI_CP_OPC_GET_STATE:
            fields = cpsp_getstate_fields;
            break;
        case NVME_MI_CP_OPC_REPLAY:
            fields = cpsp_replay_fields;
            break;
        default:
            /* Pause/Resume/Abort CPSP is reserved; rendered raw. */
            break;
        }
    }

    dissect_nvme_mi_ctl_cpsx(ctl_tree, tvb,
                             resp ? hf_nvme_mi_ctl_cpsr : hf_nvme_mi_ctl_cpsp,
                             resp ? ett_nvme_mi_ctl_cpsr : ett_nvme_mi_ctl_cpsp,
                             fields);

    return tvb_captured_length(tvb);
}

void
proto_register_nvme_mi_control(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        { &hf_nvme_mi_ctl_opcode,
          { "Control Primitive Opcode (CPO)", "nvme-mi.control.opcode",
            FT_UINT8, BASE_HEX, VALS(cp_opcode_vals), 0,
            "Control Primitive being requested (NVMe-MI 2.1 §4.2.1)", HFILL },
        },
        { &hf_nvme_mi_ctl_status,
          { "Status", "nvme-mi.control.status",
            FT_UINT8, BASE_HEX, VALS(nvme_mi_status_vals), 0,
            "Response Message Status (NVMe-MI 2.1 Figure 29)", HFILL },
        },
        { &hf_nvme_mi_ctl_tag,
          { "Tag", "nvme-mi.control.tag",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Tracking identifier; echoed verbatim in the response", HFILL },
        },
        { &hf_nvme_mi_ctl_cpsp,
          { "Control Primitive Specific Parameter (CPSP)", "nvme-mi.control.cpsp",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Opcode-specific request parameter", HFILL },
        },
        { &hf_nvme_mi_ctl_cpsr,
          { "Control Primitive Specific Response (CPSR)", "nvme-mi.control.cpsr",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Opcode-specific response data; undefined on error status", HFILL },
        },
        { &hf_nvme_mi_ctl_cesf,
          { "Clear Error State Flags (CESF)", "nvme-mi.control.cesf",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001,
            "Atomically clear MES error-state bits when set (Get State, §4.2.1.4)",
            HFILL },
        },
        { &hf_nvme_mi_ctl_cpas,
          { "Command Processing Abort Status (CPAS)", "nvme-mi.control.cpas",
            FT_UINT16, BASE_HEX, VALS(cpas_vals), 0x0003,
            "Outcome of an Abort primitive (§4.2.1.3)", HFILL },
        },
        /* MES — Management Endpoint State (CPSR for Get State, Figure 43) */
        { &hf_nvme_mi_ctl_mes_pflg,
          { "Pause Flag (PFLG)", "nvme-mi.control.mes.pflg",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000,
            "Management Endpoint is paused", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_nssro,
          { "NVM Subsystem Reset Occurred (NSSRO)", "nvme-mi.control.mes.nssro",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000,
            "An NVM Subsystem Reset has occurred since the last clear", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_bpopl,
          { "Bad Packet or Other Physical Layer (BPOPL)", "nvme-mi.control.mes.bpopl",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x2000,
            "Physical-layer transport error observed", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_buemt,
          { "Bad/Unexpected/Expired Message Tag (BUEMT)", "nvme-mi.control.mes.buemt",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x1000,
            "Received MCTP message tag was invalid or unexpected", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_ospsn,
          { "Out-of-Sequence Packet Sequence Number (OSPSN)", "nvme-mi.control.mes.ospsn",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0800,
            "Packet sequence number arrived out of order", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_umep,
          { "Unexpected Middle or End of Packet (UMEP)", "nvme-mi.control.mes.umep",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0400,
            "Middle/end packet received without a preceding start", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_itu,
          { "Incorrect Transmission Unit (ITU)", "nvme-mi.control.mes.itu",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0200,
            "Received transmission unit size differs from negotiated", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_udstid,
          { "Unknown Destination ID (UDSTID)", "nvme-mi.control.mes.udstid",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0100,
            "Destination EID/ID was not recognized", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_bhvs,
          { "Bad Header Version (BHVS)", "nvme-mi.control.mes.bhvs",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0080,
            "Received message header version not supported", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_utunt,
          { "Unsupported Transmission Unit (UTUNT)", "nvme-mi.control.mes.utunt",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0040,
            "Requested transmission unit value is not supported", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_bmice,
          { "Bad Message Integrity Check Error (BMICE)", "nvme-mi.control.mes.bmice",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0010,
            "Received message failed MIC verification", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_cmnics,
          { "Command Message to non-Idle Slot (CMNICS)", "nvme-mi.control.mes.cmnics",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0008,
            "Command arrived on a slot not in the Idle state", HFILL },
        },
        { &hf_nvme_mi_ctl_mes_ssta,
          { "Slot Servicing State (SSTA)", "nvme-mi.control.mes.ssta",
            FT_UINT16, BASE_HEX, VALS(ssta_vals), 0x0003,
            "Current state of the per-slot command-servicing FSM (§4.2.1.4)",
            HFILL },
        },
        { &hf_nvme_mi_ctl_rro,
          { "Response Replay Offset (RRO)", "nvme-mi.control.rro",
            FT_UINT16, BASE_DEC, NULL, 0x00FF,
            "0-based packet number to replay (Replay request, §4.2.1.5)", HFILL },
        },
        { &hf_nvme_mi_ctl_rr,
          { "Response Replay (RR)", "nvme-mi.control.rr",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001,
            "1 = retransmitting response; 0 = no response available", HFILL },
        },
    };
    /* *INDENT-ON* */

    static ei_register_info ei[] = {
        { &ei_nvme_mi_ctl_truncated,
          { "nvme-mi.control.truncated", PI_MALFORMED, PI_WARN,
            "Control Primitive payload truncated (less than 4 bytes)", EXPFILL },
        },
        { &ei_nvme_mi_ctl_reserved_opcode,
          { "nvme-mi.control.reserved_opcode", PI_PROTOCOL, PI_NOTE,
            "Control Primitive opcode is in the Reserved range (05h-EFh)",
            EXPFILL },
        },
        { &ei_nvme_mi_ctl_orphan_response,
          { "nvme-mi.control.orphan_response", PI_SEQUENCE, PI_NOTE,
            "Control Primitive response without a usable matching request "
            "(missing or truncated); opcode and CPSR layout could not be "
            "recovered", EXPFILL },
        },
        { &ei_nvme_mi_ctl_tag_mismatch,
          { "nvme-mi.control.tag_mismatch", PI_PROTOCOL, PI_WARN,
            "Control Primitive response tag does not echo the request tag",
            EXPFILL },
        },
    };

    static int *ett[] = {
        &ett_nvme_mi_control,
        &ett_nvme_mi_ctl_cpsp,
        &ett_nvme_mi_ctl_cpsr,
    };

    expert_module_t *expert_nvme_mi_control;

    proto_nvme_mi_control = proto_register_protocol(
            "NVMe-MI Control Primitive", "NVMe-MI Control", "nvme-mi.control");
    proto_register_field_array(proto_nvme_mi_control, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi_control = expert_register_protocol(proto_nvme_mi_control);
    expert_register_field_array(expert_nvme_mi_control, ei, array_length(ei));
}

void
proto_reg_handoff_nvme_mi_control(void)
{
    dissector_add_uint("nvme-mi.type", NVME_MI_TYPE_CONTROL,
                       create_dissector_handle(dissect_nvme_mi_control,
                                               proto_nvme_mi_control));
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
