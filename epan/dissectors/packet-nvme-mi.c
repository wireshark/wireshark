/* packet-nvme-mi.c
 * Routines for NVMe Management Interface (NVMe-MI), over MCTP
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* NVMe-MI is defined by the NVM Express Management Interface specification:
 * https://nvmexpress.org/specification/nvme-mi-specification/
 *
 * This file handles the common NVMe-MI framing (4-byte header, MIC) and
 * request/response transaction tracking.  Per-type body decoding is split
 * into separate files that each register a dissector handle into the
 * "nvme-mi.type" table keyed by the NMIMT field:
 *
 *   packet-nvme-mi-control.c  NMIMT=0  Control Primitive (§4.2.1)
 *   packet-nvme-mi-mi.c       NMIMT=1  MI Command        (§5)
 *   packet-nvme-mi-admin.c    NMIMT=2  Admin Command     (§6)
 */

#include <config.h>

#include <epan/conversation.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-mctp.h"
#include "packet-nvme-mi.h"

void proto_register_nvme_mi(void);
void proto_reg_handoff_nvme_mi(void);

static int proto_nvme_mi;

/* Common NVMe-MI header fields */
static int hf_nvme_mi_mctp_mt;
static int hf_nvme_mi_mctp_ic;
static int hf_nvme_mi_csi;
static int hf_nvme_mi_type;
static int hf_nvme_mi_ror;
static int hf_nvme_mi_meb;
static int hf_nvme_mi_mic;
static int hf_nvme_mi_mic_status;

/* Invalid Parameter Error Response — Parameter Error Location (PEL) */
static int hf_nvme_mi_pel_bit;
static int hf_nvme_mi_pel_byte;

/* Request/response cross-reference fields */
static int hf_nvme_mi_response_in;
static int hf_nvme_mi_response_to;
static int hf_nvme_mi_response_time;
static int hf_nvme_mi_response_is_mpr;

static int ett_nvme_mi;
static int ett_nvme_mi_hdr;

static expert_field ei_nvme_mi_mic_truncated;
static expert_field ei_nvme_mi_mic_bad;
static expert_field ei_nvme_mi_req_superseded;

/* Dissector table keyed by the NMIMT field; sub-dissectors register here. */
static dissector_table_t nvme_mi_type_dissector_table;

/* Response Message Status (NVMe-MI 2.1 Figure 29); shared with the per-type
 * body dissectors via packet-nvme-mi.h. */
const value_string nvme_mi_status_vals[] = {
    { NVME_MI_STATUS_SUCCESS, "Success" },
    { NVME_MI_STATUS_MORE_PROCESSING_REQUIRED, "More Processing Required" },
    { 0x02, "Internal Error" },
    { 0x03, "Invalid Command Opcode" },
    { NVME_MI_STATUS_INVALID_PARAMETER, "Invalid Parameter" },
    { 0x05, "Invalid Command Size" },
    { 0x06, "Invalid Command Input Data Size" },
    { 0x07, "Access Denied" },
    { 0x08, "Unable to Abort" },
    { 0x20, "VPD Updates Exceeded" },
    { 0x21, "PCIe Inaccessible" },
    { 0x22, "Management Endpoint Buffer Cleared Due to Sanitize" },
    { 0x23, "Enclosure Services Failure" },
    { 0x24, "Enclosure Services Transfer Failure" },
    { 0x25, "Enclosure Failure" },
    { 0x26, "Enclosure Services Transfer Refused" },
    { 0x27, "Unsupported Enclosure Function" },
    { 0x28, "Enclosure Services Unavailable" },
    { 0x29, "Enclosure Degraded" },
    { 0x2a, "Sanitize In Progress" },
    { 0, NULL },
};

static const value_string mi_mctp_type_vals[] = {
    { 4, "NVMe-MI" },
    { 0, NULL },
};

const value_string mi_type_vals[] = {
    { NVME_MI_TYPE_CONTROL, "Control primitive" },
    { NVME_MI_TYPE_MI,      "MI command" },
    { NVME_MI_TYPE_ADMIN,   "NVMe Admin command" },
    { NVME_MI_TYPE_PCIE,    "PCIe command" },
    { 0, NULL },
};

static const true_false_string tfs_meb = { "data in MEB", "data in message" };

void
nvme_mi_dissect_invalid_param_resp(tvbuff_t *tvb, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_nvme_mi_pel_bit, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_nvme_mi_pel_byte, tvb, 2, 2,
                        ENC_LITTLE_ENDIAN);
}

void
nvme_mi_dissect_truncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          proto_item *it, expert_field *ei, int hf_data, int off)
{
    expert_add_info(pinfo, it, ei);
    if (tvb_reported_length_remaining(tvb, off) > 0)
        proto_tree_add_item(tree, hf_data, tvb, off, -1, ENC_NA);
}

proto_item *
nvme_mi_recover_resp_opcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            proto_item *it,
                            const struct nvme_mi_transaction *trans,
                            uint8_t nmimt, int hf_opcode,
                            expert_field *ei_orphan, unsigned *opcode)
{
    proto_item *gi;

    if (!trans || !trans->req_parsed || trans->nmimt != nmimt) {
        *opcode = 0;
        expert_add_info(pinfo, it, ei_orphan);
        return NULL;
    }

    *opcode = trans->opcode;
    gi = proto_tree_add_uint(tree, hf_opcode, tvb, 0, 0, trans->opcode);
    proto_item_set_generated(gi);
    return gi;
}

/* Per-slot in-flight transaction (NULL when the slot is idle); only written
 * when !pinfo->fd->visited. */
struct nvme_mi_conv_info {
    struct nvme_mi_transaction *command_slots[2];
    /*
     * Control Primitives are processed out-of-band from the command slots:
     * Pause/Abort/Get State/Replay exist precisely to be issued while a
     * command message is outstanding in the targeted slot, so a Control
     * Primitive request must not displace the in-flight command transaction.
     * They get their own per-slot request/response pairing (the CSI bit in
     * the message header selects which slot the primitive targets).
     */
    struct nvme_mi_transaction *cp_slots[2];
};

/* Per-frame annotation; points into the shared transaction. */
struct nvme_mi_frame_info {
    struct nvme_mi_transaction *trans;
    bool                        is_interim_mpr;
    /* This request found the slot still occupied by an unanswered request,
     * whose transaction it supersedes. */
    bool                        superseded_unanswered;
};

static int
dissect_nvme_mi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                void *data _U_)
{
    proto_tree *nvme_mi_tree, *nvme_mi_hdr_tree;
    struct nvme_mi_conv_info *mi_conv;
    unsigned len, payload_len, type;
    bool resp, mic_enabled;
    proto_item *ti, *it2;
    conversation_t *conv;
    tvbuff_t *sub_tvb;
    uint32_t mic = 0;
    unsigned csi;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe-MI");
    col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_reported_length(tvb);
    if (len < 4) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus length %u, minimum %u",
                     len, 4);
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_item(tree, proto_nvme_mi, tvb, 0, -1, ENC_NA);
    nvme_mi_tree = proto_item_add_subtree(ti, ett_nvme_mi);

    proto_item *hdr_it =
        proto_tree_add_item(nvme_mi_tree, proto_nvme_mi, tvb, 0, 4, ENC_NA);
    proto_item_set_text(hdr_it, "NVMe-MI header");
    nvme_mi_hdr_tree = proto_item_add_subtree(hdr_it, ett_nvme_mi_hdr);

    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_mctp_mt,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_item *ic_it =
        proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_mctp_ic,
                                        tvb, 0, 4, ENC_LITTLE_ENDIAN,
                                        &mic_enabled);
    proto_tree_add_item_ret_uint(nvme_mi_hdr_tree, hf_nvme_mi_csi,
                                 tvb, 0, 4, ENC_LITTLE_ENDIAN, &csi);
    proto_tree_add_item_ret_uint(nvme_mi_hdr_tree, hf_nvme_mi_type,
                                 tvb, 0, 4, ENC_LITTLE_ENDIAN, &type);
    proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_ror,
                                    tvb, 0, 4, ENC_LITTLE_ENDIAN, &resp);
    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_meb,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);

    payload_len = len - 4;
    if (mic_enabled) {
        if (payload_len < 4) {
            /*
             * The IC bit claims a trailing 4-byte MIC, but the frame is too
             * short to contain one.  Flag the inconsistency and keep the
             * trailing bytes as payload (rather than underflowing
             * payload_len, which would corrupt the sub-tvb's reported
             * length); only MIC verification is skipped.
             */
            expert_add_info(pinfo, ic_it, &ei_nvme_mi_mic_truncated);
            mic_enabled = false;
        } else {
            mic = ~crc32c_tvb_offset_calculate(tvb, 0, payload_len, 0xffffffff);
            payload_len -= 4;
        }
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "NVMe-MI %s %s",
                 val_to_str_const(type, mi_type_vals, "command"),
                 tfs_get_string(resp, &tfs_response_request));

    struct nvme_mi_frame_info *fi = p_get_proto_data(wmem_file_scope(), pinfo,
                                                     proto_nvme_mi, 0);

    /*
     * Identify the transaction this frame belongs to and resolve the slot
     * lifecycle.  An MPR response leaves the slot occupied so the next
     * response links to the same transaction.
     */
    if (!pinfo->fd->visited) {
        /*
         * The Response Message Status byte sits at payload offset 0 for
         * every command-message response type (NVMe-MI 2.1 Figure 29;
         * Control Primitives have their own out-of-band lifecycle and no
         * MPR concept).  Peek it here in the framing layer so the slot
         * lifecycle below never depends on a body dissector running to
         * completion: a disabled body protocol or an exception thrown on a
         * truncated payload must not leak a pending slot and mislink later
         * responses.
         *
         * On a sliced capture the status byte may be missing even though
         * the reported payload carries one; the response is then treated
         * like an interim one (the slot stays open) so that an MPR whose
         * status was cut off cannot close the slot and silently mislink the
         * real final response.
         */
        bool is_mpr = false;
        bool status_known = true;
        if (resp && type != NVME_MI_TYPE_CONTROL && payload_len >= 1) {
            if (tvb_bytes_exist(tvb, 4, 1))
                is_mpr = tvb_get_uint8(tvb, 4) ==
                         NVME_MI_STATUS_MORE_PROCESSING_REQUIRED;
            else
                status_known = false;
        }

        conv = find_or_create_conversation(pinfo);
        mi_conv = conversation_get_proto_data(conv, proto_nvme_mi);
        if (!mi_conv) {
            mi_conv = wmem_new0(wmem_file_scope(), struct nvme_mi_conv_info);
            conversation_add_proto_data(conv, proto_nvme_mi, mi_conv);
        }

        struct nvme_mi_transaction **slot = (type == NVME_MI_TYPE_CONTROL)
                                                ? &mi_conv->cp_slots[csi]
                                                : &mi_conv->command_slots[csi];

        if (resp) {
            if (*slot) {
                fi = wmem_new0(wmem_file_scope(), struct nvme_mi_frame_info);
                fi->trans = *slot;
                fi->is_interim_mpr = is_mpr;
                p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                                 0, fi);
                if (!is_mpr && status_known) {
                    fi->trans->resp_frame = pinfo->num;
                    *slot = NULL;
                }
            }
        } else {
            struct nvme_mi_transaction *trans =
                wmem_new0(wmem_file_scope(), struct nvme_mi_transaction);
            trans->req_frame = pinfo->num;
            trans->req_time  = pinfo->fd->abs_ts;
            trans->nmimt     = (uint8_t)type;

            fi = wmem_new0(wmem_file_scope(), struct nvme_mi_frame_info);
            fi->trans = trans;
            fi->superseded_unanswered = (*slot != NULL);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi, 0, fi);

            *slot = trans;
        }
    }

    /* Cross-references that do not depend on the body.  fi->trans is shared,
     * so resp_frame written on the response pass is visible here when
     * re-dissecting the request. */
    if (fi && fi->trans) {
        if (resp) {
            if (fi->trans->req_frame) {
                nstime_t ns;
                nstime_delta(&ns, &pinfo->fd->abs_ts, &fi->trans->req_time);

                it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_response_to,
                                          tvb, 0, 0, fi->trans->req_frame);
                proto_item_set_generated(it2);
                it2 = proto_tree_add_time(nvme_mi_tree, hf_nvme_mi_response_time,
                                          tvb, 0, 0, &ns);
                proto_item_set_generated(it2);
            }
            if (fi->is_interim_mpr) {
                it2 = proto_tree_add_boolean(nvme_mi_tree,
                                             hf_nvme_mi_response_is_mpr,
                                             tvb, 0, 0, true);
                proto_item_set_generated(it2);
            }
        } else {
            if (fi->superseded_unanswered)
                expert_add_info(pinfo, ti, &ei_nvme_mi_req_superseded);
            if (fi->trans->resp_frame) {
                it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_response_in,
                                          tvb, 0, 0, fi->trans->resp_frame);
                proto_item_set_generated(it2);
            }
        }
    }

    sub_tvb = tvb_new_subset_length(tvb, 4, payload_len);

    struct nvme_mi_dissect_ctx ctx = {
        .resp  = resp,
        .trans = fi ? fi->trans : NULL,
    };
    /*
     * A body dissector handed an empty payload legitimately returns 0, which
     * is indistinguishable from "no dissector registered for this type" —
     * only fall back to the data dissector when there are actual payload
     * bytes left to show.
     */
    if (!dissector_try_uint_with_data(nvme_mi_type_dissector_table, type,
                                      sub_tvb, pinfo, nvme_mi_tree, false,
                                      &ctx) && payload_len > 0)
        call_data_dissector(sub_tvb, pinfo, nvme_mi_tree);

    /*
     * The MIC is little-endian on the wire (NVMe convention); reading it
     * big-endian matches the byte-swapped value crc32c_tvb_offset_calculate
     * returns, so the two swaps cancel out.
     */
    if (mic_enabled)
        proto_tree_add_checksum(nvme_mi_tree, tvb, payload_len + 4,
                                hf_nvme_mi_mic, hf_nvme_mi_mic_status,
                                &ei_nvme_mi_mic_bad, pinfo, mic,
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

    return tvb_captured_length(tvb);
}

void
proto_register_nvme_mi(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        /* Common NVMe-MI header (4 bytes, NVMe-MI 2.1 Figure 12) */
        { &hf_nvme_mi_mctp_mt,
          { "MCTP message type", "nvme-mi.mctp-mt",
            FT_UINT32, BASE_HEX, VALS(mi_mctp_type_vals), 0x7f,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mctp_ic,
          { "MCTP IC", "nvme-mi.mctp-ic",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL },
        },
        { &hf_nvme_mi_csi,
          { "CSI", "nvme-mi.csi",
            FT_UINT32, BASE_DEC, NULL, 0x00000100,
            NULL, HFILL },
        },
        { &hf_nvme_mi_type,
          { "Type", "nvme-mi.type",
            FT_UINT32, BASE_HEX, VALS(mi_type_vals), 0x00007800,
            NULL, HFILL },
        },
        { &hf_nvme_mi_ror,
          { "ROR", "nvme-mi.ror",
            FT_BOOLEAN, 32, TFS(&tfs_response_request), 0x00008000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_meb,
          { "MEB", "nvme-mi.meb",
            FT_BOOLEAN, 32, TFS(&tfs_meb), 0x00010000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mic,
          { "Message Integrity Check", "nvme-mi.mic",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mic_status,
          { "Message Integrity Check Status", "nvme-mi.mic.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
            NULL, HFILL },
        },

        /* Invalid Parameter Error Response (status 04h) — Parameter Error
         * Location over payload bytes 3:1; shared by the command message
         * types via nvme_mi_dissect_invalid_param_resp(). */
        { &hf_nvme_mi_pel_bit,
          { "Parameter Error Bit (PEL)", "nvme-mi.pel.bit",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            "Least-significant bit of the parameter in error", HFILL },
        },
        { &hf_nvme_mi_pel_byte,
          { "Parameter Error Byte (PEL)", "nvme-mi.pel.byte",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Offset of the least-significant byte of the parameter in "
            "error, relative to the start of the message", HFILL },
        },

        /* Request/response cross-reference (generated fields) */
        { &hf_nvme_mi_response_in,
          { "Response In", "nvme-mi.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            "The response to this NVMe-MI request is in this frame", HFILL }
        },
        { &hf_nvme_mi_response_to,
          { "Request In", "nvme-mi.response_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            "This is a response to the NVMe-MI request in this frame", HFILL }
        },
        { &hf_nvme_mi_response_time,
          { "Response Time", "nvme-mi.response_time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "The time between the request and the response", HFILL }
        },
        { &hf_nvme_mi_response_is_mpr,
          { "More Processing Required", "nvme-mi.response_is_mpr",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "This is an interim response; the endpoint will send a final "
            "response when processing is complete", HFILL }
        },
    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi,
        &ett_nvme_mi_hdr,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_mi_mic_truncated,
          { "nvme-mi.mic_truncated", PI_MALFORMED, PI_WARN,
            "IC bit is set but the message is too short to contain a MIC; "
            "trailing bytes treated as payload", EXPFILL },
        },
        { &ei_nvme_mi_mic_bad,
          { "nvme-mi.mic_bad", PI_CHECKSUM, PI_WARN,
            "Message Integrity Check does not match the computed CRC-32C",
            EXPFILL },
        },
        { &ei_nvme_mi_req_superseded,
          { "nvme-mi.req_superseded", PI_SEQUENCE, PI_NOTE,
            "The previous request on this command slot was still unanswered; "
            "its transaction is superseded by this request", EXPFILL },
        },
    };

    expert_module_t *expert_nvme_mi;

    proto_nvme_mi = proto_register_protocol("NVMe-MI", "NVMe-MI", "nvme-mi");
    proto_register_field_array(proto_nvme_mi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi = expert_register_protocol(proto_nvme_mi);
    expert_register_field_array(expert_nvme_mi, ei, array_length(ei));

    nvme_mi_type_dissector_table = register_dissector_table("nvme-mi.type",
            "NVMe-MI Message Type", proto_nvme_mi, FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_nvme_mi(void)
{
    dissector_handle_t nvme_mi_handle =
        create_dissector_handle(dissect_nvme_mi, proto_nvme_mi);
    dissector_add_uint("mctp.type", MCTP_TYPE_NVME, nvme_mi_handle);
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
