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

/* NVMe is defined by the NVM Express Management Interface standard,
 * athttps://nvmexpress.org/developers/nvme-mi-specification/
 */

#include <config.h>

#include <epan/conversation.h>
#include <epan/crc32-tvb.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include "packet-sll.h"
#include "packet-mctp.h"
#include "packet-nvme.h"

void proto_register_nvme_mi(void);
void proto_reg_handoff_nvme_mi(void);

static int proto_nvme_mi;

static int hf_nvme_mi_mctp_mt;
static int hf_nvme_mi_mctp_ic;
static int hf_nvme_mi_csi;
static int hf_nvme_mi_type;
static int hf_nvme_mi_ror;
static int hf_nvme_mi_meb;
static int hf_nvme_mi_mic;

static int hf_nvme_mi_mi_opcode;
static int hf_nvme_mi_mi_cdw0;
static int hf_nvme_mi_mi_cdw1;
static int hf_nvme_mi_mi_status;
static int hf_nvme_mi_mi_nmresp;
static int hf_nvme_mi_mi_data;

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

static int hf_nvme_mi_response_in;
static int hf_nvme_mi_response_to;
static int hf_nvme_mi_response_time;


static int ett_nvme_mi;
static int ett_nvme_mi_hdr;
static int ett_nvme_mi_mi;
static int ett_nvme_mi_admin;
static int ett_nvme_mi_admin_flags;

enum nvme_mi_type {
    NVME_MI_TYPE_CONTROL = 0x0,
    NVME_MI_TYPE_MI = 0x1,
    NVME_MI_TYPE_ADMIN = 0x2,
    NVME_MI_TYPE_PCIE = 0x4,
};

struct nvme_mi_command {
    bool                init;
    enum nvme_mi_type   type;
    unsigned            opcode;
    uint32_t            req_frame;
    uint32_t            resp_frame;
    nstime_t            req_time;
};

struct nvme_mi_conv_info {
    struct nvme_mi_command command_slots[2];
};

static const value_string mi_mctp_type_vals[] = {
    { 4, "NVMe-MI" },
    { 0, NULL },
};

static const value_string mi_type_vals[] = {
    { NVME_MI_TYPE_CONTROL, "Control primitive" },
    { NVME_MI_TYPE_MI,      "MI command" },
    { NVME_MI_TYPE_ADMIN,   "NVMe Admin command" },
    { NVME_MI_TYPE_PCIE,    "PCIe command" },
    { 0, NULL },
};

static const value_string mi_opcode_vals[] = {
    { 0x00, "Read NVMe-MI Data Structure" },
    { 0x01, "NVM Subsystem Health Status Poll" },
    { 0x02, "Controller Health Status Poll" },
    { 0x03, "Configuration Set" },
    { 0x04, "Configuration Get" },
    { 0, NULL },
};

static const value_string admin_opcode_vals[] = {
    { 0x00, "Delete I/O Submission Queue" },
    { 0x01, "Create I/O Submission Queue" },
    { 0x02, "Get Log Page" },
    { 0x04, "Delete I/O Completion Queue" },
    { 0x05, "Create I/O Completion Queue" },
    { 0x06, "Identify" },
    { 0x09, "Set Features" },
    { 0x0a, "Get Features" },
    { 0x0d, "Namespace Management" },
    { 0x10, "Firmware Commit" },
    { 0x11, "Firmware Image Download" },
    { 0x80, "Format NVM" },
    { 0x81, "Security Send" },
    { 0x82, "Security Receive" },
    { 0, NULL },
};

static const true_false_string tfs_meb = { "data in MEB", "data in message" };

static int
dissect_nvme_mi_mi(tvbuff_t *tvb, bool resp, struct nvme_mi_command *cmd,
                   proto_tree *tree)
{
    proto_item *it, *it2;
    proto_tree *mi_tree;

    it = proto_tree_add_item(tree, proto_nvme_mi, tvb, 0, -1, ENC_NA);
    mi_tree = proto_item_add_subtree(it, ett_nvme_mi_mi);

    if (!resp) {
        proto_tree_add_item_ret_uint(mi_tree, hf_nvme_mi_mi_opcode,
                                     tvb, 0, 1, ENC_NA, &cmd->opcode);

        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw0,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_cdw1,
                            tvb, 8, 4, ENC_LITTLE_ENDIAN);

        if (tvb_reported_length(tvb) > 12)
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                tvb, 12, -1, ENC_NA);
    } else {
        it2 = proto_tree_add_uint(mi_tree, hf_nvme_mi_mi_opcode,
                                  tvb, 0, 0, cmd->opcode);
        proto_item_set_generated(it2);

        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_status,
                            tvb, 0, 1, ENC_NA);
        proto_tree_add_item(mi_tree, hf_nvme_mi_mi_nmresp,
                            tvb, 1, 3, ENC_LITTLE_ENDIAN);

        if (tvb_reported_length(tvb) > 4)
            proto_tree_add_item(mi_tree, hf_nvme_mi_mi_data,
                                tvb, 4, -1, ENC_NA);
    }

    return 0;
}

static int
dissect_nvme_mi_admin(tvbuff_t *tvb, bool resp, struct nvme_mi_command *cmd,
                      proto_tree *tree)
{
    proto_tree *admin_tree;
    proto_item *it, *it2;

    it = proto_tree_add_item(tree, proto_nvme_mi, tvb, 0, -1, ENC_NA);
    admin_tree = proto_item_add_subtree(it, ett_nvme_mi_admin);

    proto_item_set_text(it, "NVMe Admin %s",
                        resp ? "response" : "request");

    if (resp) {
        it2 = proto_tree_add_uint(admin_tree, hf_nvme_mi_admin_opcode,
                                  tvb, 0, 0, cmd->opcode);
        proto_item_set_generated(it2);

        proto_tree_add_item(admin_tree, hf_nvme_mi_admin_status,
                            tvb, 0, 1, ENC_NA);

        if (tvb_reported_length(tvb) >= 16) {
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe1,
                                tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe2,
                                tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_cqe3,
                                tvb, 12, 4, ENC_LITTLE_ENDIAN);
        }

        if (tvb_reported_length(tvb) > 16)
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                tvb, 16, -1, ENC_NA);
    } else {
        static int * const nvme_mi_admin_flags[] = {
            &hf_nvme_mi_admin_flags_doff,
            &hf_nvme_mi_admin_flags_dlen,
            NULL,
        };

        proto_tree_add_item_ret_uint(admin_tree, hf_nvme_mi_admin_opcode,
                                     tvb, 0, 1, ENC_NA, &cmd->opcode);

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

        if (tvb_reported_length(tvb) > 64)
            proto_tree_add_item(admin_tree, hf_nvme_mi_admin_data,
                                tvb, 64, -1, ENC_NA);
    }

    return 0;
}

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

    /* Check that the packet is long enough for it to belong to us. */
    len = tvb_reported_length(tvb);

    if (len < 4) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus length %u, minimum %u",
                     len, 4);
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_item(tree, proto_nvme_mi, tvb, 0, -1, ENC_NA);
    nvme_mi_tree = proto_item_add_subtree(ti, ett_nvme_mi);

    ti = proto_tree_add_item(nvme_mi_tree, proto_nvme_mi, tvb, 0, 4, ENC_NA);
    proto_item_set_text(ti, "NVMe-MI header");
    nvme_mi_hdr_tree = proto_item_add_subtree(ti, ett_nvme_mi_hdr);

    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_mctp_mt,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_mctp_ic,
                                    tvb, 0, 4, ENC_LITTLE_ENDIAN, &mic_enabled);

    proto_tree_add_item_ret_uint(nvme_mi_hdr_tree, hf_nvme_mi_csi,
                                 tvb, 0, 4, ENC_LITTLE_ENDIAN, &csi);

    proto_tree_add_item_ret_uint(nvme_mi_hdr_tree, hf_nvme_mi_type,
                                 tvb, 0, 4, ENC_LITTLE_ENDIAN, &type);

    proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_ror,
                                    tvb, 0, 4, ENC_LITTLE_ENDIAN, &resp);

    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_meb,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);

    payload_len = tvb_reported_length(tvb) - 4;
    if (mic_enabled) {
        mic = ~crc32c_tvb_offset_calculate(tvb, 0, payload_len, 0xffffffff);
        payload_len -= 4;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "NVMe-MI %s %s",
                 val_to_str_const(type, mi_type_vals, "command"),
                 tfs_get_string(resp, &tfs_response_request));

    conv = find_or_create_conversation(pinfo);
    mi_conv = conversation_get_proto_data(conv, proto_nvme_mi);
    if (!mi_conv) {
        mi_conv = wmem_new0(wmem_file_scope(), struct nvme_mi_conv_info);
        conversation_add_proto_data(conv, proto_nvme_mi, mi_conv);
    }

    struct nvme_mi_command *cmd = &mi_conv->command_slots[csi];

    if (resp) {
        if (cmd->req_frame) {
            nstime_t ns;

            nstime_delta(&ns, &pinfo->fd->abs_ts, &cmd->req_time);

            it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_response_to,
                                      tvb, 0, 0, cmd->req_frame);
            proto_item_set_generated(it2);
            it2 = proto_tree_add_time(nvme_mi_tree, hf_nvme_mi_response_time,
                                      tvb, 0, 0, &ns);
            proto_item_set_generated(it2);
        } else {
            /* TODO: no request frame available? */
        }
        cmd->resp_frame = pinfo->num;

    } else {
        if (cmd->resp_frame) {
            it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_response_in,
                                      tvb, 0, 0, cmd->resp_frame);
            proto_item_set_generated(it2);
        }
        cmd->type = type;
        cmd->opcode = 0;
        cmd->init = true;
        cmd->req_frame = pinfo->num;
        cmd->req_time = pinfo->fd->abs_ts;
    }

    sub_tvb = tvb_new_subset_length(tvb, 4, payload_len);

    switch (type) {
    case NVME_MI_TYPE_MI:
        dissect_nvme_mi_mi(sub_tvb, resp, cmd, nvme_mi_tree);
        break;
    case NVME_MI_TYPE_ADMIN:
        dissect_nvme_mi_admin(sub_tvb, resp, cmd, nvme_mi_tree);
        break;
    default:
        break;
    }

    if (mic_enabled)
        proto_tree_add_checksum(nvme_mi_tree, tvb, payload_len + 4,
                                hf_nvme_mi_mic, -1, NULL, pinfo, mic,
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

    return tvb_captured_length(tvb);
}

void
proto_register_nvme_mi(void)
{
    /* *INDENT-OFF* */
    /* Field definitions */
    static hf_register_info hf[] = {
        /* base MI header */
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

        /* meta */
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

        /* MI commands */
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
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
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

        /* Admin commands */
        { &hf_nvme_mi_admin_opcode,
          { "Opcode", "nvme-mi.admin.opcode",
            FT_UINT8, BASE_HEX, VALS(admin_opcode_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_admin_status,
          { "Status", "nvme-mi.admin.status",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
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

    /* protocol subtree */
    static int *ett[] = {
        &ett_nvme_mi,
        &ett_nvme_mi_hdr,
        &ett_nvme_mi_mi,
        &ett_nvme_mi_admin,
        &ett_nvme_mi_admin_flags,
    };

    proto_nvme_mi = proto_register_protocol("NVMe-MI", "NVMe-MI", "nvme-mi");

    proto_register_field_array(proto_nvme_mi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nvme_mi(void)
{
    dissector_handle_t nvme_mi_handle;
    nvme_mi_handle = create_dissector_handle(dissect_nvme_mi, proto_nvme_mi);
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
