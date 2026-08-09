/* packet-mctp-control.c
 * Routines for Management Component Transport Protocol (MCTP) control
 * protocol disassembly
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * MCTP control protocol provides transport-layer initialisation and
 * management for MCTP endpoints; typically for device discovery, enumeration
 * and address assigment.
 *
 * MCTP Control protocol is defined by DMTF standard DSP0236:
 * https://www.dmtf.org/dsp/DSP0236
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-mctp.h"

#define MCTP_CTRL_MIN_LENGTH 3

void proto_register_mctp_control(void);
void proto_reg_handoff_mctp_control(void);

static int proto_mctp_ctrl;

static int hf_mctp_ctrl_command;
static int hf_mctp_ctrl_rq;
static int hf_mctp_ctrl_d;
static int hf_mctp_ctrl_rsvd;
static int hf_mctp_ctrl_instance;
static int hf_mctp_ctrl_cc;
static int hf_mctp_ctrl_data;

/* Set Endpoint ID (DSP0236 1.3.3, Table 14) */
static int hf_mctp_ctrl_set_eid_op;
static int hf_mctp_ctrl_set_eid_eid;
static int hf_mctp_ctrl_set_eid_rsvd_hi;
static int hf_mctp_ctrl_set_eid_status;
static int hf_mctp_ctrl_set_eid_rsvd_lo;
static int hf_mctp_ctrl_set_eid_alloc_status;
static int hf_mctp_ctrl_set_eid_setting;
static int hf_mctp_ctrl_set_eid_pool_size;

/* Get Endpoint ID (DSP0236 1.3.3, Table 15) */
static int hf_mctp_ctrl_get_eid_eid;
static int hf_mctp_ctrl_get_eid_rsvd_hi;
static int hf_mctp_ctrl_get_eid_endpoint_type;
static int hf_mctp_ctrl_get_eid_rsvd_lo;
static int hf_mctp_ctrl_get_eid_eid_type;
static int hf_mctp_ctrl_get_eid_medium_info;

/* Get Endpoint UUID (DSP0236 1.3.3, Table 16) */
static int hf_mctp_ctrl_uuid;

/* Get MCTP Version Support (DSP0236 1.3.3, Table 18) */
static int hf_mctp_ctrl_get_ver_msg_type;
static int hf_mctp_ctrl_get_ver_count;
static int hf_mctp_ctrl_get_ver_entry;

/* Get Message Type Support (DSP0236 1.3.3, Table 19) */
static int hf_mctp_ctrl_msg_type_count;
static int hf_mctp_ctrl_msg_type;

/* Allocate Endpoint IDs (DSP0236 1.3.3, Table 23) */
static int hf_mctp_ctrl_alloc_eids_op;
static int hf_mctp_ctrl_alloc_eids_count;
static int hf_mctp_ctrl_alloc_eids_start;
static int hf_mctp_ctrl_alloc_eids_status;
static int hf_mctp_ctrl_alloc_eids_pool_size;
static int hf_mctp_ctrl_alloc_eids_first;

static int ett_mctp_ctrl;
static int ett_mctp_ctrl_hdr;

static expert_field ei_mctp_ctrl_ver_bcd;

/* DSP0236 1.3.3, Table 12 - MCTP control command numbers. The 0xf0 - 0xff
 * range is reserved for the individual transport binding specifications, so
 * it has no fixed name here. */
static const value_string command_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Set Endpoint ID" },
    { 0x02, "Get Endpoint ID" },
    { 0x03, "Get Endpoint UUID" },
    { 0x04, "Get MCTP Version Support" },
    { 0x05, "Get Message Type Support" },
    { 0x06, "Get Vendor Defined Message Support" },
    { 0x07, "Resolve Endpoint ID" },
    { 0x08, "Allocate Endpoint IDs" },
    { 0x09, "Routing Information Update" },
    { 0x0a, "Get Routing Table Entries" },
    { 0x0b, "Prepare for Endpoint Discovery" },
    { 0x0c, "Endpoint Discovery" },
    { 0x0d, "Discovery Notify" },
    { 0x0e, "Get Network ID" },
    { 0x0f, "Query Hop" },
    { 0x10, "Resolve UUID" },
    { 0x11, "Query Rate Limit" },
    { 0x12, "Request TX Rate Limit" },
    { 0x13, "Update Rate Limit" },
    { 0x14, "Query Supported Interfaces" },
    { 0,    NULL },
};

static const range_string cc_vals[] = {
    { 0x00, 0x00, "Success" },
    { 0x01, 0x01, "Error" },
    { 0x02, 0x02, "Error: invalid data" },
    { 0x03, 0x03, "Error: invalid length" },
    { 0x04, 0x04, "Error: not ready" },
    { 0x05, 0x05, "Error: unsupported command" },
    { 0x80, 0xFF, "Command Specific" },
    { 0,    0,    NULL },
};

static const true_false_string tfs_rq = { "Request", "Response" };

#define MCTP_CTRL_CMD_SET_EID           0x01
#define MCTP_CTRL_CMD_GET_EID           0x02
#define MCTP_CTRL_CMD_GET_UUID          0x03
#define MCTP_CTRL_CMD_GET_VERSION       0x04
#define MCTP_CTRL_CMD_GET_MSG_TYPES     0x05
#define MCTP_CTRL_CMD_ALLOCATE_EIDS     0x08

/* DSP0236 1.3.3, Table 14 - Set Endpoint ID request byte 1 [1:0] */
static const value_string set_eid_op_vals[] = {
    { 0x0, "Set EID" },
    { 0x1, "Force EID" },
    { 0x2, "Reset EID" },
    { 0x3, "Set Discovered Flag" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 14 - Set Endpoint ID response byte 2 [5:4] */
static const value_string set_eid_status_vals[] = {
    { 0x0, "EID assignment accepted" },
    { 0x1, "EID assignment rejected" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 14 - Set Endpoint ID response byte 2 [1:0] */
static const value_string set_eid_alloc_status_vals[] = {
    { 0x0, "Device does not use an EID pool" },
    { 0x1, "Endpoint requires EID pool allocation" },
    { 0x2, "Endpoint has already received an EID pool allocation" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 15 - Get Endpoint ID response byte 3 [5:4] */
static const value_string get_eid_endpoint_type_vals[] = {
    { 0x0, "Simple endpoint" },
    { 0x1, "Bus owner/bridge" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 15 - Get Endpoint ID response byte 3 [1:0] */
static const value_string get_eid_eid_type_vals[] = {
    { 0x0, "Dynamic EID" },
    { 0x1, "Static EID supported" },
    { 0x2, "Static EID supported, present EID matches static EID" },
    { 0x3, "Static EID supported, present EID does not match static EID" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 18 - Get MCTP Version Support message type numbers.
 * Message type values per DSP0239, plus the 0xff special value for the MCTP
 * base specification itself. */
static const value_string get_ver_msg_type_vals[] = {
    { 0x00, "MCTP control protocol" },
    { 0x01, "PLDM" },
    { 0x02, "NC-SI over MCTP" },
    { 0x03, "Ethernet over MCTP" },
    { 0x04, "NVMe-MI over MCTP" },
    { 0x05, "SPDM" },
    { 0x06, "Secured Messages" },
    { 0x07, "CXL FM API" },
    { 0x08, "CXL CCI" },
    { 0x09, "PCIe-MI" },
    { 0xff, "MCTP base specification" },
    { 0,    NULL },
};

/* MCTP message type numbers per DSP0239 1.12.0 Table 1, for the Get Message
 * Type Support response list (DSP0236 1.3.3, Table 19). */
static const value_string msg_type_vals[] = {
    { 0x00, "MCTP control protocol" },
    { 0x01, "PLDM" },
    { 0x02, "NC-SI over MCTP" },
    { 0x03, "Ethernet over MCTP" },
    { 0x04, "NVMe-MI over MCTP" },
    { 0x05, "SPDM" },
    { 0x06, "Secured Messages" },
    { 0x07, "CXL FM API" },
    { 0x08, "CXL CCI" },
    { 0x09, "PCIe-MI" },
    { 0x7e, "Vendor Defined - PCI" },
    { 0x7f, "Vendor Defined - IANA" },
    { 0,    NULL },
};

/* DSP0236 1.3.3, Table 23 - Allocate Endpoint IDs request byte 1 [1:0] */
static const value_string alloc_eids_op_vals[] = {
    { 0x0, "Allocate EIDs" },
    { 0x1, "Force allocation" },
    { 0x2, "Get allocation information" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* DSP0236 1.3.3, Table 23 - Allocate Endpoint IDs response byte 2 [1:0] */
static const value_string alloc_eids_status_vals[] = {
    { 0x0, "Allocation accepted" },
    { 0x1, "Allocation rejected" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0,   NULL },
};

/* True if a BCD version byte is well-formed per DSP0236 1.3.3 section 12.7.2:
 * the low nibble is a digit 0-9 and the high nibble is a digit or Fh (the
 * single-digit marker).  0xff (both nibbles Fh) is therefore invalid for the
 * major and minor bytes; it is defined only as "no update" for the update
 * byte, which the caller handles separately. */
static bool
mctp_ctrl_bcd_byte_valid(uint8_t bcd)
{
    return (bcd & 0x0f) <= 9 && ((bcd >> 4) <= 9 || (bcd >> 4) == 0x0f);
}

/* Format one BCD-encoded version byte per DSP0236 1.3.3 section 12.7.2: a
 * 0xf upper nibble means a single-digit value. */
static void
mctp_ctrl_fmt_version_bcd(char *buf, size_t size, uint8_t bcd)
{
    if ((bcd & 0xf0) == 0xf0)
        snprintf(buf, size, "%u", bcd & 0x0f);
    else
        snprintf(buf, size, "%u%u", bcd >> 4, bcd & 0x0f);
}

/* Format a 32-bit version number entry per DSP0236 1.3.3 section 12.7.2,
 * e.g. 0xf1f3f300 -> "1.3.3", 0xf1f0ff61 -> "1.0a". */
static void
mctp_ctrl_fmt_version(char *buf, uint32_t ver)
{
    char major[5], minor[5], update[6] = "", alpha[2] = "";

    mctp_ctrl_fmt_version_bcd(major, sizeof(major), (ver >> 24) & 0xff);
    mctp_ctrl_fmt_version_bcd(minor, sizeof(minor), (ver >> 16) & 0xff);
    if (((ver >> 8) & 0xff) != 0xff) {
        update[0] = '.';
        mctp_ctrl_fmt_version_bcd(update + 1, sizeof(update) - 1,
                                  (ver >> 8) & 0xff);
    }
    /* The alpha byte is 0 (unused) or one of [a-zA-Z] (section 12.7.2);
     * don't copy other, possibly unprintable, octets into the label. */
    if (g_ascii_isalpha(ver & 0xff)) {
        alpha[0] = ver & 0xff;
        alpha[1] = '\0';
    }
    snprintf(buf, ITEM_LABEL_LENGTH, "%s.%s%s%s (0x%08x)",
             major, minor, update, alpha, ver);
}

/* Dissect the command-specific payload starting at offset; returns the
 * offset past the decoded fields. Layouts per DSP0236 1.3.3 clause 12.
 * Prepare for Endpoint Discovery (0x0b), Endpoint Discovery (0x0c) and
 * Discovery Notify (0x0d) carry no payload (Tables 28-30), so they need no
 * handling here. */
static unsigned
dissect_mctp_ctrl_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        unsigned cmd, bool rq, unsigned offset)
{
    unsigned count, i;

    switch (cmd) {
    case MCTP_CTRL_CMD_SET_EID:
        if (rq) {
            proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_op,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_eid,
                                tvb, offset + 1, 1, ENC_NA);
            offset += 2;
        } else {
            proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_rsvd_hi,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_status,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_rsvd_lo,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_alloc_status,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_setting,
                                tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_set_eid_pool_size,
                                tvb, offset + 2, 1, ENC_NA);
            offset += 3;
        }
        break;

    case MCTP_CTRL_CMD_GET_EID:
        if (!rq) {
            proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_eid,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_rsvd_hi,
                                tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_endpoint_type,
                                tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_rsvd_lo,
                                tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_eid_type,
                                tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_get_eid_medium_info,
                                tvb, offset + 2, 1, ENC_NA);
            offset += 3;
        }
        break;

    case MCTP_CTRL_CMD_GET_UUID:
        if (!rq) {
            /* RFC4122 byte order, MSB first (Table 17) */
            proto_tree_add_item(tree, hf_mctp_ctrl_uuid,
                                tvb, offset, 16, ENC_BIG_ENDIAN);
            offset += 16;
        }
        break;

    case MCTP_CTRL_CMD_GET_VERSION:
        if (rq) {
            proto_tree_add_item(tree, hf_mctp_ctrl_get_ver_msg_type,
                                tvb, offset, 1, ENC_NA);
            offset += 1;
        } else {
            proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_get_ver_count,
                                         tvb, offset, 1, ENC_NA, &count);
            offset += 1;
            for (i = 0; i < count; i++) {
                proto_item *pi;
                uint32_t ver;

                pi = proto_tree_add_item_ret_uint(tree,
                                    hf_mctp_ctrl_get_ver_entry,
                                    tvb, offset, 4, ENC_BIG_ENDIAN, &ver);
                /* Major/minor must be valid BCD; the update byte may be 0xff
                 * ("no update"), otherwise it too must be valid BCD (12.7.2). */
                if (!mctp_ctrl_bcd_byte_valid((ver >> 24) & 0xff) ||
                    !mctp_ctrl_bcd_byte_valid((ver >> 16) & 0xff) ||
                    (((ver >> 8) & 0xff) != 0xff &&
                     !mctp_ctrl_bcd_byte_valid((ver >> 8) & 0xff)))
                    expert_add_info(pinfo, pi, &ei_mctp_ctrl_ver_bcd);
                offset += 4;
            }
        }
        break;

    case MCTP_CTRL_CMD_GET_MSG_TYPES:
        if (!rq) {
            proto_tree_add_item_ret_uint(tree, hf_mctp_ctrl_msg_type_count,
                                         tvb, offset, 1, ENC_NA, &count);
            offset += 1;
            for (i = 0; i < count; i++) {
                proto_tree_add_item(tree, hf_mctp_ctrl_msg_type,
                                    tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }
        break;

    case MCTP_CTRL_CMD_ALLOCATE_EIDS:
        if (rq) {
            proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_op,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_count,
                                tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_start,
                                tvb, offset + 2, 1, ENC_NA);
            offset += 3;
        } else {
            proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_status,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_pool_size,
                                tvb, offset + 1, 1, ENC_NA);
            proto_tree_add_item(tree, hf_mctp_ctrl_alloc_eids_first,
                                tvb, offset + 2, 1, ENC_NA);
            offset += 3;
        }
        break;

    default:
        break;
    }

    return offset;
}

static int
dissect_mctp_ctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_tree *mctp_ctrl_tree, *mctp_ctrl_hdr_tree;
    unsigned len, payload_start, cmd, cc = 0;
    proto_item *ti, *hti;
    bool rq;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCTP Control");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Check that the packet is long enough for it to belong to us. */
    len = tvb_reported_length(tvb);

    if (len < MCTP_CTRL_MIN_LENGTH) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus length %u, minimum %u",
                     len, MCTP_CTRL_MIN_LENGTH);
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_item(tree, proto_mctp_ctrl, tvb, 0, -1, ENC_NA);
    mctp_ctrl_tree = proto_item_add_subtree(ti, ett_mctp_ctrl);

    hti = proto_tree_add_item(mctp_ctrl_tree, proto_mctp_ctrl, tvb, 0, -1,
                              ENC_NA);
    proto_item_set_text(hti, "MCTP Control Protocol header");
    mctp_ctrl_hdr_tree = proto_item_add_subtree(hti, ett_mctp_ctrl_hdr);

    proto_tree_add_item_ret_boolean(mctp_ctrl_hdr_tree, hf_mctp_ctrl_rq,
                                    tvb, 1, 1, ENC_NA, &rq);

    proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_d,
                        tvb, 1, 1, ENC_NA);

    proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_rsvd,
                        tvb, 1, 1, ENC_NA);

    proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_instance,
                        tvb, 1, 1, ENC_NA);

    proto_tree_add_item_ret_uint(mctp_ctrl_hdr_tree, hf_mctp_ctrl_command,
                                 tvb, 2, 1, ENC_NA, &cmd);

    col_add_fstr(pinfo->cinfo, COL_INFO, "MCTP %s %s",
                 val_to_str_const(cmd, command_vals, "Control"),
                 tfs_get_string(rq, &tfs_rq));

    payload_start = 3;

    if (!rq) {
        if (len == 3) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Bogus length %u for response, minimum 4", len);
            return tvb_captured_length(tvb);
        }
        proto_tree_add_item_ret_uint(mctp_ctrl_tree, hf_mctp_ctrl_cc,
                                     tvb, 3, 1, ENC_NA, &cc);
        payload_start++;
    }

    /* On an error completion code the responder shall not return any
     * additional parametric data (DSP0236 1.3.3 section 12.3), so only
     * decode response payloads for SUCCESS. */
    if (rq || cc == 0)
        payload_start = dissect_mctp_ctrl_payload(tvb, pinfo, mctp_ctrl_tree,
                                                  cmd, rq, payload_start);

    if (len > payload_start) {
        proto_tree_add_item(mctp_ctrl_tree, hf_mctp_ctrl_data,
                            tvb, payload_start, -1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_mctp_control(void)
{
    /* *INDENT-OFF* */
    /* Field definitions */
    static hf_register_info hf[] = {
        { &hf_mctp_ctrl_command,
          { "Command", "mctpc.command",
            FT_UINT8, BASE_DEC, VALS(command_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_rq,
          { "Rq", "mctpc.rq",
            FT_BOOLEAN, 8, TFS(&tfs_rq), 0x80,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_d,
          { "Datagram", "mctpc.d",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_rsvd,
          { "Reserved", "mctpc.rsvd",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_instance,
          { "Instance ID", "mctpc.instance",
            FT_UINT8, BASE_HEX, NULL, 0x1f,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_cc,
          { "Completion code", "mctpc.cc",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(cc_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_data,
          { "Data", "mctpc.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },
        /* Set Endpoint ID (DSP0236 1.3.3, Table 14) */
        { &hf_mctp_ctrl_set_eid_op,
          { "Operation", "mctpc.set_eid.op",
            FT_UINT8, BASE_HEX, VALS(set_eid_op_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_eid,
          { "Endpoint ID", "mctpc.set_eid.eid",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_rsvd_hi,
          { "Reserved", "mctpc.set_eid.rsvd_hi",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_status,
          { "EID assignment status", "mctpc.set_eid.status",
            FT_UINT8, BASE_HEX, VALS(set_eid_status_vals), 0x30,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_rsvd_lo,
          { "Reserved", "mctpc.set_eid.rsvd_lo",
            FT_UINT8, BASE_HEX, NULL, 0x0c,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_alloc_status,
          { "EID allocation status", "mctpc.set_eid.alloc_status",
            FT_UINT8, BASE_HEX, VALS(set_eid_alloc_status_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_setting,
          { "EID setting", "mctpc.set_eid.eid_setting",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_set_eid_pool_size,
          { "EID pool size", "mctpc.set_eid.pool_size",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Size of the dynamic EID pool; 0 = no dynamic EID pool", HFILL },
        },
        /* Get Endpoint ID (DSP0236 1.3.3, Table 15) */
        { &hf_mctp_ctrl_get_eid_eid,
          { "Endpoint ID", "mctpc.get_eid.eid",
            FT_UINT8, BASE_HEX, NULL, 0,
            "0x00 = EID not yet assigned", HFILL },
        },
        { &hf_mctp_ctrl_get_eid_rsvd_hi,
          { "Reserved", "mctpc.get_eid.rsvd_hi",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_endpoint_type,
          { "Endpoint type", "mctpc.get_eid.endpoint_type",
            FT_UINT8, BASE_HEX, VALS(get_eid_endpoint_type_vals), 0x30,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_rsvd_lo,
          { "Reserved", "mctpc.get_eid.rsvd_lo",
            FT_UINT8, BASE_HEX, NULL, 0x0c,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_eid_type,
          { "Endpoint ID type", "mctpc.get_eid.eid_type",
            FT_UINT8, BASE_HEX, VALS(get_eid_eid_type_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_eid_medium_info,
          { "Medium-specific information", "mctpc.get_eid.medium_info",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        /* Get Endpoint UUID (DSP0236 1.3.3, Table 16) */
        { &hf_mctp_ctrl_uuid,
          { "Endpoint UUID", "mctpc.uuid",
            FT_GUID, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        /* Get MCTP Version Support (DSP0236 1.3.3, Table 18) */
        { &hf_mctp_ctrl_get_ver_msg_type,
          { "Message type number", "mctpc.get_ver.msg_type",
            FT_UINT8, BASE_HEX, VALS(get_ver_msg_type_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_ver_count,
          { "Version number entry count", "mctpc.get_ver.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_get_ver_entry,
          { "Version number entry", "mctpc.get_ver.entry",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(mctp_ctrl_fmt_version), 0,
            NULL, HFILL },
        },
        /* Get Message Type Support (DSP0236 1.3.3, Table 19) */
        { &hf_mctp_ctrl_msg_type_count,
          { "Message type count", "mctpc.get_msg_types.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Number of message types supported in addition to MCTP control",
            HFILL },
        },
        { &hf_mctp_ctrl_msg_type,
          { "Message type", "mctpc.get_msg_types.type",
            FT_UINT8, BASE_HEX, VALS(msg_type_vals), 0,
            NULL, HFILL },
        },
        /* Allocate Endpoint IDs (DSP0236 1.3.3, Table 23) */
        { &hf_mctp_ctrl_alloc_eids_op,
          { "Operation", "mctpc.alloc_eids.op",
            FT_UINT8, BASE_HEX, VALS(alloc_eids_op_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_count,
          { "Number of Endpoint IDs", "mctpc.alloc_eids.count",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Number of EIDs in the pool being allocated", HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_start,
          { "Starting Endpoint ID", "mctpc.alloc_eids.start",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_status,
          { "Allocation status", "mctpc.alloc_eids.status",
            FT_UINT8, BASE_HEX, VALS(alloc_eids_status_vals), 0x03,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_pool_size,
          { "Endpoint ID pool size", "mctpc.alloc_eids.pool_size",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Size of the dynamic EID pool used by this endpoint", HFILL },
        },
        { &hf_mctp_ctrl_alloc_eids_first,
          { "First Endpoint ID", "mctpc.alloc_eids.first",
            FT_UINT8, BASE_HEX, NULL, 0,
            "First EID assigned to the pool; 0x00 = no EIDs assigned", HFILL },
        },
    };

    /* protocol subtree */
    static int *ett[] = {
        &ett_mctp_ctrl,
        &ett_mctp_ctrl_hdr,
    };

    static ei_register_info ei[] = {
        { &ei_mctp_ctrl_ver_bcd,
          { "mctpc.get_ver.entry.invalid_bcd", PI_PROTOCOL, PI_WARN,
            "Invalid BCD version encoding: each nibble must be 0-9 (an upper"
            " nibble of Fh marks a single digit), and 0xff is only defined for"
            " the update byte (DSP0236 section 12.7.2)", EXPFILL },
        },
    };

    expert_module_t *expert_mctp_ctrl;

    proto_mctp_ctrl = proto_register_protocol("MCTP Control Protocol",
                                              "MCTP-Control", "mctpc");

    proto_register_field_array(proto_mctp_ctrl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mctp_ctrl = expert_register_protocol(proto_mctp_ctrl);
    expert_register_field_array(expert_mctp_ctrl, ei, array_length(ei));

}

void
proto_reg_handoff_mctp_control(void)
{
    dissector_handle_t mctp_ctrl_handle;
    mctp_ctrl_handle = create_dissector_handle(dissect_mctp_ctrl, proto_mctp_ctrl);
    dissector_add_uint("mctp.type", MCTP_TYPE_CONTROL, mctp_ctrl_handle);
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
