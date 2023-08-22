/*
 * packet-mdb.c
 * Routines for MDB dissection
 * Copyright 2023 Martin Kaiser for PayTec AG (www.paytec.ch)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The MDB (Multi-Drop Bus) protocol is used inside a vending machine. MDB
 * defines the communication between the main control board (VMC = Vending
 * Machine Controller) and peripheral components, e.g. a payment terminal
 * or a bill validator.
 *
 * The VMC acts as bus master and sends a request to one peripheral at a time.
 * A peripheral may send data only in response to such a request.
 *
 * The MDB specification is maintained by the National Automatic Merchandising
 * Association (NAMA). As of August 2023, the current version of the MDB
 * specification is 4.3. It is available from
 * https://namanow.org/nama-releases-mdb-version-4-3/
 *
 * The pcap input format for this dissector is documented at
 * https://www.kaiser.cx/pcap-mdb.html
 */

#include "config.h"
#include <epan/expert.h>
#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_mdb(void);

static dissector_handle_t mdb_handle;

static int proto_mdb = -1;

static int ett_mdb = -1;
static int ett_mdb_hdr = -1;
static int ett_mdb_cl = -1;

static int hf_mdb_hdr_ver = -1;
static int hf_mdb_event = -1;
static int hf_mdb_addr = -1;
static int hf_mdb_cmd = -1;
static int hf_mdb_cl_setup_sub = -1;
static int hf_mdb_cl_feat_lvl = -1;
static int hf_mdb_cl_cols = -1;
static int hf_mdb_cl_rows = -1;
static int hf_mdb_cl_disp_info = -1;
static int hf_mdb_cl_vend_sub = -1;
static int hf_mdb_cl_reader_sub = -1;
static int hf_mdb_cl_resp = -1;
static int hf_mdb_ack = -1;
static int hf_mdb_data = -1;
static int hf_mdb_chk = -1;

static expert_field ei_mdb_short_packet = EI_INIT;

#define MDB_EVT_DATA_MST_PER 0xFF
#define MDB_EVT_DATA_PER_MST 0xFE
#define MDB_EVT_BUS_RESET    0xFD

static const value_string mdb_event[] = {
    { MDB_EVT_DATA_MST_PER, "Data transfer Master -> Peripheral" },
    { MDB_EVT_DATA_PER_MST, "Data transfer Peripheral -> Master" },
    { MDB_EVT_BUS_RESET, "Bus reset" },
    { 0, NULL }
};

#define ADDR_VMC "VMC"

#define ADDR_CASHLESS1 0x10

static const value_string mdb_addr[] = {
    { 0x08, "Changer" },
    { ADDR_CASHLESS1, "Cashless #1" },
    { 0x18, "Communication Gateway" },
    { 0x30, "Bill Validator" },
    { 0x60, "Cashless #2" },
    { 0x68, "Age Verification Device" },
    { 0, NULL }
};

static const value_string mdb_ack[] = {
    { 0x00, "ACK" },
    { 0xAA, "RET" },
    { 0xFF, "NAK" },
    { 0, NULL }
};

#define MDB_CL_CMD_SETUP  0x01
#define MDB_CL_CMD_VEND   0x03
#define MDB_CL_CMD_READER 0x04

static const value_string mdb_cl_cmd[] = {
    { 0x00, "Reset" },
    { MDB_CL_CMD_SETUP, "Setup" },
    { 0x02, "Poll" },
    { MDB_CL_CMD_VEND, "Vend" },
    { MDB_CL_CMD_READER, "Reader" },
    { 0x07, "Expansion" },
    { 0, NULL }
};

#define MDB_CL_SETUP_CFG_DATA 0x00
#define MDB_CL_SETUP_MAX_MIN  0x01

static const value_string mdb_cl_setup_sub_cmd[] = {
    { MDB_CL_SETUP_CFG_DATA, "Config Data" },
    { MDB_CL_SETUP_MAX_MIN, "Max/Min Prices" },
    { 0, NULL }
};

static const value_string mdb_cl_vend_sub_cmd[] = {
    { 0x00, "Vend Request" },
    { 0x02, "Vend Success" },
    { 0x04, "Session Complete" },
    { 0, NULL }
};

static const value_string mdb_cl_reader_sub_cmd[] = {
    { 0x00, "Reader Disable" },
    { 0x01, "Reader Enable" },
    { 0, NULL }
};

static const value_string mdb_cl_resp[] = {
    { 0x00, "Just Reset" },
    { 0x01, "Reader Config Data" },
    { 0x03, "Begin Session" },
    { 0x05, "Vend Approved" },
    { 0x06, "Vend Denied" },
    { 0x07, "End Session" },
    { 0x09, "Peripheral ID" },
    { 0x0b, "Cmd Out Of Sequence" },
    { 0, NULL }
};

static void dissect_mdb_ack(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    guint32 ack;

    proto_tree_add_item_ret_uint(tree, hf_mdb_ack, tvb, offset, 1,
                ENC_BIG_ENDIAN, &ack);
    col_set_str(pinfo->cinfo, COL_INFO,
            val_to_str_const(ack, mdb_ack, "Invalid ack byte"));
}

static void mdb_set_addrs(guint8 event, guint8 addr, packet_info *pinfo)
{
    const char *periph = val_to_str(addr, mdb_addr, "Unknown (0x%02x)");

    /* pinfo->p2p_dir is from the perspective of the master (VMC) */

    if (event == MDB_EVT_DATA_MST_PER) {
        set_address(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR_VMC)+1, ADDR_VMC);
        set_address(&pinfo->dst, AT_STRINGZ, (int)strlen(periph)+1, periph);
        pinfo->p2p_dir = P2P_DIR_SENT;
    }
    else if (event == MDB_EVT_DATA_PER_MST) {
        set_address(&pinfo->src, AT_STRINGZ, (int)strlen(periph)+1, periph);
        set_address(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR_VMC)+1, ADDR_VMC);
        pinfo->p2p_dir = P2P_DIR_RECV;
    }
}

static void dissect_mdb_cl_setup(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree)
{
    guint32 sub_cmd;
    const gchar *s;

    proto_tree_add_item_ret_uint(tree, hf_mdb_cl_setup_sub,
                    tvb, offset, 1, ENC_BIG_ENDIAN, &sub_cmd);
    s = try_val_to_str(sub_cmd, mdb_cl_setup_sub_cmd);
    if (s) {
        col_set_str(pinfo->cinfo, COL_INFO, s);
    }
    offset++;

    switch (sub_cmd) {
        case MDB_CL_SETUP_CFG_DATA:
            proto_tree_add_item(tree, hf_mdb_cl_feat_lvl, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_mdb_cl_cols, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_mdb_cl_rows, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_mdb_cl_disp_info, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            break;
    }
}

static void dissect_mdb_mst_per_cl( tvbuff_t *tvb, gint offset, gint len _U_,
        packet_info *pinfo, proto_tree *tree, proto_item *cmd_it,
        guint8 addr_byte)
{
    guint8 cmd = addr_byte & 0x07; /* the 3-bit command */
    proto_tree *cl_tree;
    guint32 sub_cmd;
    const gchar *s;

    s = val_to_str_const(cmd, mdb_cl_cmd, "Unknown");
    proto_item_append_text(cmd_it, " (%s)", s);
    col_set_str(pinfo->cinfo, COL_INFO, s);

    cl_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_cl,
            NULL, "Cashless");

    s = NULL;
    switch (cmd) {
        case MDB_CL_CMD_SETUP:
            dissect_mdb_cl_setup(tvb, offset, pinfo, cl_tree);
            break;
        case MDB_CL_CMD_VEND:
            proto_tree_add_item_ret_uint(cl_tree, hf_mdb_cl_vend_sub,
                    tvb, offset, 1, ENC_BIG_ENDIAN, &sub_cmd);
            s = try_val_to_str(sub_cmd, mdb_cl_vend_sub_cmd);
            break;
        case MDB_CL_CMD_READER:
            proto_tree_add_item_ret_uint(cl_tree, hf_mdb_cl_reader_sub,
                    tvb, offset, 1, ENC_BIG_ENDIAN, &sub_cmd);
            s = try_val_to_str(sub_cmd, mdb_cl_reader_sub_cmd);
            break;
    }
    if (s)
        col_set_str(pinfo->cinfo, COL_INFO, s);
}

static void dissect_mdb_per_mst_cl( tvbuff_t *tvb, gint offset,
        gint len _U_, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *cl_tree;
    guint32 cl_resp;

    cl_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_cl,
            NULL, "Cashless");

    proto_tree_add_item_ret_uint(cl_tree, hf_mdb_cl_resp, tvb, offset, 1,
            ENC_BIG_ENDIAN, &cl_resp);
    col_set_str(pinfo->cinfo,
            COL_INFO, val_to_str_const(cl_resp, mdb_cl_resp, "Unknown"));
}

static void dissect_mdb_mst_per(tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree)
{
    guint8 addr_byte, addr;
    gint mst_per_len;
    guint data_len;
    proto_item *cmd_it;

    mst_per_len = tvb_reported_length_remaining(tvb, offset);
    if (mst_per_len <= 0) {
        expert_add_info(pinfo, tree, &ei_mdb_short_packet);
        return;
    }

    if (mst_per_len == 1) {
        dissect_mdb_ack(tvb, offset, pinfo, tree);
        return;
    }

    /*
     * Our packet has one address byte, an optional data block and one
     * checksum byte.
     */

    data_len = mst_per_len - 2;

    /*
     * The address byte is 5-bit address | 3-bit command.
     *
     * The specification uses 8-bit addresses which are the address byte
     * with the three lowest bits set to 0.
     *
     * The commands are defined as the complete address byte (i.e. they
     * include the address part). This does not make much sense: Cashless #1
     * and #2 have different addresses but exactly the same 3-bit commands.
     *
     * In this dissector, we try to use the same values as the specification.
     */
    addr_byte = tvb_get_guint8(tvb, offset);
    addr = addr_byte & 0xF8;
    proto_tree_add_uint_bits_format_value(tree, hf_mdb_addr,
            tvb, 8*offset, 5, addr, ENC_BIG_ENDIAN, "0x%02x", addr);
    cmd_it = proto_tree_add_uint(tree, hf_mdb_cmd, tvb, offset, 1, addr_byte);
    mdb_set_addrs(MDB_EVT_DATA_MST_PER, addr, pinfo);
    offset++;

    /*
     * We call the peripheral functions even if data_len == 0 so they can fix
     * up the command with peripheral-specific info.
     */
    switch (addr) {
        case ADDR_CASHLESS1:
            dissect_mdb_mst_per_cl(tvb, offset, data_len, pinfo, tree,
                    cmd_it, addr_byte);
            break;

        default:
            if (data_len > 0) {
                proto_tree_add_item(tree, hf_mdb_data,
                        tvb, offset, data_len, ENC_NA);
            }
            break;
    }
    offset += data_len;

    /* XXX - verify the checksum */
    proto_tree_add_item(tree, hf_mdb_chk, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void dissect_mdb_per_mst(tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree, guint8 addr)
{
    gint per_mst_len;
    guint data_len;

    /*
     * A packet from peripheral to master is either a single ACK/NAK byte or
     * a non-empty data block followed by one checksum byte.
     */

    per_mst_len = tvb_reported_length_remaining(tvb, offset);
    if (per_mst_len <= 0) {
        expert_add_info(pinfo, tree, &ei_mdb_short_packet);
        return;
    }

    if (per_mst_len == 1) {
        dissect_mdb_ack(tvb, offset, pinfo, tree);
        return;
    }

    data_len = per_mst_len - 1;
    switch (addr) {
        case ADDR_CASHLESS1:
            dissect_mdb_per_mst_cl(tvb, offset, data_len, pinfo, tree);
            break;

        default:
            proto_tree_add_item(tree, hf_mdb_data, tvb, offset, data_len, ENC_NA);
            break;
    }
    offset += data_len;

    /* XXX - verify the checksum */
    proto_tree_add_item(tree, hf_mdb_chk, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static int dissect_mdb(tvbuff_t *tvb,
        packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0, offset_ver, offset_evt;
    guint8 version, event, addr;
    proto_tree *mdb_tree, *hdr_tree;
    proto_item *tree_ti, *hdr_ti;

    /* We need at least the shortest possible pseudo header. */
    if (tvb_captured_length(tvb) < 3)
        return 0;

    offset_ver = offset;
    version = tvb_get_guint8(tvb, offset++);
    if (version != 0)
        return 0;

    offset_evt = offset;
    event = tvb_get_guint8(tvb, offset++);
    if (!try_val_to_str(event, mdb_event))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MDB");
    col_clear(pinfo->cinfo, COL_INFO);

    tree_ti = proto_tree_add_protocol_format(tree, proto_mdb,
            tvb, 0, tvb_reported_length(tvb), "MDB");
    mdb_tree = proto_item_add_subtree(tree_ti, ett_mdb);

    hdr_tree = proto_tree_add_subtree(mdb_tree, tvb, 0, -1, ett_mdb_hdr,
            &hdr_ti, "Pseudo header");

    proto_tree_add_item(hdr_tree, hf_mdb_hdr_ver,
            tvb, offset_ver, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_mdb_event,
            tvb, offset_evt, 1, ENC_BIG_ENDIAN);

    /* Packets from peripheral to master always have an address byte in their
       pseudo header. */
    if (event == MDB_EVT_DATA_PER_MST) {
        /* See the comment in dissect_mdb_mst_per about MDB addresses. */
        addr = tvb_get_guint8(tvb, offset) & 0xF8;
        proto_tree_add_uint_bits_format_value(hdr_tree, hf_mdb_addr,
                tvb, 8*offset, 5, addr, ENC_BIG_ENDIAN, "0x%02x", addr);
        offset++;
        mdb_set_addrs(event, addr, pinfo);
    }

    /* We're now at the end of the pseudo header. */
    proto_item_set_len(hdr_ti, offset);

    if (event == MDB_EVT_BUS_RESET)
        return offset;

    if (event == MDB_EVT_DATA_MST_PER)
        dissect_mdb_mst_per(tvb, offset, pinfo, mdb_tree);
    else if (event == MDB_EVT_DATA_PER_MST)
        dissect_mdb_per_mst(tvb, offset, pinfo, mdb_tree, addr);

    return tvb_reported_length(tvb);
}

void proto_register_mdb(void)
{
    expert_module_t* expert_mdb;

    static gint *ett[] = {
        &ett_mdb,
        &ett_mdb_hdr,
        &ett_mdb_cl
    };

    static hf_register_info hf[] = {
        { &hf_mdb_hdr_ver,
            { "Version", "mdb.hdr_ver",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_event,
            { "Event", "mdb.event",
                FT_UINT8, BASE_HEX, VALS(mdb_event), 0, NULL, HFILL }
        },
        { &hf_mdb_addr,
            { "Address", "mdb.addr",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cmd,
            { "Command", "mdb.cmd",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_setup_sub,
            { "Sub-command", "mdb.cashless.setup_sub_cmd",
                FT_UINT8, BASE_HEX, VALS(mdb_cl_setup_sub_cmd), 0, NULL, HFILL }
        },
        { &hf_mdb_cl_feat_lvl,
            { "Feature level", "mdb.cashless.feature_level",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_cols,
            { "Columns on display", "mdb.cashless.columns",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_rows,
            { "Rows on display", "mdb.cashless.rows",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_disp_info,
            { "Display information", "mdb.cashless.disp_info",
                FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
        },
        { &hf_mdb_cl_vend_sub,
            { "Sub-command", "mdb.cashless.vend_sub_cmd",
                FT_UINT8, BASE_HEX, VALS(mdb_cl_vend_sub_cmd), 0, NULL, HFILL }
        },
        { &hf_mdb_cl_reader_sub,
            { "Sub-command", "mdb.cashless.reader_sub_cmd",
                FT_UINT8, BASE_HEX, VALS(mdb_cl_reader_sub_cmd), 0, NULL, HFILL }
        },
        { &hf_mdb_cl_resp,
            { "Response", "mdb.cashless.resp",
                FT_UINT8, BASE_HEX, VALS(mdb_cl_resp), 0, NULL, HFILL }
        },
        { &hf_mdb_ack,
            { "Ack byte", "mdb.ack",
                FT_UINT8, BASE_HEX, VALS(mdb_ack), 0, NULL, HFILL }
        },
        { &hf_mdb_data,
            { "Data", "mdb.data",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_chk,
            { "Checksum", "mdb.chk",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_mdb_short_packet,
            { "mdb.short_packet", PI_PROTOCOL, PI_ERROR,
                "MDB packet without payload", EXPFILL }}
    };

    proto_mdb = proto_register_protocol("Multi-Drop Bus", "MDB", "mdb");
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_mdb, hf, array_length(hf));
    expert_mdb = expert_register_protocol(proto_mdb);
    expert_register_field_array(expert_mdb, ei, array_length(ei));
    mdb_handle = register_dissector("mdb", dissect_mdb, proto_mdb);
}

void proto_reg_handoff_mdb(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_MDB, mdb_handle);
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
