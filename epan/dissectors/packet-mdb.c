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

static int proto_mdb;

static int ett_mdb;
static int ett_mdb_hdr;
static int ett_mdb_cl;
static int ett_mdb_cgw;

static int hf_mdb_hdr_ver;
static int hf_mdb_event;
static int hf_mdb_addr;
static int hf_mdb_cmd;
static int hf_mdb_cl_setup_sub;
static int hf_mdb_cl_feat_lvl;
static int hf_mdb_cl_cols;
static int hf_mdb_cl_rows;
static int hf_mdb_cl_disp_info;
static int hf_mdb_cl_max_price;
static int hf_mdb_cl_min_price;
static int hf_mdb_cl_vend_sub;
static int hf_mdb_cl_item_price;
static int hf_mdb_cl_item_num;
static int hf_mdb_cl_reader_sub;
static int hf_mdb_cl_resp;
static int hf_mdb_cl_scale;
static int hf_mdb_cl_dec_pl;
static int hf_mdb_cl_max_rsp_time;
static int hf_mdb_cl_vend_amt;
static int hf_mdb_cl_expns_sub;
static int hf_mdb_cl_manuf_code;
static int hf_mdb_cl_ser_num;
static int hf_mdb_cl_mod_num;
static int hf_mdb_cl_opt_feat;
static int hf_mdb_cgw_feat_lvl;
static int hf_mdb_cgw_scale;
static int hf_mdb_cgw_dec_pl;
static int hf_mdb_cgw_resp;
static int hf_mdb_cgw_max_rsp_time;
static int hf_mdb_cgw_report_sub;
static int hf_mdb_cgw_dts_evt_code;
static int hf_mdb_cgw_duration;
static int hf_mdb_cgw_activity;
static int hf_mdb_cgw_expns_sub;
static int hf_mdb_cgw_opt_feat;
static int hf_mdb_cgw_manuf_code;
static int hf_mdb_cgw_ser_num;
static int hf_mdb_cgw_mod_num;
static int hf_mdb_ack;
static int hf_mdb_data;
static int hf_mdb_chk;

static expert_field ei_mdb_short_packet;

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
#define ADDR_COMMS_GW  0x18

static const value_string mdb_addr[] = {
    { 0x08, "Changer" },
    { ADDR_CASHLESS1, "Cashless #1" },
    { ADDR_COMMS_GW, "Communications Gateway" },
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

/*
 * These are just the command bits in the address + command byte. MDB supports
 * two Cashless peripherals (Cashless #1 and #2) with different addresses,
 * both use the same commands.
 */
#define MDB_CL_CMD_SETUP  0x01
#define MDB_CL_CMD_VEND   0x03
#define MDB_CL_CMD_READER 0x04
#define MDB_CL_CMD_EXPNS  0x07

static const value_string mdb_cl_cmd[] = {
    { 0x00, "Reset" },
    { MDB_CL_CMD_SETUP, "Setup" },
    { 0x02, "Poll" },
    { MDB_CL_CMD_VEND, "Vend" },
    { MDB_CL_CMD_READER, "Reader" },
    { MDB_CL_CMD_EXPNS, "Expansion" },
    { 0, NULL }
};

#define MDB_CL_SETUP_CFG_DATA 0x00
#define MDB_CL_SETUP_MAX_MIN  0x01

static const value_string mdb_cl_setup_sub_cmd[] = {
    { MDB_CL_SETUP_CFG_DATA, "Config Data" },
    { MDB_CL_SETUP_MAX_MIN, "Max/Min Prices" },
    { 0, NULL }
};

#define MDB_CL_VEND_REQ 0x00
#define MDB_CL_VEND_SUC 0x02

static const value_string mdb_cl_vend_sub_cmd[] = {
    { MDB_CL_VEND_REQ, "Vend Request" },
    { MDB_CL_VEND_SUC, "Vend Success" },
    { 0x04, "Session Complete" },
    { 0, NULL }
};

static const value_string mdb_cl_reader_sub_cmd[] = {
    { 0x00, "Reader Disable" },
    { 0x01, "Reader Enable" },
    { 0, NULL }
};

#define MDB_CL_EXPNS_REQ_ID  0x00
#define MDB_CL_EXPNS_OPT_ENA 0x04

static const value_string mdb_cl_expns_sub_cmd[] = {
    { MDB_CL_EXPNS_REQ_ID, "Request ID" },
    { MDB_CL_EXPNS_OPT_ENA, "Optional Feature Enabled" },
    { 0, NULL }
};

#define MDB_CL_RESP_RD_CFG_DATA 0x01
#define MDB_CL_RESP_VEND_APRV   0x05
#define MDB_CL_RESP_PER_ID      0x09

static const value_string mdb_cl_resp[] = {
    { 0x00, "Just Reset" },
    { MDB_CL_RESP_RD_CFG_DATA, "Reader Config Data" },
    { 0x03, "Begin Session" },
    { MDB_CL_RESP_VEND_APRV, "Vend Approved" },
    { 0x06, "Vend Denied" },
    { 0x07, "End Session" },
    { MDB_CL_RESP_PER_ID, "Peripheral ID" },
    { 0x0b, "Cmd Out Of Sequence" },
    { 0, NULL }
};

/*
 * For the Communications Gateway, we use the complete address + command byte
 * as value for the value string. The values here match those in the MDB
 * specification.
 *
 * There's only one Communications Gateway, the address bits are always the
 * same. (This is different from the Cashless peripherals, see above.)
 */
#define MDB_CGW_ADDR_CMD_SETUP  0x19
#define MDB_CGW_ADDR_CMD_REPORT 0x1B
#define MDB_CGW_ADDR_CMD_EXPNS  0x1F

static const value_string mdb_cgw_addr_cmd[] = {
    { 0x18, "Reset" },
    { MDB_CGW_ADDR_CMD_SETUP, "Setup" },
    { 0x1A, "Poll" },
    { MDB_CGW_ADDR_CMD_REPORT, "Report" },
    { MDB_CGW_ADDR_CMD_EXPNS, "Expansion" },
    { 0, NULL }
};

#define MDB_CGW_REPORT_DTS_EVT 0x02

static const value_string mdb_cgw_report_sub_cmd[] = {
    { 0x01, "Transaction" },
    { MDB_CGW_REPORT_DTS_EVT, "DTS Event" },
    { 0, NULL }
};

#define MDB_CGW_EXPNS_FEAT_ENA 0x01

static const value_string mdb_cgw_expns_sub_cmd[] = {
    { 0x00, "Identification" },
    { MDB_CGW_EXPNS_FEAT_ENA, "Feature enable" },
    { 0x02, "Time/Date Request" },
    { 0, NULL }
};

#define MDB_CGW_RESP_CFG    0x01
#define MDB_CGW_RESP_PER_ID 0x06

static const value_string mdb_cgw_resp[] = {
    { 0x00, "Just Reset" },
    { MDB_CGW_RESP_CFG, "Comms Gateway Config" },
    { 0x05, "DTS Event Acknowledge" },
    { MDB_CGW_RESP_PER_ID, "Peripheral ID" },
    { 0, NULL }
};

static void dissect_mdb_ack(tvbuff_t *tvb, int offset,
        packet_info *pinfo, proto_tree *tree)
{
    uint32_t ack;

    proto_tree_add_item_ret_uint(tree, hf_mdb_ack, tvb, offset, 1,
                ENC_BIG_ENDIAN, &ack);
    col_set_str(pinfo->cinfo, COL_INFO,
            val_to_str_const(ack, mdb_ack, "Invalid ack byte"));
}

static void mdb_set_addrs(uint8_t event, uint8_t addr, packet_info *pinfo)
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

static void dissect_mdb_cl_setup(tvbuff_t *tvb, int offset,
        packet_info *pinfo, proto_tree *tree)
{
    uint32_t sub_cmd, price;
    const char *s;
    proto_item *pi;

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

        case MDB_CL_SETUP_MAX_MIN:
            if (tvb_reported_length_remaining(tvb, offset) == 5) {
                /* This is the "default version" of Max/Min Prices. */

                /* XXX - convert the scaled prices into actual amounts */
                price = tvb_get_ntohs(tvb, offset);
                pi = proto_tree_add_uint_format(tree, hf_mdb_cl_max_price,
                        tvb, offset, 2, price, "Maximum price: 0x%04x", price);
                if (price == 0xFFFF) {
                    proto_item_append_text(pi, " (unknown)");
                }
                offset += 2;

                price = tvb_get_ntohs(tvb, offset);
                pi = proto_tree_add_uint_format(tree, hf_mdb_cl_min_price,
                        tvb, offset, 2, price, "Minimum price: 0x%04x", price);
                if (price == 0x0000) {
                    proto_item_append_text(pi, " (unknown)");
                }
            }
            else if (tvb_reported_length_remaining(tvb, offset) == 11) {
                /* This is the "expanded currency version" of Max/Min Prices. */

                proto_tree_add_item(tree, hf_mdb_cl_max_price, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(tree, hf_mdb_cl_min_price, tvb, offset, 4,
                        ENC_BIG_ENDIAN);
            }
            /* XXX - expert info for other lengths */
            break;
    }
}

static void dissect_mdb_cl_vend(tvbuff_t *tvb, int offset,
        packet_info *pinfo, proto_tree *tree)
{
    uint32_t sub_cmd, price, item;
    const char *s;

    proto_tree_add_item_ret_uint(tree, hf_mdb_cl_vend_sub, tvb, offset, 1,
            ENC_BIG_ENDIAN, &sub_cmd);
    s = try_val_to_str(sub_cmd, mdb_cl_vend_sub_cmd);
    if (s) {
        col_set_str(pinfo->cinfo, COL_INFO, s);
    }
    offset++;

    switch (sub_cmd) {
        case MDB_CL_VEND_REQ:
            if (tvb_reported_length_remaining(tvb, offset) == 5) {
                proto_tree_add_item_ret_uint(tree, hf_mdb_cl_item_price, tvb,
                        offset, 2, ENC_BIG_ENDIAN, &price);
                offset += 2;
                proto_tree_add_item_ret_uint(tree, hf_mdb_cl_item_num, tvb,
                        offset, 2, ENC_BIG_ENDIAN, &item);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (item %d, price %d)",
                        item, price);
            }
            /* XXX - dissect the longer request in Expanded Currency Mode */
            break;
        case MDB_CL_VEND_SUC:
                proto_tree_add_item(tree, hf_mdb_cl_item_num, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
            break;
    }
}

static int
dissect_mdb_cl_id_fields(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_cl_manuf_code, tvb, offset, 3, ENC_ASCII);
    offset += 3;
    proto_tree_add_item(tree, hf_mdb_cl_ser_num, tvb, offset, 12, ENC_ASCII);
    offset += 12;
    proto_tree_add_item(tree, hf_mdb_cl_mod_num, tvb, offset, 12, ENC_ASCII);
    offset += 12;
    /* XXX - dissect the Software Version bytes */
    offset += 2;

    return offset;
}

static void dissect_mdb_cl_expns(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree)
{
    uint32_t sub_cmd;
    const char *s;

    proto_tree_add_item_ret_uint(tree, hf_mdb_cl_expns_sub,
                    tvb, offset, 1, ENC_BIG_ENDIAN, &sub_cmd);
    s = try_val_to_str(sub_cmd, mdb_cl_expns_sub_cmd);
    if (s) {
        col_set_str(pinfo->cinfo, COL_INFO, s);
    }
    offset++;

    switch (sub_cmd) {
        case MDB_CL_EXPNS_REQ_ID:
            dissect_mdb_cl_id_fields(tvb, offset, tree);
            break;
        case MDB_CL_EXPNS_OPT_ENA:
            /* XXX - add a bitmask for the Optional Feature Bits */
            proto_tree_add_item(tree, hf_mdb_cl_opt_feat, tvb, offset, 4,
                    ENC_BIG_ENDIAN);
            break;
    }
}

static void dissect_mdb_cl_rd_cfg_data(tvbuff_t *tvb, int offset,
        packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_cl_feat_lvl, tvb, offset, 1,
            ENC_BIG_ENDIAN);
    offset++;
    /* XXX - dissect Country/Currency Code */
    offset += 2;
    proto_tree_add_item(tree, hf_mdb_cl_scale, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_mdb_cl_dec_pl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_mdb_cl_max_rsp_time, tvb, offset, 1,
            ENC_TIME_SECS | ENC_BIG_ENDIAN);
}

static void dissect_mdb_mst_per_cl( tvbuff_t *tvb, int offset, int len _U_,
        packet_info *pinfo, proto_tree *tree, proto_item *cmd_it,
        uint8_t addr_byte)
{
    uint8_t cmd = addr_byte & 0x07; /* the 3-bit command */
    proto_tree *cl_tree;
    uint32_t sub_cmd;
    const char *s;

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
            dissect_mdb_cl_vend(tvb, offset, pinfo, cl_tree);
            break;
        case MDB_CL_CMD_READER:
            proto_tree_add_item_ret_uint(cl_tree, hf_mdb_cl_reader_sub,
                    tvb, offset, 1, ENC_BIG_ENDIAN, &sub_cmd);
            s = try_val_to_str(sub_cmd, mdb_cl_reader_sub_cmd);
            break;
        case MDB_CL_CMD_EXPNS:
            dissect_mdb_cl_expns(tvb, offset, pinfo, cl_tree);
            break;
    }
    if (s)
        col_set_str(pinfo->cinfo, COL_INFO, s);
}

static void dissect_mdb_per_mst_cl( tvbuff_t *tvb, int offset,
        int len _U_, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *cl_tree;
    uint32_t cl_resp;

    cl_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_cl,
            NULL, "Cashless");

    proto_tree_add_item_ret_uint(cl_tree, hf_mdb_cl_resp, tvb, offset, 1,
            ENC_BIG_ENDIAN, &cl_resp);
    col_set_str(pinfo->cinfo,
            COL_INFO, val_to_str_const(cl_resp, mdb_cl_resp, "Unknown"));
    offset++;

    switch (cl_resp) {
        case MDB_CL_RESP_RD_CFG_DATA:
            dissect_mdb_cl_rd_cfg_data(tvb, offset, pinfo, cl_tree);
            break;
        case MDB_CL_RESP_VEND_APRV:
            if (tvb_reported_length_remaining(tvb, offset) == 3) {
                proto_tree_add_item(cl_tree, hf_mdb_cl_vend_amt, tvb, offset,
                        2, ENC_BIG_ENDIAN);
            }
            /* XXX - dissect the longer response in Expanded Currency Mode */
            break;
        case MDB_CL_RESP_PER_ID:
            dissect_mdb_cl_id_fields(tvb, offset, tree);
            /* XXX - check if we have Optional Feature Bits */
            break;
    }
}

static void dissect_mdb_cgw_report(tvbuff_t *tvb, int offset,
        packet_info *pinfo, proto_tree *tree)
{
    uint32_t sub_cmd;
    const char *s;

    proto_tree_add_item_ret_uint(tree, hf_mdb_cgw_report_sub,
                    tvb, offset, 1, ENC_BIG_ENDIAN, &sub_cmd);
    s = try_val_to_str(sub_cmd, mdb_cgw_report_sub_cmd);
    if (s) {
        col_set_str(pinfo->cinfo, COL_INFO, s);
    }
    offset++;

    switch (sub_cmd) {
        case MDB_CGW_REPORT_DTS_EVT:
            proto_tree_add_item(tree, hf_mdb_cgw_dts_evt_code, tvb, offset, 10,
                    ENC_ASCII);
            offset += 10;
            /* XXX - dissect Date */
            offset += 4;
            /* XXX - dissect Time */
            offset += 2;
            proto_tree_add_item(tree, hf_mdb_cgw_duration, tvb, offset, 4,
                    ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_mdb_cgw_activity, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            break;
    }
}

static void dissect_mdb_cgw_expns(tvbuff_t *tvb, int offset,
        packet_info *pinfo, proto_tree *tree)
{
    uint32_t sub_cmd;
    const char *s;

    proto_tree_add_item_ret_uint(tree, hf_mdb_cgw_expns_sub,
                    tvb, offset, 1, ENC_BIG_ENDIAN, &sub_cmd);
    s = try_val_to_str(sub_cmd, mdb_cgw_expns_sub_cmd);
    if (s) {
        col_set_str(pinfo->cinfo, COL_INFO, s);
    }
    offset++;

    switch (sub_cmd) {
        case MDB_CGW_EXPNS_FEAT_ENA:
            proto_tree_add_item(tree, hf_mdb_cgw_opt_feat, tvb, offset, 4,
                    ENC_BIG_ENDIAN);
            break;
    }
}

static void dissect_mdb_mst_per_cgw( tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo, proto_tree *tree, proto_item *cmd_it,
        uint8_t addr_cmd_byte)
{
    proto_tree *cgw_tree;
    const char *s;

    s = val_to_str_const(addr_cmd_byte, mdb_cgw_addr_cmd, "Unknown");
    proto_item_append_text(cmd_it, " (%s)", s);
    col_set_str(pinfo->cinfo, COL_INFO, s);

    cgw_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_cgw,
            NULL, "Communications Gateway");

    switch (addr_cmd_byte) {
        case MDB_CGW_ADDR_CMD_SETUP:
            proto_tree_add_item(cgw_tree, hf_mdb_cgw_feat_lvl, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(cgw_tree, hf_mdb_cgw_scale, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(cgw_tree, hf_mdb_cgw_dec_pl, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            break;
        case MDB_CGW_ADDR_CMD_REPORT:
            dissect_mdb_cgw_report(tvb, offset, pinfo, cgw_tree);
            break;
        case MDB_CGW_ADDR_CMD_EXPNS:
            dissect_mdb_cgw_expns(tvb, offset, pinfo, cgw_tree);
            break;
    }
}

static void dissect_mdb_per_mst_cgw( tvbuff_t *tvb, int offset,
        int len, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree *cgw_tree;
    uint32_t cgw_resp;

    cgw_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_cgw,
            NULL, "Communications Gateway");

    proto_tree_add_item_ret_uint(cgw_tree, hf_mdb_cgw_resp, tvb, offset, 1,
            ENC_BIG_ENDIAN, &cgw_resp);
    col_set_str(pinfo->cinfo,
            COL_INFO, val_to_str_const(cgw_resp, mdb_cgw_resp, "Unknown"));
    offset++;

    switch (cgw_resp) {
        case MDB_CGW_RESP_CFG:
            proto_tree_add_item(cgw_tree, hf_mdb_cgw_feat_lvl, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(cgw_tree, hf_mdb_cgw_max_rsp_time, tvb, offset,
                    2, ENC_TIME_SECS | ENC_BIG_ENDIAN);
            break;
        case MDB_CGW_RESP_PER_ID:
            proto_tree_add_item(tree, hf_mdb_cgw_manuf_code, tvb, offset, 3,
                    ENC_ASCII);
            offset += 3;
            proto_tree_add_item(tree, hf_mdb_cgw_ser_num, tvb, offset, 12,
                    ENC_ASCII);
            offset += 12;
            proto_tree_add_item(tree, hf_mdb_cgw_mod_num, tvb, offset, 12,
                    ENC_ASCII);
            offset += 12;
            /* XXX - dissect the Software Version bytes */
            offset += 2;
            proto_tree_add_item(tree, hf_mdb_cgw_opt_feat, tvb, offset, 4,
                    ENC_BIG_ENDIAN);
            break;
    }
}

static void dissect_mdb_mst_per(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree)
{
    uint8_t addr_byte, addr;
    int mst_per_len;
    unsigned data_len;
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
    addr_byte = tvb_get_uint8(tvb, offset);
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
        case ADDR_COMMS_GW:
            dissect_mdb_mst_per_cgw(tvb, offset, data_len, pinfo, tree,
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

static void dissect_mdb_per_mst(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, uint8_t addr)
{
    int per_mst_len;
    unsigned data_len;

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
        case ADDR_COMMS_GW:
            dissect_mdb_per_mst_cgw(tvb, offset, data_len, pinfo, tree);
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
    int offset = 0, offset_ver, offset_evt;
    uint8_t version, event, addr;
    proto_tree *mdb_tree, *hdr_tree;
    proto_item *tree_ti, *hdr_ti;

    /* We need at least the shortest possible pseudo header. */
    if (tvb_captured_length(tvb) < 3)
        return 0;

    offset_ver = offset;
    version = tvb_get_uint8(tvb, offset++);
    if (version != 0)
        return 0;

    offset_evt = offset;
    event = tvb_get_uint8(tvb, offset++);
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
        addr = tvb_get_uint8(tvb, offset) & 0xF8;
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

    static int *ett[] = {
        &ett_mdb,
        &ett_mdb_hdr,
        &ett_mdb_cl,
        &ett_mdb_cgw
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
        { &hf_mdb_cl_max_price,
            { "Maximum price", "mdb.cashless.max_price",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_min_price,
            { "Minimum price", "mdb.cashless.min_price",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_vend_sub,
            { "Sub-command", "mdb.cashless.vend_sub_cmd",
                FT_UINT8, BASE_HEX, VALS(mdb_cl_vend_sub_cmd), 0, NULL, HFILL }
        },
        { &hf_mdb_cl_item_price,
            { "Item Price", "mdb.cashless.item_price",
                FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_item_num,
            { "Item Number", "mdb.cashless.item_number",
                FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_reader_sub,
            { "Sub-command", "mdb.cashless.reader_sub_cmd",
                FT_UINT8, BASE_HEX, VALS(mdb_cl_reader_sub_cmd), 0, NULL, HFILL }
        },
        { &hf_mdb_cl_resp,
            { "Response", "mdb.cashless.resp",
                FT_UINT8, BASE_HEX, VALS(mdb_cl_resp), 0, NULL, HFILL }
        },
        { &hf_mdb_cl_scale,
            { "Scale factor", "mdb.cashless.scale_factor",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_dec_pl,
            { "Decimal places", "mdb.cashless.decimal_places",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_max_rsp_time,
            { "Application maximum response time", "mdb.cashless.max_rsp_time",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_vend_amt,
            { "Vend Amount", "mdb.cashless.vend_amount",
                FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_expns_sub,
            { "Sub-command", "mdb.cashless.expansion_sub_cmd",
                FT_UINT8, BASE_HEX, VALS(mdb_cl_expns_sub_cmd), 0, NULL, HFILL }
        },
        { &hf_mdb_cl_manuf_code,
            { "Manufacturer Code", "mdb.cashless.manuf_code",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_ser_num,
            { "Serial Number", "mdb.cashless.serial_number",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_mod_num,
            { "Model Number", "mdb.cashless.model_number",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cl_opt_feat,
            { "Optional Feature Bits", "mdb.cashless.opt_feature_bits",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_feat_lvl,
            { "Feature level", "mdb.comms_gw.feature_level",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_scale,
            { "Scale factor", "mdb.comms_gw.scale_factor",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_dec_pl,
            { "Decimal places", "mdb.comms_gw.decimal_places",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_resp,
            { "Response", "mdb.comms_gw.resp",
                FT_UINT8, BASE_HEX, VALS(mdb_cgw_resp), 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_max_rsp_time,
            { "Application maximum response time", "mdb.comms_gw.max_rsp_time",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_report_sub,
            { "Sub-command", "mdb.comms_gw.report_sub_cmd", FT_UINT8,
                BASE_HEX, VALS(mdb_cgw_report_sub_cmd), 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_dts_evt_code,
            { "DTS Event Code", "mdb.comms_gw.dts_event_code",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_duration,
            { "Duration", "mdb.comms_gw.duration",
                FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_activity,
            { "Activity", "mdb.comms_gw.activity",
                FT_BOOLEAN, 8, TFS(&tfs_active_inactive), 0x1, NULL, HFILL }
        },
        { &hf_mdb_cgw_expns_sub,
            { "Sub-command", "mdb.comms_gw.expansion_sub_cmd", FT_UINT8,
                BASE_HEX, VALS(mdb_cgw_expns_sub_cmd), 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_opt_feat,
            { "Optional Feature Bits", "mdb.comms_gw.opt_feature_bits",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_manuf_code,
            { "Manufacturer Code", "mdb.comms_gw.manuf_code",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_ser_num,
            { "Serial Number", "mdb.comms_gw.serial_number",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_cgw_mod_num,
            { "Model Number", "mdb.comms_gw.model_number",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
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
