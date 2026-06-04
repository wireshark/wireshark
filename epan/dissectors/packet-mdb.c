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
#include <epan/conversation.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wiretap/wtap.h>

void proto_reg_handoff_mdb(void);
void proto_register_mdb(void);

static int proto_mdb;

static int ett_mdb;
static int ett_mdb_hdr;
static int ett_mdb_cl;
static int ett_mdb_cgw;
static int ett_mdb_bv;

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
static int hf_mdb_bv_setup_bill_val_feature;
static int hf_mdb_bv_setup_ctry_currency_code;
static int hf_mdb_bv_setup_bill_scal_fac;
static int hf_mdb_bv_setup_dec_places;
static int hf_mdb_bv_setup_bill_stacker_cap;
static int hf_mdb_bv_setup_bill_sec_lvls;
static int hf_mdb_bv_setup_escrow;
static int hf_mdb_bv_setup_bill_type_cred;
static int hf_mdb_bv_bill_enable;
static int hf_mdb_bv_bill_escrow_enable;
static int hf_mdb_bv_poll_state;
static int hf_mdb_bv_poll_bill_routing_state;
static int hf_mdb_bv_poll_bill_type;
static int hf_mdb_bv_escrow_state;
static int hf_mdb_bv_stacker;
static int hf_mdb_bv_exp_cmd;
static int hf_mdb_bv_exp_opt_feat;
static int hf_mdb_bv_exp_opt_feat_enable;
static int hf_mdb_bv_exp_manufact_code;
static int hf_mdb_bv_exp_serial_num;
static int hf_mdb_bv_exp_model_tuning_num;
static int hf_mdb_bv_exp_software_version;
static int hf_mdb_bv_exp_bill_type_routing;
static int hf_mdb_bv_exp_manual_dispense_enable;
static int hf_mdb_bv_exp_bill_recycler_enabled;
static int hf_mdb_bv_exp_bill_count;
static int hf_mdb_bv_exp_dispenser_full_state;
static int hf_mdb_bv_exp_bill_type_dispensed;
static int hf_mdb_bv_exp_bill_type_number_bills;
static int hf_mdb_bv_exp_dispense_value_bills;
static int hf_mdb_bv_exp_payout_state;
static int hf_mdb_bv_exp_dispenser_payout_activity;

static int hf_mdb_ack;
static int hf_mdb_data;
static int hf_mdb_chk;
static int hf_mdb_chk_status;
static int hf_mdb_response_in;
static int hf_mdb_response_to;
static int hf_mdb_time;

static expert_field ei_mdb_short_packet;
static expert_field ei_mdb_bad_checksum;

static dissector_handle_t mdb_handle;

/* MDB is a master slave protocol, so per request, there is exactly one response */
typedef struct {
    uint32_t req_num, rep_num;
    nstime_t req_time;
    uint16_t cmd;   // In case of expanse cmd, 2 byte are used
} mdb_transaction_t;

typedef struct {
    wmem_tree_t* transactions;
    uint32_t last_req_packet;
    uint16_t last_cmd;
} mdb_conv_info_t;

static mdb_conv_info_t* get_mdb_conv_info(packet_info* pinfo)
{
    conversation_t* conversation;
    mdb_conv_info_t* conv_info;

    conversation = find_or_create_conversation(pinfo);
    conv_info = (mdb_conv_info_t*)conversation_get_proto_data(conversation, proto_mdb);
    if (!conv_info) {
        conv_info = wmem_new0(wmem_file_scope(), mdb_conv_info_t);
        conv_info->transactions = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_mdb, conv_info);
    }
    return conv_info;
}

#define MDB_EVT_DATA_MST_PER 0xFF
#define MDB_EVT_DATA_PER_MST 0xFE
#define MDB_EVT_BUS_RESET    0xFD

#define MDB_PSEUDO_HDR_LEN   2

static bool is_mdb_reply(uint8_t byte) {
    return (byte == 0x00 || byte == 0xAA || byte == 0xFF);
}

static const value_string mdb_event[] = {
    { MDB_EVT_DATA_MST_PER, "Data transfer Master -> Peripheral" },
    { MDB_EVT_DATA_PER_MST, "Data transfer Peripheral -> Master" },
    { MDB_EVT_BUS_RESET, "Bus reset" },
    { 0, NULL }
};

#define ADDR_VMC "VMC"

#define ADDR_CASHLESS1      0x10
#define ADDR_COMMS_GW       0x18
#define ADDR_BILL_VALIDATOR 0x30

#define ADDR_MASK           0xF8
#define CMD_MASK            0x07
#define SUB_CMD_OFFSET      8

static const value_string mdb_addr[] = {
    { 0x00, "Reserved for VMC" },
    { 0x08, "Changer" },
    { ADDR_CASHLESS1, "Cashless #1" },
    { ADDR_COMMS_GW, "Communications Gateway" },
    { 0x20, "Display" },
    { 0x28, "Energy Management System" },
    { ADDR_BILL_VALIDATOR, "Bill Validator" },
    { 0x38, "Reserved for Future Standard Peripheral" },
    { 0x40, "Universal Satellite Device #1" },
    { 0x48, "Universal Satellite Device #2" },
    { 0x50, "Universal Satellite Device #3" },
    { 0x58, "Coin Hopper or Tube - Dispenser 1" },
    { 0x60, "Cashless #2" },
    { 0x68, "Age Verification Device" },
    { 0x70, "Coin Hopper or Tube - Dispenser 2" },
    { 0xF0, "Vending Machine Specific Peripheral #1" },
    { 0xF8, "Vending Machine Specific Peripheral #2" },
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

/*
 * Commands for Bill Validator
 */
#define MDB_BV_CMD_SETUP      0x01
#define MDB_BV_CMD_SECURITY   0x02
#define MDB_BV_CMD_POLL       0x03
#define MDB_BV_CMD_BILL_TYPE  0x04
#define MDB_BV_CMD_ESCROW     0x05
#define MDB_BV_CMD_STACKER    0x06
#define MDB_BV_CMD_EXPNS      0x07
#define MDB_BV_CMD_NONE       0xFF

static const value_string mdb_bv_cmd[] = {
    { 0x00, "Reset" },
    { MDB_BV_CMD_SETUP, "Setup" },
    { MDB_BV_CMD_SECURITY, "Security" },
    { MDB_BV_CMD_POLL, "Poll" },
    { MDB_BV_CMD_BILL_TYPE, "Bill type" },
    { MDB_BV_CMD_ESCROW, "Escrow" },
    { MDB_BV_CMD_STACKER, "Stacker" },
    { MDB_BV_CMD_EXPNS, "Expansion" },
    { 0, NULL }
};

#define MDB_BV_LVL1_WITHOUT_OPT_BITS    0x00
#define MDB_BV_LVL2_FEATURE_ENABLE      0x01
#define MDB_BV_LVL2_ID_WITH_OPTION_BITS 0x02
#define MDB_BV_RECYCL_SETUP             0x03
#define MDB_BV_RECYCL_ENABLE            0x04
#define MDB_BV_BILL_DISPENSE_STAT       0x05
#define MDB_BV_DISPENSE_BILL            0x06
#define MDB_BV_DISPENSE_VAL             0x07
#define MDB_BV_PAYOUT_STAT              0x08
#define MDB_BV_PAYOUT_VALUE_POLL        0x09
#define MDB_BV_PAYOUT_CANCEL            0x0A

static const value_string mdb_bv_exp_cmd[] = {
    { MDB_BV_LVL1_WITHOUT_OPT_BITS, "Level1 Identification without option bits" },
    { MDB_BV_LVL2_FEATURE_ENABLE, "Level2+ Feature Enable" },
    { MDB_BV_LVL2_ID_WITH_OPTION_BITS, "ID with Option Bits" },
    { MDB_BV_RECYCL_SETUP, "Recycler Setup" },
    { MDB_BV_RECYCL_ENABLE, "Recycler Enable" },
    { MDB_BV_BILL_DISPENSE_STAT, "Bill Dispense Status" },
    { MDB_BV_DISPENSE_BILL, "Dispense Bill" },
    { MDB_BV_DISPENSE_VAL, "Dispense Value" },
    { MDB_BV_PAYOUT_STAT, "Payout Status" },
    { MDB_BV_PAYOUT_VALUE_POLL, "Payout Value Poll" },
    { MDB_BV_PAYOUT_CANCEL, "Payout Cancel" },
    { 0, NULL }
};

static const true_false_string mdb_bv_escrow_state = { "Escrow Stack Bill", "Escrow Return Bill" };

// Format: 1yyyxxxx, where yyy = Bill routing, xxxx = Bill type (0 to 15)
static const value_string mdb_bv_poll_bill_routing_state[] = {
    { 0x00, "Bill Stacked" },
    { 0x01, "Escrow Position" },
    { 0x02, "Bill Returned" },
    { 0x03, "Bill to Recycler" },
    { 0x04, "Disabled Bill Rejected" },
    { 0x05, "Bill to Recycler" },
    { 0x06, "Manual Dispense" },
    { 0x07, "Transferred from Recycler to Cashbox" },
    { 0, NULL }
};


static const value_string mdb_bv_poll_state[] = {
/* Bill Validator (Only) */
    { 0x01, "Defective Motor" }, // One of the motors has failed to perform its expected assignment.
    { 0x02, "Sensor Problem" }, // One of the sensors has failed to provide its response.
    { 0x03, "Validator Busy" }, // The validator is busy and can not answer a detailed command right now.
    { 0x04, "ROM Checksum Error" }, // The validators internal checksum does not match the calculated checksum.
    { 0x05, "Validator Jammed" }, // A bill(s) has jammed in the acceptance path.
    { 0x06, "Validator was reset" }, // The validator has been reset since the last POLL.
    { 0x07, "Bill removed" }, // A bill in the escrow position has been removed by an unknown means. A BILL RETURNED message should also be sent.
    { 0x08, "Cash Box out of position" }, // The validator has detected the cash box to be open or removed.
    { 0x09, "Validator disabled" }, // The validator has been disabled, by the VMC or because of internal conditions.
    { 0x0A, "Invalid Escrow request" }, // An ESCROW command was requested for a bill not in the escrow position.
    { 0x0B, "Bill rejected" }, // A bill was detected, but rejected because it could not be identified.
    { 0x0C, "Possible Credited Bill Removal" }, // There has been an attempt to remove a credited (stacked) bill.
    { 0x40, "Disabled validator, number of attempts to input bill" }, // Format: 010xxxxx
/* Bill Recycler (Only) */
    { 0x21, "Escrow request" }, // An escrow lever activation has been detected. If a button is present and activated.
    { 0x22, "Dispenser Payout Busy" }, // The dispenser is busy activating payout devices.
    { 0x23, "Dispenser Busy" }, // The dispenser is busy and can not answer a detailed command right now
    { 0x24, "Defective Dispenser Sensor" }, // The dispenser has detected one of the dispenser sensors behaving abnormally

    { 0x26, "Dispenser did not start / motor problem" },
    { 0x27, "Dispenser Jam" }, // A dispenser payout attempt has resulted in jammed condition.
    { 0x28, "ROM Checksum Error" }, // The dispensers internal checksum does not match the calculated checksum.
                                    // (If separate from validator microprocessor.)
    { 0x29, "Dispenser Disabled" }, // dispenser disabled because of error or bill in escrow position
    { 0x2A, "Bill Waiting" },   // waiting for customer removal
    { 0x2F, "Filled key pressed" }, // The VMC should request a new DISPENSER STATUS
    { 0, NULL }
};

static const value_string mdb_bv_exp_bills_recyc_enabled[] = {
    { 0x00, "Bill type disabled" },
    { 0x01, "Only High quality bills are used" },
    { 0x02, "Only High and Medium quality bills are used" },
    { 0x03, "Use all possible bills" },
    { 0, NULL }
};

static void dissect_mdb_ack(tvbuff_t *tvb, int offset,
        packet_info *pinfo, proto_tree *tree)
{
    uint32_t ack;

    proto_tree_add_item_ret_uint(tree, hf_mdb_ack, tvb, offset, 1, ENC_BIG_ENDIAN, &ack);
    col_set_str(pinfo->cinfo, COL_INFO,
            val_to_str_const(ack, mdb_ack, "Invalid ack byte"));
}

static void mdb_set_addrs(uint8_t event, uint8_t addr, packet_info *pinfo)
{
    const char *periph = val_to_str(pinfo->pool, addr, mdb_addr, "Unknown (0x%02x)");

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

static void mdb_add_checksum(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int total_len)
{
    if (total_len <= 1) return;
    uint8_t calculated_checksum = 0;

    for (int i = 0; i < total_len - 1; i++) {
        uint8_t val = tvb_get_uint8(tvb, offset + i);
        /* The MDB checksum is a simple sum modulo 256. Using uint8_t
         * causes an intentional wrap-around that perfectly matches the modulo.
         */
        calculated_checksum += val;
    }

    proto_tree_add_checksum(tree, tvb, offset + total_len - 1, hf_mdb_chk, hf_mdb_chk_status, &ei_mdb_bad_checksum, pinfo, calculated_checksum, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
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
                pi = proto_tree_add_item_ret_uint(tree, hf_mdb_cl_max_price,
                        tvb, offset, 2, ENC_BIG_ENDIAN, &price);
                if (price == 0xFFFF) {
                    proto_item_append_text(pi, " (unknown)");
                }
                offset += 2;

                pi = proto_tree_add_item_ret_uint(tree, hf_mdb_cl_min_price,
                        tvb, offset, 2, ENC_BIG_ENDIAN, &price);
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
        uint8_t addr_byte, mdb_conv_info_t* conv_info _U_)
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
        int len _U_, packet_info *pinfo, proto_tree *tree, mdb_conv_info_t* conv_info _U_)
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
        uint8_t addr_cmd_byte, mdb_conv_info_t* conv_info _U_)
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
        int len, packet_info *pinfo _U_, proto_tree *tree, mdb_conv_info_t* conv_info _U_)
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

static int dissect_mdb_bv_setup_fields(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    wmem_strbuf_t* bill_str = wmem_strbuf_new(pinfo->pool, "");

    proto_tree_add_item(tree, hf_mdb_bv_setup_bill_val_feature, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdb_bv_setup_ctry_currency_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdb_bv_setup_bill_scal_fac, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdb_bv_setup_dec_places, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdb_bv_setup_bill_stacker_cap, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdb_bv_setup_bill_sec_lvls, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdb_bv_setup_escrow, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    uint8_t bill_val;
    for (int i = 0; i < 16; i++) {
        bill_val = tvb_get_uint8(tvb, offset + i);
        // Append each bill value to comma separated string
        wmem_strbuf_append_printf(bill_str, "%u%s", bill_val, (i < 15) ? "," : "");
    }
    // Add the formatted string to the protocol tree
    proto_tree_add_string_format_value(tree, hf_mdb_bv_setup_bill_type_cred, tvb, offset, 16,
                                        bill_str->str, "Bill values: %s", bill_str->str);
    offset += 16;

    return offset;
}

static int dissect_mdb_bv_poll_stat_bill_accept(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint32_t bill_routing;

    proto_tree_add_item_ret_uint(tree, hf_mdb_bv_poll_bill_routing_state, tvb, offset, 1, ENC_NA, &bill_routing);
    proto_tree_add_item(tree, hf_mdb_bv_poll_bill_type, tvb, offset, 1, ENC_NA);

    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str(pinfo->pool, bill_routing, mdb_bv_poll_bill_routing_state, "Unknown Bill Routing: 0x%x"));

    offset += 1;

    return offset;
}

static int dissect_mdb_bv_poll_fields(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint8_t cmd = tvb_get_uint8(tvb, offset);

    if (cmd & 0x80)
    {
        // Bills Accepted response
        dissect_mdb_bv_poll_stat_bill_accept(tvb, offset, pinfo, tree);
        offset += 1;
    }
    else if (cmd > 0x1A)
    {
        // File transport layer response
        offset += 1;
    }
    else
    {
        proto_tree_add_item(tree, hf_mdb_bv_poll_state, tvb, offset, 1, ENC_BIG_ENDIAN);
        col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(pinfo->pool, cmd, mdb_bv_poll_state, "Unknown Poll Response 0x%x"));
        offset += 1;
    }

    return offset;
}

static int dissect_mdb_bv_bill_type(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_bill_enable, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_mdb_bv_bill_escrow_enable, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int dissect_mdb_bv_escrow(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_escrow_state, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

static int dissect_mdb_bv_stacker(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_stacker, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int dissect_mdb_bv_exp_id_opt_fields(tvbuff_t *tvb, int offset,
proto_tree *tree, bool opt_features)
{
    proto_tree_add_item(tree, hf_mdb_bv_exp_manufact_code, tvb, offset, 3, ENC_ASCII);
    offset += 3;
    proto_tree_add_item(tree, hf_mdb_bv_exp_serial_num, tvb, offset, 12, ENC_ASCII);
    offset += 12;
    proto_tree_add_item(tree, hf_mdb_bv_exp_model_tuning_num, tvb, offset, 12, ENC_ASCII);
    offset += 12;
    proto_tree_add_item(tree, hf_mdb_bv_exp_software_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    // Only for cmd 37 02
    if (opt_features) {
        proto_tree_add_item(tree, hf_mdb_bv_exp_opt_feat, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return offset;
}

static int dissect_mdb_bv_exp_recycler_setup(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_exp_manual_dispense_enable, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int dissect_mdb_bv_exp_recycler_enable(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_exp_bill_type_routing, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for (int i = 0; i < 16; i++) {
        proto_tree_add_item(tree, hf_mdb_bv_exp_bill_recycler_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    return offset;
}

static int dissect_mdb_bv_exp_dispense_status(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_exp_dispenser_full_state, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    for (int i = 0; i < 32; i++) {
        proto_tree_add_item(tree, hf_mdb_bv_exp_bill_count, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    return offset;
}

static int dissect_mdb_bv_exp_dispense_bill(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_exp_bill_type_dispensed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mdb_bv_exp_bill_type_number_bills, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int dissect_mdb_bv_exp_dispense_value_bill(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_exp_dispense_value_bills, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int dissect_mdb_bv_exp_payout_status(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    for (int i = 0; i < 16; i++) {
        proto_tree_add_item(tree, hf_mdb_bv_exp_payout_state, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    return offset;
}

static int dissect_mdb_bv_exp_payout_value_poll(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_mdb_bv_exp_dispenser_payout_activity, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static void dissect_mdb_bv_expns_mst_per(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree)
{
    const char *s;
    uint32_t sub_cmd = tvb_get_uint8(tvb, offset);

    s = try_val_to_str(sub_cmd, mdb_bv_exp_cmd);
    if (s) {
        col_set_str(pinfo->cinfo, COL_INFO, s);
    }

    switch (sub_cmd) {
        case MDB_BV_LVL2_FEATURE_ENABLE:
            proto_tree_add_item(tree, hf_mdb_bv_exp_opt_feat_enable, tvb, offset, 4,
                    ENC_BIG_ENDIAN);
            break;
        case MDB_BV_RECYCL_ENABLE:
            dissect_mdb_bv_exp_recycler_enable(tvb, offset, tree);
            break;
        case MDB_BV_DISPENSE_BILL:
            dissect_mdb_bv_exp_dispense_bill(tvb, offset, tree);
            break;
        case MDB_BV_DISPENSE_VAL:
            dissect_mdb_bv_exp_dispense_value_bill(tvb, offset, tree);
            break;
        case MDB_BV_PAYOUT_CANCEL:
            // Nothing to dissect
            break;
    }
}

static void dissect_mdb_bv_expns_per_mst(tvbuff_t *tvb, int offset, proto_tree *tree, uint16_t cmd)
{
    uint8_t sub_cmd = cmd >> SUB_CMD_OFFSET;

    switch (sub_cmd) {
        case MDB_BV_LVL1_WITHOUT_OPT_BITS:
            dissect_mdb_bv_exp_id_opt_fields(tvb, offset, tree, false);
            break;
        case MDB_BV_LVL2_ID_WITH_OPTION_BITS:
            dissect_mdb_bv_exp_id_opt_fields(tvb, offset, tree, true);
            break;
        case MDB_BV_RECYCL_SETUP:
            dissect_mdb_bv_exp_recycler_setup(tvb, offset, tree);
            break;
        case MDB_BV_BILL_DISPENSE_STAT:
            dissect_mdb_bv_exp_dispense_status(tvb, offset, tree);
            break;
        case MDB_BV_PAYOUT_STAT:
            dissect_mdb_bv_exp_payout_status(tvb, offset, tree);
            break;
        case MDB_BV_PAYOUT_VALUE_POLL:
            dissect_mdb_bv_exp_payout_value_poll(tvb, offset, tree);
            break;
        // FTL Expansion commands not implemented yet
    }
}

static void dissect_mdb_mst_per_bv( tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo, proto_tree *tree, proto_item *cmd_it,
        uint8_t addr_cmd_byte, mdb_conv_info_t* conv_info)
{
    uint8_t cmd = CMD_MASK & addr_cmd_byte; /* the 3-bit command */
    proto_tree *bv_tree;
    mdb_transaction_t* transaction;
    uint8_t sub_cmd = 0;
    const char *s;

    s = val_to_str(pinfo->pool, cmd, mdb_bv_cmd, "Unknown Command: 0x%x");
    proto_item_append_text(cmd_it, " (%s)", s);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s (Request)", s);

    bv_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_bv,
            NULL, "Bill Validator");

    switch (cmd) {
        case MDB_BV_CMD_SETUP:
            break;
        case MDB_BV_CMD_SECURITY:
            break;
        case MDB_BV_CMD_BILL_TYPE:
            dissect_mdb_bv_bill_type(tvb, offset, bv_tree);
            break;
        case MDB_BV_CMD_ESCROW:
            dissect_mdb_bv_escrow(tvb, offset, bv_tree);
            break;
        case MDB_BV_CMD_STACKER:
            break;
        case MDB_BV_CMD_EXPNS:
            sub_cmd = tvb_get_uint8(tvb, offset);
            dissect_mdb_bv_expns_mst_per(tvb, offset, pinfo, bv_tree);
            break;
    }

    if (!pinfo->fd->visited)
    {
        //Create the request information
        transaction = wmem_new0(wmem_file_scope(), mdb_transaction_t);
        transaction->req_num = pinfo->num;
        transaction->req_time = pinfo->abs_ts;

        // If not MDB_BV_CMD_EXPNS, then sub_cmd is just 0
        transaction->cmd = (cmd | (sub_cmd << SUB_CMD_OFFSET));
        wmem_tree_insert32(conv_info->transactions, pinfo->num, (void*)transaction);
        conv_info->last_cmd = transaction->cmd;
        conv_info->last_req_packet = pinfo->num;
    }
    else
    {
        transaction = (mdb_transaction_t*)wmem_tree_lookup32_le(conv_info->transactions, pinfo->num);
    }

    if ((transaction != NULL) && (transaction->rep_num))
    {
        proto_item* it = proto_tree_add_uint(tree, hf_mdb_response_in, NULL, 0, 0, transaction->rep_num);
        proto_item_set_generated(it);

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
    int start_offset = offset;

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
    addr = addr_byte & ADDR_MASK;
    proto_tree_add_uint_bits_format_value(tree, hf_mdb_addr,
            tvb, 8*offset, 5, addr, ENC_BIG_ENDIAN, "0x%02x", addr);
    cmd_it = proto_tree_add_uint(tree, hf_mdb_cmd, tvb, offset, 1, addr_byte & CMD_MASK);
    mdb_set_addrs(MDB_EVT_DATA_MST_PER, addr, pinfo);
    mdb_conv_info_t* conv_info = get_mdb_conv_info(pinfo);
    offset++;

    /*
     * We call the peripheral functions even if data_len == 0 so they can fix
     * up the command with peripheral-specific info.
     */
    switch (addr) {
        case ADDR_CASHLESS1:
            dissect_mdb_mst_per_cl(tvb, offset, data_len, pinfo, tree,
                    cmd_it, addr_byte, conv_info);
            break;
        case ADDR_COMMS_GW:
            dissect_mdb_mst_per_cgw(tvb, offset, data_len, pinfo, tree,
                    cmd_it, addr_byte, conv_info);
            break;
        case ADDR_BILL_VALIDATOR:
            dissect_mdb_mst_per_bv(tvb, offset, data_len, pinfo, tree,
                    cmd_it, addr_byte, conv_info);
            break;
        default:
            if (data_len > 0) {
                proto_tree_add_item(tree, hf_mdb_data,
                        tvb, offset, data_len, ENC_NA);
            }
            break;
    }
    offset += data_len;

    /* Verify the checksum */
    mdb_add_checksum(tvb, pinfo, tree, start_offset, data_len + 2);
}

static void dissect_mdb_per_mst_bv( tvbuff_t *tvb, int offset,
        int len, packet_info *pinfo _U_, proto_tree *tree, mdb_conv_info_t* conv_info)
{
    proto_tree *bv_tree;
    mdb_transaction_t* transaction;

    if (!pinfo->fd->visited)
    {
        transaction = (mdb_transaction_t*)wmem_tree_lookup32_le(conv_info->transactions, conv_info->last_req_packet);
        if (transaction)
        {
            transaction->rep_num = pinfo->num;
        }
        else
        {
            transaction = wmem_new0(wmem_file_scope(), mdb_transaction_t);
            transaction->rep_num = pinfo->num;
        }
        wmem_tree_insert32(conv_info->transactions, pinfo->num, (void*)transaction);
    }
    else
    {
        transaction = (mdb_transaction_t*)wmem_tree_lookup32_le(conv_info->transactions, pinfo->num);
    }

    //Sanity check
    if (transaction == NULL)
        return;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s (Response)",
        val_to_str(pinfo->pool, transaction->cmd & CMD_MASK, mdb_bv_cmd, "Unknown Command: 0x%x"));

    switch (transaction->cmd & CMD_MASK) {
        case MDB_BV_CMD_SETUP:
            bv_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_bv, NULL, "Setup Response");
            dissect_mdb_bv_setup_fields(tvb, offset, pinfo, bv_tree);
            break;
        case MDB_BV_CMD_SECURITY:
            /* bv_tree = */ proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_bv, NULL, "Security Response");
            break;
        case MDB_BV_CMD_POLL:
            bv_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_bv, NULL, "Poll Response");
            dissect_mdb_bv_poll_fields(tvb, offset, pinfo, bv_tree);
            break;
        case MDB_BV_CMD_BILL_TYPE:
            break;
        case MDB_BV_CMD_ESCROW:
            break;
        case MDB_BV_CMD_STACKER:
            bv_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_bv, NULL, "Stacker Response");
            dissect_mdb_bv_stacker(tvb, offset, bv_tree);
            break;
        case MDB_BV_CMD_EXPNS:
            bv_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_mdb_bv, NULL, "Expansion Feature Response");
            dissect_mdb_bv_expns_per_mst(tvb, offset, bv_tree, transaction->cmd);
            break;
    }

    // This is a reply
    if (transaction->req_num)
    {
        proto_item* it;
        nstime_t    ns;

        it = proto_tree_add_uint(tree, hf_mdb_response_to, NULL, 0, 0, transaction->req_num);
        proto_item_set_generated(it);

        nstime_delta(&ns, &pinfo->abs_ts, &transaction->req_time);
        it = proto_tree_add_time(tree, hf_mdb_time, NULL, 0, 0, &ns);
        proto_item_set_generated(it);
    }

}

/*
 * Peripheral-to-Master messages can be simple control replies (ACK, NAK, RET)
 * that do not include a checksum. Master-to-Peripheral commands always
 * require a checksum, which is why this check is only needed for
 * Peripheral-to-Master events.
 */
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

    col_set_str(pinfo->cinfo,
           COL_INFO, val_to_str_const(addr, mdb_addr, "Unknown"));

    mdb_conv_info_t* conv_info = get_mdb_conv_info(pinfo);

    data_len = per_mst_len - 1;
    int start_offset = offset;

    /*
     * Peripheral-to-Master messages can be simple control replies (ACK, NAK, RET)
     * that do not include a checksum.
     */
    bool checksum_needed = true;
    if (data_len == 1 && is_mdb_reply(tvb_get_uint8(tvb, offset))) {
        checksum_needed = false;
    }


    switch (addr) {
        case ADDR_CASHLESS1:
            dissect_mdb_per_mst_cl(tvb, offset, data_len, pinfo, tree, conv_info);
            break;
        case ADDR_COMMS_GW:
            dissect_mdb_per_mst_cgw(tvb, offset, data_len, pinfo, tree, conv_info);
            break;
        case ADDR_BILL_VALIDATOR:
            dissect_mdb_per_mst_bv(tvb, offset, data_len, pinfo, tree, conv_info);
            break;
        default:
            proto_tree_add_item(tree, hf_mdb_data, tvb, offset, data_len, ENC_NA);
            break;
    }
    offset += data_len;

    if (checksum_needed) {
        mdb_add_checksum(tvb, pinfo, tree, start_offset, data_len + 1);
    }
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

    tree_ti = proto_tree_add_item(tree, proto_mdb, tvb, 0, -1, ENC_NA);
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
        addr = tvb_get_uint8(tvb, offset) & ADDR_MASK;
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
        &ett_mdb_cgw,
        &ett_mdb_bv
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
        { &hf_mdb_bv_setup_bill_val_feature,
            { "Bill Validator Feature Level", "mdb.bv.setup.feature_level",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_setup_ctry_currency_code,
            { "Country/Currency Code", "mdb.bv.setup.ctry_currency",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_setup_bill_scal_fac,
            { "Bill scaling factor", "mdb.bv.setup.bill_scale_factor",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_setup_dec_places,
            { "Decimal Places", "mdb.bv.setup.dec_places",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_setup_bill_stacker_cap,
            { "Stacker Capacity", "mdb.bv.setup.stacker_cap",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_setup_bill_sec_lvls,
            { "Security Levels", "mdb.bv.setup.sec_levels",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_setup_escrow,
            { "Escrow capability", "mdb.bv.setup.escrow",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_setup_bill_type_cred,
            { "Bill Type Credit", "mdb.bv.setup.bill_type_credit",
                FT_STRING, BASE_NONE, NULL, 0, "Bill values per channel", HFILL }
        },
        { &hf_mdb_bv_bill_enable,
            { "Bill Enable State", "mdb.bv.bill_type.enable",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_bill_escrow_enable,
            { "Bill Escrow Enable State", "mdb.bv.bill_type.escrow_enable",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_poll_bill_routing_state,
            { "Escrow", "mdb.bv.poll.routing_state",
                FT_UINT8, BASE_HEX, VALS(mdb_bv_poll_bill_routing_state), 0x70, NULL, HFILL }
        },
        { &hf_mdb_bv_poll_bill_type,
            { "Bill Type", "mdb.bv.poll.bill_type",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_mdb_bv_poll_state,
            { "Bill Accept State", "mdb.bv.poll.state",
                FT_UINT8, BASE_HEX, VALS(mdb_bv_poll_state), 0, NULL, HFILL }
        },
        { &hf_mdb_bv_escrow_state,
            { "Escrow", "mdb.bv.escrow.state",
                FT_BOOLEAN, 8, TFS(&mdb_bv_escrow_state), 0x01, NULL, HFILL }
        },
        { &hf_mdb_bv_stacker,
            { "Stacker Full", "mdb.bv.stacker.full_state",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_exp_cmd,
            { "Expansion Command", "mdb.bv.exp.cmd", FT_UINT8,
                BASE_HEX, VALS(mdb_bv_exp_cmd), 0, NULL, HFILL }
        },
        // EXPANSION cmd: Level 1/2 Identification with/Without Option bits
        { &hf_mdb_bv_exp_opt_feat,
            { "Bill Type Routing", "mdb.bv.exp.bill_type_routing",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_exp_manufact_code,
            { "Manufacturer Code", "mdb.bv.expns.manufact_code",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_exp_serial_num,
            { "Serial Number", "mdb.bv.expns.serial_num",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_exp_model_tuning_num,
            { "Model/Tuning number", "mdb.bv.expns.model_tuning_num",
                FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_exp_software_version,
            { "Software version", "mdb.bv.expns.software_version",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        // EXPANSION cmd: Lvl2 Feature enable
        { &hf_mdb_bv_exp_opt_feat_enable,
            { "Level 2+ Feature enable", "mdb.bv.exp.opt_feat",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        // EXPANSION cmd: Recycler Setup
        { &hf_mdb_bv_exp_bill_type_routing,
            { "Bill Type Routing", "mdb.bv.exp.bill_type_routing",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        // EXPANSION cmd: Recycler Enable
        { &hf_mdb_bv_exp_manual_dispense_enable,
            { "Manual Dispense Enable", "mdb.bv.exp.manual_dispense_enable",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_exp_bill_recycler_enabled,
            { "Bill Recycler Enabled", "mdb.bv.exp.bill_recycler_enabled",
                FT_UINT8, BASE_HEX, VALS(mdb_bv_exp_bills_recyc_enabled), 0, NULL, HFILL }
        },
        // EXPANSION cmd: Bill Dispense Status
        { &hf_mdb_bv_exp_dispenser_full_state,
            { "Dispenser Full Status", "mdb.bv.exp.dispenser_full_state",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_exp_bill_count,
            { "Bill count", "mdb.bv.exp.bill_count",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        // EXPANSION cmd: Dispense Bill
        { &hf_mdb_bv_exp_bill_type_dispensed,
            { "Bill type to be dispensed", "mdb.bv.exp.bill_type_disp",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_mdb_bv_exp_bill_type_number_bills,
            { "Bills type number of bills", "mdb.bv.exp.bill_type_num_bills",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        // EXPANSION cmd: Dispense Value
        { &hf_mdb_bv_exp_dispense_value_bills,
            { "Bill value to be paid out", "mdb.bv.exp.dispense_value_bills",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        // EXPANSION cmd: Payout Status
        { &hf_mdb_bv_exp_payout_state,
            { "Number of bills paid out", "mdb.bv.exp.payout_state_num_bills",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        // EXPANSION cmd: Payout Value Poll
        { &hf_mdb_bv_exp_dispenser_payout_activity,
            { "Dispenser Payout Activity", "mdb.bv.exp.payout_value_activity",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        // EXPANSION cmd: Payout Cancel
        // No data
        // EXPANSION cmd: FTL REQ to RCV
        // EXPANSION cmd: FTL Send Block
        // EXPANSION cmd: FTL OK to Send
        // EXPANSION cmd: FTL REQ to Send
        // EXPANSION cmd: Diagnostics
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
        },
        { &hf_mdb_chk_status,
            { "Checksum Status", "mdb.chk.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_mdb_response_in,
            { "Response In", "mdb.response_in",
                FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
                "The response to this request is in this frame", HFILL }
        },
        { &hf_mdb_response_to,
            { "Request In", "mdb.response_to",
                FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
                "This is a response to the request in this frame", HFILL }
        },
        { &hf_mdb_time,
            { "Time", "mdb.time",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                "The time between the Call and the Reply", HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_mdb_short_packet,
            { "mdb.short_packet", PI_PROTOCOL, PI_ERROR,
                "MDB packet without payload", EXPFILL }},
        { &ei_mdb_bad_checksum,
            { "mdb.bad_checksum", PI_CHECKSUM, PI_ERROR,
                "Bad checksum", EXPFILL }}
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
