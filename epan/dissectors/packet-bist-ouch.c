/* packet-bist-ouch.c
 * Routines for BIST-OUCH dissection
 * Copyright 2025, Sadettin Er <sadettin.er@b-ulltech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
// -----------------------------------------------------------------------------
//
//  Documentation:
//  https://www.borsaistanbul.com/files/OUCH_ProtSpec_BIST_va2413.pdf

#include "config.h"
#include <wireshark.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/column-utils.h>

#define PNAME  "BIST OUCH"
#define PSHORT "BIST-OUCH"
#define PFILT  "bist_ouch"

static bool bist_ouch_show_decimal_price = false;
static dissector_handle_t bist_ouch_handle;

static const value_string ouch_msg_types[] = {
    { 'O', "Enter Order" }, /* inbound */
    { 'U', "Replace/Order Replaced" }, /* inbound/outbound */
    { 'X', "Cancel Order" }, /* inbound */
    { 'Y', "Cancel by Order ID" }, /* inbound */
    { 'Q', "Mass Quote" }, /* inbound */
    { 'A', "Order Accepted" }, /* outbound */
    { 'J', "Order Rejected" }, /* outbound */
    { 'C', "Order Canceled" }, /* outbound */
    { 'E', "Order Executed" }, /* outbound */
    { 'K', "Mass Quote Ack" }, /* outbound */
    { 'R', "Mass Quote Rejection" }, /* outbound */
    {  0, NULL }
};

static const value_string ouch_side_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 'T', "Short" },
    { 0, NULL }
};

static const value_string ouch_tif_vals[] = {
    { 0, "Day" },
    { 3, "IOC" },
    { 4, "FOK" },
    { 0, NULL }
};

static const value_string ouch_openclose_vals[] = {
    { 0, "Default/No change" },
    { 1, "Open"  },
    { 2, "Close/Net" },
    { 4, "Default for account" },
    { 0, NULL }
};

static const value_string ouch_client_cat_vals[] = {
    { 1,  "Client" },
    { 2,  "House" },
    { 7,  "Fund" },
    { 9,  "Investment Trust" },
    { 10, "Primary Dealer Govt" },
    { 11, "Primary Dealer Corp" },
    { 12, "Portfolio Mgmt Company" },
    { 0,  NULL }
};

static const value_string ouch_cancel_reason_vals[] = {
    { 1,  "Canceled by user/other user" },
    { 3,  "Trade" },
    { 4,  "Inactivate" },
    { 5,  "Replaced by User" },
    { 6,  "New" },
    { 8,  "Converted by System" },
    { 9,  "Canceled by System" },
    { 10, "Canceled by Proxy" },
    { 11, "Bait Recalculated" },
    { 12, "Triggered by System" },
    { 13, "Refreshed by System" },
    { 15, "Canceled by System Limit Change" },
    { 17, "Linked Leg Canceled" },
    { 18, "Linked Leg Modified" },
    { 19, "Expired" },
    { 20, "Canceled Due to ISS" },
    { 21, "Inactivated Due to ISS" },
    { 23, "Inactivated Due to Purge" },
    { 24, "Inactivated Day Order" },
    { 25, "Inactivated Due to DeList" },
    { 26, "Inactivated Due to Expiry" },
    { 27, "Inactivated Due to Outside Limits" },
    { 28, "Transfer of Ownership" },
    { 29, "New Inactive" },
    { 30, "Reloaded" },
    { 31, "Reloaded Intraday" },
    { 34, "Canceled After Auction" },
    { 35, "Inactivated Due to Outside Price Limits" },
    { 36, "Activated Due to Outside Limits" },
    { 37, "Trigger on Session Order Triggered" },
    { 39, "Undisclosed Qty Order Converted" },
    { 40, "Inactivated Due to Order Value" },
    { 41, "System Delta Protection" },
    { 42, "System Quantity Protection" },
    { 43, "Internal Crossing Delete" },
    { 44, "Participant Block on Market" },
    { 45, "Inactivated Due to Participant Block" },
    { 46, "Order deleted due to SMP" },
    { 52, "Paused" },
    { 53, "Activated Paused Order" },
    { 56, "Linked Leg Activated" },
    { 115, "PTRM misc" },
    { 116, "PTRM user limits auto" },
    { 117, "PTRM user limits manual" },
    { 118, "PTRM market limits" },
    { 119, "PTRM investor limits" },
    { 120, "PTRM margin breach" },
    { 121, "PTRM participant suspension" },
    { 122, "PTRM mra suspension" },
    { 123, "PTRM mca suspension" },
    { 124, "PTRM ta suspension" },
    { 125, "Canceled: Investor Position Value Limit" },
    { 0,   NULL }
};

static const value_string ouch_quote_status_vals[] = {
    { 0, "Accept" },
    { 1, "Updated" },
    { 2, "Canceled" },
    { 3, "Unsolicited update" },
    { 4, "Unsolicited cancel" },
    { 5, "Traded" },
    { 0, NULL }
};

static int proto_bist_ouch;
static int ett_bist_ouch;
static int ett_bist_ouch_quote;

static int hf_ouch_msg_type;
static int hf_ouch_timestamp_ns;
static int hf_ouch_order_token;
static int hf_ouch_prev_order_token;
static int hf_ouch_repl_order_token;
static int hf_ouch_orderbook_id;
static int hf_ouch_side;
static int hf_ouch_order_id;
static int hf_ouch_quantity;
static int hf_ouch_price_int;
static int hf_ouch_price_double;
static int hf_ouch_tif;
static int hf_ouch_openclose;
static int hf_ouch_client_account;
static int hf_ouch_customer_info;
static int hf_ouch_exchange_info;
static int hf_ouch_display_qty;
static int hf_ouch_client_category;
static int hf_ouch_offhours;
static int hf_ouch_smp_level;
static int hf_ouch_smp_method;
static int hf_ouch_smp_id;
static int hf_ouch_reject_code;
static int hf_ouch_order_state;
static int hf_ouch_pretrade_qty;
static int hf_ouch_reserved;
static int hf_ouch_no_quote_entries;
static int hf_ouch_q_entry_orderbook_id;
static int hf_ouch_q_entry_bid_px_int;
static int hf_ouch_q_entry_offer_px_int;
static int hf_ouch_q_entry_bid_sz;
static int hf_ouch_q_entry_offer_sz;
static int hf_ouch_quote_side;
static int hf_ouch_quote_status;
static int hf_ouch_cancel_reason;
static int hf_ouch_raw;
static int hf_ouch_match_id;
static int hf_ouch_traded_qty;

static int add_price(proto_tree *tree, int hf_int, int hf_double, tvbuff_t *tvb, int offset)
{
    int32_t raw = (int32_t)tvb_get_ntohl(tvb, offset);
    if (bist_ouch_show_decimal_price) {
        double val = ((double)raw) / 10000.0;
        proto_tree_add_double(tree, hf_double, tvb, offset, 4, val);
    } else {
        proto_tree_add_int(tree, hf_int, tvb, offset, 4, raw);
    }
    return offset + 4;
}

static int dissect_u_replace_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt, int offset)
{
    proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII);      offset += 14; /* existing token */
    proto_tree_add_item(pt, hf_ouch_repl_order_token, tvb, offset, 14, ENC_ASCII);      offset += 14;
    proto_tree_add_item(pt, hf_ouch_quantity, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
    proto_tree_add_item(pt, hf_ouch_openclose, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(pt, hf_ouch_client_account, tvb, offset, 16, ENC_ASCII);      offset += 16;
    proto_tree_add_item(pt, hf_ouch_customer_info, tvb, offset, 15, ENC_ASCII);      offset += 15;
    proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 32, ENC_ASCII);      offset += 32;
    proto_tree_add_item(pt, hf_ouch_display_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(pt, hf_ouch_reserved, tvb, offset,  8, ENC_NA);         offset += 8;
    col_append_str(pinfo->cinfo, COL_INFO, ", Replace Order");
    return offset;
}

static int dissect_u_order_replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt, int offset)
{
    proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    proto_tree_add_item(pt, hf_ouch_repl_order_token, tvb, offset, 14, ENC_ASCII);      offset += 14;
    proto_tree_add_item(pt, hf_ouch_prev_order_token, tvb, offset, 14, ENC_ASCII);      offset += 14;
    proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset,  4, ENC_BIG_ENDIAN); offset += 4;
    proto_tree_add_item(pt, hf_ouch_side, tvb, offset,  1, ENC_BIG_ENDIAN);      offset += 1;
    proto_tree_add_item(pt, hf_ouch_order_id, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    proto_tree_add_item(pt, hf_ouch_quantity, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
    proto_tree_add_item(pt, hf_ouch_tif, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(pt, hf_ouch_openclose, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(pt, hf_ouch_client_account, tvb, offset, 16, ENC_ASCII);      offset += 16;
    proto_tree_add_item(pt, hf_ouch_order_state, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(pt, hf_ouch_customer_info, tvb, offset, 15, ENC_ASCII);      offset += 15;
    proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 32, ENC_ASCII);      offset += 32;
    proto_tree_add_item(pt, hf_ouch_pretrade_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    proto_tree_add_item(pt, hf_ouch_display_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    col_append_str(pinfo->cinfo, COL_INFO, ", Order Replaced");
    return offset;
}

static int dissect_bist_ouch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    uint32_t type;
    char* str_type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSHORT);

    proto_item* ti = proto_tree_add_item(tree, proto_bist_ouch, tvb, 0, -1, ENC_NA);
    proto_tree *pt = proto_item_add_subtree(ti, ett_bist_ouch);

    proto_tree_add_item_ret_uint(pt, hf_ouch_msg_type, tvb, 0, 1, ENC_NA, &type);
    str_type = val_to_str(pinfo->pool, type, ouch_msg_types, "Unknown (0x%02x)");
    proto_item_append_text(ti, ", %s", str_type);
    col_set_str(pinfo->cinfo, COL_INFO, str_type);
    offset = 1;

    switch (type) {

    case 'O': { /* Enter Order */
        uint64_t qty = 0;

        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;

        proto_tree_add_item_ret_uint64(pt, hf_ouch_quantity, tvb, offset, 8, ENC_BIG_ENDIAN, &qty);
        offset += 8;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Qty=%" PRIu64, (uint64_t)qty);

        offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
        proto_tree_add_item(pt, hf_ouch_tif, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_openclose, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_client_account, tvb, offset, 16, ENC_ASCII); offset += 16;
        proto_tree_add_item(pt, hf_ouch_customer_info, tvb, offset, 15, ENC_ASCII); offset += 15;
        proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 32, ENC_ASCII); offset += 32;
        proto_tree_add_item(pt, hf_ouch_display_qty, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_offhours, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_level, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_method, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_id, tvb, offset, 3, ENC_ASCII); offset += 3;
        if (tvb_captured_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(pt, hf_ouch_reserved, tvb, offset, 2, ENC_NA); offset += 2;
        }
        break;
    }
    case 'U': { /* Replace Order vs  Order Replaced */
        const int mlen = tvb_reported_length(tvb);
        if (mlen >= 145) {
            offset = dissect_u_order_replaced(tvb, pinfo, pt, offset);
        } else if (mlen == 122) {
            offset = dissect_u_replace_order(tvb, pinfo, pt, offset);
        } else {
            if (tvb_captured_length_remaining(tvb, 1) >= 8) {
                uint64_t ts = tvb_get_ntoh64(tvb, 1);
                if (ts > 1000000000000000000ULL) {
                    offset = dissect_u_order_replaced(tvb, pinfo, pt, offset);
                    break;
                }
            }
            offset = dissect_u_replace_order(tvb, pinfo, pt, offset);
        }
        break;
    }
    case 'X': { /* Cancel Order */
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        break;
    }
    case 'Y': { /* Cancel by Order ID */
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_order_id, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        break;
    }
    case 'Q': { /* Mass Quote */
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_client_account, tvb, offset, 16, ENC_ASCII); offset += 16;
        proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 16, ENC_ASCII); offset += 16;
        if (tvb_captured_length_remaining(tvb, offset) < 2) break;
        uint16_t num_entries = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(pt, hf_ouch_no_quote_entries, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Entries=%u", num_entries);
        for (unsigned i = 0; i < num_entries && tvb_captured_length_remaining(tvb, offset) >= 28; i++) {
            proto_item *entry_item = proto_tree_add_item(pt, hf_ouch_raw, tvb, offset, 28, ENC_NA);
            proto_item_set_text(entry_item, "Quote Entry %u", i+1);
            proto_tree *entry_tree = proto_item_add_subtree(entry_item, ett_bist_ouch_quote);
            proto_tree_add_item(entry_tree, hf_ouch_q_entry_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            offset = add_price(entry_tree, hf_ouch_q_entry_bid_px_int, hf_ouch_price_double, tvb, offset);
            offset = add_price(entry_tree, hf_ouch_q_entry_offer_px_int, hf_ouch_price_double, tvb, offset);
            proto_tree_add_item(entry_tree, hf_ouch_q_entry_bid_sz, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
            proto_tree_add_item(entry_tree, hf_ouch_q_entry_offer_sz, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        }
        break;
    }
    case 'A': { /* Order Accepted */
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset,  4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_order_id, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_quantity, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
        proto_tree_add_item(pt, hf_ouch_tif, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_openclose, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_client_account,tvb, offset, 16, ENC_ASCII); offset += 16;
        proto_tree_add_item(pt, hf_ouch_order_state, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_customer_info, tvb, offset, 15, ENC_ASCII); offset += 15;
        proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 32, ENC_ASCII); offset += 32;
        proto_tree_add_item(pt, hf_ouch_pretrade_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_display_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_offhours, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_level, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_method, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_id, tvb, offset,  3, ENC_ASCII); offset += 3;
        break;
    }
    case 'J': { /* Order Rejected */
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset,14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_reject_code, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        break;
    }
    case 'C': { /* Order Canceled */
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset,14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_order_id, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_cancel_reason, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        break;
    }
    case 'E': { /* Order Executed */
        uint64_t traded_qty = 0;

        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;

        proto_tree_add_item_ret_uint64(pt, hf_ouch_quantity, tvb, offset, 8, ENC_BIG_ENDIAN, &traded_qty);
        offset += 8;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", TradedQty=%" PRIu64, (uint64_t)traded_qty);
        offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
        proto_tree_add_item(pt, hf_ouch_match_id, tvb, offset, 12, ENC_NA); offset += 12;
        proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_reserved, tvb, offset, 16, ENC_NA); offset += 16;
        break;
    }
    case 'K': { /* Mass Quote Ack */
        uint64_t qty = 0, traded_qty = 0;
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_q_entry_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item_ret_uint64(pt, hf_ouch_quantity, tvb, offset, 8, ENC_BIG_ENDIAN, &qty); offset += 8;
        proto_tree_add_item_ret_uint64(pt, hf_ouch_traded_qty, tvb, offset, 8, ENC_BIG_ENDIAN, &traded_qty); offset += 8;
        offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_quote_status, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Qty=%" PRIu64 ", Traded=%" PRIu64, (uint64_t)qty, (uint64_t)traded_qty);
        break;
    }

    case 'R': { /* Mass Quote Rejection */
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token,  tvb, offset,14, ENC_ASCII); offset += 14;
        if (tvb_captured_length_remaining(tvb, offset) >= 4) {
            proto_tree_add_item(pt, hf_ouch_q_entry_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        }
        if (tvb_captured_length_remaining(tvb, offset) >= 4) {
            proto_tree_add_item(pt, hf_ouch_reject_code, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        }
        if (tvb_captured_length_remaining(tvb, offset) > 0) {
            int rem = tvb_captured_length_remaining(tvb, offset);
            proto_tree_add_item(pt, hf_ouch_raw, tvb, offset, rem, ENC_NA); offset += rem;
        }
        break;
    }
    default: {
        int rem = tvb_captured_length_remaining(tvb, offset);
        if (rem > 0) proto_tree_add_item(pt, hf_ouch_raw, tvb, offset, rem, ENC_NA);
        break;
    }
    }

    int rem = tvb_captured_length_remaining(tvb, offset);
    if (rem > 0) proto_tree_add_item(pt, hf_ouch_raw, tvb, offset, rem, ENC_NA);
    return tvb_captured_length(tvb);
}

static bool dissect_bist_ouch_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (tvb_captured_length(tvb) < 1)
        return false;

    uint8_t msg_type = tvb_get_uint8(tvb, 0);
    /* It would make sense to sanity-check the tvb length against the expected
     length for this msg_type (as done in packet-ouch.c) before claiming the
     packet, to reduce false positives. Also, several OUCH msg_type values
     are shared with other OUCH dialects, so keep the heuristic conservative.
    */
    int idx = -1;
    const char *s = try_val_to_str_idx(msg_type, ouch_msg_types, &idx);
    if (s != NULL) {
        dissect_bist_ouch(tvb, pinfo, tree, NULL);
        return true;
    }
    return false;
}


void proto_register_bist_ouch(void)
{
    static hf_register_info hf[] = {
        { &hf_ouch_msg_type,        { "Message Type", "bist_ouch.msg_type", FT_UINT8, BASE_HEX, VALS(ouch_msg_types), 0x0, NULL, HFILL }},
        { &hf_ouch_timestamp_ns,    { "Timestamp (ns)", "bist_ouch.timestamp_ns", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_order_token,     { "Order Token", "bist_ouch.order_token", FT_STRING, BASE_NONE, NULL, 0x0, "Order/Quote token", HFILL }},
        { &hf_ouch_prev_order_token,{ "Previous Order Token", "bist_ouch.prev_order_token", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_repl_order_token,{ "Replacement Order Token", "bist_ouch.repl_order_token", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_orderbook_id,    { "Order Book ID", "bist_ouch.orderbook_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_side,            { "Side", "bist_ouch.side", FT_UINT8, BASE_HEX, VALS(ouch_side_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_order_id,        { "Order ID", "bist_ouch.order_id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_quantity,        { "Quantity", "bist_ouch.quantity", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_price_int,       { "Price (int)", "bist_ouch.price.int", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_price_double,    { "Price", "bist_ouch.price", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_tif,             { "Time In Force", "bist_ouch.tif", FT_UINT8, BASE_DEC, VALS(ouch_tif_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_openclose,       { "Open/Close", "bist_ouch.openclose", FT_UINT8, BASE_DEC, VALS(ouch_openclose_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_client_account,  { "Client/Account", "bist_ouch.client_account", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_customer_info,   { "Customer Info", "bist_ouch.customer_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_exchange_info,   { "Exchange Info", "bist_ouch.exchange_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_display_qty,     { "Display Quantity", "bist_ouch.display_qty", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_client_category, { "Client Category", "bist_ouch.client_category", FT_UINT8, BASE_DEC, VALS(ouch_client_cat_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_offhours,        { "OffHours", "bist_ouch.offhours", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_smp_level,       { "SMP Level", "bist_ouch.smp_level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_smp_method,      { "SMP Method", "bist_ouch.smp_method", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_smp_id,          { "SMP ID", "bist_ouch.smp_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_reject_code,     { "Reject Code", "bist_ouch.reject_code", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_order_state,     { "Order State", "bist_ouch.order_state", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_pretrade_qty,    { "Pre-Trade Qty", "bist_ouch.qty2", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_no_quote_entries,{ "NoQuoteEntries", "bist_ouch.mq.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_orderbook_id, { "Quote OrderBookID", "bist_ouch.mq.ob", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_bid_px_int,   { "Bid Px (int)", "bist_ouch.mq.bid_px.int", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_offer_px_int, { "Offer Px (int)", "bist_ouch.mq.offer_px.int", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_bid_sz,       { "Bid Size", "bist_ouch.mq.bid_sz", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_offer_sz,     { "Offer Size", "bist_ouch.mq.offer_sz", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_quote_side,           { "Quote Side", "bist_ouch.mq.side", FT_UINT8, BASE_HEX, VALS(ouch_side_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_quote_status,         { "Quote Status", "bist_ouch.mq.status", FT_UINT32, BASE_DEC, VALS(ouch_quote_status_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_cancel_reason,        { "Cancel Reason", "bist_ouch.cancel_reason", FT_UINT8, BASE_DEC, VALS(ouch_cancel_reason_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_raw,                  { "Raw", "bist_ouch.raw", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_reserved,             { "Reserved", "bist_ouch.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_match_id, { "Match ID", "bist_ouch.match_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_traded_qty,{ "Traded Quantity", "bist_ouch.traded_qty", FT_UINT64, BASE_DEC, NULL, 0x0, "Total traded quantity for this order", HFILL }},
    };

    static int *ett[] = { &ett_bist_ouch, &ett_bist_ouch_quote };

    proto_bist_ouch = proto_register_protocol(PNAME, PSHORT, PFILT);
    proto_register_field_array(proto_bist_ouch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module_t *pref = prefs_register_protocol(proto_bist_ouch, NULL);
    prefs_register_bool_preference(pref, "show_decimal_price",
        "Show Prices as Decimals (/10000)",
        "If enabled, 4-byte signed price fields are divided by 10000 and shown as doubles.",
        &bist_ouch_show_decimal_price);

    bist_ouch_handle = register_dissector("bist-ouch", dissect_bist_ouch, proto_bist_ouch);
}

void proto_reg_handoff_bist_ouch(void)
{
    heur_dissector_add("soupbintcp", dissect_bist_ouch_heur, "BIST OUCH over SoupBinTCP", "bist_ouch_soupbintcp", proto_bist_ouch, HEURISTIC_ENABLE);
}
