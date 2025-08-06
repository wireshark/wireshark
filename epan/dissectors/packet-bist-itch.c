/* packet-bist-itch.c
 * Routines for BIST-ITCH dissection
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
//  https://www.borsaistanbul.com/files/bistech-itch-protocol-specification.pdf

#include "config.h"

#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/column-utils.h>
#include <wsutil/to_str.h>
#include <wsutil/type_util.h>
#include <wsutil/wmem/wmem.h>

static bool bist_show_bigint_price = false;
static dissector_handle_t bist_handle;

static const value_string message_types_val[] = {
    { 'A', "Add Order"                 },
    { 'Z', "Equilibrium Price"         },
    { 'M', "Combo Leg"                 },
    { 'E', "Order Executed"            },
    { 'T', "Second"                    },
    { 'P', "Trade"                     },
    { 'C', "Order Executed w/ Price"   },
    { 'D', "Order Delete"              },
    { 'S', "System Event"              },
    { 'R', "Order Book Directory"      },
    { 'Y', "Order Book Flush"          },
    { 'V', "Short Sell Status"         },
    { 'O', "Order Book State"          },
    { 'L', "Tick Size"                 },
    { 0,     NULL                       }
};

static const value_string bist_itch_side_vals[] = {
    { 'B', "Buy"  },
    { 'S', "Sell" },
    { 0,    NULL   }
};

static const value_string bist_itch_event_vals[] = {
    { 'O', "Start of Messages" },
    { 'C', "End of Messages"   },
    { 0,    NULL               }
};


static int hf_bist_message;
static int hf_bist_version;
static int hf_bist_message_type;
static int hf_bist_nanosecond;
static int hf_bist_second;
static int hf_bist_orderbook_id;
static int hf_bist_order_id;
static int hf_bist_side;
static int hf_bist_quantity;
static int hf_bist_price;
static int hf_bist_match_id;
static int hf_bist_combo_group;
static int hf_bist_printable;
static int hf_bist_occurred_cross;
static int hf_bist_event_code;
static int hf_bist_symbol;
static int hf_bist_isin;
static int hf_bist_financial_product;
static int hf_bist_trading_currency;
static int hf_bist_tick_size;
static int hf_bist_price_from;
static int hf_bist_price_to;
static int hf_bist_leg_order_book;
static int hf_bist_leg_side;
static int hf_bist_leg_ratio;
static int hf_bist_short_sell_status;
static int hf_bist_state_name;
static int hf_bist_bid_qty;
static int hf_bist_ask_qty;
static int hf_bist_best_bid_price;
static int hf_bist_best_ask_price;
static int hf_bist_best_bid_qty;
static int hf_bist_ranking_seq;
static int hf_bist_ranking_time;
static int hf_bist_order_attributes;
static int hf_bist_lot_type;
static int hf_bist_long_name;
static int hf_bist_price_decimals;
static int hf_bist_nominal_decimals;
static int hf_bist_odd_lot_size;
static int hf_bist_round_lot_size;
static int hf_bist_block_lot_size;
static int hf_bist_nominal_value;
static int hf_bist_number_of_leg;
static int hf_bist_underlying_orderbook_id;
static int hf_bist_strike_price;
static int hf_bist_expiration_date;
static int hf_bist_strike_price_decimals;
static int hf_bist_put_or_call;
static int hf_bist_ranking_type;
static int hf_bist_combo_orderbook_id;
static int hf_bist_eq_bid_qty;
static int hf_bist_eq_ask_qty;
static int hf_bist_reserved1;
static int hf_bist_reserved2;
static int hf_bist_unexpected;

static int  proto_bist;
static int ett_bist_itch;

static int add_price(proto_tree *tree, int hf_id, tvbuff_t *tvb, int offset)
{
    uint32_t raw = tvb_get_ntohl(tvb, offset);
    double val = bist_show_bigint_price ? raw / 10000.0 : (double)raw;
    proto_tree_add_double(tree, hf_id, tvb, offset, 4, val);
    return offset + 4;
}

static int dissect_timestamp(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_bist_nanosecond, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset + 4;
}

static int dissect_quantity(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, int offset)
{
    uint64_t q;
    proto_tree_add_item_ret_uint64(tree, hf_bist_quantity, tvb,
                                   offset, 8, ENC_BIG_ENDIAN, &q);
    col_append_fstr(pinfo->cinfo, COL_INFO, "qty %" PRIu64 " ", q);
    return offset + 8;
}

static int dissect_order_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    uint64_t oid;
    proto_tree_add_item_ret_uint64(tree, hf_bist_order_id, tvb,
                                   offset, 8, ENC_BIG_ENDIAN, &oid);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%" PRIu64 " ", oid);
    return offset + 8;
}
/* Guard for optional/trailing bytes: if remaining < len, bail out (goto done). */
/* Avoids malformed on omitted reserved fields; don’t use for required fields. */
#define NEED(len) do { \
    if (tvb_reported_length_remaining(tvb, offset) < (len)) \
        goto done; \
} while (0)

static int
dissect_bist_itch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *bist_tree = NULL;
    int        offset    = 0;
    uint8_t      type      = tvb_get_uint8(tvb, offset);


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "bist‑ITCH");
    const char *type_desc = val_to_str(type, message_types_val, "Unknown (0x%02x)");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo,   COL_INFO,  type_desc);

    ti = proto_tree_add_protocol_format(tree, proto_bist, tvb, 0, -1,
                                    "bist ITCH, %s", type_desc);
    bist_tree = proto_item_add_subtree(ti, ett_bist_itch);
    proto_tree_add_uint(bist_tree, hf_bist_message_type, tvb, 0, 1, type);
    offset += 1;

    switch (type) {
    case 'A': { // Add Order
            offset = dissect_timestamp(tvb, bist_tree, offset);
            offset = dissect_order_id(tvb, pinfo, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_side,        tvb, offset, 1, ENC_BIG_ENDIAN);   offset += 1;
            NEED(4);
            proto_tree_add_item(bist_tree, hf_bist_ranking_seq, tvb, offset, 4, ENC_BIG_ENDIAN);   offset += 4;
            NEED(8 + 4 + 2 + 1);
            offset = dissect_quantity(tvb, pinfo, bist_tree, offset);  // 8
            offset = add_price(bist_tree, hf_bist_price, tvb, offset); // 4
            proto_tree_add_item(bist_tree, hf_bist_order_attributes, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
            proto_tree_add_item(bist_tree, hf_bist_lot_type,        tvb, offset, 1, ENC_BIG_ENDIAN);   offset += 1;
            NEED(8);
            proto_tree_add_item(bist_tree, hf_bist_ranking_time, tvb, offset, 8, ENC_BIG_ENDIAN);  offset += 8;
            break;
    }
    case 'Z': { // Equilibrium Price
            offset = dissect_timestamp(tvb, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_eq_bid_qty,  tvb, offset, 8, ENC_BIG_ENDIAN);   offset += 8;
            proto_tree_add_item(bist_tree, hf_bist_eq_ask_qty,  tvb, offset, 8, ENC_BIG_ENDIAN);   offset += 8;
            offset = add_price(bist_tree, hf_bist_price,         tvb, offset);
            offset = add_price(bist_tree, hf_bist_best_bid_price,tvb, offset);
            offset = add_price(bist_tree, hf_bist_best_ask_price,tvb, offset);
            proto_tree_add_item(bist_tree, hf_bist_bid_qty,      tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
            proto_tree_add_item(bist_tree, hf_bist_ask_qty,      tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
            break;
    }
    case 'M': { // Combo Leg
            offset = dissect_timestamp(tvb, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_combo_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_leg_order_book,     tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_leg_side, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(bist_tree, hf_bist_leg_ratio, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            break;
    }
    case 'E': { // Order Executed
            offset = dissect_timestamp(tvb, bist_tree, offset);
            offset = dissect_order_id(tvb, pinfo, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            offset = dissect_quantity(tvb, pinfo, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_match_id, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
            proto_tree_add_item(bist_tree, hf_bist_combo_group, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;proto_tree_add_item(bist_tree, hf_bist_reserved1, tvb, offset, 7, ENC_NA); offset += 7;
            proto_tree_add_item(bist_tree, hf_bist_reserved2, tvb, offset, 7, ENC_NA); offset += 7;
            break;
    }
    case 'T': { // Second
            proto_tree_add_item(bist_tree, hf_bist_second, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
    }
    case 'P': { // Trade
            offset = dissect_timestamp(tvb, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_match_id, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
            proto_tree_add_item(bist_tree, hf_bist_combo_group, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            offset = dissect_quantity(tvb, pinfo, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            offset = add_price(bist_tree, hf_bist_price, tvb, offset);
            proto_tree_add_item(bist_tree, hf_bist_reserved1, tvb, offset, 7, ENC_NA); offset += 7;
            proto_tree_add_item(bist_tree, hf_bist_reserved2, tvb, offset, 7, ENC_NA); offset += 7;
            proto_tree_add_item(bist_tree, hf_bist_printable, tvb, offset, 1, ENC_ASCII);
            offset += 1;
            proto_tree_add_item(bist_tree, hf_bist_occurred_cross, tvb, offset, 1, ENC_ASCII);
            offset += 1;
            break;
    }
    case 'C': { // Order Executed with price
            offset = dissect_timestamp(tvb, bist_tree, offset);
            offset = dissect_order_id(tvb, pinfo, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            offset = dissect_quantity(tvb, pinfo, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_match_id, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
            proto_tree_add_item(bist_tree, hf_bist_combo_group, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_reserved1, tvb, offset, 7, ENC_NA); offset += 7;
            proto_tree_add_item(bist_tree, hf_bist_reserved2, tvb, offset, 7, ENC_NA); offset += 7;
            offset = add_price(bist_tree, hf_bist_price, tvb, offset);
            proto_tree_add_item(bist_tree, hf_bist_occurred_cross, tvb, offset, 1, ENC_ASCII);
            offset += 1;
            proto_tree_add_item(bist_tree, hf_bist_printable, tvb, offset, 1, ENC_ASCII);
            offset += 1;
            break;
    }
    case 'D': { // Order Delete
            offset = dissect_timestamp(tvb, bist_tree, offset);
            offset = dissect_order_id(tvb, pinfo, bist_tree, offset);
            proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
    }
    case 'S': { // System Event
            offset = dissect_timestamp(tvb, bist_tree, offset);                  // 1..4
            proto_tree_add_item(bist_tree, hf_bist_event_code, tvb, offset, 1, ENC_BIG_ENDIAN); // 'O' or 'C'
            offset += 1;
            break;
    }
    case 'R': { // Orderbook Directory
        offset = dissect_timestamp(tvb, bist_tree, offset);
        proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(bist_tree, hf_bist_symbol,       tvb, offset, 32, ENC_ASCII);     offset += 32;
        proto_tree_add_item(bist_tree, hf_bist_long_name,    tvb, offset, 32, ENC_ASCII);     offset += 32;
        proto_tree_add_item(bist_tree, hf_bist_isin,         tvb, offset, 12, ENC_ASCII);     offset += 12;
        proto_tree_add_item(bist_tree, hf_bist_financial_product, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(bist_tree, hf_bist_trading_currency,  tvb, offset, 3, ENC_ASCII); offset += 3;
        proto_tree_add_item(bist_tree, hf_bist_price_decimals,    tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
        proto_tree_add_item(bist_tree, hf_bist_nominal_decimals,  tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
        proto_tree_add_item(bist_tree, hf_bist_odd_lot_size,      tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(bist_tree, hf_bist_round_lot_size,    tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(bist_tree, hf_bist_block_lot_size,    tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(bist_tree, hf_bist_nominal_value,     tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(bist_tree, hf_bist_number_of_leg,     tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(bist_tree, hf_bist_underlying_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        offset = add_price(bist_tree, hf_bist_strike_price, tvb, offset);
        proto_tree_add_item(bist_tree, hf_bist_expiration_date, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(bist_tree, hf_bist_strike_price_decimals, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
        proto_tree_add_item(bist_tree, hf_bist_put_or_call, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        NEED(1);
        proto_tree_add_item(bist_tree, hf_bist_ranking_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        break;
    }
    case 'Y': { // Orderbook Flush
        offset = dissect_timestamp(tvb, bist_tree, offset);
        proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        break;
    }
    case 'V': { // Short Sell Status
        offset = dissect_timestamp(tvb, bist_tree, offset);
        proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(bist_tree, hf_bist_short_sell_status, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
    }
    case 'O': { // Orderbook State
        offset = dissect_timestamp(tvb, bist_tree, offset);
        proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(bist_tree, hf_bist_state_name,   tvb, offset, 20, ENC_ASCII);     offset += 20;
        break;
    }
    case 'L': { // Tick Size
        offset = dissect_timestamp(tvb, bist_tree, offset);
        proto_tree_add_item(bist_tree, hf_bist_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(bist_tree, hf_bist_tick_size,    tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        offset = add_price(bist_tree, hf_bist_price_from,   tvb, offset);
        offset = add_price(bist_tree, hf_bist_price_to,     tvb, offset);
        break;
    }
    default: {
        proto_tree_add_item(bist_tree, hf_bist_message, tvb, offset, -1, ENC_NA);
        offset = tvb_captured_length(tvb);
        break;
    }
    }

    /* Show any trailing/extra bytes for this message type. */
    if (bist_tree) {
        int rem = tvb_reported_length_remaining(tvb, offset);
        if (rem > 0)
            proto_tree_add_item(bist_tree, hf_bist_unexpected, tvb, offset, rem, ENC_NA);
    }
done:
    return tvb_captured_length(tvb);
}

void proto_register_bist(void)
{
    static hf_register_info hf_bist[] = {
        { &hf_bist_version,              { "Version",                 "bist-itch.version",                 FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_message_type,         { "Message Type",            "bist-itch.message_type",            FT_UINT8,  BASE_HEX,  VALS(message_types_val), 0x0, NULL, HFILL } },
        { &hf_bist_second,               { "Second",                  "bist-itch.second",                  FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_nanosecond,           { "Nanosecond",              "bist-itch.nanosecond",              FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_orderbook_id,         { "Order Book ID",           "bist-itch.orderbook_id",            FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_order_id,             { "Order ID",                "bist-itch.order_id",                FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_side,                 { "Side",                    "bist-itch.side",                    FT_UINT8,  BASE_HEX,  VALS(bist_itch_side_vals), 0x0, NULL, HFILL } },
        { &hf_bist_quantity,             { "Quantity",                "bist-itch.quantity",                FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_price,                { "Price",                   "bist-itch.price",                   FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_match_id,             { "Match ID",                "bist-itch.match_id",                FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_combo_group,          { "Combo Group ID",          "bist-itch.combo_group",             FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_printable,            { "Printable",               "bist-itch.printable",               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_occurred_cross,       { "Occurred at Cross",       "bist-itch.occurred_cross",          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_event_code,           { "Event Code",              "bist-itch.event_code",              FT_UINT8,  BASE_HEX,  VALS(bist_itch_event_vals), 0x0, NULL, HFILL } },
        { &hf_bist_symbol,               { "Symbol",                  "bist-itch.symbol",                  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_long_name,            { "Long Name",               "bist-itch.long_name",               FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_isin,                 { "ISIN",                    "bist-itch.isin",                    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_financial_product,    { "Financial Product",       "bist-itch.financial_product",       FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_trading_currency,     { "Trading Currency",        "bist-itch.trading_currency",        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_tick_size,            { "Tick Size",               "bist-itch.tick_size",               FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_price_from,           { "Price From",              "bist-itch.price_from",              FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_price_to,             { "Price To",                "bist-itch.price_to",                FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_short_sell_status,    { "Short Sell Status",       "bist-itch.short_sell_status",       FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_state_name,           { "State Name",              "bist-itch.state_name",              FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_ranking_seq,          { "Ranking Sequence #",      "bist-itch.ranking_seq",             FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_ranking_time,         { "Ranking Time (ns)",       "bist-itch.ranking_time",            FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_order_attributes,     { "Order Attributes",        "bist-itch.order_attributes",        FT_UINT16, BASE_HEX,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_lot_type,             { "Lot Type",                "bist-itch.lot_type",                FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_price_decimals,       { "Price Decimals",          "bist-itch.price_decimals",          FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_nominal_decimals,     { "Nominal Decimals",        "bist-itch.nominal_decimals",        FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_odd_lot_size,         { "Odd-Lot Size",            "bist-itch.odd_lot_size",            FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_round_lot_size,       { "Round-Lot Size",          "bist-itch.round_lot_size",          FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_block_lot_size,       { "Block-Lot Size",          "bist-itch.block_lot_size",          FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_nominal_value,        { "Nominal Value",           "bist-itch.nominal_value",           FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_number_of_leg,        { "Number of Legs",          "bist-itch.number_of_leg",           FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_underlying_orderbook_id, { "Underlying Orderbook", "bist-itch.underlying_orderbook_id", FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_strike_price,         { "Strike Price",            "bist-itch.strike_price",            FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_expiration_date,      { "Expiration Date",         "bist-itch.expiration_date",         FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_strike_price_decimals,{ "Strike Price Decimals",   "bist-itch.strike_price_decimals",   FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_put_or_call,          { "Put/Call",                "bist-itch.put_or_call",             FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_ranking_type,         { "Ranking Type",            "bist-itch.ranking_type",            FT_UINT8,  BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_message,              { "Raw Message",             "bist-itch.message",                 FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_leg_order_book,       { "Leg Order Book ID",       "bist-itch.leg_order_book",          FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_leg_side,             { "Leg Side",                "bist-itch.leg_side",                FT_UINT8,  BASE_HEX,  VALS(bist_itch_side_vals), 0x0, NULL, HFILL } },
        { &hf_bist_leg_ratio,            { "Leg Ratio",               "bist-itch.leg_ratio",               FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_bid_qty,              { "Best Bid Qty",            "bist-itch.bid_qty",                 FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_ask_qty,              { "Best Ask Qty",            "bist-itch.ask_qty",                 FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_best_bid_price,       { "Best Bid Price",          "bist-itch.best_bid_price",          FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_best_ask_price,       { "Best Ask Price",          "bist-itch.best_ask_price",          FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_best_bid_qty,         { "Next-Level Bid Qty",      "bist-itch.best_bid_qty",            FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_bist_eq_bid_qty, { "Avail Bid Qty at Equilibrium", "bist-itch.eq_bid_qty", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_eq_ask_qty, { "Avail Ask Qty @ Equilibrium", "bist-itch.eq_ask_qty", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_reserved1, { "Reserved", "bist-itch.reserved1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_reserved2, { "Reserved", "bist-itch.reserved2", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_bist_unexpected, { "Unexpected Bytes", "bist-itch.unexpected", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };
    static int *ett[] = { &ett_bist_itch };

    proto_bist = proto_register_protocol("BIST ITCH", "BIST‑ITCH", "bist_itch");
    proto_register_field_array(proto_bist, hf_bist, array_length(hf_bist));
    proto_register_subtree_array(ett,      array_length(ett));

    module_t *pref = prefs_register_protocol(proto_bist, NULL);
    prefs_register_bool_preference(pref, "show_bigint_price",
        "Show Prices as Decimals",
        "If enabled, 4‑byte price fields are divided by 10000 and shown as doubles.",
        &bist_show_bigint_price);

    bist_handle = register_dissector("bist-itch", dissect_bist_itch, proto_bist);
}

void proto_reg_handoff_bist(void)
{
    dissector_add_for_decode_as("moldudp64.payload", bist_handle);
    dissector_add_for_decode_as("moldudp.payload",   bist_handle);
}
