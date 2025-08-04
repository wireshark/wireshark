//
// Created by Sadettin ER on 30.07.2025.
//
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/type_util.h>

static gboolean test_show_bigint_price = FALSE;
static dissector_handle_t test_handle;
static const value_string message_type_vals[] = {
    { 'A', "Add Order" },
    { 'Z', "Equilibrium Price" },
    { 'M', "Combo Leg" },
    { 'E', "Order Executed" },
    { 'T', "Second" },
    { 'P', "Trade" },
    { 'C', "Order Executed With Price" },
    { 'D', "Order Delete" },
    { 'S', "System Event" },
    { 'R', "Order Book Directory" },
    { 'Y', "Order Book Flush" },
    { 'V', "Short Sell Status" },
    { 'O', "Order Book State" },
    { 'L', "Tick Size" },
    { 0, NULL }
};
static const value_string test_itch_side_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 0, NULL },
};
static const value_string test_itch_event_vals[] = {
    { 'O', "Start of Messages" },
    { 'C', "End of Messages" },
    { 0, NULL },
}

static int hf_test_message;
static int proto_test;
static gint ett_test_itch;
static int hf_test_version;
static int hf_test_message_type;
static int hf_test_nanosecond;
static int hf_test_second;
static int hf_test_orderbook_id;
static int hf_test_order_id;
static int hf_test_side;
static int hf_test_quantity;
static int hf_test_price;
static int hf_test_match_id;
static int hf_test_combo_group;
static int hf_test_printable;
static int hf_test_occured_cross;
static int hf_test_event_code;
static int hf_test_symbol;
static int hf_test_isin;
static int hf_test_financial_product;
static int hf_test_trading_currency;
static int hf_test_tick_size;
static int hf_test_price_from;
static int hf_test_price_to;
static int hf_test_leg_order_book;
static int hf_test_leg_side;
static int hf_test_leg_ratio;
static int hf_test_short_sell_status;
static int hf_test_state_name;
static int hf_test_bid_qty;
static int hf_test_ask_qty;
static int hf_test_best_bid_price;
static int hf_test_best_ask_price;
static int hf_test_best_bid_qty;
static int hf_test_ranking_seq;
static int hf_test_ranking_time;
static int hf_test_order_attributes;
static int hf_test_lot_type;
static int hf_test_long_name;
static int hf_test_price_decimals;
static int hf_test_nominal_decimals;
static int hf_test_odd_lot_size;
static int hf_test_round_lot_size;
static int hf_test_block_lot_size;
static int hf_test_nominal_value;
static int hf_test_number_of_leg;
static int hf_test_underlying_orderbook_id;
static int hf_test_strike_price;
static int hf_test_expiration_date;
static int hf_test_strike_price_decimals;
static int hf_test_put_or_call;
static int hf_test_ranking_type;

static int add_uint(proto_tree *tree, int hf_id, tvbuff_t *tvb, int offset, int len)
{
  guint64 v = tvb_get_bits64(tvb, offset*8, len*8, ENC_BIG_ENDIAN);
  if (len == 8)
    proto_tree_add_uint64(tree, hf_id, tvb, offset, len, v);
  else
    proto_tree_add_uint(tree, hf_id, tvb, offset, len, v);
  return offset + len;
}
static int add_string(proto_tree *tree, int hf_id, tvbuff_t *tvb, int offset, int len)
{
  proto_tree_add_item(tree, hf_id, tvb, offset, len, ENC_ASCII|ENC_NA);
  return offset + len;
}
static int add_price(proto_tree *tree, int hf_id, tvbuff_t *tvb, int offset)
{
  guint32 raw = tvb_get_ntohl(tvb, offset);
  if (test_show_bigint_price){
    gdouble p = raw / 10000.0;
    proto_tree_add_double(tree, hf_id, tvb, offset, 4, p);
  }
  else {
    proto_tree_add_double(tree, hf_id, tvb, offset, 4, raw);
  }
  return offset + 4;
}
static int dissect_timestamp(proto_tree *tree, tvbuff_t *tvb, int offset)
{
  guint32 ns = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(tree, hf_id, tvb, offset, 4, ns);
  return offset + 4;
}
static int dissect_quantity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint len)
{
  quint64 q = tvb_get_bits64(tvb, offset*8, len*8, ENC_BIG_ENDIAN);
  proto_tree_add_uint64(tree, hf_test_quantity, tvb, offset, len, q);
  col_append_fstr(pinfo->cinfo, COL_INFO, "qty %" G_GUINT64_FORMAT "", q);
  return offset + len;
}
static int dissect_order_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint64 oid = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint64(tree, hf_test_order_id, tvb, offset, 8, oid);
  col_append_fstr(pinfo->cinfo, COL_INFO, "%" G_GUINT64_FORMAT "", oid);
  return offset + 8;
}
static void dissect_test_itch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto item ti*;
  proto_tree *test_tree = NULL;
  guint8 type;
  gint offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TEST-ITCH");
  type = tvb_get_guint8(tvb, offset);

  const gchar *type_desc = val_to_str(type, message_type_vals, "Unknown (0x%02x)");

  col_clear(pinfo->cinfo, COL_INFO);
  col_add_str(pinfo->cinfo, COL_INFO, type_desc);

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_test, tvb, 0, -1, "TEST ITCH, %s", type_desc);
    test_tree = proto_item_add_subtree(ti, ett_test_itch);
  }
  if (type == 'T') {
    if (test_tree) {
      proto_tree_add_uint(test_tree, hf_test_message_type, tvb, offset, 0, 1, type);
    }
    offset++;
    add_uint(test_tree, hf_test_message_type, tvb, 0, 1, type);
    return;
  }
  if (test_tree)
    proto_tree_add_uint(test_tree, hf_test_message_type, tvb, 0, 1, type);
    offset++;


    switch (type) {
      case 'R': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = add_uint(test_tree, hf_test_orderbook_id, tvb, offset, 4);
        offset = add_string(test_tree, hf_test_symbol, tvb, offset, 32);
        offset = add_string(test_tree, hf_test_long_name, tvb, offset, 32);
        offset = add_string(test_tree, hf_test_isin, tvb, offset, 12);
        offset = add_uint(test_tree, hf_test_financial_product, tvb, offset, 1);
        offset = add_string(test_tree, hf_test_trading_currency, tvb, offset, 3);
        offset = add_uint(test_tree, hf_test_price_decimals, tvb, offset, 2);
        offset = add_uint(test_tree, hf_test_nominal_decimals, tvb, offset, 2);
        offset = add_uint(test_tree, hf_test_lot_size, tvb, offset, 4);
        offset = add_uint(test_tree, hf_test_round_lot_size, tvb, offset, 4);
        offset = add_uint(test_tree, hf_test_block_lot_size, tvb, offset, 4);
        offset = add_uint(test_tree, hf_test_nominal_value, tvb, offset, 8);
        offset = add_uint(test_tree, hf_test_number_of_leg, tvb, offset, 1);
        offset = add_uint(test_tree, hf_test_underlying_orderbook_id, tvb, offset, 4);
        offset = add_price(test_tree, hf_test_strike_price, tvb, offset);
        offset = add_uint(test_tree, hf_test_expiration_date, tvb, offset, 4);
        offset = add_uint(test_tree, hf_test_strike_price_decimals, tvb, offset, 2);
        offset = add_uint(test_tree, hf_test_put_or_call, tvb, offset, 1);
        offset = add_uint(test_tree, hf_test_ranking_type, tvb, offset, 1);
        break;
      }
      case 'L': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = add_uint(test_tree, hf_test_orderbook_id, tvb, offset, 4);
        offset = add_uint(test_tree, hf_test_tick_size, tvb, offset, 8);
        offset = add_price(test_tree, hf_test_price_from, tvb, offset);
        offset = add_price(test_tree, hf_test_price_to, tvb, offset);
        break;
      }
      case 'V': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = add_uint(test_tree, hf_test_order_book_id, tvb, offset, 4);
        offset = add_uint(test_tree, hf_test_short_sell_status, tvb, offset, 1);
        break;
      }
      case 'O': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = add_uint(test_tree, hf_test_order_book_id, tvb, offset, 4);
        offset = add_string(test_tree, hf_test_state_name, tvb, offset, 20);
        break;
      }
      case 'A': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = dissect_order_id(tvb, pinfo, test_tree, offset);
        offset = add_uint(test_tree, hf_test_order_book_id, tvb, offset, 4);
        offset = add_string(test_tree, hf_test_side, tvb, offset, 1, ENC_ASCII | ENC_NA);
        offset += 1;
        offset = add_uint(test_tree, hf_test_ranking_seq, tvb, offset, 4);
        offset = dissect_quantity(test_tree, pinfo, hf_test_quantity, tvb, offset, 8);
        offset = add_price(test_tree, hf_test_price, tvb, offset);
        offset = add_uint(test_tree, hf_test_order_attributes, tvb, offset, 1);
        offset = add_uint(test_tree, hf_test_lot_type, tvb, offset, 2);
        offset = add_uint(test_tree, hf_test_ranking_time, tvb, offset, 8);
        break;
      }
      case 'E': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = dissect_order_id(tvb, pinfo, test_tree, offset);
        offset = add_uint(test_tree, hf_test_order_book_id, tvb, offset, 4);
        offset = add_string(test_tree, hf_test_side, tvb, offset, 1);
        offset = dissect_quantity(test_tree, pinfo, hf_test_quantity, tvb, offset, 8);
        offset = add_uint(test_tree, hf_test_match_id, tvb, offset, 8);
        offset = add_uint(test_tree, hf_test_combo_group, tvb, offset, 4);
        offset += 14;
        break;
      }
      case 'C': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = dissect_order_id(tvb, pinfo, test_tree, offset);
        offset = add_uint(test_tree, hf_test_order_book_id, tvb, offset, 4);
        proto_tree_add_item(test_tree, hf_test_side, tvb, offset, 1, ENC_ASCII | ENC_NA);
        offset += 1;
        offset = dissect_quantity(test_tree, pinfo, hf_test_quantity, tvb, offset, 8);
        offset = add_uint(test_tree, hf_test_match_id, tvb, offset, 8);
        offset = add_uint(test_tree, hf_test_combo_group, tvb, offset, 4);
        offset += 14;
        offset = add_price(test_tree, hf_test_price, tvb, offset);
        proto_tree_add_item(test_tree, hf_test_occured_cross, tvb, offset, 1, ENC_ASCII | ENC_NA);
        offset += 1;
        proto_tree_add_item(test_tree, hf_test_printable, tvb, offset, 1, ENC_ASCII | ENC_NA);
        break;
      }
      case 'D': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = dissect_order_id(tvb, pinfo, test_tree, offset);
        offset = add_uint(test_tree, hf_test_order_book_id, tvb, offset, 4);
        proto_tree_add_item(test_tree, hf_test_side, tvb, offset, 1, ENC_ASCII | ENC_NA);
        break;
      }
      case 'Y': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = add_uint(test_tree, hf_test_order_book_id, tvb, offset, 4);
        break;
      }
      case 'P': {
        offset = dissect_timestamp(tvb, test_tree, offset);
        offset = add_uint(test_tree, hf_test_match_id, tvb, offset, 8);
        offset = add_uint(test_tree, hf_test_combo_group, tvb, offste, 4);
        proto_tree_add_item(test_tree, hf_test_side, tvb, offset, 1, ENC_ASCII | ENC_NA);
        offset += 1;
        offset = dissect_quantity(test_tree, pinfo, hf_test_quantity, tvb, offset, 8);
        offset = add_uint(test_tree, hf_test_order_book_id, tvb, offset, 4);
        offset = add_price(test_tree, hf_test_price, tvb, offset);
        offset += 14;
        proto_tree_add_item(test_tree, hf_test_printable, tvb, offset, 1, ENC_ASCII | ENC_NA);
        offset += 1;
        proto_tree_add_item(test_tree, hf_test_occured_cross, tvb, offset, 1, ENC_ASCII | ENC_NA);
        break;
      }
      default:
        if (test_tree)
          proto_tree_add_item(test_tree, hf_test_message, tvb, offset, -1, ENC_NA);
        break;
    }

}
#define HF_ENTRY(id, name, abbr, type, base, vals, blurb) \ {&hf_bist_##id, {name, "test-itch." abbr, type, base, vals, 0x0, blurb, HFILL} }
void
proto_register_test(void)
{
  static hf_register_info hf[] = {
    HF_ENTRY(version, "Version", "version", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(message_type, "Message Type", "message type", FT_UINT8, BASE_DEC, VALS(message_type_vals), NULL),
    HF_ENTRY(second, "Second", "second", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(nanosecond, "Nanosecond", "nanosecond", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(orderbook_id, "Orderbook ID", "orderbook_id", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(order_id, "Order ID", "order_id", FT_UINT64, BASE_DEC, NULL, NULL),
    HF_ENTRY(side, "Side", "side", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(quantity, "Quantity", "quantity", FT_UINT64, BASE_DEC, NULL, NULL),
    HF_ENTRY(price, "Price", "price", FT_DOUBLE, BASE_NONE, NULL, NULL),
    HF_ENTRY(match_id, "Match ID", "match_id", FT_UINT64, BASE_DEC, NULL, NULL),
    HF_ENTRY(combo_group, "Combo Group", "combo_group", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(printable, "Printable", "printable", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(occured_cross, "Occured cross", "occured_cross", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(event_code, "Event Code", "event_code", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(symbol, "Symbol", "symbol", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(long_name, "Long Name", "long_name", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(isin, "ISIN", "isin", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(financial_product, "Financial Product", "financial_product", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(trading_currency, "Trading Currency", "trading_currency", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(tick_size, "Tick Size", "tick_size", FT_UINT64, BASE_DEC, NULL, NULL),
    HF_ENTRY(price_from, "Price From", "price_from", FT_DOUBLE, BASE_NONE, NULL, NULL),
    HF_ENTRY(price_to, "Price To", "price_to", FT_DOUBLE, BASE_NONE, NULL, NULL),
    HF_ENTRY(short_sell_status, "Short Sell Status", "short_sell_status", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(state_name, "State Name", "state_name", FT_STRING, BASE_NONE, NULL, NULL),
    HF_ENTRY(ranking_seq, "Ranking Sequence", "ranking_seq", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(ranking_time, "Ranking Time", "ranking_time", FT_UINT64, BASE_DEC, NULL, NULL),
    HF_ENTRY(order_attributes, "Order Attributes", "order_attributes", FT_UINT16, BASE_HEX, NULL, NULL),
    HF_ENTRY(lot_type, "Lot Type", "lot_type", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(price_decimals, "Price Decimals", "price_decimals", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(nominal_decimals, "Nominal Decimals", "nominal_decimals", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(odd_lot_size, "Odd Lot Size", "odd_lot_size", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(round_lot_size, "Round Lot Size", "round_lot_size", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(block_lot_size, "Block Lot Size", "block_lot_size", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(nominal_value, "Nominal Value", "nominal_value", FT_UINT64, BASE_DEC, NULL, NULL),
    HF_ENTRY(number_of_leg, "Number of Leg", "number_of_leg", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(underlying_orderbook_id, "Underlying Orderbook ID", "underlying_orderbook_id", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(strike_price, "Strike Price", "strike_price", FT_DOUBLE, BASE_NONE, NULL, NULL),
    HF_ENTRY(expiration_date, "Expiration Date", "expiration_date", FT_UINT32, BASE_DEC, NULL, NULL),
    HF_ENTRY(strike_price_decimals, "Strike Price Decimals", "strike_price_decimals", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(put_or_call, "Put or Call", "put_or_call", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(ranking_type, "Ranking Type", "ranking_type", FT_UINT8, BASE_DEC, NULL, NULL),
    HF_ENTRY(message, "Message", "message", FT_BYTES, BASE_NONE, NULL, NULL),
  };
  static gint *ett[] = { &ett_test_itch };
  proto_test = proto_register_protocol("TEST ITCH", "TEST-ITCH", "test_itch");
  proto_register_field_array(proto_test, hf_test, array_length(hf_test));
  proto_register_subtree_array(ett, array_length(ett));

  module_t *pref = prefs_register_protocol(proto_bist, NULL);
  prefs_register_bool_preference(pref, "show_bigint_price", "Show Prices as Decimals", "If enabled, 4-byte prices are divided by 10000 and shown as doubles.", &test_show_bigint_price);
  bist_handle = register_dissector("test-itch", dissect_test_itch, proto_test);
}
void proto_reg_handoff_test(void) {
  dissector_add_for_decode_as("moldudp64.payload", bist_handle);
  dissector_add_for_decode_as("moldudp.payload", bist_handle);
}