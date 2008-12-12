/* packet-itch.c
 * Routines for NASDAQ TotalView-ITCH version 2.00/3.00 (with Chi-X extension) Protocol dissection
 * Copyright 2007,2008 Didier Gautheron <dgautheron@magic.fr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Documentation:
 * http://www.nasdaqtrader.com/Trader.aspx?id=DPSpecs
 * ex:
 * http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/tv-itch2a.pdf
 * http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/tvitch-v3.pdf
 *
 * Chi-X
 * http://www.chi-x.com/docs/Chi-X%20CHIXMD.pdf

 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>

/* Chi-X version */
static gboolean itch_chi_x = TRUE;

static const value_string message_types_val[] = {
 { 'A', "Add Order " },
 { 'X', "Order Cancel " },
 { 'M', "Milliseconds " },
 { 'E', "Order Executed " },
 { 'T', "Second " },
 { 'P', "Trade Message Identifier " },
 { 'C', "Order Executed With Price " },
 { 'D', "Order Delete " },
 { 'Q', "Cross Trade " },
 { 'S', "System Event " },
 { 'R' , "Stock Directory " },
 { 'H', "Stock Trading Action " },
 { 'F', "Add Order (MPID) " },
 { 'I', "Net Order Imbalance Indicator (NOII) " },
 { 'B', "Broken Trade " },
 /* Chi-X msg with big size,price */
 { 'a', "Add Order (big)" },
 { 'p', "Trade Message Identifier (big)" },
 { 'e', "Order Executed (big)" },
 { 'x', "Order Cancel (big)" },
 { 0, NULL }
};

static char chix_msg[] = "apex";

static const value_string system_event_val[] = {
 { 'O', "Start of Messages" },
 { 'S', "Start of System hours" },
 { 'Q', "Start of Market hours" },
 { 'M', "End of Market hours" },
 { 'E', "End of System hours" },
 { 'C', "End of Messages" },
 { 0, NULL }
};

static const value_string market_category_val[] = {
 { 'T', "CQS (NYSE, Amex or regional exchange)" },
 { 'Q', "NASDAQ Global Select MarketSM" },
 { 'G', "NASDAQ Global MarketSM" },
 { 'S', "NASDAQ Capital Market" },
 { ' ', "Not available" },
 { 0, NULL }
};

static const value_string financial_status_val[] = {
 { 'D', "Deficient" },
 { 'E', "Delinquent" },
 { 'Q', "Bankrupt" },
 { 'S', "Suspended" },
 { 'G', "Deficient and Bankrupt" },
 { 'H', "Deficient and Delinquent" },
 { 'J', "Delinquent and Bankrupt" },
 { 'K', "Deficient, Delinquent and Bankrupt" },
 { ' ', "Company is in compliance" },
 { 0, NULL }
};

static const value_string round_lots_only_val[] = {
 { 'Y', "only round lots are accepted in this stock" },
 { 'N', "odd/mixed lots are allowed" },
 { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_itch = -1;

/* Initialize the subtree pointers */
static gint ett_itch = -1;

static int hf_itch_version = -1;

static int hf_itch_message_type = -1; 
static int hf_itch_market_category = -1;
static int hf_itch_financial_status = -1;
static int hf_itch_stock = -1;
static int hf_itch_round_lot_size = -1;
static int hf_itch_round_lots_only = -1;

static int hf_itch_system_event = -1;
static int hf_itch_second = -1;
static int hf_itch_millisecond = -1;

static int hf_itch_message = -1; 

static int hf_itch_trading_state = -1; 
static int hf_itch_reserved = -1; 
static int hf_itch_reason = -1; 
static int hf_itch_order_reference = -1; 
static int hf_itch_buy_sell = -1; 
static int hf_itch_shares = -1; 
static int hf_itch_price = -1; 
static int hf_itch_attribution = -1;
static int hf_itch_executed = -1;
static int hf_itch_match = -1;
static int hf_itch_printable = -1;
static int hf_itch_execution_price = -1;
static int hf_itch_canceled = -1;
static int hf_itch_cross = -1;

#define PINFO_COL(a) (check_col((a)->cinfo, COL_INFO))

/* atou(ll) like functions for NOT 0 terminated string
   assume it doesn't overflow
*/

static guint32 itch_atou(const char *str_value, int size)
{
  int i;
  const char *ptr = str_value;
  guint32 value = 0;

  for (i = 0; i < size && *ptr == ' '; i++, ptr++) {
      continue;
  }

  for (; i < size; i++, ptr++) {
      value = value*10 + *ptr - '0';
  }
  return value;
}

/* ---------------------- */
static guint64 itch_atoull(const char *str_value, int size)
{
  int i;
  const char *ptr = str_value;
  guint64 value = 0;

  for (i = 0; i < size && *ptr == ' '; i++, ptr++) {
      continue;
  }

  for (; i < size; i++, ptr++) {
      value = value*10 + *ptr - '0';
  }
  return value;
}

/* ---------------------- */
static int
order_ref_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *itch_tree, int offset)
{
  gint col_info = PINFO_COL(pinfo);
  const char *str_value = tvb_get_ptr(tvb, offset, 9);

  if (itch_tree || col_info) {
      guint32 value = itch_atou(str_value, 9);

      proto_tree_add_uint(itch_tree, hf_itch_order_reference, tvb, offset, 9, value);
      if (col_info) {
          col_append_fstr(pinfo->cinfo, COL_INFO, "%u ", value);
      }
  }
  return offset+9;
}

/* -------------------------- */
static int
time_stamp(tvbuff_t *tvb, proto_tree *itch_tree, int id, int offset, int size)
{
  const char *str_value = tvb_get_ptr(tvb, offset, size);

  if (itch_tree) {
      guint32 ms, val;
      char *display = "";

      ms = val = itch_atou(str_value, size);
      switch (size) {
      case 3:
          display = ep_strdup_printf(" %03u" , val);
          break;
      case 5:
          ms = val *1000;
      case 8: /* 0 86 400 000 */
          display = ep_strdup_printf(" %u (%02u:%02u:%02u.%03u)", val,
              ms/3600000, (ms % 3600000)/60000, (ms % 60000)/1000, ms %1000);
          break;
      }
      proto_tree_add_uint_format_value(itch_tree, id, tvb, offset, size, val, "%s", display);
  }
  return offset+size;
}

/* -------------------------- */
static int
number_of_shares(tvbuff_t *tvb, packet_info *pinfo, proto_tree *itch_tree, int id, int offset, int big)
{
  gint col_info = PINFO_COL(pinfo);
  gint size = (big)?10:6;
  const char *str_value = tvb_get_ptr(tvb, offset, size);

  if (itch_tree || col_info) {
      guint32 value = itch_atou(str_value, size);

      proto_tree_add_uint(itch_tree, id, tvb, offset, size, value);
      if (col_info) {
          col_append_fstr(pinfo->cinfo, COL_INFO, "qty %u ", value);
      }
  }
  return offset +size;
}

/* -------------------------- */
static int
price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *itch_tree, int id, int offset, int big)
{
  gint col_info = PINFO_COL(pinfo);
  gint size = (big)?19:10;

  if (itch_tree || col_info) {
      const char *str_value = tvb_get_ptr(tvb, offset, size);
      gdouble value = itch_atoull(str_value, size)/((big)?1000000.0:10000.0);

      proto_tree_add_double(itch_tree, id, tvb, offset, size, value);
      if (col_info) {
          col_append_fstr(pinfo->cinfo, COL_INFO, "price %g ", value);
      }
  }
  return offset+size;
}

/* -------------------------- */
static int
stock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *itch_tree, int offset)
{
  gint col_info = PINFO_COL(pinfo);
  if (itch_tree || col_info) {
      char *stock = tvb_get_ephemeral_string(tvb, offset, 6); 

      proto_tree_add_item(itch_tree, hf_itch_stock, tvb, offset, 6, FALSE);
      if (col_info) {
          col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", stock);
      }
  }
  return offset+6;
}

/* -------------------------- */
static int
order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *itch_tree, int offset, int big)
{
  gint col_info = PINFO_COL(pinfo);
  guint8 value;

  offset = order_ref_number(tvb, pinfo, itch_tree, offset);

  value = tvb_get_guint8(tvb, offset);
  if (col_info) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "%c ", value);
  }
  proto_tree_add_item(itch_tree, hf_itch_buy_sell, tvb, offset, 1, FALSE);
  offset += 1;

  offset = number_of_shares(tvb, pinfo, itch_tree, hf_itch_shares, offset, big);

  offset = stock(tvb, pinfo, itch_tree, offset);

  offset = price(tvb, pinfo, itch_tree, hf_itch_price, offset, big);
  return offset;
}

/* -------------------------- */
static int
executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *itch_tree, int offset, int big)
{
  offset = order_ref_number(tvb, pinfo, itch_tree, offset);

  offset = number_of_shares(tvb, pinfo, itch_tree, hf_itch_executed, offset, big);

  proto_tree_add_item(itch_tree, hf_itch_match, tvb, offset, 9, FALSE);
  offset += 9;
  return offset;
}

/* ---------------------------- */
static void
dissect_itch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *itch_tree = NULL;
    guint8 itch_type;
    int  offset = 0;
    gint col_info;
    int version = 3;
    int big = 0;

    col_info = PINFO_COL(pinfo);

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ITCH");

    itch_type = tvb_get_guint8(tvb, offset);
    if (itch_type >= '0' && itch_type <= '9') {
        version = 2;
        itch_type = tvb_get_guint8(tvb, offset +8);
    }

    if ((!itch_chi_x || version == 3) && strchr(chix_msg, itch_type)) {
        itch_type = 0; /* unknown */
    }
    if (col_info || tree) {
        const gchar *rep = val_to_str(itch_type, message_types_val, "Unknown packet type (0x%02x) ");
        if (col_info ) {
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_str(pinfo->cinfo, COL_INFO, rep);
        }
        if (tree) {
            proto_item *item;

            ti = proto_tree_add_protocol_format(tree, proto_itch, tvb, offset, -1, "TotalView-ITCH %s, %s",
                    version == 2?"2.0":"3.0", rep);

            itch_tree = proto_item_add_subtree(ti, ett_itch);

            item=proto_tree_add_uint(itch_tree, hf_itch_version, tvb, 0, 0, version);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }

    if (version == 2) {
        offset = time_stamp (tvb, itch_tree, hf_itch_millisecond, offset, 8);
    }

    proto_tree_add_item(itch_tree, hf_itch_message_type, tvb, offset, 1, FALSE);
    offset++;

    if (version == 3) {
      switch (itch_type) {
      case 'T': /* seconds */
          offset = time_stamp (tvb, itch_tree, hf_itch_second, offset, 5);
          return;

      case 'M': /* milliseconds */
          offset = time_stamp (tvb, itch_tree, hf_itch_millisecond, offset, 3);
          return;
      }
    }

    switch (itch_type) {
    case 'S': /* system event */
        proto_tree_add_item(itch_tree, hf_itch_system_event, tvb, offset, 1, FALSE);
        offset++;
        break;

    case 'R': /* Stock Directory */
        offset = stock(tvb, pinfo, itch_tree, offset);

        proto_tree_add_item(itch_tree, hf_itch_market_category, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(itch_tree, hf_itch_financial_status, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(itch_tree, hf_itch_round_lot_size, tvb, offset, 6, FALSE);
        offset += 6;
        proto_tree_add_item(itch_tree, hf_itch_round_lots_only, tvb, offset, 1, FALSE);
        offset += 1;
        break;

    case 'H': /* Stock trading action */
        offset = stock(tvb, pinfo, itch_tree, offset);

        proto_tree_add_item(itch_tree, hf_itch_trading_state, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(itch_tree, hf_itch_reserved, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(itch_tree, hf_itch_reason, tvb, offset, 4, FALSE);
        offset += 4;
        break;

    case 'a' :
        big = 1;
    case 'A': /* Add order, no MPID */
        offset = order(tvb, pinfo, itch_tree, offset, big);
        if (version == 2) {
            proto_tree_add_item(itch_tree, hf_itch_printable, tvb, offset, 1, FALSE);
            offset += 1;
        }
        break;

    case 'F': /* Add order, MPID */
        offset = order(tvb, pinfo, itch_tree, offset, big);
        proto_tree_add_item(itch_tree, hf_itch_attribution, tvb, offset, 4, FALSE);
        offset += 4;
        break;

    case 'e' :
        big = 1;
    case 'E' : /* Order executed */
        offset = executed(tvb, pinfo, itch_tree, offset, big);
        break;

    case 'C' : /* Order executed with price */
        offset = executed(tvb, pinfo, itch_tree, offset, big);
        proto_tree_add_item(itch_tree, hf_itch_printable, tvb, offset, 1, FALSE);
        offset += 1;

        offset = price(tvb, pinfo, itch_tree, hf_itch_execution_price, offset, big);
        break;

    case 'x' :
        big = 1;
    case 'X' : /* Order cancel */
        offset = order_ref_number(tvb, pinfo, itch_tree, offset);
        offset = number_of_shares(tvb, pinfo, itch_tree, hf_itch_canceled, offset, big);
        break;

    case 'D' : /* Order delete */
        offset = order_ref_number(tvb, pinfo, itch_tree, offset);
        offset += 9;
        break;

    case 'p' :
        big = 1;
    case 'P' : /* Trade identifier */
        offset = order(tvb, pinfo, itch_tree, offset, big);
        proto_tree_add_item(itch_tree, hf_itch_match, tvb, offset, 9, FALSE);
        offset += 9;
        break;

    case 'Q' : /* Cross Trade */
        offset = number_of_shares(tvb, pinfo, itch_tree, hf_itch_shares, offset, big);

        offset = stock(tvb, pinfo, itch_tree, offset);

        offset = price(tvb, pinfo, itch_tree, hf_itch_price, offset, big);

        proto_tree_add_item(itch_tree, hf_itch_match, tvb, offset, 9, FALSE);
        offset += 9;
        proto_tree_add_item(itch_tree, hf_itch_cross, tvb, offset, 1, FALSE);
        offset += 1;
        break;

    case 'B' : /* Broken Trade */
        proto_tree_add_item(itch_tree, hf_itch_match, tvb, offset, 9, FALSE);
        offset += 9;
        break;

    case 'I': /* NOII, FIXME */
        offset = stock(tvb, pinfo, itch_tree, offset);

        proto_tree_add_item(itch_tree, hf_itch_cross, tvb, offset, 1, FALSE);
        offset += 1;
        break;

    default:
        /* unknow */
        proto_tree_add_item(itch_tree, hf_itch_message, tvb, offset, -1, FALSE);
        offset += 5-1;
        break;
    }
}

/* Register the protocol with Wireshark */

void
proto_register_itch(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
    { &hf_itch_version,
      { "Version",         "itch.version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_message_type,
      { "Message Type",         "itch.message_type",
        FT_UINT8, BASE_DEC, VALS(message_types_val), 0x0,
        NULL, HFILL }},

    { &hf_itch_second,
      { "Second",         "itch.second",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_millisecond,
      { "Millisecond",         "itch.millisecond",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_system_event,
      { "System Event",         "itch.system_event",
        FT_UINT8, BASE_DEC, VALS(system_event_val), 0x0,
        NULL, HFILL }},

    { &hf_itch_market_category,
      { "Market Category",         "itch.market_category",
        FT_UINT8, BASE_DEC, VALS(market_category_val), 0x0,
        NULL, HFILL }},

    { &hf_itch_financial_status,
      { "Financial Status Indicator",         "itch.financial_status",
        FT_UINT8, BASE_DEC, VALS(financial_status_val), 0x0,
        NULL, HFILL }},

    { &hf_itch_stock,
      { "Stock",         "itch.stock",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_round_lot_size,
      { "Round Lot Size",         "itch.round_lot_size",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_round_lots_only,
      { "Round Lots Only",         "itch.round_lots_only",
        FT_UINT8, BASE_DEC, VALS(round_lots_only_val), 0x0,
        NULL, HFILL }},

    { &hf_itch_trading_state,
      { "Trading State",         "itch.trading_state",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_reserved,
      { "Reserved",         "itch.reserved",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_reason,
      { "Reason",         "itch.reason",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_order_reference,
      { "Order Reference",         "itch.order_reference",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Order reference number", HFILL }},

    { &hf_itch_buy_sell,
      { "Buy/Sell",         "itch.buy_sell",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Buy/Sell indicator", HFILL }},

    { &hf_itch_shares,
      { "Shares",         "itch.shares",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Number of shares", HFILL }},

    { &hf_itch_price,
      { "Price",         "itch.price",
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_attribution,
      { "Attribution",         "itch.attribution",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Market participant identifier", HFILL }},

    { &hf_itch_executed,
      { "Executed Shares",         "itch.executed",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Number of shares executed", HFILL }},

    { &hf_itch_match,
      { "Matched",         "itch.match",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Match number", HFILL }},

    { &hf_itch_printable,
      { "Printable",         "itch.printable",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_execution_price,
      { "Execution Price",         "itch.execution_price",
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_itch_canceled,
      { "Canceled Shares",         "itch.canceled",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Number of shares be removed", HFILL }},

    { &hf_itch_cross,
      { "Cross Type",         "itch.cross",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Cross trade type", HFILL }},

    { &hf_itch_message,
      { "Message",         "itch.message",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }}
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_itch
    };

    module_t *itch_module;

    /* Register the protocol name and description */
    proto_itch = proto_register_protocol("TotalView-ITCH", "ITCH", "itch");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_itch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    itch_module = prefs_register_protocol(proto_itch, NULL);
    prefs_register_bool_preference(itch_module, "chi_x", "Decode Chi X extensions",
        "Whether the ITCH dissector should decode Chi X extensions.",
        &itch_chi_x);

    register_dissector("itch", dissect_itch, proto_itch);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_itch(void)
{
}

