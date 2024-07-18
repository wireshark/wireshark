/* packet-ouch.c
 * Routines for OUCH 4.x protocol dissection
 * Copyright (C) 2013, 2015, 2016 David Arnold <d@0x1.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* OUCH is a stock exchange order entry protocol published and used by
 * NASDAQ.  This dissector supports versions 4.x, which differ from
 * earlier versions by adopting binary encoding for numeric values.
 *
 * OUCH is usually encapsulated within NASDAQ's SoupBinTCP protocol,
 * running over a TCP connection from the trading application to the
 * exchange.  SOUP provides framing, heartbeats and authentication;
 * consequently none of these is present in OUCH.
 *
 * Other exchanges have created order entry protocols very similar to
 * OUCH, but typically they differ in subtle ways (and continue to
 * diverge as time progresses) so I have not attempted to dissect
 * anything other than proper NASDAQ OUCH in this code.
 *
 * Specifications are available from NASDAQ's website, although the
 * links to find them tend to move around over time.  At the time of
 * writing, the correct URL is:
 *
 * http://www.nasdaqtrader.com/content/technicalsupport/specifications/TradingProducts/OUCH4.2.pdf
 */


#include "config.h"

#include <epan/packet.h>

void proto_register_ouch(void);
void proto_reg_handoff_ouch(void);

static const value_string pkt_type_val[] = {
    { 'O', "Enter Order" },
    { 'U', "Replace Order" },
    { 'X', "Cancel Order" },
    { 'M', "Modify Order" },
    { 'S', "System Event" },
    { 'A', "Accepted" },
    { 'R', "Replaced" }, /* 'U' on the wire, but use 'R' to disambiguate */
    { 'C', "Canceled" },
    { 'D', "AIQ Canceled" },
    { 'E', "Executed" },
    { 'F', "Trade Correction" },
    { 'G', "Executed with Reference Price" },
    { 'B', "Broken Trade" },
    { 'K', "Price Correction" },
    { 'J', "Rejected" },
    { 'P', "Cancel Pending" },
    { 'I', "Cancel Reject" },
    { 'T', "Order Priority Update" },
    { 'm', "Order Modified" }, /* 'M' on the wire; 'm' to disambiguate */
    { 0, NULL }
};


static const value_string ouch_bbo_weight_indicator_val[] = {
    { '0', "0 - 0.2%" },
    { '1', "0.2 - 1%" },
    { '2', "1 - 2%" },
    { '3', "Greater than 2%" },
    { ' ', "Unspecified" },
    { 'S', "Sets the QBBO while joining the NBBO" },
    { 'N', "Improves the NBBO upon entry" },
    { 0, NULL }
};

static const value_string ouch_broken_trade_reason_val[] = {
    { 'E', "Erroneous" },
    { 'C', "Consent" },
    { 'S', "Supervisory" },
    { 'X', "External" },
    { 0, NULL }
};

static const value_string ouch_buy_sell_indicator_val[] = {
    { 'B', "Buy Order" },
    { 'S', "Sell Order" },
    { 'T', "Sell Short" },
    { 'E', "Sell Short Exempt" },
    { 0, NULL }
};

static const value_string ouch_cancel_reason_val[] = {
    { 'C', "Cross cancel" },
    { 'D', "Regulatory restriction" },
    { 'E', "Closed" },
    { 'H', "Halted" },
    { 'I', "Immediate or Cancel order" },
    { 'K', "Market Collars" },
    { 'Q', "Self-match prevention" },
    { 'S', "Supervisory" },
    { 'T', "Timeout" },
    { 'U', "User requested cancel" },
    { 'X', "Open Protection" },
    { 'Z', "System cancel" },
    { 0, NULL }
};

static const value_string ouch_capacity_val[] = {
    { 'A', "Agency" },
    { 'O', "Other" },
    { 'P', "Principal" },
    { 'R', "Riskless" },
    { 0, NULL }
};

static const value_string ouch_cross_type_val[] = {
    { 'N', "No Cross" },
    { 'O', "Opening Cross" },
    { 'C', "Closing Cross" },
    { 'I', "Intra-day Cross" }, /* Seems to have been removed */
    { 'H', "Halt/IPO Cross" },
    { 'R', "Retail" }, /* Not in 4.0 */
    { 'S', "Supplemental Order" },
    { 0, NULL }
};

/* Not in 4.0 */
static const value_string ouch_customer_type_val[] = {
    { 'R', "Retail designated order" },
    { 'N', "Not a retail designated order" },
    { ' ', "Default configured for port" },
    { 0, NULL }
};

static const value_string ouch_display_val[] = {
    { 'A', "Attributable-Price to Display" },
    { 'I', "Imbalance-Only" },
    { 'L', "Post-Only and Attributable - Price to Display" },
    { 'M', "Mid-Point Peg" },
    { 'N', "Non-Display" },
    { 'O', "Retail Order Type 1" }, /* Not in 4.0 */
    { 'P', "Post-Only" },
    { 'Q', "Retail Price Improvement Order" }, /* Not in 4.0 */
    { 'R', "Round-Lot Only" }, /* Seems to have been removed? */
    { 'T', "Retail Order Type 2" }, /* Not in 4.0 */
    { 'W', "Mid-point Peg Post Only" },
    { 'Y', "Anonymous-Price to Comply" },
    { 'Z', "Entered as displayed bu changed to non-displayed "
           "(Priced to comply)" }, /* New in 4.2 */
    { 0, NULL}
};

static const value_string ouch_event_code_val[] = {
    { 'S', "Start of Day" },
    { 'E', "End of Day" },
    { 0, NULL}
};

static const value_string ouch_iso_eligibility_val[] = {
    { 'Y', "Eligible" },
    { 'N', "Not eligible" },
    { 0, NULL }
};

static const value_string ouch_liquidity_flag_val[] = {
    { '0', "Supplemental Order Execution" },
    { '4', "Added displayed liquidity in a Group A Symbol" },
    { '5', "Added non-displayed liquidity in a Group A Symbol" },
    { '6', "Removed liquidity in a Group A Symbol" },
    { '7', "Displayed, liquidity-adding order improves the NBBO" },
    { '8', "Displayed, liquidity-adding order sets the QBBO while joining the NBBO" },
    { 'A', "Added" },
    { 'C', "Closing Cross" },
    { 'H', "Halt/IPO Cross" },
    { 'I', "Intraday/Post-Market Cross" }, /* Seems to have been removed */
    { 'J', "Non-displayed adding liquidity" },
    { 'K', "Halt Cross" },
    { 'L', "Closing Cross (imbalance-only)" },
    { 'M', "Opening Cross (imbalance-only)" },
    { 'N', "Halt Cross, orders entered in pilot symbols during the LULD Trading Pause" },
    { 'O', "Opening Cross" },
    { 'R', "Removed" },
    { 'W', "Added post-only" }, /* Removed 4.2 2013/02/05 */
    { 'a', "Added displayed liquidity in a SCIP Symbol" },
    { 'b', "Displayed, liquidity-adding order improves the NBBO in pilot symbol during specified LULD Pricing Pilot timeframe" },
    { 'c', "Added displayed liquidity in a pilot symbol during specified LULD Pricing Pilot timeframe" },
    { 'd', "Retail designated execution that removed liquidity" },
    { 'e', "Retail designated execution that added displayed liquidity" },
    { 'f', "Retail designated execution that added non-displayed liquidity" },
    { 'g', "Added non-displayed mid-point liquidity in a Group A Symbol" },
    { 'h', "Removed liquidity in a pilot symbol during specified LULD Pricing Pilot timeframe" },
    { 'j', "RPI (Retail Price Improving) order provides liquidity" },
    { 'k', "Added liquidity via a midpoint order" },
    { 'm', "Removed liquidity at a midpoint" },
    { 'r', "Retail Order removes RPI liquidity" },
    { 't', "Retail Order removes price improving non-displayed liquidity other than RPI liquidity" },
    { 'x', "Displayed, liquidity-adding order improves the NBBO in a SCIP Symbol" },
    { 'y', "Displayed, liquidity-adding order set the QBBO while joining the NBBO in a SCIP Symbol" },
    { 0, NULL }
};

static const value_string ouch_order_state_val[] = {
    { 'L', "Order Live" },
    { 'D', "Order Dead" },
    { 0, NULL }
};

static const value_string ouch_price_correction_reason_val[] = {
    { 'E', "Erroneous" },
    { 'C', "Consent" },
    { 'S', "Supervisory" },
    { 'X', "External" },
    { 0, NULL }
};

static const value_string ouch_reference_price_type_val[] = {
    { 'I', "Intraday Indicative Value" },
    { 0, NULL }
};

static const value_string ouch_reject_reason_val[] = {
    { 'T', "Test Mode" },
    { 'H', "Halted" },
    { 'Z', "Shares exceeds configured safety threshold" },
    { 'S', "Invalid Stock" },
    { 'D', "Invalid Display Type" },
    { 'C', "NASDAQ is Closed" },
    { 'L', "Requested firm not authorized for requested clearing "
           "type on this account" },
    { 'M', "Outside of permitted times for requested clearing type" },
    { 'R', "This order is not allowed in this type of cross" },
    { 'X', "Invalid Price" },
    { 'N', "Invalid Minimum Quantity" },
    { 'O', "Other" },
    { 'W', "Invalid Mid-point Post Only Price" },
    { 'a', "Reject All enabled" },
    { 'b', "Easy to Borrow (ETB) reject" },
    { 'c', "Restricted symbol list reject" },
    { 'd', "ISO order restriction" },
    { 'e', "Odd lot order restriction" },
    { 'f', "Mid-Point order restriction" },
    { 'g', "Pre-market order restriction" },
    { 'h', "Post-market order restriction" },
    { 'i', "Short sale order restriction" },
    { 'j', "On Open order restriction" },
    { 'k', "On Close order restriction" },
    { 'l', "Two sided quote reject" },
    { 'm', "Exceeded shares limit" },
    { 'n', "Exceeded dollar value limit" },
    { 0, NULL}
};

static const value_string ouch_trade_correction_reason_val[] = {
    { 'N', "Adjusted to NAV" },
    { 0, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_ouch;
static dissector_handle_t ouch_handle;

/* Initialize the subtree pointers */
static int ett_ouch;

static int hf_ouch_bbo_weight_indicator;
static int hf_ouch_broken_trade_reason;
static int hf_ouch_buy_sell_indicator;
static int hf_ouch_cancel_reason;
static int hf_ouch_capacity;
static int hf_ouch_cross_type;
static int hf_ouch_customer_type;
static int hf_ouch_decrement_shares;
static int hf_ouch_display;
static int hf_ouch_event_code;
static int hf_ouch_executed_shares;
static int hf_ouch_execution_price;
static int hf_ouch_existing_order_token;
static int hf_ouch_firm;
static int hf_ouch_iso_eligible;
static int hf_ouch_liquidity_flag;
static int hf_ouch_match_number;
static int hf_ouch_message;
static int hf_ouch_min_quantity;
static int hf_ouch_new_execution_price;
static int hf_ouch_order_reference_number;
static int hf_ouch_order_state;
static int hf_ouch_order_token;
static int hf_ouch_packet_type;
static int hf_ouch_previous_order_token;
static int hf_ouch_price;
static int hf_ouch_price_correction_reason;
static int hf_ouch_quantity_prevented_from_trading;
static int hf_ouch_reference_price;
static int hf_ouch_reference_price_type;
static int hf_ouch_reject_reason;
static int hf_ouch_replacement_order_token;
static int hf_ouch_shares;
static int hf_ouch_stock;
static int hf_ouch_tif;
static int hf_ouch_timestamp;
static int hf_ouch_trade_correction_reason;


/** Format an OUCH timestamp into a useful string
 *
 * We use this function rather than a BASE_CUSTOM formatter because
 * BASE_CUSTOM doesn't support passing a 64-bit value to the
 * formatting function. */
static void
ouch_tree_add_timestamp(
    packet_info *pinfo,
    proto_tree *tree,
    const int hf,
    tvbuff_t *tvb,
    int offset)
{
    uint64_t ts = tvb_get_ntoh64(tvb, offset);
    char *buf = (char *)wmem_alloc(pinfo->pool, ITEM_LABEL_LENGTH);
    uint32_t tmp, hours, mins, secs, nsecs;

    nsecs = (uint32_t)(ts % UINT64_C(1000000000));
    tmp = (uint32_t)(ts / UINT64_C(1000000000));

    hours = tmp / 3600;
    mins = (tmp % 3600) / 60;
    secs = tmp % 60;

    snprintf(buf, ITEM_LABEL_LENGTH,
               "%u:%02u:%02u.%09u",
               hours, mins, secs, nsecs);

    proto_tree_add_string(tree, hf, tvb, offset, 8, buf);
}

/** BASE_CUSTOM formatter for prices
 *
 * OUCH prices are integers, with four implicit decimal places.  So we
 * insert the decimal point, and add a leading dollar sign as well. */
static void
format_price(
    char *buf,
    uint32_t value)
{
    if (value == 0x7fffffff) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "Market");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH,
                   "$%u.%04u",
                   value / 10000, value % 10000);
    }
}

/** BASE_CUSTOM formatter for reference price type code
 *
 * Displays the code value as a character, not its ASCII value, as
 * would be done by BASE_DEC and friends. */
static void
format_reference_price_type(
    char *buf,
    uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH,
               "%s (%c)",
               val_to_str_const(value,
                                ouch_reference_price_type_val,
                                "Unknown"),
               value);
}

/** BASE_CUSTOM formatter for the Time In Force (TIF) code
 *
 * There are three reserved values for the TIF: 0, 99998 and 99999.
 * These are trapped and displayed as an appropriate string.  All
 * other values are printed as a duration in hours, minutes and
 * seconds. */
static void
format_tif(
    char *buf,
    uint32_t value)
{
    uint32_t hours;
    uint32_t mins;
    uint32_t secs;

    switch (value) {
    case 0:
        snprintf(buf, ITEM_LABEL_LENGTH, "Immediate Or Cancel (%u)", value);
        break;

    case 99998:
        snprintf(buf, ITEM_LABEL_LENGTH, "Market Hours (%u)", value);
        break;

    case 99999:
        snprintf(buf, ITEM_LABEL_LENGTH, "System Hours (%u)", value);
        break;

    default:
        hours = value / 3600;
        mins = (value % 3600) / 60;
        secs = value % 60;

        snprintf(buf, ITEM_LABEL_LENGTH,
                   "%uh %02um %02us (%u seconds)",
                   hours, mins, secs,
                   value);
        break;
    }
}


static int
dissect_ouch(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    proto_item *ti;
    proto_tree *ouch_tree = NULL;
    const char *pkt_name;
    uint16_t reported_len;
    uint8_t pkt_type;
    int offset = 0;

    /* Get the OUCH message type value */
    pkt_type = tvb_get_uint8(tvb, offset);
    reported_len = tvb_reported_length(tvb);

    /* OUCH has two messages with the same code: Replace Order and
     * Replaced.  It's possible to tell which is which because clients
     * send the Replace Order, and NASDAQ sends Replaced replies.
     * Nonetheless, this complicates the switch, so instead we
     * distinguish between them by length, and use 'R' for Replaced
     * (like XPRS does). */
    if (pkt_type == 'U' && (reported_len == 79 || reported_len == 80)) {
        pkt_type = 'R';
    }

    /* OUCH has two messages with the same code: Modify Order and
     * Modified.  Again, one is sent by clients, the other sent by
     * NASDAQ.  We change Modified to 'm' for simplicity in the
     * switch. */
    if (pkt_type == 'M' && reported_len == 28) {
        pkt_type = 'm';
    }

    /* Since we use the packet name a few times, get and save that value */
    pkt_name = val_to_str(pkt_type, pkt_type_val, "Unknown (%u)");

    /* Set the protocol name in the summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OUCH");

    /* Set the packet name in the info column */
    col_add_str(pinfo->cinfo, COL_INFO, pkt_name);

    if (tree) {
        /* Create a sub-tree for the OUCH packet details */
        ti = proto_tree_add_item(tree,
                                 proto_ouch,
                                 tvb, 0, -1, ENC_NA);

        ouch_tree = proto_item_add_subtree(ti, ett_ouch);

        /* Append the packet name to the sub-tree item */
        proto_item_append_text(ti, ", %s", pkt_name);

        /* Packet type (using the cooked value). */
        proto_tree_add_item(ouch_tree, hf_ouch_packet_type,
                                  tvb, offset, 1, ENC_ASCII|ENC_NA);
        offset += 1;

        switch (pkt_type) {
        case 'O': /* Enter Order */
            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_buy_sell_indicator,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_stock,
                                tvb, offset, 8,
                                ENC_ASCII);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_tif,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_firm,
                                tvb, offset, 4,
                                ENC_ASCII);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_display,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_capacity,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_iso_eligible,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_min_quantity,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_cross_type,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            if (reported_len >= 49) { /* Added in 4.1 */
                proto_tree_add_item(ouch_tree,
                                    hf_ouch_customer_type,
                                    tvb, offset, 1,
                                    ENC_ASCII|ENC_NA);
                offset += 1;
            }
            break;

        case 'A': /* Accepted */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_buy_sell_indicator,
                                tvb, offset, 1,
                                ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_stock,
                                tvb, offset, 8,
                                ENC_ASCII);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_tif,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_firm,
                                tvb, offset, 4,
                                ENC_ASCII);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_display,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_reference_number,
                                tvb, offset, 8,
                                ENC_BIG_ENDIAN);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_capacity,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_iso_eligible,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_min_quantity,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_cross_type,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_state,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            if (reported_len >= 66) { /* Added in 4.2 */
                proto_tree_add_item(ouch_tree,
                                    hf_ouch_bbo_weight_indicator,
                                    tvb, offset, 1,
                                    ENC_ASCII|ENC_NA);
                offset += 1;
            }
            break;

        case 'U': /* Replace Order */
            proto_tree_add_item(ouch_tree,
                                hf_ouch_existing_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_replacement_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_tif,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_display,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_iso_eligible,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_min_quantity,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;
            break;

        case 'X': /* Cancel Order */
            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;
            break;

        case 'M': /* Modify Order (from 4.2 onwards) */
            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_buy_sell_indicator,
                                tvb, offset, 1,
                                ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;
            break;

        case 'S': /* System Event */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_event_code,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;
            break;

        case 'R': /* Replaced */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_replacement_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_buy_sell_indicator,
                                tvb, offset, 1,
                                ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_stock,
                                tvb, offset, 8,
                                ENC_ASCII);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_tif,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_firm,
                                tvb, offset, 4,
                                ENC_ASCII);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_display,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_reference_number,
                                tvb, offset, 8,
                                ENC_BIG_ENDIAN);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_capacity,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_iso_eligible,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_min_quantity,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_cross_type,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_state,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_previous_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            if (reported_len >= 80) { /* Added in 4.2 */
                proto_tree_add_item(ouch_tree,
                                    hf_ouch_bbo_weight_indicator,
                                    tvb, offset, 1,
                                    ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;

        case 'C': /* Canceled */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_decrement_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_cancel_reason,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;
            break;

        case 'D': /* AIQ Canceled */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_decrement_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_cancel_reason,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_quantity_prevented_from_trading,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_execution_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_liquidity_flag,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;
            break;

        case 'E': /* Executed */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_executed_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_execution_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_liquidity_flag,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_match_number,
                                tvb, offset, 8,
                                ENC_BIG_ENDIAN);
            offset += 8;
            break;

        case 'B': /* Broken Trade */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_match_number,
                                tvb, offset, 8,
                                ENC_BIG_ENDIAN);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_broken_trade_reason,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;
            break;

        case 'F': /* Trade Correction (4.2 onwards) */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_executed_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_execution_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_liquidity_flag,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_match_number,
                                tvb, offset, 8,
                                ENC_BIG_ENDIAN);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_trade_correction_reason,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;
            break;

        case 'G': /* Executed with Reference Price (4.2 onwards) */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_executed_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_execution_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_liquidity_flag,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_match_number,
                                tvb, offset, 8,
                                ENC_BIG_ENDIAN);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_reference_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_reference_price_type,
                                tvb, offset, 1,
                                ENC_BIG_ENDIAN);
            offset += 1;
            break;

        case 'K': /* Price Correction */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_match_number,
                                tvb, offset, 8,
                                ENC_BIG_ENDIAN);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_new_execution_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_price_correction_reason,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;
            break;

        case 'J': /* Rejected Order */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_reject_reason,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;
            break;

        case 'P': /* Cancel Pending */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;
            break;

        case 'I': /* Cancel Reject */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;
            break;

        case 'T': /* Order Priority Update (4.2 onwards) */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_price,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_display,
                                tvb, offset, 1,
                                ENC_ASCII|ENC_NA);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_reference_number,
                                tvb, offset, 8,
                                ENC_BIG_ENDIAN);
            offset += 8;
            break;

        case 'm': /* Order Modified (4.2 onwards) */
            ouch_tree_add_timestamp(pinfo, ouch_tree,
                                    hf_ouch_timestamp,
                                    tvb, offset);
            offset += 8;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_order_token,
                                tvb, offset, 14,
                                ENC_ASCII);
            offset += 14;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_buy_sell_indicator,
                                tvb, offset, 1,
                                ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(ouch_tree,
                                hf_ouch_shares,
                                tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            offset += 4;
            break;

        default:
            /* Unknown */
            proto_tree_add_item(tree,
                                hf_ouch_message,
                                tvb, offset, -1, ENC_NA);
            offset += reported_len - 1;
            break;
        }
    }

    return offset;
}

/** Returns a guess if a packet is OUCH or not
 *
 * Since SOUP doesn't have a sub-protocol type flag, we have to use a
 * heuristic decision to determine if the contained protocol is OUCH
 * or ITCH (or something else entirely).  We look at the message type
 * code, and since we know that we're being called from SOUP, we can
 * check the passed-in length too: if the type code and the length
 * match, we guess at OUCH. */
static bool
dissect_ouch_heur(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    uint8_t msg_type = tvb_get_uint8(tvb, 0);
    unsigned msg_len = tvb_reported_length(tvb);

    switch (msg_type) {
    case 'O': /* Enter order (with or without optional customer type) */
        if (msg_len != 48 && msg_len != 49) {
            return false;
        }
        break;

    case 'U': /* Replace order or Replaced (4.0, 4.1) or Replaced (4.2) */
        if (msg_len != 47 && msg_len != 79 && msg_len != 80) {
            return false;
        }
        break;

    case 'X': /* Cancel order */
        if (msg_len != 19) {
            return false;
        }
        break;

    case 'M': /* Modify Order or Order Modified (added 4.2) */
        if (msg_len != 20 && msg_len != 28) {
            return false;
        }
        break;

    case 'S': /* System event */
        if (msg_len != 10) {
            return false;
        }
        break;

    case 'A': /* Accepted */
        if (msg_len != 65 && msg_len != 66) {
            return false;
        }
        break;

    case 'C': /* Canceled */
        if (msg_len != 28) {
            return false;
        }
        break;

    case 'D': /* AIQ Canceled */
        if (msg_len != 37) {
            return false;
        }
        break;
    case 'E': /* Executed */
        if (msg_len != 40) {
            return false;
        }
        break;

    case 'F': /* Trade Correction */
        if (msg_len != 41) {
            return false;
        }
        break;

    case 'G': /* Executed with Reference Price */
        if (msg_len != 45) {
            return false;
        }
        break;

    case 'B': /* Broken Trade */
        if (msg_len != 32) {
            return false;
        }
        break;

    case 'K': /* Correction */
        if (msg_len != 36) {
            return false;
        }
        break;

    case 'J': /* Rejected */
        if (msg_len != 24) {
            return false;
        }
        break;

    case 'P': /* Cancel Pending */
        if (msg_len != 23) {
            return false;
        }
        break;

    case 'I': /* Cancel Reject */
        if (msg_len != 23) {
            return false;
        }
        break;

    case 'T': /* Order Priority Update */
        if (msg_len != 36) {
            return false;
        }
        break;

    default:
        /* Not a known OUCH message code */
        return false;
    }

    /* Perform dissection of this (initial) packet */
    dissect_ouch(tvb, pinfo, tree, NULL);

    return true;
}


void
proto_register_ouch(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {

        { &hf_ouch_bbo_weight_indicator,
          { "BBO Weight Indicator", "ouch.bbo_weight_indicator",
            FT_CHAR, BASE_HEX, VALS(ouch_bbo_weight_indicator_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_broken_trade_reason,
          { "Broken Trade Reason", "ouch.broken_trade_reason",
            FT_CHAR, BASE_HEX, VALS(ouch_broken_trade_reason_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_buy_sell_indicator,
          { "Buy/Sell Indicator", "ouch.buy_sell_indicator",
            FT_CHAR, BASE_HEX, VALS(ouch_buy_sell_indicator_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_cancel_reason,
          { "Cancel Reason", "ouch.cancel_reason",
            FT_CHAR, BASE_HEX, VALS(ouch_cancel_reason_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_capacity,
          { "Capacity", "ouch.capacity",
            FT_CHAR, BASE_HEX, VALS(ouch_capacity_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_cross_type,
          { "Cross Type", "ouch.cross_type",
            FT_CHAR, BASE_HEX, VALS(ouch_cross_type_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_customer_type,
          { "Customer Type", "ouch.customer_type",
            FT_CHAR, BASE_HEX, VALS(ouch_customer_type_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_decrement_shares,
          { "Decrement Shares", "ouch.decrement_shares",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_display,
          { "Display", "ouch.display",
            FT_CHAR, BASE_HEX, VALS(ouch_display_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_event_code,
          { "Event Code", "ouch.event_code",
            FT_CHAR, BASE_HEX, VALS(ouch_event_code_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_executed_shares,
          { "Executed Shares", "ouch.executed_shares",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_execution_price,
          { "Execution Price", "ouch.execution_price",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_price), 0x0,
            NULL, HFILL }},

        { &hf_ouch_existing_order_token,
          { "Existing Order Token", "ouch.existing_order_token",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_firm,
          { "Firm", "ouch.firm",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_iso_eligible,
          { "Intermarket Sweep Eligibility", "ouch.iso_eligible",
            FT_CHAR, BASE_HEX, VALS(ouch_iso_eligibility_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_liquidity_flag,
          { "Liquidity Flag", "ouch.liquidity_flag",
            FT_CHAR, BASE_HEX, VALS(ouch_liquidity_flag_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_match_number,
          { "Match Number", "ouch.match_number",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_message,
          { "Unknown Message", "ouch.unknown_message",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_min_quantity,
          { "Minimum Quantity", "ouch.min_quantity",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_new_execution_price,
          { "New Execution Price", "ouch.new_execution_price",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_price), 0x0,
            NULL, HFILL }},

        { &hf_ouch_order_reference_number,
          { "Order Reference Number", "ouch.order_reference_number",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_order_state,
          { "Order State", "ouch.order_state",
            FT_CHAR, BASE_HEX, VALS(ouch_order_state_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_order_token,
          { "Order Token", "ouch.order_token",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_packet_type,
          { "Packet Type", "ouch.packet_type",
            FT_CHAR, BASE_HEX, VALS(pkt_type_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_previous_order_token,
          { "Previous Order Token", "ouch.previous_order_token",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_price,
          { "Price", "ouch.price",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_price), 0x0,
            NULL, HFILL }},

        { &hf_ouch_price_correction_reason,
          { "Price Correction Reason", "ouch.price_correction_reason",
            FT_CHAR, BASE_HEX, VALS(ouch_price_correction_reason_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_quantity_prevented_from_trading,
          { "Quantity Prevented from Trading",
            "ouch.quantity_prevented_from_trading",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_reference_price,
          { "Reference Price", "ouch.reference_price",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_price), 0x0,
            NULL, HFILL }},

        { &hf_ouch_reference_price_type,
          { "Reference Price Type", "ouch.reference_price_type",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_reference_price_type), 0x0,
            NULL, HFILL }},

        { &hf_ouch_reject_reason,
          { "Reject Reason", "ouch.reject_reason",
            FT_CHAR, BASE_HEX, VALS(ouch_reject_reason_val), 0x0,
            NULL, HFILL }},

        { &hf_ouch_replacement_order_token,
          { "Replacement Order Token", "ouch.replacement_order_token",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_shares,
          { "Shares", "ouch.shares",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_stock,
          { "Stock", "ouch.stock",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_tif,
          { "Time In Force", "ouch.tif",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_tif), 0x0,
            NULL, HFILL }},

        { &hf_ouch_timestamp,
          { "Timestamp", "ouch.timestamp",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ouch_trade_correction_reason,
          { "Trade Correction Reason", "ouch.trade_correction_reason",
            FT_CHAR, BASE_HEX, VALS(ouch_trade_correction_reason_val), 0x0,
            NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_ouch
    };

    /* Register the protocol name and description */
    proto_ouch = proto_register_protocol("OUCH", "OUCH", "ouch");

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_ouch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissector */
    ouch_handle = register_dissector("ouch", dissect_ouch, proto_ouch);
}


/* If this dissector uses sub-dissector registration add a
 * registration routine.  This format is required because a script is
 * used to find these routines and create the code that calls these
 * routines. */
void
proto_reg_handoff_ouch(void)
{
    heur_dissector_add("soupbintcp", dissect_ouch_heur, "OUCH over SoupBinTCP", "ouch_soupbintcp", proto_ouch, HEURISTIC_ENABLE);
    dissector_add_uint_range_with_preference("tcp.port", "", ouch_handle);
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
