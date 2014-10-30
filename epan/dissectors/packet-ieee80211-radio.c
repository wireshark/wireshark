/* packet-ieee80211-radio.c
 * Routines for pseudo 802.11 header dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

#include "packet-ieee80211.h"

void proto_register_ieee80211_radio(void);
void proto_reg_handoff_ieee80211_radio(void);

static dissector_handle_t ieee80211_handle;

static int proto_radio = -1;

/* ************************************************************************* */
/*                Header field info values for radio information             */
/* ************************************************************************* */
static int hf_data_rate = -1;
static int hf_mcs_index = -1;
static int hf_bandwidth = -1;
static int hf_short_gi = -1;
static int hf_channel = -1;
static int hf_frequency = -1;
static int hf_signal_percent = -1;
static int hf_signal_dbm = -1;
static int hf_noise_percent = -1;
static int hf_noise_dbm = -1;

static const value_string bandwidth_vals[] = {
    { PHDR_802_11_BANDWIDTH_20_MHZ, "20 MHz" },
    { PHDR_802_11_BANDWIDTH_40_MHZ, "40 MHz" },
    { PHDR_802_11_BANDWIDTH_20_20L, "20 MHz + 20 MHz lower" },
    { PHDR_802_11_BANDWIDTH_20_20U, "20 MHz + 20 MHz upper" },
    { 0, NULL }
};

/*
 * Data rates corresponding to a given 802.11n MCS index, bandwidth, and
 * guard interval.
 *
 * Indices are:
 *
 *	the MCS index (0-76);
 *
 *	0 for 20 MHz, 1 for 40 MHz;
 *
 *	0 for a long guard interval, 1 for a short guard interval.
 */
WS_DLL_PUBLIC_DEF
const float ieee80211_float_htrates[MAX_MCS_INDEX+1][2][2] = {
	/* MCS  0  */
	{	/* 20 Mhz */ {    6.5f,		/* SGI */    7.2f, },
		/* 40 Mhz */ {   13.5f,		/* SGI */   15.0f, },
	},

	/* MCS  1  */
	{	/* 20 Mhz */ {   13.0f,		/* SGI */   14.4f, },
		/* 40 Mhz */ {   27.0f,		/* SGI */   30.0f, },
	},

	/* MCS  2  */
	{	/* 20 Mhz */ {   19.5f,		/* SGI */   21.7f, },
		/* 40 Mhz */ {   40.5f,		/* SGI */   45.0f, },
	},

	/* MCS  3  */
	{	/* 20 Mhz */ {   26.0f,		/* SGI */   28.9f, },
		/* 40 Mhz */ {   54.0f,		/* SGI */   60.0f, },
	},

	/* MCS  4  */
	{	/* 20 Mhz */ {   39.0f,		/* SGI */   43.3f, },
		/* 40 Mhz */ {   81.0f,		/* SGI */   90.0f, },
	},

	/* MCS  5  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS  6  */
	{	/* 20 Mhz */ {   58.5f,		/* SGI */   65.0f, },
		/* 40 Mhz */ {  121.5f,		/* SGI */  135.0f, },
	},

	/* MCS  7  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {   135.0f,	/* SGI */  150.0f, },
	},

	/* MCS  8  */
	{	/* 20 Mhz */ {   13.0f,		/* SGI */   14.4f, },
		/* 40 Mhz */ {   27.0f,		/* SGI */   30.0f, },
	},

	/* MCS  9  */
	{	/* 20 Mhz */ {   26.0f,		/* SGI */   28.9f, },
		/* 40 Mhz */ {   54.0f,		/* SGI */   60.0f, },
	},

	/* MCS 10  */
	{	/* 20 Mhz */ {   39.0f,		/* SGI */   43.3f, },
		/* 40 Mhz */ {   81.0f,		/* SGI */   90.0f, },
	},

	/* MCS 11  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS 12  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 13  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 14  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 15  */
	{	/* 20 Mhz */ {  130.0f,		/* SGI */  144.4f, },
		/* 40 Mhz */ {  270.0f,		/* SGI */  300.0f, },
	},

	/* MCS 16  */
	{	/* 20 Mhz */ {   19.5f,		/* SGI */   21.7f, },
		/* 40 Mhz */ {   40.5f,		/* SGI */   45.0f, },
	},

	/* MCS 17  */
	{	/* 20 Mhz */ {   39.0f,		/* SGI */   43.3f, },
		/* 40 Mhz */ {   81.0f,		/* SGI */   90.0f, },
	},

	/* MCS 18  */
	{	/* 20 Mhz */ {   58.5f,		/* SGI */   65.0f, },
		/* 40 Mhz */ {  121.5f,		/* SGI */  135.0f, },
	},

	/* MCS 19  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 20  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 21  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 22  */
	{	/* 20 Mhz */ {  175.5f,		/* SGI */  195.0f, },
		/* 40 Mhz */ {  364.5f,		/* SGI */  405.0f, },
	},

	/* MCS 23  */
	{	/* 20 Mhz */ {  195.0f,		/* SGI */  216.7f, },
		/* 40 Mhz */ {  405.0f,		/* SGI */  450.0f, },
	},

	/* MCS 24  */
	{	/* 20 Mhz */ {   26.0f,		/* SGI */   28.9f, },
		/* 40 Mhz */ {   54.0f,		/* SGI */   60.0f, },
	},

	/* MCS 25  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS 26  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 27  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 28  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 29  */
	{	/* 20 Mhz */ {  208.0f,		/* SGI */  231.1f, },
		/* 40 Mhz */ {  432.0f,		/* SGI */  480.0f, },
	},

	/* MCS 30  */
	{	/* 20 Mhz */ {  234.0f,		/* SGI */  260.0f, },
		/* 40 Mhz */ {  486.0f,		/* SGI */  540.0f, },
	},

	/* MCS 31  */
	{	/* 20 Mhz */ {  260.0f,		/* SGI */  288.9f, },
		/* 40 Mhz */ {  540.0f,		/* SGI */  600.0f, },
	},

	/* MCS 32  */
	{	/* 20 Mhz */ {    0.0f,		/* SGI */    0.0f, }, /* not valid */
		/* 40 Mhz */ {    6.0f,		/* SGI */    6.7f, },
	},

	/* MCS 33  */
	{	/* 20 Mhz */ {   39.0f,		/* SGI */   43.3f, },
		/* 40 Mhz */ {   81.0f,		/* SGI */   90.0f, },
	},

	/* MCS 34  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS 35  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {  135.0f,		/* SGI */  150.0f, },
	},

	/* MCS 36  */
	{	/* 20 Mhz */ {   58.5f,		/* SGI */   65.0f, },
		/* 40 Mhz */ {  121.5f,		/* SGI */  135.0f, },
	},

	/* MCS 37  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 38  */
	{	/* 20 Mhz */ {   97.5f,		/* SGI */  108.3f, },
		/* 40 Mhz */ {  202.5f,		/* SGI */  225.0f, },
	},

	/* MCS 39  */
	{	/* 20 Mhz */ {   52.0f,		/* SGI */   57.8f, },
		/* 40 Mhz */ {  108.0f,		/* SGI */  120.0f, },
	},

	/* MCS 40  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {  135.0f,		/* SGI */  150.0f, },
	},

	/* MCS 41  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {  135.0f,		/* SGI */  150.0f, },
	},

	/* MCS 42  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 43  */
	{	/* 20 Mhz */ {   91.0f,		/* SGI */  101.1f, },
		/* 40 Mhz */ {  189.0f,		/* SGI */  210.0f, },
	},

	/* MCS 44  */
	{	/* 20 Mhz */ {   91.0f,		/* SGI */  101.1f, },
		/* 40 Mhz */ {  189.0f,		/* SGI */  210.0f, },
	},

	/* MCS 45  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 46  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 47  */
	{	/* 20 Mhz */ {   97.5f,		/* SGI */  108.3f, },
		/* 40 Mhz */ {  202.5f,		/* SGI */  225.0f, },
	},

	/* MCS 48  */
	{	/* 20 Mhz */ {   97.5f,		/* SGI */  108.3f, },
		/* 40 Mhz */ {  202.5f,		/* SGI */  225.0f, },
	},

	/* MCS 49  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 50  */
	{	/* 20 Mhz */ {  136.5f,		/* SGI */  151.7f, },
		/* 40 Mhz */ {  283.5f,		/* SGI */  315.0f, },
	},

	/* MCS 51  */
	{	/* 20 Mhz */ {  136.5f,		/* SGI */  151.7f, },
		/* 40 Mhz */ {  283.5f,		/* SGI */  315.0f, },
	},

	/* MCS 52  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 53  */
	{	/* 20 Mhz */ {   65.0f,		/* SGI */   72.2f, },
		/* 40 Mhz */ {  135.0f,		/* SGI */  150.0f, },
	},

	/* MCS 54  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 55  */
	{	/* 20 Mhz */ {   91.0f,		/* SGI */  101.1f, },
		/* 40 Mhz */ {  189.0f,		/* SGI */  210.0f, },
	},

	/* MCS 56  */
	{	/* 20 Mhz */ {   78.0f,		/* SGI */   86.7f, },
		/* 40 Mhz */ {  162.0f,		/* SGI */  180.0f, },
	},

	/* MCS 57  */
	{	/* 20 Mhz */ {   91.0f,		/* SGI */  101.1f, },
		/* 40 Mhz */ {  189.0f,		/* SGI */  210.0f, },
	},

	/* MCS 58  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 59  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 60  */
	{	/* 20 Mhz */ {  104.0f,		/* SGI */  115.6f, },
		/* 40 Mhz */ {  216.0f,		/* SGI */  240.0f, },
	},

	/* MCS 61  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 62  */
	{	/* 20 Mhz */ {  130.0f,		/* SGI */  144.4f, },
		/* 40 Mhz */ {  270.0f,		/* SGI */  300.0f, },
	},

	/* MCS 63  */
	{	/* 20 Mhz */ {  130.0f,		/* SGI */  144.4f, },
		/* 40 Mhz */ {  270.0f,		/* SGI */  300.0f, },
	},

	/* MCS 64  */
	{	/* 20 Mhz */ {  143.0f,		/* SGI */  158.9f, },
		/* 40 Mhz */ {  297.0f,		/* SGI */  330.0f, },
	},

	/* MCS 65  */
	{	/* 20 Mhz */ {   97.5f,		/* SGI */  108.3f, },
		/* 40 Mhz */ {  202.5f,		/* SGI */  225.0f, },
	},

	/* MCS 66  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 67  */
	{	/* 20 Mhz */ {  136.5f,		/* SGI */  151.7f, },
		/* 40 Mhz */ {  283.5f,		/* SGI */  315.0f, },
	},

	/* MCS 68  */
	{	/* 20 Mhz */ {  117.0f,		/* SGI */  130.0f, },
		/* 40 Mhz */ {  243.0f,		/* SGI */  270.0f, },
	},

	/* MCS 69  */
	{	/* 20 Mhz */ {  136.5f,		/* SGI */  151.7f, },
		/* 40 Mhz */ {  283.5f,		/* SGI */  315.0f, },
	},

	/* MCS 70  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 71  */
	{	/* 20 Mhz */ {  175.5f,		/* SGI */  195.0f, },
		/* 40 Mhz */ {  364.5f,		/* SGI */  405.0f, },
	},

	/* MCS 72  */
	{	/* 20 Mhz */ {  156.0f,		/* SGI */  173.3f, },
		/* 40 Mhz */ {  324.0f,		/* SGI */  360.0f, },
	},

	/* MCS 73  */
	{	/* 20 Mhz */ {  175.5f,		/* SGI */  195.0f, },
		/* 40 Mhz */ {  364.5f,		/* SGI */  405.0f, },
	},

	/* MCS 74  */
	{	/* 20 Mhz */ {  195.0f,		/* SGI */  216.7f, },
		/* 40 Mhz */ {  405.0f,		/* SGI */  450.0f, },
	},

	/* MCS 75  */
	{	/* 20 Mhz */ {  195.0f,		/* SGI */  216.7f, },
		/* 40 Mhz */ {  405.0f,		/* SGI */  450.0f, },
	},

	/* MCS 76  */
	{	/* 20 Mhz */ {  214.5f,		/* SGI */  238.3f, },
		/* 40 Mhz */ {  445.5f,		/* SGI */  495.0f, },
	},
};

static gint ett_radio = -1;

/*
 * Dissect 802.11 with a variable-length link-layer header and a pseudo-
 * header containing radio information.
 */
static void
dissect_radio (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *ti = NULL;
  proto_tree *radio_tree = NULL;
  float data_rate = 0.0f;
  gboolean have_data_rate = FALSE;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Radio");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Calculate the data rate, if we have the necessary data */
  if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_DATA_RATE) {
    data_rate = pinfo->pseudo_header->ieee_802_11.data_rate * 0.5f;
    have_data_rate = TRUE;
  } else {
    /* Do we have all the fields we need to look it up? */
#define PHDR_802_11_ALL_MCS_FIELDS \
    (PHDR_802_11_HAS_MCS_INDEX | \
     PHDR_802_11_HAS_BANDWIDTH | \
     PHDR_802_11_HAS_SHORT_GI)

    guint bandwidth_40;

    if ((pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_ALL_MCS_FIELDS) == PHDR_802_11_ALL_MCS_FIELDS) {
      bandwidth_40 =
        (pinfo->pseudo_header->ieee_802_11.bandwidth == PHDR_802_11_BANDWIDTH_40_MHZ) ?
         1 : 0;
      if (pinfo->pseudo_header->ieee_802_11.mcs_index < MAX_MCS_INDEX) {
        data_rate = ieee80211_float_htrates[pinfo->pseudo_header->ieee_802_11.mcs_index][bandwidth_40][pinfo->pseudo_header->ieee_802_11.short_gi];
        have_data_rate = TRUE;
      }
    }
  }

  /* Add the radio information to the column information */
  if (have_data_rate)
    col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%.1f", data_rate);

  if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_SIGNAL_PERCENT) {
    /*
     * For tagged Peek files, this is presumably signal strength as a
     * percentage of the maximum, as it is for classic Peek files,
     * i.e. (RXVECTOR RSSI/RXVECTOR RSSI_Max)*100, or, at least, that's
     * what I infer it is, given what the WildPackets note "Converting
     * Signal Strength Percentage to dBm Values" says.
     *
     * It also says that the conversion the percentage to a dBm value is
     * an adapter-dependent process, so, as we don't know what type of
     * adapter was used to do the capture, we can't do the conversion.
     *
     * It's *probably* something similar for other capture file formats.
     */
    col_add_fstr(pinfo->cinfo, COL_RSSI, "%u%%",
          pinfo->pseudo_header->ieee_802_11.signal_percent);
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_radio, tvb, 0, 0, ENC_NA);
    radio_tree = proto_item_add_subtree (ti, ett_radio);

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_MCS_INDEX) {
      proto_tree_add_uint(radio_tree, hf_mcs_index, tvb, 0, 0,
               pinfo->pseudo_header->ieee_802_11.mcs_index);
    }

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_BANDWIDTH) {
      proto_tree_add_uint(radio_tree, hf_bandwidth, tvb, 0, 0,
               pinfo->pseudo_header->ieee_802_11.bandwidth);
    }

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_SHORT_GI) {
      proto_tree_add_boolean(radio_tree, hf_short_gi, tvb, 0, 0,
               pinfo->pseudo_header->ieee_802_11.short_gi);
    }

    if (have_data_rate) {
      proto_tree_add_float_format_value(radio_tree, hf_data_rate, tvb, 0, 0,
               data_rate,
               "%.1f Mb/s",
               data_rate);
    }

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_CHANNEL) {
      proto_tree_add_uint(radio_tree, hf_channel, tvb, 0, 0,
              pinfo->pseudo_header->ieee_802_11.channel);
    }

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_FREQUENCY) {
      proto_tree_add_uint_format_value(radio_tree, hf_frequency, tvb, 0, 0,
              pinfo->pseudo_header->ieee_802_11.frequency,
              "%u MHz",
              pinfo->pseudo_header->ieee_802_11.frequency);
    }

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_SIGNAL_PERCENT) {
      proto_tree_add_uint_format_value(radio_tree, hf_signal_percent, tvb, 0, 0,
              pinfo->pseudo_header->ieee_802_11.signal_percent,
              "%u%%",
              pinfo->pseudo_header->ieee_802_11.signal_percent);
    }

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_SIGNAL_DBM) {
      proto_tree_add_int_format_value(radio_tree, hf_signal_dbm, tvb, 0, 0,
              pinfo->pseudo_header->ieee_802_11.signal_dbm,
              "%d dBm",
              pinfo->pseudo_header->ieee_802_11.signal_dbm);
    }

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_NOISE_PERCENT) {
      proto_tree_add_uint_format_value(radio_tree, hf_noise_percent, tvb, 0, 0,
              pinfo->pseudo_header->ieee_802_11.noise_percent,
              "%u%%",
              pinfo->pseudo_header->ieee_802_11.noise_percent);
    }

    if (pinfo->pseudo_header->ieee_802_11.presence_flags & PHDR_802_11_HAS_NOISE_DBM) {
      proto_tree_add_int_format_value(radio_tree, hf_noise_dbm, tvb, 0, 0,
              pinfo->pseudo_header->ieee_802_11.noise_dbm,
              "%d dBm",
              pinfo->pseudo_header->ieee_802_11.noise_dbm);
    }
  }

  /* dissect the 802.11 header next */
  pinfo->current_proto = "IEEE 802.11";
  call_dissector(ieee80211_handle, tvb, pinfo, tree);
}

static hf_register_info hf_radio[] = {
    {&hf_data_rate,
     {"Data rate", "wlan.data_rate", FT_FLOAT, BASE_NONE, NULL, 0,
      "Data rate (bits/s)", HFILL }},

    {&hf_mcs_index,
     {"MCS index", "wlan.mcs_index", FT_UINT32, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_bandwidth,
     {"Bandwidth", "wlan.bandwidth", FT_UINT32, BASE_DEC, VALS(bandwidth_vals), 0,
      NULL, HFILL }},

    {&hf_short_gi,
     {"Short GI", "wlan.short_gi", FT_BOOLEAN, 0, NULL, 0,
      NULL, HFILL }},

    {&hf_channel,
     {"Channel", "wlan.channel", FT_UINT8, BASE_DEC, NULL, 0,
      "802.11 channel number that this frame was sent/received on", HFILL }},

    {&hf_frequency,
     {"Frequency", "wlan.frequency", FT_UINT16, BASE_DEC, NULL, 0,
      "Center frequency of the 802.11 channel that this frame was sent/received on", HFILL }},

    {&hf_signal_percent,
     {"Signal strength (percentage)", "wlan.signal_dbm", FT_UINT8, BASE_DEC, NULL, 0,
      "Signal strength, as percentage of maximum RSSI", HFILL }},

    {&hf_signal_dbm,
     {"Signal strength (dBm)", "wlan.signal_dbm", FT_INT8, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_noise_percent,
     {"Noise level (percentage)", "wlan.noise_percentage", FT_UINT8, BASE_DEC, NULL, 0,
      NULL, HFILL }},

    {&hf_noise_dbm,
     {"Noise level (dBm)", "wlan.noise_dbm", FT_INT8, BASE_DEC, NULL, 0,
      NULL, HFILL }},
};

static gint *tree_array[] = {
  &ett_radio
};

void proto_register_ieee80211_radio(void)
{
  proto_radio = proto_register_protocol("802.11 radio information", "Radio",
                                        "radio");
  proto_register_field_array(proto_radio, hf_radio, array_length(hf_radio));
  proto_register_subtree_array(tree_array, array_length(tree_array));
}

void proto_reg_handoff_ieee80211_radio(void)
{
  dissector_handle_t radio_handle;

  /* Register handoff to radio-header dissectors */
  radio_handle = create_dissector_handle(dissect_radio, proto_radio);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
                     radio_handle);
  ieee80211_handle = find_dissector("wlan");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
