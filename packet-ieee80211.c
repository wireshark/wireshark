/* packet-ieee80211.c
 * Routines for Wireless LAN (IEEE 802.11) dissection
 * Copyright 2000, Axis Communications AB
 * Inquiries/bugreports should be sent to Johan.Jorgensen@axis.com
 *
 * $Id: packet-ieee80211.c,v 1.104 2004/01/27 08:06:11 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Credits:
 *
 * The following people helped me by pointing out bugs etc. Thank you!
 *
 * Marco Molteni
 * Lena-Marie Nilsson
 * Magnus Hultman-Persson
 */

/*
 * 09/12/2003 - Added dissection of country information tag
 *
 * Ritchie<at>tipsybottle.com
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/bitswap.h>
#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/resolv.h>
#include <epan/strutil.h>
#include "prefs.h"
#include "reassemble.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "packet-ieee80211.h"
#include "etypes.h"
#include "crc32.h"

/* Defragment fragmented 802.11 datagrams */
static gboolean wlan_defragment = TRUE;

/* Check for the presence of the 802.11 FCS */
static gboolean wlan_check_fcs = FALSE;

/* Ignore the WEP bit; assume packet is decrypted */
static gboolean wlan_ignore_wep = FALSE;

/* Tables for reassembly of fragments. */
static GHashTable *wlan_fragment_table = NULL;
static GHashTable *wlan_reassembled_table = NULL;

/* Stuff for the WEP decoder */
static guint num_wepkeys = 0;
static guint8 **wep_keys = NULL;
static int *wep_keylens = NULL;
static void init_wepkeys(void);
static int wep_decrypt(guint8 *buf, guint32 len, int key_override);
static tvbuff_t *try_decrypt_wep(tvbuff_t *tvb, guint32 offset, guint32 len);
#define SSWAP(a,b) {guint8 tmp = s[a]; s[a] = s[b]; s[b] = tmp;}

/* #define USE_ENV */
/* When this is set, an unlimited number of WEP keys can be set in the
   environment:

   ETHEREAL_WEPKEYNUM=##
   ETHEREAL_WEPKEY1=aa:bb:cc:dd:...
   ETHEREAL_WEPKEY2=aa:bab:cc:dd:ee:...

   ... you get the idea.

   otherwise you're limited to specifying four keys in the preference system.
 */

#ifndef USE_ENV
static char *wep_keystr[] = {NULL, NULL, NULL, NULL};
#endif

/* ************************************************************************* */
/*                          Miscellaneous Constants                          */
/* ************************************************************************* */
#define SHORT_STR 256

/* ************************************************************************* */
/*  Define some very useful macros that are used to analyze frame types etc. */
/* ************************************************************************* */
#define COMPOSE_FRAME_TYPE(x) (((x & 0x0C)<< 2)+((x & 0xF0) >> 4))	/* Create key to (sub)type */
#define COOK_PROT_VERSION(x)  ((x) & 0x3)
#define COOK_FRAME_TYPE(x)    (((x) & 0xC) >> 2)
#define COOK_FRAME_SUBTYPE(x) (((x) & 0xF0) >> 4)
#define COOK_ADDR_SELECTOR(x) ((x) & 0x300)
#define COOK_ASSOC_ID(x)      ((x) & 0x3FFF)
#define COOK_FRAGMENT_NUMBER(x) ((x) & 0x000F)
#define COOK_SEQUENCE_NUMBER(x) (((x) & 0xFFF0) >> 4)
#define COOK_FLAGS(x)           (((x) & 0xFF00) >> 8)
#define COOK_DS_STATUS(x)       ((x) & 0x3)
#define COOK_WEP_KEY(x)       (((x) & 0xC0) >> 6)

#define FLAG_TO_DS		0x01
#define FLAG_FROM_DS		0x02
#define FLAG_MORE_FRAGMENTS	0x04
#define FLAG_RETRY		0x08
#define FLAG_POWER_MGT		0x10
#define FLAG_MORE_DATA		0x20
#define FLAG_WEP		0x40
#define FLAG_ORDER		0x80

#define IS_TO_DS(x)            ((x) & FLAG_TO_DS)
#define IS_FROM_DS(x)          ((x) & FLAG_FROM_DS)
#define HAVE_FRAGMENTS(x)      ((x) & FLAG_MORE_FRAGMENTS)
#define IS_RETRY(x)            ((x) & FLAG_RETRY)
#define POWER_MGT_STATUS(x)    ((x) & FLAG_POWER_MGT)
#define HAS_MORE_DATA(x)       ((x) & FLAG_MORE_DATA)
#define IS_WEP(x)              (!wlan_ignore_wep && ((x) & FLAG_WEP))
#define IS_STRICTLY_ORDERED(x) ((x) & FLAG_ORDER)

#define MGT_RESERVED_RANGE(x)  (((x>=0x06)&&(x<=0x07))||((x>=0x0D)&&(x<=0x0F)))
#define CTRL_RESERVED_RANGE(x) ((x>=0x10)&&(x<=0x19))
#define DATA_RESERVED_RANGE(x) ((x>=0x28)&&(x<=0x2f))
#define SPEC_RESERVED_RANGE(x) ((x>=0x30)&&(x<=0x3f))


/* ************************************************************************* */
/*              Constants used to identify cooked frame types                */
/* ************************************************************************* */
#define MGT_FRAME            0x00	/* Frame type is management */
#define CONTROL_FRAME        0x01	/* Frame type is control */
#define DATA_FRAME           0x02	/* Frame type is Data */

#define DATA_SHORT_HDR_LEN     24
#define DATA_LONG_HDR_LEN      30
#define MGT_FRAME_HDR_LEN      24	/* Length of Managment frame-headers */

#define MGT_ASSOC_REQ        0x00	/* Management - association request        */
#define MGT_ASSOC_RESP       0x01	/* Management - association response       */
#define MGT_REASSOC_REQ      0x02	/* Management - reassociation request      */
#define MGT_REASSOC_RESP     0x03	/* Management - reassociation response     */
#define MGT_PROBE_REQ        0x04	/* Management - Probe request              */
#define MGT_PROBE_RESP       0x05	/* Management - Probe response             */
#define MGT_BEACON           0x08	/* Management - Beacon frame               */
#define MGT_ATIM             0x09	/* Management - ATIM                       */
#define MGT_DISASS           0x0A	/* Management - Disassociation             */
#define MGT_AUTHENTICATION   0x0B	/* Management - Authentication             */
#define MGT_DEAUTHENTICATION 0x0C	/* Management - Deauthentication           */

#define CTRL_PS_POLL         0x1A	/* Control - power-save poll               */
#define CTRL_RTS             0x1B	/* Control - request to send               */
#define CTRL_CTS             0x1C	/* Control - clear to send                 */
#define CTRL_ACKNOWLEDGEMENT 0x1D	/* Control - acknowledgement               */
#define CTRL_CFP_END         0x1E	/* Control - contention-free period end    */
#define CTRL_CFP_ENDACK      0x1F	/* Control - contention-free period end/ack */

#define DATA                 0x20	/* Data - Data                             */
#define DATA_CF_ACK          0x21	/* Data - Data + CF acknowledge            */
#define DATA_CF_POLL         0x22	/* Data - Data + CF poll                   */
#define DATA_CF_ACK_POLL     0x23	/* Data - Data + CF acknowledge + CF poll  */
#define DATA_NULL_FUNCTION   0x24	/* Data - Null function (no data)          */
#define DATA_CF_ACK_NOD      0x25	/* Data - CF ack (no data)                 */
#define DATA_CF_POLL_NOD     0x26       /* Data - Data + CF poll (No data)         */
#define DATA_CF_ACK_POLL_NOD 0x27	/* Data - CF ack + CF poll (no data)       */

#define DATA_ADDR_T1         0
#define DATA_ADDR_T2         (FLAG_FROM_DS << 8)
#define DATA_ADDR_T3         (FLAG_TO_DS << 8)
#define DATA_ADDR_T4         ((FLAG_TO_DS|FLAG_FROM_DS) << 8)


/* ************************************************************************* */
/*          Macros used to extract information about fixed fields            */
/* ************************************************************************* */
#define ESS_SET(x) ((x) & 0x0001)
#define IBSS_SET(x) ((x) & 0x0002)



/* ************************************************************************* */
/*        Logical field codes (dissector's encoding of fixed fields)         */
/* ************************************************************************* */
#define FIELD_TIMESTAMP       0x01	/* 64-bit timestamp                       */
#define FIELD_BEACON_INTERVAL 0x02	/* 16-bit beacon interval                 */
#define FIELD_CAP_INFO        0x03	/* Add capability information tree        */
#define FIELD_AUTH_ALG        0x04	/* Authentication algorithm used          */
#define FIELD_AUTH_TRANS_SEQ  0x05	/* Authentication sequence number         */
#define FIELD_CURRENT_AP_ADDR 0x06
#define FIELD_LISTEN_IVAL     0x07
#define FIELD_REASON_CODE     0x08
#define FIELD_ASSOC_ID        0x09
#define FIELD_STATUS_CODE     0x0A

/* ************************************************************************* */
/*        Logical field codes (IEEE 802.11 encoding of tags)                 */
/* ************************************************************************* */
#define TAG_SSID                 0x00
#define TAG_SUPP_RATES           0x01
#define TAG_FH_PARAMETER         0x02
#define TAG_DS_PARAMETER         0x03
#define TAG_CF_PARAMETER         0x04
#define TAG_TIM                  0x05
#define TAG_IBSS_PARAMETER       0x06
#define TAG_COUNTRY_INFO         0x07
#define TAG_FH_HOPPING_PARAMETER 0x08
#define TAG_FH_HOPPING_TABLE     0x09
#define TAG_CHALLENGE_TEXT       0x10
#define TAG_ERP_INFO             0x2A
#define TAG_ERP_INFO_OLD         0x2F	/* IEEE Std 802.11g/D4.0 */
#define TAG_EXT_SUPP_RATES       0x32
#define TAG_VENDOR_SPECIFIC_IE	 0xDD

#define WPA_OUI	"\x00\x50\xF2"

/* ************************************************************************* */
/*                         Frame types, and their names                      */
/* ************************************************************************* */
static const value_string frame_type_subtype_vals[] = {
	{MGT_ASSOC_REQ,        "Association Request"},
	{MGT_ASSOC_RESP,       "Association Response"},
	{MGT_REASSOC_REQ,      "Reassociation Request"},
	{MGT_REASSOC_RESP,     "Reassociation Response"},
	{MGT_PROBE_REQ,        "Probe Request"},
	{MGT_PROBE_RESP,       "Probe Response"},
	{MGT_BEACON,           "Beacon frame"},
	{MGT_ATIM,             "ATIM"},
	{MGT_DISASS,           "Dissassociate"},
	{MGT_AUTHENTICATION,   "Authentication"},
	{MGT_DEAUTHENTICATION, "Deauthentication"},
	{CTRL_PS_POLL,         "Power-Save poll"},
	{CTRL_RTS,             "Request-to-send"},
	{CTRL_CTS,             "Clear-to-send"},
	{CTRL_ACKNOWLEDGEMENT, "Acknowledgement"},
	{CTRL_CFP_END,         "CF-End (Control-frame)"},
	{CTRL_CFP_ENDACK,      "CF-End + CF-Ack (Control-frame)"},
	{DATA,                 "Data"},
	{DATA_CF_ACK,          "Data + CF-Acknowledgement"},
	{DATA_CF_POLL,         "Data + CF-Poll"},
	{DATA_CF_ACK_POLL,     "Data + CF-Acknowledgement/Poll"},
	{DATA_NULL_FUNCTION,   "Null function (No data)"},
	{DATA_CF_ACK_NOD,      "Data + Acknowledgement (No data)"},
	{DATA_CF_POLL_NOD,     "Data + CF-Poll (No data)"},
	{DATA_CF_ACK_POLL_NOD, "Data + CF-Acknowledgement/Poll (No data)"},
	{0,                    NULL}
};

static int proto_wlan = -1;

/* ************************************************************************* */
/*                Header field info values for radio information             */
/* ************************************************************************* */
static int hf_data_rate = -1;
static int hf_channel = -1;
static int hf_signal_strength = -1;

/* ************************************************************************* */
/*                Header field info values for FC-field                      */
/* ************************************************************************* */
static int hf_fc_field = -1;
static int hf_fc_proto_version = -1;
static int hf_fc_frame_type = -1;
static int hf_fc_frame_subtype = -1;
static int hf_fc_frame_type_subtype = -1;

static int hf_fc_flags = -1;
static int hf_fc_to_ds = -1;
static int hf_fc_from_ds = -1;
static int hf_fc_data_ds = -1;

static int hf_fc_more_frag = -1;
static int hf_fc_retry = -1;
static int hf_fc_pwr_mgt = -1;
static int hf_fc_more_data = -1;
static int hf_fc_wep = -1;
static int hf_fc_order = -1;


/* ************************************************************************* */
/*                   Header values for Duration/ID field                     */
/* ************************************************************************* */
static int hf_did_duration = -1;
static int hf_assoc_id = -1;


/* ************************************************************************* */
/*         Header values for different address-fields (all 4 of them)        */
/* ************************************************************************* */
static int hf_addr_da = -1;	/* Destination address subfield */
static int hf_addr_sa = -1;	/* Source address subfield */
static int hf_addr_ra = -1;	/* Receiver address subfield */
static int hf_addr_ta = -1;	/* Transmitter address subfield */
static int hf_addr_bssid = -1;	/* address is bssid */

static int hf_addr = -1;	/* Source or destination address subfield */


/* ************************************************************************* */
/*                Header values for sequence number field                    */
/* ************************************************************************* */
static int hf_frag_number = -1;
static int hf_seq_number = -1;

/* ************************************************************************* */
/*                   Header values for Frame Check field                     */
/* ************************************************************************* */
static int hf_fcs = -1;

/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int hf_fragments = -1;
static int hf_fragment = -1;
static int hf_fragment_overlap = -1;
static int hf_fragment_overlap_conflict = -1;
static int hf_fragment_multiple_tails = -1;
static int hf_fragment_too_long_fragment = -1;
static int hf_fragment_error = -1;
static int hf_reassembled_in = -1;


static int proto_wlan_mgt = -1;
/* ************************************************************************* */
/*                      Fixed fields found in mgt frames                     */
/* ************************************************************************* */
static int ff_auth_alg = -1;	/* Authentication algorithm field            */
static int ff_auth_seq = -1;	/* Authentication transaction sequence       */
static int ff_current_ap = -1;	/* Current AP MAC address                    */
static int ff_listen_ival = -1;	/* Listen interval fixed field               */
static int ff_timestamp = -1;	/* 64 bit timestamp                          */
static int ff_beacon_interval = -1;	/* 16 bit Beacon interval            */
static int ff_assoc_id = -1;	/* 16 bit AID field                          */
static int ff_reason = -1;	/* 16 bit reason code                        */
static int ff_status_code = -1;	/* Status code                               */

/* ************************************************************************* */
/*            Flags found in the capability field (fixed field)              */
/* ************************************************************************* */
static int ff_capture = -1;
static int ff_cf_ess = -1;
static int ff_cf_ibss = -1;
static int ff_cf_sta_poll = -1; /* CF pollable status for a STA            */
static int ff_cf_ap_poll = -1;	/* CF pollable status for an AP            */
static int ff_cf_privacy = -1;
static int ff_cf_preamble = -1;
static int ff_cf_pbcc = -1;
static int ff_cf_agility = -1;
static int ff_short_slot_time = -1;
static int ff_dsss_ofdm = -1;

/* ************************************************************************* */
/*                       Tagged value format fields                          */
/* ************************************************************************* */
static int tag_number = -1;
static int tag_length = -1;
static int tag_interpretation = -1;



static int hf_fixed_parameters = -1;	/* Protocol payload for management frames */
static int hf_tagged_parameters = -1;	/* Fixed payload item */
static int hf_wep_iv = -1;
static int hf_wep_key = -1;
static int hf_wep_icv = -1;

/* ************************************************************************* */
/*                               Protocol trees                              */
/* ************************************************************************* */
static gint ett_80211 = -1;
static gint ett_proto_flags = -1;
static gint ett_cap_tree = -1;
static gint ett_fc_tree = -1;
static gint ett_fragments = -1;
static gint ett_fragment = -1;

static gint ett_80211_mgt = -1;
static gint ett_fixed_parameters = -1;
static gint ett_tagged_parameters = -1;
static gint ett_wep_parameters = -1;

static const fragment_items frag_items = {
	&ett_fragment,
	&ett_fragments,
	&hf_fragments,
	&hf_fragment,
	&hf_fragment_overlap,
	&hf_fragment_overlap_conflict,
	&hf_fragment_multiple_tails,
	&hf_fragment_too_long_fragment,
	&hf_fragment_error,
	&hf_reassembled_in,
	"fragments"
};

static dissector_handle_t llc_handle;
static dissector_handle_t ipx_handle;
static dissector_handle_t data_handle;

/* ************************************************************************* */
/*            Return the length of the current header (in bytes)             */
/* ************************************************************************* */
static int
find_header_length (guint16 fcf)
{
  switch (COOK_FRAME_TYPE (fcf)) {

  case MGT_FRAME:
    return MGT_FRAME_HDR_LEN;

  case CONTROL_FRAME:
    switch (COMPOSE_FRAME_TYPE (fcf)) {

    case CTRL_CTS:
    case CTRL_ACKNOWLEDGEMENT:
      return 10;

    case CTRL_RTS:
    case CTRL_PS_POLL:
    case CTRL_CFP_END:
    case CTRL_CFP_ENDACK:
      return 16;
    }
    return 4;	/* XXX */

  case DATA_FRAME:
    return (COOK_ADDR_SELECTOR(fcf) == DATA_ADDR_T4) ? DATA_LONG_HDR_LEN :
						       DATA_SHORT_HDR_LEN;
  default:
    return 4;	/* XXX */
  }
}


/* ************************************************************************* */
/*          This is the capture function used to update packet counts        */
/* ************************************************************************* */
static void
capture_ieee80211_common (const guchar * pd, int offset, int len,
			  packet_counts * ld, gboolean fixed_length_header)
{
  guint16 fcf, hdr_length;

  if (!BYTES_ARE_IN_FRAME(offset, len, 2)) {
    ld->other++;
    return;
  }

  fcf = pletohs (&pd[0]);

  if (IS_WEP(COOK_FLAGS(fcf)))
    {
      ld->other++;
      return;
    }

  switch (COMPOSE_FRAME_TYPE (fcf))
    {

    case DATA:			/* We got a data frame */
    case DATA_CF_ACK:		/* Data with ACK */
    case DATA_CF_POLL:
    case DATA_CF_ACK_POLL:
      if (fixed_length_header)
        hdr_length = DATA_LONG_HDR_LEN;
      else
        hdr_length = find_header_length (fcf);
      /* I guess some bridges take Netware Ethernet_802_3 frames,
         which are 802.3 frames (with a length field rather than
         a type field, but with no 802.2 header in the payload),
         and just stick the payload into an 802.11 frame.  I've seen
         captures that show frames of that sort.

         This means we have to do the same check for Netware 802.3 -
         or, if you will, "Netware 802.11" - that we do in the
         Ethernet dissector, i.e. checking for 0xffff as the first
         four bytes of the payload and, if we find it, treating it
         as an IPX frame. */
      if (!BYTES_ARE_IN_FRAME(offset+hdr_length, len, 2)) {
        ld->other++;
        return;
      }
      if (pd[offset+hdr_length] == 0xff && pd[offset+hdr_length+1] == 0xff) {
        capture_ipx (ld);
      }
      else {
        capture_llc (pd, offset + hdr_length, len, ld);
      }
      break;

    default:
      ld->other++;
      break;
    }
}

/*
 * Handle 802.11 with a variable-length link-layer header.
 */
void
capture_ieee80211 (const guchar * pd, int offset, int len, packet_counts * ld)
{
  capture_ieee80211_common (pd, offset, len, ld, FALSE);
}

/*
 * Handle 802.11 with a fixed-length link-layer header (padded to the
 * maximum length).
 */
void
capture_ieee80211_fixed (const guchar * pd, int offset, int len, packet_counts * ld)
{
  capture_ieee80211_common (pd, offset, len, ld, TRUE);
}


/* ************************************************************************* */
/*          Add the subtree used to store the fixed parameters               */
/* ************************************************************************* */
static proto_tree *
get_fixed_parameter_tree (proto_tree * tree, tvbuff_t *tvb, int start, int size)
{
  proto_item *fixed_fields;
  fixed_fields =
    proto_tree_add_uint_format (tree, hf_fixed_parameters, tvb, start,
				size, size, "Fixed parameters (%d bytes)",
				size);

  return proto_item_add_subtree (fixed_fields, ett_fixed_parameters);
}


/* ************************************************************************* */
/*            Add the subtree used to store tagged parameters                */
/* ************************************************************************* */
static proto_tree *
get_tagged_parameter_tree (proto_tree * tree, tvbuff_t *tvb, int start, int size)
{
  proto_item *tagged_fields;

  tagged_fields = proto_tree_add_uint_format (tree, hf_tagged_parameters,
					      tvb,
					      start,
					      size,
					      size,
					      "Tagged parameters (%d bytes)",
					      size);

  return proto_item_add_subtree (tagged_fields, ett_tagged_parameters);
}


/* ************************************************************************* */
/*              Dissect and add fixed mgmt fields to protocol tree           */
/* ************************************************************************* */
static void
add_fixed_field (proto_tree * tree, tvbuff_t * tvb, int offset, int lfcode)
{
  const guint8 *dataptr;
  char out_buff[SHORT_STR];
  guint16 capability;
  proto_item *cap_item;
  static proto_tree *cap_tree;
  double temp_double;

  switch (lfcode)
    {
    case FIELD_TIMESTAMP:
      dataptr = tvb_get_ptr (tvb, offset, 8);
      memset (out_buff, 0, SHORT_STR);
      snprintf (out_buff, SHORT_STR, "0x%02X%02X%02X%02X%02X%02X%02X%02X",
		dataptr[7],
		dataptr[6],
		dataptr[5],
		dataptr[4],
		dataptr[3],
		dataptr[2],
		dataptr[1],
		dataptr[0]);

      proto_tree_add_string (tree, ff_timestamp, tvb, offset, 8, out_buff);
      break;

    case FIELD_BEACON_INTERVAL:
      temp_double = (double) tvb_get_letohs (tvb, offset);
      temp_double = temp_double * 1024 / 1000000;
      proto_tree_add_double_format (tree, ff_beacon_interval, tvb, offset, 2,
				    temp_double,"Beacon Interval: %f [Seconds]",
				    temp_double);
      break;


    case FIELD_CAP_INFO:
      capability = tvb_get_letohs (tvb, offset);

      cap_item = proto_tree_add_uint_format (tree, ff_capture,
					     tvb, offset, 2,
					     capability,
					     "Capability Information: 0x%04X",
					     capability);
      cap_tree = proto_item_add_subtree (cap_item, ett_cap_tree);
      proto_tree_add_boolean (cap_tree, ff_cf_ess, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_ibss, tvb, offset, 2,
			      capability);
      if (ESS_SET (capability) != 0)	/* This is an AP */
	proto_tree_add_uint (cap_tree, ff_cf_ap_poll, tvb, offset, 2,
			     capability);

      else			/* This is a STA */
	proto_tree_add_uint (cap_tree, ff_cf_sta_poll, tvb, offset, 2,
			     capability);
      proto_tree_add_boolean (cap_tree, ff_cf_privacy, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_preamble, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_pbcc, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_cf_agility, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_short_slot_time, tvb, offset, 2,
			      capability);
      proto_tree_add_boolean (cap_tree, ff_dsss_ofdm, tvb, offset, 2,
			      capability);
      break;

    case FIELD_AUTH_ALG:
      proto_tree_add_item (tree, ff_auth_alg, tvb, offset, 2, TRUE);
      break;

    case FIELD_AUTH_TRANS_SEQ:
      proto_tree_add_item (tree, ff_auth_seq, tvb, offset, 2, TRUE);
      break;

    case FIELD_CURRENT_AP_ADDR:
      proto_tree_add_item (tree, ff_current_ap, tvb, offset, 6, FALSE);
      break;

    case FIELD_LISTEN_IVAL:
      proto_tree_add_item (tree, ff_listen_ival, tvb, offset, 2, TRUE);
      break;

    case FIELD_REASON_CODE:
      proto_tree_add_item (tree, ff_reason, tvb, offset, 2, TRUE);
      break;

    case FIELD_ASSOC_ID:
      proto_tree_add_item (tree, ff_assoc_id, tvb, offset, 2, TRUE);
      break;

    case FIELD_STATUS_CODE:
      proto_tree_add_item (tree, ff_status_code, tvb, offset, 2, TRUE);
      break;
    }
}

static char *wpa_cipher_str[] = 
{
  "NONE",
  "WEP (40-bit)",
  "TKIP",
  "AES (OCB)",
  "AES (CCM)",
  "WEP (104-bit)",
};

static char *
wpa_cipher_idx2str(guint idx)
{
  if (idx < sizeof(wpa_cipher_str)/sizeof(wpa_cipher_str[0]))
    return wpa_cipher_str[idx];
  return "UNKNOWN";
}

static char *wpa_keymgmt_str[] = 
{
  "NONE",
  "WPA",
  "PSK",
};

static char *
wpa_keymgmt_idx2str(guint idx)
{
  if (idx < sizeof(wpa_keymgmt_str)/sizeof(wpa_keymgmt_str[0]))
    return wpa_keymgmt_str[idx];
  return "UNKNOWN";
}

static void 
dissect_vendor_specific_ie(proto_tree * tree, tvbuff_t * tvb, int offset,
		guint32 tag_len, const guint8 *tag_val)
{
      guint32 tag_val_off = 0;
      char out_buff[SHORT_STR];
      int i;
	
      if (tag_val_off + 6 <= tag_len && !memcmp(tag_val, WPA_OUI"\x01", 4)) {
        snprintf(out_buff, SHORT_STR, "WPA IE, type %u, version %u",
                  tag_val[tag_val_off + 3], pletohs(&tag_val[tag_val_off + 4]));
        proto_tree_add_string(tree, tag_interpretation, tvb, offset, 6, out_buff);
        offset += 6;
        tag_val_off += 6;
        if (tag_val_off + 4 <= tag_len) {
          /* multicast cipher suite */
          if (!memcmp(&tag_val[tag_val_off], WPA_OUI, 3)) {
            snprintf(out_buff, SHORT_STR, "Multicast cipher suite: %s", 
                      wpa_cipher_idx2str(tag_val[tag_val_off + 3]));
            proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
            offset += 4;
            tag_val_off += 4;
            /* unicast cipher suites */
            if (tag_val_off + 2 <= tag_len) {
              snprintf(out_buff, SHORT_STR, "# of unicast cipher suites: %u",
                        pletohs(tag_val + tag_val_off));
              proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
              offset += 2;
              tag_val_off += 2;
              i = 1;
              while (tag_val_off + 4 <= tag_len) {
                if (!memcmp(&tag_val[tag_val_off], WPA_OUI, 3)) {
                  snprintf(out_buff, SHORT_STR, "Unicast cipher suite %u: %s", 
                            i, wpa_cipher_idx2str(tag_val[tag_val_off + 3]));
                  proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
                  offset += 4;
                  tag_val_off += 4;
                  i ++;
                }
                else
                  break;
              }
	      /* authenticated key management suites */
              if (tag_val_off + 2 <= tag_len) {
                snprintf(out_buff, SHORT_STR, "# of auth key management suites: %u",
                          pletohs(tag_val + tag_val_off));
                proto_tree_add_string(tree, tag_interpretation, tvb, offset, 2, out_buff);
                offset += 2;
                tag_val_off += 2;
                i = 1;
                while (tag_val_off + 4 <= tag_len) {
                  if (!memcmp(&tag_val[tag_val_off], WPA_OUI, 3)) {
                    snprintf(out_buff, SHORT_STR, "auth key management suite %u: %s", 
                              i, wpa_keymgmt_idx2str(tag_val[tag_val_off + 3]));
                    proto_tree_add_string(tree, tag_interpretation, tvb, offset, 4, out_buff);
                    offset += 4;
                    tag_val_off += 4;
                    i ++;
                  }
                  else
                    break;
                }
              }
            }
          }
        }
        if (tag_val_off < tag_len)
          proto_tree_add_string(tree, tag_interpretation, tvb,
                                 offset, tag_len - tag_val_off, "Not interpreted");
      }
      else
        proto_tree_add_string(tree, tag_interpretation, 
        		tvb, offset, tag_len, "Not interpreted");
}

/* ************************************************************************* */
/*           Dissect and add tagged (optional) fields to proto tree          */
/* ************************************************************************* */

static const value_string tag_num_vals[] = {
	{ TAG_SSID,                 "SSID parameter set" },
	{ TAG_SUPP_RATES,           "Supported Rates" },
	{ TAG_FH_PARAMETER,         "FH Parameter set" },
	{ TAG_DS_PARAMETER,         "DS Parameter set" },
	{ TAG_CF_PARAMETER,         "CF Parameter set" },
	{ TAG_TIM,                  "(TIM) Traffic Indication Map" },
	{ TAG_IBSS_PARAMETER,       "IBSS Parameter set" },
	{ TAG_COUNTRY_INFO,         "Country Information" },
	{ TAG_FH_HOPPING_PARAMETER, "Hopping Pattern Parameters" },
	{ TAG_CHALLENGE_TEXT,       "Challenge text" },
	{ TAG_ERP_INFO,             "ERP Information" },
	{ TAG_ERP_INFO_OLD,         "ERP Information" },
	{ TAG_EXT_SUPP_RATES,       "Extended Supported Rates" },
	{ TAG_VENDOR_SPECIFIC_IE,   "Vendor Specific" },
	{ 0,                        NULL }
};

static const value_string environment_vals[] = {
	{ 0x20, "Any" },
	{ 0x4f, "Outdoor" },
	{ 0x49, "Indoor" },
	{ 0,    NULL }
};

static int
add_tagged_field (proto_tree * tree, tvbuff_t * tvb, int offset)
{
  const guint8 *tag_data_ptr;
  guint32 tag_no, tag_len;
  unsigned int i;
  int n, ret;
  char out_buff[SHORT_STR];


  tag_no = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint_format (tree, tag_number, tvb, offset, 1, tag_no,
			      "Tag Number: %u (%s)",
			      tag_no,
			      val_to_str(tag_no, tag_num_vals,
					 (tag_no >= 17 && tag_no <= 31) ?
					 "Reserved for challenge text" :
					 "Reserved tag number"));

  tag_len = tvb_get_guint8(tvb, offset + 1);
  proto_tree_add_uint (tree, tag_length, tvb, offset + 1, 1, tag_len);

  tag_data_ptr = tvb_get_ptr (tvb, offset + 2, tag_len);

  switch (tag_no)
    {


    case TAG_SSID:
      memset (out_buff, 0, SHORT_STR);

      memcpy (out_buff, tag_data_ptr, (size_t) tag_len);
      out_buff[tag_len + 1] = 0;

      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      break;



    case TAG_SUPP_RATES:
    case TAG_EXT_SUPP_RATES:
      memset (out_buff, 0, SHORT_STR);
      strcpy (out_buff, "Supported rates: ");
      n = strlen (out_buff);

      for (i = 0; i < tag_len && n < SHORT_STR; i++)
	{
	    ret = snprintf (out_buff + n, SHORT_STR - n, "%2.1f%s ",
			   (tag_data_ptr[i] & 0x7F) * 0.5,
			   (tag_data_ptr[i] & 0x80) ? "(B)" : "");
	    if (ret == -1 || ret >= SHORT_STR - n) {
	      /* Some versions of snprintf return -1 if they'd truncate
	         the output. Others return <buf_size> or greater.  */
	      break;
	    }
	    n += ret;
	}
      if (n < SHORT_STR)
	snprintf (out_buff + n, SHORT_STR - n, "[Mbit/sec]");

      out_buff[SHORT_STR-1] = '\0';
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      break;



    case TAG_FH_PARAMETER:
      memset (out_buff, 0, SHORT_STR);

      snprintf (out_buff, SHORT_STR,
		"Dwell time 0x%04X, Hop Set %2d, Hop Pattern %2d, "
		"Hop Index %2d", pletohs (tag_data_ptr), tag_data_ptr[2],
		tag_data_ptr[3], tag_data_ptr[4]);

      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      break;



    case TAG_DS_PARAMETER:
      memset (out_buff, 0, SHORT_STR);

      snprintf (out_buff, SHORT_STR, "Current Channel: %u", tag_data_ptr[0]);
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      break;


    case TAG_CF_PARAMETER:
      memset (out_buff, 0, SHORT_STR);

      snprintf (out_buff, SHORT_STR,
		"CFP count %u, CFP period %u, CFP max duration %u, "
		"CFP Remaining %u", tag_data_ptr[0], tag_data_ptr[1],
		pletohs (tag_data_ptr + 2), pletohs (tag_data_ptr + 4));

      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      break;


    case TAG_TIM:
      memset (out_buff, 0, SHORT_STR);
      snprintf (out_buff, SHORT_STR,
		"DTIM count %u, DTIM period %u, Bitmap control 0x%X, "
		"(Bitmap suppressed)", tag_data_ptr[0], tag_data_ptr[1],
		tag_data_ptr[2]);
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      break;



    case TAG_IBSS_PARAMETER:
      memset (out_buff, 0, SHORT_STR);
      snprintf (out_buff, SHORT_STR, "ATIM window 0x%X",
		pletohs (tag_data_ptr));

      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);
      break;


    case TAG_COUNTRY_INFO:
      memset (out_buff, 0, SHORT_STR);

      snprintf (out_buff, SHORT_STR, "Country Code: %c%c, %s Environment",
               tag_data_ptr[0], tag_data_ptr[1], 
               val_to_str(tag_data_ptr[2], environment_vals,"Unknown (0x%02x)"));

      n = strlen (out_buff);

      for (i = 3; (i + 3) <= tag_len && n < SHORT_STR; i += 3)
      { 
        ret = snprintf(out_buff + n, SHORT_STR - n,
                       ", Start Channel: %u, Channels: %u, Max TX Power: %d dBm",
                       tag_data_ptr[i], tag_data_ptr[i + 1],
                       (gint)tag_data_ptr[i + 2]);

        if (ret == -1 || ret >= SHORT_STR - n) {
          /* Some versions of snprintf return -1 if they'd truncate
             the output. Others return <buf_size> or greater.  */
          break;
        }
        n += ret;
      }

      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,tag_len, out_buff);
      break;


    case TAG_FH_HOPPING_PARAMETER:
      memset (out_buff, 0, SHORT_STR);
      snprintf (out_buff, SHORT_STR, "Prime Radix: %u, Number of Channels: %u", 
                       tag_data_ptr[0], tag_data_ptr[1]);
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2, tag_len, out_buff);
			     

      break;


    case TAG_CHALLENGE_TEXT:
      memset (out_buff, 0, SHORT_STR);
      snprintf (out_buff, SHORT_STR, "Challenge text: %.47s", tag_data_ptr);
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);

      break;



    case TAG_ERP_INFO:
    case TAG_ERP_INFO_OLD:
      memset (out_buff, 0, SHORT_STR);

      snprintf (out_buff, SHORT_STR,
		"ERP info: 0x%x (%sNon-ERP STAs, %suse protection, %s preambles)",
		tag_data_ptr[0],
		tag_data_ptr[0] & 0x01 ? "" : "no ",
		tag_data_ptr[0] & 0x02 ? "" : "do not ",
		tag_data_ptr[0] & 0x04 ? "short or long": "long");
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, out_buff);

      break;

    case TAG_VENDOR_SPECIFIC_IE:
      dissect_vendor_specific_ie(tree, tvb, offset + 2, tag_len,
				 tag_data_ptr);
      break;


    default:
      proto_tree_add_string (tree, tag_interpretation, tvb, offset + 2,
			     tag_len, "Not interpreted");
      break;
    }

  return tag_len + 2;
}

void
ieee_80211_add_tagged_parameters (tvbuff_t * tvb, int offset, proto_tree * tree,
       int tagged_parameters_len)
{
  int next_len;

  while (tagged_parameters_len > 0) {
    if ((next_len=add_tagged_field (tree, tvb, offset))==0)
      break;
    if (next_len > tagged_parameters_len) {
      /* XXX - flag this as an error? */
      next_len = tagged_parameters_len;
    }
    offset += next_len;
    tagged_parameters_len -= next_len;
  }
}

/* ************************************************************************* */
/*                     Dissect 802.11 management frame                       */
/* ************************************************************************* */
static void
dissect_ieee80211_mgt (guint16 fcf, tvbuff_t * tvb, packet_info * pinfo,
	proto_tree * tree)
{
  proto_item *ti = NULL;
  proto_tree *mgt_tree;
  proto_tree *fixed_tree;
  proto_tree *tagged_tree;
  int offset;
  int tagged_parameter_tree_len;

  CHECK_DISPLAY_AS_X(data_handle,proto_wlan_mgt, tvb, pinfo, tree);

  if (tree)
    {
      ti = proto_tree_add_item (tree, proto_wlan_mgt, tvb, 0, -1, FALSE);
      mgt_tree = proto_item_add_subtree (ti, ett_80211_mgt);

      switch (COMPOSE_FRAME_TYPE(fcf))
	{

	case MGT_ASSOC_REQ:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 4);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_LISTEN_IVAL);

	  offset = 4;	/* Size of fixed fields */
	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);

	  ieee_80211_add_tagged_parameters (tvb, offset, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_ASSOC_RESP:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 6);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_STATUS_CODE);
	  add_fixed_field (fixed_tree, tvb, 4, FIELD_ASSOC_ID);

	  offset = 6;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);

	  ieee_80211_add_tagged_parameters (tvb, offset, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_REASSOC_REQ:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 10);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_LISTEN_IVAL);
	  add_fixed_field (fixed_tree, tvb, 4, FIELD_CURRENT_AP_ADDR);

	  offset = 10;	/* Size of fixed fields */
	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);

	  ieee_80211_add_tagged_parameters (tvb, offset, tagged_tree,
	      tagged_parameter_tree_len);
	  break;

	case MGT_REASSOC_RESP:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 10);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_CAP_INFO);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_STATUS_CODE);
	  add_fixed_field (fixed_tree, tvb, 4, FIELD_ASSOC_ID);

	  offset = 6;	/* Size of fixed fields */
	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);

	  ieee_80211_add_tagged_parameters (tvb, offset, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_PROBE_REQ:
	  offset = 0;
	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);

	  ieee_80211_add_tagged_parameters (tvb, offset, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_PROBE_RESP:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 12);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_TIMESTAMP);
	  add_fixed_field (fixed_tree, tvb, 8, FIELD_BEACON_INTERVAL);
	  add_fixed_field (fixed_tree, tvb, 10, FIELD_CAP_INFO);

	  offset = 12;	/* Size of fixed fields */
	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);

	  ieee_80211_add_tagged_parameters (tvb, offset, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_BEACON:		/* Dissect protocol payload fields  */
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 12);

	  add_fixed_field (fixed_tree, tvb, 0, FIELD_TIMESTAMP);
	  add_fixed_field (fixed_tree, tvb, 8, FIELD_BEACON_INTERVAL);
	  add_fixed_field (fixed_tree, tvb, 10, FIELD_CAP_INFO);

	  offset = 12;	/* Size of fixed fields */
	  tagged_parameter_tree_len =
	      tvb_reported_length_remaining(tvb, offset);
	  tagged_tree = get_tagged_parameter_tree (mgt_tree, tvb, offset,
						   tagged_parameter_tree_len);

	  ieee_80211_add_tagged_parameters (tvb, offset, tagged_tree,
	      tagged_parameter_tree_len);
	  break;


	case MGT_ATIM:
	  break;


	case MGT_DISASS:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_REASON_CODE);
	  break;


	case MGT_AUTHENTICATION:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 6);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_AUTH_ALG);
	  add_fixed_field (fixed_tree, tvb, 2, FIELD_AUTH_TRANS_SEQ);
	  add_fixed_field (fixed_tree, tvb, 4, FIELD_STATUS_CODE);

	  offset = 6;	/* Size of fixed fields */

	  tagged_parameter_tree_len =
		  tvb_reported_length_remaining(tvb, offset);
	  if (tagged_parameter_tree_len != 0)
	    {
	      tagged_tree = get_tagged_parameter_tree (mgt_tree,
						       tvb,
						       offset,
						       tagged_parameter_tree_len);

	      ieee_80211_add_tagged_parameters (tvb, offset, tagged_tree,
		tagged_parameter_tree_len);
	    }
	  break;


	case MGT_DEAUTHENTICATION:
	  fixed_tree = get_fixed_parameter_tree (mgt_tree, tvb, 0, 2);
	  add_fixed_field (fixed_tree, tvb, 0, FIELD_REASON_CODE);
	  break;
	}
    }
}

static void
set_src_addr_cols(packet_info *pinfo, const guint8 *addr, char *type)
{
  if (check_col(pinfo->cinfo, COL_RES_DL_SRC))
    col_add_fstr(pinfo->cinfo, COL_RES_DL_SRC, "%s (%s)",
		    get_ether_name(addr), type);
  if (check_col(pinfo->cinfo, COL_UNRES_DL_SRC))
    col_add_fstr(pinfo->cinfo, COL_UNRES_DL_SRC, "%s (%s)",
		     ether_to_str(addr), type);
}

static void
set_dst_addr_cols(packet_info *pinfo, const guint8 *addr, char *type)
{
  if (check_col(pinfo->cinfo, COL_RES_DL_DST))
    col_add_fstr(pinfo->cinfo, COL_RES_DL_DST, "%s (%s)",
		     get_ether_name(addr), type);
  if (check_col(pinfo->cinfo, COL_UNRES_DL_DST))
    col_add_fstr(pinfo->cinfo, COL_UNRES_DL_DST, "%s (%s)",
		     ether_to_str(addr), type);
}

/* ************************************************************************* */
/*                          Dissect 802.11 frame                             */
/* ************************************************************************* */
static void
dissect_ieee80211_common (tvbuff_t * tvb, packet_info * pinfo,
			  proto_tree * tree, gboolean fixed_length_header,
			  gboolean has_radio_information, gint fcs_len,
			  gboolean wlan_broken_fc)
{
  guint16 fcf, flags, frame_type_subtype;
  guint16 seq_control;
  guint32 seq_number, frag_number;
  gboolean more_frags;
  const guint8 *src = NULL, *dst = NULL;
  proto_item *ti = NULL;
  proto_item *flag_item;
  proto_item *fc_item;
  proto_tree *hdr_tree = NULL;
  proto_tree *flag_tree;
  proto_tree *fc_tree;
  guint16 hdr_len;
  gboolean has_fcs;
  gint len, reported_len;
  gboolean save_fragmented;
  tvbuff_t *volatile next_tvb = NULL;
  guint32 addr_type;
  volatile gboolean is_802_2;

  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "IEEE 802.11");
  if (check_col (pinfo->cinfo, COL_INFO))
    col_clear (pinfo->cinfo, COL_INFO);

  fcf = tvb_get_letohs (tvb, 0);
  if (wlan_broken_fc) {
    /* Swap bytes */
    fcf = ((fcf & 0xff) << 8) | (((fcf & 0xff00) >> 8) & 0xff);
  }
  if (fixed_length_header)
    hdr_len = DATA_LONG_HDR_LEN;
  else
    hdr_len = find_header_length (fcf);
  frame_type_subtype = COMPOSE_FRAME_TYPE(fcf);

  if (check_col (pinfo->cinfo, COL_INFO))
      col_set_str (pinfo->cinfo, COL_INFO,
          val_to_str(frame_type_subtype, frame_type_subtype_vals,
              "Unrecognized (Reserved frame)"));

  flags = COOK_FLAGS (fcf);
  more_frags = HAVE_FRAGMENTS (flags);

  /* Add the radio information, if present, and the FC to the current tree */
  if (tree)
    {
      ti = proto_tree_add_protocol_format (tree, proto_wlan, tvb, 0, hdr_len,
					   "IEEE 802.11");
      hdr_tree = proto_item_add_subtree (ti, ett_80211);

      if (has_radio_information) {
	proto_tree_add_uint_format(hdr_tree, hf_data_rate,
				   tvb, 0, 0,
				   pinfo->pseudo_header->ieee_802_11.data_rate,
				   "Data Rate: %g mb/s",
				   .5*pinfo->pseudo_header->ieee_802_11.data_rate);

	proto_tree_add_uint(hdr_tree, hf_channel,
			    tvb, 0, 0,
			    pinfo->pseudo_header->ieee_802_11.channel);

	proto_tree_add_uint_format(hdr_tree, hf_signal_strength,
				   tvb, 0, 0,
				   pinfo->pseudo_header->ieee_802_11.signal_level,
				   "Signal Strength: %u%%",
				   pinfo->pseudo_header->ieee_802_11.signal_level);
      }

      proto_tree_add_uint (hdr_tree, hf_fc_frame_type_subtype,
			   tvb, 
	  	    	   wlan_broken_fc?1:0, 1,
			   frame_type_subtype);

      fc_item = proto_tree_add_uint_format (hdr_tree, hf_fc_field, tvb, 
		      			    0, 2,
					    fcf,
					    "Frame Control: 0x%04X (%s)",
					    fcf, wlan_broken_fc?"Swapped":"Normal");

      fc_tree = proto_item_add_subtree (fc_item, ett_fc_tree);


      proto_tree_add_uint (fc_tree, hf_fc_proto_version, tvb, 
		           wlan_broken_fc?1:0, 1,
			   COOK_PROT_VERSION (fcf));

      proto_tree_add_uint (fc_tree, hf_fc_frame_type, tvb, 
		           wlan_broken_fc?1:0, 1,
			   COOK_FRAME_TYPE (fcf));

      proto_tree_add_uint (fc_tree, hf_fc_frame_subtype,
			   tvb, 
			   wlan_broken_fc?1:0, 1,
			   COOK_FRAME_SUBTYPE (fcf));

      flag_item =
	proto_tree_add_uint_format (fc_tree, hf_fc_flags, tvb, 
			            wlan_broken_fc?0:1, 1,
				    flags, "Flags: 0x%X", flags);

      flag_tree = proto_item_add_subtree (flag_item, ett_proto_flags);

      proto_tree_add_uint (flag_tree, hf_fc_data_ds, tvb, 
		           wlan_broken_fc?0:1, 1,
			   COOK_DS_STATUS (flags));
      proto_tree_add_boolean_hidden (flag_tree, hf_fc_to_ds, tvb, 1, 1, 
				     flags);
      proto_tree_add_boolean_hidden (flag_tree, hf_fc_from_ds, tvb, 1, 1, 
				     flags);

      proto_tree_add_boolean (flag_tree, hf_fc_more_frag, tvb, 
		              wlan_broken_fc?0:1, 1,
			      flags);

      proto_tree_add_boolean (flag_tree, hf_fc_retry, tvb, 
		              wlan_broken_fc?0:1, 1, flags);

      proto_tree_add_boolean (flag_tree, hf_fc_pwr_mgt, tvb, 
		              wlan_broken_fc?0:1, 1, flags);

      proto_tree_add_boolean (flag_tree, hf_fc_more_data, tvb, 
		              wlan_broken_fc?0:1, 1,
			      flags);

      proto_tree_add_boolean (flag_tree, hf_fc_wep, tvb,
		              wlan_broken_fc?0:1, 1, flags);

      proto_tree_add_boolean (flag_tree, hf_fc_order, tvb, 
		              wlan_broken_fc?0:1, 1, flags);

      if (frame_type_subtype == CTRL_PS_POLL)
	proto_tree_add_uint(hdr_tree, hf_assoc_id,tvb,2,2,
			    COOK_ASSOC_ID(tvb_get_letohs(tvb,2)));

      else
	  proto_tree_add_uint (hdr_tree, hf_did_duration, tvb, 2, 2,
			       tvb_get_letohs (tvb, 2));
    }

  /*
   * Decode the part of the frame header that isn't the same for all
   * frame types.
   */
  seq_control = 0;
  frag_number = 0;
  seq_number = 0;

  switch (COOK_FRAME_TYPE (fcf))
    {

    case MGT_FRAME:
      /*
       * All management frame types have the same header.
       */
      src = tvb_get_ptr (tvb, 10, 6);
      dst = tvb_get_ptr (tvb, 4, 6);

      SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst);
      SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst);

      seq_control = tvb_get_letohs(tvb, 22);
      frag_number = COOK_FRAGMENT_NUMBER(seq_control);
      seq_number = COOK_SEQUENCE_NUMBER(seq_control);

      if (tree)
	{
	  proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 4, 6, dst);

	  proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 10, 6, src);

	  /* add items for wlan.addr filter */
	  proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 4, 6, dst);
	  proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 10, 6, src);

	  proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 16, 6,
				tvb_get_ptr (tvb, 16, 6));

	  proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
			       frag_number);

	  proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
			       seq_number);
	}
      break;

    case CONTROL_FRAME:
      switch (frame_type_subtype)
	{

	case CTRL_PS_POLL:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_src_addr_cols(pinfo, src, "BSSID");
	  set_dst_addr_cols(pinfo, dst, "BSSID");

	  if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 4, 6, dst);

	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6, src);
	    }
	  break;


	case CTRL_RTS:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_src_addr_cols(pinfo, src, "TA");
	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);

	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6, src);
	    }
	  break;


	case CTRL_CTS:
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);
	  break;


	case CTRL_ACKNOWLEDGEMENT:
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);
	  break;


	case CTRL_CFP_END:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_src_addr_cols(pinfo, src, "BSSID");
	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 10, 6, src);
	    }
	  break;


	case CTRL_CFP_ENDACK:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);

	  set_src_addr_cols(pinfo, src, "BSSID");
	  set_dst_addr_cols(pinfo, dst, "RA");

	  if (tree)
	    {
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6, dst);

	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 10, 6, src);
	    }
	  break;
	}
      break;

    case DATA_FRAME:
      addr_type = COOK_ADDR_SELECTOR (fcf);

      /* In order to show src/dst address we must always do the following */
      switch (addr_type)
	{

	case DATA_ADDR_T1:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);
	  break;


	case DATA_ADDR_T2:
	  src = tvb_get_ptr (tvb, 16, 6);
	  dst = tvb_get_ptr (tvb, 4, 6);
	  break;


	case DATA_ADDR_T3:
	  src = tvb_get_ptr (tvb, 10, 6);
	  dst = tvb_get_ptr (tvb, 16, 6);
	  break;


	case DATA_ADDR_T4:
	  src = tvb_get_ptr (tvb, 24, 6);
	  dst = tvb_get_ptr (tvb, 16, 6);
	  break;
	}

      SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst);
      SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst);

      seq_control = tvb_get_letohs(tvb, 22);
      frag_number = COOK_FRAGMENT_NUMBER(seq_control);
      seq_number = COOK_SEQUENCE_NUMBER(seq_control);

      /* Now if we have a tree we start adding stuff */
      if (tree)
	{


	  switch (addr_type)
	    {

	    case DATA_ADDR_T1:
	      proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 4, 6, dst);
	      proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 10, 6, src);
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 16, 6,
				    tvb_get_ptr (tvb, 16, 6));
	      proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
				   frag_number);
	      proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
				   seq_number);

	      /* add items for wlan.addr filter */
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 4, 6, dst);
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 10, 6, src);
	      break;


	    case DATA_ADDR_T2:
	      proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 4, 6, dst);
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 10, 6,
				    tvb_get_ptr (tvb, 10, 6));
	      proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 16, 6, src);
	      proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
				   frag_number);
	      proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
				   seq_number);

	      /* add items for wlan.addr filter */
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 4, 6, dst);
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 16, 6, src);
	      break;


	    case DATA_ADDR_T3:
	      proto_tree_add_ether (hdr_tree, hf_addr_bssid, tvb, 4, 6,
				    tvb_get_ptr (tvb, 4, 6));
	      proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 10, 6, src);
	      proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 16, 6, dst);

	      proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
				   frag_number);
	      proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
				   seq_number);

	      /* add items for wlan.addr filter */
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 10, 6, src);
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 16, 6, dst);
	      break;


	    case DATA_ADDR_T4:
	      proto_tree_add_ether (hdr_tree, hf_addr_ra, tvb, 4, 6,
				    tvb_get_ptr (tvb, 4, 6));
	      proto_tree_add_ether (hdr_tree, hf_addr_ta, tvb, 10, 6,
				    tvb_get_ptr (tvb, 10, 6));
	      proto_tree_add_ether (hdr_tree, hf_addr_da, tvb, 16, 6, dst);
	      proto_tree_add_uint (hdr_tree, hf_frag_number, tvb, 22, 2,
				   frag_number);
	      proto_tree_add_uint (hdr_tree, hf_seq_number, tvb, 22, 2,
				   seq_number);
	      proto_tree_add_ether (hdr_tree, hf_addr_sa, tvb, 24, 6, src);

	      /* add items for wlan.addr filter */
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 16, 6, dst);
	      proto_tree_add_ether_hidden(hdr_tree, hf_addr, tvb, 24, 6, src);
	      break;
	    }

	}
      break;
    }

  len = tvb_length_remaining(tvb, hdr_len);
  reported_len = tvb_reported_length_remaining(tvb, hdr_len);

  switch (fcs_len)
    {
      case 0: /* Definitely has no FCS */
        has_fcs = FALSE;
        break;

      case 4: /* Definitely has an FCS */
        has_fcs = TRUE;
        break;

      default: /* Don't know - use "wlan_check_fcs" */
        has_fcs = wlan_check_fcs;
        break;
    }
  if (has_fcs)
    {
      /*
       * Well, this packet should, in theory, have an FCS.
       * Do we have the entire packet, and does it have enough data for
       * the FCS?
       */
      if (reported_len < 4)
	{
	  /*
	   * The packet is claimed not to even have enough data for a 4-byte
	   * FCS.
	   * Pretend it doesn't have an FCS.
	   */
	  ;
        }
      else if (len < reported_len)
	{
	  /*
	   * The packet is claimed to have enough data for a 4-byte FCS, but
	   * we didn't capture all of the packet.
	   * Slice off the 4-byte FCS from the reported length, and trim the
	   * captured length so it's no more than the reported length; that
	   * will slice off what of the FCS, if any, is in the captured
	   * length.
	   */
	  reported_len -= 4;
	  if (len > reported_len)
	    len = reported_len;
	}
      else
	{
	  /*
	   * We have the entire packet, and it includes a 4-byte FCS.
	   * Slice it off, and put it into the tree.
	   */
	  len -= 4;
	  reported_len -= 4;
	  if (tree)
	    {
	      guint32 fcs = crc32_tvb_802(tvb, hdr_len + len);
	      guint32 sent_fcs = tvb_get_ntohl(tvb, hdr_len + len);
	      if (fcs == sent_fcs)
		proto_tree_add_uint_format(hdr_tree, hf_fcs, tvb,
			hdr_len + len, 4, sent_fcs,
			"Frame check sequence: 0x%08x (correct)", sent_fcs);
	      else
		proto_tree_add_uint_format(hdr_tree, hf_fcs, tvb,
			hdr_len + len, 4, sent_fcs,
			"Frame check sequence: 0x%08x (incorrect, should be 0x%08x)",
			sent_fcs, fcs);
	    }
	}
    }

  /*
   * Only management and data frames have a body, so we don't have
   * anything more to do for other types of frames.
   */
  switch (COOK_FRAME_TYPE (fcf))
    {

    case MGT_FRAME:
      break;

    case DATA_FRAME:
      /*
       * No-data frames don't have a body.
       */
      switch (frame_type_subtype)
	{

	case DATA_NULL_FUNCTION:
	case DATA_CF_ACK_NOD:
	case DATA_CF_POLL_NOD:
	case DATA_CF_ACK_POLL_NOD:
	  return;
	}
	break;

    default:
      return;
    }

  if (IS_WEP(COOK_FLAGS(fcf))) {
    /*
     * It's a WEP-encrypted frame; dissect the WEP parameters and decrypt
     * the data, if we have a matching key.  Otherwise display it as data.
     */
    gboolean can_decrypt = FALSE;
    proto_tree *wep_tree = NULL;
    guint32 iv;
    guint8 key;

    /*
     * XXX - pass the IV and key to "try_decrypt_wep()", and have it pass
     * them to "wep_decrypt()", rather than having "wep_decrypt()" extract
     * them itself.
     *
     * Also, just pass the data *following* the WEP parameters as the
     * buffer to decrypt.
     */
    iv = tvb_get_letoh24(tvb, hdr_len);
    if (tree) {
      proto_item *wep_fields;

      wep_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 4,
					   "WEP parameters");

      wep_tree = proto_item_add_subtree (wep_fields, ett_wep_parameters);
      proto_tree_add_uint (wep_tree, hf_wep_iv, tvb, hdr_len, 3, iv);
    }
    key = COOK_WEP_KEY (tvb_get_guint8 (tvb, hdr_len + 3));
    if (tree)
      proto_tree_add_uint (wep_tree, hf_wep_key, tvb, hdr_len + 3, 1, key);

    /* Subtract out the length of the IV. */
    len -= 4;
    reported_len -= 4;

    /*
     * Well, this packet should, in theory, have an ICV.
     * Do we have the entire packet, and does it have enough data for
     * the ICV?
     */
    if (reported_len < 4) {
      /*
       * The packet is claimed not to even have enough data for a
       * 4-byte ICV.
       * Pretend it doesn't have an ICV.
       */
      ;
    } else if (len < reported_len) {
      /*
       * The packet is claimed to have enough data for a 4-byte ICV,
       * but we didn't capture all of the packet.
       * Slice off the 4-byte ICV from the reported length, and trim
       * the captured length so it's no more than the reported length;
       * that will slice off what of the ICV, if any, is in the
       * captured length.
       *
       */
      reported_len -= 4;
      if (len > reported_len)
	len = reported_len;
    } else {
      /*
       * We have the entire packet, and it includes a 4-byte ICV.
       * Slice it off, and put it into the tree.
       *
       * We only support decrypting if we have the the ICV.
       *
       * XXX - the ICV is encrypted; we're putting the encrypted
       * value, not the decrypted value, into the tree.
       */
      len -= 4;
      reported_len -= 4;
      can_decrypt = TRUE;
    }

    if (!can_decrypt || (next_tvb = try_decrypt_wep(tvb, hdr_len, reported_len + 8)) == NULL) {
      /*
       * WEP decode impossible or failed, treat payload as raw data
       * and don't attempt fragment reassembly or further dissection.
       */
      next_tvb = tvb_new_subset(tvb, hdr_len + 4, len, reported_len);

      if (tree && can_decrypt)
	proto_tree_add_uint_format (wep_tree, hf_wep_icv, tvb, 
				    hdr_len + 4 + len, 4, 
				    tvb_get_ntohl(tvb, hdr_len + 4 + len),
				    "WEP ICV: 0x%08x (not verified)", 
				    tvb_get_ntohl(tvb, hdr_len + 4 + len));

      call_dissector(data_handle, next_tvb, pinfo, tree);
      return;
    } else {

      if (tree)
	proto_tree_add_uint_format (wep_tree, hf_wep_icv, tvb, 
				    hdr_len + 4 + len, 4, 
				    tvb_get_ntohl(tvb, hdr_len + 4 + len),
				    "WEP ICV: 0x%08x (correct)", 
				    tvb_get_ntohl(tvb, hdr_len + 4 + len));

      add_new_data_source(pinfo, next_tvb, "Decrypted WEP data");
    }

    /*
     * WEP decryption successful!
     *
     * Use the tvbuff we got back from the decryption; the data starts at
     * the beginning.  The lengths are already correct for the decoded WEP
     * payload.
     */
    hdr_len = 0;

  } else {
    /*
     * Not a WEP-encrypted frame; just use the data from the tvbuff
     * handed to us.
     *
     * The payload starts at "hdr_len" (i.e., just past the 802.11
     * MAC header), the length of data in the tvbuff following the
     * 802.11 header is "len", and the length of data in the packet
     * following the 802.11 header is "reported_len".
     */
    next_tvb = tvb;
  }

  /*
   * Do defragmentation if "wlan_defragment" is true, and we have more
   * fragments or this isn't the first fragment.
   *
   * We have to do some special handling to catch frames that
   * have the "More Fragments" indicator not set but that
   * don't show up as reassembled and don't have any other
   * fragments present.  Some networking interfaces appear
   * to do reassembly even when you're capturing raw packets
   * *and* show the reassembled packet without the "More
   * Fragments" indicator set *but* with a non-zero fragment
   * number.
   *
   * "fragment_add_seq_802_11()" handles that; we want to call it
   * even if we have a short frame, so that it does those checks - if
   * the frame is short, it doesn't do reassembly on it.
   *
   * (This could get some false positives if we really *did* only
   * capture the last fragment of a fragmented packet, but that's
   * life.)
   */
  save_fragmented = pinfo->fragmented;
  if (wlan_defragment && (more_frags || frag_number != 0)) {
    fragment_data *fd_head;

    /*
     * If we've already seen this frame, look it up in the
     * table of reassembled packets, otherwise add it to
     * whatever reassembly is in progress, if any, and see
     * if it's done.
     */
    fd_head = fragment_add_seq_802_11(next_tvb, hdr_len, pinfo, seq_number,
				     wlan_fragment_table,
				     wlan_reassembled_table,
				     frag_number,
				     reported_len,
				     more_frags);
    next_tvb = process_reassembled_data(tvb, hdr_len, pinfo,
					"Reassembled 802.11", fd_head,
					&frag_items, NULL, hdr_tree);
  } else {
    /*
     * If this is the first fragment, dissect its contents, otherwise
     * just show it as a fragment.
     */
    if (frag_number != 0) {
      /* Not the first fragment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First fragment, or not fragmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset (next_tvb, hdr_len, len, reported_len);

      /*
       * If this is the first fragment, but not the only fragment,
       * tell the next protocol that.
       */
      if (more_frags)
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as an incomplete fragment. */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "Fragmented IEEE 802.11 frame");
    next_tvb = tvb_new_subset (tvb, hdr_len, len, reported_len);
    call_dissector(data_handle, next_tvb, pinfo, tree);
    pinfo->fragmented = save_fragmented;
    return;
  }

  switch (COOK_FRAME_TYPE (fcf))
    {

    case MGT_FRAME:
      dissect_ieee80211_mgt (fcf, next_tvb, pinfo, tree);
      break;


    case DATA_FRAME:
      /* I guess some bridges take Netware Ethernet_802_3 frames,
         which are 802.3 frames (with a length field rather than
         a type field, but with no 802.2 header in the payload),
         and just stick the payload into an 802.11 frame.  I've seen
         captures that show frames of that sort.

         This means we have to do the same check for Netware 802.3 -
         or, if you will, "Netware 802.11" - that we do in the
         Ethernet dissector, i.e. checking for 0xffff as the first
         four bytes of the payload and, if we find it, treating it
         as an IPX frame. */
      is_802_2 = TRUE;
      TRY {
        if (tvb_get_ntohs(next_tvb, 0) == 0xffff)
          is_802_2 = FALSE;
      }
      CATCH2(BoundsError, ReportedBoundsError) {
	    ; /* do nothing */

      }
      ENDTRY;

      if (is_802_2)
        call_dissector(llc_handle, next_tvb, pinfo, tree);
      else
        call_dissector(ipx_handle, next_tvb, pinfo, tree);
      break;
    }
  pinfo->fragmented = save_fragmented;
}

/*
 * Dissect 802.11 with a variable-length link-layer header.
 */
static void
dissect_ieee80211 (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, FALSE, FALSE,
      pinfo->pseudo_header->ieee_802_11.fcs_len, FALSE);
}

/*
 * Dissect 802.11 with a variable-length link-layer header and a pseudo-
 * header containing radio information.
 */
static void
dissect_ieee80211_radio (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, FALSE, TRUE,
     pinfo->pseudo_header->ieee_802_11.fcs_len, FALSE);
}

/*
 * Dissect 802.11 with a variable-length link-layer header and a byte-swapped
 * control field (some hardware sends out LWAPP-encapsulated 802.11
 * packets with the control field byte swapped).
 */
static void
dissect_ieee80211_bsfc (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, FALSE, FALSE, FALSE, TRUE);
}

/*
 * Dissect 802.11 with a fixed-length link-layer header (padded to the
 * maximum length).
 */
static void
dissect_ieee80211_fixed (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  dissect_ieee80211_common (tvb, pinfo, tree, TRUE, FALSE, FALSE, FALSE);
}

static void
wlan_defragment_init(void)
{
  fragment_table_init(&wlan_fragment_table);
  reassembled_table_init(&wlan_reassembled_table);
}

void
proto_register_ieee80211 (void)
{
  static const value_string frame_type[] = {
    {MGT_FRAME,     "Management frame"},
    {CONTROL_FRAME, "Control frame"},
    {DATA_FRAME,    "Data frame"},
    {0,             NULL}
  };

  static const value_string tofrom_ds[] = {
    {0,                       "Not leaving DS or network is operating in AD-HOC mode (To DS: 0  From DS: 0)"},
    {FLAG_TO_DS,              "Frame is entering DS (To DS: 1  From DS: 0)"},
    {FLAG_FROM_DS,            "Frame is exiting DS (To DS: 0  From DS: 1)"},
    {FLAG_TO_DS|FLAG_FROM_DS, "Frame part of WDS (To DS: 1  From DS: 1)"},
    {0, NULL}
  };

  static const true_false_string tods_flag = {
    "Frame is entering DS",
    "Frame is not entering DS"
  };

  static const true_false_string fromds_flag = {
    "Frame is exiting DS",
    "Frame is not exiting DS"
  };

  static const true_false_string more_frags = {
    "More fragments follow",
    "This is the last fragment"
  };

  static const true_false_string retry_flags = {
    "Frame is being retransmitted",
    "Frame is not being retransmitted"
  };

  static const true_false_string pm_flags = {
    "STA will go to sleep",
    "STA will stay up"
  };

  static const true_false_string md_flags = {
    "Data is buffered for STA at AP",
    "No data buffered"
  };

  static const true_false_string wep_flags = {
    "WEP is enabled",
    "WEP is disabled"
  };

  static const true_false_string order_flags = {
    "Strictly ordered",
    "Not strictly ordered"
  };

  static const true_false_string cf_ess_flags = {
    "Transmitter is an AP",
    "Transmitter is a STA"
  };


  static const true_false_string cf_privacy_flags = {
    "AP/STA can support WEP",
    "AP/STA cannot support WEP"
  };

  static const true_false_string cf_preamble_flags = {
    "Short preamble allowed",
    "Short preamble not allowed"
  };

  static const true_false_string cf_pbcc_flags = {
    "PBCC modulation allowed",
    "PBCC modulation not allowed"
  };

  static const true_false_string cf_agility_flags = {
    "Channel agility in use",
    "Channel agility not in use"
  };

  static const true_false_string short_slot_time_flags = {
    "Short slot time in use",
    "Short slot time not in use"
  };

  static const true_false_string dsss_ofdm_flags = {
    "DSSS-OFDM modulation allowed",
    "DSSS-OFDM modulation not allowed"
  };


  static const true_false_string cf_ibss_flags = {
    "Transmitter belongs to an IBSS",
    "Transmitter belongs to a BSS"
  };

  static const value_string sta_cf_pollable[] = {
    {0x00, "Station is not CF-Pollable"},
    {0x02, "Station is CF-Pollable, "
     "not requesting to be placed on the  CF-polling list"},
    {0x01, "Station is CF-Pollable, "
     "requesting to be placed on the CF-polling list"},
    {0x03, "Station is CF-Pollable, requesting never to be polled"},
    {0, NULL}
  };

  static const value_string ap_cf_pollable[] = {
    {0x00, "No point coordinator at AP"},
    {0x02, "Point coordinator at AP for delivery only (no polling)"},
    {0x01, "Point coordinator at AP for delivery and polling"},
    {0x03, "Reserved"},
    {0, NULL}
  };


  static const value_string auth_alg[] = {
    {0x00, "Open System"},
    {0x01, "Shared key"},
    {0, NULL}
  };

  static const value_string reason_codes[] = {
    {0x00, "Reserved"},
    {0x01, "Unspecified reason"},
    {0x02, "Previous authentication no longer valid"},
    {0x03, "Deauthenticated because sending STA is leaving (has left) "
     "IBSS or ESS"},
    {0x04, "Disassociated due to inactivity"},
    {0x05, "Disassociated because AP is unable to handle all currently "
     "associated stations"},
    {0x06, "Class 2 frame received from nonauthenticated station"},
    {0x07, "Class 3 frame received from nonassociated station"},
    {0x08, "Disassociated because sending STA is leaving (has left) BSS"},
    {0x09, "Station requesting (re)association is not authenticated with "
     "responding station"},
    {0x00, NULL}
  };


  static const value_string status_codes[] = {
    {0x00, "Successful"},
    {0x01, "Unspecified failure"},
    {0x0A, "Cannot support all requested capabilities in the "
     "Capability information field"},
    {0x0B, "Reassociation denied due to inability to confirm that "
     "association exists"},
    {0x0C, "Association denied due to reason outside the scope of this "
     "standard"},

    {0x0D, "Responding station does not support the specified authentication "
     "algorithm"},
    {0x0E, "Received an Authentication frame with authentication sequence "
     "transaction sequence number out of expected sequence"},
    {0x0F, "Authentication rejected because of challenge failure"},
    {0x10, "Authentication rejected due to timeout waiting for next "
     "frame in sequence"},
    {0x11, "Association denied because AP is unable to handle additional "
     "associated stations"},
    {0x12, "Association denied due to requesting station not supporting all "
     "of the datarates in the BSSBasicServiceSet Parameter"},
    {0x13, "Association denied due to requesting station not supporting "
     "short preamble operation"},
    {0x14, "Association denied due to requesting station not supporting "
     "PBCC encoding"},
    {0x15, "Association denied due to requesting station not supporting "
     "channel agility"},
    {0x19, "Association denied due to requesting station not supporting "
     "short slot operation"},
    {0x1A, "Association denied due to requesting station not supporting "
     "DSSS-OFDM operation"},
    {0x00, NULL}
  };

  static hf_register_info hf[] = {
    {&hf_data_rate,
     {"Data Rate", "wlan.data_rate", FT_UINT8, BASE_DEC, NULL, 0,
      "Data rate (.5 Mb/s units)", HFILL }},

    {&hf_channel,
     {"Channel", "wlan.channel", FT_UINT8, BASE_DEC, NULL, 0,
      "Radio channel", HFILL }},

    {&hf_signal_strength,
     {"Signal Strength", "wlan.signal_strength", FT_UINT8, BASE_DEC, NULL, 0,
      "Signal strength (percentage)", HFILL }},

    {&hf_fc_field,
     {"Frame Control Field", "wlan.fc", FT_UINT16, BASE_HEX, NULL, 0,
      "MAC Frame control", HFILL }},

    {&hf_fc_proto_version,
     {"Version", "wlan.fc.version", FT_UINT8, BASE_DEC, NULL, 0,
      "MAC Protocol version", HFILL }},	/* 0 */

    {&hf_fc_frame_type,
     {"Type", "wlan.fc.type", FT_UINT8, BASE_DEC, VALS(frame_type), 0,
      "Frame type", HFILL }},

    {&hf_fc_frame_subtype,
     {"Subtype", "wlan.fc.subtype", FT_UINT8, BASE_DEC, NULL, 0,
      "Frame subtype", HFILL }},	/* 2 */

    {&hf_fc_frame_type_subtype,
     {"Type/Subtype", "wlan.fc.type_subtype", FT_UINT16, BASE_DEC, VALS(frame_type_subtype_vals), 0,
      "Type and subtype combined", HFILL }},

    {&hf_fc_flags,
     {"Protocol Flags", "wlan.flags", FT_UINT8, BASE_HEX, NULL, 0,
      "Protocol flags", HFILL }},

    {&hf_fc_data_ds,
     {"DS status", "wlan.fc.ds", FT_UINT8, BASE_HEX, VALS (&tofrom_ds), 0,
      "Data-frame DS-traversal status", HFILL }},	/* 3 */

    {&hf_fc_to_ds,
     {"To DS", "wlan.fc.tods", FT_BOOLEAN, 8, TFS (&tods_flag), FLAG_TO_DS,
      "To DS flag", HFILL }},		/* 4 */

    {&hf_fc_from_ds,
     {"From DS", "wlan.fc.fromds", FT_BOOLEAN, 8, TFS (&fromds_flag), FLAG_FROM_DS,
      "From DS flag", HFILL }},		/* 5 */

    {&hf_fc_more_frag,
     {"More Fragments", "wlan.fc.frag", FT_BOOLEAN, 8, TFS (&more_frags), FLAG_MORE_FRAGMENTS,
      "More Fragments flag", HFILL }},	/* 6 */

    {&hf_fc_retry,
     {"Retry", "wlan.fc.retry", FT_BOOLEAN, 8, TFS (&retry_flags), FLAG_RETRY,
      "Retransmission flag", HFILL }},

    {&hf_fc_pwr_mgt,
     {"PWR MGT", "wlan.fc.pwrmgt", FT_BOOLEAN, 8, TFS (&pm_flags), FLAG_POWER_MGT,
      "Power management status", HFILL }},

    {&hf_fc_more_data,
     {"More Data", "wlan.fc.moredata", FT_BOOLEAN, 8, TFS (&md_flags), FLAG_MORE_DATA,
      "More data flag", HFILL }},

    {&hf_fc_wep,
     {"WEP flag", "wlan.fc.wep", FT_BOOLEAN, 8, TFS (&wep_flags), FLAG_WEP,
      "WEP flag", HFILL }},

    {&hf_fc_order,
     {"Order flag", "wlan.fc.order", FT_BOOLEAN, 8, TFS (&order_flags), FLAG_ORDER,
      "Strictly ordered flag", HFILL }},

    {&hf_assoc_id,
     {"Association ID","wlan.aid",FT_UINT16, BASE_DEC,NULL,0,
      "Association-ID field", HFILL }},

    {&hf_did_duration,
     {"Duration", "wlan.duration", FT_UINT16, BASE_DEC, NULL, 0,
      "Duration field", HFILL }},

    {&hf_addr_da,
     {"Destination address", "wlan.da", FT_ETHER, BASE_NONE, NULL, 0,
      "Destination Hardware Address", HFILL }},

    {&hf_addr_sa,
     {"Source address", "wlan.sa", FT_ETHER, BASE_NONE, NULL, 0,
      "Source Hardware Address", HFILL }},

    { &hf_addr,
      {"Source or Destination address", "wlan.addr", FT_ETHER, BASE_NONE, NULL, 0,
       "Source or Destination Hardware Address", HFILL }},

    {&hf_addr_ra,
     {"Receiver address", "wlan.ra", FT_ETHER, BASE_NONE, NULL, 0,
      "Receiving Station Hardware Address", HFILL }},

    {&hf_addr_ta,
     {"Transmitter address", "wlan.ta", FT_ETHER, BASE_NONE, NULL, 0,
      "Transmitting Station Hardware Address", HFILL }},

    {&hf_addr_bssid,
     {"BSS Id", "wlan.bssid", FT_ETHER, BASE_NONE, NULL, 0,
      "Basic Service Set ID", HFILL }},

    {&hf_frag_number,
     {"Fragment number", "wlan.frag", FT_UINT16, BASE_DEC, NULL, 0,
      "Fragment number", HFILL }},

    {&hf_seq_number,
     {"Sequence number", "wlan.seq", FT_UINT16, BASE_DEC, NULL, 0,
      "Sequence number", HFILL }},

    {&hf_fcs,
     {"Frame check sequence", "wlan.fcs", FT_UINT32, BASE_HEX,
      NULL, 0, "FCS", HFILL }},

    {&hf_fragment_overlap,
      {"Fragment overlap", "wlan.fragment.overlap", FT_BOOLEAN, BASE_NONE,
       NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

    {&hf_fragment_overlap_conflict,
      {"Conflicting data in fragment overlap", "wlan.fragment.overlap.conflict",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Overlapping fragments contained conflicting data", HFILL }},

    {&hf_fragment_multiple_tails,
      {"Multiple tail fragments found", "wlan.fragment.multipletails",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Several tails were found when defragmenting the packet", HFILL }},

    {&hf_fragment_too_long_fragment,
      {"Fragment too long", "wlan.fragment.toolongfragment",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Fragment contained data past end of packet", HFILL }},

    {&hf_fragment_error,
      {"Defragmentation error", "wlan.fragment.error",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "Defragmentation error due to illegal fragments", HFILL }},

    {&hf_fragment,
      {"802.11 Fragment", "wlan.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "802.11 Fragment", HFILL }},

    {&hf_fragments,
      {"802.11 Fragments", "wlan.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
       "802.11 Fragments", HFILL }},

    {&hf_reassembled_in,
      {"Reassembled 802.11 in frame", "wlan.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "This 802.11 packet is reassembled in this frame", HFILL }},

    {&hf_wep_iv,
     {"Initialization Vector", "wlan.wep.iv", FT_UINT24, BASE_HEX, NULL, 0,
      "Initialization Vector", HFILL }},

    {&hf_wep_key,
     {"Key", "wlan.wep.key", FT_UINT8, BASE_DEC, NULL, 0,
      "Key", HFILL }},

    {&hf_wep_icv,
     {"WEP ICV", "wlan.wep.icv", FT_UINT32, BASE_HEX, NULL, 0,
      "WEP ICV", HFILL }},
  };

  static hf_register_info ff[] = {
    {&ff_timestamp,
     {"Timestamp", "wlan_mgt.fixed.timestamp", FT_STRING, BASE_NONE,
      NULL, 0, "", HFILL }},

    {&ff_auth_alg,
     {"Authentication Algorithm", "wlan_mgt.fixed.auth.alg",
      FT_UINT16, BASE_DEC, VALS (&auth_alg), 0, "", HFILL }},

    {&ff_beacon_interval,
     {"Beacon Interval", "wlan_mgt.fixed.beacon", FT_DOUBLE, BASE_DEC, NULL, 0,
      "", HFILL }},

    {&hf_fixed_parameters,
     {"Fixed parameters", "wlan_mgt.fixed.all", FT_UINT16, BASE_DEC, NULL, 0,
      "", HFILL }},

    {&hf_tagged_parameters,
     {"Tagged parameters", "wlan_mgt.tagged.all", FT_UINT16, BASE_DEC, NULL, 0,
      "", HFILL }},

    {&ff_capture,
     {"Capabilities", "wlan_mgt.fixed.capabilities", FT_UINT16, BASE_HEX, NULL, 0,
      "Capability information", HFILL }},

    {&ff_cf_ess,
     {"ESS capabilities", "wlan_mgt.fixed.capabilities.ess",
      FT_BOOLEAN, 16, TFS (&cf_ess_flags), 0x0001, "ESS capabilities", HFILL }},

    {&ff_cf_ibss,
     {"IBSS status", "wlan_mgt.fixed.capabilities.ibss",
      FT_BOOLEAN, 16, TFS (&cf_ibss_flags), 0x0002, "IBSS participation", HFILL }},

    {&ff_cf_sta_poll,
     {"CFP participation capabilities", "wlan_mgt.fixed.capabilities.cfpoll.sta",
      FT_UINT16, BASE_HEX, VALS (&sta_cf_pollable), 0x000C,
      "CF-Poll capabilities for a STA", HFILL }},

    {&ff_cf_ap_poll,
     {"CFP participation capabilities", "wlan_mgt.fixed.capabilities.cfpoll.ap",
      FT_UINT16, BASE_HEX, VALS (&ap_cf_pollable), 0x000C,
      "CF-Poll capabilities for an AP", HFILL }},

    {&ff_cf_privacy,
     {"Privacy", "wlan_mgt.fixed.capabilities.privacy",
      FT_BOOLEAN, 16, TFS (&cf_privacy_flags), 0x0010, "WEP support", HFILL }},

    {&ff_cf_preamble,
     {"Short Preamble", "wlan_mgt.fixed.capabilities.preamble",
      FT_BOOLEAN, 16, TFS (&cf_preamble_flags), 0x0020, "Short Preamble", HFILL }},

    {&ff_cf_pbcc,
     {"PBCC", "wlan_mgt.fixed.capabilities.pbcc",
      FT_BOOLEAN, 16, TFS (&cf_pbcc_flags), 0x0040, "PBCC Modulation", HFILL }},

    {&ff_cf_agility,
     {"Channel Agility", "wlan_mgt.fixed.capabilities.agility",
      FT_BOOLEAN, 16, TFS (&cf_agility_flags), 0x0080, "Channel Agility", HFILL }},

    {&ff_short_slot_time,
     {"Short Slot Time", "wlan_mgt.fixed.capabilities.short_slot_time",
      FT_BOOLEAN, 16, TFS (&short_slot_time_flags), 0x0400, "Short Slot Time",
      HFILL }},

    {&ff_dsss_ofdm,
     {"DSSS-OFDM", "wlan_mgt.fixed.capabilities.dsss_ofdm",
      FT_BOOLEAN, 16, TFS (&dsss_ofdm_flags), 0x2000, "DSSS-OFDM Modulation",
      HFILL }},

    {&ff_auth_seq,
     {"Authentication SEQ", "wlan_mgt.fixed.auth_seq",
      FT_UINT16, BASE_HEX, NULL, 0, "Authentication sequence number", HFILL }},

    {&ff_assoc_id,
     {"Association ID", "wlan_mgt.fixed.aid",
      FT_UINT16, BASE_HEX, NULL, 0, "Association ID", HFILL }},

    {&ff_listen_ival,
     {"Listen Interval", "wlan_mgt.fixed.listen_ival",
      FT_UINT16, BASE_HEX, NULL, 0, "Listen Interval", HFILL }},

    {&ff_current_ap,
     {"Current AP", "wlan_mgt.fixed.current_ap",
      FT_ETHER, BASE_NONE, NULL, 0, "MAC address of current AP", HFILL }},

    {&ff_reason,
     {"Reason code", "wlan_mgt.fixed.reason_code",
      FT_UINT16, BASE_HEX, VALS (&reason_codes), 0,
      "Reason for unsolicited notification", HFILL }},

    {&ff_status_code,
     {"Status code", "wlan_mgt.fixed.status_code",
      FT_UINT16, BASE_HEX, VALS (&status_codes), 0,
      "Status of requested event", HFILL }},

    {&tag_number,
     {"Tag", "wlan_mgt.tag.number",
      FT_UINT8, BASE_DEC, VALS(tag_num_vals), 0,
      "Element ID", HFILL }},

    {&tag_length,
     {"Tag length", "wlan_mgt.tag.length",
      FT_UINT8, BASE_DEC, NULL, 0, "Length of tag", HFILL }},

    {&tag_interpretation,
     {"Tag interpretation", "wlan_mgt.tag.interpretation",
      FT_STRING, BASE_NONE, NULL, 0, "Interpretation of tag", HFILL }}

  };

  static gint *tree_array[] = {
    &ett_80211,
    &ett_fc_tree,
    &ett_proto_flags,
    &ett_fragments,
    &ett_fragment,
    &ett_80211_mgt,
    &ett_fixed_parameters,
    &ett_tagged_parameters,
    &ett_wep_parameters,
    &ett_cap_tree,
  };
  module_t *wlan_module;

  static const enum_val_t wep_keys_options[] = {
    {"0", 0},
    {"1", 1},
    {"2", 2},
    {"3", 3},
    {"4", 4},
    {NULL, -1},
  };


  proto_wlan = proto_register_protocol ("IEEE 802.11 wireless LAN",
					"IEEE 802.11", "wlan");
  proto_register_field_array (proto_wlan, hf, array_length (hf));
  proto_wlan_mgt = proto_register_protocol ("IEEE 802.11 wireless LAN management frame",
					"802.11 MGT", "wlan_mgt");
  proto_register_field_array (proto_wlan_mgt, ff, array_length (ff));
  proto_register_subtree_array (tree_array, array_length (tree_array));

  register_dissector("wlan", dissect_ieee80211, proto_wlan);
  register_dissector("wlan_fixed", dissect_ieee80211_fixed, proto_wlan);
  register_dissector("wlan_bsfc", dissect_ieee80211_bsfc, proto_wlan);
  register_init_routine(wlan_defragment_init);

  /* Register configuration options */
  wlan_module = prefs_register_protocol(proto_wlan, init_wepkeys);
  prefs_register_bool_preference(wlan_module, "defragment",
	"Reassemble fragmented 802.11 datagrams",
	"Whether fragmented 802.11 datagrams should be reassembled",
	&wlan_defragment);

  prefs_register_bool_preference(wlan_module, "check_fcs",
				 "Assume packets have FCS",
				 "Some 802.11 cards include the FCS at the end of a packet, others do not.",
				 &wlan_check_fcs);

  prefs_register_bool_preference(wlan_module, "ignore_wep",
				 "Ignore the WEP bit",
				 "Some 802.11 cards leave the WEP bit set even though the packet is decrypted.",
				 &wlan_ignore_wep);

#ifndef USE_ENV
  prefs_register_enum_preference(wlan_module, "wep_keys",
				 "WEP key count",
				 "How many WEP keys do we have to choose from? (0 to disable, up to 4)",
				 &num_wepkeys, wep_keys_options, FALSE);

  prefs_register_string_preference(wlan_module, "wep_key1",
				   "WEP key #1",
				   "First WEP key (A:B:C:D:E) [40bit], (A:B:C:D:E:F:G:H:I:J:K:L:M) [104bit], or whatever key length you're using",
				   &wep_keystr[0]);
  prefs_register_string_preference(wlan_module, "wep_key2",
				   "WEP key #2",
				   "Second WEP key (A:B:C:D:E) [40bit], (A:B:C:D:E:F:G:H:I:J:K:L:M) [104bit], or whatever key length you're using",
				   &wep_keystr[1]);
  prefs_register_string_preference(wlan_module, "wep_key3",
				   "WEP key #3",
				   "Third WEP key (A:B:C:D:E) [40bit], (A:B:C:D:E:F:G:H:I:J:K:L:M) [104bit], or whatever key length you're using",
				   &wep_keystr[2]);
  prefs_register_string_preference(wlan_module, "wep_key4",
				   "WEP key #4",
				   "Fourth WEP key (A:B:C:D:E) [40bit] (A:B:C:D:E:F:G:H:I:J:K:L:M) [104bit], or whatever key length you're using",
				   &wep_keystr[3]);
#endif
}

void
proto_reg_handoff_ieee80211(void)
{
  dissector_handle_t ieee80211_handle;
  dissector_handle_t ieee80211_radio_handle;

  /*
   * Get handles for the LLC and IPX dissectors.
   */
  llc_handle = find_dissector("llc");
  ipx_handle = find_dissector("ipx");
  data_handle = find_dissector("data");

  ieee80211_handle = find_dissector("wlan");
  dissector_add("wtap_encap", WTAP_ENCAP_IEEE_802_11, ieee80211_handle);
  ieee80211_radio_handle = create_dissector_handle(dissect_ieee80211_radio,
						   proto_wlan);
  dissector_add("wtap_encap", WTAP_ENCAP_IEEE_802_11_WITH_RADIO,
		ieee80211_radio_handle);
}

static tvbuff_t *try_decrypt_wep(tvbuff_t *tvb, guint32 offset, guint32 len) {
  guint8 *tmp = NULL;
  int i;
  tvbuff_t *decr_tvb = NULL;

  if (num_wepkeys < 1)
    return NULL;

  if ((tmp = g_malloc(len)) == NULL)
    return NULL;  /* krap! */

  /* try once with the key index in the packet, then look through our list. */
  for (i = -1; i < (int) num_wepkeys; i++) {
    /* copy the encrypted data over to the tmp buffer */
#if 0
    printf("trying %d\n", i);
#endif
    tvb_memcpy(tvb, tmp, offset, len);
    if (wep_decrypt(tmp, len, i) == 0) {

      /* decrypt successful, let's set up a new data tvb. */
      decr_tvb = tvb_new_real_data(tmp, len-8, len-8);
      tvb_set_free_cb(decr_tvb, g_free);
      tvb_set_child_real_data_tvbuff(tvb, decr_tvb);

      goto done;
    }
  }

 done:
  if ((!decr_tvb) && (tmp))    g_free(tmp);

#if 0
  printf("de-wep %p\n", decr_tvb);
#endif

  return decr_tvb;
}


/* de-weps the block.  if successful, buf* will point to the data start. */
static int wep_decrypt(guint8 *buf, guint32 len, int key_override) {
  guint32 i, j, k, crc, keylen;
  guint8 s[256], key[128], c_crc[4];
  guint8 keyidx, *dpos, *cpos;

  /* Needs to be at least 8 bytes of payload */
  if (len < 8)
    return -1;

  /* initialize the first bytes of the key from the IV */
  key[0] = buf[0];
  key[1] = buf[1];
  key[2] = buf[2];
  keyidx = COOK_WEP_KEY(buf[3]);

  if (key_override >= 0)
    keyidx = key_override;

  if (keyidx >= num_wepkeys)
    return -1;

  keylen = wep_keylens[keyidx];

  if (keylen == 0)
    return -1;
  if (wep_keys[keyidx] == NULL)
    return -1;

  keylen+=3;  /* add in ICV bytes */

  /* copy the rest of the key over from the designated key */
  memcpy(key+3, wep_keys[keyidx], wep_keylens[keyidx]);

#if 0
  printf("%d: %02x %02x %02x (%d %d) %02x:%02x:%02x:%02x:%02x\n", len, key[0], key[1], key[2], keyidx, keylen, key[3], key[4], key[5], key[6], key[7]);
#endif

  /* set up the RC4 state */
  for (i = 0; i < 256; i++)
    s[i] = i;
  j = 0;
  for (i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % keylen]) & 0xff;
    SSWAP(i,j);
  }

  /* Apply the RC4 to the data, update the CRC32 */
  cpos = buf+4;
  dpos = buf;
  crc = ~0;
  i = j = 0;
  for (k = 0; k < (len -8); k++) {
    i = (i+1) & 0xff;
    j = (j+s[i]) & 0xff;
    SSWAP(i,j);
#if 0
    printf("%d -- %02x ", k, *dpos);
#endif
    *dpos = *cpos++ ^ s[(s[i] + s[j]) & 0xff];
#if 0
    printf("%02x\n", *dpos);
#endif
    crc = crc32_table[(crc ^ *dpos++) & 0xff] ^ (crc >> 8);
  }
  crc = ~crc;

  /* now let's check the crc */
  c_crc[0] = crc;
  c_crc[1] = crc >> 8;
  c_crc[2] = crc >> 16;
  c_crc[3] = crc >> 24;

  for (k = 0; k < 4; k++) {
    i = (i + 1) & 0xff;
    j = (j+s[i]) & 0xff;
    SSWAP(i,j);
#if 0
    printf("-- %02x %02x\n", *dpos, c_crc[k]);
#endif
    if ((*cpos++ ^ s[(s[i] + s[j]) & 0xff]) != c_crc[k])
      return -1; /* ICV mismatch */
  }

  return 0;
}

static void init_wepkeys(void) {
  char *tmp;
  guint i;
  GByteArray *bytes;
  gboolean res;

#ifdef USE_ENV
  guint8 buf[128];

  tmp = getenv("ETHEREAL_WEPKEYNUM");
  if (!tmp) {
    num_wepkeys = 0;
    return;
  }
  num_wepkeys = atoi(tmp);
#else
  if (num_wepkeys > 4)
    num_wepkeys = 4;
#endif

  if (num_wepkeys < 1)
    return;

  if (wep_keys)
    g_free(wep_keys);

  if (wep_keylens)
    g_free(wep_keylens);

  wep_keys = g_malloc(num_wepkeys * sizeof(guint8*));
  wep_keylens = g_malloc(num_wepkeys * sizeof(int));
  bytes = g_byte_array_new();

  for (i = 0 ; i < num_wepkeys; i++) {
    wep_keys[i] = NULL;
    wep_keylens[i] = 0;

#ifdef USE_ENV
    sprintf(buf, "ETHEREAL_WEPKEY%d", i+1);
    tmp = getenv(buf);
#else
    tmp = wep_keystr[i];
#endif

    if (tmp) {
#if 0
#ifdef USE_ENV
      printf("%s -- %s\n", buf, tmp);
#else
      printf("%d -- %s\n", i+1, tmp);
#endif
#endif

      if (wep_keys[i]) {
	g_free(wep_keys[i]);
      }

      res = hex_str_to_bytes(tmp, bytes);
      if (res && bytes->len > 0) {
        if (bytes->len > 32) {
	  bytes->len = 32;
	}
	wep_keys[i] = g_malloc(32 * sizeof(guint8));
	memset(wep_keys[i], 0, 32 * sizeof(guint8));
	memcpy(wep_keys[i], bytes->data, bytes->len * sizeof(guint8));
	wep_keylens[i] = bytes->len;
#if 0
	printf("%d: %d bytes\n", i, bytes->len);
	printf("%d: %s\n", i, bytes_to_str(bytes->data, bytes->len));
#endif
      } else {
        g_warning("Could not parse WEP key %d: %s", i + 1, tmp);
      }
    }
  }
  g_byte_array_free(bytes, TRUE);
}
