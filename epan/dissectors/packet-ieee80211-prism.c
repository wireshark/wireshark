/* packet-ieee80211-prism.c
 * Routines for Prism monitoring mode header dissection
 *
 * $Id$
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
#include "packet-ieee80211.h"

#define SHORT_STR 256

static dissector_handle_t wlancap_handle;
static dissector_handle_t ieee80211_handle;

static int proto_prism = -1;

/* Prism radio header */

static int hf_ieee80211_prism_msgcode = -1;
static int hf_ieee80211_prism_msglen = -1;
static int hf_ieee80211_prism_devname = -1;
static int hf_ieee80211_prism_did = -1;
static int hf_ieee80211_prism_did_type = -1;
static int hf_ieee80211_prism_did_status = -1;
static int hf_ieee80211_prism_did_length = -1;
static int hf_ieee80211_prism_did_hosttime = -1;
static int hf_ieee80211_prism_did_mactime = -1;
static int hf_ieee80211_prism_did_channel = -1;
static int hf_ieee80211_prism_did_rssi = -1;
static int hf_ieee80211_prism_did_sq = -1;
static int hf_ieee80211_prism_did_signal = -1;
static int hf_ieee80211_prism_did_noise = -1;
static int hf_ieee80211_prism_did_rate = -1;
static int hf_ieee80211_prism_did_istx = -1;
static int hf_ieee80211_prism_did_frmlen = -1;
static int hf_ieee80211_prism_did_unknown = -1;

static gint ett_prism = -1;
static gint ett_prism_did = -1;

/*
 * Prism II-based wlan devices have a monitoring mode that sticks
 * a proprietary header on each packet with lots of good
 * information.  This file is responsible for decoding that
 * data.
 *
 * Support by Tim Newsham
 *
 * A value from the header.
 *
 * It appears from looking at the linux-wlan-ng and Prism II HostAP
 * drivers, and various patches to the orinoco_cs drivers to add
 * Prism headers, that:
 *
 *      the "did" identifies what the value is (i.e., what it's the value
 *      of);
 *
 *      "status" is 0 if the value is present or 1 if it's absent;
 *
 *      "len" is the length of the value (always 4, in that code);
 *
 *      "data" is the value of the data (or 0 if not present).
 *
 * Note: all of those values are in the *host* byte order of the machine
 * on which the capture was written.
 */


/*
 * Header attached during Prism monitor mode.
 *
 * At least according to one paper I've seen, the Prism 2.5 chip set
 * provides:
 *
 *      RSSI (receive signal strength indication) is "the total power
 *      received by the radio hardware while receiving the frame,
 *      including signal, interfereence, and background noise";
 *
 *      "silence value" is "the total power observed just before the
 *      start of the frame".
 *
 * None of the drivers I looked at supply the "rssi" or "sq" value,
 * but they do supply "signal" and "noise" values, along with a "rate"
 * value that's 1/5 of the raw value from what is presumably a raw
 * HFA384x frame descriptor, with the comment "set to 802.11 units",
 * which presumably means the units are 500 Kb/s.
 *
 * I infer from the current NetBSD "wi" driver that "signal" and "noise"
 * are adjusted dBm values, with the dBm value having 100 added to it
 * for the Prism II cards (although the NetBSD code has an XXX comment
 * for the #define for WI_PRISM_DBM_OFFSET) and 149 (with no XXX comment)
 * for the Orinoco cards.
 *
 * XXX - what about other drivers that supply Prism headers, such as
 * old versions of the MadWifi driver?
 *
 * I'm not sure where these DID values come from, but they work with
 * at least one capture file.  However, in
 *
 *    http://ask.wireshark.org/questions/14963/how-to-get-the-field-did-unknown-4041-into-the-column
 *
 * somebody reports a capture where *different* DID values, corresponding
 * to
 *
 *    http://home.martin.cc/linux/prism
 *
 * are used (and that's not a byte-order issue, as those values are *not*
 * just byte-swapped versions of the other values).
 */

#define PRISM_HEADER_LENGTH     144             /* Default Prism Header Length */

/*
 * Message code values.
 *
 * Some Prism captures have headers that begin with 0x00000044; those
 * captures have the non-home.martin.cc values for the DID types,
 * while a capture with 0x00000041 as the message code have the
 * home.martin.cc values for the DID types, and the home.martin.cc
 * page has 0x00000041 as the message code.
 */
#define PRISM_TYPE1_MSGCODE      0x00000044      /* Monitor Frame */
#define PRISM_TYPE2_MSGCODE      0x00000041

/*
 * DID codes - PRISM_TYPE1_xxx are the non-home.martin.cc values, and
 * PRISM_TYPE2_xxx are the home.martin.cc values.
 */
#define PRISM_TYPE1_HOSTTIME     0x00010044      /* Host time element */
#define PRISM_TYPE2_HOSTTIME     0x00001041
#define PRISM_TYPE1_MACTIME      0x00020044      /* Mac time element */
#define PRISM_TYPE2_MACTIME      0x00002041
#define PRISM_TYPE1_CHANNEL      0x00030044      /* Channel element */
#define PRISM_TYPE2_CHANNEL      0x00003041 
#define PRISM_TYPE1_RSSI         0x00040044      /* RSSI element */
#define PRISM_TYPE2_RSSI         0x00004041
#define PRISM_TYPE1_SQ           0x00050044      /* SQ element */
#define PRISM_TYPE2_SQ           0x00005041
#define PRISM_TYPE1_SIGNAL       0x00060044      /* Signal element */
#define PRISM_TYPE2_SIGNAL       0x00006041
#define PRISM_TYPE1_NOISE        0x00070044      /* Noise element */
#define PRISM_TYPE2_NOISE        0x00007041
#define PRISM_TYPE1_RATE         0x00080044      /* Rate element */
#define PRISM_TYPE2_RATE         0x00008041
#define PRISM_TYPE1_ISTX         0x00090044      /* Is Tx frame */
#define PRISM_TYPE2_ISTX         0x00009041
#define PRISM_TYPE1_FRMLEN       0x000A0044      /* Frame length */
#define PRISM_TYPE2_FRMLEN       0x0000A041

static const value_string prism_did_vals[] =
{
  { PRISM_TYPE1_HOSTTIME,   "Host Time" },
  { PRISM_TYPE2_HOSTTIME,   "Host Time" },
  { PRISM_TYPE1_MACTIME,    "Mac Time" },
  { PRISM_TYPE2_MACTIME,    "Mac Time" },
  { PRISM_TYPE1_CHANNEL,    "Channel" },
  { PRISM_TYPE2_CHANNEL,    "Channel" },
  { PRISM_TYPE1_RSSI,       "RSSI" },
  { PRISM_TYPE2_RSSI,       "RSSI" },
  { PRISM_TYPE1_SQ,         "SQ" },
  { PRISM_TYPE2_SQ,         "SQ" },
  { PRISM_TYPE1_SIGNAL,     "Signal" },
  { PRISM_TYPE2_SIGNAL,     "Signal" },
  { PRISM_TYPE1_NOISE,      "Noise" },
  { PRISM_TYPE2_NOISE,      "Noise" },
  { PRISM_TYPE1_RATE,       "Rate" },
  { PRISM_TYPE2_RATE,       "Rate" },
  { PRISM_TYPE1_ISTX,       "Is Tx" },
  { PRISM_TYPE2_ISTX,       "Is Tx" },
  { PRISM_TYPE1_FRMLEN,     "Frame Length" },
  { PRISM_TYPE2_FRMLEN,     "Frame Length" },
  { 0, NULL}
};

/*
 * The header file mentioned above says 0 means "supplied" and 1 means
 * "not supplied".  I haven't seen a capture file with anything other
 * than 0 there.
 */
static const value_string prism_status_vals[] =
{
  { 0,   "Supplied" },
  { 1,   "Not Supplied" },
  { 0, NULL}
};

static const value_string prism_istx_vals[] =
{
  { 0,   "Rx Packet" },
  { 1,   "Tx Packet" },
  { 0, NULL}
};

static void
prism_rate_base_custom(gchar *result, guint32 rate)
{
   g_snprintf(result, ITEM_LABEL_LENGTH, "%u.%u", rate /2, rate & 1 ? 5 : 0);
}

static gchar *
prism_rate_return(guint32 rate)
{
  gchar *result=NULL;
  result = ep_alloc(SHORT_STR);
  result[0] = '\0';
  prism_rate_base_custom(result, rate);

  return result;
}


void
capture_prism(const guchar *pd, int offset, int len, packet_counts *ld)
{
  guint32 cookie;

  if (!BYTES_ARE_IN_FRAME(offset, len, 4)) {
    ld->other++;
    return;
  }

  /* Some captures with DLT_PRISM have the AVS WLAN header */
  cookie = pntohl(pd);
  if ((cookie == WLANCAP_MAGIC_COOKIE_V1) ||
      (cookie == WLANCAP_MAGIC_COOKIE_V2)) {
    capture_wlancap(pd, offset, len, ld);
    return;
  }

  /* Prism header */
  if (!BYTES_ARE_IN_FRAME(offset, len, PRISM_HEADER_LENGTH)) {
    ld->other++;
    return;
  }
  offset += PRISM_HEADER_LENGTH;

  /* 802.11 header follows */
  capture_ieee80211(pd, offset, len, ld);
}

static void
dissect_prism(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *prism_tree = NULL, *prism_did_tree = NULL;
    proto_item *ti = NULL, *ti_did = NULL;
    tvbuff_t *next_tvb;
    int offset;
    guint32 msgcode, msglen, did;
    guint16 status;
    guint8 *devname_p;

    offset = 0;
    did = 0;

    /* handle the AVS header */
    msgcode = tvb_get_ntohl(tvb, offset);
    if ((msgcode == WLANCAP_MAGIC_COOKIE_V1) ||
        (msgcode == WLANCAP_MAGIC_COOKIE_V2)) {
      call_dissector(wlancap_handle, tvb, pinfo, tree);
      return;
    }

    /*
     * If we don't see a valid message type, assume the Prism or AVS
     * header was omitted and just hand off to the 802.11 dissector;
     * at least one capture has AVS headers on some packets and no
     * radio headers on others (incoming vs. outgoing?).
     *
     * XXX - check for both byte orders and use that to determine
     * the byte order of the fields in the Prism header?
     */
    msgcode = tvb_get_letohl(tvb, offset);
    if ((msgcode != PRISM_TYPE1_MSGCODE) &&
        (msgcode != PRISM_TYPE2_MSGCODE)) {
        call_dissector(ieee80211_handle, tvb, pinfo, tree);
        return;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Prism");
    col_clear(pinfo->cinfo, COL_INFO);

    if(tree) {
        ti = proto_tree_add_item(tree, proto_prism, tvb, 0, 144, ENC_NA);
        prism_tree = proto_item_add_subtree(ti, ett_prism);
    }

    /* Message Code */
    if(tree) {
        proto_tree_add_item(prism_tree, hf_ieee80211_prism_msgcode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
    msgcode = tvb_get_letohl(tvb, offset);
    offset += 4;

    /* Message Length */
    if(tree) {
        proto_tree_add_item(prism_tree, hf_ieee80211_prism_msglen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
    msglen = tvb_get_letohl(tvb, offset);
    offset += 4;

    /* Device Name */
    if(tree) {
       proto_tree_add_item(prism_tree, hf_ieee80211_prism_devname, tvb, offset, 16, ENC_ASCII|ENC_NA);
    }
    devname_p = tvb_get_ephemeral_string(tvb, offset, 16);
    offset += 16;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Device: %s, Message 0x%x, Length %d", devname_p, msgcode, msglen);


    while(offset < PRISM_HEADER_LENGTH)
    {
        /* DID */
        if(tree) {
            ti_did = proto_tree_add_item(prism_tree, hf_ieee80211_prism_did, tvb, offset, 12, ENC_NA);
            prism_did_tree = proto_item_add_subtree(ti_did, ett_prism_did);

            proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            did = tvb_get_letohl(tvb, offset);
            proto_item_append_text(ti_did, " %s", val_to_str(did, prism_did_vals, "Unknown %x") );
        }
        offset += 4;


        /* Status */
        status = tvb_get_letohs(tvb, offset);
        if(tree) {
            proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_status, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
        offset += 2;

        /* Length */
        if(tree) {
            proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
        offset += 2;

        /* Data, if present... */
        if (status == 0) {
            switch(did){
              case PRISM_TYPE1_HOSTTIME:
              case PRISM_TYPE2_HOSTTIME:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_hosttime, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " %d", tvb_get_letohl(tvb, offset) );
                }
              break;

              case PRISM_TYPE1_MACTIME:
              case PRISM_TYPE2_MACTIME:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_mactime, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " %d", tvb_get_letohl(tvb, offset) );
                }
              break;

              case PRISM_TYPE1_CHANNEL:
              case PRISM_TYPE2_CHANNEL:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_channel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " %d", tvb_get_letohl(tvb, offset) );
                }
                col_add_fstr(pinfo->cinfo, COL_FREQ_CHAN, "%u", tvb_get_letohl(tvb, offset));
              break;

              case PRISM_TYPE1_RSSI:
              case PRISM_TYPE2_RSSI:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_rssi, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_letohl(tvb, offset) );
                }
                col_add_fstr(pinfo->cinfo, COL_RSSI, "%d", tvb_get_letohl(tvb, offset));
              break;

              case PRISM_TYPE1_SQ:
              case PRISM_TYPE2_SQ:
                 if(tree){
                      proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_sq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                      proto_item_append_text(ti_did, " 0x%x", tvb_get_letohl(tvb, offset) );
                }
              break;

              case PRISM_TYPE1_SIGNAL:
              case PRISM_TYPE2_SIGNAL:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_signal, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_letohl(tvb, offset) );
                }
              break;

              case PRISM_TYPE1_NOISE:
              case PRISM_TYPE2_NOISE:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_noise, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_letohl(tvb, offset) );
                }
              break;

              case PRISM_TYPE1_RATE:
              case PRISM_TYPE2_RATE:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " %s Mb/s", prism_rate_return(tvb_get_letohl(tvb, offset)) );
                }
                col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%s", prism_rate_return(tvb_get_letohl(tvb, offset)) );
              break;

              case PRISM_TYPE1_ISTX:
              case PRISM_TYPE2_ISTX:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_istx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " 0x%x", tvb_get_letohl(tvb, offset) );
                }
              break;

              case PRISM_TYPE1_FRMLEN:
              case PRISM_TYPE2_FRMLEN:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_frmlen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_did, " %d", tvb_get_letohl(tvb, offset) );
                }
              break;

              default:
                if(tree){
                    proto_tree_add_item(prism_did_tree, hf_ieee80211_prism_did_unknown, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                }
              break;
            }
        }
        offset += 4;
    }

    /* dissect the 802.11 header next */
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
}

static hf_register_info hf_prism[] = {
    /* Prism-specific header fields
       XXX - make as many of these generic as possible. */
    { &hf_ieee80211_prism_msgcode,
     {"Message Code", "prism.msgcode", FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_msglen,
     {"Message Length", "prism.msglen", FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_devname,
     {"Device Name", "prism.devname", FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did,
     {"DID", "prism.did.type", FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_type,
     {"DID", "prism.did.type", FT_UINT32, BASE_HEX, VALS(prism_did_vals), 0x0,
      "Different ID for each parameter", HFILL }},

    { &hf_ieee80211_prism_did_status,
     {"Status", "prism.did.status", FT_UINT16, BASE_DEC, VALS(prism_status_vals), 0x0,
      "Supplied by the driver or not", HFILL }},

    { &hf_ieee80211_prism_did_length,
     {"Length", "prism.did.length", FT_UINT16, BASE_DEC, NULL, 0x0,
      "Length of data", HFILL }},

    { &hf_ieee80211_prism_did_hosttime,
     {"Host Time", "prism.did.hosttime", FT_UINT32, BASE_DEC, NULL, 0x0,
      "In jiffies - for our system this is in 10ms units", HFILL }},

    { &hf_ieee80211_prism_did_mactime,
     {"MAC timestamp (lower 32 bits)", "prism.did.mactime", FT_UINT32, BASE_DEC, NULL, 0x0,
      "Lower 32 bits of value in microseconds of the MAC's Time Synchronization Function timer when the first bit of the MPDU arrived at the MAC.", HFILL }},

    { &hf_ieee80211_prism_did_channel,
     {"Channel", "prism.did.channel", FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_rssi,
     {"RSSI", "prism.did.rssi", FT_INT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_sq,
     {"Signal Quality", "prism.did.sq", FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_signal,
     {"Signal", "prism.did.signal", FT_INT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_noise,
     {"Noise", "prism.did.noise", FT_INT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_ieee80211_prism_did_rate,
     {"Data rate (Mb/s)", "prism.did.rate", FT_UINT32, BASE_CUSTOM, prism_rate_base_custom, 0x0,
      "Speed this frame was sent/received at", HFILL }},

    { &hf_ieee80211_prism_did_istx,
     {"IsTX", "prism.did.istx", FT_UINT32, BASE_HEX, VALS(prism_istx_vals), 0x0,
      "Type of packet (RX or TX?)", HFILL }},

    { &hf_ieee80211_prism_did_frmlen,
     {"Frame Length", "prism.did.frmlen", FT_UINT32, BASE_DEC, NULL, 0x0,
      "Length of the following frame in bytes", HFILL }},

    { &hf_ieee80211_prism_did_unknown,
     {"Unknown DID Field", "prism.did.unknown", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
      NULL, HFILL }}
};

static gint *tree_array[] = {
  &ett_prism,
  &ett_prism_did
};

void proto_register_ieee80211_prism(void)
{
  proto_prism = proto_register_protocol("Prism capture header", "Prism",
                                        "prism");
  proto_register_field_array(proto_prism, hf_prism, array_length(hf_prism));
  proto_register_subtree_array(tree_array, array_length(tree_array));
}

void proto_reg_handoff_ieee80211_prism(void)
{
  dissector_handle_t prism_handle;

  prism_handle = create_dissector_handle(dissect_prism, proto_prism);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE_802_11_PRISM, prism_handle);
  ieee80211_handle = find_dissector("wlan");
  wlancap_handle = find_dissector("wlancap");
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
