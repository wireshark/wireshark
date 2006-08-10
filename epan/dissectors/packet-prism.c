/*
 *  packet-prism.c
 *	Decode packets with a Prism header
 *
 * Prism II-based wlan devices have a monitoring mode that sticks
 * a proprietary header on each packet with lots of good
 * information.  This file is responsible for decoding that
 * data.
 *
 * By Tim Newsham
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include "packet-ieee80211.h"
#include "packet-prism.h"
#include "packet-wlancap.h"

/* protocol */
static int proto_prism = -1;

/* header fields */
static int hf_prism_msgcode = -1;
static int hf_prism_msglen = -1;

/*
 * A value from the header.
 *
 * It appears from looking at the linux-wlan-ng and Prism II HostAP
 * drivers, and various patches to the orinoco_cs drivers to add
 * Prism headers, that:
 *
 *	the "did" identifies what the value is (i.e., what it's the value
 *	of);
 *
 *	"status" is 0 if the value is present or 1 if it's absent;
 *
 *	"len" is the length of the value (always 4, in that code);
 *
 *	"data" is the value of the data (or 0 if not present).
 *
 * Note: all of those values are in the *host* byte order of the machine
 * on which the capture was written.
 */
struct val_80211 {
    unsigned int did;
    unsigned short status, len;
    unsigned int data;
};

/*
 * Header attached during Prism monitor mode.
 *
 * At least according to one paper I've seen, the Prism 2.5 chip set
 * provides:
 *
 *	RSSI (receive signal strength indication) is "the total power
 *	received by the radio hardware while receiving the frame,
 *	including signal, interfereence, and background noise";
 *
 *	"silence value" is "the total power observed just before the
 *	start of the frame".
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
 */
struct prism_hdr {
    unsigned int msgcode, msglen;
    char devname[16];
    struct val_80211 hosttime, mactime, channel, rssi, sq, signal,
        noise, rate, istx, frmlen;
};

#define VALFIELDS(name) \
    static int hf_prism_ ## name ## _data = -1
VALFIELDS(hosttime);
VALFIELDS(mactime);
VALFIELDS(channel);
VALFIELDS(rssi);
VALFIELDS(sq);
VALFIELDS(signal);
VALFIELDS(noise);
VALFIELDS(rate);
VALFIELDS(istx);
VALFIELDS(frmlen);

static gint ett_prism = -1;

static dissector_handle_t ieee80211_handle;
static dissector_handle_t wlancap_handle;

void
capture_prism(const guchar *pd, int offset, int len, packet_counts *ld)
{
    guint32 cookie = 0;
    guint32 length = 0;
    if (!BYTES_ARE_IN_FRAME(offset, len, sizeof(guint32) *2 )) {
        ld->other++;
        return;
    }

    cookie = pntohl(pd);
    length = pntohl(pd+sizeof(guint32));

    /* Handle the new type of capture format */
    if ((cookie == WLANCAP_MAGIC_COOKIE_V1) || 
	(cookie == WLANCAP_MAGIC_COOKIE_V2)) {
      if(!BYTES_ARE_IN_FRAME(offset, len, length)) {
        ld->other++;
        return;
      }
      offset += length;
    } else {
      /* We have an old capture format */
      if(!BYTES_ARE_IN_FRAME(offset, len, (int)sizeof(struct prism_hdr))) {
        ld->other++;
        return;
      }
      offset += sizeof(struct prism_hdr);
    }

    /* 802.11 header follows */
    capture_ieee80211(pd, offset, len, ld);

}

/*
 * yah, I know, macros, ugh, but it makes the code
 * below more readable
 */
#define IFHELP(size, name, var, str) \
        if(tree) {						  \
            proto_tree_add_uint_format(prism_tree, hf_prism_ ## name, \
                tvb, offset, size, hdr.var, str, hdr.var);		  \
        }								  \
        offset += (size)
#define INTFIELD(size, name, str)	IFHELP(size, name, name, str)
#define VALFIELD(name, str) \
        if (hdr.name.status == 0) {				  \
            if(tree) {						  \
                proto_tree_add_uint_format(prism_tree, hf_prism_ ## name ## _data, \
                    tvb, offset, 12, hdr.name.data,			   \
                    str ": 0x%x (DID 0x%x, Status 0x%x, Length 0x%x)",	   \
                    hdr.name.data, hdr.name.did,			   \
                    hdr.name.status, hdr.name.len);			   \
            }								   \
        }								   \
        offset += 12

static void
dissect_prism(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    struct prism_hdr hdr;
    proto_tree *prism_tree = NULL;
    proto_item *ti;
    tvbuff_t *next_tvb;
    int offset;
    guint32 msgcode;

    offset = 0;

    /* handle the new capture type. */
    msgcode = tvb_get_ntohl(tvb, offset);
    if ((msgcode == WLANCAP_MAGIC_COOKIE_V1) || 
	(msgcode == WLANCAP_MAGIC_COOKIE_V2)) {
	    call_dissector(wlancap_handle, tvb, pinfo, tree);
	    return;
    }
      
    tvb_memcpy(tvb, (guint8 *)&hdr, offset, sizeof(hdr));

    if(check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Prism");
    if(check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    if(check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "Device: %.16s  "
                     "Message 0x%x, Length %d", hdr.devname,
                     hdr.msgcode, hdr.msglen);

    if(tree) {
        ti = proto_tree_add_protocol_format(tree, proto_prism,
            tvb, 0, sizeof hdr, "Prism Monitoring Header");
        prism_tree = proto_item_add_subtree(ti, ett_prism);
    }

    INTFIELD(4, msgcode, "Message Code: %d");
    INTFIELD(4, msglen, "Message Length: %d");
    if(tree) {
        proto_tree_add_text(prism_tree, tvb, offset, sizeof hdr.devname,
            "Device: %s", hdr.devname);
    }
    offset += sizeof hdr.devname;

    VALFIELD(hosttime, "Host Time");
    VALFIELD(mactime, "MAC Time");
    VALFIELD(channel, "Channel");
    if (hdr.rate.status == 0) {
      if (check_col(pinfo->cinfo, COL_RSSI))
        col_add_fstr(pinfo->cinfo, COL_RSSI, "%d", hdr.rssi.data);
      if (tree) {
        proto_tree_add_uint_format(prism_tree, hf_prism_rssi_data,
            tvb, offset, 12, hdr.rssi.data,
            "RSSI: 0x%x (DID 0x%x, Status 0x%x, Length 0x%x)",
            hdr.rssi.data, hdr.rssi.did, hdr.rssi.status, hdr.rssi.len);
      }
    }
    offset += 12;
    VALFIELD(sq, "SQ");
    VALFIELD(signal, "Signal");
    VALFIELD(noise, "Noise");
    if (hdr.rate.status == 0) {
      if (check_col(pinfo->cinfo, COL_TX_RATE)) {
        col_add_fstr(pinfo->cinfo, COL_TX_RATE, "%u.%u",
                  hdr.rate.data / 2, hdr.rate.data & 1 ? 5 : 0);
      }
      if (tree) {
          proto_tree_add_uint_format(prism_tree, hf_prism_rate_data,
                  tvb, offset, 12, hdr.rate.data,
                  "Data Rate: %u.%u Mb/s",
                  hdr.rate.data / 2, hdr.rate.data & 1 ? 5 : 0);
      }
    }
    offset += 12;
    VALFIELD(istx, "IsTX");
    VALFIELD(frmlen, "Frame Length");

    /* dissect the 802.11 header next */
    next_tvb = tvb_new_subset(tvb, sizeof hdr, -1, -1);
    call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
}

#define IFHELP2(size, name, var, str) \
        { &hf_prism_ ## name, {					   \
            str, "prism." #var, size, BASE_HEX, NULL, 0x0, "", HFILL } },
#define INTFIELD2(size, name, str)	IFHELP2(size, name, name, str)
#define VALFIELD2(name, str) \
   IFHELP2(FT_UINT32, name ## _data, name.data, str " Field")

void
proto_register_prism(void)
{
    static hf_register_info hf[] = {
        INTFIELD2(FT_UINT32, msgcode, "Message Code")
        INTFIELD2(FT_UINT32, msglen, "Message Length")
        VALFIELD2(hosttime, "Host Time")
        VALFIELD2(mactime, "MAC Time")
        VALFIELD2(channel, "Channel")
        VALFIELD2(rssi, "RSSI")
        VALFIELD2(sq, "SQ")
        VALFIELD2(signal, "Signal")
        VALFIELD2(noise, "Noise")
        VALFIELD2(rate, "Rate")
        VALFIELD2(istx, "IsTX")
        VALFIELD2(frmlen, "Frame Length")

    };
    static gint *ett[] = {
        &ett_prism
    };

    proto_prism = proto_register_protocol("Prism", "Prism", "prism");
    proto_register_field_array(proto_prism, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_prism(void)
{
    dissector_handle_t prism_handle;

    /* handle for 802.11 dissector */
    ieee80211_handle = find_dissector("wlan");
    wlancap_handle = find_dissector("wlancap");

    prism_handle = create_dissector_handle(dissect_prism, proto_prism);
    dissector_add("wtap_encap", WTAP_ENCAP_PRISM_HEADER, prism_handle);
}
