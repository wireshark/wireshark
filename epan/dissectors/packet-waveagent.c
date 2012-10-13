/* packet-waveagent.c
 * Routines for WaveAgent dissection
 * Copyright 2009-2011, Tom Cook <tcook@ixiacom.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 * *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/strutil.h>

#define ETHERNET_INTERFACE      1
#define WLAN_INTERFACE          2

#define IPV4_TYPE               2
#define IPV6_TYPE               10

#define NUM_STATE_CHANGES       8
#define NUM_BSS                 8
#define SHORT_STR               256

#define WA_V2_PAYLOAD_OFFSET    40
#define WA_V3_PAYLOAD_OFFSET    44

/* Initialize the protocol and registered fields */
static int proto_waveagent = -1;
static int hf_waveagent_controlword = -1;
static int hf_waveagent_payloadlen = -1;
static int hf_waveagent_transnum = -1;
static int hf_waveagent_rtoken = -1;
static int hf_waveagent_flowid = -1;
static int hf_waveagent_capstatus = -1;
static int hf_waveagent_protocolversion = -1;
static int hf_waveagent_capimpl = -1;
static int hf_waveagent_id = -1;
static int hf_waveagent_bindtag = -1;
static int hf_waveagent_version = -1;
static int hf_waveagent_brokerip = -1;
static int hf_waveagent_brokerport = -1;
static int hf_waveagent_bindlevel = -1;
static int hf_waveagent_bindport = -1;
static int hf_waveagent_numinterfaces = -1;
static int hf_waveagent_capabilities2 = -1;
static int hf_waveagent_ifmask = -1;
static int hf_waveagent_commandstatus = -1;
static int hf_waveagent_syserrno = -1;
static int hf_waveagent_statusstring = -1;
static int hf_waveagent_rxdatapckts = -1;
static int hf_waveagent_rxdatabytes = -1;
static int hf_waveagent_rxpcktrate = -1;
static int hf_waveagent_rxbyterate = -1;
static int hf_waveagent_txdatapckts = -1;
static int hf_waveagent_txdatabytes = -1;
static int hf_waveagent_txpcktrate = -1;
static int hf_waveagent_txbyterate = -1;
static int hf_waveagent_looppckts = -1;
static int hf_waveagent_loopbytes = -1;
static int hf_waveagent_rxctlpckts = -1;
static int hf_waveagent_rxctlbytes = -1;
static int hf_waveagent_txctlpckts = -1;
static int hf_waveagent_txctlbytes = -1;
static int hf_waveagent_unknowncmds = -1;
static int hf_waveagent_snap = -1;
static int hf_waveagent_state = -1;
static int hf_waveagent_appstate = -1;
static int hf_waveagent_rx1pl = -1;
static int hf_waveagent_rx2pl = -1;
static int hf_waveagent_rx3pl = -1;
static int hf_waveagent_rx4pl = -1;
static int hf_waveagent_rx5pl = -1;
static int hf_waveagent_rxoospkts = -1;
static int hf_waveagent_rxmeanlatency = -1;
static int hf_waveagent_rxminlatency = -1;
static int hf_waveagent_rxmaxlatency = -1;
static int hf_waveagent_latencysum = -1;
static int hf_waveagent_latencycount = -1;
static int hf_waveagent_txflowstop = -1;
static int hf_waveagent_jitter = -1;
static int hf_waveagent_remoteport = -1;
static int hf_waveagent_remoteaddr = -1;
static int hf_waveagent_dscp = -1;
static int hf_waveagent_fsflags = -1;
static int hf_waveagent_fscbrflag = -1;
static int hf_waveagent_fscombinedsetupflag = -1;
/* static int hf_waveagent_totalbytes = -1; */
static int hf_waveagent_payfill = -1;
static int hf_waveagent_paysize = -1;
static int hf_waveagent_avgrate = -1;
static int hf_waveagent_rxflownum = -1;
static int hf_waveagent_mode = -1;
static int hf_waveagent_endpointtype = -1;
static int hf_waveagent_totalframes = -1;
static int hf_waveagent_bssidstartindex = -1;
static int hf_waveagent_bssidstopindex = -1;
static int hf_waveagent_ifindex = -1;
static int hf_waveagent_iftype = -1;
static int hf_waveagent_ifdescription = -1;
static int hf_waveagent_ifmacaddr = -1;
static int hf_waveagent_iflinkspeed = -1;
static int hf_waveagent_ifdhcp = -1;
static int hf_waveagent_ifwlanbssid = -1;
static int hf_waveagent_ifwlanssid = -1;
static int hf_waveagent_ifiptype = -1;
static int hf_waveagent_ifipv4 = -1;
static int hf_waveagent_ifipv6 = -1;
static int hf_waveagent_ifdhcpserver = -1;
static int hf_waveagent_ifgateway = -1;
static int hf_waveagent_ifdnsserver = -1;
static int hf_waveagent_ifethl2status = -1;
static int hf_waveagent_ifwlanl2status = -1;
static int hf_waveagent_ifl3status = -1;
static int hf_waveagent_totalbssid = -1;
static int hf_waveagent_returnedbssid = -1;
static int hf_waveagent_scanbssid = -1;
static int hf_waveagent_scanssid = -1;
static int hf_waveagent_ifwlanrssi = -1;
static int hf_waveagent_ifwlansupprates = -1;
static int hf_waveagent_ifwlancapabilities = -1;
static int hf_waveagent_ifwlanchannel = -1;
static int hf_waveagent_ifwlanprivacy = -1;
static int hf_waveagent_ifwlanbssmode = -1;
static int hf_waveagent_ifwlannoise = -1;
static int hf_waveagent_ifphytypes = -1;
static int hf_waveagent_ifphytypebit0 = -1;
static int hf_waveagent_ifphytypebit1 = -1;
static int hf_waveagent_ifphytypebit2 = -1;
static int hf_waveagent_ifphytypebit3 = -1;
/* static int hf_waveagent_ifphytypebit4 = -1; */
static int hf_waveagent_ifwlanauthentication = -1;
static int hf_waveagent_ifwlancipher = -1;
static int hf_waveagent_delayfactor = -1;
static int hf_waveagent_medialossrate = -1;
static int hf_waveagent_txstartts = -1;
static int hf_waveagent_txendts = -1;
static int hf_waveagent_rxstartts = -1;
static int hf_waveagent_rxendts = -1;
static int hf_waveagent_oidcode = -1;
static int hf_waveagent_oidvalue = -1;
static int hf_waveagent_destip = -1;
static int hf_waveagent_destport = -1;
static int hf_waveagent_connectflags = -1;
static int hf_waveagent_connecttype = -1;
static int hf_waveagent_minrssi = -1;
static int hf_waveagent_connecttimeout = -1;
static int hf_waveagent_connectattempts = -1;
static int hf_waveagent_reason = -1;
static int hf_waveagent_sigsequencenum = -1;
static int hf_waveagent_relaydestid = -1;
static int hf_waveagent_relaysrcid = -1;
static int hf_waveagent_relaymessagest = -1;

/* Initialize the subtree pointers */
static gint ett_waveagent = -1;
static gint ett_statechange = -1;
static gint ett_phytypes = -1;
static gint ett_fsflags = -1;
static gint ett_scindex[8] = { -1, -1, -1, -1, -1, -1, -1, -1 };  /* NUM_STATE_CHANGES */
static gint ett_bss[8]     = { -1, -1, -1, -1, -1, -1, -1, -1 };  /* NUM_BSS           */
static gint ett_relaymessage = -1;


static const value_string control_words[] = {
    { 0x01, "Receive, Count, Discard"},
    { 0x02, "Receive, Count, Loopback"},
    { 0x03, "Receive, Count, Push timestamp, Discard"},
    { 0x04, "Receive, Count, Push timestamp, Loopback"},
    { 0x08, "Transmit"},
    { 0x11, "Start Flow"},
    { 0x12, "Stop Flow"},
    { 0x20, "Stats Reset"},
    { 0x21, "Stats Request"},
    { 0x22, "Flow Stats Reset"},
    { 0x23, "Scan Results Request"},
    { 0x24, "Interface Info Request"},
    { 0x25, "Interface Change Info Request"},
    { 0x26, "OID Request"},
    { 0x2e, "Scan Results Response"},
    { 0x2f, "Stats Response"},
    { 0x30, "Interface Info Response"},
    { 0x31, "Interface Change Info Response"},
    { 0x32, "OID Response"},  /* XXX: is this correct ? entry originally located after 0x41 */
    { 0x3e, "Relay Message"},
    { 0x3f, "Relay Response"},
    { 0x40, "Client Connect Request"},
    { 0x41, "Client Disconnect Request"},
    { 0x80, "Capabilities Request"},
    { 0x81, "Capabilities Response"},
    { 0x82, "Reserve Request"},
    { 0x84, "Release Request"},
    { 0x85, "Flow Setup"},
    { 0x86, "Flow Destroy"},
    { 0x87, "Flow Connect"},
    { 0x88, "Flow Disconnect"},
    { 0x89, "Flow Listen"},
    { 0x8a, "Scan Request"},
    { 0x8b, "Learning Message"},
    { 0x8f, "Command Response"},
    { 0, NULL},
};
static value_string_ext control_words_ext = VALUE_STRING_EXT_INIT(control_words);

/* Dissects the WLAN interface stats structure */
static void dissect_wlan_if_stats(guint32 starting_offset, proto_item *parent_tree, tvbuff_t *tvb)
{
    proto_item *phy_types;
    proto_tree *phy_types_tree;
    guint32     phy_types_bitfield, noise_floor;

    proto_tree_add_item(parent_tree,
        hf_waveagent_ifwlanbssid, tvb, starting_offset, 6, ENC_NA);

    /* two bytes of pad go here */

    proto_tree_add_item(parent_tree,
        hf_waveagent_ifwlanssid, tvb, starting_offset + 8, 32, ENC_ASCII|ENC_NA);

    /* 4 byte SSID length field not reported */

    proto_tree_add_item(parent_tree,
        hf_waveagent_ifwlanrssi, tvb, starting_offset + 44, 4, ENC_BIG_ENDIAN);

    noise_floor = tvb_get_ntohl(tvb, starting_offset + 48);

    if (noise_floor != 0x7fffffff) {
        proto_tree_add_item(parent_tree,
            hf_waveagent_ifwlannoise, tvb, starting_offset + 48, 4, ENC_BIG_ENDIAN);
    }
    else {
        proto_tree_add_int_format(parent_tree,
            hf_waveagent_ifwlannoise, tvb, starting_offset + 48, 4, noise_floor,
            "WLAN Interface Noise Floor (dBm): Not Reported");
    }

    phy_types_bitfield = tvb_get_ntohl(tvb, starting_offset + 52);

    phy_types = proto_tree_add_uint(parent_tree, hf_waveagent_ifphytypes,
                                tvb, starting_offset + 52, 4, phy_types_bitfield);

    phy_types_tree = proto_item_add_subtree(phy_types, ett_phytypes);

    proto_tree_add_item(phy_types_tree,
            hf_waveagent_ifphytypebit0, tvb, starting_offset + 55, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(phy_types_tree,
            hf_waveagent_ifphytypebit1, tvb, starting_offset + 55, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(phy_types_tree,
            hf_waveagent_ifphytypebit2, tvb, starting_offset + 55, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(phy_types_tree,
            hf_waveagent_ifphytypebit3, tvb, starting_offset + 55, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(parent_tree,
        hf_waveagent_ifwlanauthentication, tvb, starting_offset + 56, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(parent_tree,
        hf_waveagent_ifwlancipher, tvb, starting_offset + 60, 4, ENC_BIG_ENDIAN);
}

static void dissect_wa_payload(guint32 starting_offset, proto_item *parent_tree, tvbuff_t *tvb, guint32 control_word, guint8 version)
{
    switch (control_word)
    {
        case 0x11:   /* Flow start message */
            proto_tree_add_item(parent_tree,
                hf_waveagent_payfill, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_paysize, tvb, starting_offset+4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_avgrate, tvb, starting_offset+8, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_totalframes, tvb, starting_offset+12, 4, ENC_BIG_ENDIAN);

            break;

        case 0x23:   /* Scan results request */
            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_bssidstartindex, tvb, starting_offset+4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_bssidstopindex, tvb, starting_offset+8, 4, ENC_BIG_ENDIAN);

            break;

        case 0x24:   /* Interface info request */
        case 0x25:   /* Interface change info request */
        case 0x8a:   /* Scan request */
            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            break;

        case 0x26:   /* OID request */
            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_oidcode, tvb, starting_offset+4, 4, ENC_BIG_ENDIAN);

            break;

        case 0x30: {  /* Interface stats response */
            guint32 if_type;

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            if_type = tvb_get_ntohl(tvb, starting_offset + 4);

            proto_tree_add_item(parent_tree,
                hf_waveagent_iftype, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifdhcp, tvb, starting_offset + 8, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifmacaddr, tvb, starting_offset + 12, 6, ENC_NA);

            /* 2 bytes of pad go here */

            proto_tree_add_item(parent_tree,
                hf_waveagent_iflinkspeed, tvb, starting_offset + 20, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifdescription, tvb, starting_offset + 24, 128, ENC_ASCII|ENC_NA);

            /* 4 byte length field goes here - skip it */

            /* two bytes of pad go here */

            /* If we have WLAN interface, then report the following */
            if (if_type == WLAN_INTERFACE)
                dissect_wlan_if_stats(starting_offset + 156, parent_tree, tvb);

            /* Next come the BindingAddress fields (for each address):
                2 bytes:  IP type (v4 or v6)
                2 bytes:  address length
                4 bytes:  service number (not used)
                16 bytes: IP address     */

            /* for the bound IP address, report both IP type and address */

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifiptype, tvb, starting_offset + 252, 2, ENC_BIG_ENDIAN);

            if (tvb_get_ntohs(tvb, starting_offset + 252) == IPV4_TYPE) {
                proto_tree_add_item(parent_tree,
                    hf_waveagent_ifipv4, tvb, starting_offset + 260, 4, ENC_BIG_ENDIAN);  /* grab the last 4 bytes of the IP address field */
            }
            else {
                proto_tree_add_item(parent_tree,
                    hf_waveagent_ifipv6, tvb, starting_offset + 260, 16, ENC_NA);
            }

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifdhcpserver, tvb, starting_offset + 284, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifgateway,    tvb, starting_offset + 308, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifdnsserver,  tvb, starting_offset + 332, 4, ENC_BIG_ENDIAN);

            break;
        }

        case 0x31:  {  /* Interface change info response */
            guint32 offset;
            guint32 if_type;
            guint32 delta;
            guint32 iLoop;

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            if_type = tvb_get_ntohl(tvb, starting_offset + 4);

            proto_tree_add_item(parent_tree,
                hf_waveagent_iftype, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            offset = starting_offset + 8;
            delta = 156;

            for (iLoop = 0; iLoop < NUM_STATE_CHANGES; iLoop++) {
                proto_item *stIndex;
                proto_tree *st_change_index_tree;
                guint32     if_status;
                int         current_offset;

                current_offset = offset + iLoop * delta;

                /* Check to see if the interface entry is valid */
                if_status = tvb_get_ntohl(tvb, current_offset);
                if (if_status == 0) continue;  /* No entry at this index, keep going */

                /* Add index specific trees to hide the details */
                stIndex = proto_tree_add_uint_format_value(parent_tree,
                    hf_waveagent_ifwlanl2status, tvb, current_offset, 4, if_status, "Interface state change %d", iLoop);

                st_change_index_tree = proto_item_add_subtree(stIndex, ett_scindex[iLoop]);

                if (if_type == WLAN_INTERFACE) {
                    proto_tree_add_item(st_change_index_tree,
                        hf_waveagent_ifwlanl2status, tvb, current_offset, 4, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item(st_change_index_tree,
                        hf_waveagent_ifethl2status, tvb, current_offset, 4, ENC_BIG_ENDIAN);
                }

                proto_tree_add_item(st_change_index_tree,
                    hf_waveagent_ifl3status, tvb, current_offset + 4, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(st_change_index_tree,
                    hf_waveagent_iflinkspeed, tvb, current_offset + 8, 4, ENC_BIG_ENDIAN);

                if (if_type == WLAN_INTERFACE) {
                    dissect_wlan_if_stats(current_offset + 12, st_change_index_tree, tvb);
                }

                proto_tree_add_item(st_change_index_tree,
                    hf_waveagent_snap, tvb, current_offset + 108, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(st_change_index_tree,
                    hf_waveagent_ifiptype, tvb, current_offset + 116, 2, ENC_BIG_ENDIAN);

                if (tvb_get_ntohs(tvb, current_offset + 116) == IPV4_TYPE) {
                    proto_tree_add_item(st_change_index_tree,
                        hf_waveagent_ifipv4, tvb, current_offset + 124, 4, ENC_BIG_ENDIAN);  /* grab the last 4 bytes of the IP address field */
                }
                else {
                    proto_tree_add_item(st_change_index_tree,
                        hf_waveagent_ifipv6, tvb, current_offset + 124, 16, ENC_NA);
                }

                /* 16 bytes of padding */
            }

            break;
        }

        case 0x32:   /* OID response */
            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_oidcode, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_oidvalue, tvb, starting_offset + 12, 1024, ENC_ASCII|ENC_NA);

            break;

        case 0x2e: {  /* scan results response message */
            guint32        offset;
            proto_item    *pi;
            guint32        num_bss_entries;
            guint32        tag_len;
            guint32        delta;
            guint32        iLoop;
            emem_strbuf_t *sb;

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);


            proto_tree_add_item(parent_tree,
                hf_waveagent_totalbssid, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            pi = proto_tree_add_item(parent_tree,
                hf_waveagent_returnedbssid, tvb, starting_offset + 8, 4, ENC_BIG_ENDIAN);

            num_bss_entries = tvb_get_ntohl(tvb, starting_offset + 8);

            if (num_bss_entries > NUM_BSS) {
                proto_item_append_text(pi, " [**Too large: Limiting to " STRINGIFY(NUM_BSS) "]");
                num_bss_entries = NUM_BSS;
            }
            /* Add 4 bytes of pad for the offset */

            offset = starting_offset + 16;
            delta  = 148;

            sb = ep_strbuf_sized_new(8, SHORT_STR);

            for (iLoop = 0; iLoop < num_bss_entries; iLoop++)
            {
                proto_item *bssIndex;
                proto_tree *bss_tree;
                int         current_offset;

                ep_strbuf_truncate(sb, 0);

                current_offset = offset + iLoop * delta;

                bssIndex = proto_tree_add_item(parent_tree,
                    hf_waveagent_scanssid, tvb, current_offset, 32, ENC_ASCII|ENC_NA);

                bss_tree = proto_item_add_subtree(bssIndex, ett_bss[iLoop]);

                tag_len = tvb_get_ntohl(tvb, current_offset + 52);

                if (tag_len != 0) {
                    const guint8  *tag_data_ptr;
                    guint32        isr;

                    tag_data_ptr = tvb_get_ptr (tvb, offset + 36, tag_len);

                    for (isr = 0; isr < tag_len; isr++) {
                        if (tag_data_ptr[isr] == 0xFF){
                            proto_tree_add_string (bss_tree, hf_waveagent_ifwlansupprates, tvb, offset + 36 + isr,
                                                   1,
                                                   "BSS requires support for mandatory features of HT PHY (IEEE 802.11"
                                                   " - Clause 20)");
                        } else {
                            ep_strbuf_append_printf(sb, "%2.1f%s ",
                                      (tag_data_ptr[isr] & 0x7F) * 0.5,
                                      (tag_data_ptr[isr] & 0x80) ? "(B)" : "");

                        }
                    }
                    ep_strbuf_append(sb, " [Mbit/sec]");
                }
                else {
                    ep_strbuf_append(sb, "Not defined");
                }

                proto_tree_add_string (bss_tree, hf_waveagent_ifwlansupprates, tvb, offset + 36,
                    tag_len, sb->str);

                proto_tree_add_item(bss_tree,
                    hf_waveagent_scanbssid, tvb, current_offset + 56, 6, ENC_NA);

                proto_tree_add_item(bss_tree,
                    hf_waveagent_ifwlancapabilities, tvb, current_offset + 62, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(bss_tree,
                    hf_waveagent_ifwlanrssi, tvb, current_offset + 64, 4, ENC_BIG_ENDIAN);

                /*  For now this is just a 4 byte pad, so comment it out...  */
#if 0
                proto_tree_add_item(bss_tree,
                    hf_waveagent_ifwlansigquality, tvb, current_offset + 68, 4, ENC_BIG_ENDIAN);
#endif
                proto_tree_add_item(bss_tree,
                    hf_waveagent_ifwlanchannel, tvb, current_offset + 72, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(bss_tree,
                    hf_waveagent_ifwlanprivacy, tvb, current_offset + 76, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(bss_tree,
                    hf_waveagent_ifwlanbssmode, tvb, current_offset + 80, 4, ENC_BIG_ENDIAN);
            }
            break;
        }

        case 0x2f:   /* Stats response message */
            if (version < 3) {
                /* For version 2 WA protocol the capability status is not in the header but in the CAP
                   RESPONSE.  Need to read it here and then advance the payload offset.  This is a
                   packet that had a structure change in the beginning of the packet when moving
                   to v3 */
                proto_tree_add_item(parent_tree,
                    hf_waveagent_capstatus, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_protocolversion, tvb, starting_offset, 1, ENC_BIG_ENDIAN);

                starting_offset += 4;
            }

            proto_tree_add_item(parent_tree,
                hf_waveagent_capimpl, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                       hf_waveagent_state, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                       hf_waveagent_appstate, tvb, starting_offset + 8, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rxdatapckts, tvb, starting_offset + 12, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rxdatabytes, tvb, starting_offset + 20, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rxpcktrate, tvb, starting_offset + 28, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rxbyterate, tvb, starting_offset + 36, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_txdatapckts, tvb, starting_offset + 44, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_txdatabytes, tvb, starting_offset + 52, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_txpcktrate, tvb, starting_offset + 60, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_txbyterate, tvb, starting_offset + 68, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_looppckts, tvb, starting_offset + 76, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_loopbytes, tvb, starting_offset + 84, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rxctlpckts, tvb, starting_offset + 92, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rxctlbytes, tvb, starting_offset + 100, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_txctlpckts, tvb, starting_offset + 108, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_txctlbytes, tvb, starting_offset + 116, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_unknowncmds, tvb, starting_offset + 124, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_snap, tvb, starting_offset + 132, 8, ENC_BIG_ENDIAN);

#if 0
            proto_tree_add_item(parent_tree,
                hf_waveagent_tstamp1, tvb, 140, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_tstamp2, tvb, 144, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_tstamp3, tvb, 148, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_tstamp4, tvb, 152, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_tstamp5, tvb, 156, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_tstamp6, tvb, 160, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_tstamp7, tvb, 164, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_tstamp8, tvb, 168, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_minlcldelta, tvb, 172, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_maxlcldelta, tvb, 176, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_avglcldelta, tvb, 180, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_minremdelta, tvb, 184, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_maxremdelta, tvb, 188, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_avgremdelta, tvb, 192, 4, ENC_BIG_ENDIAN);
#endif
            proto_tree_add_item(parent_tree,
                hf_waveagent_rx1pl, tvb, starting_offset + 284, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rx2pl, tvb, starting_offset + 292, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rx3pl, tvb, starting_offset + 300, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rx4pl, tvb, starting_offset + 308, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rx5pl, tvb, starting_offset + 316, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_rxoospkts, tvb, starting_offset + 324, 8, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_jitter, tvb, starting_offset + 356, 8, ENC_BIG_ENDIAN);

            if (version >= 3) {
                proto_tree_add_item(parent_tree,
                    hf_waveagent_delayfactor, tvb, starting_offset + 364, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_medialossrate, tvb, starting_offset + 372, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_txstartts, tvb, starting_offset + 380, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_txendts, tvb, starting_offset + 388, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_rxstartts, tvb, starting_offset + 396, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_rxendts, tvb, starting_offset + 404, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_latencysum, tvb, starting_offset + 412, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_latencycount, tvb, starting_offset + 420, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_txflowstop, tvb, starting_offset + 428, 8, ENC_BIG_ENDIAN);
            }

            break;

        case 0x40: {
            guint32 offset;
            guint32 delta;
            guint32 iLoop;
            guint32 num_bss_entries;

            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_connectflags, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_connecttype, tvb, starting_offset + 8, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_scanssid, tvb, starting_offset + 12, 32, ENC_ASCII|ENC_NA);

            num_bss_entries = tvb_get_ntohl(tvb, starting_offset + 142);

            offset = starting_offset + 46;
            delta = 6;
            for (iLoop = 0; iLoop < num_bss_entries; iLoop++)
            {
                int current_offset;
                current_offset = offset + iLoop * delta;

                proto_tree_add_item(parent_tree,
                    hf_waveagent_scanbssid, tvb, current_offset, 6, ENC_NA);
            }

            proto_tree_add_item(parent_tree,
                hf_waveagent_minrssi, tvb, starting_offset + 146, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_connecttimeout, tvb, starting_offset + 150, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_connectattempts, tvb, starting_offset + 154, 4, ENC_BIG_ENDIAN);

            break;
        }

        case 0x41:
            proto_tree_add_item(parent_tree,
                hf_waveagent_ifindex, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_reason, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            break;

        case 0x81:   /* Capabilities response */
            if (version < 3) {
                /* For version 2 WA protocol the capability status is not in the header but in the CAP
                   RESPONSE.  Need to read it here and then advance the payload offset.  This is a
                   packet that had a structure change in the beginning of the packet when moving
                   to v3 */
                proto_tree_add_item(parent_tree,
                    hf_waveagent_capstatus, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_protocolversion, tvb, starting_offset, 1, ENC_BIG_ENDIAN);

                starting_offset += 4;
            }

            proto_tree_add_item(parent_tree,
                hf_waveagent_capimpl, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_id, tvb, starting_offset + 4, 128, ENC_ASCII|ENC_NA);

            proto_tree_add_item(parent_tree,
                hf_waveagent_bindtag, tvb, starting_offset + 136, 128, ENC_ASCII|ENC_NA);

            proto_tree_add_item(parent_tree,
                hf_waveagent_version, tvb, starting_offset + 268, 128, ENC_ASCII|ENC_NA);

            proto_tree_add_item(parent_tree,
                hf_waveagent_brokerip, tvb, starting_offset + 400, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_brokerport, tvb, starting_offset + 404, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_bindlevel, tvb, starting_offset + 408, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_bindport, tvb, starting_offset + 412, 4, ENC_BIG_ENDIAN);

            if (version >= 3) {
                proto_tree_add_item(parent_tree,
                    hf_waveagent_capabilities2, tvb, starting_offset + 416, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_numinterfaces, tvb, starting_offset + 420, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_ifmask, tvb, starting_offset + 424, 4, ENC_BIG_ENDIAN);
            }

            break;

        case 0x82:    /* Reserve request */
            proto_tree_add_item(parent_tree,
                hf_waveagent_bindtag, tvb, starting_offset, 128, ENC_ASCII|ENC_NA);

            proto_tree_add_item(parent_tree,
                hf_waveagent_brokerip, tvb, starting_offset + 132, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_brokerport, tvb, starting_offset + 136, 4, ENC_BIG_ENDIAN);

            break;

        case 0x85: {   /* Flow setup */
            proto_tree *fs_flags;
            proto_tree *fs_flags_tree;
            guint32     flags_bitfield;

            if (version < 3) {
                proto_tree_add_item(parent_tree,
                    hf_waveagent_rxflownum, tvb, starting_offset, 4, ENC_BIG_ENDIAN);
            }

            proto_tree_add_item(parent_tree,
                hf_waveagent_mode, tvb, starting_offset + 7, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_endpointtype, tvb, starting_offset + 7, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_bindport, tvb, starting_offset + 8, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_bindlevel, tvb, starting_offset + 12, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_remoteport, tvb, starting_offset + 16, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_remoteaddr, tvb, starting_offset + 24, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_dscp, tvb, starting_offset + 40, 4, ENC_BIG_ENDIAN);

            flags_bitfield = tvb_get_ntohl(tvb, starting_offset + 44);

            fs_flags = proto_tree_add_uint(parent_tree, hf_waveagent_fsflags,
                                        tvb, starting_offset + 44, 4, flags_bitfield);

            fs_flags_tree = proto_item_add_subtree(fs_flags, ett_fsflags);

            proto_tree_add_item(fs_flags_tree,
                    hf_waveagent_fscbrflag, tvb, starting_offset + 47, 1, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(fs_flags_tree,
                    hf_waveagent_fscombinedsetupflag, tvb, starting_offset + 47, 1, ENC_LITTLE_ENDIAN);

            if (version >= 3) {
                proto_tree_add_item(parent_tree,
                    hf_waveagent_ifindex, tvb, starting_offset + 48, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_payfill, tvb, starting_offset + 52, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_paysize, tvb, starting_offset + 56, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_avgrate, tvb, starting_offset + 60, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parent_tree,
                    hf_waveagent_totalframes, tvb, starting_offset + 64, 4, ENC_BIG_ENDIAN);
            }

            break;
        }

        case 0x8b:
            proto_tree_add_item(parent_tree,
                hf_waveagent_destip, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_destport, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_connectflags, tvb, starting_offset + 8, 4, ENC_BIG_ENDIAN);

            break;

        case 0x3f:  /* Relay response */
        case 0x8f:  /* Command Response */
            proto_tree_add_item(parent_tree,
                hf_waveagent_commandstatus, tvb, starting_offset, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_syserrno, tvb, starting_offset + 4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(parent_tree,
                hf_waveagent_statusstring, tvb, starting_offset + 8, 128, ENC_ASCII|ENC_NA);

            break;
    }
}



static guint32 dissect_wa_header(guint32 starting_offset, proto_item *parent_tree, tvbuff_t *tvb, guint8 version)
{
    guint32 wa_payload_offset;

    proto_tree_add_item(parent_tree,
        hf_waveagent_controlword, tvb, 30+starting_offset, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(parent_tree,
        hf_waveagent_payloadlen, tvb, 20+starting_offset, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(parent_tree,
        hf_waveagent_transnum, tvb, 24+starting_offset, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(parent_tree,
        hf_waveagent_rtoken, tvb, 32+starting_offset, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(parent_tree,
        hf_waveagent_flowid, tvb, 36+starting_offset, 4, ENC_BIG_ENDIAN);

    if (version >= 3) {
        proto_tree_add_item(parent_tree,
            hf_waveagent_capstatus, tvb, 40+starting_offset, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(parent_tree,
            hf_waveagent_protocolversion, tvb, 40+starting_offset, 1, ENC_BIG_ENDIAN);

        wa_payload_offset = WA_V3_PAYLOAD_OFFSET + starting_offset;
    }
    else {
        wa_payload_offset = WA_V2_PAYLOAD_OFFSET + starting_offset;
    }

    proto_tree_add_item(parent_tree,
        hf_waveagent_sigsequencenum, tvb, 4+starting_offset, 1, ENC_BIG_ENDIAN);

    return wa_payload_offset;
}

/* Dissect the packets */
static int dissect_waveagent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti, *rmi;
    proto_tree *waveagent_tree, *relay_message_tree, *payload_tree;
    guint8      signature_start, signature_end;
    guint8      version;
    guint32     magic_number;
    guint32     control_word, paylen;
    guint32     wa_payload_offset;

    /* Check that there's enough data */
    if (tvb_length(tvb) < 52 )
        return 0;

    signature_start = tvb_get_guint8(tvb, 0);
    signature_end   = tvb_get_guint8(tvb, 15);
    version         = ((tvb_get_ntohl(tvb, 16) & 0xF0000000) >> 28 == 1) ? 3 : 2;       /* Mask version bit off */
    magic_number    = tvb_get_ntohl(tvb, 16) & 0x0FFFFFFF;  /* Mask magic number off */

    if ( ((signature_start != 0xcc) && (signature_start !=0xdd)) ||
         (signature_end != 0xE2) || (magic_number != 0x0F87C3A5) )
        /*  This packet does not appear to belong to WaveAgent.
         *  Return 0 to give another dissector a chance to dissect it.
         */
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WA");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Grab the control word, parse the WaveAgent payload accordingly */

    control_word = tvb_get_ntohl(tvb, 28);
    paylen       = tvb_get_ntohl(tvb, 20);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%x)",
        val_to_str_ext_const(control_word, &control_words_ext, "Unknown"), control_word);

    if (tree) {
        /* create display subtree for the protocol */
        ti = proto_tree_add_protocol_format(tree, proto_waveagent, tvb, 0, -1,
                        "WaveAgent, %s (0x%x), Payload Length %u Bytes",
                        val_to_str_ext_const(control_word, &control_words_ext, "Unknown"), control_word, paylen);

        waveagent_tree = proto_item_add_subtree(ti, ett_waveagent);

        wa_payload_offset = dissect_wa_header(0, waveagent_tree, tvb, version);

        payload_tree = waveagent_tree;

        /* Need to check for a relay message.  If so, parse the extra fields and then parse the WA packet */
        if (control_word == 0x3e)
        {
            proto_tree_add_item(waveagent_tree,
                hf_waveagent_relaydestid, tvb, wa_payload_offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(waveagent_tree,
                hf_waveagent_relaysrcid, tvb, wa_payload_offset+4, 4, ENC_BIG_ENDIAN);

            /* Parse control_word of the relay message */
            control_word = tvb_get_ntohl(tvb, wa_payload_offset+12+28);
                rmi = proto_tree_add_none_format(waveagent_tree, hf_waveagent_relaymessagest,
                                                 tvb, wa_payload_offset+12+28, 0,
                                                 "Relayed WaveAgent Message, %s (0x%x)",
                                                 val_to_str_ext_const(control_word, &control_words_ext, "Unknown"),
                                                 control_word);

            relay_message_tree = proto_item_add_subtree(rmi, ett_relaymessage);

            wa_payload_offset = dissect_wa_header(wa_payload_offset+12, relay_message_tree, tvb, version);
            payload_tree = relay_message_tree;
        }

        dissect_wa_payload(wa_payload_offset, payload_tree, tvb, control_word, version);
    }

/* Return the amount of data this dissector was able to dissect */
    return tvb_length(tvb);
}

static gboolean dissect_waveagent_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return (dissect_waveagent(tvb, pinfo, tree) > 0) ? TRUE : FALSE;
}


#if 0
static const value_string status_values[] = {
    { 0, "OK" },
    { 1, "In Use" },
    { 0, NULL }
};
#endif

/* Register the protocol with Wireshark */

void proto_register_waveagent(void)
{
    static const value_string tcp_states[] = {
        { 0, "Closed" },
        { 1, "Listen" },
        { 2, "SYN Sent" },
        { 3, "SYN received" },
        { 4, "Established" },
        { 5, "FIN Wait 1" },
        { 6, "FIN Wait 2" },
        { 7, "Close Wait" },
        { 8, "Closing" },
        { 9, "Last ACK" },
        { 10, "Time Wait" },
        { 0, NULL },
    };

    static const value_string app_states[] = {
        { 0, "IDLE" },
        { 1, "READY" },
        { 0, NULL },
    };

    static const value_string wa_modes[] = {
        { 0, "In-band" },
        { 1, "Source" },
        { 2, "Sink" },
        { 3, "Loopback" },
        { 0, NULL },
    };

    static const value_string wa_endpointtypes[] = {
        { 0, "Undefined" },
        { 1, "Server" },
        { 2, "Client" },
        { 0, NULL },
    };

    static const value_string binding_levels[] = {
        { 0, "WLAN" },
        { 1, "Ethernet" },
        { 2, "IP" },
        { 3, "UDP" },
        { 4, "TCP" },
        { 5, "FIN Wait 1" },
        { 6, "FIN Wait 2" },
        { 7, "Close Wait" },
        { 8, "Closing" },
        { 9, "Last ACK" },
        { 10, "Time Wait" },
        { 0, NULL },
    };

    static const value_string if_types[] = {
        { ETHERNET_INTERFACE, "Ethernet" },
        { WLAN_INTERFACE, "WLAN" },
        { 0, NULL },
    };

    static const value_string no_yes[] = {
        { 0, "No" },
        { 1, "Yes" },
        { 0, NULL },
    };

    static const value_string ip_types[] = {
        { 0,  "Unspecified" },
        { IPV4_TYPE,  "IPv4" },
        { IPV6_TYPE, "IPv6" },
        { 0, NULL },
    };

    static const value_string if_l3_states[] = {
        { 0, "Uninitialized" },
        { 1, "Disconnected" },
        { 2, "Connected" },
        { 3, "Error" },
        { 0, NULL },
    };

    static const value_string if_wlan_states[] = {
        { 0, "Uninitialized" },
        { 1, "Not ready" },
        { 2, "Connected" },
        { 3, "Ad Hoc network formed" },
        { 4, "Disconnecting" },
        { 5, "Disconnected" },
        { 6, "Associating" },
        { 7, "Discovering" },
        { 8, "Authenticating" },
        { 0, NULL },
    };

    static const value_string if_eth_states[] = {
        { 0, "Uninitialized" },
        { 1, "Not Operational" },
        { 2, "Unreachable" },
        { 3, "Disconnected" },
        { 4, "Connecting" },
        { 5, "Connected" },
        { 6, "Operational" },
        { 7, "Error" },
        { 0, NULL },
    };

    static const value_string bss_modes[] = {
        { 0, "Infrastructure" },
        { 1, "IBSS" },
        { 2, "Unknown" },
        { 0, NULL },
    };

    static const value_string auth_algs[] = {
        { 0,  "Open" },
        { 1,  "Shared Key" },
        { 2,  "WPA" },
        { 4,  "WPA PSK" },
        { 8,  "WPA2" },
        { 16, "WPA2 PSK" },
        { 0, NULL },
    };

    static const value_string cipher_algs[] = {
        { 0,  "None" },
        { 1,  "WEP 40" },
        { 2,  "WEP 104" },
        { 4,  "WEP" },
        { 8,  "TKIP" },
        { 16, "CCMP" },
        { 0, NULL },
    };

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {

    /* START: General purpose message fields - used in multiple messages */
        { &hf_waveagent_controlword,
        { "Control Word", "waveagent.cword",
        FT_UINT16, BASE_HEX | BASE_EXT_STRING, &control_words_ext, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_payloadlen,
        { "Payload Length", "waveagent.paylen",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_transnum,
        { "Transaction Number", "waveagent.transnum",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rtoken,
        { "Reservation Token", "waveagent.rtoken",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_flowid,
        { "Flow ID", "waveagent.flowid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_capstatus,
        { "Capabilities Status", "waveagent.capstatus",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_protocolversion,
        { "Protocol Version", "waveagent.protocolversion",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_capimpl,
        { "Capabilities Implementation", "waveagent.capimpl",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_sigsequencenum,
        { "Signature Sequence Number", "waveagent.sigsequencenum",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_id,
        { "ID", "waveagent.id",
        FT_STRING, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_bindtag,
        { "Binding Tag", "waveagent.bindtag",
        FT_STRING, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_version,
        { "Version", "waveagent.version",
        FT_STRING, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_brokerip,
        { "Broker IP address", "waveagent.brokerip",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_brokerport,
        { "Broker Port", "waveagent.brokerport",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_bindlevel,
        { "Binding Level", "waveagent.bindlevel",
        FT_UINT32, BASE_DEC, VALS(binding_levels), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_bindport,
        { "Binding Port", "waveagent.bindport",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifindex,
        { "Interface Index", "waveagent.ifindex",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
    /* END: General purpose message fields - used in multiple messages */

    /* START: Capabilities response fields (specific to this message, other general fields are also used) */
        { &hf_waveagent_capabilities2,
        { "Additional Capabilities", "waveagent.capabilities2",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_numinterfaces,
        { "Number of WA Interfaces", "waveagent.numinterfaces",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifmask,
        { "Mask of Active Interfaces", "waveagent.ifmask",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },
    /* END: Capabilities response fields (specific to this message, other general fields are also used) */

    /* START: Command response message fields */
        { &hf_waveagent_commandstatus,
        { "Status of Previous Command", "waveagent.cmdstat",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_syserrno,
        { "System Error Number", "waveagent.syserrno",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_statusstring,
        { "Status Message", "waveagent.statmsg",
        FT_STRING, 0, NULL, 0x0,
        NULL, HFILL } },
    /* END: Command response message fields */

    /* START: Stats response message fields */
        { &hf_waveagent_rxdatapckts,
        { "Received Data Packets", "waveagent.rxdpkts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxdatabytes,
        { "Received Data Bytes", "waveagent.rxdbytes",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxpcktrate,
        { "Received Data Packet Rate (pps)", "waveagent.rxpktrate",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxbyterate,
        { "Received Byte Rate", "waveagent.rxbyterate",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txdatapckts,
        { "Transmitted Data Packets", "waveagent.txdpkts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txdatabytes,
        { "Transmitted Data Bytes", "waveagent.txdbytes",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txpcktrate,
        { "Transmitted Data Packet Rate (pps)", "waveagent.txpktrate",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txbyterate,
        { "Transmitted Byte Rate", "waveagent.txbyterate",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_looppckts,
        { "Loopback Packets", "waveagent.looppckts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_loopbytes,
        { "Loopback Bytes", "waveagent.loopbytes",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxctlpckts,
        { "Received Control Packets", "waveagent.rxctlpkts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxctlbytes,
        { "Received Control Bytes", "waveagent.rxctlbytes",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txctlpckts,
        { "Transmitted Control Packets", "waveagent.txctlpkts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txctlbytes,
        { "Transmitted Control Bytes", "waveagent.txctlbytes",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_unknowncmds,
        { "Unknown Commands", "waveagent.unkcmds",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_snap,
        { "Time Snap for Counters", "waveagent.snap",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_appstate,
        { "TCP State", "waveagent.state",
        FT_UINT32, BASE_DEC, VALS(tcp_states), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_state,
        { "Application State", "waveagent.appstate",
        FT_UINT32, BASE_DEC, VALS(app_states), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rx1pl,
        { "Instances of single packet loss", "waveagent.rx1pl",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rx2pl,
        { "Instances of 2 sequential packets lost", "waveagent.rx2pl",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rx3pl,
        { "Instances of 3 sequential packets lost", "waveagent.rx3pl",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rx4pl,
        { "Instances of 4 sequential packets lost", "waveagent.rx4pl",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rx5pl,
        { "Instances of 5 sequential packets lost", "waveagent.rx5pl",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxoospkts,
        { "Instances of out-of-sequence packets", "waveagent.rxoospkts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxmeanlatency,
        { "Rx Mean latency", "waveagent.rxmeanlatency",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxminlatency,
        { "Rx Minimum latency", "waveagent.rxminlatency",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxmaxlatency,
        { "Rx Maximum latency", "waveagent.rxmaxlatency",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_jitter,
        { "Jitter (microseconds)", "waveagent.jitter",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_delayfactor,
        { "Delay Factor", "waveagent.delayfactor",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_medialossrate,
        { "Media Loss Rate", "waveagent.medialossrate",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txstartts,
        { "Timestamp for first Tx flow packet", "waveagent.txstartts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txendts,
        { "Timestamp for last Tx flow packet", "waveagent.txendts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxstartts,
        { "Timestamp for first Rx flow packet", "waveagent.rxstartts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_rxendts,
        { "Timestamp for last Rx flow packet", "waveagent.rxendts",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_latencysum,
        { "Sum of latencies across all received packets", "waveagent.latencysum",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_latencycount,
        { "Count of packets included in the latency sum", "waveagent.latencycount",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_txflowstop,
        { "Timestamp for Tx flow stop message", "waveagent.txflowstop",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
    /* END Stats response message fields */

    /* START: Flow setup message */
        { &hf_waveagent_rxflownum,
        { "Received Flow Number", "waveagent.rxflownum",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_mode,
        { "WaveAgent Mode", "waveagent.trafficmode",
        FT_UINT8, BASE_DEC, VALS(wa_modes), 0x03,
        NULL, HFILL } },

        { &hf_waveagent_endpointtype,
        { "WaveAgent Endpoint Type", "waveagent.endpointtype",
        FT_UINT8, BASE_DEC, VALS(wa_endpointtypes), 0x0c,
        NULL, HFILL } },

        { &hf_waveagent_remoteport,
        { "Remote port", "waveagent.remoteport",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_remoteaddr,
        { "Remote address", "waveagent.remoteaddr",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_dscp,
        { "DSCP Setting", "waveagent.dscp",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_fsflags,
        { "Flow Setup Flags", "waveagent.fsflags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_fscbrflag,
        { "CBR Transmit Mode", "waveagent.fscbrflag",
        FT_BOOLEAN, 4, NULL, 0x01, NULL, HFILL } },

        { &hf_waveagent_fscombinedsetupflag,
        { "Setup, Connect/Listen, Start Combined", "waveagent.fscombinedsetupflag",
        FT_BOOLEAN, 4, NULL, 0x02, NULL, HFILL } },

    /* END: Flow setup message */

    /* START: Flow start message fields */
        { &hf_waveagent_payfill,
        { "Payload Fill", "waveagent.payfill",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_paysize,
        { "WaveAgent Payload Size (bytes)", "waveagent.paysize",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_avgrate,
        { "Average Rate (header + payload + trailer bytes/s)", "waveagent.avgrate",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_totalframes,
        { "Total Frames", "waveagent.totalframes",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    /* END: Flow start message fields */

    /* START: Scan results request (0x23) fields */
        { &hf_waveagent_bssidstartindex,
        { "Starting Index of BSSID list for reporting", "waveagent.bssidstartindex",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_bssidstopindex,
        { "Ending Index of BSSID list for reporting", "waveagent.bssidstopindex",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    /* END: Scan results request (0x23) fields */

    /* START: WLAN Interface stats fields */
        { &hf_waveagent_ifwlanbssid,
        { "WLAN Interface Connected to BSSID", "waveagent.ifwlanbssid",
        FT_ETHER, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlanssid,
        { "WLAN Interface Connected to SSID", "waveagent.ifwlanssid",
        FT_STRING, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlanrssi,
        { "WLAN Interface RSSI", "waveagent.ifwlanrssi",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlannoise,
        { "WLAN Interface Noise Floor (dBm)", "waveagent.ifwlannoise",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifphytypes,
        { "WLAN Interface Supported PHY Types", "waveagent.ifphytypes",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifphytypebit0,
        { "11b", "waveagent.ifphytypebit0",
        FT_BOOLEAN, 4, NULL, 0x01, NULL, HFILL } },

        { &hf_waveagent_ifphytypebit1,
        { "11g", "waveagent.ifphytypebit1",
        FT_BOOLEAN, 4, NULL, 0x02, NULL, HFILL } },

        { &hf_waveagent_ifphytypebit2,
        { "11a", "waveagent.ifphytypebit2",
        FT_BOOLEAN, 4, NULL, 0x04, NULL, HFILL } },

        { &hf_waveagent_ifphytypebit3,
        { "11n", "waveagent.ifphytypebit3",
        FT_BOOLEAN, 4, NULL, 0x08, NULL, HFILL } },

        { &hf_waveagent_ifwlanauthentication,
        { "WLAN Interface Authentication Algorithm", "waveagent.ifwlanauthentication",
        FT_UINT32, BASE_DEC, VALS(auth_algs), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlancipher,
        { "WLAN Interface Encryption/Cipher Algorithm", "waveagent.ifwlancipher",
        FT_UINT32, BASE_DEC, VALS(cipher_algs), 0x0,
        NULL, HFILL } },
    /* END: WLAN Interface stats fields */

    /* START: Interface stats response (0x2d) fields */
        { &hf_waveagent_iftype,
        { "Interface type", "waveagent.iftype",
        FT_UINT32, BASE_DEC, VALS(if_types), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifdescription,
        { "Name/Description of the adapter", "waveagent.ifdescription",
        FT_STRING, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifmacaddr,
        { "Interface MAC Address", "waveagent.ifmacaddr",
        FT_ETHER, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_iflinkspeed,
        { "Interface Link Speed (kbps)", "waveagent.iflinkspeed",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifdhcp,
        { "Interface DHCP Enabled", "waveagent.ifdhcp",
        FT_UINT32, BASE_DEC, VALS(no_yes), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifiptype,
        { "Interface IP Type", "waveagent.ifiptype",
        FT_UINT32, BASE_DEC, VALS(ip_types), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifipv4,
        { "Interface Bound to IP Address", "waveagent.ifipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifipv6,
        { "Interface Bound to IP Address", "waveagent.ifipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifdhcpserver,
        { "Interface DHCP Server Address", "waveagent.ifdhcpserver",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifgateway,
        { "Interface Gateway", "waveagent.ifgateway",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifdnsserver,
        { "Interface DNS Server Address", "waveagent.ifdnsserver",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifethl2status,
        { "Ethernet L2 Interface Status", "waveagent.ifethl2status",
        FT_UINT32, BASE_DEC, VALS(if_eth_states), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlanl2status,
        { "WLAN L2 Interface Status", "waveagent.ifwlanl2status",
        FT_UINT32, BASE_DEC, VALS(if_wlan_states), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifl3status,
        { "L3 Interface Status", "waveagent.ifl3status",
        FT_UINT32, BASE_DEC, VALS(if_l3_states), 0x0,
        NULL, HFILL } },

    /* END: Interface stats response (0x2d) fields */

    /* START: Scan results response (0x2e) fields */
        { &hf_waveagent_totalbssid,
        { "Number of Found BSSID", "waveagent.totalbssid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_returnedbssid,
        { "Number of BSSID Reported in This Response", "waveagent.returnedbssid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_scanbssid,
        { "BSSID", "waveagent.scanbssid",
        FT_ETHER, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_scanssid,
        { "SSID", "waveagent.scanssid",
        FT_STRING, 0, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlansupprates,
        { "Supported Rates", "waveagent.ifwlansupportedrates",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlancapabilities,
        { "Capabilities field", "waveagent.ifwlancapabilities",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlanchannel,
        { "Channel", "waveagent.ifwlanchannel",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlanprivacy,
        { "Privacy Enabled", "waveagent.ifwlanprivacy",
        FT_UINT32, BASE_DEC, VALS(no_yes), 0x0,
        NULL, HFILL } },

        { &hf_waveagent_ifwlanbssmode,
        { "BSS Mode", "waveagent.ifwlanbssmode",
        FT_UINT32, BASE_DEC, VALS(bss_modes), 0x0,
        NULL, HFILL } },
    /* END: Scan results response (0x2e) fields */

    /* START: OID fields */
        { &hf_waveagent_oidcode,
        { "OID Code", "waveagent.oidcode",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_oidvalue,
        { "OID Value", "waveagent.oidvalue",
        FT_STRING, 0, NULL, 0x0,
        NULL, HFILL } },
    /* END: OID fields */

    /* START: Learning Message fields */
        { &hf_waveagent_destip,
        { "Destination IP", "waveagent.destip",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_destport,
        { "Destination Port", "waveagent.destport",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_connectflags,
        { "Connect Flags", "waveagent.connectflags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },
    /* END: Learning Message fields */

    /* START: client connect fields */
        { &hf_waveagent_connecttype,
        { "Connect Type", "waveagent.connecttype",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_minrssi,
        { "Minimum RSSI", "waveagent.minrssi",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_connecttimeout,
        { "Connect timeout (s)", "waveagent.connecttimeout",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_connectattempts,
        { "Connect attempts", "waveagent.connectattempt",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_reason,
        { "Reason", "waveagent.reason",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
    /* END: client connect fields */

    /* START: relay server fields */
        { &hf_waveagent_relaydestid,
        { "ID of destination client (assigned by relay server)", "waveagent.relaydestid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_relaysrcid,
        { "ID of source client (assigned by relay server)", "waveagent.relaysrcid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

        { &hf_waveagent_relaymessagest,
        { "Relayed WaveAgent Message", "waveagent.relaymessagest",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "This is a relayed WaveAgent message", HFILL } },

/* END: relay server fields */

    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_waveagent,
        &ett_statechange,
        &ett_phytypes,
        &ett_fsflags,
        &ett_scindex[0],
        &ett_scindex[1],
        &ett_scindex[2],
        &ett_scindex[3],
        &ett_scindex[4],
        &ett_scindex[5],
        &ett_scindex[6],
        &ett_scindex[7],
        &ett_bss[0],
        &ett_bss[1],
        &ett_bss[2],
        &ett_bss[3],
        &ett_bss[4],
        &ett_bss[5],
        &ett_bss[6],
        &ett_bss[7],
        &ett_relaymessage,
    };

    proto_waveagent = proto_register_protocol(
        "WaveAgent", "waveagent", "waveagent");

    proto_register_field_array(proto_waveagent, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_waveagent(void)
{
    heur_dissector_add("udp", dissect_waveagent_heur, proto_waveagent);
}
