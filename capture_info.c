/* capture_info.c
 * capture info functions
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <glib.h>

#include <epan/packet.h>
/* XXX - try to remove this later */
#include <epan/prefs.h>
/* XXX - try to remove this later */

#include "capture_info.h"

#include <epan/dissectors/packet-ap1394.h>
#include <epan/dissectors/packet-atalk.h>
#include <epan/dissectors/packet-atm.h>
#include <epan/dissectors/packet-clip.h>
#include <epan/dissectors/packet-eth.h>
#include <epan/dissectors/packet-fddi.h>
#include <epan/dissectors/packet-fr.h>
#include <epan/dissectors/packet-null.h>
#include <epan/dissectors/packet-ppp.h>
#include <epan/dissectors/packet-raw.h>
#include <epan/dissectors/packet-sll.h>
#include <epan/dissectors/packet-tr.h>
#include <epan/dissectors/packet-ieee80211.h>
#include <epan/dissectors/packet-chdlc.h>
#include <epan/dissectors/packet-prism.h>
#include <epan/dissectors/packet-ipfc.h>
#include <epan/dissectors/packet-arcnet.h>
#include <epan/dissectors/packet-enc.h>

static void capture_info_packet(
packet_counts *counts, gint wtap_linktype, const guchar *pd, guint32 caplen, union wtap_pseudo_header *pseudo_header);



typedef struct _info_data {
    packet_counts     counts;     /* several packet type counters */
    struct wtap*      wtap;       /* current wtap file */
    capture_info      ui;         /* user interface data */
} info_data_t;


info_data_t info_data;


/* open the info */
void capture_info_open(const char *iface)
{
    info_data.counts.total      = 0;
    info_data.counts.sctp       = 0;
    info_data.counts.tcp        = 0;
    info_data.counts.udp        = 0;
    info_data.counts.icmp       = 0;
    info_data.counts.ospf       = 0;
    info_data.counts.gre        = 0;
    info_data.counts.ipx        = 0;
    info_data.counts.netbios    = 0;
    info_data.counts.vines      = 0;
    info_data.counts.other      = 0;
    info_data.counts.arp        = 0;

    info_data.wtap = NULL;
    info_data.ui.counts = &info_data.counts;

    capture_info_ui_create(&info_data.ui, iface);
}


/* new file arrived */
void capture_info_new_file(const char *new_filename)
{
    int err;
    gchar *err_info;


    if(info_data.wtap != NULL) {
        wtap_close(info_data.wtap);
    }

    info_data.wtap = wtap_open_offline(new_filename, &err, &err_info, FALSE);
    if (!info_data.wtap) {
        g_warning("capture_info_new_file: wtap open failed: %s", err_info);
    }

}


/* new packets arrived */
void capture_info_new_packets(int to_read)
{
    int err;
    gchar *err_info;
    long data_offset;
    const struct wtap_pkthdr *phdr;
    union wtap_pseudo_header *pseudo_header;
    int wtap_linktype;
    const guchar *buf;


    info_data.ui.new_packets = to_read;

    /*g_warning("new packets: %u", to_read);*/

    while (to_read != 0 && (wtap_read(info_data.wtap, &err, &err_info, &data_offset))) {
        phdr = wtap_phdr(info_data.wtap);
        pseudo_header = wtap_pseudoheader(info_data.wtap);
        wtap_linktype = phdr->pkt_encap;
        buf = wtap_buf_ptr(info_data.wtap);

        capture_info_packet(&info_data.counts, wtap_linktype, buf, phdr->caplen, pseudo_header);

        /*g_warning("new packet");*/
        to_read--;
    }

    capture_info_ui_update(&info_data.ui);
}


/* close the info */
void capture_info_close(void)
{
    capture_info_ui_destroy(&info_data.ui);
    wtap_close(info_data.wtap);
}


static void
capture_info_packet(packet_counts *counts, gint wtap_linktype, const guchar *pd, guint32 caplen, union wtap_pseudo_header *pseudo_header)
{
  counts->total++;
  switch (wtap_linktype) {
    case WTAP_ENCAP_ETHERNET:
      capture_eth(pd, 0, caplen, counts);
      break;
    case WTAP_ENCAP_FDDI:
    case WTAP_ENCAP_FDDI_BITSWAPPED:
      capture_fddi(pd, caplen, counts);
      break;
    case WTAP_ENCAP_PRISM_HEADER:
      capture_prism(pd, 0, caplen, counts);
      break;
    case WTAP_ENCAP_TOKEN_RING:
      capture_tr(pd, 0, caplen, counts);
      break;
    case WTAP_ENCAP_NULL:
      capture_null(pd, caplen, counts);
      break;
    case WTAP_ENCAP_PPP:
      capture_ppp_hdlc(pd, 0, caplen, counts);
      break;
    case WTAP_ENCAP_RAW_IP:
      capture_raw(pd, caplen, counts);
      break;
    case WTAP_ENCAP_SLL:
      capture_sll(pd, caplen, counts);
      break;
    case WTAP_ENCAP_LINUX_ATM_CLIP:
      capture_clip(pd, caplen, counts);
      break;
    case WTAP_ENCAP_IEEE_802_11:
    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
      capture_ieee80211(pd, 0, caplen, counts);
      break;
    case WTAP_ENCAP_CHDLC:
      capture_chdlc(pd, 0, caplen, counts);
      break;
    case WTAP_ENCAP_LOCALTALK:
      capture_llap(counts);
      break;
    case WTAP_ENCAP_ATM_PDUS:
      capture_atm(pseudo_header, pd, caplen, counts);
      break;
    case WTAP_ENCAP_IP_OVER_FC:
      capture_ipfc(pd, caplen, counts);
      break;
    case WTAP_ENCAP_ARCNET:
      capture_arcnet(pd, caplen, counts, FALSE, TRUE);
      break;
    case WTAP_ENCAP_ARCNET_LINUX:
      capture_arcnet(pd, caplen, counts, TRUE, FALSE);
      break;
    case WTAP_ENCAP_APPLE_IP_OVER_IEEE1394:
      capture_ap1394(pd, 0, caplen, counts);
      break;
    case WTAP_ENCAP_FRELAY:
    case WTAP_ENCAP_FRELAY_WITH_PHDR:
      capture_fr(pd, 0, caplen, counts);
      break;
    case WTAP_ENCAP_ENC:
      capture_enc(pd, caplen, counts);
      break;
    /* XXX - some ATM drivers on FreeBSD might prepend a 4-byte ATM
       pseudo-header to DLT_ATM_RFC1483, with LLC header following;
       we might have to implement that at some point. */
  }
}


#endif /* HAVE_LIBPCAP */
