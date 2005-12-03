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


void
capture_info_init(packet_counts *counts)
{
  counts->total       = 0;
  counts->sctp        = 0;
  counts->tcp         = 0;
  counts->udp         = 0;
  counts->icmp        = 0;
  counts->ospf        = 0;
  counts->gre         = 0;
  counts->ipx         = 0;
  counts->netbios     = 0;
  counts->vines       = 0;
  counts->other       = 0;
  counts->arp         = 0;
}


void
capture_info_packet(packet_counts *counts, gint wtap_linktype, const u_char *pd, guint32 caplen, union wtap_pseudo_header pseudo_header)
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
      capture_atm(&pseudo_header, pd, caplen, counts);
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
    /* XXX - some ATM drivers on FreeBSD might prepend a 4-byte ATM
       pseudo-header to DLT_ATM_RFC1483, with LLC header following;
       we might have to implement that at some point. */
  }
}


#endif /* HAVE_LIBPCAP */
