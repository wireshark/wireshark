/* packet-ip.c
 * Routines for IP and miscellaneous IP protocol packet disassembly
 *
 * $Id: packet-ip.c,v 1.6 1998/10/10 18:23:42 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#include <gtk/gtk.h>
#include <pcap.h>

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "etypes.h"
#include "resolv.h"

extern packet_info pi;

void
dissect_ip(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  e_ip       iph;
  GtkWidget *ip_tree, *ti;
  gchar      tos_str[32];

  /* To do: check for runts, errs, etc. */
  /* Avoids alignment problems on many architectures. */
  memcpy(&iph, &pd[offset], sizeof(e_ip));
  iph.ip_len = ntohs(iph.ip_len);
  iph.ip_id  = ntohs(iph.ip_id);
  iph.ip_off = ntohs(iph.ip_off);
  iph.ip_sum = ntohs(iph.ip_sum);
  
  if (fd->win_info[COL_NUM]) {
    switch (iph.ip_p) {
      case IP_PROTO_ICMP:
      case IP_PROTO_IGMP:
      case IP_PROTO_TCP:
      case IP_PROTO_UDP:
      case IP_PROTO_OSPF:
        /* Names are set in the associated dissect_* routines */
        break;
      default:
        strcpy(fd->win_info[COL_PROTOCOL], "IP");
        sprintf(fd->win_info[COL_INFO], "Unknown IP protocol (%02x)", iph.ip_p);
    }

    strcpy(fd->win_info[COL_SOURCE], get_hostname(iph.ip_src));
    strcpy(fd->win_info[COL_DESTINATION], get_hostname(iph.ip_dst));
  }
  
  iph.ip_tos = IPTOS_TOS(iph.ip_tos);
  switch (iph.ip_tos) {
    case IPTOS_NONE:
      strcpy(tos_str, "None");
      break;
    case IPTOS_LOWDELAY:
      strcpy(tos_str, "Minimize delay");
      break;
    case IPTOS_THROUGHPUT:
      strcpy(tos_str, "Maximize throughput");
      break;
    case IPTOS_RELIABILITY:
      strcpy(tos_str, "Maximize reliability");
      break;
    case IPTOS_LOWCOST:
      strcpy(tos_str, "Minimize cost");
      break;
    default:
      strcpy(tos_str, "Unknon.  Malformed?");
      break;
  }
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, (iph.ip_hl * 4),
      "Internet Protocol");
    ip_tree = gtk_tree_new();
    add_subtree(ti, ip_tree, ETT_IP);
    add_item_to_tree(ip_tree, offset,      1, "Version: %d", iph.ip_v);
    add_item_to_tree(ip_tree, offset,      1, "Header length: %d", iph.ip_hl); 
    add_item_to_tree(ip_tree, offset +  1, 1, "Type of service: 0x%02x (%s)",
      iph.ip_tos, tos_str);
    add_item_to_tree(ip_tree, offset +  2, 2, "Total length: %d", iph.ip_len);
    add_item_to_tree(ip_tree, offset +  4, 2, "Identification: 0x%04x",
      iph.ip_id);
    /* To do: add flags */
    add_item_to_tree(ip_tree, offset +  6, 2, "Fragment offset: %d",
      iph.ip_off & 0x1fff);
    add_item_to_tree(ip_tree, offset +  8, 1, "Time to live: %d",
      iph.ip_ttl);
    add_item_to_tree(ip_tree, offset +  9, 1, "Protocol: 0x%02x",
      iph.ip_p);
    add_item_to_tree(ip_tree, offset + 10, 2, "Header checksum: 0x%04x",
      iph.ip_sum);
    add_item_to_tree(ip_tree, offset + 12, 4, "Source address: %s",
		     get_hostname(iph.ip_src));
    add_item_to_tree(ip_tree, offset + 16, 4, "Destination address: %s",
		     get_hostname(iph.ip_dst));
  }

  pi.srcip = ip_to_str( (guint8 *) &iph.ip_src);
  pi.destip = ip_to_str( (guint8 *) &iph.ip_dst);
  pi.ipproto = iph.ip_p;
  pi.iplen = iph.ip_len;
  pi.iphdrlen = iph.ip_hl;
  pi.ip_src = iph.ip_src;

  offset += iph.ip_hl * 4;
  switch (iph.ip_p) {
    case IP_PROTO_ICMP:
      dissect_icmp(pd, offset, fd, tree);
     break;
    case IP_PROTO_IGMP:
      dissect_igmp(pd, offset, fd, tree);
     break;
    case IP_PROTO_TCP:
      dissect_tcp(pd, offset, fd, tree);
     break;
   case IP_PROTO_UDP:
      dissect_udp(pd, offset, fd, tree);
      break;
    case IP_PROTO_OSPF:
      dissect_ospf(pd, offset, fd, tree);
     break;
  }
}


const gchar *unreach_str[] = {"Network unreachable",
                              "Host unreachable",
                              "Protocol unreachable",
                              "Port unreachable",
                              "Fragmentation needed",
                              "Source route failed",
                              "Administratively prohibited",
                              "Network unreachable for TOS",
                              "Host unreachable for TOS",
                              "Communication administratively filtered",
                              "Host precedence violation",
                              "Precedence cutoff in effect"};

const gchar *redir_str[] = {"Redirect for network",
                            "Redirect for host",
                            "Redirect for TOS and network",
                            "Redirect for TOS and host"};

const gchar *ttl_str[] = {"TTL equals 0 during transit",
                          "TTL equals 0 during reassembly"};

const gchar *par_str[] = {"IP header bad", "Required option missing"};

void
dissect_icmp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  e_icmp     ih;
  GtkWidget *icmp_tree, *ti;
  guint16    cksum;
  gchar      type_str[64], code_str[64] = "";

  /* Avoids alignment problems on many architectures. */
  memcpy(&ih, &pd[offset], sizeof(e_icmp));
  /* To do: check for runts, errs, etc. */
  cksum = ntohs(ih.icmp_cksum);
  
  switch (ih.icmp_type) {
    case ICMP_ECHOREPLY:
      strcpy(type_str, "Echo (ping) reply");
      break;
    case ICMP_UNREACH:
      strcpy(type_str, "Destination unreachable");
      if (ih.icmp_code < 12) {
        sprintf(code_str, "(%s)", unreach_str[ih.icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_SOURCEQUENCH:
      strcpy(type_str, "Source quench (flow control)");
      break;
    case ICMP_REDIRECT:
      strcpy(type_str, "Redirect");
      if (ih.icmp_code < 4) {
        sprintf(code_str, "(%s)", redir_str[ih.icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_ECHO:
      strcpy(type_str, "Echo (ping) request");
      break;
    case ICMP_TIMXCEED:
      strcpy(type_str, "Time-to-live exceeded");
      if (ih.icmp_code < 2) {
        sprintf(code_str, "(%s)", ttl_str[ih.icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_PARAMPROB:
      strcpy(type_str, "Parameter problem");
      if (ih.icmp_code < 2) {
        sprintf(code_str, "(%s)", par_str[ih.icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_TSTAMP:
      strcpy(type_str, "Timestamp request");
      break;
    case ICMP_TSTAMPREPLY:
      strcpy(type_str, "Timestamp reply");
      break;
    case ICMP_MASKREQ:
      strcpy(type_str, "Address mask request");
      break;
    case ICMP_MASKREPLY:
      strcpy(type_str, "Address mask reply");
      break;
    default:
      strcpy(type_str, "Unknown ICMP (obsolete or malformed?)");
  }

  if (fd->win_info[COL_NUM]) {    
    strcpy(fd->win_info[COL_PROTOCOL], "ICMP");
    strcpy(fd->win_info[COL_INFO], type_str);
  }
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 4,
      "Internet Control Message Protocol");
    icmp_tree = gtk_tree_new();
    add_subtree(ti, icmp_tree, ETT_ICMP);
    add_item_to_tree(icmp_tree, offset,      1, "Type: %d (%s)",
      ih.icmp_type, type_str);
    add_item_to_tree(icmp_tree, offset +  1, 1, "Code: %d %s",
      ih.icmp_code, code_str);
    add_item_to_tree(icmp_tree, offset +  2, 2, "Checksum: 0x%04x",
      ih.icmp_cksum);
  }
}

void
dissect_igmp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  e_igmp     ih;
  GtkWidget *igmp_tree, *ti;
  guint16    cksum;
  gchar      type_str[64] = "";

  /* Avoids alignment problems on many architectures. */
  memcpy(&ih, &pd[offset], sizeof(e_igmp));
  /* To do: check for runts, errs, etc. */
  cksum = ntohs(ih.igmp_cksum);
  
  switch (ih.igmp_t) {
    case IGMP_M_QRY:
      strcpy(type_str, "Router query");
      break;
    case IGMP_V1_M_RPT:
      strcpy(type_str, "Host response (v1)");
      break;
    case IGMP_V2_LV_GRP:
      strcpy(type_str, "Leave group (v2)");
      break;
    case IGMP_DVMRP:
      strcpy(type_str, "DVMRP");
      break;
    case IGMP_PIM:
      strcpy(type_str, "PIM");
      break;
    case IGMP_V2_M_RPT:
      strcpy(type_str, "Host reponse (v2)");
      break;
    case IGMP_MTRC_RESP:
      strcpy(type_str, "Traceroute response");
      break;
    case IGMP_MTRC:
      strcpy(type_str, "Traceroute message");
      break;
    default:
      strcpy(type_str, "Unknown IGMP");
  }

  if (fd->win_info[COL_NUM]) {    
    strcpy(fd->win_info[COL_PROTOCOL], "IGMP");
  }
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 4,
      "Internet Group Management Protocol");
    igmp_tree = gtk_tree_new();
    add_subtree(ti, igmp_tree, ETT_IGMP);
    add_item_to_tree(igmp_tree, offset,     1, "Version: %d",
      ih.igmp_v);
    add_item_to_tree(igmp_tree, offset    , 1, "Type: %d (%s)",
      ih.igmp_t, type_str);
    add_item_to_tree(igmp_tree, offset + 1, 1, "Unused: 0x%02x",
      ih.igmp_unused);
    add_item_to_tree(igmp_tree, offset + 2, 2, "Checksum: 0x%04x",
      ih.igmp_cksum);
    add_item_to_tree(igmp_tree, offset + 4, 4, "Group address: %s",
      ip_to_str((guint8 *) &ih.igmp_gaddr));
  }
}
