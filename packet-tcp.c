/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * $Id: packet-tcp.c,v 1.2 1998/09/16 03:22:11 gerald Exp $
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"

void
dissect_tcp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  e_tcphdr   th;
  GtkWidget *tcp_tree, *ti;
  gchar      flags[64] = "<None>";
  gchar     *fstr[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
  gint       fpos = 0, i;
  guint      bpos;

  /* To do: Check for {cap len,pkt len} < struct len */
  /* Avoids alignment problems on many architectures. */
  memcpy(&th, &pd[offset], sizeof(e_tcphdr));
  th.th_sport = ntohs(th.th_sport);
  th.th_dport = ntohs(th.th_dport);
  th.th_win   = ntohs(th.th_win);
  th.th_sum   = ntohs(th.th_sum);
  th.th_urp   = ntohs(th.th_urp);
  th.th_seq   = ntohl(th.th_seq);
  th.th_ack   = ntohl(th.th_ack);
  
  for (i = 0; i < 6; i++) {
    bpos = 1 << i;
    if (th.th_flags & bpos) {
      if (fpos) {
        strcpy(&flags[fpos], ", ");
        fpos += 2;
      }
      strcpy(&flags[fpos], fstr[i]);
      fpos += 3;
    }
  }
  flags[fpos] = '\0';
  
  if (fd->win_info[0]) {
    strcpy(fd->win_info[3], "TCP");
    sprintf(fd->win_info[4], "Source port: %d  Destination port: %d",
      th.th_sport, th.th_dport);
  }
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 20,
      "Transmission Control Protocol");
    tcp_tree = gtk_tree_new();
    add_subtree(ti, tcp_tree, ETT_TCP);
    add_item_to_tree(tcp_tree, offset,      2, "Source port: %d", th.th_sport);
    add_item_to_tree(tcp_tree, offset +  2, 2, "Destination port: %d", th.th_dport);
    add_item_to_tree(tcp_tree, offset +  4, 4, "Sequence number: 0x%08x",
      th.th_seq);
    add_item_to_tree(tcp_tree, offset +  8, 4, "Acknowledgement number: 0x%08x",
      th.th_ack);
    add_item_to_tree(tcp_tree, offset + 12, 1, "Header length: %d", th.th_off);
    add_item_to_tree(tcp_tree, offset + 13, 1, "Flags: %s", flags);
    add_item_to_tree(tcp_tree, offset + 14, 2, "Window size: %d", th.th_win);
    add_item_to_tree(tcp_tree, offset + 16, 2, "Checksum: 0x%04x", th.th_sum);
    add_item_to_tree(tcp_tree, offset + 18, 2, "Urgent pointer: 0x%04x",
      th.th_urp);
    /* To do: TCP options */

  }
    /* Skip over header + options */
	offset += 4 * th.th_off;

	/* until we decode those options, I'll check the packet length
	to see if there's more data. -- gilbert */
	if (fd->cap_len > offset) {
		switch(MIN(th.th_sport, th.th_dport)) {
			case TCP_PORT_PRINTER:
				dissect_lpd(pd, offset, fd, tree);
				break;
			default:
				dissect_data(pd, offset, fd, tree);
		}
	}
}
