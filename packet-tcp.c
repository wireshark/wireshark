/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * $Id: packet-tcp.c,v 1.5 1998/10/13 05:40:04 guy Exp $
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
#include "follow.h"

extern FILE* data_out_file;
extern packet_info pi;

static void
dissect_tcpopt_maxseg(GtkWidget *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  add_item_to_tree(opt_tree, offset,      optlen,
    "%s: %u bytes", name, pntohs(opd));
}

static void
dissect_tcpopt_wscale(GtkWidget *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  add_item_to_tree(opt_tree, offset,      optlen,
    "%s: %u bytes", name, *opd);
}

static void
dissect_tcpopt_sack(GtkWidget *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  GtkWidget *field_tree = NULL, *tf;
  guint leftedge, rightedge;

  tf = add_item_to_tree(opt_tree, offset,      optlen, "%s:", name);
  offset += 2;	/* skip past type and length */
  optlen -= 2;	/* subtract size of type and length */
  while (optlen > 0) {
    if (field_tree == NULL) {
      /* Haven't yet made a subtree out of this option.  Do so. */
      field_tree = gtk_tree_new();
      add_subtree(tf, field_tree, ETT_TCP_OPTION_SACK);
    }
    if (optlen < 4) {
      add_item_to_tree(field_tree, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    leftedge = pntohl(opd);
    opd += 4;
    optlen -= 4;
    if (optlen < 4) {
      add_item_to_tree(field_tree, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    rightedge = pntohl(opd);
    opd += 4;
    optlen -= 4;
    add_item_to_tree(field_tree, offset,      8,
        "left edge = %u, right edge = %u", leftedge, rightedge);
    offset += 8;
  }
}

static void
dissect_tcpopt_echo(GtkWidget *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  add_item_to_tree(opt_tree, offset,      optlen,
    "%s: %u", name, pntohl(opd));
}

static void
dissect_tcpopt_timestamp(GtkWidget *opt_tree, const char *name,
    const u_char *opd, int offset, guint optlen)
{
  add_item_to_tree(opt_tree, offset,      optlen,
    "%s: tsval %u, tsecr %u", name, pntohl(opd), pntohl(opd + 4));
}

static void
dissect_tcpopt_cc(GtkWidget *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  add_item_to_tree(opt_tree, offset,      optlen,
    "%s: %u", name, pntohl(opd));
}

static ip_tcp_opt tcpopts[] = {
  {
    TCPOPT_EOL,
    "EOL",
    NO_LENGTH,
    0,
    NULL,
  },
  {
    TCPOPT_NOP,
    "NOP",
    NO_LENGTH,
    0,
    NULL,
  },
  {
    TCPOPT_MSS,
    "Maximum segment size",
    FIXED_LENGTH,
    TCPOLEN_MSS,
    dissect_tcpopt_maxseg
  },
  {
    TCPOPT_WINDOW,
    "Window scale",
    FIXED_LENGTH,
    TCPOLEN_WINDOW,
    dissect_tcpopt_wscale
  },
  {
    TCPOPT_SACK_PERM,
    "SACK permitted",
    FIXED_LENGTH,
    TCPOLEN_SACK_PERM,
    NULL,
  },
  {
    TCPOPT_SACK,
    "SACK",
    VARIABLE_LENGTH,
    TCPOLEN_SACK_MIN,
    dissect_tcpopt_sack
  },
  {
    TCPOPT_ECHO,
    "Echo",
    FIXED_LENGTH,
    TCPOLEN_ECHO,
    dissect_tcpopt_echo
  },
  {
    TCPOPT_ECHOREPLY,
    "Echo reply",
    FIXED_LENGTH,
    TCPOLEN_ECHOREPLY,
    dissect_tcpopt_echo
  },
  {
    TCPOPT_TIMESTAMP,
    "Time stamp",
    FIXED_LENGTH,
    TCPOLEN_TIMESTAMP,
    dissect_tcpopt_timestamp
  },
  {
    TCPOPT_CC,
    "CC",
    FIXED_LENGTH,
    TCPOLEN_CC,
    dissect_tcpopt_cc
  },
  {
    TCPOPT_CCNEW,
    "CC.NEW",
    FIXED_LENGTH,
    TCPOPT_CCNEW,
    dissect_tcpopt_cc
  },
  {
    TCPOPT_CCECHO,
    "CC.ECHO",
    FIXED_LENGTH,
    TCPOLEN_CCECHO,
    dissect_tcpopt_cc
  }
};

#define N_TCP_OPTS	(sizeof tcpopts / sizeof tcpopts[0])

void
dissect_tcp(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  e_tcphdr   th;
  GtkWidget *tcp_tree, *ti, *field_tree, *tf;
  gchar      flags[64] = "<None>";
  gchar     *fstr[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
  gint       fpos = 0, i;
  guint      bpos;
  guint      hlen;
  guint      optlen;

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
  
  if (fd->win_info[COL_NUM]) {
    strcpy(fd->win_info[COL_PROTOCOL], "TCP");
    sprintf(fd->win_info[COL_INFO], "Source port: %d  Destination port: %d",
      th.th_sport, th.th_dport);
  }
  
  hlen = th.th_off * 4;  /* TCP header length, in bytes */

  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, hlen,
      "Transmission Control Protocol");
    tcp_tree = gtk_tree_new();
    add_subtree(ti, tcp_tree, ETT_TCP);
    add_item_to_tree(tcp_tree, offset,      2, "Source port: %d", th.th_sport);
    add_item_to_tree(tcp_tree, offset +  2, 2, "Destination port: %d", th.th_dport);
    add_item_to_tree(tcp_tree, offset +  4, 4, "Sequence number: %u",
      th.th_seq);
    if (th.th_flags & TH_ACK)
      add_item_to_tree(tcp_tree, offset +  8, 4, "Acknowledgement number: %u",
        th.th_ack);
    add_item_to_tree(tcp_tree, offset + 12, 1, "Header length: %d bytes", hlen);
    add_item_to_tree(tcp_tree, offset + 13, 1, "Flags: %s", flags);
    add_item_to_tree(tcp_tree, offset + 14, 2, "Window size: %d", th.th_win);
    add_item_to_tree(tcp_tree, offset + 16, 2, "Checksum: 0x%04x", th.th_sum);
    if (th.th_flags & TH_URG)
      add_item_to_tree(tcp_tree, offset + 18, 2, "Urgent pointer: 0x%04x",
        th.th_urp);

    /* Decode TCP options, if any. */
    if (hlen > sizeof (e_tcphdr)) {
      /* There's more than just the fixed-length header.  Decode the
         options. */
      optlen = hlen - sizeof (e_tcphdr); /* length of options, in bytes */
      tf = add_item_to_tree(tcp_tree, offset +  20, optlen,
        "Options: (%d bytes)", optlen);
      field_tree = gtk_tree_new();
      add_subtree(tf, field_tree, ETT_TCP_OPTIONS);
      dissect_ip_tcp_options(field_tree, &pd[offset + 20], offset + 20, optlen,
         tcpopts, N_TCP_OPTS, TCPOPT_EOL);
    }
  }

  /* Skip over header + options */
  offset += hlen;

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
 
  pi.srcport = th.th_sport;
  pi.destport = th.th_dport;
  
  if( data_out_file ) {
    reassemble_tcp( th.th_seq, /* sequence number */
        ( pi.iplen -( pi.iphdrlen * 4 )-( th.th_off * 4 ) ), /* length */
        ( pd+offset ), /* data */
        ( th.th_flags & 0x02 ), /* is syn set? */
        pi.ip_src ); /* src ip */
  }
}
