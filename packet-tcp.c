/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * $Id: packet-tcp.c,v 1.25 1999/07/07 00:34:57 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <glib.h>
#include "packet.h"
#include "resolv.h"
#include "follow.h"
#include "util.h"

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifndef __PACKET_IP_H__
#include "packet-ip.h"
#endif

extern FILE* data_out_file;
extern packet_info pi;

static gchar info_str[COL_MAX_LEN];
static int   info_len;

/* TCP Ports */

#define TCP_PORT_FTPDATA  20
#define TCP_PORT_FTP      21
#define TCP_PORT_TELNET   23
#define TCP_PORT_SMTP     25
#define TCP_PORT_HTTP     80
#define TCP_PORT_POP      110
#define TCP_PORT_NNTP     119
#define TCP_PORT_NBSS     139
#define TCP_PORT_PRINTER  515
#define TCP_ALT_PORT_HTTP 8080
#define TCP_PORT_PPTP     1723
#define TCP_PORT_RTSP     554

/* TCP structs and definitions */

typedef struct _e_tcphdr {
  guint16 th_sport;
  guint16 th_dport;
  guint32 th_seq;
  guint32 th_ack;
  guint8  th_off_x2; /* combines th_off and th_x2 */
  guint8  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
  guint16 th_win;
  guint16 th_sum;
  guint16 th_urp;
} e_tcphdr;

/*
 *	TCP option
 */
 
#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_ECHO             6
#define TCPOPT_ECHOREPLY        7
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_CC               11
#define TCPOPT_CCNEW            12
#define TCPOPT_CCECHO           13

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_SACK_MIN       2
#define TCPOLEN_ECHO           6
#define TCPOLEN_ECHOREPLY      6
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_CC             6
#define TCPOLEN_CCNEW          6
#define TCPOLEN_CCECHO         6

static void
tcp_info_append_uint(const char *abbrev, guint32 val) {
  int add_len = 0;
  
  if (info_len > 0)
  if(info_len > 0)
    add_len = snprintf(&info_str[info_len], COL_MAX_LEN - info_len, " %s=%u",
      abbrev, val);
  if (add_len > 0)
    info_len += add_len;
}

static void
dissect_tcpopt_maxseg(proto_tree *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  proto_tree_add_item(opt_tree, offset,      optlen,
    "%s: %u bytes", name, pntohs(opd));
  tcp_info_append_uint("MSS", pntohs(opd));
}

static void
dissect_tcpopt_wscale(proto_tree *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  proto_tree_add_item(opt_tree, offset,      optlen,
    "%s: %u bytes", name, *opd);
  tcp_info_append_uint("WS", *opd);
}

static void
dissect_tcpopt_sack(proto_tree *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  proto_tree *field_tree = NULL;
  proto_item *tf;
  guint leftedge, rightedge;

  tf = proto_tree_add_item(opt_tree, offset,      optlen, "%s:", name);
  offset += 2;	/* skip past type and length */
  optlen -= 2;	/* subtract size of type and length */
  while (optlen > 0) {
    if (field_tree == NULL) {
      /* Haven't yet made a subtree out of this option.  Do so. */
      field_tree = proto_tree_new();
      proto_item_add_subtree(tf, field_tree, ETT_TCP_OPTION_SACK);
    }
    if (optlen < 4) {
      proto_tree_add_item(field_tree, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    leftedge = pntohl(opd);
    opd += 4;
    optlen -= 4;
    if (optlen < 4) {
      proto_tree_add_item(field_tree, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    rightedge = pntohl(opd);
    opd += 4;
    optlen -= 4;
    proto_tree_add_item(field_tree, offset,      8,
        "left edge = %u, right edge = %u", leftedge, rightedge);
    tcp_info_append_uint("SLE", leftedge);
    tcp_info_append_uint("SRE", rightedge);
    offset += 8;
  }
}

static void
dissect_tcpopt_echo(proto_tree *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  proto_tree_add_item(opt_tree, offset,      optlen,
    "%s: %u", name, pntohl(opd));
  tcp_info_append_uint("ECHO", pntohl(opd));
}

static void
dissect_tcpopt_timestamp(proto_tree *opt_tree, const char *name,
    const u_char *opd, int offset, guint optlen)
{
  proto_tree_add_item(opt_tree, offset,      optlen,
    "%s: tsval %u, tsecr %u", name, pntohl(opd), pntohl(opd + 4));
  tcp_info_append_uint("TSV", pntohl(opd));
  tcp_info_append_uint("TSER", pntohl(opd + 4));
}

static void
dissect_tcpopt_cc(proto_tree *opt_tree, const char *name, const u_char *opd,
    int offset, guint optlen)
{
  proto_tree_add_item(opt_tree, offset,      optlen,
    "%s: %u", name, pntohl(opd));
  tcp_info_append_uint("CC", pntohl(opd));
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
dissect_tcp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_tcphdr   th;
  proto_tree *tcp_tree = NULL, *field_tree = NULL;
  proto_item *ti, *tf;
  gchar      flags[64] = "<None>";
  gchar     *fstr[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
  gint       fpos = 0, i;
  guint      bpos;
  guint      hlen;
  guint      optlen;
  guint      packet_max = pi.payload + offset;
  guint      payload;

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
  
  info_len = 0;

  if (check_col(fd, COL_PROTOCOL) || tree) {  
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
  }
  
  hlen = hi_nibble(th.th_off_x2) * 4;  /* TCP header length, in bytes */

  payload = pi.payload - hlen;

  if (check_col(fd, COL_RES_SRC_PORT))
    col_add_str(fd, COL_RES_SRC_PORT, get_tcp_port(th.th_sport));
  if (check_col(fd, COL_UNRES_SRC_PORT))
    col_add_fstr(fd, COL_UNRES_SRC_PORT, "%u", th.th_sport);
  if (check_col(fd, COL_RES_DST_PORT))
    col_add_str(fd, COL_RES_DST_PORT, get_tcp_port(th.th_dport));
  if (check_col(fd, COL_UNRES_DST_PORT))
    col_add_fstr(fd, COL_UNRES_DST_PORT, "%u", th.th_dport);
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "TCP");
  if (check_col(fd, COL_INFO)) {
    /* Copy the data into info_str in case one of the option handling
       routines needs to append to it. */
    if (th.th_flags & TH_URG)
      info_len = snprintf(info_str, COL_MAX_LEN, "%s > %s [%s] Seq=%u Ack=%u Win=%u Urg=%u",
        get_tcp_port(th.th_sport), get_tcp_port(th.th_dport), flags,
        th.th_seq, th.th_ack, th.th_win, th.th_urp);
    else
      info_len = snprintf(info_str, COL_MAX_LEN, "%s > %s [%s] Seq=%u Ack=%u Win=%u",
        get_tcp_port(th.th_sport), get_tcp_port(th.th_dport), flags,
        th.th_seq, th.th_ack, th.th_win);
    /* The info column is actually written after the options are decoded */
  }
  
  if (tree) {
    ti = proto_tree_add_item(tree, offset, hlen,
      "Transmission Control Protocol");
    tcp_tree = proto_tree_new();
    proto_item_add_subtree(ti, tcp_tree, ETT_TCP);
    proto_tree_add_item(tcp_tree, offset,      2, "Source port: %s (%u)",
      get_tcp_port(th.th_sport), th.th_sport);
    proto_tree_add_item(tcp_tree, offset +  2, 2, "Destination port: %s (%u)",
      get_tcp_port(th.th_dport), th.th_dport);
    proto_tree_add_item(tcp_tree, offset +  4, 4, "Sequence number: %u",
      th.th_seq);
    if (th.th_flags & TH_ACK)
      proto_tree_add_item(tcp_tree, offset +  8, 4, "Acknowledgement number: %u",
        th.th_ack);
    proto_tree_add_item(tcp_tree, offset + 12, 1, "Header length: %u bytes", hlen);
     tf = proto_tree_add_item(tcp_tree, offset + 13, 1, "Flags: 0x%x", th.th_flags);
     field_tree = proto_tree_new();
     proto_item_add_subtree(tf, field_tree, ETT_TCP_FLAGS);
     proto_tree_add_item(field_tree, offset + 13, 1, "%s",
       decode_boolean_bitfield(th.th_flags, TH_URG, sizeof (th.th_flags)*8,
                         "Urgent pointer", "No urgent pointer"));
     proto_tree_add_item(field_tree, offset + 13, 1, "%s",
       decode_boolean_bitfield(th.th_flags, TH_ACK, sizeof (th.th_flags)*8,
                         "Acknowledgment", "No acknowledgment"));
     proto_tree_add_item(field_tree, offset + 13, 1, "%s",
       decode_boolean_bitfield(th.th_flags, TH_PUSH, sizeof (th.th_flags)*8,
                         "Push", "No push"));
     proto_tree_add_item(field_tree, offset + 13, 1, "%s",
       decode_boolean_bitfield(th.th_flags, TH_RST, sizeof (th.th_flags)*8,
                         "Reset", "No reset"));
     proto_tree_add_item(field_tree, offset + 13, 1, "%s",
       decode_boolean_bitfield(th.th_flags, TH_SYN, sizeof (th.th_flags)*8,
                         "Syn", "No Syn"));
     proto_tree_add_item(field_tree, offset + 13, 1, "%s",
       decode_boolean_bitfield(th.th_flags, TH_FIN, sizeof (th.th_flags)*8,
                         "Fin", "No Fin"));
    proto_tree_add_item(tcp_tree, offset + 14, 2, "Window size: %u", th.th_win);
    proto_tree_add_item(tcp_tree, offset + 16, 2, "Checksum: 0x%04x", th.th_sum);
    if (th.th_flags & TH_URG)
      proto_tree_add_item(tcp_tree, offset + 18, 2, "Urgent pointer: 0x%04x",
        th.th_urp);
  }

  /* Decode TCP options, if any. */
  if (tree  && hlen > sizeof (e_tcphdr)) {
    /* There's more than just the fixed-length header.  Decode the
       options. */
    optlen = hlen - sizeof (e_tcphdr); /* length of options, in bytes */
    tf = proto_tree_add_item(tcp_tree, offset +  20, optlen,
      "Options: (%d bytes)", optlen);
    field_tree = proto_tree_new();
    proto_item_add_subtree(tf, field_tree, ETT_TCP_OPTIONS);
    dissect_ip_tcp_options(field_tree, &pd[offset + 20], offset + 20, optlen,
      tcpopts, N_TCP_OPTS, TCPOPT_EOL);
  }

  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, info_str);

  /* Skip over header + options */
  offset += hlen;

  pi.srcport = th.th_sport;
  pi.destport = th.th_dport;
  
  /* Check the packet length to see if there's more data
     (it could be an ACK-only packet) */
  if (packet_max > offset) {
    /* XXX - this should be handled the way UDP handles this, with a table
       of port numbers to which stuff can be added */
#define PORT_IS(port)	(th.th_sport == port || th.th_dport == port)
    if (PORT_IS(TCP_PORT_PRINTER))
      dissect_lpd(pd, offset, fd, tree);
    else if (PORT_IS(TCP_PORT_TELNET)) {
      pi.match_port = TCP_PORT_TELNET;
      dissect_telnet(pd, offset, fd, tree, payload);
    } else if (PORT_IS(TCP_PORT_FTPDATA)) {
      pi.match_port = TCP_PORT_FTPDATA;
      dissect_ftpdata(pd, offset, fd, tree, payload);
    } else if (PORT_IS(TCP_PORT_FTP)) {
      pi.match_port = TCP_PORT_FTP;
      dissect_ftp(pd, offset, fd, tree, payload);
    } else if (PORT_IS(TCP_PORT_POP)) {
      pi.match_port = TCP_PORT_POP;
      dissect_pop(pd, offset, fd, tree, payload);
    } else if (PORT_IS(TCP_PORT_NNTP)) {
      pi.match_port = TCP_PORT_NNTP;
      dissect_nntp(pd, offset, fd, tree, payload);
    } else if (PORT_IS(TCP_PORT_PPTP)) {
      pi.match_port = TCP_PORT_PPTP;
      dissect_pptp(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_HTTP) || PORT_IS(TCP_ALT_PORT_HTTP))
      dissect_http(pd, offset, fd, tree);
    else if (PORT_IS(TCP_PORT_NBSS)) {
      pi.match_port = TCP_PORT_NBSS;
      dissect_nbss(pd, offset, fd, tree, payload);
    } else if (PORT_IS(TCP_PORT_RTSP))
      dissect_rtsp(pd, offset, fd, tree);
    else {
        /* check existence of high level protocols */

        if (memcmp(&pd[offset], "GIOP",  4) == 0) {
          dissect_giop(pd, offset, fd, tree);
        }
        else {
          dissect_data(pd, offset, fd, tree);
        }
    }
  }
 
  if( data_out_file ) {
    reassemble_tcp( th.th_seq, /* sequence number */
        ( pi.iplen -( pi.iphdrlen * 4 )-( hi_nibble(th.th_off_x2) * 4 ) ), /* length */
        ( pd+offset ), /* data */
        ( fd->cap_len - offset ), /* captured data length */
        ( th.th_flags & 0x02 ), /* is syn set? */
        pi.ip_src ); /* src ip */
  }
}
