/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * $Id: packet-tcp.c,v 1.57 2000/02/15 21:03:15 gram Exp $
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
#include "globals.h"
#include "resolv.h"
#include "follow.h"

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include "plugins.h"

#include "packet-bgp.h"
#include "packet-ip.h"
#include "packet-ftp.h"
#include "packet-giop.h"
#include "packet-http.h"
#include "packet-imap.h"
#include "packet-irc.h"
#include "packet-ldap.h"
#include "packet-lpd.h"
#include "packet-mapi.h"
#include "packet-nbns.h"
#include "packet-ncp.h"
#include "packet-nntp.h"
#include "packet-ntp.h"
#include "packet-pop.h"
#include "packet-pptp.h"
#include "packet-rpc.h"
#include "packet-rtsp.h"
#include "packet-srvloc.h"
#include "packet-tacacs.h"
#include "packet-telnet.h"
#include "packet-tns.h"
#include "packet-yhoo.h"

extern FILE* data_out_file;

static gchar info_str[COL_MAX_LEN];
static int   info_len;

static int proto_tcp = -1;
static int hf_tcp_srcport = -1;
static int hf_tcp_dstport = -1;
static int hf_tcp_port = -1;
static int hf_tcp_seq = -1;
static int hf_tcp_ack = -1;
static int hf_tcp_hdr_len = -1;
static int hf_tcp_flags = -1;
static int hf_tcp_flags_urg = -1;
static int hf_tcp_flags_ack = -1;
static int hf_tcp_flags_push = -1;
static int hf_tcp_flags_reset = -1;
static int hf_tcp_flags_syn = -1;
static int hf_tcp_flags_fin = -1;
static int hf_tcp_window_size = -1;
static int hf_tcp_checksum = -1;
static int hf_tcp_urgent_pointer = -1;

static gint ett_tcp = -1;
static gint ett_tcp_flags = -1;
static gint ett_tcp_options = -1;
static gint ett_tcp_option_sack = -1;

/* TCP Ports */

#define TCP_PORT_FTPDATA		20
#define TCP_PORT_FTP			21
#define TCP_PORT_TELNET			23
#define TCP_PORT_SMTP			25
#define TCP_PORT_HTTP			80
#define TCP_PORT_TACACS			49
#define TCP_PORT_POP			110
#define TCP_PORT_NNTP			119
#define TCP_PORT_NTP			123
#define TCP_PORT_NBSS			139
#define TCP_PORT_IMAP			143
#define TCP_PORT_BGP			179
#define TCP_PORT_LDAP			389
#define TCP_PORT_SRVLOC			427
#define TCP_PORT_PRINTER		515
#define TCP_PORT_NCP			524
#define TCP_PORT_RTSP			554
#define TCP_PORT_MAPI			1065
#define TCP_PORT_TNS			1521
#define TCP_PORT_PPTP			1723
#define TCP_PORT_PROXY_HTTP		3128
#define TCP_PORT_PROXY_ADMIN_HTTP	3132
#define TCP_PORT_YHOO			5050
#define TCP_ALT_PORT_HTTP		8080
#define TCP_PORT_IRC			6667
	/* good candidate for dynamic port specification */

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
dissect_tcpopt_maxseg(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, offset,      optlen,
			"%s: %u bytes", optp->name, pntohs(opd));
  tcp_info_append_uint("MSS", pntohs(opd));
}

static void
dissect_tcpopt_wscale(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, offset,      optlen,
			"%s: %u bytes", optp->name, *opd);
  tcp_info_append_uint("WS", *opd);
}

static void
dissect_tcpopt_sack(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree *field_tree = NULL;
  proto_item *tf;
  guint leftedge, rightedge;

  tf = proto_tree_add_text(opt_tree, offset,      optlen, "%s:", optp->name);
  offset += 2;	/* skip past type and length */
  optlen -= 2;	/* subtract size of type and length */
  while (optlen > 0) {
    if (field_tree == NULL) {
      /* Haven't yet made a subtree out of this option.  Do so. */
      field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    }
    if (optlen < 4) {
      proto_tree_add_text(field_tree, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    leftedge = pntohl(opd);
    opd += 4;
    optlen -= 4;
    if (optlen < 4) {
      proto_tree_add_text(field_tree, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    rightedge = pntohl(opd);
    opd += 4;
    optlen -= 4;
    proto_tree_add_text(field_tree, offset,      8,
        "left edge = %u, right edge = %u", leftedge, rightedge);
    tcp_info_append_uint("SLE", leftedge);
    tcp_info_append_uint("SRE", rightedge);
    offset += 8;
  }
}

static void
dissect_tcpopt_echo(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, offset,      optlen,
			"%s: %u", optp->name, pntohl(opd));
  tcp_info_append_uint("ECHO", pntohl(opd));
}

static void
dissect_tcpopt_timestamp(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, offset,      optlen,
    "%s: tsval %u, tsecr %u", optp->name, pntohl(opd), pntohl(opd + 4));
  tcp_info_append_uint("TSV", pntohl(opd));
  tcp_info_append_uint("TSER", pntohl(opd + 4));
}

static void
dissect_tcpopt_cc(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, offset,      optlen,
			"%s: %u", optp->name, pntohl(opd));
  tcp_info_append_uint("CC", pntohl(opd));
}

static const ip_tcp_opt tcpopts[] = {
  {
    TCPOPT_EOL,
    "EOL",
    NULL,
    NO_LENGTH,
    0,
    NULL,
  },
  {
    TCPOPT_NOP,
    "NOP",
    NULL,
    NO_LENGTH,
    0,
    NULL,
  },
  {
    TCPOPT_MSS,
    "Maximum segment size",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_MSS,
    dissect_tcpopt_maxseg
  },
  {
    TCPOPT_WINDOW,
    "Window scale",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_WINDOW,
    dissect_tcpopt_wscale
  },
  {
    TCPOPT_SACK_PERM,
    "SACK permitted",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_SACK_PERM,
    NULL,
  },
  {
    TCPOPT_SACK,
    "SACK",
    &ett_tcp_option_sack,
    VARIABLE_LENGTH,
    TCPOLEN_SACK_MIN,
    dissect_tcpopt_sack
  },
  {
    TCPOPT_ECHO,
    "Echo",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_ECHO,
    dissect_tcpopt_echo
  },
  {
    TCPOPT_ECHOREPLY,
    "Echo reply",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_ECHOREPLY,
    dissect_tcpopt_echo
  },
  {
    TCPOPT_TIMESTAMP,
    "Time stamp",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_TIMESTAMP,
    dissect_tcpopt_timestamp
  },
  {
    TCPOPT_CC,
    "CC",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_CC,
    dissect_tcpopt_cc
  },
  {
    TCPOPT_CCNEW,
    "CC.NEW",
    NULL,
    FIXED_LENGTH,
    TCPOPT_CCNEW,
    dissect_tcpopt_cc
  },
  {
    TCPOPT_CCECHO,
    "CC.ECHO",
    NULL,
    FIXED_LENGTH,
    TCPOLEN_CCECHO,
    dissect_tcpopt_cc
  }
};

#define N_TCP_OPTS	(sizeof tcpopts / sizeof tcpopts[0])

/* TCP flags flag */
static const true_false_string flags_set_truth = {
  "Set",
  "Not set"
};

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
  guint      packet_max = pi.len;

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
    ti = proto_tree_add_item_format(tree, proto_tcp, offset, hlen, NULL, "Transmission Control Protocol, Src Port: %s (%u), Dst Port: %s (%u), Seq: %u, Ack: %u", get_tcp_port(th.th_sport), th.th_sport, get_tcp_port(th.th_dport), th.th_dport, th.th_seq, th.th_ack);
    tcp_tree = proto_item_add_subtree(ti, ett_tcp);
    proto_tree_add_item_format(tcp_tree, hf_tcp_srcport, offset, 2, th.th_sport,
	"Source port: %s (%u)", get_tcp_port(th.th_sport), th.th_sport);
    proto_tree_add_item_format(tcp_tree, hf_tcp_dstport, offset + 2, 2, th.th_dport,
	"Destination port: %s (%u)", get_tcp_port(th.th_dport), th.th_dport);
    proto_tree_add_item_hidden(tcp_tree, hf_tcp_port, offset, 2, th.th_sport);
    proto_tree_add_item_hidden(tcp_tree, hf_tcp_port, offset + 2, 2, th.th_dport);
    proto_tree_add_item(tcp_tree, hf_tcp_seq, offset + 4, 4, th.th_seq);
    if (th.th_flags & TH_ACK)
      proto_tree_add_item(tcp_tree, hf_tcp_ack, offset + 8, 4, th.th_ack);
    proto_tree_add_item_format(tcp_tree, hf_tcp_hdr_len, offset + 12, 1, hlen,
	"Header length: %u bytes", hlen);
    tf = proto_tree_add_item_format(tcp_tree, hf_tcp_flags, offset + 13, 1,
	th.th_flags, "Flags: 0x%04x (%s)", th.th_flags, flags);
    field_tree = proto_item_add_subtree(tf, ett_tcp_flags);
    proto_tree_add_item(field_tree, hf_tcp_flags_urg, offset + 13, 1, th.th_flags);
    proto_tree_add_item(field_tree, hf_tcp_flags_ack, offset + 13, 1, th.th_flags);
    proto_tree_add_item(field_tree, hf_tcp_flags_push, offset + 13, 1, th.th_flags);
    proto_tree_add_item(field_tree, hf_tcp_flags_reset, offset + 13, 1, th.th_flags);
    proto_tree_add_item(field_tree, hf_tcp_flags_syn, offset + 13, 1, th.th_flags);
    proto_tree_add_item(field_tree, hf_tcp_flags_fin, offset + 13, 1, th.th_flags);
    proto_tree_add_item(tcp_tree, hf_tcp_window_size, offset + 14, 2, th.th_win);
    proto_tree_add_item(tcp_tree, hf_tcp_checksum, offset + 16, 2, th.th_sum);
    if (th.th_flags & TH_URG)
      proto_tree_add_item(tcp_tree, hf_tcp_urgent_pointer, offset + 18, 2, th.th_urp);
  }

  /* Decode TCP options, if any. */
  if (tree  && hlen > sizeof (e_tcphdr)) {
    /* There's more than just the fixed-length header.  Decode the
       options. */
    optlen = hlen - sizeof (e_tcphdr); /* length of options, in bytes */
    tf = proto_tree_add_text(tcp_tree, offset +  20, optlen,
      "Options: (%d bytes)", optlen);
    field_tree = proto_item_add_subtree(tf, ett_tcp_options);
    dissect_ip_tcp_options(&pd[offset + 20], offset + 20, optlen,
      tcpopts, N_TCP_OPTS, TCPOPT_EOL, field_tree);
  }

  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, info_str);

  /* Skip over header + options */
  offset += hlen;

  pi.ptype = PT_TCP;
  pi.srcport = th.th_sport;
  pi.destport = th.th_dport;
  
  /* Check the packet length to see if there's more data
     (it could be an ACK-only packet) */
  if (packet_max > offset) {

    /* try to apply the plugins */
#ifdef HAVE_PLUGINS
    plugin *pt_plug = plugin_list;

    if (pt_plug) {
      while (pt_plug) {
	if (pt_plug->enabled && !strcmp(pt_plug->protocol, "tcp") &&
	    tree && dfilter_apply(pt_plug->filter, tree, pd)) {
	  pt_plug->dissector(pd, offset, fd, tree);
	  goto reas;
	}
	pt_plug = pt_plug->next;
      }
    }
#endif

    /* ONC RPC.  We can't base this on anything in the TCP header; we have
       to look at the payload.  If "dissect_rpc()" returns TRUE, it was
       an RPC packet, otherwise it's some other type of packet. */
    if (dissect_rpc(pd, offset, fd, tree))
      goto reas;

    /* XXX - this should be handled the way UDP handles this, with a table
       of port numbers to which stuff can be added */
#define PORT_IS(port)	(th.th_sport == port || th.th_dport == port)
    if (PORT_IS(TCP_PORT_PRINTER))
      dissect_lpd(pd, offset, fd, tree);
    else if (PORT_IS(TCP_PORT_TELNET)) {
      pi.match_port = TCP_PORT_TELNET;
      dissect_telnet(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_FTPDATA)) {
      pi.match_port = TCP_PORT_FTPDATA;
      dissect_ftpdata(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_FTP)) {
      pi.match_port = TCP_PORT_FTP;
      dissect_ftp(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_POP)) {
      pi.match_port = TCP_PORT_POP;
      dissect_pop(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_IMAP)) {
      pi.match_port = TCP_PORT_IMAP;
      dissect_imap(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_NNTP)) {
      pi.match_port = TCP_PORT_NNTP;
      dissect_nntp(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_NTP)) {
      pi.match_port = TCP_PORT_NTP;
      dissect_ntp(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_PPTP)) {
      pi.match_port = TCP_PORT_PPTP;
      dissect_pptp(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_HTTP) || PORT_IS(TCP_ALT_PORT_HTTP)
            || PORT_IS(631) || PORT_IS(TCP_PORT_PROXY_HTTP)
            || PORT_IS(TCP_PORT_PROXY_ADMIN_HTTP))
      dissect_http(pd, offset, fd, tree);
    else if (PORT_IS(TCP_PORT_NBSS)) {
      pi.match_port = TCP_PORT_NBSS;
      dissect_nbss(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_RTSP))
      dissect_rtsp(pd, offset, fd, tree);
    else if (PORT_IS(TCP_PORT_BGP)) {
      pi.match_port = TCP_PORT_BGP;
      dissect_bgp(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_TACACS)) {
      pi.match_port = TCP_PORT_TACACS;
      dissect_tacplus(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_MAPI)) {
      pi.match_port = TCP_PORT_MAPI;
      dissect_mapi(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_TNS)) {
      pi.match_port = TCP_PORT_TNS;
      dissect_tns(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_IRC)) {
      pi.match_port = TCP_PORT_IRC;
      dissect_irc(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_LDAP)) {
      pi.match_port = TCP_PORT_LDAP;
      dissect_ldap(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_SRVLOC)) {
      pi.match_port = TCP_PORT_SRVLOC;
      dissect_srvloc(pd, offset, fd, tree);
    } else if (PORT_IS(TCP_PORT_NCP)) {
      pi.match_port = TCP_PORT_NCP;
      dissect_ncp(pd, offset, fd, tree); /* XXX -- need to handle nw_server_address */
    } else {
        /* check existence of high level protocols */

        if (memcmp(&pd[offset], "GIOP",  4) == 0) {
          dissect_giop(pd, offset, fd, tree);
        }
	else if ( PORT_IS(TCP_PORT_YHOO) && 
		(memcmp(&pd[offset], "YPNS",  4) == 0 ||
			memcmp(&pd[offset], "YHOO",  4) == 0 )) {
	  dissect_yhoo(pd, offset, fd, tree);
	}
        else {
          dissect_data(pd, offset, fd, tree);
        }
    }
  }

reas:
 
  if( data_out_file ) {
    reassemble_tcp( th.th_seq,		/* sequence number */
        ( pi.len - offset ),		/* data length */
        ( pd+offset ),			/* data */
        ( pi.captured_len - offset ),	/* captured data length */
        ( th.th_flags & TH_SYN ),	/* is syn set? */
        &pi.net_src,
	&pi.net_dst,
	pi.srcport,
	pi.destport,
	fd->rel_secs,
	fd->rel_usecs);
  }
}

void
proto_register_tcp(void)
{
	static hf_register_info hf[] = {

		{ &hf_tcp_srcport,
		{ "Source Port",		"tcp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_tcp_dstport,
		{ "Destination Port",		"tcp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_tcp_port,
		{ "Source or Destination Port",	"tcp.port", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_tcp_seq,
		{ "Sequence number",		"tcp.seq", FT_UINT32, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_tcp_ack,
		{ "Acknowledgement number",	"tcp.ack", FT_UINT32, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_tcp_hdr_len,
		{ "Header Length",		"tcp.hdr_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_tcp_flags,
		{ "Flags",			"tcp.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_tcp_flags_urg,
		{ "Urgent",			"tcp.flags.urg", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_URG,
			"" }},

		{ &hf_tcp_flags_ack,
		{ "Acknowledgment",		"tcp.flags.ack", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_ACK,
			"" }},

		{ &hf_tcp_flags_push,
		{ "Push",			"tcp.flags.push", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_PUSH,
			"" }},

		{ &hf_tcp_flags_reset,
		{ "Reset",			"tcp.flags.reset", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_RST,
			"" }},

		{ &hf_tcp_flags_syn,
		{ "Syn",			"tcp.flags.syn", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_SYN,
			"" }},

		{ &hf_tcp_flags_fin,
		{ "Fin",			"tcp.flags.fin", FT_BOOLEAN, 8, TFS(&flags_set_truth), TH_FIN,
			"" }},

		{ &hf_tcp_window_size,
		{ "Window size",		"tcp.window_size", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_tcp_checksum,
		{ "Checksum",			"tcp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_tcp_urgent_pointer,
		{ "Urgent pointer",		"tcp.urgent_pointer", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},
	};
	static gint *ett[] = {
		&ett_tcp,
		&ett_tcp_flags,
		&ett_tcp_options,
		&ett_tcp_option_sack,
	};

	proto_tcp = proto_register_protocol ("Transmission Control Protocol", "tcp");
	proto_register_field_array(proto_tcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
