/* packet-tcp.c
 * Routines for TCP packet disassembly
 *
 * $Id: packet-tcp.c,v 1.79 2000/08/07 03:21:15 guy Exp $
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
#include "prefs.h"

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include "plugins.h"
#include "packet-tcp.h"

#include "packet-ip.h"
#include "conversation.h"

/* Place TCP summary in proto tree */
gboolean g_tcp_summary_in_tree = TRUE;

extern FILE* data_out_file;

guint16 tcp_urgent_pointer;

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

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;

/* TCP Ports */

#define TCP_PORT_SMTP			25

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
  proto_tree_add_text(opt_tree, NullTVB, offset,      optlen,
			"%s: %u bytes", optp->name, pntohs(opd));
  tcp_info_append_uint("MSS", pntohs(opd));
}

static void
dissect_tcpopt_wscale(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, NullTVB, offset,      optlen,
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

  tf = proto_tree_add_text(opt_tree, NullTVB, offset,      optlen, "%s:", optp->name);
  offset += 2;	/* skip past type and length */
  optlen -= 2;	/* subtract size of type and length */
  while (optlen > 0) {
    if (field_tree == NULL) {
      /* Haven't yet made a subtree out of this option.  Do so. */
      field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    }
    if (optlen < 4) {
      proto_tree_add_text(field_tree, NullTVB, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    leftedge = pntohl(opd);
    opd += 4;
    optlen -= 4;
    if (optlen < 4) {
      proto_tree_add_text(field_tree, NullTVB, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }
    /* XXX - check whether it goes past end of packet */
    rightedge = pntohl(opd);
    opd += 4;
    optlen -= 4;
    proto_tree_add_text(field_tree, NullTVB, offset,      8,
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
  proto_tree_add_text(opt_tree, NullTVB, offset,      optlen,
			"%s: %u", optp->name, pntohl(opd));
  tcp_info_append_uint("ECHO", pntohl(opd));
}

static void
dissect_tcpopt_timestamp(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, NullTVB, offset,      optlen,
    "%s: tsval %u, tsecr %u", optp->name, pntohl(opd), pntohl(opd + 4));
  tcp_info_append_uint("TSV", pntohl(opd));
  tcp_info_append_uint("TSER", pntohl(opd + 4));
}

static void
dissect_tcpopt_cc(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, NullTVB, offset,      optlen,
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


/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine to other protocol dissectors */
/* can call to it, ie. socks	*/

void
decode_tcp_ports(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
	int src_port, int dst_port)
{
/* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

  if (old_try_conversation_dissector(&pi.src, &pi.dst, PT_TCP,
		src_port, dst_port, pd, offset, fd, tree))
	return;

  /* try to apply the plugins */
#ifdef HAVE_PLUGINS
  {
    plugin *pt_plug = plugin_list;

    if (enabled_plugins_number > 0) {
      while (pt_plug) {
	if (pt_plug->enabled && !strcmp(pt_plug->protocol, "tcp") &&
	    tree && dfilter_apply(pt_plug->filter, tree, pd, fd->cap_len)) {
	  pt_plug->dissector(pd, offset, fd, tree);
	  return;
	}
	pt_plug = pt_plug->next;
      }
    }
  }
#endif

  /* do lookup with the subdissector table */
  if (old_dissector_try_port(subdissector_table, src_port, pd, offset, fd, tree) ||
      old_dissector_try_port(subdissector_table, dst_port, pd, offset, fd, tree))
    return;

  /* do lookup with the heuristic subdissector table */
  if (old_dissector_try_heuristic(heur_subdissector_list, pd, offset, fd, tree))
    return;

  /* Oh, well, we don't know this; dissect it as data. */
  old_dissect_data(pd, offset, fd, tree);
}


static void
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

  /* Export the urgent pointer, for the benefit of protocols such as
     rlogin. */
  tcp_urgent_pointer = th.th_urp;
 
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
      info_len = snprintf(info_str, COL_MAX_LEN, "%s > %s [%s] Seq=%u Ack=%u Win=%u Urg=%u Len=%d",
        get_tcp_port(th.th_sport), get_tcp_port(th.th_dport), flags,
        th.th_seq, th.th_ack, th.th_win, th.th_urp, pi.len - offset - hlen);
    else
      info_len = snprintf(info_str, COL_MAX_LEN, "%s > %s [%s] Seq=%u Ack=%u Win=%u Len=%d",
        get_tcp_port(th.th_sport), get_tcp_port(th.th_dport), flags,
        th.th_seq, th.th_ack, th.th_win, pi.len - offset - hlen);
    /* The info column is actually written after the options are decoded */
  }
  
  if (tree) {
    if (g_tcp_summary_in_tree) {
	    ti = proto_tree_add_protocol_format(tree, proto_tcp, NullTVB, offset, hlen, "Transmission Control Protocol, Src Port: %s (%u), Dst Port: %s (%u), Seq: %u, Ack: %u", get_tcp_port(th.th_sport), th.th_sport, get_tcp_port(th.th_dport), th.th_dport, th.th_seq, th.th_ack);
    }
    else {
	    ti = proto_tree_add_item(tree, proto_tcp, NullTVB, offset, hlen, FALSE);
    }
    tcp_tree = proto_item_add_subtree(ti, ett_tcp);
    proto_tree_add_uint_format(tcp_tree, hf_tcp_srcport, NullTVB, offset, 2, th.th_sport,
	"Source port: %s (%u)", get_tcp_port(th.th_sport), th.th_sport);
    proto_tree_add_uint_format(tcp_tree, hf_tcp_dstport, NullTVB, offset + 2, 2, th.th_dport,
	"Destination port: %s (%u)", get_tcp_port(th.th_dport), th.th_dport);
    proto_tree_add_uint_hidden(tcp_tree, hf_tcp_port, NullTVB, offset, 2, th.th_sport);
    proto_tree_add_uint_hidden(tcp_tree, hf_tcp_port, NullTVB, offset + 2, 2, th.th_dport);
    proto_tree_add_uint(tcp_tree, hf_tcp_seq, NullTVB, offset + 4, 4, th.th_seq);
    if (th.th_flags & TH_ACK)
      proto_tree_add_uint(tcp_tree, hf_tcp_ack, NullTVB, offset + 8, 4, th.th_ack);
    proto_tree_add_uint_format(tcp_tree, hf_tcp_hdr_len, NullTVB, offset + 12, 1, hlen,
	"Header length: %u bytes", hlen);
    tf = proto_tree_add_uint_format(tcp_tree, hf_tcp_flags, NullTVB, offset + 13, 1,
	th.th_flags, "Flags: 0x%04x (%s)", th.th_flags, flags);
    field_tree = proto_item_add_subtree(tf, ett_tcp_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_urg, NullTVB, offset + 13, 1, th.th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_ack, NullTVB, offset + 13, 1, th.th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_push, NullTVB, offset + 13, 1, th.th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_reset, NullTVB, offset + 13, 1, th.th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_syn, NullTVB, offset + 13, 1, th.th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_fin, NullTVB, offset + 13, 1, th.th_flags);
    proto_tree_add_uint(tcp_tree, hf_tcp_window_size, NullTVB, offset + 14, 2, th.th_win);
    proto_tree_add_uint(tcp_tree, hf_tcp_checksum, NullTVB, offset + 16, 2, th.th_sum);
    if (th.th_flags & TH_URG)
      proto_tree_add_uint(tcp_tree, hf_tcp_urgent_pointer, NullTVB, offset + 18, 2, th.th_urp);
  }

  /* Decode TCP options, if any. */
  if (tree  && hlen > sizeof (e_tcphdr)) {
    /* There's more than just the fixed-length header.  Decode the
       options. */
    optlen = hlen - sizeof (e_tcphdr); /* length of options, in bytes */
    tf = proto_tree_add_text(tcp_tree, NullTVB, offset +  20, optlen,
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
    if (th.th_flags & TH_RST) {
      /*
       * RFC1122 says:
       *
       *	4.2.2.12  RST Segment: RFC-793 Section 3.4
       *
       *	  A TCP SHOULD allow a received RST segment to include data.
       *
       *	  DISCUSSION
       * 	       It has been suggested that a RST segment could contain
       * 	       ASCII text that encoded and explained the cause of the
       *	       RST.  No standard has yet been established for such
       *	       data.
       *
       * so for segments with RST we just display the data as text.
       */
      proto_tree_add_text(tcp_tree, NullTVB, offset, END_OF_FRAME,
			    "Reset cause: %s",
			    format_text(&pd[offset], END_OF_FRAME));
    } else
      decode_tcp_ports( pd, offset, fd, tree, th.th_sport, th.th_dport);
  }
 
  if( data_out_file ) {
    reassemble_tcp( th.th_seq,		/* sequence number */
        ( pi.len - offset ),		/* data length */
        ( pd+offset ),			/* data */
        ( pi.captured_len - offset ),	/* captured data length */
        ( th.th_flags & TH_SYN ),	/* is syn set? */
        &pi.net_src,
	&pi.net_dst,
	pi.srcport,
	pi.destport);
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
	module_t *tcp_module;

	proto_tcp = proto_register_protocol ("Transmission Control Protocol", "tcp");
	proto_register_field_array(proto_tcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	subdissector_table = register_dissector_table("tcp.port");
	register_heur_dissector_list("tcp", &heur_subdissector_list);

	/* Register a configuration preferences */
	tcp_module = prefs_register_module("tcp", "TCP", NULL);
	prefs_register_bool_preference(tcp_module, "tcp_summary_in_tree",
	    "Show TCP summary in protocol tree",
"Whether the TCP summary line should be shown in the protocol tree",
	    &g_tcp_summary_in_tree);
}

void
proto_reg_handoff_tcp(void)
{
	old_dissector_add("ip.proto", IP_PROTO_TCP, dissect_tcp);
}
