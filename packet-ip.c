/* packet-ip.c
 * Routines for IP and miscellaneous IP protocol packet disassembly
 *
 * $Id: packet-ip.c,v 1.70 2000/01/23 08:55:32 guy Exp $
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
#include <string.h>
#include <glib.h>
#include "packet.h"
#include "resolv.h"

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

static int proto_ip = -1;
static int hf_ip_version = -1;
static int hf_ip_hdr_len = -1;
static int hf_ip_tos = -1;
static int hf_ip_tos_precedence = -1;
static int hf_ip_tos_delay = -1;
static int hf_ip_tos_throughput = -1;
static int hf_ip_tos_reliability = -1;
static int hf_ip_tos_cost = -1;
static int hf_ip_len = -1;
static int hf_ip_id = -1;
static int hf_ip_dst = -1;
static int hf_ip_src = -1;
static int hf_ip_addr = -1;
static int hf_ip_flags = -1;
static int hf_ip_flags_df = -1;
static int hf_ip_flags_mf = -1;
static int hf_ip_frag_offset = -1;
static int hf_ip_ttl = -1;
static int hf_ip_proto = -1;
static int hf_ip_checksum = -1;

static gint ett_ip = -1;
static gint ett_ip_tos = -1;
static gint ett_ip_off = -1;
static gint ett_ip_options = -1;
static gint ett_ip_option_sec = -1;
static gint ett_ip_option_route = -1;
static gint ett_ip_option_timestamp = -1;

static int proto_igmp = -1;
static int hf_igmp_version = -1;
static int hf_igmp_type = -1;
static int hf_igmp_unused = -1;
static int hf_igmp_checksum = -1;
static int hf_igmp_group = -1;

static gint ett_igmp = -1;

static int proto_icmp = -1;
static int hf_icmp_type = -1;
static int hf_icmp_code = -1;
static int hf_icmp_checksum = -1;

static gint ett_icmp = -1;

/* ICMP structs and definitions */
typedef struct _e_icmp {
  guint8  icmp_type;
  guint8  icmp_code;
  guint16 icmp_cksum;
  union {
    struct {  /* Address mask request/reply */
      guint16 id;
      guint16 seq;
      guint32 sn_mask;
    } am;
    struct {  /* Timestap request/reply */
      guint16 id;
      guint16 seq;
      guint32 orig;
      guint32 recv;
      guint32 xmit;
    } ts;
    guint32 zero;  /* Unreachable */
  } opt;
} e_icmp;

#define ICMP_ECHOREPLY     0
#define ICMP_UNREACH       3
#define ICMP_SOURCEQUENCH  4
#define ICMP_REDIRECT      5
#define ICMP_ECHO          8
#define ICMP_RTRADVERT     9
#define ICMP_RTRSOLICIT   10
#define ICMP_TIMXCEED     11
#define ICMP_PARAMPROB    12
#define ICMP_TSTAMP       13
#define ICMP_TSTAMPREPLY  14
#define ICMP_IREQ         15
#define ICMP_IREQREPLY    16
#define ICMP_MASKREQ      17
#define ICMP_MASKREPLY    18

/* ICMP UNREACHABLE */

#define ICMP_NET_UNREACH        0       /* Network Unreachable */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set */
#define ICMP_SR_FAILED          5       /* Source Route failed */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */


/* IGMP structs and definitions */
typedef struct _e_igmp {
  guint8  igmp_v_t; /* combines igmp_v and igmp_t */
  guint8  igmp_unused;
  guint16 igmp_cksum;
  guint32 igmp_gaddr;
} e_igmp;

#define IGMP_M_QRY     0x01
#define IGMP_V1_M_RPT  0x02
#define IGMP_V2_LV_GRP 0x07
#define IGMP_DVMRP     0x03
#define IGMP_PIM       0x04
#define IGMP_V2_M_RPT  0x06
#define IGMP_MTRC_RESP 0x1e
#define IGMP_MTRC      0x1f

/* EIGRP Structs and Definitions. */    

/* EIGRP Opcodes */

#define EIGRP_UPDATE    0x01
#define EIGRP_REQUEST   0x02
#define EIGRP_QUERY     0x03
#define EIGRP_REPLY     0x04
#define EIGRP_HELLO     0x05

typedef struct _e_eigrp 
   {
   guint8 eigrp_version;
   guint8 eigrp_opcode;
   guint16 eigrp_checksum;
   guint16 eigrp_subnets;
   guint16 eigrp_networks;
   guint32 eigrp_sequence;
   guint32 eigrp_asnumber;
   guint8 eigrp_type1;
   guint8 eigrp_subtype1;
   guint16 eigrp_length1;
   guint16 eigrp_holdtime;
   guint8 eigrp_type2;
   guint8 eigrp_subtype2;
   guint16 eigrp_length2;
   guint8 eigrp_level;
   guint16 eigrp_dummy;
   } e_eigrp;

/* IP structs and definitions */

typedef struct _e_ip 
   {
   guint8  ip_v_hl; /* combines ip_v and ip_hl */
   guint8  ip_tos;
   guint16 ip_len;
   guint16 ip_id;
   guint16 ip_off;
   guint8  ip_ttl;
   guint8  ip_p;
   guint16 ip_sum;
   guint32 ip_src;
   guint32 ip_dst;
   } e_ip;

/* Offsets of fields within an IP header. */
#define	IPH_V_HL	0
#define	IPH_TOS		1
#define	IPH_LEN		2
#define	IPH_ID		4
#define	IPH_TTL		6
#define	IPH_OFF		8
#define	IPH_P		9
#define	IPH_SUM		10
#define	IPH_SRC		12
#define	IPH_DST		16

/* Minimum IP header length. */
#define	IPH_MIN_LEN	20

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define IPTOS_TOS_MASK    0x1E
#define IPTOS_TOS(tos)    ((tos) & IPTOS_TOS_MASK)
#define IPTOS_NONE        0x00
#define IPTOS_LOWCOST     0x02
#define IPTOS_RELIABILITY 0x04
#define IPTOS_THROUGHPUT  0x08
#define IPTOS_LOWDELAY    0x10
#define IPTOS_SECURITY    0x1E

#define IPTOS_PREC_MASK		0xE0
#define IPTOS_PREC_SHIFT	5
#define IPTOS_PREC(tos)		(((tos)&IPTOS_PREC_MASK)>>IPTOS_PREC_SHIFT)
#define IPTOS_PREC_NETCONTROL           7
#define IPTOS_PREC_INTERNETCONTROL      6
#define IPTOS_PREC_CRITIC_ECP           5
#define IPTOS_PREC_FLASHOVERRIDE        4
#define IPTOS_PREC_FLASH                3
#define IPTOS_PREC_IMMEDIATE            2
#define IPTOS_PREC_PRIORITY             1
#define IPTOS_PREC_ROUTINE              0

/* IP options */
#define IPOPT_COPY		0x80

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_MEASUREMENT	0x40
#define	IPOPT_RESERVED2		0x60

#define IPOPT_END	(0 |IPOPT_CONTROL)
#define IPOPT_NOOP	(1 |IPOPT_CONTROL)
#define IPOPT_SEC	(2 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_LSRR	(3 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_TIMESTAMP	(4 |IPOPT_MEASUREMENT)
#define IPOPT_RR	(7 |IPOPT_CONTROL)
#define IPOPT_SID	(8 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_SSRR	(9 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)

/* IP option lengths */
#define IPOLEN_SEC      11
#define IPOLEN_LSRR_MIN 3
#define IPOLEN_TIMESTAMP_MIN 5
#define IPOLEN_RR_MIN   3
#define IPOLEN_SID      4
#define IPOLEN_SSRR_MIN 3

#define IPSEC_UNCLASSIFIED	0x0000
#define	IPSEC_CONFIDENTIAL	0xF135
#define	IPSEC_EFTO		0x789A
#define	IPSEC_MMMM		0xBC4D
#define	IPSEC_RESTRICTED	0xAF13
#define	IPSEC_SECRET		0xD788
#define	IPSEC_TOPSECRET		0x6BC5
#define	IPSEC_RESERVED1		0x35E2
#define	IPSEC_RESERVED2		0x9AF1
#define	IPSEC_RESERVED3		0x4D78
#define	IPSEC_RESERVED4		0x24BD
#define	IPSEC_RESERVED5		0x135E
#define	IPSEC_RESERVED6		0x89AF
#define	IPSEC_RESERVED7		0xC4D6
#define	IPSEC_RESERVED8		0xE26B

#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3		/* specified modules only */


void
capture_ip(const u_char *pd, int offset, packet_counts *ld) {
  if (!BYTES_ARE_IN_FRAME(offset, IPH_MIN_LEN)) {
    ld->other++;
    return;
  }
  switch (pd[offset + 9]) {
    case IP_PROTO_TCP:
      ld->tcp++;
      break;
    case IP_PROTO_UDP:
      ld->udp++;
      break;
    case IP_PROTO_ICMP:
      ld->icmp++;
      break;
    case IP_PROTO_OSPF:
      ld->ospf++;
      break;
    case IP_PROTO_GRE:
      ld->gre++;
      break;
    case IP_PROTO_VINES:
      ld->gre++;
      break;
    default:
      ld->other++;
  }
}

static void
dissect_ipopt_security(const ip_tcp_opt *optp, const u_char *opd, int offset,
			guint optlen, proto_tree *opt_tree)
{
  proto_tree *field_tree = NULL;
  proto_item *tf;
  guint      val;
  static const value_string secl_vals[] = {
    {IPSEC_UNCLASSIFIED, "Unclassified"},
    {IPSEC_CONFIDENTIAL, "Confidential"},
    {IPSEC_EFTO,         "EFTO"        },
    {IPSEC_MMMM,         "MMMM"        },
    {IPSEC_RESTRICTED,   "Restricted"  },
    {IPSEC_SECRET,       "Secret"      },
    {IPSEC_TOPSECRET,    "Top secret"  },
    {IPSEC_RESERVED1,    "Reserved"    },
    {IPSEC_RESERVED2,    "Reserved"    },
    {IPSEC_RESERVED3,    "Reserved"    },
    {IPSEC_RESERVED4,    "Reserved"    },
    {IPSEC_RESERVED5,    "Reserved"    },
    {IPSEC_RESERVED6,    "Reserved"    },
    {IPSEC_RESERVED7,    "Reserved"    },
    {IPSEC_RESERVED8,    "Reserved"    },
    {0,                  NULL          } };

  tf = proto_tree_add_text(opt_tree, offset,      optlen, "%s:", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;

  val = pntohs(opd);
  proto_tree_add_text(field_tree, offset,       2,
              "Security: %s", val_to_str(val, secl_vals, "Unknown (0x%x)"));
  offset += 2;
  opd += 2;

  val = pntohs(opd);
  proto_tree_add_text(field_tree, offset,         2,
              "Compartments: %d", val);
  offset += 2;
  opd += 2;

  proto_tree_add_text(field_tree, offset,         2,
              "Handling restrictions: %c%c", opd[0], opd[1]);
  offset += 2;
  opd += 2;

  proto_tree_add_text(field_tree, offset,         3,
              "Transmission control code: %c%c%c", opd[0], opd[1], opd[2]);
}

static void
dissect_ipopt_route(const ip_tcp_opt *optp, const u_char *opd, int offset,
			guint optlen, proto_tree *opt_tree)
{
  proto_tree *field_tree = NULL;
  proto_item *tf;
  int ptr;
  int optoffset = 0;
  struct in_addr addr;

  tf = proto_tree_add_text(opt_tree, offset,      optlen, "%s (%d bytes)",
				optp->name, optlen);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  optoffset += 2;	/* skip past type and length */
  optlen -= 2;		/* subtract size of type and length */

  ptr = *opd;
  proto_tree_add_text(field_tree, offset + optoffset, 1,
              "Pointer: %d%s", ptr,
              ((ptr < 4) ? " (points before first address)" :
               ((ptr & 3) ? " (points to middle of address)" : "")));
  optoffset++;
  opd++;
  optlen--;
  ptr--;	/* ptr is 1-origin */

  while (optlen > 0) {
    if (optlen < 4) {
      proto_tree_add_text(field_tree, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }

    /* Avoids alignment problems on many architectures. */
    memcpy((char *)&addr, (char *)opd, sizeof(addr));

    proto_tree_add_text(field_tree, offset + optoffset, 4,
              "%s%s",
              ((addr.s_addr == 0) ? "-" : (char *)get_hostname(addr.s_addr)),
              ((optoffset == ptr) ? " <- (current)" : ""));
    optoffset += 4;
    opd += 4;
    optlen -= 4;
  }
}

static void
dissect_ipopt_sid(const ip_tcp_opt *optp, const u_char *opd, int offset,
			guint optlen, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, offset,      optlen,
    "%s: %d", optp->name, pntohs(opd));
  return;
}

static void
dissect_ipopt_timestamp(const ip_tcp_opt *optp, const u_char *opd,
    int offset, guint optlen, proto_tree *opt_tree)
{
  proto_tree *field_tree = NULL;
  proto_item *tf;
  int        ptr;
  int        optoffset = 0;
  int        flg;
  static const value_string flag_vals[] = {
    {IPOPT_TS_TSONLY,    "Time stamps only"                      },
    {IPOPT_TS_TSANDADDR, "Time stamp and address"                },
    {IPOPT_TS_PRESPEC,   "Time stamps for prespecified addresses"},
    {0,                  NULL                                    } };
  struct in_addr addr;
  guint ts;

  tf = proto_tree_add_text(opt_tree, offset,      optlen, "%s:", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  optoffset += 2;	/* skip past type and length */
  optlen -= 2;		/* subtract size of type and length */

  ptr = *opd;
  proto_tree_add_text(field_tree, offset + optoffset, 1,
              "Pointer: %d%s", ptr,
              ((ptr < 5) ? " (points before first address)" :
               (((ptr - 1) & 3) ? " (points to middle of address)" : "")));
  optoffset++;
  opd++;
  optlen--;
  ptr--;	/* ptr is 1-origin */

  flg = *opd;
  proto_tree_add_text(field_tree, offset + optoffset,   1,
        "Overflow: %d", flg >> 4);
  flg &= 0xF;
  proto_tree_add_text(field_tree, offset + optoffset, 1,
        "Flag: %s", val_to_str(flg, flag_vals, "Unknown (0x%x)"));
  optoffset++;
  opd++;
  optlen--;

  while (optlen > 0) {
    if (flg == IPOPT_TS_TSANDADDR) {
      if (optlen < 4) {
        proto_tree_add_text(field_tree, offset + optoffset, optlen,
          "(suboption would go past end of option)");
        break;
      }
      /* XXX - check whether it goes past end of packet */
      ts = pntohl(opd);
      opd += 4;
      optlen -= 4;
      if (optlen < 4) {
        proto_tree_add_text(field_tree, offset + optoffset, optlen,
          "(suboption would go past end of option)");
        break;
      }
      /* XXX - check whether it goes past end of packet */
      memcpy((char *)&addr, (char *)opd, sizeof(addr));
      opd += 4;
      optlen -= 4;
      proto_tree_add_text(field_tree, offset,      8,
          "Address = %s, time stamp = %u",
          ((addr.s_addr == 0) ? "-" :  (char *)get_hostname(addr.s_addr)),
          ts);
      optoffset += 8;
    } else {
      if (optlen < 4) {
        proto_tree_add_text(field_tree, offset + optoffset, optlen,
          "(suboption would go past end of option)");
        break;
      }
      /* XXX - check whether it goes past end of packet */
      ts = pntohl(opd);
      opd += 4;
      optlen -= 4;
      proto_tree_add_text(field_tree, offset + optoffset, 4,
          "Time stamp = %u", ts);
      optoffset += 4;
    }
  }
}

static const ip_tcp_opt ipopts[] = {
  {
    IPOPT_END,
    "EOL",
    NULL,
    NO_LENGTH,
    0,
    NULL,
  },
  {
    IPOPT_NOOP,
    "NOP",
    NULL,
    NO_LENGTH,
    0,
    NULL,
  },
  {
    IPOPT_SEC,
    "Security",
    &ett_ip_option_sec,
    FIXED_LENGTH,
    IPOLEN_SEC,
    dissect_ipopt_security
  },
  {
    IPOPT_SSRR,
    "Strict source route",
    &ett_ip_option_route,
    VARIABLE_LENGTH,
    IPOLEN_SSRR_MIN,
    dissect_ipopt_route
  },
  {
    IPOPT_LSRR,
    "Loose source route",
    &ett_ip_option_route,
    VARIABLE_LENGTH,
    IPOLEN_LSRR_MIN,
    dissect_ipopt_route
  },
  {
    IPOPT_RR,
    "Record route",
    &ett_ip_option_route,
    VARIABLE_LENGTH,
    IPOLEN_RR_MIN,
    dissect_ipopt_route
  },
  {
    IPOPT_SID,
    "Stream identifier",
    NULL,
    FIXED_LENGTH,
    IPOLEN_SID,
    dissect_ipopt_sid
  },
  {
    IPOPT_TIMESTAMP,
    "Time stamp",
    &ett_ip_option_timestamp,
    VARIABLE_LENGTH,
    IPOLEN_TIMESTAMP_MIN,
    dissect_ipopt_timestamp
  }
};

#define N_IP_OPTS	(sizeof ipopts / sizeof ipopts[0])

/* Dissect the IP or TCP options in a packet. */
void
dissect_ip_tcp_options(const u_char *opd, int offset, guint length,
			const ip_tcp_opt *opttab, int nopts, int eol,
			proto_tree *opt_tree)
{
  u_char            opt;
  const ip_tcp_opt *optp;
  opt_len_type      len_type;
  int               optlen;
  char             *name;
  char              name_str[7+1+1+2+2+1+1];	/* "Unknown (0x%02x)" */
  void            (*dissect)(const struct ip_tcp_opt *, const u_char *,
				int, guint, proto_tree *);
  guint             len;

  while (length > 0) {
    opt = *opd++;
    for (optp = &opttab[0]; optp < &opttab[nopts]; optp++) {
      if (optp->optcode == opt)
        break;
    }
    if (optp == &opttab[nopts]) {
      /* We assume that the only NO_LENGTH options are EOL and NOP options,
         so that we can treat unknown options as VARIABLE_LENGTH with a
	 minimum of 2, and at least be able to move on to the next option
	 by using the length in the option. */
      optp = NULL;	/* indicate that we don't know this option */
      len_type = VARIABLE_LENGTH;
      optlen = 2;
      snprintf(name_str, sizeof name_str, "Unknown (0x%02x)", opt);
      name = name_str;
      dissect = NULL;
    } else {
      len_type = optp->len_type;
      optlen = optp->optlen;
      name = optp->name;
      dissect = optp->dissect;
    }
    --length;      /* account for type byte */
    if (len_type != NO_LENGTH) {
      /* Option has a length. Is it in the packet? */
      if (length == 0) {
        /* Bogus - packet must at least include option code byte and
           length byte! */
        proto_tree_add_text(opt_tree, offset,      1,
              "%s (length byte past end of options)", name);
        return;
      }
      len = *opd++;  /* total including type, len */
      --length;    /* account for length byte */
      if (len < 2) {
        /* Bogus - option length is too short to include option code and
           option length. */
        proto_tree_add_text(opt_tree, offset,      2,
              "%s (with too-short option length = %u byte%s)", name,
              len, plurality(len, "", "s"));
        return;
      } else if (len - 2 > length) {
        /* Bogus - option goes past the end of the header. */
        proto_tree_add_text(opt_tree, offset,      length,
              "%s (option length = %u byte%s says option goes past end of options)",
	      name, len, plurality(len, "", "s"));
        return;
      } else if (len_type == FIXED_LENGTH && len != optlen) {
        /* Bogus - option length isn't what it's supposed to be for this
           option. */
        proto_tree_add_text(opt_tree, offset,      len,
              "%s (with option length = %u byte%s; should be %u)", name,
              len, plurality(len, "", "s"), optlen);
        return;
      } else if (len_type == VARIABLE_LENGTH && len < optlen) {
        /* Bogus - option length is less than what it's supposed to be for
           this option. */
        proto_tree_add_text(opt_tree, offset,      len,
              "%s (with option length = %u byte%s; should be >= %u)", name,
              len, plurality(len, "", "s"), optlen);
        return;
      } else {
        if (optp == NULL) {
          proto_tree_add_text(opt_tree, offset,    len, "%s (%d byte%s)",
				name, len, plurality(len, "", "s"));
        } else {
          if (dissect != NULL) {
            /* Option has a dissector. */
            (*dissect)(optp, opd, offset,          len, opt_tree);
          } else {
            /* Option has no data, hence no dissector. */
            proto_tree_add_text(opt_tree, offset,  len, "%s", name);
          }
        }
        len -= 2;	/* subtract size of type and length */
        offset += 2 + len;
      }
      opd += len;
      length -= len;
    } else {
      proto_tree_add_text(opt_tree, offset,      1, "%s", name);
      offset += 1;
    }
    if (opt == eol)
      break;
  }
}

static const value_string proto_vals[] = { {IP_PROTO_ICMP, "ICMP"},
                                           {IP_PROTO_IGMP, "IGMP"},
                                           {IP_PROTO_EIGRP, "IGRP/EIGRP"},
                                           {IP_PROTO_TCP,  "TCP" },
                                           {IP_PROTO_UDP,  "UDP" },
                                           {IP_PROTO_OSPF, "OSPF"},
                                           {IP_PROTO_RSVP, "RSVP"},
                                           {IP_PROTO_AH,   "AH"  },
                                           {IP_PROTO_GRE,  "GRE" },
                                           {IP_PROTO_ESP,  "ESP" },
                                           {IP_PROTO_IPV6, "IPv6"},
                                           {IP_PROTO_PIM,  "PIM" },
                                           {IP_PROTO_VINES,"VINES"},
                                           {0,             NULL  } };

static const value_string precedence_vals[] = {
		  { IPTOS_PREC_ROUTINE,         "routine"              },
		  { IPTOS_PREC_PRIORITY,        "priority"             },
		  { IPTOS_PREC_IMMEDIATE,       "immediate"            },
		  { IPTOS_PREC_FLASH,           "flash"                },
		  { IPTOS_PREC_FLASHOVERRIDE,   "flash override"       },
		  { IPTOS_PREC_CRITIC_ECP,      "CRITIC/ECP"           },
		  { IPTOS_PREC_INTERNETCONTROL, "internetwork control" },
		  { IPTOS_PREC_NETCONTROL,      "network control"      },
		  { 0,                          NULL                   } };

static const value_string iptos_vals[] = {
	{ IPTOS_NONE,		"None" },
	{ IPTOS_LOWCOST,	"Minimize cost" },
	{ IPTOS_RELIABILITY,	"Maximize reliability" },
	{ IPTOS_THROUGHPUT,	"Maximize throughput" },
	{ IPTOS_LOWDELAY,	"Minimize delay" },
	{ IPTOS_SECURITY,	"Maximize security" },
	{ 0,			NULL }
};

static const true_false_string tos_set_low = {
  "Low",
  "Normal"
};

static const true_false_string tos_set_high = {
  "High",
  "Normal"
};

static const true_false_string flags_set_truth = {
  "Set",
  "Not set"
};

static char *ip_checksum_state(e_ip *iph)
{
    unsigned long Sum;
    unsigned char *Ptr, *PtrEnd;
    unsigned short word;

    Sum    = 0;
    PtrEnd = (lo_nibble(iph->ip_v_hl) * 4 + (char *)iph);
    for (Ptr = (unsigned char *) iph; Ptr < PtrEnd; Ptr += 2) {
	memcpy(&word, Ptr, sizeof word);
        Sum += word;
    }

    Sum = (Sum & 0xFFFF) + (Sum >> 16);
    Sum = (Sum & 0xFFFF) + (Sum >> 16);

    if (Sum != 0xffff)
        return "incorrect";

    return "correct";
}

void
dissect_ip(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_ip       iph;
  proto_tree *ip_tree, *field_tree;
  proto_item *ti, *tf;
  gchar      tos_str[32];
  guint      hlen, optlen, len;
  guint16    flags;
  int        advance;
  guint8     nxt;

  /* To do: check for errs, etc. */
  if (!BYTES_ARE_IN_FRAME(offset, IPH_MIN_LEN)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* Avoids alignment problems on many architectures. */
  memcpy(&iph, &pd[offset], sizeof(e_ip));
  iph.ip_len = ntohs(iph.ip_len);
  iph.ip_id  = ntohs(iph.ip_id);
  iph.ip_off = ntohs(iph.ip_off);
  iph.ip_sum = ntohs(iph.ip_sum);

  /* Length of IP datagram plus headers above it. */
  len = iph.ip_len + offset;

  /* Set the payload and captured-payload lengths to the minima of (the
     IP length plus the length of the headers above it) and the frame
     lengths. */
  if (pi.len > len)
    pi.len = len;
  if (pi.captured_len > len)
    pi.captured_len = len;

  /* XXX - check to make sure this is at least IPH_MIN_LEN. */
  hlen = lo_nibble(iph.ip_v_hl) * 4;	/* IP header length, in bytes */
  
  switch (iph.ip_p) {
    case IP_PROTO_ICMP:
    case IP_PROTO_IGMP:
    case IP_PROTO_TCP:
    case IP_PROTO_UDP:
    case IP_PROTO_OSPF:
    case IP_PROTO_GRE:
    case IP_PROTO_ESP:
    case IP_PROTO_AH:
    case IP_PROTO_IPV6:
    case IP_PROTO_PIM:
    case IP_PROTO_VINES:
      /* Names are set in the associated dissect_* routines */
      break;
    default:
      if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "IP");
      if (check_col(fd, COL_INFO))
        col_add_fstr(fd, COL_INFO, "%s (0x%02x)",
	    ipprotostr(iph.ip_p), iph.ip_p);
  }

  if (tree) {

    switch (IPTOS_TOS(iph.ip_tos)) {
      case IPTOS_NONE:
        strcpy(tos_str, "None");
        break;
      case IPTOS_LOWCOST:
        strcpy(tos_str, "Minimize cost");
        break;
      case IPTOS_RELIABILITY:
        strcpy(tos_str, "Maximize reliability");
        break;
      case IPTOS_THROUGHPUT:
        strcpy(tos_str, "Maximize throughput");
        break;
      case IPTOS_LOWDELAY:
        strcpy(tos_str, "Minimize delay");
        break;
      case IPTOS_SECURITY:
        strcpy(tos_str, "Maximize security");
        break;
      default:
        strcpy(tos_str, "Unknown.  Malformed?");
        break;
    }

    ti = proto_tree_add_item(tree, proto_ip, offset, hlen, NULL);
    ip_tree = proto_item_add_subtree(ti, ett_ip);

    proto_tree_add_item(ip_tree, hf_ip_version, offset, 1, hi_nibble(iph.ip_v_hl));
    proto_tree_add_item_format(ip_tree, hf_ip_hdr_len, offset, 1, hlen,
	"Header length: %u bytes", hlen);
    tf = proto_tree_add_item_format(ip_tree, hf_ip_tos, offset + 1, 1, iph.ip_tos,
	"Type of service: 0x%02x (%s)", iph.ip_tos,
	val_to_str( IPTOS_TOS(iph.ip_tos), iptos_vals, "Unknown") );

    field_tree = proto_item_add_subtree(tf, ett_ip_tos);
    proto_tree_add_item(field_tree, hf_ip_tos_precedence, offset + 1, 1, iph.ip_tos);
    proto_tree_add_item(field_tree, hf_ip_tos_delay, offset + 1, 1, iph.ip_tos);
    proto_tree_add_item(field_tree, hf_ip_tos_throughput, offset + 1, 1, iph.ip_tos);
    proto_tree_add_item(field_tree, hf_ip_tos_reliability, offset + 1, 1, iph.ip_tos);
    proto_tree_add_item(field_tree, hf_ip_tos_cost, offset + 1, 1, iph.ip_tos);
    proto_tree_add_item(ip_tree, hf_ip_len, offset +  2, 2, iph.ip_len);
    proto_tree_add_item(ip_tree, hf_ip_id, offset +  4, 2, iph.ip_id);

    flags = (iph.ip_off & (IP_DF|IP_MF)) >> 12;
    tf = proto_tree_add_item(ip_tree, hf_ip_flags, offset +  6, 1, flags);
    field_tree = proto_item_add_subtree(tf, ett_ip_off);
    proto_tree_add_item(field_tree, hf_ip_flags_df, offset + 6, 1, flags),
    proto_tree_add_item(field_tree, hf_ip_flags_mf, offset + 6, 1, flags),

    proto_tree_add_item(ip_tree, hf_ip_frag_offset, offset +  6, 2,
      iph.ip_off & IP_OFFSET);
    proto_tree_add_item(ip_tree, hf_ip_ttl, offset +  8, 1, iph.ip_ttl);
    proto_tree_add_item_format(ip_tree, hf_ip_proto, offset +  9, 1, iph.ip_p,
	"Protocol: %s (0x%02x)", ipprotostr(iph.ip_p), iph.ip_p);
    proto_tree_add_item_format(ip_tree, hf_ip_checksum, offset + 10, 2, iph.ip_sum,
        "Header checksum: 0x%04x (%s)", iph.ip_sum, ip_checksum_state((e_ip*) &pd[offset]));
    proto_tree_add_item(ip_tree, hf_ip_src, offset + 12, 4, iph.ip_src);
    proto_tree_add_item(ip_tree, hf_ip_dst, offset + 16, 4, iph.ip_dst);
    proto_tree_add_item_hidden(ip_tree, hf_ip_addr, offset + 12, 4, iph.ip_src);
    proto_tree_add_item_hidden(ip_tree, hf_ip_addr, offset + 16, 4, iph.ip_dst);

    /* Decode IP options, if any. */
    if (hlen > sizeof (e_ip)) {
      /* There's more than just the fixed-length header.  Decode the
         options. */
      optlen = hlen - sizeof (e_ip);	/* length of options, in bytes */
      tf = proto_tree_add_text(ip_tree, offset +  20, optlen,
        "Options: (%d bytes)", optlen);
      field_tree = proto_item_add_subtree(tf, ett_ip_options);
      dissect_ip_tcp_options(&pd[offset + 20], offset + 20, optlen,
         ipopts, N_IP_OPTS, IPOPT_END, field_tree);
    }
  }

  pi.ipproto = iph.ip_p;
  pi.iplen = iph.ip_len;
  pi.iphdrlen = lo_nibble(iph.ip_v_hl);
  SET_ADDRESS(&pi.net_src, AT_IPv4, 4, &pd[offset + IPH_SRC]);
  SET_ADDRESS(&pi.src, AT_IPv4, 4, &pd[offset + IPH_SRC]);
  SET_ADDRESS(&pi.net_dst, AT_IPv4, 4, &pd[offset + IPH_DST]);
  SET_ADDRESS(&pi.dst, AT_IPv4, 4, &pd[offset + IPH_DST]);

  /* Skip over header + options */
  offset += hlen;
  nxt = iph.ip_p;
  if (iph.ip_off & IP_OFFSET) {
    /* fragmented */
    if (check_col(fd, COL_PROTOCOL))
      col_add_str(fd, COL_PROTOCOL, "IP");
    if (check_col(fd, COL_INFO))
      col_add_fstr(fd, COL_INFO, "Fragmented IP protocol (proto=%s 0x%02x, off=%d)",
	ipprotostr(iph.ip_p), iph.ip_p, iph.ip_off & IP_OFFSET);
    dissect_data(pd, offset, fd, tree);
    return;
  }

again:
  switch (nxt) {
    case IP_PROTO_ICMP:
      dissect_icmp(pd, offset, fd, tree);
     break;
    case IP_PROTO_IGMP:
      dissect_igmp(pd, offset, fd, tree);
     break;
    case IP_PROTO_EIGRP:
      dissect_eigrp(pd, offset, fd, tree);
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
    case IP_PROTO_VINES:
      dissect_vines_frp(pd, offset, fd, tree);
      break;
    case IP_PROTO_RSVP:
      dissect_rsvp(pd, offset, fd, tree);
      break;
    case IP_PROTO_AH:
      advance = dissect_ah(pd, offset, fd, tree);
      nxt = pd[offset];
      offset += advance;
      goto again;
    case IP_PROTO_GRE:
      dissect_gre(pd, offset, fd, tree);
      break;
    case IP_PROTO_ESP:
      dissect_esp(pd, offset, fd, tree);
      break;
    case IP_PROTO_IPV6:
      dissect_ipv6(pd, offset, fd, tree);
      break;
    case IP_PROTO_PIM:
      dissect_pim(pd, offset, fd, tree);
      break;
    case IP_PROTO_IPCOMP:
      dissect_ipcomp(pd, offset, fd, tree);
      break;
    case IP_PROTO_VRRP:
      dissect_vrrp(pd, offset, fd, tree);
      break;
    default:
      dissect_data(pd, offset, fd, tree);
      break;
  }
}


static const gchar *unreach_str[] = {"Network unreachable",
                                     "Host unreachable",
                                     "Protocol unreachable",
                                     "Port unreachable",
                                     "Fragmentation needed",
                                     "Source route failed",
                                     "Destination network unknown",
                                     "Destination host unknown",
                                     "Source host isolated",
                                     "Network administratively prohibited",
                                     "Host administratively prohibited",
                                     "Network unreachable for TOS",
                                     "Host unreachable for TOS",
                                     "Communication administratively filtered",
                                     "Host precedence violation",
                                     "Precedence cutoff in effect"};
                                     
#define	N_UNREACH	(sizeof unreach_str / sizeof unreach_str[0])

static const gchar *redir_str[] = {"Redirect for network",
                                   "Redirect for host",
                                   "Redirect for TOS and network",
                                   "Redirect for TOS and host"};

#define	N_REDIRECT	(sizeof redir_str / sizeof redir_str[0])

static const gchar *ttl_str[] = {"TTL equals 0 during transit",
                                 "TTL equals 0 during reassembly"};
                                 
#define	N_TIMXCEED	(sizeof ttl_str / sizeof ttl_str[0])

static const gchar *par_str[] = {"IP header bad", "Required option missing"};

#define	N_PARAMPROB	(sizeof par_str / sizeof par_str[0])

void
dissect_icmp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_icmp     ih;
  proto_tree *icmp_tree;
  proto_item *ti;
  guint16    cksum;
  gchar      type_str[64], code_str[64] = "";
  guint8     num_addrs = 0;
  guint8     addr_entry_size = 0;
  int        i;

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
      if (ih.icmp_code < N_UNREACH) {
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
      if (ih.icmp_code < N_REDIRECT) {
        sprintf(code_str, "(%s)", redir_str[ih.icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_ECHO:
      strcpy(type_str, "Echo (ping) request");
      break;
    case ICMP_RTRADVERT:
      strcpy(type_str, "Router advertisement");
      break;
    case ICMP_RTRSOLICIT:
      strcpy(type_str, "Router solicitation");
      break;
    case ICMP_TIMXCEED:
      strcpy(type_str, "Time-to-live exceeded");
      if (ih.icmp_code < N_TIMXCEED) {
        sprintf(code_str, "(%s)", ttl_str[ih.icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_PARAMPROB:
      strcpy(type_str, "Parameter problem");
      if (ih.icmp_code < N_PARAMPROB) {
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
    case ICMP_IREQ:
      strcpy(type_str, "Information request");
      break;
    case ICMP_IREQREPLY:
      strcpy(type_str, "Information reply");
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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "ICMP");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, type_str);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_icmp, offset, 4, NULL);
    icmp_tree = proto_item_add_subtree(ti, ett_icmp);
    proto_tree_add_item_format(icmp_tree, hf_icmp_type, offset,      1, 
			       ih.icmp_type,
			       "Type: %d (%s)",
			       ih.icmp_type, type_str);
    proto_tree_add_item_format(icmp_tree, hf_icmp_code,	offset +  1, 1, 
			       ih.icmp_code,
			       "Code: %d %s",
			       ih.icmp_code, code_str);
    proto_tree_add_item(icmp_tree, hf_icmp_checksum, offset +  2, 2, 
			cksum);

    /* Decode the second 4 bytes of the packet. */
    switch (ih.icmp_type) {
      case ICMP_ECHOREPLY:
      case ICMP_ECHO:
      case ICMP_TSTAMP:
      case ICMP_TSTAMPREPLY:
      case ICMP_IREQ:
      case ICMP_IREQREPLY:
      case ICMP_MASKREQ:
      case ICMP_MASKREPLY:
	proto_tree_add_text(icmp_tree, offset +  4, 2, "Identifier: 0x%04x",
	  pntohs(&pd[offset +  4]));
	proto_tree_add_text(icmp_tree, offset +  6, 2, "Sequence number: %u",
	  pntohs(&pd[offset +  6]));
	break;

       case ICMP_UNREACH:
         switch (ih.icmp_code) {
           case ICMP_FRAG_NEEDED:
                 proto_tree_add_text(icmp_tree, offset +  6, 2, "MTU of next hop: %u",
                   pntohs(&pd[offset + 6]));
                 break;
           }
         break;

      case ICMP_RTRADVERT:
        num_addrs = pd[offset + 4];
	proto_tree_add_text(icmp_tree, offset +  4, 1, "Number of addresses: %u",
	  num_addrs);
	addr_entry_size = pd[offset + 5];
	proto_tree_add_text(icmp_tree, offset +  5, 1, "Address entry size: %u",
	  addr_entry_size);
	proto_tree_add_text(icmp_tree, offset +  6, 2, "Lifetime: %s",
	  time_secs_to_str(pntohs(&pd[offset +  6])));
	break;

      case ICMP_PARAMPROB:
	proto_tree_add_text(icmp_tree, offset +  4, 1, "Pointer: %u",
	  pd[offset +  4]);
	break;

      case ICMP_REDIRECT:
	proto_tree_add_text(icmp_tree, offset +  4, 4, "Gateway address: %s",
	  ip_to_str((guint8 *)&pd[offset +  4]));
	break;
    }

    /* Decode the additional information in the packet.  */
    switch (ih.icmp_type) {
      case ICMP_UNREACH:
      case ICMP_TIMXCEED:
      case ICMP_PARAMPROB:
      case ICMP_SOURCEQUENCH:
      case ICMP_REDIRECT:
	/* Decode the IP header and first 64 bits of data from the
	   original datagram.

	   XXX - for now, just display it as data; not all dissection
	   routines can handle a short packet without exploding. */
	dissect_data(pd, offset + 8, fd, icmp_tree);
	break;

      case ICMP_ECHOREPLY:
      case ICMP_ECHO:
	dissect_data(pd, offset + 8, fd, icmp_tree);
	break;

      case ICMP_RTRADVERT:
        if (addr_entry_size == 2) {
	  for (i = 0; i < num_addrs; i++) {
	    proto_tree_add_text(icmp_tree, offset + 8 + (i*8), 4,
	      "Router address: %s",
	      ip_to_str((guint8 *)&pd[offset +  8 + (i*8)]));
	    proto_tree_add_text(icmp_tree, offset + 12 + (i*8), 4,
	      "Preference level: %d", pntohl(&pd[offset + 12 + (i*8)]));
	  }
	} else
	  dissect_data(pd, offset + 8, fd, icmp_tree);
	break;

      case ICMP_TSTAMP:
      case ICMP_TSTAMPREPLY:
	proto_tree_add_text(icmp_tree, offset +  8, 4, "Originate timestamp: %u",
	  pntohl(&pd[offset +  8]));
	proto_tree_add_text(icmp_tree, offset + 12, 4, "Receive timestamp: %u",
	  pntohl(&pd[offset + 12]));
	proto_tree_add_text(icmp_tree, offset + 16, 4, "Transmit timestamp: %u",
	  pntohl(&pd[offset + 16]));
	break;

    case ICMP_MASKREQ:
    case ICMP_MASKREPLY:
	proto_tree_add_text(icmp_tree, offset +  8, 4, "Address mask: %s (0x%8x)",
	  ip_to_str((guint8 *)&pd[offset +  8]), pntohl(&pd[offset +  8]));
	break;
    }
  }
}

void
dissect_igmp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_igmp     ih;
  proto_tree *igmp_tree;
  proto_item *ti;
  guint16    cksum;
  gchar      type_str[64] = "";

  /* Avoids alignment problems on many architectures. */
  memcpy(&ih, &pd[offset], sizeof(e_igmp));
  /* To do: check for runts, errs, etc. */
  cksum = ntohs(ih.igmp_cksum);
  
  switch (lo_nibble(ih.igmp_v_t)) {
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
      strcpy(type_str, "Host response (v2)");
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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "IGMP");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, type_str);
  if (tree) {
    ti = proto_tree_add_item(tree, proto_igmp, offset, 8, NULL);
    igmp_tree = proto_item_add_subtree(ti, ett_igmp);
    proto_tree_add_item(igmp_tree, hf_igmp_version, offset,     1, 
			hi_nibble(ih.igmp_v_t));
    proto_tree_add_item_format(igmp_tree, hf_igmp_type,  offset    , 1, 
			       lo_nibble(ih.igmp_v_t),
			       "Type: %d (%s)",
			       lo_nibble(ih.igmp_v_t), type_str);
    proto_tree_add_item_format(igmp_tree, hf_igmp_unused, offset + 1, 1,
			       ih.igmp_unused,
			       "Unused: 0x%02x",
			       ih.igmp_unused);
    proto_tree_add_item(igmp_tree, hf_igmp_checksum, offset + 2, 2, 
			cksum);
    proto_tree_add_item(igmp_tree, hf_igmp_group, offset + 4, 4, 
			ih.igmp_gaddr);
  }
}

void
proto_register_igmp(void)
{
	static hf_register_info hf[] = {

		{ &hf_igmp_version,
		{ "Version",		"igmp.version", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_igmp_type,
		{ "Type",		"igmp.type", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_igmp_unused,
		{ "Unused",		"igmp.unused", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_igmp_checksum,
		{ "Checksum",		"igmp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_igmp_group,
		{ "Group address",	"igmp.group", FT_IPv4, BASE_NONE, NULL, 0x0,
			"" }},
	};
	static gint *ett[] = {
		&ett_igmp,
	};

	proto_igmp = proto_register_protocol ("Internet Group Management Protocol", "igmp");
	proto_register_field_array(proto_igmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_register_ip(void)
{
	static hf_register_info hf[] = {

		{ &hf_ip_version,
		{ "Version",		"ip.version", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_ip_hdr_len,
		{ "Header Length",	"ip.hdr_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_ip_tos,
		{ "Type of Service",	"ip.tos", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_ip_tos_precedence,
		{ "Precedence",		"ip.tos.precedence", FT_UINT8, BASE_DEC, VALS(precedence_vals),
			IPTOS_PREC_MASK,
			"" }},

		{ &hf_ip_tos_delay,
		{ "Delay",		"ip.tos.delay", FT_BOOLEAN, 8, TFS(&tos_set_low),
			IPTOS_LOWDELAY,
			"" }},

		{ &hf_ip_tos_throughput,
		{ "Throughput",		"ip.tos.throughput", FT_BOOLEAN, 8, TFS(&tos_set_high),
			IPTOS_THROUGHPUT,
			"" }},

		{ &hf_ip_tos_reliability,
		{ "Reliability",	"ip.tos.reliability", FT_BOOLEAN, 8, TFS(&tos_set_high),
			IPTOS_RELIABILITY,
			"" }},

		{ &hf_ip_tos_cost,
		{ "Cost",		"ip.tos.cost", FT_BOOLEAN, 8, TFS(&tos_set_low),
			IPTOS_LOWCOST,
			"" }},

		{ &hf_ip_len,
		{ "Total Length",	"ip.len", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_ip_id,
		{ "Identification",	"ip.id", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_ip_dst,
		{ "Destination",	"ip.dst", FT_IPv4, BASE_NONE, NULL, 0x0,
			"" }},

		{ &hf_ip_src,
		{ "Source",		"ip.src", FT_IPv4, BASE_NONE, NULL, 0x0,
			"" }},

		{ &hf_ip_addr,
		{ "Source or Destination Address", "ip.addr", FT_IPv4, BASE_NONE, NULL, 0x0,
			"" }},

		{ &hf_ip_flags,
		{ "Flags",		"ip.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_ip_flags_df,
		{ "Don't fragment",	"ip.flags.df", FT_BOOLEAN, 4, TFS(&flags_set_truth), IP_DF>>12,
			"" }},

		{ &hf_ip_flags_mf,
		{ "More fragments",	"ip.flags.mf", FT_BOOLEAN, 4, TFS(&flags_set_truth), IP_MF>>12,
			"" }},

		{ &hf_ip_frag_offset,
		{ "Fragment offset",	"ip.frag_offset", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_ip_ttl,
		{ "Time to live",	"ip.ttl", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_ip_proto,
		{ "Protocol",		"ip.proto", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_ip_checksum,
		{ "Header checksum",	"ip.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},
	};
	static gint *ett[] = {
		&ett_ip,
		&ett_ip_tos,
		&ett_ip_off,
		&ett_ip_options,
		&ett_ip_option_sec,
		&ett_ip_option_route,
		&ett_ip_option_timestamp,
	};

	proto_ip = proto_register_protocol ("Internet Protocol", "ip");
	proto_register_field_array(proto_ip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_register_icmp(void)
{
  static hf_register_info hf[] = {
    
    { &hf_icmp_type,
      { "Type",		"icmp.type",		FT_UINT8, BASE_DEC,	NULL, 0x0,
      	"" }},

    { &hf_icmp_code,
      { "Code",		"icmp.code",		FT_UINT8, BASE_HEX,	NULL, 0x0,
      	"" }},    

    { &hf_icmp_checksum,
      { "Checksum",	"icmp.checksum",	FT_UINT16, BASE_HEX,	NULL, 0x0,
      	"" }},
  };
  static gint *ett[] = {
    &ett_icmp,
  };
  
  proto_icmp = proto_register_protocol ("Internet Control Message Protocol", 
					"icmp");
  proto_register_field_array(proto_icmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

static int proto_eigrp = -1;

static gint ett_eigrp = -1;

void
dissect_eigrp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_eigrp     ih;
  proto_tree *eigrp_tree;
  proto_item *ti;
  guint16    cksum;
  gchar      type_str[64] = "";

  /* Avoids alignment problems on many architectures. */
static const value_string eigrp_opcode_vals[] = {
	{ EIGRP_HELLO,		"Hello/Ack" },
	{ EIGRP_UPDATE,		"Update" },
   	{ EIGRP_REPLY, 		"Reply" },
   	{ EIGRP_QUERY, 		"Query" },
	{ EIGRP_REQUEST,	"Request" },
	{ 0,				NULL }    
};
  
   memcpy(&ih, &pd[offset], sizeof(e_eigrp));
  /* To do: check for runts, errs, etc. */
  cksum = ntohs(ih.eigrp_checksum);
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "EIGRP");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, type_str);
  if (tree) {

     ti = proto_tree_add_item(tree, proto_eigrp, offset, END_OF_FRAME, NULL);
     eigrp_tree = proto_item_add_subtree(ti, ett_eigrp);
  
     proto_tree_add_text(eigrp_tree, offset, 1, "Version: %d", ih.eigrp_version); 
     proto_tree_add_text(eigrp_tree, offset + 1, 1, "Opcode: %d (%s)", ih.eigrp_opcode,
         val_to_str( ih.eigrp_opcode, eigrp_opcode_vals, "Unknown") );
     proto_tree_add_text(eigrp_tree, offset + 2, 2, "Checksum: 0x%x", cksum); 
     proto_tree_add_text(eigrp_tree, offset + 4, 2, "Subnets in local net: %d", ih.eigrp_subnets); 
     proto_tree_add_text(eigrp_tree, offset + 6, 2, "Networks in Autonomous System: %d", ih.eigrp_networks); 
     proto_tree_add_text(eigrp_tree, offset + 8, 4, "Sequence Number: 0x%x", ih.eigrp_sequence); 
     proto_tree_add_text(eigrp_tree, offset + 12, 4, "Autonomous System number: %ld", ih.eigrp_asnumber); 
   }
}


void
proto_register_eigrp(void)
   {
      static gint *ett[] = {
        &ett_eigrp,
      };
   proto_eigrp = proto_register_protocol("Enhanced Interior Gateway Routing Protocol", "eigrp");
   proto_register_subtree_array(ett, array_length(ett));
   }
