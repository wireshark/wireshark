/* packet-ip.c
 * Routines for IP and miscellaneous IP protocol packet disassembly
 *
 * $Id: packet-ip.c,v 1.158 2002/01/21 07:36:35 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include <epan/resolv.h>
#include "ipproto.h"
#include "prefs.h"
#include "reassemble.h"
#include "etypes.h"
#include "greproto.h"
#include "ppptypes.h"
#include "llcsaps.h"
#include "aftypes.h"
#include "packet-ip.h"
#include "packet-ipsec.h"
#include "in_cksum.h"
#include "nlpid.h"

static void dissect_icmp(tvbuff_t *, packet_info *, proto_tree *);

/* Decode the old IPv4 TOS field as the DiffServ DS Field */
static gboolean g_ip_dscp_actif = TRUE;

/* Defragment fragmented IP datagrams */
static gboolean ip_defragment = FALSE;

/* Place IP summary in proto tree */
static gboolean ip_summary_in_tree = TRUE;

static int proto_ip = -1;
static int hf_ip_version = -1;
static int hf_ip_hdr_len = -1;
static int hf_ip_dsfield = -1;
static int hf_ip_dsfield_dscp = -1;
static int hf_ip_dsfield_ect = -1;
static int hf_ip_dsfield_ce = -1;
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
static int hf_ip_checksum_bad = -1;
static int hf_ip_fragments = -1;
static int hf_ip_fragment = -1;
static int hf_ip_fragment_overlap = -1;
static int hf_ip_fragment_overlap_conflict = -1;
static int hf_ip_fragment_multiple_tails = -1;
static int hf_ip_fragment_too_long_fragment = -1;
static int hf_ip_fragment_error = -1;

static gint ett_ip = -1;
static gint ett_ip_dsfield = -1;
static gint ett_ip_tos = -1;
static gint ett_ip_off = -1;
static gint ett_ip_options = -1;
static gint ett_ip_option_sec = -1;
static gint ett_ip_option_route = -1;
static gint ett_ip_option_timestamp = -1;
static gint ett_ip_fragments = -1;
static gint ett_ip_fragment  = -1;

/* Used by IPv6 as well, so not static */
dissector_table_t ip_dissector_table;

static dissector_handle_t ip_handle;
static dissector_handle_t data_handle;

static int proto_icmp = -1;
static int hf_icmp_type = -1;
static int hf_icmp_code = -1;
static int hf_icmp_checksum = -1;
static int hf_icmp_checksum_bad = -1;

/* Mobile ip */
static int hf_icmp_mip_type = -1;
static int hf_icmp_mip_length = -1;
static int hf_icmp_mip_prefix_length = -1;
static int hf_icmp_mip_seq = -1;
static int hf_icmp_mip_life = -1;
static int hf_icmp_mip_flags = -1;
static int hf_icmp_mip_r = -1;
static int hf_icmp_mip_b = -1;
static int hf_icmp_mip_h = -1;
static int hf_icmp_mip_f = -1;
static int hf_icmp_mip_m = -1;
static int hf_icmp_mip_g = -1;
static int hf_icmp_mip_v = -1;
static int hf_icmp_mip_res = -1;
static int hf_icmp_mip_reserved = -1;
static int hf_icmp_mip_coa = -1;
static int hf_icmp_mip_challenge = -1;

static gint ett_icmp = -1;
static gint ett_icmp_mip = -1;
static gint ett_icmp_mip_flags = -1;

/* ICMP definitions */

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

/* Differentiated Services Field. See RFCs 2474, 2597 and 2598. */
#define IPDSFIELD_DSCP_MASK     0xFC
#define IPDSFIELD_ECN_MASK     0x03
#define IPDSFIELD_DSCP_SHIFT	2
#define IPDSFIELD_DSCP(dsfield)	(((dsfield)&IPDSFIELD_DSCP_MASK)>>IPDSFIELD_DSCP_SHIFT)
#define IPDSFIELD_ECN(dsfield)	((dsfield)&IPDSFIELD_ECN_MASK)
#define IPDSFIELD_DSCP_DEFAULT  0x00
#define IPDSFIELD_DSCP_CS1      0x08
#define IPDSFIELD_DSCP_CS2      0x10
#define IPDSFIELD_DSCP_CS3      0x18
#define IPDSFIELD_DSCP_CS4      0x20
#define IPDSFIELD_DSCP_CS5      0x28
#define IPDSFIELD_DSCP_CS6      0x30
#define IPDSFIELD_DSCP_CS7      0x38
#define IPDSFIELD_DSCP_AF11     0x0A
#define IPDSFIELD_DSCP_AF12     0x0C
#define IPDSFIELD_DSCP_AF13     0x0E
#define IPDSFIELD_DSCP_AF21     0x12
#define IPDSFIELD_DSCP_AF22     0x14
#define IPDSFIELD_DSCP_AF23     0x16
#define IPDSFIELD_DSCP_AF31     0x1A
#define IPDSFIELD_DSCP_AF32     0x1C
#define IPDSFIELD_DSCP_AF33     0x1E
#define IPDSFIELD_DSCP_AF41     0x22
#define IPDSFIELD_DSCP_AF42     0x24
#define IPDSFIELD_DSCP_AF43     0x26
#define IPDSFIELD_DSCP_EF       0x2E
#define IPDSFIELD_ECT_MASK	0x02
#define IPDSFIELD_CE_MASK	0x01

/* IP TOS, superseded by the DS Field, RFC 2474. */
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
#define IPOLEN_RA       4

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

/*
 * defragmentation of IPv4
 */
static GHashTable *ip_fragment_table = NULL;

static void
ip_defragment_init(void)
{
  fragment_table_init(&ip_fragment_table);
}

void
capture_ip(const u_char *pd, int offset, int len, packet_counts *ld) {
  if (!BYTES_ARE_IN_FRAME(offset, len, IPH_MIN_LEN)) {
    ld->other++;
    return;
  }
  switch (pd[offset + 9]) {
    case IP_PROTO_SCTP:
      ld->sctp++;
      break;
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
      ld->vines++;
      break;
    default:
      ld->other++;
  }
}

static void
dissect_ipopt_security(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint optlen, packet_info *pinfo, proto_tree *opt_tree)
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

  tf = proto_tree_add_text(opt_tree, tvb, offset,      optlen, "%s:", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;

  val = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(field_tree, tvb, offset,       2,
              "Security: %s", val_to_str(val, secl_vals, "Unknown (0x%x)"));
  offset += 2;

  val = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(field_tree, tvb, offset,         2,
              "Compartments: %u", val);
  offset += 2;

  proto_tree_add_text(field_tree, tvb, offset,         2,
              "Handling restrictions: %c%c",
	      tvb_get_guint8(tvb, offset),
	      tvb_get_guint8(tvb, offset + 1));
  offset += 2;

  proto_tree_add_text(field_tree, tvb, offset,         3,
              "Transmission control code: %c%c%c",
	      tvb_get_guint8(tvb, offset),
	      tvb_get_guint8(tvb, offset + 1),
	      tvb_get_guint8(tvb, offset + 2));
}

static void
dissect_ipopt_route(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  proto_tree *field_tree = NULL;
  proto_item *tf;
  int ptr;
  int optoffset = 0;
  struct in_addr addr;

  tf = proto_tree_add_text(opt_tree, tvb, offset,      optlen, "%s (%u bytes)",
				optp->name, optlen);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  optoffset += 2;	/* skip past type and length */
  optlen -= 2;		/* subtract size of type and length */

  ptr = tvb_get_guint8(tvb, offset + optoffset);
  proto_tree_add_text(field_tree, tvb, offset + optoffset, 1,
              "Pointer: %d%s", ptr,
              ((ptr < 4) ? " (points before first address)" :
               ((ptr & 3) ? " (points to middle of address)" : "")));
  optoffset++;
  optlen--;
  ptr--;	/* ptr is 1-origin */

  while (optlen > 0) {
    if (optlen < 4) {
      proto_tree_add_text(field_tree, tvb, offset,      optlen,
        "(suboption would go past end of option)");
      break;
    }

    /* Avoids alignment problems on many architectures. */
    tvb_memcpy(tvb, (guint8 *)&addr, offset + optoffset, sizeof(addr));

    proto_tree_add_text(field_tree, tvb, offset + optoffset, 4,
              "%s%s",
              ((addr.s_addr == 0) ? "-" : (char *)get_hostname(addr.s_addr)),
              ((optoffset == ptr) ? " <- (current)" : ""));
    optoffset += 4;
    optlen -= 4;
  }
}

static void
dissect_ipopt_sid(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  proto_tree_add_text(opt_tree, tvb, offset,      optlen,
    "%s: %u", optp->name, tvb_get_ntohs(tvb, offset + 2));
  return;
}

static void
dissect_ipopt_timestamp(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
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

  tf = proto_tree_add_text(opt_tree, tvb, offset,      optlen, "%s:", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  optoffset += 2;	/* skip past type and length */
  optlen -= 2;		/* subtract size of type and length */

  ptr = tvb_get_guint8(tvb, offset + optoffset);
  proto_tree_add_text(field_tree, tvb, offset + optoffset, 1,
              "Pointer: %d%s", ptr,
              ((ptr < 5) ? " (points before first address)" :
               (((ptr - 1) & 3) ? " (points to middle of address)" : "")));
  optoffset++;
  optlen--;
  ptr--;	/* ptr is 1-origin */

  flg = tvb_get_guint8(tvb, offset + optoffset);
  proto_tree_add_text(field_tree, tvb, offset + optoffset,   1,
        "Overflow: %u", flg >> 4);
  flg &= 0xF;
  proto_tree_add_text(field_tree, tvb, offset + optoffset, 1,
        "Flag: %s", val_to_str(flg, flag_vals, "Unknown (0x%x)"));
  optoffset++;
  optlen--;

  while (optlen > 0) {
    if (flg == IPOPT_TS_TSANDADDR) {
      if (optlen < 8) {
        proto_tree_add_text(field_tree, tvb, offset + optoffset, optlen,
          "(suboption would go past end of option)");
        break;
      }
      tvb_memcpy(tvb, (char *)&addr, offset + optoffset, sizeof(addr));
      ts = tvb_get_ntohl(tvb, offset + optoffset + 4);
      optlen -= 8;
      proto_tree_add_text(field_tree, tvb, offset + optoffset,      8,
          "Address = %s, time stamp = %u",
          ((addr.s_addr == 0) ? "-" :  (char *)get_hostname(addr.s_addr)),
          ts);
      optoffset += 8;
    } else {
      if (optlen < 4) {
        proto_tree_add_text(field_tree, tvb, offset + optoffset, optlen,
          "(suboption would go past end of option)");
        break;
      }
      ts = tvb_get_ntohl(tvb, offset + optoffset);
      optlen -= 4;
      proto_tree_add_text(field_tree, tvb, offset + optoffset, 4,
          "Time stamp = %u", ts);
      optoffset += 4;
    }
  }
}

static void
dissect_ipopt_ra(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
		guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
  /* Router-Alert, as defined by RFC2113 */
  int opt = tvb_get_ntohs(tvb, offset + 2);
  static const value_string ra_opts[] = { 
	{0, "Every router examines packet"},
	{0, NULL}
  };
  
  proto_tree_add_text(opt_tree, tvb, offset,      optlen,
    "%s: %s", optp->name, val_to_str(opt, ra_opts, "Unknown (%d)"));
  return;
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
  },
  {
    IPOPT_RA,
    "Router Alert",
    NULL,
    FIXED_LENGTH,
    IPOLEN_RA,
    dissect_ipopt_ra
  },
};

#define N_IP_OPTS	(sizeof ipopts / sizeof ipopts[0])

/* Dissect the IP or TCP options in a packet. */
void
dissect_ip_tcp_options(tvbuff_t *tvb, int offset, guint length,
			const ip_tcp_opt *opttab, int nopts, int eol,
			packet_info *pinfo, proto_tree *opt_tree)
{
  u_char            opt;
  const ip_tcp_opt *optp;
  opt_len_type      len_type;
  unsigned int      optlen;
  char             *name;
  char              name_str[7+1+1+2+2+1+1];	/* "Unknown (0x%02x)" */
  void            (*dissect)(const struct ip_tcp_opt *, tvbuff_t *,
				int, guint, packet_info *, proto_tree *);
  guint             len;

  while (length > 0) {
    opt = tvb_get_guint8(tvb, offset);
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
        proto_tree_add_text(opt_tree, tvb, offset,      1,
              "%s (length byte past end of options)", name);
        return;
      }
      len = tvb_get_guint8(tvb, offset + 1);  /* total including type, len */
      --length;    /* account for length byte */
      if (len < 2) {
        /* Bogus - option length is too short to include option code and
           option length. */
        proto_tree_add_text(opt_tree, tvb, offset,      2,
              "%s (with too-short option length = %u byte%s)", name,
              len, plurality(len, "", "s"));
        return;
      } else if (len - 2 > length) {
        /* Bogus - option goes past the end of the header. */
        proto_tree_add_text(opt_tree, tvb, offset,      length,
              "%s (option length = %u byte%s says option goes past end of options)",
	      name, len, plurality(len, "", "s"));
        return;
      } else if (len_type == FIXED_LENGTH && len != optlen) {
        /* Bogus - option length isn't what it's supposed to be for this
           option. */
        proto_tree_add_text(opt_tree, tvb, offset,      len,
              "%s (with option length = %u byte%s; should be %u)", name,
              len, plurality(len, "", "s"), optlen);
        return;
      } else if (len_type == VARIABLE_LENGTH && len < optlen) {
        /* Bogus - option length is less than what it's supposed to be for
           this option. */
        proto_tree_add_text(opt_tree, tvb, offset,      len,
              "%s (with option length = %u byte%s; should be >= %u)", name,
              len, plurality(len, "", "s"), optlen);
        return;
      } else {
        if (optp == NULL) {
          proto_tree_add_text(opt_tree, tvb, offset,    len, "%s (%u byte%s)",
				name, len, plurality(len, "", "s"));
        } else {
          if (dissect != NULL) {
            /* Option has a dissector. */
            (*dissect)(optp, tvb, offset,          len, pinfo, opt_tree);
          } else {
            /* Option has no data, hence no dissector. */
            proto_tree_add_text(opt_tree, tvb, offset,  len, "%s", name);
          }
        }
        len -= 2;	/* subtract size of type and length */
        offset += 2 + len;
      }
      length -= len;
    } else {
      proto_tree_add_text(opt_tree, tvb, offset,      1, "%s", name);
      offset += 1;
    }
    if (opt == eol)
      break;
  }
}

const value_string dscp_vals[] = {
		  { IPDSFIELD_DSCP_DEFAULT, "Default"               },
		  { IPDSFIELD_DSCP_CS1,     "Class Selector 1"      },
		  { IPDSFIELD_DSCP_CS2,     "Class Selector 2"      },
		  { IPDSFIELD_DSCP_CS3,     "Class Selector 3"      },
		  { IPDSFIELD_DSCP_CS4,     "Class Selector 4"      },
		  { IPDSFIELD_DSCP_CS5,     "Class Selector 5"      },
		  { IPDSFIELD_DSCP_CS6,     "Class Selector 6"      },
		  { IPDSFIELD_DSCP_CS7,     "Class Selector 7"      },
		  { IPDSFIELD_DSCP_AF11,    "Assured Forwarding 11" },
		  { IPDSFIELD_DSCP_AF12,    "Assured Forwarding 12" },
		  { IPDSFIELD_DSCP_AF13,    "Assured Forwarding 13" },
		  { IPDSFIELD_DSCP_AF21,    "Assured Forwarding 21" },
		  { IPDSFIELD_DSCP_AF22,    "Assured Forwarding 22" },
		  { IPDSFIELD_DSCP_AF23,    "Assured Forwarding 23" },
		  { IPDSFIELD_DSCP_AF31,    "Assured Forwarding 31" },
		  { IPDSFIELD_DSCP_AF32,    "Assured Forwarding 32" },
		  { IPDSFIELD_DSCP_AF33,    "Assured Forwarding 33" },
		  { IPDSFIELD_DSCP_AF41,    "Assured Forwarding 41" },
		  { IPDSFIELD_DSCP_AF42,    "Assured Forwarding 42" },
		  { IPDSFIELD_DSCP_AF43,    "Assured Forwarding 43" },
		  { IPDSFIELD_DSCP_EF,      "Expedited Forwarding"  },
		  { 0,                      NULL                    } };

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

static guint16 ip_checksum(const guint8 *ptr, int len)
{
	vec_t cksum_vec[1];

	cksum_vec[0].ptr = ptr;
	cksum_vec[0].len = len;
	return in_cksum(&cksum_vec[0], 1);
}

static void
dissect_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  e_ip       iph;
  proto_tree *ip_tree = NULL, *field_tree;
  proto_item *ti, *tf;
  int        offset = 0;
  guint      hlen, optlen, len;
  guint16    flags;
  guint8     nxt;
  guint16    ipsum;
  fragment_data *ipfd_head;
  tvbuff_t   *next_tvb;
  gboolean   update_col_info = TRUE;
  gboolean   save_fragmented;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  /* Avoids alignment problems on many architectures. */
  tvb_memcpy(tvb, (guint8 *)&iph, offset, sizeof(e_ip));
  iph.ip_len = ntohs(iph.ip_len);
  iph.ip_id  = ntohs(iph.ip_id);
  iph.ip_off = ntohs(iph.ip_off);
  iph.ip_sum = ntohs(iph.ip_sum);

  /* Length of IP datagram.
     XXX - what if this is greater than the reported length of the
     tvbuff?  This could happen, for example, in an IP datagram
     inside an ICMP datagram; we need to somehow let the
     dissector we call know that, as it might want to avoid
     doing its checksumming. */
  len = iph.ip_len;

  /* Adjust the length of this tvbuff to include only the IP datagram. */
  set_actual_length(tvb, pinfo, len);

  hlen = lo_nibble(iph.ip_v_hl) * 4;	/* IP header length, in bytes */
 
  if (tree) {
    if (ip_summary_in_tree && hlen >= IPH_MIN_LEN) {
      ti = proto_tree_add_protocol_format(tree, proto_ip, tvb, offset, hlen,
		"Internet Protocol, Src Addr: %s (%s), Dst Addr: %s (%s)",
		get_hostname(iph.ip_src), ip_to_str((guint8 *) &iph.ip_src),
		get_hostname(iph.ip_dst), ip_to_str((guint8 *) &iph.ip_dst));
    } else {
      ti = proto_tree_add_item(tree, proto_ip, tvb, offset, hlen, FALSE);
    }
    ip_tree = proto_item_add_subtree(ti, ett_ip);
  }

  if (hlen < IPH_MIN_LEN) {
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus IP header length (%u, must be at least %u)",
       hlen, IPH_MIN_LEN);
    if (tree) {
      proto_tree_add_uint_format(ip_tree, hf_ip_hdr_len, tvb, offset, 1, hlen,
       "Header length: %u bytes (bogus, must be at least %u)", hlen,
       IPH_MIN_LEN);
    }
    return;
  }

  /*
   * Compute the checksum of the IP header.
   */
  ipsum = ip_checksum(tvb_get_ptr(tvb, offset, hlen), hlen);

  if (tree) {
    proto_tree_add_uint(ip_tree, hf_ip_version, tvb, offset, 1, hi_nibble(iph.ip_v_hl));
    proto_tree_add_uint_format(ip_tree, hf_ip_hdr_len, tvb, offset, 1, hlen,
	"Header length: %u bytes", hlen);

    if (g_ip_dscp_actif) {
      tf = proto_tree_add_uint_format(ip_tree, hf_ip_dsfield, tvb, offset + 1, 1, iph.ip_tos,
	   "Differentiated Services Field: 0x%02x (DSCP 0x%02x: %s; ECN: 0x%02x)", iph.ip_tos,
	   IPDSFIELD_DSCP(iph.ip_tos), val_to_str(IPDSFIELD_DSCP(iph.ip_tos), dscp_vals,
	   "Unknown DSCP"),IPDSFIELD_ECN(iph.ip_tos));

      field_tree = proto_item_add_subtree(tf, ett_ip_dsfield);
      proto_tree_add_uint(field_tree, hf_ip_dsfield_dscp, tvb, offset + 1, 1, iph.ip_tos);
      proto_tree_add_uint(field_tree, hf_ip_dsfield_ect, tvb, offset + 1, 1, iph.ip_tos);
      proto_tree_add_uint(field_tree, hf_ip_dsfield_ce, tvb, offset + 1, 1, iph.ip_tos);
    } else {
      tf = proto_tree_add_uint_format(ip_tree, hf_ip_tos, tvb, offset + 1, 1, iph.ip_tos,
	  "Type of service: 0x%02x (%s)", iph.ip_tos,
	  val_to_str( IPTOS_TOS(iph.ip_tos), iptos_vals, "Unknown") );

      field_tree = proto_item_add_subtree(tf, ett_ip_tos);
      proto_tree_add_uint(field_tree, hf_ip_tos_precedence, tvb, offset + 1, 1, iph.ip_tos);
      proto_tree_add_boolean(field_tree, hf_ip_tos_delay, tvb, offset + 1, 1, iph.ip_tos);
      proto_tree_add_boolean(field_tree, hf_ip_tos_throughput, tvb, offset + 1, 1, iph.ip_tos);
      proto_tree_add_boolean(field_tree, hf_ip_tos_reliability, tvb, offset + 1, 1, iph.ip_tos);
      proto_tree_add_boolean(field_tree, hf_ip_tos_cost, tvb, offset + 1, 1, iph.ip_tos);
    }
    proto_tree_add_uint(ip_tree, hf_ip_len, tvb, offset +  2, 2, iph.ip_len);
    proto_tree_add_uint(ip_tree, hf_ip_id, tvb, offset +  4, 2, iph.ip_id);

    flags = (iph.ip_off & (IP_DF|IP_MF)) >> 12;
    tf = proto_tree_add_uint(ip_tree, hf_ip_flags, tvb, offset +  6, 1, flags);
    field_tree = proto_item_add_subtree(tf, ett_ip_off);
    proto_tree_add_boolean(field_tree, hf_ip_flags_df, tvb, offset + 6, 1, flags),
    proto_tree_add_boolean(field_tree, hf_ip_flags_mf, tvb, offset + 6, 1, flags),

    proto_tree_add_uint(ip_tree, hf_ip_frag_offset, tvb, offset +  6, 2,
      (iph.ip_off & IP_OFFSET)*8);

    proto_tree_add_uint(ip_tree, hf_ip_ttl, tvb, offset +  8, 1, iph.ip_ttl);
    proto_tree_add_uint_format(ip_tree, hf_ip_proto, tvb, offset +  9, 1, iph.ip_p,
	"Protocol: %s (0x%02x)", ipprotostr(iph.ip_p), iph.ip_p);

    if (ipsum == 0) {
	proto_tree_add_uint_format(ip_tree, hf_ip_checksum, tvb, offset + 10, 2, iph.ip_sum,
              "Header checksum: 0x%04x (correct)", iph.ip_sum);
    }
    else {
	proto_tree_add_item_hidden(ip_tree, hf_ip_checksum_bad, tvb, offset + 10, 2, TRUE);
	proto_tree_add_uint_format(ip_tree, hf_ip_checksum, tvb, offset + 10, 2, iph.ip_sum,
          "Header checksum: 0x%04x (incorrect, should be 0x%04x)", iph.ip_sum,
	  in_cksum_shouldbe(iph.ip_sum, ipsum));
    }

    proto_tree_add_ipv4(ip_tree, hf_ip_src, tvb, offset + 12, 4, iph.ip_src);
    proto_tree_add_ipv4(ip_tree, hf_ip_dst, tvb, offset + 16, 4, iph.ip_dst);
    proto_tree_add_ipv4_hidden(ip_tree, hf_ip_addr, tvb, offset + 12, 4, iph.ip_src);
    proto_tree_add_ipv4_hidden(ip_tree, hf_ip_addr, tvb, offset + 16, 4, iph.ip_dst);

    /* Decode IP options, if any. */
    if (hlen > sizeof (e_ip)) {
      /* There's more than just the fixed-length header.  Decode the
         options. */
      optlen = hlen - sizeof (e_ip);	/* length of options, in bytes */
      tf = proto_tree_add_text(ip_tree, tvb, offset +  20, optlen,
        "Options: (%u bytes)", optlen);
      field_tree = proto_item_add_subtree(tf, ett_ip_options);
      dissect_ip_tcp_options(tvb, offset + 20, optlen,
         ipopts, N_IP_OPTS, IPOPT_END, pinfo, field_tree);
    }
  }

  pinfo->ipproto = iph.ip_p;

  pinfo->iplen = iph.ip_len;

  pinfo->iphdrlen = lo_nibble(iph.ip_v_hl);

  SET_ADDRESS(&pinfo->net_src, AT_IPv4, 4, tvb_get_ptr(tvb, offset + IPH_SRC, 4));
  SET_ADDRESS(&pinfo->src, AT_IPv4, 4, tvb_get_ptr(tvb, offset + IPH_SRC, 4));
  SET_ADDRESS(&pinfo->net_dst, AT_IPv4, 4, tvb_get_ptr(tvb, offset + IPH_DST, 4));
  SET_ADDRESS(&pinfo->dst, AT_IPv4, 4, tvb_get_ptr(tvb, offset + IPH_DST, 4));

  /* Skip over header + options */
  offset += hlen;
  nxt = iph.ip_p;	/* XXX - what if this isn't the same for all fragments? */

  /* If ip_defragment is on, this is a fragment, we have all the data
   * in the fragment, and the header checksum is valid, then just add
   * the fragment to the hashtable.
   */
  save_fragmented = pinfo->fragmented;
  if (ip_defragment && (iph.ip_off & (IP_MF|IP_OFFSET)) &&
	tvb_reported_length(tvb) <= tvb_length(tvb) && ipsum == 0) {
    ipfd_head = fragment_add(tvb, offset, pinfo, iph.ip_id,
			     ip_fragment_table,
			     (iph.ip_off & IP_OFFSET)*8,
			     pinfo->iplen - (pinfo->iphdrlen*4),
			     iph.ip_off & IP_MF);

    if (ipfd_head != NULL) {
      fragment_data *ipfd;
      proto_tree *ft=NULL;
      proto_item *fi=NULL;

      /* OK, we have the complete reassembled payload. */
      /* show all fragments */
      fi = proto_tree_add_item(ip_tree, hf_ip_fragments, 
                tvb, 0, 0, FALSE);
      ft = proto_item_add_subtree(fi, ett_ip_fragments);
      for (ipfd=ipfd_head->next; ipfd; ipfd=ipfd->next){
        if (ipfd->flags & (FD_OVERLAP|FD_OVERLAPCONFLICT
                          |FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
          /* this fragment has some flags set, create a subtree 
           * for it and display the flags.
           */
          proto_tree *fet=NULL;
          proto_item *fei=NULL;
          int hf;

          if (ipfd->flags & (FD_OVERLAPCONFLICT
                      |FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
            hf = hf_ip_fragment_error;
          } else {
            hf = hf_ip_fragment;
          }
          fei = proto_tree_add_none_format(ft, hf, 
                   tvb, 0, 0,
                   "Frame:%u payload:%u-%u",
                   ipfd->frame,
                   ipfd->offset,
                   ipfd->offset+ipfd->len-1
          );
          fet = proto_item_add_subtree(fei, ett_ip_fragment);
          if (ipfd->flags&FD_OVERLAP) {
            proto_tree_add_boolean(fet, 
                 hf_ip_fragment_overlap, tvb, 0, 0, 
                 TRUE);
          }
          if (ipfd->flags&FD_OVERLAPCONFLICT) {
            proto_tree_add_boolean(fet, 
                 hf_ip_fragment_overlap_conflict, tvb, 0, 0, 
                 TRUE);
          }
          if (ipfd->flags&FD_MULTIPLETAILS) {
            proto_tree_add_boolean(fet, 
                 hf_ip_fragment_multiple_tails, tvb, 0, 0, 
                 TRUE);
          }
          if (ipfd->flags&FD_TOOLONGFRAGMENT) {
            proto_tree_add_boolean(fet, 
                 hf_ip_fragment_too_long_fragment, tvb, 0, 0, 
                 TRUE);
          }
        } else {
          /* nothing of interest for this fragment */
          proto_tree_add_none_format(ft, hf_ip_fragment, 
                   tvb, 0, 0,
                   "Frame:%u payload:%u-%u",
                   ipfd->frame,
                   ipfd->offset,
                   ipfd->offset+ipfd->len-1
          );
        }
      }
      if (ipfd_head->flags & (FD_OVERLAPCONFLICT
                        |FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
        if (check_col(pinfo->cinfo, COL_INFO)) {
          col_set_str(pinfo->cinfo, COL_INFO, "[Illegal fragments]");
          update_col_info = FALSE;
        }
      }

      /* Allocate a new tvbuff, referring to the reassembled payload. */
      next_tvb = tvb_new_real_data(ipfd_head->data, ipfd_head->datalen,
	ipfd_head->datalen, "Reassembled");

      /* Add the tvbuff to the list of tvbuffs to which the tvbuff we
         were handed refers, so it'll get cleaned up when that tvbuff
         is cleaned up. */
      tvb_set_child_real_data_tvbuff(tvb, next_tvb);

      /* Add the defragmented data to the data source list. */
      pinfo->fd->data_src = g_slist_append(pinfo->fd->data_src, next_tvb);

      /* It's not fragmented. */
      pinfo->fragmented = FALSE;
    } else {
      /* We don't have the complete reassembled payload. */
      next_tvb = NULL;
    }
  } else {
    /* If this is the first fragment, dissect its contents, otherwise
       just show it as a fragment.

       XXX - if we eventually don't save the reassembled contents of all
       fragmented datagrams, we may want to always reassemble. */
    if (iph.ip_off & IP_OFFSET) {
      /* Not the first fragment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First fragment, or not fragmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset(tvb, offset, -1, -1);

      /*
       * If this is the first fragment, but not the only fragment,
       * tell the next protocol that.
       */
      if (iph.ip_off & IP_MF)
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as a fragment. */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "Fragmented IP protocol (proto=%s 0x%02x, off=%u)",
	ipprotostr(iph.ip_p), iph.ip_p, (iph.ip_off & IP_OFFSET) * 8);
    call_dissector(data_handle,tvb_new_subset(tvb, offset,-1,tvb_reported_length_remaining(tvb,offset)), pinfo, tree);
    pinfo->fragmented = save_fragmented;
    return;
  }

  /* Hand off to the next protocol.

     XXX - setting the columns only after trying various dissectors means
     that if one of those dissectors throws an exception, the frame won't
     even be labelled as an IP frame; ideally, if a frame being dissected
     throws an exception, it'll be labelled as a mangled frame of the
     type in question. */
  if (!dissector_try_port(ip_dissector_table, nxt, next_tvb, pinfo, tree)) {
    /* Unknown protocol */
    if (update_col_info) {
      if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%02x)", ipprotostr(iph.ip_p), iph.ip_p);
    }
    call_dissector(data_handle,next_tvb, pinfo, tree);
  }
  pinfo->fragmented = save_fragmented;
}

#define ICMP_MIP_EXTENSION_PAD	0
#define ICMP_MIP_MOB_AGENT_ADV	16
#define ICMP_MIP_PREFIX_LENGTHS	19
#define ICMP_MIP_CHALLENGE	24

static value_string mip_extensions[] = {
  { ICMP_MIP_EXTENSION_PAD, "One byte padding extension"},  /* RFC 2002 */
  { ICMP_MIP_MOB_AGENT_ADV, "Mobility Agent Advertisement Extension"},
							    /* RFC 2002 */
  { ICMP_MIP_PREFIX_LENGTHS, "Prefix Lengths Extension"},   /* RFC 2002 */
  { ICMP_MIP_CHALLENGE, "Challenge Extension"},             /* RFC 3012 */
  { 0, NULL}
};

/*
 * Dissect the mobile ip advertisement extensions.
 */
static void
dissect_mip_extensions(tvbuff_t *tvb, size_t offset, packet_info *pinfo,
					   proto_tree *tree)
{
  guint8       type;
  guint8       length;
  guint8       flags;
  proto_item   *ti;
  proto_tree   *mip_tree=NULL;
  proto_tree   *flags_tree=NULL;
  gint         numCOAs;
  gint         i;

  /* Not much to do if we're not parsing everything */
  if (!tree) return;
  
  while ((tvb_length(tvb) - offset) > 0) {

	type = tvb_get_guint8(tvb, offset + 0);
	if (type)
	  length = tvb_get_guint8(tvb, offset + 1);
	else
	  length=0;

	ti = proto_tree_add_text(tree, tvb, offset,
							 type?(length + 2):1,
							 "Ext: %s",
							 val_to_str(type, mip_extensions,
										"Unknown ext %u"));
	mip_tree = proto_item_add_subtree(ti, ett_icmp_mip);
  

	switch (type) {
	case ICMP_MIP_EXTENSION_PAD:
	  /* One byte padding extension */
	  /* Add our fields */
	  /* type */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_type, tvb, offset, 
						  1, FALSE);
	  offset++;
	  break;
	case ICMP_MIP_MOB_AGENT_ADV:
	  /* Mobility Agent Advertisement Extension (RFC 2002)*/
	  /* Add our fields */
	  /* type */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_type, tvb, offset, 
						  1, FALSE);
	  offset++;
	  /* length */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_length, tvb, offset, 
						  1, FALSE);
	  offset++;
	  /* sequence number */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_seq, tvb, offset, 
						  2, FALSE);
	  offset+=2;
	  /* Registration Lifetime */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_life, tvb, offset, 
						  2, FALSE);
	  offset+=2;
	  /* flags */
	  flags = tvb_get_guint8(tvb, offset);
	  ti = proto_tree_add_item(mip_tree, hf_icmp_mip_flags, tvb, offset,
							   1, FALSE);
	  flags_tree = proto_item_add_subtree(ti, ett_icmp_mip_flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_r, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_b, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_h, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_f, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_m, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_g, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_v, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_res, tvb, offset, 1, flags);
	  offset++;
	  
	  /* Reserved */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_reserved, tvb, offset, 
						  1, FALSE);
	  offset++;
	  
	  /* COAs */
	  numCOAs = (length - 6) / 4;
	  for (i=0; i<numCOAs; i++) {
		proto_tree_add_item(mip_tree, hf_icmp_mip_coa, tvb, offset, 
							4, FALSE);
		offset+=4;
	  }
	  break;
	case ICMP_MIP_PREFIX_LENGTHS:
	  /* Prefix-Lengths Extension  (RFC 2002)*/
	  /* Add our fields */
	  /* type */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_type, tvb, offset, 
						  1, FALSE);
	  offset++;
	  /* length */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_length, tvb, offset, 
						  1, FALSE);
	  offset++;

	  /* prefix lengths */
	  for(i=0; i<length; i++) {
		proto_tree_add_item(mip_tree, hf_icmp_mip_prefix_length, tvb, offset,
							1, FALSE);
		offset++;
	  }
	  break;
	case ICMP_MIP_CHALLENGE:
	  /* Challenge Extension  (RFC 3012)*/
	  /* type */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_type, tvb, offset, 
						  1, FALSE);
	  offset++;
	  /* length */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_length, tvb, offset, 
						  1, FALSE);
	  offset++;
	  /* challenge */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_challenge, tvb, offset, 
						  length, FALSE);
	  offset+=length;
	  
	  break;
	default:
	  g_warning("Unknown type(%u)!  I hope the length is right (%u)",
				type, length);
	  offset += length;
	  break;
	} /* switch type */
  } /* end while */
  
} /* dissect_mip_extensions */

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

/*
 * RFC 792 for basic ICMP.
 * RFC 1191 for ICMP_FRAG_NEEDED (with MTU of next hop).
 * RFC 1256 for router discovery messages.
 * RFC 2002 and 3012 for Mobile IP stuff.
 */
static void
dissect_icmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *icmp_tree;
  proto_item *ti;
  guint8     icmp_type;
  guint8     icmp_code;
  guint      length, reported_length;
  guint16    cksum, computed_cksum;
  gchar      type_str[64], code_str[64] = "";
  guint8     num_addrs = 0;
  guint8     addr_entry_size = 0;
  int        i;
  address    save_dl_src;
  address    save_dl_dst;
  address    save_net_src;
  address    save_net_dst;
  address    save_src;
  address    save_dst;
  gboolean   save_in_error_pkt;
  tvbuff_t   *next_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICMP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  /* To do: check for runts, errs, etc. */
  icmp_type = tvb_get_guint8(tvb, 0);
  icmp_code = tvb_get_guint8(tvb, 1);
  cksum = tvb_get_ntohs(tvb, 2);

  switch (icmp_type) {
    case ICMP_ECHOREPLY:
      strcpy(type_str, "Echo (ping) reply");
      break;
    case ICMP_UNREACH:
      strcpy(type_str, "Destination unreachable");
      if (icmp_code < N_UNREACH) {
        sprintf(code_str, "(%s)", unreach_str[icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_SOURCEQUENCH:
      strcpy(type_str, "Source quench (flow control)");
      break;
    case ICMP_REDIRECT:
      strcpy(type_str, "Redirect");
      if (icmp_code < N_REDIRECT) {
        sprintf(code_str, "(%s)", redir_str[icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_ECHO:
      strcpy(type_str, "Echo (ping) request");
      break;
    case ICMP_RTRADVERT:
      switch (icmp_code) {
      case 16: /* Mobile-Ip */
        strcpy(type_str, "Mobile IP Advertisement");
        break;
      default:
        strcpy(type_str, "Router advertisement");
        break;
      } /* switch icmp_code */
      break;
    case ICMP_RTRSOLICIT:
      strcpy(type_str, "Router solicitation");
      break;
    case ICMP_TIMXCEED:
      strcpy(type_str, "Time-to-live exceeded");
      if (icmp_code < N_TIMXCEED) {
        sprintf(code_str, "(%s)", ttl_str[icmp_code]);
      } else {
        strcpy(code_str, "(Unknown - error?)");
      }
      break;
    case ICMP_PARAMPROB:
      strcpy(type_str, "Parameter problem");
      if (icmp_code < N_PARAMPROB) {
        sprintf(code_str, "(%s)", par_str[icmp_code]);
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
      break;
  }

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, type_str);

  if (tree) {
    length = tvb_length(tvb);
    reported_length = tvb_reported_length(tvb);
    ti = proto_tree_add_item(tree, proto_icmp, tvb, 0, length, FALSE);
    icmp_tree = proto_item_add_subtree(ti, ett_icmp);
    proto_tree_add_uint_format(icmp_tree, hf_icmp_type, tvb, 0, 1, 
			       icmp_type,
			       "Type: %u (%s)",
			       icmp_type, type_str);
    proto_tree_add_uint_format(icmp_tree, hf_icmp_code, tvb, 1, 1, 
			       icmp_code,
			       "Code: %u %s",
			       icmp_code, code_str);

    if (!pinfo->fragmented && length >= reported_length) {
      /* The packet isn't part of a fragmented datagram and isn't
         truncated, so we can checksum it. */

      computed_cksum = ip_checksum(tvb_get_ptr(tvb, 0, reported_length),
	  			     reported_length);
      if (computed_cksum == 0) {
        proto_tree_add_uint_format(icmp_tree, hf_icmp_checksum, tvb, 2, 2,
 			  cksum,
			  "Checksum: 0x%04x (correct)", cksum);
      } else {
        proto_tree_add_item_hidden(icmp_tree, hf_icmp_checksum_bad,
			  tvb, 2, 2, TRUE);
        proto_tree_add_uint_format(icmp_tree, hf_icmp_checksum, tvb, 2, 2,
		  cksum,
		  "Checksum: 0x%04x (incorrect, should be 0x%04x)",
		  cksum, in_cksum_shouldbe(cksum, computed_cksum));
      }
    } else {
      proto_tree_add_uint(icmp_tree, hf_icmp_checksum, tvb, 2, 2, cksum);
    }

    /* Decode the second 4 bytes of the packet. */
    switch (icmp_type) {
      case ICMP_ECHOREPLY:
      case ICMP_ECHO:
      case ICMP_TSTAMP:
      case ICMP_TSTAMPREPLY:
      case ICMP_IREQ:
      case ICMP_IREQREPLY:
      case ICMP_MASKREQ:
      case ICMP_MASKREPLY:
	proto_tree_add_text(icmp_tree, tvb, 4, 2, "Identifier: 0x%04x",
	  tvb_get_ntohs(tvb, 4));
	proto_tree_add_text(icmp_tree, tvb, 6, 2, "Sequence number: %02x:%02x",
	  tvb_get_guint8(tvb, 6), tvb_get_guint8(tvb, 7));
	break;

      case ICMP_UNREACH:
        switch (icmp_code) {
          case ICMP_FRAG_NEEDED:
            proto_tree_add_text(icmp_tree, tvb, 6, 2, "MTU of next hop: %u",
                  tvb_get_ntohs(tvb, 6));
            break;
	}
        break;

      case ICMP_RTRADVERT:
        num_addrs = tvb_get_guint8(tvb, 4);
	proto_tree_add_text(icmp_tree, tvb, 4, 1, "Number of addresses: %u",
	  num_addrs);
	addr_entry_size = tvb_get_guint8(tvb, 5);
	proto_tree_add_text(icmp_tree, tvb, 5, 1, "Address entry size: %u",
	  addr_entry_size);
	proto_tree_add_text(icmp_tree, tvb, 6, 2, "Lifetime: %s",
	  time_secs_to_str(tvb_get_ntohs(tvb, 6)));
	break;

      case ICMP_PARAMPROB:
	proto_tree_add_text(icmp_tree, tvb, 4, 1, "Pointer: %u",
	  tvb_get_guint8(tvb, 4));
	break;

      case ICMP_REDIRECT:
	proto_tree_add_text(icmp_tree, tvb, 4, 4, "Gateway address: %s",
	  ip_to_str(tvb_get_ptr(tvb, 4, 4)));
	break;
    }

    /* Decode the additional information in the packet.  */
    switch (icmp_type) {
      case ICMP_UNREACH:
      case ICMP_TIMXCEED:
      case ICMP_PARAMPROB:
      case ICMP_SOURCEQUENCH:
      case ICMP_REDIRECT:
	/* Decode the IP header and first 64 bits of data from the
	   original datagram.

	   Set the columns non-writable, so that the packet list
	   shows this as an ICMP packet, not as the type of packet
	   for which the ICMP packet was generated. */
	col_set_writable(pinfo->cinfo, FALSE);

	/* Also, save the current values of the addresses, and restore
	   them when we're finished dissecting the contained packet, so
	   that the address columns in the summary don't reflect the
	   contained packet, but reflect this packet instead. */
	save_dl_src = pinfo->dl_src;
	save_dl_dst = pinfo->dl_dst;
	save_net_src = pinfo->net_src;
	save_net_dst = pinfo->net_dst;
	save_src = pinfo->src;
	save_dst = pinfo->dst;

	/* Save the current value of the "we're inside an error packet"
	   flag, and set that flag; subdissectors may treat packets
	   that are the payload of error packets differently from
	   "real" packets. */
	save_in_error_pkt = pinfo->in_error_pkt;
	pinfo->in_error_pkt = TRUE;

	/* Dissect the contained packet.
	   Catch ReportedBoundsError, and do nothing if we see it,
	   because it's not an error if the contained packet is short;
	   there's no guarantee that all of it was included.

	   XXX - should catch BoundsError, and re-throw it after cleaning
	   up. */
	next_tvb = tvb_new_subset(tvb, 8, -1, -1);
	TRY {
	  call_dissector(ip_handle, next_tvb, pinfo, icmp_tree);
	}
	CATCH(ReportedBoundsError) {
	  ; /* do nothing */
	}
	ENDTRY;

	/* Restore the "we're inside an error packet" flag. */
	pinfo->in_error_pkt = save_in_error_pkt;

	/* Restore the addresses. */
	pinfo->dl_src = save_dl_src;
	pinfo->dl_dst = save_dl_dst;
	pinfo->net_src = save_net_src;
	pinfo->net_dst = save_net_dst;
	pinfo->src = save_src;
	pinfo->dst = save_dst;
	break;

      case ICMP_ECHOREPLY:
      case ICMP_ECHO:
	call_dissector(data_handle,tvb_new_subset(tvb, 8,-1,tvb_reported_length_remaining(tvb,8)), pinfo, icmp_tree);
	break;

      case ICMP_RTRADVERT:
        if (addr_entry_size == 2) {
	  for (i = 0; i < num_addrs; i++) {
	    proto_tree_add_text(icmp_tree, tvb, 8 + (i*8), 4,
	      "Router address: %s",
	      ip_to_str(tvb_get_ptr(tvb, 8 + (i*8), 4)));
	    proto_tree_add_text(icmp_tree, tvb, 12 + (i*8), 4,
	      "Preference level: %d", tvb_get_ntohl(tvb, 12 + (i*8)));
	  }
	  if (icmp_code == 16) {
		/* Mobile-Ip */
		dissect_mip_extensions(tvb,8 + i*8, pinfo, icmp_tree);
	  }
	} else
	  call_dissector(data_handle,tvb_new_subset(tvb, 8,-1,tvb_reported_length_remaining(tvb,8)), pinfo, icmp_tree);
	break;

      case ICMP_TSTAMP:
      case ICMP_TSTAMPREPLY:
	proto_tree_add_text(icmp_tree, tvb, 8, 4, "Originate timestamp: %u",
	  tvb_get_ntohl(tvb, 8));
	proto_tree_add_text(icmp_tree, tvb, 12, 4, "Receive timestamp: %u",
	  tvb_get_ntohl(tvb, 12));
	proto_tree_add_text(icmp_tree, tvb, 16, 4, "Transmit timestamp: %u",
	  tvb_get_ntohl(tvb, 16));
	break;

    case ICMP_MASKREQ:
    case ICMP_MASKREPLY:
	proto_tree_add_text(icmp_tree, tvb, 8, 4, "Address mask: %s (0x%08x)",
	  ip_to_str(tvb_get_ptr(tvb, 8, 4)), tvb_get_ntohl(tvb, 8));
	break;
    }
  }
}

void
proto_register_ip(void)
{
	static hf_register_info hf[] = {

		{ &hf_ip_version,
		{ "Version",		"ip.version", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_hdr_len,
		{ "Header Length",	"ip.hdr_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_dsfield,
		{ "Differentiated Services field",	"ip.dsfield", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_dsfield_dscp,
		{ "Differentiated Services Codepoint",	"ip.dsfield.dscp", FT_UINT8, BASE_HEX,
			VALS(dscp_vals), IPDSFIELD_DSCP_MASK,
			"", HFILL }},

		{ &hf_ip_dsfield_ect,
		{ "ECN-Capable Transport (ECT)",	"ip.dsfield.ect", FT_UINT8, BASE_DEC, NULL,
			IPDSFIELD_ECT_MASK,
			"", HFILL }},

		{ &hf_ip_dsfield_ce,
		{ "ECN-CE",	"ip.dsfield.ce", FT_UINT8, BASE_DEC, NULL,
			IPDSFIELD_CE_MASK,
			"", HFILL }},

		{ &hf_ip_tos,
		{ "Type of Service",	"ip.tos", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_tos_precedence,
		{ "Precedence",		"ip.tos.precedence", FT_UINT8, BASE_DEC, VALS(precedence_vals),
			IPTOS_PREC_MASK,
			"", HFILL }},

		{ &hf_ip_tos_delay,
		{ "Delay",		"ip.tos.delay", FT_BOOLEAN, 8, TFS(&tos_set_low),
			IPTOS_LOWDELAY,
			"", HFILL }},

		{ &hf_ip_tos_throughput,
		{ "Throughput",		"ip.tos.throughput", FT_BOOLEAN, 8, TFS(&tos_set_high),
			IPTOS_THROUGHPUT,
			"", HFILL }},

		{ &hf_ip_tos_reliability,
		{ "Reliability",	"ip.tos.reliability", FT_BOOLEAN, 8, TFS(&tos_set_high),
			IPTOS_RELIABILITY,
			"", HFILL }},

		{ &hf_ip_tos_cost,
		{ "Cost",		"ip.tos.cost", FT_BOOLEAN, 8, TFS(&tos_set_low),
			IPTOS_LOWCOST,
			"", HFILL }},

		{ &hf_ip_len,
		{ "Total Length",	"ip.len", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_id,
		{ "Identification",	"ip.id", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_dst,
		{ "Destination",	"ip.dst", FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_src,
		{ "Source",		"ip.src", FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_addr,
		{ "Source or Destination Address", "ip.addr", FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_flags,
		{ "Flags",		"ip.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_flags_df,
		{ "Don't fragment",	"ip.flags.df", FT_BOOLEAN, 4, TFS(&flags_set_truth), IP_DF>>12,
			"", HFILL }},

		{ &hf_ip_flags_mf,
		{ "More fragments",	"ip.flags.mf", FT_BOOLEAN, 4, TFS(&flags_set_truth), IP_MF>>12,
			"", HFILL }},

		{ &hf_ip_frag_offset,
		{ "Fragment offset",	"ip.frag_offset", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_ttl,
		{ "Time to live",	"ip.ttl", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_proto,
		{ "Protocol",		"ip.proto", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_checksum,
		{ "Header checksum",	"ip.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_checksum_bad,
		{ "Bad Header checksum",	"ip.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_ip_fragment_overlap,
		{ "Fragment overlap",	"ip.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Fragment overlaps with other fragments", HFILL }},

		{ &hf_ip_fragment_overlap_conflict,
		{ "Conflicting data in fragment overlap",	"ip.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Overlapping fragments contained conflicting data", HFILL }},

		{ &hf_ip_fragment_multiple_tails,
		{ "Multiple tail fragments found",	"ip.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Several tails were found when defragmenting the packet", HFILL }},

		{ &hf_ip_fragment_too_long_fragment,
		{ "Fragment too long",	"ip.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Fragment contained data past end of packet", HFILL }},

		{ &hf_ip_fragment_error,
		{ "Defragmentation error", "ip.fragment.error", FT_NONE, BASE_NONE, NULL, 0x0,
			"Defragmentation error due to illegal fragments", HFILL }},

		{ &hf_ip_fragment,
		{ "IP Fragment", "ip.fragment", FT_NONE, BASE_NONE, NULL, 0x0,
			"IP Fragment", HFILL }},

		{ &hf_ip_fragments,
		{ "IP Fragments", "ip.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
			"IP Fragments", HFILL }},
	};
	static gint *ett[] = {
		&ett_ip,
		&ett_ip_dsfield,
		&ett_ip_tos,
		&ett_ip_off,
		&ett_ip_options,
		&ett_ip_option_sec,
		&ett_ip_option_route,
		&ett_ip_option_timestamp,
		&ett_ip_fragments,
		&ett_ip_fragment,
	};
	module_t *ip_module;

	proto_ip = proto_register_protocol("Internet Protocol", "IP", "ip");
	proto_register_field_array(proto_ip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	ip_dissector_table = register_dissector_table("ip.proto",
	    "IP protocol", FT_UINT8, BASE_DEC);

	/* Register configuration options */
	ip_module = prefs_register_protocol(proto_ip, NULL);
	prefs_register_bool_preference(ip_module, "decode_tos_as_diffserv",
	    "Decode IPv4 TOS field as DiffServ field",
	    "Whether the IPv4 type-of-service field should be decoded as a Differentiated Services field",
	    &g_ip_dscp_actif);
	prefs_register_bool_preference(ip_module, "defragment",
		"Reassemble fragmented IP datagrams",
		"Whether fragmented IP datagrams should be reassembled",
		&ip_defragment);
	prefs_register_bool_preference(ip_module, "ip_summary_in_tree",
	    "Show IP summary in protocol tree",
	    "Whether the IP summary line should be shown in the protocol tree",
	    &ip_summary_in_tree);

	register_dissector("ip", dissect_ip, proto_ip);
	register_init_routine(ip_defragment_init);
}

void
proto_reg_handoff_ip(void)
{
	dissector_handle_t ip_handle;

        data_handle = find_dissector("data");
        ip_handle = find_dissector("ip");
	dissector_add("ethertype", ETHERTYPE_IP, ip_handle);
	dissector_add("ppp.protocol", PPP_IP, ip_handle);
	dissector_add("ppp.protocol", ETHERTYPE_IP, ip_handle);
	dissector_add("gre.proto", ETHERTYPE_IP, ip_handle);
	dissector_add("gre.proto", GRE_WCCP, ip_handle);
	dissector_add("llc.dsap", SAP_IP, ip_handle);
	dissector_add("ip.proto", IP_PROTO_IPIP, ip_handle);
	dissector_add("null.type", BSD_AF_INET, ip_handle);
	dissector_add("chdlctype", ETHERTYPE_IP, ip_handle);
	dissector_add("fr.ietf", NLPID_IP, ip_handle);
	dissector_add("x.25.spi", NLPID_IP, ip_handle);
}

void
proto_register_icmp(void)
{
  static hf_register_info hf[] = {
    
    { &hf_icmp_type,
      { "Type",		"icmp.type",		FT_UINT8, BASE_DEC,	NULL, 0x0,
      	"", HFILL }},

    { &hf_icmp_code,
      { "Code",		"icmp.code",		FT_UINT8, BASE_HEX,	NULL, 0x0,
      	"", HFILL }},    

    { &hf_icmp_checksum,
      { "Checksum",	"icmp.checksum",	FT_UINT16, BASE_HEX,	NULL, 0x0,
      	"", HFILL }},

    { &hf_icmp_checksum_bad,
      { "Bad Checksum",	"icmp.checksum_bad",	FT_BOOLEAN, BASE_NONE,	NULL, 0x0,
	"", HFILL }},

    { &hf_icmp_mip_type,
      { "Extension Type", "icmp.mip.type",	FT_UINT8, BASE_DEC,
	VALS(mip_extensions), 0x0,"", HFILL}},

    { &hf_icmp_mip_length,
      { "Length", "icmp.mip.length",		FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL}},

    { &hf_icmp_mip_prefix_length,
      { "Prefix Length", "icmp.mip.prefixlength",  FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL}},

    { &hf_icmp_mip_seq,
      { "Sequence Number", "icmp.mip.seq",	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL}},

    { &hf_icmp_mip_life,
      { "Registration Lifetime", "icmp.mip.life",  FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL}},

    { &hf_icmp_mip_flags,
      { "Flags", "icmp.mip.flags",            FT_UINT8, BASE_HEX, NULL, 0x0,
	"", HFILL}},

    { &hf_icmp_mip_r,
      { "Registration Required", "icmp.mip.r", FT_BOOLEAN, 8, NULL, 128,
	"Registration with this FA is required", HFILL }},

    { &hf_icmp_mip_b,
      { "Busy", "icmp.mip.b", FT_BOOLEAN, 8, NULL, 64,
	"This FA will not accept requests at this time", HFILL }},

    { &hf_icmp_mip_h,
      { "Home Agent", "icmp.mip.h", FT_BOOLEAN, 8, NULL, 32,
	"Home Agent Services Offered", HFILL }},

    { &hf_icmp_mip_f,
      { "Foreign Agent", "icmp.mip.f", FT_BOOLEAN, 8, NULL, 16,
	"Foreign Agent Services Offered", HFILL }},

    { &hf_icmp_mip_m,
      { "Minimal Encapsulation", "icmp.mip.m", FT_BOOLEAN, 8, NULL, 8,
	"Minimal encapsulation tunneled datagram support", HFILL }},

    { &hf_icmp_mip_g,
      { "GRE", "icmp.mip.g", FT_BOOLEAN, 8, NULL, 4,
	"GRE encapsulated tunneled datagram support", HFILL }},

    { &hf_icmp_mip_v,
      { "VJ Comp", "icmp.mip.v", FT_BOOLEAN, 8, NULL, 2,
	"Van Jacobson Header Compression Support", HFILL }},

    { &hf_icmp_mip_res,
      { "Reserved", "icmp.mip.res", FT_BOOLEAN, 8, NULL, 1,
	"Reserved", HFILL }},

    { &hf_icmp_mip_reserved,
      { "Reserved", "icmp.mip.reserved",     FT_UINT8, BASE_HEX, NULL, 0x0,
	"", HFILL}},

    { &hf_icmp_mip_coa,
      { "Care-Of-Address", "icmp.mip.coa",    FT_IPv4, BASE_NONE, NULL, 0x0,
	"", HFILL}},

    { &hf_icmp_mip_challenge,
      { "Challenge", "icmp.mip.challenge",    FT_BYTES, BASE_NONE, NULL, 0x0,
	"", HFILL}},
  };
  static gint *ett[] = {
    &ett_icmp,
	&ett_icmp_mip,
	&ett_icmp_mip_flags
  };
  
  proto_icmp = proto_register_protocol("Internet Control Message Protocol", 
				       "ICMP", "icmp");
  proto_register_field_array(proto_icmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_icmp(void)
{
  dissector_handle_t icmp_handle;

  /*
   * Get handle for the IP dissector.
   */
  ip_handle = find_dissector("ip");

  icmp_handle = create_dissector_handle(dissect_icmp, proto_icmp);
  dissector_add("ip.proto", IP_PROTO_ICMP, icmp_handle);
}
