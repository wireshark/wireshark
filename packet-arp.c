/* packet-arp.c
 * Routines for ARP packet disassembly
 *
 * $Id: packet-arp.c,v 1.24 1999/11/27 04:48:12 guy Exp $
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

#include <glib.h>
#include "packet.h"
#include "packet-arp.h"
#include "etypes.h"

static int proto_arp = -1;
static int hf_arp_hard_type = -1;
static int hf_arp_proto_type = -1;
static int hf_arp_hard_size = -1;
static int hf_atmarp_shtl = -1;
static int hf_atmarp_ssl = -1;
static int hf_arp_proto_size = -1;
static int hf_arp_opcode = -1;
static int hf_atmarp_spln = -1;
static int hf_atmarp_thtl = -1;
static int hf_atmarp_tsl = -1;
static int hf_atmarp_tpln = -1;
static int hf_arp_src_ether = -1;
static int hf_arp_src_proto = -1;
static int hf_arp_dst_ether = -1;
static int hf_arp_dst_proto = -1;
static int hf_atmarp_src_atm_num_e164 = -1;
static int hf_atmarp_src_atm_num_nsap = -1;
static int hf_atmarp_src_atm_subaddr = -1;
static int hf_atmarp_dst_atm_num_e164 = -1;
static int hf_atmarp_dst_atm_num_nsap = -1;
static int hf_atmarp_dst_atm_subaddr = -1;

static gint ett_arp = -1;
static gint ett_atmarp_nsap = -1;

/* Definitions taken from Linux "linux/if_arp.h" header file, and from

	http://www.isi.edu/in-notes/iana/assignments/arp-parameters

 */

/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM	0		/* from KA9Q: NET/ROM pseudo	*/
#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/
#define	ARPHRD_EETHER	2		/* Experimental Ethernet	*/
#define	ARPHRD_AX25	3		/* AX.25 Level 2		*/
#define	ARPHRD_PRONET	4		/* PROnet token ring		*/
#define	ARPHRD_CHAOS	5		/* Chaosnet			*/
#define	ARPHRD_IEEE802	6		/* IEEE 802.2 Ethernet/TR/TB	*/
#define	ARPHRD_ARCNET	7		/* ARCnet			*/
#define	ARPHRD_HYPERCH	8		/* Hyperchannel			*/
#define	ARPHRD_LANSTAR	9		/* Lanstar			*/
#define	ARPHRD_AUTONET	10		/* Autonet Short Address	*/
#define	ARPHRD_LOCALTLK	11		/* Localtalk			*/
#define	ARPHRD_LOCALNET	12		/* LocalNet (IBM PCNet/Sytek LocalNET) */
#define	ARPHRD_ULTRALNK	13		/* Ultra link			*/
#define	ARPHRD_SMDS	14		/* SMDS				*/
#define ARPHRD_DLCI	15		/* Frame Relay DLCI		*/
#define ARPHRD_ATM	16		/* ATM				*/
#define ARPHRD_HDLC	17		/* HDLC				*/
#define ARPHRD_FIBREC	18		/* Fibre Channel		*/
#define ARPHRD_ATM2225	19		/* ATM (RFC 2225)		*/
#define ARPHRD_SERIAL	20		/* Serial Line			*/
#define ARPHRD_ATM2	21		/* ATM				*/
#define ARPHRD_MS188220	22		/* MIL-STD-188-220		*/
#define ARPHRD_METRICOM	23		/* Metricom STRIP		*/
#define ARPHRD_IEEE1394	24		/* IEEE 1394.1995		*/
#define ARPHRD_MAPOS	25		/* MAPOS			*/
#define ARPHRD_TWINAX	26		/* Twinaxial			*/
#define ARPHRD_EUI_64	27		/* EUI-64			*/

/* ARP / RARP structs and definitions */
#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST  1       /* ARP request.  */
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY    2       /* ARP reply.  */
#endif
/* Some OSes have different names, or don't define these at all */
#ifndef ARPOP_RREQUEST
#define ARPOP_RREQUEST 3       /* RARP request.  */
#endif
#ifndef ARPOP_RREPLY
#define ARPOP_RREPLY   4       /* RARP reply.  */
#endif
#ifndef ARPOP_IREQUEST
#define ARPOP_IREQUEST 8       /* Inverse ARP (RFC 1293) request.  */
#endif
#ifndef ARPOP_IREPLY
#define ARPOP_IREPLY   9       /* Inverse ARP reply.  */
#endif
#ifndef ATMARPOP_NAK
#define ATMARPOP_NAK   10      /* ATMARP NAK.  */
#endif

static const value_string op_vals[] = {
  {ARPOP_REQUEST,  "ARP request" },
  {ARPOP_REPLY,    "ARP reply"   },
  {ARPOP_RREQUEST, "RARP request"},
  {ARPOP_RREPLY,   "RARP reply"  },
  {ARPOP_IREQUEST, "Inverse ARP request"},
  {ARPOP_IREPLY,   "Inverse ARP reply"  },
  {0,              NULL          } };

static const value_string atmop_vals[] = {
  {ARPOP_REQUEST,  "ATMARP request" },
  {ARPOP_REPLY,    "ATMARP reply"   },
  {ARPOP_IREQUEST, "Inverse ATMARP request"},
  {ARPOP_IREPLY,   "Inverse ATMARP reply"  },
  {ATMARPOP_NAK,   "ATMARP NAK"  },
  {0,              NULL          } };

#define	ATMARP_IS_E164	0x40	/* bit in shtl/thtl for E.164 format */
#define	ATMARP_LEN_MASK	0x3F	/* length of address in shtl/thtl */

gchar *
arphrdaddr_to_str(guint8 *ad, int ad_len, guint16 type)
{
  if (ad_len == 0)
    return "<No address>";
  if ((type == ARPHRD_ETHER || type == ARPHRD_EETHER || type == ARPHRD_IEEE802)
  				&& ad_len == 6) {
    /* Ethernet address (or Experimental 3Mb Ethernet, or IEEE 802.x
       address, which are the same type of address). */
    return ether_to_str(ad);
  }
  return bytes_to_str(ad, ad_len);
}

static gchar *
arpproaddr_to_str(guint8 *ad, int ad_len, guint16 type)
{
  if (ad_len == 0)
    return "<No address>";
  if (type == ETHERTYPE_IP && ad_len == 4) {
    /* IPv4 address.  */
    return ip_to_str(ad);
  }
  return bytes_to_str(ad, ad_len);
}

#define	N_ATMARPNUM_TO_STR_STRINGS	2
#define	MAX_E164_STR_LEN		20
static gchar *
atmarpnum_to_str(guint8 *ad, int ad_tl)
{
  int           ad_len = ad_tl & ATMARP_LEN_MASK;
  static gchar  str[N_ATMARPNUM_TO_STR_STRINGS][MAX_E164_STR_LEN+3+1];
  static int    cur_idx;
  gchar        *cur;

  if (ad_len == 0)
    return "<No address>";

  if (ad_tl & ATMARP_IS_E164) {
    /*
     * I'm assuming this means it's an ASCII (IA5) string.
     */
    cur_idx++;
    if (cur_idx >= N_ATMARPNUM_TO_STR_STRINGS)
      cur_idx = 0;
    cur = &str[cur_idx][0];
    if (ad_len > MAX_E164_STR_LEN) {
      /* Can't show it all. */
      memcpy(cur, ad, MAX_E164_STR_LEN);
      strcpy(&cur[MAX_E164_STR_LEN], "...");
    } else {
      memcpy(cur, ad, ad_len);
      cur[ad_len + 1] = '\0';
    }
    return cur;
  } else {
    /*
     * NSAP.
     *
     * XXX - break down into subcomponents.
     */
    return bytes_to_str(ad, ad_len);
  }
}

static gchar *
atmarpsubaddr_to_str(guint8 *ad, int ad_len)
{
  if (ad_len == 0)
    return "<No address>";

  /*
   * XXX - break down into subcomponents?
   */
  return bytes_to_str(ad, ad_len);
}

static const value_string hrd_vals[] = {
  {ARPHRD_NETROM,   "NET/ROM pseudo"       },
  {ARPHRD_ETHER,    "Ethernet"             },
  {ARPHRD_EETHER,   "Experimental Ethernet"},
  {ARPHRD_AX25,     "AX.25"                },
  {ARPHRD_PRONET,   "ProNET"               },
  {ARPHRD_CHAOS,    "Chaos"                },
  {ARPHRD_IEEE802,  "IEEE 802"             },
  {ARPHRD_ARCNET,   "ARCNET"               },
  {ARPHRD_HYPERCH,  "Hyperchannel"         },
  {ARPHRD_LANSTAR,  "Lanstar"              },
  {ARPHRD_AUTONET,  "Autonet Short Address"},
  {ARPHRD_LOCALTLK, "Localtalk"            },
  {ARPHRD_LOCALNET, "LocalNet"             },
  {ARPHRD_ULTRALNK, "Ultra link"           },
  {ARPHRD_SMDS,     "SMDS"                 },
  {ARPHRD_DLCI,     "Frame Relay DLCI"     },
  {ARPHRD_ATM,      "ATM"                  },
  {ARPHRD_HDLC,     "HDLC"                 },
  {ARPHRD_FIBREC,   "Fibre Channel"        },
  {ARPHRD_ATM2225,  "ATM (RFC 2225)"       },
  {ARPHRD_SERIAL,   "Serial Line"          },
  {ARPHRD_ATM2,     "ATM"                  },
  {ARPHRD_MS188220, "MIL-STD-188-220"      },
  {ARPHRD_METRICOM, "Metricom STRIP"       },
  {ARPHRD_IEEE1394, "IEEE 1394.1995"       },
  {ARPHRD_MAPOS,    "MAPOS"                },
  {ARPHRD_TWINAX,   "Twinaxial"            },
  {ARPHRD_EUI_64,   "EUI-64"               },
  {0,                NULL                  } };

gchar *
arphrdtype_to_str(guint16 hwtype, const char *fmt) {
    return val_to_str(hwtype, hrd_vals, fmt);
}

/* Offsets of fields within an ARP packet. */
#define	AR_HRD		0
#define	AR_PRO		2
#define	AR_HLN		4
#define	AR_PLN		5
#define	AR_OP		6
#define MIN_ARP_HEADER_SIZE	8

/* Offsets of fields within an ATMARP packet. */
#define	ATM_AR_HRD	0
#define	ATM_AR_PRO	2
#define	ATM_AR_SHTL	4
#define	ATM_AR_SSL	5
#define	ATM_AR_OP	6
#define	ATM_AR_SPLN	8
#define	ATM_AR_THTL	9
#define	ATM_AR_TSL	10
#define	ATM_AR_TPLN	11
#define MIN_ATMARP_HEADER_SIZE	12

static void
dissect_atm_number(const u_char *pd, int offset, int tl, int hf_e164,
    int hf_nsap, proto_tree *tree)
{
	int len = tl & ATMARP_LEN_MASK;
	proto_item *ti;
	proto_tree *nsap_tree;

	if (tl & ATMARP_IS_E164)
		proto_tree_add_item(tree, hf_e164, offset, len, &pd[offset]);
	else {
		ti = proto_tree_add_item(tree, hf_nsap, offset, len,
		    &pd[offset]);
		if (len >= 20) {
			nsap_tree = proto_item_add_subtree(ti, ett_atmarp_nsap);
			dissect_atm_nsap(pd, offset, len, nsap_tree);
		}
	}
}

void
dissect_atm_nsap(const u_char *pd, int offset, int len, proto_tree *tree)
{
	switch (pd[offset]) {

	case 0x39:	/* DCC ATM format */
	case 0xBD:	/* DCC ATM group format */
		proto_tree_add_text(tree, offset + 0, 3,
		    "Data Country Code%s: 0x%04X",
		    (pd[offset] == 0xBD) ? " (group)" : "",
		    pntohs(&pd[offset + 1]));
		proto_tree_add_text(tree, offset + 3, 10,
		    "High Order DSP: %s",
		    bytes_to_str(&pd[offset + 3], 10));
		proto_tree_add_text(tree, offset + 13, 6,
		    "End System Identifier: %s",
		    bytes_to_str(&pd[offset + 13], 6));
		proto_tree_add_text(tree, offset + 19, 1,
		    "Selector: 0x%02X", pd[offset + 19]);
		break;

	case 0x47:	/* ICD ATM format */
	case 0xC5:	/* ICD ATM group format */
		proto_tree_add_text(tree, offset + 0, 3,
		    "International Code Designator%s: 0x%04X",
		    (pd[offset] == 0xC5) ? " (group)" : "",
		    pntohs(&pd[offset + 1]));
		proto_tree_add_text(tree, offset + 3, 10,
		    "High Order DSP: %s",
		    bytes_to_str(&pd[offset + 3], 10));
		proto_tree_add_text(tree, offset + 13, 6,
		    "End System Identifier: %s",
		    bytes_to_str(&pd[offset + 13], 6));
		proto_tree_add_text(tree, offset + 19, 1,
		    "Selector: 0x%02X", pd[offset + 19]);
		break;

	case 0x45:	/* E.164 ATM format */
	case 0xC3:	/* E.164 ATM group format */
		proto_tree_add_text(tree, offset + 0, 9,
		    "E.164 ISDN%s: %s",
		    (pd[offset] == 0xC3) ? " (group)" : "",
		    bytes_to_str(&pd[offset + 1], 8));
		proto_tree_add_text(tree, offset + 9, 4,
		    "High Order DSP: %s",
		    bytes_to_str(&pd[offset + 3], 10));
		proto_tree_add_text(tree, offset + 13, 6,
		    "End System Identifier: %s",
		    bytes_to_str(&pd[offset + 13], 6));
		proto_tree_add_text(tree, offset + 19, 1,
		    "Selector: 0x%02X", pd[offset + 19]);
		break;

	default:
		proto_tree_add_text(tree, offset, 1,
		    "Unknown AFI: 0x%02X", pd[offset]);
		proto_tree_add_text(tree, offset + 1, len - 1,
		    "Rest of address: %s",
		    bytes_to_str(&pd[offset + 1], len - 1));
		break;
	}
}

/*
 * RFC 2225 ATMARP - it's just like ARP, except where it isn't.
 */
static void
dissect_atmarp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
  guint16     ar_hrd;
  guint16     ar_pro;
  guint8      ar_shtl;
  guint8      ar_sht;
  guint8      ar_shl;
  guint8      ar_ssl;
  guint16     ar_op;
  guint8      ar_spln;
  guint8      ar_thtl;
  guint8      ar_tht;
  guint8      ar_thl;
  guint8      ar_tsl;
  guint8      ar_tpln;
  int         tot_len;
  proto_tree  *arp_tree;
  proto_item  *ti;
  gchar       *op_str;
  int         sha_offset, ssa_offset, spa_offset;
  int         tha_offset, tsa_offset, tpa_offset;
  gchar       *sha_str, *ssa_str, *spa_str;
  gchar       *tha_str, *tsa_str, *tpa_str;

  if (!BYTES_ARE_IN_FRAME(offset, MIN_ATMARP_HEADER_SIZE)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  ar_hrd = pntohs(&pd[offset + ATM_AR_HRD]);
  ar_pro = pntohs(&pd[offset + ATM_AR_PRO]);
  ar_shtl = (guint8) pd[offset + ATM_AR_SHTL];
  ar_sht = ar_shtl & ATMARP_IS_E164;
  ar_shl = ar_shtl & ATMARP_LEN_MASK;
  ar_ssl = (guint8) pd[offset + ATM_AR_SSL];
  ar_op  = pntohs(&pd[offset + AR_OP]);
  ar_spln = (guint8) pd[offset + ATM_AR_SPLN];
  ar_thtl = (guint8) pd[offset + ATM_AR_THTL];
  ar_tht = ar_thtl & ATMARP_IS_E164;
  ar_thl = ar_thtl & ATMARP_LEN_MASK;
  ar_tsl = (guint8) pd[offset + ATM_AR_TSL];
  ar_tpln = (guint8) pd[offset + ATM_AR_TPLN];

  tot_len = MIN_ATMARP_HEADER_SIZE + ar_shtl + ar_ssl + ar_spln +
				ar_thtl + ar_tsl + ar_tpln;
  if (!BYTES_ARE_IN_FRAME(offset, tot_len)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* Extract the addresses.  */
  sha_offset = offset + MIN_ATMARP_HEADER_SIZE;
  if (ar_shl != 0)
    sha_str = atmarpnum_to_str((guint8 *) &pd[sha_offset], ar_shtl);
  else
    sha_str = "<No address>";
  ssa_offset = sha_offset + ar_shl;
  if (ar_ssl != 0)
    ssa_str = atmarpsubaddr_to_str((guint8 *) &pd[ssa_offset], ar_ssl);
  else
    ssa_str = NULL;
  spa_offset = ssa_offset + ar_ssl;
  spa_str = arpproaddr_to_str((guint8 *) &pd[spa_offset], ar_spln, ar_pro);
  tha_offset = spa_offset + ar_spln;
  if (ar_thl != 0)
    tha_str = atmarpnum_to_str((guint8 *) &pd[tha_offset], ar_thtl);
  else
    tha_str = "<No address>";
  tsa_offset = tha_offset + ar_thl;
  if (ar_tsl != 0)
    tsa_str = atmarpsubaddr_to_str((guint8 *) &pd[tsa_offset], ar_tsl);
  else
    tsa_str = NULL;
  tpa_offset = tsa_offset + ar_tsl;
  tpa_str = arpproaddr_to_str((guint8 *) &pd[tpa_offset], ar_tpln, ar_pro);
  
  if (check_col(fd, COL_PROTOCOL)) {
    switch (ar_op) {

    case ARPOP_REQUEST:
    case ARPOP_REPLY:
    case ATMARPOP_NAK:
    default:
      col_add_str(fd, COL_PROTOCOL, "ATMARP");
      break;

    case ARPOP_RREQUEST:
    case ARPOP_RREPLY:
      col_add_str(fd, COL_PROTOCOL, "ATMRARP");
      break;

    case ARPOP_IREQUEST:
    case ARPOP_IREPLY:
      col_add_str(fd, COL_PROTOCOL, "Inverse ATMARP");
      break;
    }
  }

  if (check_col(fd, COL_INFO)) {
    switch (ar_op) {
      case ARPOP_REQUEST:
        col_add_fstr(fd, COL_INFO, "Who has %s?  Tell %s", tpa_str, spa_str);
        break;
      case ARPOP_REPLY:
        col_add_fstr(fd, COL_INFO, "%s is at %s%s%s", spa_str, sha_str,
		((ssa_str != NULL) ? "," : ""),
		((ssa_str != NULL) ? ssa_str : ""));
        break;
      case ARPOP_IREQUEST:
        col_add_fstr(fd, COL_INFO, "Who is %s%s%s?  Tell %s%s%s", tha_str,
		((tsa_str != NULL) ? "," : ""),
		((tsa_str != NULL) ? tsa_str : ""),
		sha_str,
		((ssa_str != NULL) ? "," : ""),
		((ssa_str != NULL) ? ssa_str : ""));
        break;
      case ARPOP_IREPLY:
        col_add_fstr(fd, COL_INFO, "%s%s%s is at %s", sha_str,
		((ssa_str != NULL) ? "," : ""),
		((ssa_str != NULL) ? ssa_str : ""),
		spa_str);
        break;
      case ATMARPOP_NAK:
        col_add_fstr(fd, COL_INFO, "I don't know where %s is", spa_str);
        break;
      default:
        col_add_fstr(fd, COL_INFO, "Unknown ATMARP opcode 0x%04x", ar_op);
        break;
    }
  }

  if (tree) {
    if ((op_str = match_strval(ar_op, atmop_vals)))
      ti = proto_tree_add_item_format(tree, proto_arp, offset, tot_len,
				      NULL, op_str);
    else
      ti = proto_tree_add_item_format(tree, proto_arp, offset, tot_len,
				      NULL,
				      "Unknown ATMARP (opcode 0x%04x)", ar_op);
    arp_tree = proto_item_add_subtree(ti, ett_arp);
    proto_tree_add_item(arp_tree, hf_arp_hard_type, offset + ATM_AR_HRD, 2,
			       ar_hrd);
    proto_tree_add_item(arp_tree, hf_arp_proto_type, offset + ATM_AR_PRO, 2,
			       ar_pro);
    proto_tree_add_item(arp_tree, hf_atmarp_shtl, offset + ATM_AR_SHTL, 1,
			       ar_shtl);
    proto_tree_add_item(arp_tree, hf_atmarp_ssl, offset + ATM_AR_SSL, 1,
			       ar_ssl);
    proto_tree_add_item(arp_tree, hf_arp_opcode, offset + AR_OP,  2,
			       ar_op);
    proto_tree_add_item(arp_tree, hf_atmarp_spln, offset + ATM_AR_SPLN, 1,
			       ar_spln);
    proto_tree_add_item(arp_tree, hf_atmarp_thtl, offset + ATM_AR_THTL, 1,
			       ar_thtl);
    proto_tree_add_item(arp_tree, hf_atmarp_tsl, offset + ATM_AR_TSL, 1,
			       ar_tsl);
    proto_tree_add_item(arp_tree, hf_atmarp_tpln, offset + ATM_AR_TPLN, 1,
			       ar_tpln);
    if (ar_shl != 0)
      dissect_atm_number(pd, sha_offset, ar_shtl, hf_atmarp_src_atm_num_e164,
			       hf_atmarp_src_atm_num_nsap, arp_tree);
    if (ar_ssl != 0)
      proto_tree_add_item_format(arp_tree, hf_atmarp_src_atm_subaddr, ssa_offset,
			       ar_ssl,
			       &pd[ssa_offset],
			       "Sender ATM subaddress: %s", ssa_str);
    if (ar_spln != 0)
      proto_tree_add_item_format(arp_tree, hf_arp_src_proto, spa_offset, ar_spln,
			       &pd[spa_offset],
			       "Sender protocol address: %s", spa_str);
    if (ar_thl != 0)
      dissect_atm_number(pd, tha_offset, ar_thtl, hf_atmarp_dst_atm_num_e164,
			       hf_atmarp_dst_atm_num_nsap, arp_tree);
    if (ar_tsl != 0)
      proto_tree_add_item_format(arp_tree, hf_atmarp_dst_atm_subaddr, tsa_offset,
			       ar_tsl,
			       &pd[tsa_offset],
			       "Target ATM subaddress: %s", tsa_str);
    if (ar_tpln != 0)
      proto_tree_add_item_format(arp_tree, hf_arp_dst_proto, tpa_offset, ar_tpln,
			       &pd[tpa_offset],
			       "Target protocol address: %s", tpa_str);
  }
}

void
dissect_arp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
  guint16     ar_hrd;
  guint16     ar_pro;
  guint8      ar_hln;
  guint8      ar_pln;
  guint16     ar_op;
  int         tot_len;
  proto_tree  *arp_tree;
  proto_item  *ti;
  gchar       *op_str;
  int         sha_offset, spa_offset, tha_offset, tpa_offset;
  gchar       *sha_str, *spa_str, *tha_str, *tpa_str;

  if (!BYTES_ARE_IN_FRAME(offset, MIN_ARP_HEADER_SIZE)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  ar_hrd = pntohs(&pd[offset + AR_HRD]);
  if (ar_hrd == ARPHRD_ATM2225) {
    dissect_atmarp(pd, offset, fd, tree);
    return;
  }
  ar_pro = pntohs(&pd[offset + AR_PRO]);
  ar_hln = (guint8) pd[offset + AR_HLN];
  ar_pln = (guint8) pd[offset + AR_PLN];
  ar_op  = pntohs(&pd[offset + AR_OP]);

  tot_len = MIN_ARP_HEADER_SIZE + ar_hln*2 + ar_pln*2;
  if (!BYTES_ARE_IN_FRAME(offset, tot_len)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* Extract the addresses.  */
  sha_offset = offset + MIN_ARP_HEADER_SIZE;
  sha_str = arphrdaddr_to_str((guint8 *) &pd[sha_offset], ar_hln, ar_hrd);
  spa_offset = sha_offset + ar_hln;
  spa_str = arpproaddr_to_str((guint8 *) &pd[spa_offset], ar_pln, ar_pro);
  tha_offset = spa_offset + ar_pln;
  tha_str = arphrdaddr_to_str((guint8 *) &pd[tha_offset], ar_hln, ar_hrd);
  tpa_offset = tha_offset + ar_hln;
  tpa_str = arpproaddr_to_str((guint8 *) &pd[tpa_offset], ar_pln, ar_pro);
  
  if (check_col(fd, COL_PROTOCOL)) {
    switch (ar_op) {

    case ARPOP_REQUEST:
    case ARPOP_REPLY:
    default:
      col_add_str(fd, COL_PROTOCOL, "ARP");
      break;

    case ARPOP_RREQUEST:
    case ARPOP_RREPLY:
      col_add_str(fd, COL_PROTOCOL, "RARP");
      break;

    case ARPOP_IREQUEST:
    case ARPOP_IREPLY:
      col_add_str(fd, COL_PROTOCOL, "Inverse ARP");
      break;
    }
  }

  if (check_col(fd, COL_INFO)) {
    switch (ar_op) {
      case ARPOP_REQUEST:
        col_add_fstr(fd, COL_INFO, "Who has %s?  Tell %s", tpa_str, spa_str);
        break;
      case ARPOP_REPLY:
        col_add_fstr(fd, COL_INFO, "%s is at %s", spa_str, sha_str);
        break;
      case ARPOP_RREQUEST:
      case ARPOP_IREQUEST:
        col_add_fstr(fd, COL_INFO, "Who is %s?  Tell %s", tha_str, sha_str);
        break;
      case ARPOP_RREPLY:
      case ARPOP_IREPLY:
        col_add_fstr(fd, COL_INFO, "%s is at %s", sha_str, spa_str);
        break;
      default:
        col_add_fstr(fd, COL_INFO, "Unknown ARP opcode 0x%04x", ar_op);
        break;
    }
  }

  if (tree) {
    if ((op_str = match_strval(ar_op, op_vals)))
      ti = proto_tree_add_item_format(tree, proto_arp, offset, tot_len,
				      NULL, op_str);
    else
      ti = proto_tree_add_item_format(tree, proto_arp, offset, tot_len,
				      NULL,
				      "Unknown ARP (opcode 0x%04x)", ar_op);
    arp_tree = proto_item_add_subtree(ti, ett_arp);
    proto_tree_add_item(arp_tree, hf_arp_hard_type, offset + AR_HRD, 2,
			       ar_hrd);
    proto_tree_add_item(arp_tree, hf_arp_proto_type, offset + AR_PRO, 2,
			       ar_pro);
    proto_tree_add_item(arp_tree, hf_arp_hard_size, offset + AR_HLN, 1,
			       ar_hln);
    proto_tree_add_item(arp_tree, hf_arp_proto_size, offset + AR_PLN, 1,
			       ar_pln);
    proto_tree_add_item(arp_tree, hf_arp_opcode, offset + AR_OP,  2,
			       ar_op);
    if (ar_hln != 0)
      proto_tree_add_item_format(arp_tree, hf_arp_src_ether, sha_offset, ar_hln,
			       &pd[sha_offset],
			       "Sender hardware address: %s", sha_str);
    if (ar_pln != 0)
      proto_tree_add_item_format(arp_tree, hf_arp_src_proto, spa_offset, ar_pln,
			       &pd[spa_offset],
			       "Sender protocol address: %s", spa_str);
    if (ar_hln != 0)
      proto_tree_add_item_format(arp_tree, hf_arp_dst_ether, tha_offset, ar_hln,
			       &pd[tha_offset],
			       "Target hardware address: %s", tha_str);
    if (ar_pln != 0)
      proto_tree_add_item_format(arp_tree, hf_arp_dst_proto, tpa_offset, ar_pln,
			       &pd[tpa_offset],
			       "Target protocol address: %s", tpa_str);
  }
}

void
proto_register_arp(void)
{
  static hf_register_info hf[] = {
    { &hf_arp_hard_type,
      { "Hardware type",		"arp.hw.type",	 
	FT_UINT16,	BASE_HEX,	VALS(hrd_vals),	0x0,
      	"" }},

    { &hf_arp_proto_type,
      { "Protocol type",		"arp.proto.type",
	FT_UINT16,	BASE_HEX,	VALS(etype_vals),	0x0,
      	"" }},

    { &hf_arp_hard_size,
      { "Hardware size",		"arp.hw.size",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_shtl,
      { "Sender ATM number type and length",	"arp.src.htl",	
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_ssl,
      { "Sender ATM subaddress length",	"arp.src.slen",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},

    { &hf_arp_proto_size,
      { "Protocol size",		"arp.proto.size",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},

    { &hf_arp_opcode,
      { "Opcode",			"arp.opcode",
	FT_UINT16,	BASE_HEX,	VALS(op_vals),	0x0,
      	"" }},

    { &hf_atmarp_spln,
      { "Sender protocol size",		"arp.src.pln",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_thtl,
      { "Target ATM number type and length",	"arp.dst.htl",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_tsl,
      { "Target ATM subaddress length",	"arp.dst.slen",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_tpln,
      { "Target protocol size",		"arp.dst.pln",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"" }},

    { &hf_arp_src_ether,
      { "Sender hardware address",	"arp.src.hw",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_src_atm_num_e164,
      { "Sender ATM number (E.164)",	"arp.src.atm_num_e164",
	FT_STRING,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_src_atm_num_nsap,
      { "Sender ATM number (NSAP)",	"arp.src.atm_num_nsap",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_src_atm_subaddr,
      { "Sender ATM subaddress",	"arp.src.atm_subaddr",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_arp_src_proto,
      { "Sender protocol address",	"arp.src.proto", 
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_arp_dst_ether,
      { "Target hardware address",	"arp.dst.hw",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_dst_atm_num_e164,
      { "Target ATM number (E.164)",	"arp.dst.atm_num_e164",
	FT_STRING,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_dst_atm_num_nsap,
      { "Target ATM number (NSAP)",	"arp.dst.atm_num_nsap",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_atmarp_dst_atm_subaddr,
      { "Target ATM subaddress",	"arp.dst.atm_subaddr",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"" }},

    { &hf_arp_dst_proto,
      { "Target protocol address",	"arp.dst.proto", 
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      "" }}
  };
  static gint *ett[] = {
    &ett_arp,
    &ett_atmarp_nsap,
  };

  proto_arp = proto_register_protocol("Address Resolution Protocol", "arp");
  proto_register_field_array(proto_arp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}
