/* packet-arp.c
 * Routines for ARP packet disassembly
 *
 * $Id: packet-arp.c,v 1.44 2001/06/18 02:17:44 guy Exp $
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

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "strutil.h"
#include "resolv.h"
#include "packet-arp.h"
#include "etypes.h"

static int proto_arp = -1;
static int hf_arp_hard_type = -1;
static int hf_arp_proto_type = -1;
static int hf_arp_hard_size = -1;
static int hf_atmarp_sht = -1;
static int hf_atmarp_shl = -1;
static int hf_atmarp_sst = -1;
static int hf_atmarp_ssl = -1;
static int hf_arp_proto_size = -1;
static int hf_arp_opcode = -1;
static int hf_atmarp_spln = -1;
static int hf_atmarp_tht = -1;
static int hf_atmarp_thl = -1;
static int hf_atmarp_tst = -1;
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
static gint ett_atmarp_tl = -1;

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
  {ARPOP_REQUEST,  "request" },
  {ARPOP_REPLY,    "reply"   },
  {ARPOP_RREQUEST, "reverse request"},
  {ARPOP_RREPLY,   "reverse reply"  },
  {ARPOP_IREQUEST, "inverse request"},
  {ARPOP_IREPLY,   "inverse reply"  },
  {0,              NULL          } };

static const value_string atmop_vals[] = {
  {ARPOP_REQUEST,  "request" },
  {ARPOP_REPLY,    "reply"   },
  {ARPOP_IREQUEST, "inverse request"},
  {ARPOP_IREPLY,   "inverse reply"  },
  {ATMARPOP_NAK,   "nak"  },
  {0,              NULL          } };

#define	ATMARP_IS_E164	0x40	/* bit in type/length for E.164 format */
#define	ATMARP_LEN_MASK	0x3F	/* length of {sub}address in type/length */

gchar *
arphrdaddr_to_str(const guint8 *ad, int ad_len, guint16 type)
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
arpproaddr_to_str(const guint8 *ad, int ad_len, guint16 type)
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
atmarpnum_to_str(const guint8 *ad, int ad_tl)
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
atmarpsubaddr_to_str(const guint8 *ad, int ad_tl)
{
  int           ad_len = ad_tl & ATMARP_LEN_MASK;

  if (ad_len == 0)
    return "<No address>";

  /*
   * E.164 isn't considered legal in subaddresses (RFC 2225 says that
   * a null or unknown ATM address is indicated by setting the length
   * to 0, in which case the type must be ignored; we've seen some
   * captures in which the length of a subaddress is 0 and the type
   * is E.164).
   *
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
#define	ATM_AR_SSTL	5
#define	ATM_AR_OP	6
#define	ATM_AR_SPLN	8
#define	ATM_AR_THTL	9
#define	ATM_AR_TSTL	10
#define	ATM_AR_TPLN	11
#define MIN_ATMARP_HEADER_SIZE	12

static void
dissect_atm_number(tvbuff_t *tvb, int offset, int tl, int hf_e164,
    int hf_nsap, proto_tree *tree)
{
	int len = tl & ATMARP_LEN_MASK;
	proto_item *ti;
	proto_tree *nsap_tree;

	if (tl & ATMARP_IS_E164)
		proto_tree_add_item(tree, hf_e164, tvb, offset, len, FALSE);
	else {
		ti = proto_tree_add_item(tree, hf_nsap, tvb, offset, len, FALSE);
		if (len >= 20) {
			nsap_tree = proto_item_add_subtree(ti, ett_atmarp_nsap);
			dissect_atm_nsap(tvb, offset, len, nsap_tree);
		}
	}
}

void
dissect_atm_nsap(tvbuff_t *tvb, int offset, int len, proto_tree *tree)
{
	guint8 afi;

	afi = tvb_get_guint8(tvb, offset);
	switch (afi) {

	case 0x39:	/* DCC ATM format */
	case 0xBD:	/* DCC ATM group format */
		proto_tree_add_text(tree, tvb, offset + 0, 3,
		    "Data Country Code%s: 0x%04X",
		    (afi == 0xBD) ? " (group)" : "",
		    tvb_get_ntohs(tvb, offset + 1));
		proto_tree_add_text(tree, tvb, offset + 3, 10,
		    "High Order DSP: %s",
		    tvb_bytes_to_str(tvb, offset + 3, 10));
		proto_tree_add_text(tree, tvb, offset + 13, 6,
		    "End System Identifier: %s",
		    tvb_bytes_to_str(tvb, offset + 13, 6));
		proto_tree_add_text(tree, tvb, offset + 19, 1,
		    "Selector: 0x%02X", tvb_get_guint8(tvb, offset + 19));
		break;

	case 0x47:	/* ICD ATM format */
	case 0xC5:	/* ICD ATM group format */
		proto_tree_add_text(tree, tvb, offset + 0, 3,
		    "International Code Designator%s: 0x%04X",
		    (afi == 0xC5) ? " (group)" : "",
		    tvb_get_ntohs(tvb, offset + 1));
		proto_tree_add_text(tree, tvb, offset + 3, 10,
		    "High Order DSP: %s",
		    tvb_bytes_to_str(tvb, offset + 3, 10));
		proto_tree_add_text(tree, tvb, offset + 13, 6,
		    "End System Identifier: %s",
		    tvb_bytes_to_str(tvb, offset + 13, 6));
		proto_tree_add_text(tree, tvb, offset + 19, 1,
		    "Selector: 0x%02X", tvb_get_guint8(tvb, offset + 19));
		break;

	case 0x45:	/* E.164 ATM format */
	case 0xC3:	/* E.164 ATM group format */
		proto_tree_add_text(tree, tvb, offset + 0, 9,
		    "E.164 ISDN%s: %s",
		    (afi == 0xC3) ? " (group)" : "",
		    tvb_bytes_to_str(tvb, offset + 1, 8));
		proto_tree_add_text(tree, tvb, offset + 9, 4,
		    "High Order DSP: %s",
		    tvb_bytes_to_str(tvb, offset + 3, 10));
		proto_tree_add_text(tree, tvb, offset + 13, 6,
		    "End System Identifier: %s",
		    tvb_bytes_to_str(tvb, offset + 13, 6));
		proto_tree_add_text(tree, tvb, offset + 19, 1,
		    "Selector: 0x%02X", tvb_get_guint8(tvb, offset + 19));
		break;

	default:
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Unknown AFI: 0x%02X", afi);
		proto_tree_add_text(tree, tvb, offset + 1, len - 1,
		    "Rest of address: %s",
		    tvb_bytes_to_str(tvb, offset + 1, len - 1));
		break;
	}
}

/*
 * RFC 2225 ATMARP - it's just like ARP, except where it isn't.
 */
static void
dissect_atmarp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16     ar_hrd;
  guint16     ar_pro;
  guint8      ar_shtl;
  guint8      ar_shl;
  guint8      ar_sstl;
  guint8      ar_ssl;
  guint16     ar_op;
  guint8      ar_spln;
  guint8      ar_thtl;
  guint8      ar_thl;
  guint8      ar_tstl;
  guint8      ar_tsl;
  guint8      ar_tpln;
  int         tot_len;
  proto_tree  *arp_tree;
  proto_item  *ti;
  gchar       *op_str;
  int         sha_offset, ssa_offset, spa_offset;
  int         tha_offset, tsa_offset, tpa_offset;
  const guint8      *sha_val, *ssa_val, *spa_val;
  const guint8      *tha_val, *tsa_val, *tpa_val;
  gchar       *sha_str, *ssa_str, *spa_str;
  gchar       *tha_str, *tsa_str, *tpa_str;
  proto_tree  *tl_tree;
  proto_item  *tl;

  CHECK_DISPLAY_AS_DATA(proto_arp, tvb, pinfo, tree);

  /* Override the setting to "ARP/RARP". */
  pinfo->current_proto = "ATMARP";

  ar_hrd = tvb_get_ntohs(tvb, ATM_AR_HRD);
  ar_pro = tvb_get_ntohs(tvb, ATM_AR_PRO);
  ar_shtl = tvb_get_guint8(tvb, ATM_AR_SHTL);
  ar_shl = ar_shtl & ATMARP_LEN_MASK;
  ar_sstl = tvb_get_guint8(tvb, ATM_AR_SSTL);
  ar_ssl = ar_sstl & ATMARP_LEN_MASK;
  ar_op  = tvb_get_ntohs(tvb, AR_OP);
  ar_spln = tvb_get_guint8(tvb, ATM_AR_SPLN);
  ar_thtl = tvb_get_guint8(tvb, ATM_AR_THTL);
  ar_thl = ar_thtl & ATMARP_LEN_MASK;
  ar_tstl = tvb_get_guint8(tvb, ATM_AR_TSTL);
  ar_tsl = ar_tstl & ATMARP_LEN_MASK;
  ar_tpln = tvb_get_guint8(tvb, ATM_AR_TPLN);

  tot_len = MIN_ATMARP_HEADER_SIZE + ar_shl + ar_ssl + ar_spln +
				ar_thl + ar_tsl + ar_tpln;
  
  /* Adjust the length of this tvbuff to include only the ARP datagram.
     Our caller may use that to determine how much of its packet
     was padding. */
  tvb_set_reported_length(tvb, tot_len);

  /* Extract the addresses.  */
  sha_offset = MIN_ATMARP_HEADER_SIZE;
  if (ar_shl != 0) {
    sha_val = tvb_get_ptr(tvb, sha_offset, ar_shl);
    sha_str = atmarpnum_to_str(sha_val, ar_shtl);
  } else {
    sha_val = NULL;
    sha_str = "<No address>";
  }

  ssa_offset = sha_offset + ar_shl;
  if (ar_ssl != 0) {
    ssa_val = tvb_get_ptr(tvb, ssa_offset, ar_ssl);
    ssa_str = atmarpsubaddr_to_str(ssa_val, ar_sstl);
  } else {
    ssa_val = NULL;
    ssa_str = NULL;
  }

  spa_offset = ssa_offset + ar_ssl;
  spa_val = tvb_get_ptr(tvb, spa_offset, ar_spln);
  spa_str = arpproaddr_to_str(spa_val, ar_spln, ar_pro);

  tha_offset = spa_offset + ar_spln;
  if (ar_thl != 0) {
    tha_val = tvb_get_ptr(tvb, tha_offset, ar_thl);
    tha_str = atmarpnum_to_str(tha_val, ar_thtl);
  } else {
    tha_val = NULL;
    tha_str = "<No address>";
  }

  tsa_offset = tha_offset + ar_thl;
  if (ar_tsl != 0) {
    tsa_val = tvb_get_ptr(tvb, tsa_offset, ar_tsl);
    tsa_str = atmarpsubaddr_to_str(tsa_val, ar_tstl);
  } else {
    tsa_val = NULL;
    tsa_str = NULL;
  }

  tpa_offset = tsa_offset + ar_tsl;
  tpa_val = tvb_get_ptr(tvb, tpa_offset, ar_tpln);
  tpa_str = arpproaddr_to_str(tpa_val, ar_tpln, ar_pro);

  if (check_col(pinfo->fd, COL_PROTOCOL)) {
    switch (ar_op) {

    case ARPOP_REQUEST:
    case ARPOP_REPLY:
    case ATMARPOP_NAK:
    default:
      col_set_str(pinfo->fd, COL_PROTOCOL, "ATMARP");
      break;

    case ARPOP_RREQUEST:
    case ARPOP_RREPLY:
      col_set_str(pinfo->fd, COL_PROTOCOL, "ATMRARP");
      break;

    case ARPOP_IREQUEST:
    case ARPOP_IREPLY:
      col_set_str(pinfo->fd, COL_PROTOCOL, "Inverse ATMARP");
      break;
    }
  }

  if (check_col(pinfo->fd, COL_INFO)) {
    switch (ar_op) {
      case ARPOP_REQUEST:
        col_add_fstr(pinfo->fd, COL_INFO, "Who has %s?  Tell %s",
		tpa_str, spa_str);
        break;
      case ARPOP_REPLY:
        col_add_fstr(pinfo->fd, COL_INFO, "%s is at %s%s%s", spa_str, sha_str,
		((ssa_str != NULL) ? "," : ""),
		((ssa_str != NULL) ? ssa_str : ""));
        break;
      case ARPOP_IREQUEST:
        col_add_fstr(pinfo->fd, COL_INFO, "Who is %s%s%s?  Tell %s%s%s",
		tha_str,
		((tsa_str != NULL) ? "," : ""),
		((tsa_str != NULL) ? tsa_str : ""),
		sha_str,
		((ssa_str != NULL) ? "," : ""),
		((ssa_str != NULL) ? ssa_str : ""));
        break;
      case ARPOP_IREPLY:
        col_add_fstr(pinfo->fd, COL_INFO, "%s%s%s is at %s",
		sha_str,
		((ssa_str != NULL) ? "," : ""),
		((ssa_str != NULL) ? ssa_str : ""),
		spa_str);
        break;
      case ATMARPOP_NAK:
        col_add_fstr(pinfo->fd, COL_INFO, "I don't know where %s is", spa_str);
        break;
      default:
        col_add_fstr(pinfo->fd, COL_INFO, "Unknown ATMARP opcode 0x%04x", ar_op);
        break;
    }
  }

  if (tree) {
    if ((op_str = match_strval(ar_op, atmop_vals)))
      ti = proto_tree_add_protocol_format(tree, proto_arp, tvb, 0, tot_len,
					"ATM Address Resolution Protocol (%s)", 
					op_str);
    else
      ti = proto_tree_add_protocol_format(tree, proto_arp, tvb, 0, tot_len,
				      "ATM Address Resolution Protocol (opcode 0x%04x)", ar_op);
    arp_tree = proto_item_add_subtree(ti, ett_arp);

    proto_tree_add_uint(arp_tree, hf_arp_hard_type, tvb, ATM_AR_HRD, 2, ar_hrd);

    proto_tree_add_uint(arp_tree, hf_arp_proto_type, tvb, ATM_AR_PRO, 2,ar_pro);

    tl = proto_tree_add_text(arp_tree, tvb, ATM_AR_SHTL, 1,
			       "Sender ATM number type/length: %s/%u",
			       (ar_shtl & ATMARP_IS_E164 ?
			          "E.164" :
				  "ATM Forum NSAPA"),
			       ar_shl);
    tl_tree = proto_item_add_subtree(tl, ett_atmarp_tl);
    proto_tree_add_boolean(tl_tree, hf_atmarp_sht, tvb, ATM_AR_SHTL, 1, ar_shtl);
    proto_tree_add_uint(tl_tree, hf_atmarp_shl, tvb, ATM_AR_SHTL, 1, ar_shtl);

    tl = proto_tree_add_text(arp_tree, tvb, ATM_AR_SSTL, 1,
			       "Sender ATM subaddress type/length: %s/%u",
			       (ar_sstl & ATMARP_IS_E164 ?
			          "E.164" :
				  "ATM Forum NSAPA"),
			       ar_ssl);
    tl_tree = proto_item_add_subtree(tl, ett_atmarp_tl);
    proto_tree_add_boolean(tl_tree, hf_atmarp_sst, tvb, ATM_AR_SSTL, 1, ar_sstl);
    proto_tree_add_uint(tl_tree, hf_atmarp_ssl, tvb, ATM_AR_SSTL, 1, ar_sstl);

    proto_tree_add_uint(arp_tree, hf_arp_opcode, tvb, AR_OP,  2, ar_op);

    proto_tree_add_uint(arp_tree, hf_atmarp_spln, tvb, ATM_AR_SPLN, 1, ar_spln);

    tl = proto_tree_add_text(arp_tree, tvb, ATM_AR_THTL, 1,
			       "Target ATM number type/length: %s/%u",
			       (ar_thtl & ATMARP_IS_E164 ?
			          "E.164" :
				  "ATM Forum NSAPA"),
			       ar_thl);
    tl_tree = proto_item_add_subtree(tl, ett_atmarp_tl);
    proto_tree_add_boolean(tl_tree, hf_atmarp_tht, tvb, ATM_AR_THTL, 1, ar_thtl);
    proto_tree_add_uint(tl_tree, hf_atmarp_thl, tvb, ATM_AR_THTL, 1, ar_thtl);

    tl = proto_tree_add_text(arp_tree, tvb, ATM_AR_TSTL, 1,
			       "Target ATM subaddress type/length: %s/%u",
			       (ar_tstl & ATMARP_IS_E164 ?
			          "E.164" :
				  "ATM Forum NSAPA"),
			       ar_tsl);
    tl_tree = proto_item_add_subtree(tl, ett_atmarp_tl);
    proto_tree_add_boolean(tl_tree, hf_atmarp_tst, tvb, ATM_AR_TSTL, 1, ar_tstl);
    proto_tree_add_uint(tl_tree, hf_atmarp_tsl, tvb, ATM_AR_TSTL, 1, ar_tstl);

    proto_tree_add_uint(arp_tree, hf_atmarp_tpln, tvb, ATM_AR_TPLN, 1, ar_tpln);

    if (ar_shl != 0)
      dissect_atm_number(tvb, sha_offset, ar_shtl, hf_atmarp_src_atm_num_e164,
			       hf_atmarp_src_atm_num_nsap, arp_tree);

    if (ar_ssl != 0)
      proto_tree_add_bytes_format(arp_tree, hf_atmarp_src_atm_subaddr, tvb, ssa_offset,
			       ar_ssl,
			       ssa_val,
			       "Sender ATM subaddress: %s", ssa_str);

    if (ar_spln != 0)
      proto_tree_add_bytes_format(arp_tree, hf_arp_src_proto, tvb, spa_offset, ar_spln,
			       spa_val,
			       "Sender protocol address: %s", spa_str);

    if (ar_thl != 0)
      dissect_atm_number(tvb, tha_offset, ar_thtl, hf_atmarp_dst_atm_num_e164,
			       hf_atmarp_dst_atm_num_nsap, arp_tree);

    if (ar_tsl != 0)
      proto_tree_add_bytes_format(arp_tree, hf_atmarp_dst_atm_subaddr, tvb, tsa_offset,
			       ar_tsl,
			       tsa_val,
			       "Target ATM subaddress: %s", tsa_str);

    if (ar_tpln != 0)
      proto_tree_add_bytes_format(arp_tree, hf_arp_dst_proto, tvb, tpa_offset, ar_tpln,
			       tpa_val,
			       "Target protocol address: %s", tpa_str);
  }
}

static const guint8 mac_broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static void
dissect_arp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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
  const guint8      *sha_val, *spa_val, *tha_val, *tpa_val;
  gchar       *sha_str, *spa_str, *tha_str, *tpa_str;

  CHECK_DISPLAY_AS_DATA(proto_arp, tvb, pinfo, tree);

  pinfo->current_proto = "ARP";

  /* Call it ARP, for now, so that if we throw an exception before
     we decide whether it's ARP or RARP or IARP or ATMARP, it shows
     up in the packet list as ARP.

     Clear the Info column so that, if we throw an exception, it
     shows up as a short or malformed ARP frame. */
  if (check_col(pinfo->fd, COL_PROTOCOL))
      col_set_str(pinfo->fd, COL_PROTOCOL, "ARP");
  if (check_col(pinfo->fd, COL_INFO))
      col_clear(pinfo->fd, COL_INFO);

  ar_hrd = tvb_get_ntohs(tvb, AR_HRD);
  if (ar_hrd == ARPHRD_ATM2225) {
    dissect_atmarp(tvb, pinfo, tree);
    return;
  }
  ar_pro = tvb_get_ntohs(tvb, AR_PRO);
  ar_hln = tvb_get_guint8(tvb, AR_HLN);
  ar_pln = tvb_get_guint8(tvb, AR_PLN);
  ar_op  = tvb_get_ntohs(tvb, AR_OP);

  tot_len = MIN_ARP_HEADER_SIZE + ar_hln*2 + ar_pln*2;
  
  /* Adjust the length of this tvbuff to include only the ARP datagram.
     Our caller may use that to determine how much of its packet
     was padding. */
  tvb_set_reported_length(tvb, tot_len);

  /* Extract the addresses.  */
  sha_offset = MIN_ARP_HEADER_SIZE;
  sha_val = tvb_get_ptr(tvb, sha_offset, ar_hln);
  sha_str = arphrdaddr_to_str(sha_val, ar_hln, ar_hrd);

  spa_offset = sha_offset + ar_hln;
  spa_val = tvb_get_ptr(tvb, spa_offset, ar_pln);
  spa_str = arpproaddr_to_str(spa_val, ar_pln, ar_pro);

  tha_offset = spa_offset + ar_pln;
  tha_val = tvb_get_ptr(tvb, tha_offset, ar_hln);
  tha_str = arphrdaddr_to_str(tha_val, ar_hln, ar_hrd);

  tpa_offset = tha_offset + ar_hln;
  tpa_val = tvb_get_ptr(tvb, tpa_offset, ar_pln);
  tpa_str = arpproaddr_to_str(tpa_val, ar_pln, ar_pro);
  
  if (check_col(pinfo->fd, COL_PROTOCOL)) {
    switch (ar_op) {

    case ARPOP_REQUEST:
    case ARPOP_REPLY:
    default:
      col_set_str(pinfo->fd, COL_PROTOCOL, "ARP");
      break;

    case ARPOP_RREQUEST:
    case ARPOP_RREPLY:
      col_set_str(pinfo->fd, COL_PROTOCOL, "RARP");
      break;

    case ARPOP_IREQUEST:
    case ARPOP_IREPLY:
      col_set_str(pinfo->fd, COL_PROTOCOL, "Inverse ARP");
      break;
    }
  }

  if (check_col(pinfo->fd, COL_INFO)) {
    switch (ar_op) {
      case ARPOP_REQUEST:
        col_add_fstr(pinfo->fd, COL_INFO, "Who has %s?  Tell %s", tpa_str, spa_str);
        break;
      case ARPOP_REPLY:
        col_add_fstr(pinfo->fd, COL_INFO, "%s is at %s", spa_str, sha_str);
        break;
      case ARPOP_RREQUEST:
      case ARPOP_IREQUEST:
        col_add_fstr(pinfo->fd, COL_INFO, "Who is %s?  Tell %s", tha_str, sha_str);
        break;
      case ARPOP_RREPLY:
      case ARPOP_IREPLY:
        col_add_fstr(pinfo->fd, COL_INFO, "%s is at %s", sha_str, spa_str);
        break;
      default:
        col_add_fstr(pinfo->fd, COL_INFO, "Unknown ARP opcode 0x%04x", ar_op);
        break;
    }
  }

  if ((ar_op == ARPOP_REPLY || ar_op == ARPOP_REQUEST) &&
      ar_hln == 6 && ar_pln == 4) {

    /* inform resolv.c module of the new discovered addresses */

    u_int ip;
    const guint8 *mac;

    /* add sender address in all cases */

    tvb_memcpy(tvb, (guint8 *)&ip, spa_offset, sizeof(ip));
    add_ether_byip(ip, tvb_get_ptr(tvb, sha_offset, 6));
    
    if (ar_op == ARPOP_REQUEST) {
      /* Add target address *if* the target MAC address isn't a
         broadcast address. */
      tvb_memcpy(tvb, (guint8 *)&ip, tpa_offset, sizeof(ip));
      mac = tvb_get_ptr(tvb, tha_offset, 6);
      if (memcmp(mac, mac_broadcast, 6) != 0)
        add_ether_byip(ip, mac);
    }
  }

  if (tree) {
    if ((op_str = match_strval(ar_op, op_vals)))
      ti = proto_tree_add_protocol_format(tree, proto_arp, tvb, 0, tot_len,
					"Address Resolution Protocol (%s)", op_str);
    else
      ti = proto_tree_add_protocol_format(tree, proto_arp, tvb, 0, tot_len,
				      "Address Resolution Protocol (opcode 0x%04x)", ar_op);
    arp_tree = proto_item_add_subtree(ti, ett_arp);
    proto_tree_add_uint(arp_tree, hf_arp_hard_type, tvb, AR_HRD, 2, ar_hrd);
    proto_tree_add_uint(arp_tree, hf_arp_proto_type, tvb, AR_PRO, 2, ar_pro);
    proto_tree_add_uint(arp_tree, hf_arp_hard_size, tvb, AR_HLN, 1, ar_hln);
    proto_tree_add_uint(arp_tree, hf_arp_proto_size, tvb, AR_PLN, 1, ar_pln);
    proto_tree_add_uint(arp_tree, hf_arp_opcode, tvb, AR_OP,  2, ar_op);
    if (ar_hln != 0)
      proto_tree_add_bytes_format(arp_tree, hf_arp_src_ether, tvb, sha_offset, ar_hln,
			       sha_val,
			       "Sender hardware address: %s", sha_str);
    if (ar_pln != 0)
      proto_tree_add_bytes_format(arp_tree, hf_arp_src_proto, tvb, spa_offset, ar_pln,
			       spa_val,
			       "Sender protocol address: %s", spa_str);
    if (ar_hln != 0)
      proto_tree_add_bytes_format(arp_tree, hf_arp_dst_ether, tvb, tha_offset, ar_hln,
			       tha_val,
			       "Target hardware address: %s", tha_str);
    if (ar_pln != 0)
      proto_tree_add_bytes_format(arp_tree, hf_arp_dst_proto, tvb, tpa_offset, ar_pln,
			       tpa_val,
			       "Target protocol address: %s", tpa_str);
  }
}

void
proto_register_arp(void)
{
  static struct true_false_string type_bit = { "E.164", "ATM Forum NSAPA" };

  static hf_register_info hf[] = {
    { &hf_arp_hard_type,
      { "Hardware type",		"arp.hw.type",	 
	FT_UINT16,	BASE_HEX,	VALS(hrd_vals),	0x0,
      	"", HFILL }},

    { &hf_arp_proto_type,
      { "Protocol type",		"arp.proto.type",
	FT_UINT16,	BASE_HEX,	VALS(etype_vals),	0x0,
      	"", HFILL }},

    { &hf_arp_hard_size,
      { "Hardware size",		"arp.hw.size",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"", HFILL }},

    { &hf_atmarp_sht,
      { "Sender ATM number type",	"arp.src.htype",
	FT_BOOLEAN,	8,		&type_bit,	ATMARP_IS_E164,
      	"", HFILL }},

    { &hf_atmarp_shl,
      { "Sender ATM number length",	"arp.src.hlen",
	FT_UINT8,	BASE_DEC,	NULL,		ATMARP_LEN_MASK,
      	"", HFILL }},

    { &hf_atmarp_sst,
      { "Sender ATM subaddress type",	"arp.src.stype",
	FT_BOOLEAN,	8,		&type_bit,	ATMARP_IS_E164,
      	"", HFILL }},

    { &hf_atmarp_ssl,
      { "Sender ATM subaddress length",	"arp.src.slen",
	FT_UINT8,	BASE_DEC,	NULL,		ATMARP_LEN_MASK,
      	"", HFILL }},

    { &hf_arp_proto_size,
      { "Protocol size",		"arp.proto.size",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"", HFILL }},

    { &hf_arp_opcode,
      { "Opcode",			"arp.opcode",
	FT_UINT16,	BASE_HEX,	VALS(op_vals),	0x0,
      	"", HFILL }},

    { &hf_atmarp_spln,
      { "Sender protocol size",		"arp.src.pln",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"", HFILL }},

    { &hf_atmarp_tht,
      { "Target ATM number type",	"arp.dst.htype",
	FT_BOOLEAN,	8,		&type_bit,	ATMARP_IS_E164,
      	"", HFILL }},

    { &hf_atmarp_thl,
      { "Target ATM number length",	"arp.dst.hlen",
	FT_UINT8,	BASE_DEC,	NULL,		ATMARP_LEN_MASK,
      	"", HFILL }},

    { &hf_atmarp_tst,
      { "Target ATM subaddress type",	"arp.dst.stype",
	FT_BOOLEAN,	8,		&type_bit,	ATMARP_IS_E164,
      	"", HFILL }},

    { &hf_atmarp_tsl,
      { "Target ATM subaddress length",	"arp.dst.slen",
	FT_UINT8,	BASE_DEC,	NULL,		ATMARP_LEN_MASK,
      	"", HFILL }},

    { &hf_atmarp_tpln,
      { "Target protocol size",		"arp.dst.pln",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"", HFILL }},

    { &hf_arp_src_ether,
      { "Sender hardware address",	"arp.src.hw",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_atmarp_src_atm_num_e164,
      { "Sender ATM number (E.164)",	"arp.src.atm_num_e164",
	FT_STRING,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_atmarp_src_atm_num_nsap,
      { "Sender ATM number (NSAP)",	"arp.src.atm_num_nsap",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_atmarp_src_atm_subaddr,
      { "Sender ATM subaddress",	"arp.src.atm_subaddr",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_arp_src_proto,
      { "Sender protocol address",	"arp.src.proto", 
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_arp_dst_ether,
      { "Target hardware address",	"arp.dst.hw",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_atmarp_dst_atm_num_e164,
      { "Target ATM number (E.164)",	"arp.dst.atm_num_e164",
	FT_STRING,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_atmarp_dst_atm_num_nsap,
      { "Target ATM number (NSAP)",	"arp.dst.atm_num_nsap",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_atmarp_dst_atm_subaddr,
      { "Target ATM subaddress",	"arp.dst.atm_subaddr",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_arp_dst_proto,
      { "Target protocol address",	"arp.dst.proto", 
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      "", HFILL }}
  };
  static gint *ett[] = {
    &ett_arp,
    &ett_atmarp_nsap,
    &ett_atmarp_tl,
  };

  proto_arp = proto_register_protocol("Address Resolution Protocol",
				      "ARP/RARP", "arp");
  proto_register_field_array(proto_arp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_arp(void)
{
  dissector_add("ethertype", ETHERTYPE_ARP, dissect_arp, proto_arp);
  dissector_add("ethertype", ETHERTYPE_REVARP, dissect_arp, proto_arp);
}
