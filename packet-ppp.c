/* packet-ppp.c
 * Routines for ppp packet disassembly
 *
 * $Id: packet-ppp.c,v 1.17 1999/08/25 07:32:46 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 *
 * This file created and by Mike Hall <mlh@io.com>
 * Copyright 1998
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

static int proto_ppp = -1;

/* PPP structs and definitions */

typedef struct _e_ppphdr {
  guint8  ppp_addr;
  guint8  ppp_ctl;
  guint16 ppp_prot;
} e_ppphdr;


/* Protocol types, from Linux "ppp_defs.h" and

	http://www.isi.edu/in-notes/iana/assignments/ppp-numbers

 */
#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_AT		0x29	/* AppleTalk Protocol */
#define PPP_IPX		0x2b	/* IPX protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define	PPP_VINES	0x35	/* Banyan Vines */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b	/* IPX Control Protocol */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP	0xc029	/* Callback Control Protocol */

static const value_string ppp_vals[] = {
	{PPP_IP,        "IP"             },
	{PPP_AT,        "Appletalk"      },
	{PPP_IPX,       "Netware IPX/SPX"},
	{PPP_VJC_COMP,	"VJ compressed TCP"},
	{PPP_VJC_UNCOMP,"VJ uncompressed TCP"}, 
	{PPP_VINES,     "Vines"          },
	{PPP_IPV6,      "IPv6"           },
	{PPP_COMP,	"compressed packet" },
	{PPP_IPCP,	"IP Control Protocol" },
	{PPP_ATCP,	"AppleTalk Control Protocol" },
	{PPP_IPXCP,	"IPX Control Protocol" },
	{PPP_CCP,	"Compression Control Protocol" },
	{PPP_LCP,	"Link Control Protocol" },
	{PPP_PAP,	"Password Authentication Protocol"  },
	{PPP_LQR,	"Link Quality Report protocol" },
	{PPP_CHAP,	"Cryptographic Handshake Auth. Protocol" },
	{PPP_CBCP,	"Callback Control Protocol" },
	{0,             NULL            }
};

/* CP (LCP, IPCP, etc.) codes.
 * from pppd fsm.h 
 */
#define CONFREQ    1  /* Configuration Request */
#define CONFACK    2  /* Configuration Ack */
#define CONFNAK    3  /* Configuration Nak */
#define CONFREJ    4  /* Configuration Reject */
#define TERMREQ    5  /* Termination Request */
#define TERMACK    6  /* Termination Ack */
#define CODEREJ    7  /* Code Reject */

static const value_string cp_vals[] = {
	{CONFREQ,    "Configuration Request" },
	{CONFACK,    "Configuration Ack" },
	{CONFNAK,    "Configuration Nak" },
	{CONFREJ,    "Configuration Reject" },
	{TERMREQ,    "Termination Request" },
	{TERMACK,    "Termination Ack" },
	{CODEREJ,    "Code Reject" },
	{0,          NULL            } };

/*
 * LCP-specific packet types.
 */
#define PROTREJ    8  /* Protocol Reject */
#define ECHOREQ    9  /* Echo Request */
#define ECHOREP    10 /* Echo Reply */
#define DISCREQ    11 /* Discard Request */
#define IDENT      12 /* Identification */
#define TIMEREMAIN 13 /* Time remaining */

#define CBCP_OPT  6 /* Use callback control protocol */

static const value_string lcp_vals[] = {
	{CONFREQ,    "Configuration Request" },
	{CONFACK,    "Configuration Ack" },
	{CONFNAK,    "Configuration Nak" },
	{CONFREJ,    "Configuration Reject" },
	{TERMREQ,    "Termination Request" },
	{TERMACK,    "Termination Ack" },
	{CODEREJ,    "Code Reject" },
	{PROTREJ,    "Protocol Reject" },
	{ECHOREQ,    "Echo Request" },
	{ECHOREP,    "Echo Reply" },
	{DISCREQ,    "Discard Request" },
	{IDENT,      "Identification" },
	{TIMEREMAIN, "Time Remaining" },
	{0,          NULL }
};

/* Member of table of PPP (LCP, IPCP) options. */
typedef struct cp_opt cp_opt;
struct cp_opt {
	int	optcode;	/* code for option */
	char	*name;		/* name of option */
	int	subtree_index;	/* ETT_ value for option */
	gboolean fixed_length;	/* TRUE if option is always the same length */
	int	optlen;		/* value length should be (minimum if VARIABLE) */
	void	(*dissect)(const u_char *, const cp_opt *, int, int, proto_tree *);
			/* routine to dissect option */
};

/*
 * Options.  (LCP)
 */
#define CI_MRU			1	/* Maximum Receive Unit */
#define CI_ASYNCMAP		2	/* Async Control Character Map */
#define CI_AUTHTYPE		3	/* Authentication Type */
#define CI_QUALITY		4	/* Quality Protocol */
#define CI_MAGICNUMBER		5	/* Magic Number */
#define CI_PCOMPRESSION		7	/* Protocol Field Compression */
#define CI_ACCOMPRESSION	8	/* Address/Control Field Compression */
#define CI_FCSALTERNATIVES	9	/* FCS Alternatives (RFC 1570) */
#define CI_SELF_DESCRIBING_PAD	10	/* Self-Describing Pad (RFC 1570) */
#define CI_NUMBERED_MODE	11	/* Numbered Mode (RFC 1663) */
#define CI_CALLBACK		13	/* Callback (RFC 1570) */
#define CI_MULTILINK_MRRU	17	/* Multilink MRRU (RFC 1717) */
#define CI_MULTILINK_SSNH	18	/* Multilink Short Sequence Number
					   Header (RFC 1717) */
#define CI_MULTILINK_EP_DISC	19	/* Multilink Endpoint Discriminator
					   (RFC 1717) */
#define CI_DCE_IDENTIFIER	21	/* DCE Identifier */
#define CI_MULTILINK_PLUS_PROC	22	/* Multilink Plus Procedure */
#define CI_LINK_DISC_FOR_BACP	23	/* Link Discriminator for BACP
					   (RFC 2125) */
#define CI_LCP_AUTHENTICATION	24	/* LCP Authentication Option */
#define CI_COBS			25	/* Consistent Overhead Byte
					   Stuffing */
#define CI_PREFIX_ELISION	26	/* Prefix elision */
#define CI_MULTILINK_HDR_FMT	27	/* Multilink header format */
#define CI_INTERNATIONALIZATION	28	/* Internationalization (RFC 2484) */
#define	CI_SDL_ON_SONET_SDH	29	/* Simple Data Link on SONET/SDH */

static const value_string lcp_opt_vals[] = {
	{CI_MRU,                  "Maximum Receive Unit" },
	{CI_ASYNCMAP,             "Async Control Character Map" },
	{CI_AUTHTYPE,             "Authentication Type" },
	{CI_QUALITY,              "Quality Protocol" },
	{CI_MAGICNUMBER,          "Magic Number" },
	{CI_PCOMPRESSION,         "Protocol Field Compression" },
	{CI_ACCOMPRESSION,        "Address/Control Field Compression" },
	{CI_FCSALTERNATIVES,      "FCS Alternatives" },
	{CI_SELF_DESCRIBING_PAD,  "Self-Describing Pad" },
	{CI_NUMBERED_MODE,        "Numbered Mode" },
	{CI_CALLBACK,             "Callback" },
	{CI_MULTILINK_MRRU,       "Multilink MRRU" },
	{CI_MULTILINK_SSNH,       "Multilink Short Sequence Number Header" },
	{CI_MULTILINK_EP_DISC,    "Multilink Endpoint Discriminator" },
	{CI_DCE_IDENTIFIER,       "DCE Identifier" },
	{CI_MULTILINK_PLUS_PROC,  "Multilink Plus Procedure" },
	{CI_LINK_DISC_FOR_BACP,   "Link Discriminator for BACP" },
	{CI_LCP_AUTHENTICATION,   "LCP Authentication" },
	{CI_COBS,                 "Consistent Overhead Byte Stuffing" },
	{CI_PREFIX_ELISION,       "Prefix elision" },
	{CI_MULTILINK_HDR_FMT,    "Multilink header format" },
	{CI_INTERNATIONALIZATION, "Internationalization" },
	{CI_SDL_ON_SONET_SDH,     "Simple Data Link on SONET/SDH" },
	{0,                       NULL }
};

static void dissect_lcp_mru_opt(const u_char *pd, const cp_opt *optp,
			int offset, int length, proto_tree *tree);
static void dissect_lcp_async_map_opt(const u_char *pd, const cp_opt *optp,
			int offset, int length, proto_tree *tree);
static void dissect_lcp_protocol_opt(const u_char *pd, const cp_opt *optp,
			int offset, int length, proto_tree *tree);
static void dissect_lcp_magicnumber_opt(const u_char *pd, const cp_opt *optp,
			int offset, int length, proto_tree *tree);

static const cp_opt lcp_opts[] = {
	{CI_MRU,           NULL,                      ETT_LCP_MRU_OPT,
			TRUE,  4, dissect_lcp_mru_opt},
	{CI_ASYNCMAP,      NULL,                      ETT_LCP_ASYNC_MAP_OPT,
			TRUE,  6, dissect_lcp_async_map_opt},
	{CI_AUTHTYPE,      "Authentication protocol", ETT_LCP_AUTHPROT_OPT,
			FALSE, 4, dissect_lcp_protocol_opt},
	{CI_QUALITY,       "Quality protocol",        ETT_LCP_QUALPROT_OPT,
			FALSE, 4, dissect_lcp_protocol_opt},
	{CI_MAGICNUMBER,   NULL,                      ETT_LCP_MAGICNUM_OPT,
			TRUE,  6, dissect_lcp_magicnumber_opt},
	{CI_PCOMPRESSION,  NULL,                      -1,
			TRUE,  2, NULL},
	{CI_ACCOMPRESSION, NULL,                      -1,
			TRUE,  2, NULL}
};

#define N_LCP_OPTS	(sizeof lcp_opts / sizeof lcp_opts[0])

/*
 * Options.  (IPCP)
 */
#define CI_ADDRS	1	/* IP Addresses (deprecated) (RFC 1332) */
#define CI_COMPRESSTYPE	2	/* Compression Type (RFC 1332) */
#define CI_ADDR		3	/* IP Address (RFC 1332) */
#define CI_MOBILE_IPv4	4	/* Mobile IPv4 (RFC 2290) */
#define CI_MS_DNS1	129	/* Primary DNS value (RFC 1877) */
#define CI_MS_WINS1	130	/* Primary WINS value (RFC 1877) */
#define CI_MS_DNS2	131	/* Secondary DNS value (RFC 1877) */
#define CI_MS_WINS2	132	/* Secondary WINS value (RFC 1877) */

static const value_string ipcp_opt_vals[] = {
	{CI_ADDRS,        "IP Addresses" },
	{CI_COMPRESSTYPE, "Compression Type" },
	{CI_ADDR,         "IP Address" }, 
	{CI_MOBILE_IPv4,  "Mobile IPv4" }, 
	{CI_MS_DNS1,      "Primary DNS value" },
	{CI_MS_WINS1,     "Primary WINS value" },
	{CI_MS_DNS2,      "Secondary DNS value" },
	{CI_MS_WINS2,     "Secondary WINS value" },
	{0,               NULL }
};

static void dissect_ipcp_addr_opt(const u_char *pd, const cp_opt *optp,
			int offset, int length, proto_tree *tree);

static const cp_opt ipcp_opts[] = {
	{CI_COMPRESSTYPE, "IP compression protocol", ETT_IPCP_COMPRESSPROT_OPT,
			FALSE, 4, dissect_lcp_protocol_opt},
	{CI_ADDR,         NULL,                      ETT_IPCP_ADDR_OPT,
			TRUE,  6, dissect_ipcp_addr_opt},
};

#define N_IPCP_OPTS	(sizeof ipcp_opts / sizeof ipcp_opts[0])

void
capture_ppp( const u_char *pd, guint32 cap_len, packet_counts *ld ) {
  switch (pntohs(&pd[2])) {
    case PPP_IP:
      capture_ip(pd, 4, cap_len, ld);
      break;
    default:
      ld->other++;
      break;
  }
}

static void
dissect_lcp_mru_opt(const u_char *pd, const cp_opt *optp, int offset,
			int length, proto_tree *tree)
{
  proto_tree_add_text(tree, offset, length, "MRU: %u", pntohs(&pd[offset]));
}

static void
dissect_lcp_async_map_opt(const u_char *pd, const cp_opt *optp, int offset,
			int length, proto_tree *tree)
{
  proto_tree_add_text(tree, offset, length, "Async characters to map: 0x%08x",
			pntohl(&pd[offset]));
}

static void
dissect_lcp_protocol_opt(const u_char *pd, const cp_opt *optp, int offset,
			int length, proto_tree *tree)
{
  guint16 protocol;
  proto_item *tf;
  proto_tree *field_tree = NULL;
  
  tf = proto_tree_add_text(tree, offset, length, "%s: %u byte%s",
	  optp->name, length, plurality(length, "", "s"));
  field_tree = proto_item_add_subtree(tf, optp->subtree_index);
  offset += 2;
  length -= 2;
  protocol = pntohs(&pd[offset]);
  proto_tree_add_text(field_tree, offset, 2, "%s: %s (0x%02x)", optp->name,
		val_to_str(protocol, ppp_vals, "Unknown"), protocol);
  offset += 2;
  length -= 2;
  if (length > 0)
    proto_tree_add_text(field_tree, offset, length, "Data (%d byte%s)", length,
    			plurality(length, "", "s"));
}

static void
dissect_lcp_magicnumber_opt(const u_char *pd, const cp_opt *optp, int offset,
			int length, proto_tree *tree)
{
  proto_tree_add_text(tree, offset, length, "Magic number: 0x%08x",
			pntohl(&pd[offset]));
}

static void dissect_ipcp_addr_opt(const u_char *pd, const cp_opt *optp,
			int offset, int length, proto_tree *tree)
{
  proto_tree_add_text(tree, offset, length, "IP address: %s",
			ip_to_str((guint8 *)&pd[offset]));
}

static void
dissect_cp_opts(const u_char *pd, int offset, int length,
		const value_string *opt_vals, const cp_opt *opts,
		int nopts, proto_tree *tree)
{
  guint8 opt;
  guint16 opt_len;
  const cp_opt *optp;
  void (*dissect)(const u_char *, const cp_opt *, int, int, proto_tree *);
  gboolean error;

  while (length > 0) {
    opt = pd[offset];
    if (length == 1) {
      proto_tree_add_text(tree, offset, 1, "%s: Length byte past end of options",
        val_to_str(opt, opt_vals, "Unknown (0x%02x)"));
      return;
    }
    opt_len = pd[offset+1];
    if (length < opt_len) {
      proto_tree_add_text(tree, offset, 1, "%s: Option length %u says option goes past end of options",
        val_to_str(opt, opt_vals, "Unknown (0x%02x)"), opt_len);
      return;
    }
    for (optp = &lcp_opts[0]; optp < &lcp_opts[nopts]; optp++) {
      if (optp->optcode == opt)
        break;
    }
    dissect = NULL;
    error = FALSE;
    if (optp != &lcp_opts[nopts]) {
      if (optp->fixed_length) {
        /* Option has a fixed length - complain if the length we got
           doesn't match. */
        if (opt_len != optp->optlen) {
          proto_tree_add_text(tree, offset, 1, "%s: Option length is %u, should be %u",
            val_to_str(opt, opt_vals, "Unknown (0x%02x)"), opt_len, optp->optlen);
          error = TRUE;
        } else
          dissect = optp->dissect;
      } else {
        /* Option has a variable length - complain if the length we got
           isn't at least as much as the minimum length. */
        if (opt_len < optp->optlen) {
          proto_tree_add_text(tree, offset, 1, "%s: Option length is %u, should be at least %u",
            val_to_str(opt, opt_vals, "Unknown (0x%02x)"), opt_len, optp->optlen);
          error = TRUE;
        } else
          dissect = optp->dissect;
      }
    }
    if (dissect != NULL)
      (*dissect)(pd, optp, offset, opt_len, tree);
    else {
      if (!error) {
        proto_tree_add_text(tree, offset, opt_len, "%s: %u byte%s",
          val_to_str(opt, opt_vals, "Unknown (0x%02x)"), opt_len,
          plurality(opt_len, "", "s"));
      }
    }
    offset += opt_len;
    length -= opt_len;
  }
}

static void
dissect_cp( const u_char *pd, int offset, const char *proto_short_name,
	const char *proto_long_name, int proto_subtree_index,
	const value_string *proto_vals, int options_subtree_index,
	const value_string *opt_vals, const cp_opt *opts, int nopts,
	frame_data *fd, proto_tree *tree ) {
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  proto_item *tf;
  proto_tree *field_tree;

  guint8 code;
  guint8 id;
  int length;
  guint16 protocol;

  code = pd[0+offset];
  id = pd[1+offset];
  length = pntohs(&pd[2+offset]);

  if(check_col(fd, COL_INFO))
	col_add_fstr(fd, COL_INFO, "%sCP %s", proto_short_name,
		val_to_str(code, proto_vals, "Unknown"));

  if(tree) {
    ti = proto_tree_add_text(tree, 0+offset, 4, "%s Control Protocol",
				proto_long_name);
    fh_tree = proto_item_add_subtree(ti, proto_subtree_index);
    proto_tree_add_text(fh_tree, 0+offset, 1, "Code: %s (0x%02x)",
      val_to_str(code, proto_vals, "Unknown"), code);
    proto_tree_add_text(fh_tree, 1+offset, 1, "Identifier: 0x%02x",
			id);
    proto_tree_add_text(fh_tree, 2+offset, 2, "Length: %u",
			length);
  }
  offset += 4;
  length -= 4;

  switch (code) {
    case CONFREQ:
    case CONFACK:
    case CONFNAK:
    case CONFREJ:
      if(tree) {
        if (length > 0) {
          tf = proto_tree_add_text(fh_tree, offset, length,
            "Options: (%d byte%s)", length, plurality(length, "", "s"));
          field_tree = proto_item_add_subtree(tf, options_subtree_index);
          dissect_cp_opts(pd, offset, length, opt_vals,
          		opts, nopts, field_tree);
        }
      }
      break;

    case ECHOREQ:
    case ECHOREP:
    case DISCREQ:
    case IDENT:
      if(tree) {
	proto_tree_add_text(fh_tree, offset, 4, "Magic number: 0x%08x",
			pntohl(&pd[offset]));
	offset += 4;
	length -= 4;
	if (length > 0)
          proto_tree_add_text(fh_tree, offset, length, "Message (%d byte%s)",
				length, plurality(length, "", "s"));
      }
      break;

    case TIMEREMAIN:
      if(tree) {
	proto_tree_add_text(fh_tree, offset, 4, "Magic number: 0x%08x",
			pntohl(&pd[offset]));
	offset += 4;
	length -= 4;
	proto_tree_add_text(fh_tree, offset, 4, "Seconds remaining: %u",
			pntohl(&pd[offset]));
	offset += 4;
	length -= 4;
	if (length > 0)
          proto_tree_add_text(fh_tree, offset, length, "Message (%d byte%s)",
				length, plurality(length, "", "s"));
      }
      break;

    case PROTREJ:
      if(tree) {
      	protocol = pntohs(&pd[offset]);
	proto_tree_add_text(fh_tree, offset, 2, "Rejected protocol: %s (0x%04x)",
		val_to_str(protocol, ppp_vals, "Unknown"), protocol);
	offset += 2;
	length -= 2;
	if (length > 0)
          proto_tree_add_text(fh_tree, offset, length, "Rejected packet (%d byte%s)",
				length, plurality(length, "", "s"));
		/* XXX - should be dissected as a PPP packet */
      }
      break;

    case CODEREJ:
		/* decode the rejected LCP packet here. */
      if (length > 0)
        proto_tree_add_text(fh_tree, offset, length, "Rejected packet (%d byte%s)",
				length, plurality(length, "", "s"));
      break;

    case TERMREQ:
    case TERMACK:
      if (length > 0)
        proto_tree_add_text(fh_tree, offset, length, "Data (%d byte%s)",
				length, plurality(length, "", "s"));
      break;

    default:
      if (length > 0)
        proto_tree_add_text(fh_tree, offset, length, "Stuff (%d byte%s)",
				length, plurality(length, "", "s"));
      break;
  }
}

static gboolean
dissect_ppp_stuff( const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree, proto_tree *fh_tree ) {
  guint16 ppp_prot;

  ppp_prot = pntohs(&pd[offset]);

  if (tree) {
    proto_tree_add_text(fh_tree, offset, 2, "Protocol: %s (0x%04x)",
      val_to_str(ppp_prot, ppp_vals, "Unknown"), ppp_prot);
  }
  offset += 2;

  switch (ppp_prot) {
    case PPP_IP:
      dissect_ip(pd, offset, fd, tree);
      return TRUE;
    case PPP_AT:
      dissect_ddp(pd, offset, fd, tree);
      return TRUE;
    case PPP_IPX:
      dissect_ipx(pd, offset, fd, tree);
      return TRUE;
    case PPP_VINES:
      dissect_vines(pd, offset, fd, tree);
      return TRUE;
    case PPP_IPV6:
      dissect_ipv6(pd, offset, fd, tree);
      return TRUE;
    case PPP_LCP:
      dissect_cp(pd, offset, "L", "Link", ETT_LCP, lcp_vals, ETT_LCP_OPTIONS,
		lcp_opt_vals, lcp_opts, N_LCP_OPTS, fd, tree);
      return TRUE;
    case PPP_IPCP:
      dissect_cp(pd, offset, "IP", "IP", ETT_IPCP, cp_vals, ETT_IPCP_OPTIONS,
		ipcp_opt_vals, ipcp_opts, N_IPCP_OPTS, fd, tree);
      return TRUE;
    default:
      if (check_col(fd, COL_INFO))
        col_add_fstr(fd, COL_INFO, "PPP %s (0x%04x)",
		val_to_str(ppp_prot, ppp_vals, "Unknown"), ppp_prot);
      dissect_data(pd, offset, fd, tree);
      return FALSE;
  }
}

void
dissect_payload_ppp( const u_char *pd, int offset, frame_data *fd, proto_tree *tree ) {
  proto_item *ti;
  proto_tree *fh_tree = NULL;

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = proto_tree_add_item(tree, proto_ppp, 0+offset, 2, NULL);
    fh_tree = proto_item_add_subtree(ti, ETT_PPP);
  }

  dissect_ppp_stuff(pd, offset, fd, tree, fh_tree);
}

void
dissect_ppp( const u_char *pd, frame_data *fd, proto_tree *tree ) {
  e_ppphdr   ph;
  proto_item *ti;
  proto_tree *fh_tree = NULL;

  ph.ppp_addr = pd[0];
  ph.ppp_ctl  = pd[1];
  ph.ppp_prot = pntohs(&pd[2]);

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */

  if(check_col(fd, COL_RES_DL_SRC))
    col_add_str(fd, COL_RES_DL_SRC, "N/A" );
  if(check_col(fd, COL_RES_DL_DST))
    col_add_str(fd, COL_RES_DL_DST, "N/A" );
  if(check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "PPP" );

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = proto_tree_add_item(tree, proto_ppp, 0, 4, NULL);
    fh_tree = proto_item_add_subtree(ti, ETT_PPP);
    proto_tree_add_text(fh_tree, 0, 1, "Address: %02x", ph.ppp_addr);
    proto_tree_add_text(fh_tree, 1, 1, "Control: %02x", ph.ppp_ctl);
  }

  if (!dissect_ppp_stuff(pd, 2, fd, tree, fh_tree)) {
    if (check_col(fd, COL_PROTOCOL))
      col_add_fstr(fd, COL_PROTOCOL, "0x%04x", ph.ppp_prot);
  }
}

void
proto_register_ppp(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "ppp.abbreviation", TYPE, VALS_POINTER }},
        };*/

        proto_ppp = proto_register_protocol("Point-to-Point Protocol", "ppp");
 /*       proto_register_field_array(proto_ppp, hf, array_length(hf));*/
}
