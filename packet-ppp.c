/* packet-ppp.c
 * Routines for ppp packet disassembly
 *
 * $Id: packet-ppp.c,v 1.15 1999/08/25 03:56:07 guy Exp $
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
	{PPP_COMP,		  "compressed packet" },
	{PPP_IPCP,		  "IP Control Protocol" },
	{PPP_ATCP,		  "AppleTalk Control Protocol" },
	{PPP_IPXCP,	    "IPX Control Protocol" },
	{PPP_CCP,		    "Compression Control Protocol" },
	{PPP_LCP,		    "Link Control Protocol" },
	{PPP_PAP,		    "Password Authentication Protocol"  },
	{PPP_LQR,		    "Link Quality Report protocol" },
	{PPP_CHAP,		  "Cryptographic Handshake Auth. Protocol" },
	{PPP_CBCP,		  "Callback Control Protocol" },
	{0,             NULL            } };

/* CP (LCP, IPCP, etc.) codes.
 * from pppd fsm.h 
 */
#define CONFREQ   1 /* Configuration Request */
#define CONFACK   2 /* Configuration Ack */
#define CONFNAK   3 /* Configuration Nak */
#define CONFREJ   4 /* Configuration Reject */
#define TERMREQ   5 /* Termination Request */
#define TERMACK   6 /* Termination Ack */
#define CODEREJ   7 /* Code Reject */

static const value_string cp_vals[] = {
	{CONFREQ,    "Configuration Request " },
	{CONFACK,    "Configuration Ack " },
	{CONFNAK,    "Configuration Nak " },
	{CONFREJ,    "Configuration Reject " },
	{TERMREQ,    "Termination Request " },
	{TERMACK,    "Termination Ack " },
	{CODEREJ,    "Code Reject " },
	{0,             NULL            } };

/*
 * LCP-specific packet types.
 */
#define PROTREJ   8 /* Protocol Reject */
#define ECHOREQ   9 /* Echo Request */
#define ECHOREP   10  /* Echo Reply */
#define DISCREQ   11  /* Discard Request */
#define CBCP_OPT  6 /* Use callback control protocol */

static const value_string lcp_vals[] = {
	{CONFREQ,    "Configuration Request " },
	{CONFACK,    "Configuration Ack " },
	{CONFNAK,    "Configuration Nak " },
	{CONFREJ,    "Configuration Reject " },
	{TERMREQ,    "Termination Request " },
	{TERMACK,    "Termination Ack " },
	{CODEREJ,    "Code Reject " },
	{PROTREJ, "Protocol Reject " },
	{ECHOREQ, "Echo Request " },
	{ECHOREP, "Echo Reply " },
	{DISCREQ, "Discard Request " },
	{CBCP_OPT, "Use callback control protocol" },
	{0,             NULL            } };

/*
 * Options.  (LCP)
 */
#define CI_MRU    1 /* Maximum Receive Unit */
#define CI_ASYNCMAP 2 /* Async Control Character Map */
#define CI_AUTHTYPE 3 /* Authentication Type */
#define CI_QUALITY  4 /* Quality Protocol */
#define CI_MAGICNUMBER  5 /* Magic Number */
#define CI_PCOMPRESSION 7 /* Protocol Field Compression */
#define CI_ACCOMPRESSION 8  /* Address/Control Field Compression */
#define CI_CALLBACK 13  /* callback */

static const value_string lcp_opt_vals[] = {
	{CI_MRU,          "Maximum Receive Unit" },
	{CI_ASYNCMAP,     "Async Control Character Map" },
	{CI_AUTHTYPE,     "Authentication Type" },
	{CI_QUALITY,      "Quality Protocol" },
	{CI_MAGICNUMBER,  "Magic Number" },
	{CI_PCOMPRESSION, "Protocol Field Compression" },
	{CI_ACCOMPRESSION,"Address/Control Field Compression" },
	{CI_CALLBACK,     "callback" },
	{0,             NULL            } };

/*
 * Options.  (IPCP)
 */
#define CI_ADDRS  1 /* IP Addresses */
#define CI_COMPRESSTYPE 2 /* Compression Type */
#define CI_ADDR   3
#define CI_MS_DNS1  129 /* Primary DNS value */
#define CI_MS_WINS1 130 /* Primary WINS value */
#define CI_MS_DNS2  131 /* Secondary DNS value */
#define CI_MS_WINS2 132 /* Secondary WINS value */

static const value_string ipcp_opt_vals[] = {
	{CI_ADDRS,       "IP Addresses" },
	{CI_COMPRESSTYPE,"Compression Type" },
	{CI_ADDR,        "Address" }, 
	{CI_MS_DNS1,     "Primary DNS value" },
	{CI_MS_WINS1,    "Primary WINS value" },
	{CI_MS_DNS2,     "Secondary DNS value" },
	{CI_MS_WINS2,    "Secondary WINS value" },
	{0,             NULL            } };

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

void
dissect_ipcp( const u_char *pd, int offset, frame_data *fd, proto_tree *tree ) {
  proto_tree *fh_tree;
  proto_item *ti;

	int ipcpcode;
	int ipcpid;
	int optionslength;

	ipcpcode = pd[0+offset];
	ipcpid = pd[1+offset];
	optionslength= pntohs(&pd[2+offset]);
	
	if(check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "IPCP %s", 
			val_to_str(ipcpcode, cp_vals, "Unknown"));

  if(tree) {
    ti = proto_tree_add_text(tree, 0+offset, 4, "IP Control Protocol" );
    fh_tree = proto_item_add_subtree(ti, ETT_IPCP);
    proto_tree_add_text(fh_tree, 0+offset, 1, "Code: %s (0x%02x)",
      val_to_str(ipcpcode, cp_vals, "Unknown"), ipcpcode);
    proto_tree_add_text(fh_tree, 1+offset, 1, "Identifier: 0x%02x",
			ipcpid);
    proto_tree_add_text(fh_tree, 2+offset, 2, "Length: %d",
			optionslength);
  }

  switch (ipcpcode) {
		/* decode lcp options here. */
    default:
      dissect_data(pd, 4+offset, fd, tree);
      break;
  }
}

void
dissect_lcp( const u_char *pd, int offset, frame_data *fd, proto_tree *tree ) {
  proto_tree *fh_tree;
  proto_item *ti;

	int lcpcode;
	int lcpid;
	int optionslength;

	lcpcode = pd[0+offset];
	lcpid = pd[1+offset];
	optionslength= pntohs(&pd[2+offset]);
	
	if(check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "LCP %s", 
			val_to_str(lcpcode, lcp_vals, "Unknown"));

  if(tree) {
    ti = proto_tree_add_text(tree, 0+offset, 4, "Link Control Protocol" );
    fh_tree = proto_item_add_subtree(ti, ETT_LCP);
    proto_tree_add_text(fh_tree, 0+offset, 1, "Code: %s (0x%02x)",
      val_to_str(lcpcode, lcp_vals, "Unknown"), lcpcode);
    proto_tree_add_text(fh_tree, 1+offset, 1, "Identifier: 0x%02x",
			lcpid);
    proto_tree_add_text(fh_tree, 2+offset, 2, "Length: %d",
			optionslength);
  }

  switch (lcpcode) {
		/* decode lcp options here. */
    default:
      dissect_data(pd, 4+offset, fd, tree);
      break;
  }
}

static gboolean
dissect_ppp_stuff( const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree, proto_tree *fh_tree ) {
  guint16 ppp_prot;
  static const value_string ppp_vals[] = {
    {PPP_IP,     "IP"                                 },
    {PPP_AT,     "Appletalk"                          },
    {PPP_IPX,    "Netware IPX/SPX"                    },
    {PPP_VINES,  "Vines"                              },
    {PPP_IPV6,   "IPv6"                               },
    {PPP_LCP,    "Link Control Protocol"              },
    {PPP_IPCP,   "Internet Protocol Control Protocol" },
    {0,          NULL                                 } };

  ppp_prot = pntohs(&pd[0+offset]);

  if (tree) {
    proto_tree_add_text(fh_tree, 0+offset, 2, "Protocol: %s (0x%04x)",
      val_to_str(ppp_prot, ppp_vals, "Unknown"), ppp_prot);
  }

  switch (ppp_prot) {
    case PPP_IP:
      dissect_ip(pd, 2+offset, fd, tree);
      return TRUE;
    case PPP_AT:
      dissect_ddp(pd, 2+offset, fd, tree);
      return TRUE;
    case PPP_IPX:
      dissect_ipx(pd, 2+offset, fd, tree);
      return TRUE;
    case PPP_VINES:
      dissect_vines(pd, 2+offset, fd, tree);
      return TRUE;
    case PPP_IPV6:
      dissect_ipv6(pd, 2+offset, fd, tree);
      return TRUE;
    case PPP_LCP:
      dissect_lcp(pd, 2+offset, fd, tree);
      return TRUE;
    case PPP_IPCP:
      dissect_ipcp(pd, 2+offset, fd, tree);
      return TRUE;
    default:
      if (check_col(fd, COL_INFO))
        col_add_fstr(fd, COL_INFO, "PPP %s (0x%04x)",
		val_to_str(ppp_prot, ppp_vals, "Unknown"), ppp_prot);
      dissect_data(pd, 2+offset, fd, tree);
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
