/* packet-ipsec.c
 * Routines for IPsec/IPComp packet disassembly 
 *
 * $Id: packet-ipsec.c,v 1.29 2001/04/23 03:37:31 guy Exp $
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-ipsec.h"
#include "packet-ip.h"
#include "resolv.h"
#include "ipproto.h"
#include "prefs.h"

/* Place AH payload in sub tree */
gboolean g_ah_payload_in_subtree = FALSE;

static int proto_ah = -1;
static int hf_ah_spi = -1;
static int hf_ah_sequence = -1;
static int proto_esp = -1;
static int hf_esp_spi = -1;
static int hf_esp_sequence = -1;
static int proto_ipcomp = -1;
static int hf_ipcomp_flags = -1;
static int hf_ipcomp_cpi = -1;

static gint ett_ah = -1;
static gint ett_esp = -1;
static gint ett_ipcomp = -1;

struct newah {
	guint8	ah_nxt;		/* Next Header */
	guint8	ah_len;		/* Length of data + 1, in 32bit */
	guint16	ah_reserve;	/* Reserved for future use */
	guint32	ah_spi;		/* Security parameter index */
	guint32	ah_seq;		/* Sequence number field */
	/* variable size, 32bit bound*/	/* Authentication data */
};

struct newesp {
	guint32	esp_spi;	/* ESP */
	guint32	esp_seq;	/* Sequence number */
	/*variable size*/		/* (IV and) Payload data */
	/*variable size*/		/* padding */
	/*8bit*/			/* pad size */
	/*8bit*/			/* next header */
	/*8bit*/			/* next header */
	/*variable size, 32bit bound*/	/* Authentication data */
};

struct ipcomp {
	guint8 comp_nxt;	/* Next Header */
	guint8 comp_flags;	/* Must be zero */
	guint16 comp_cpi;	/* Compression parameter index */
};

/* well-known algorithm number (in CPI), from RFC2409 */
#define IPCOMP_OUI	1	/* vendor specific */
#define IPCOMP_DEFLATE	2	/* RFC2394 */
#define IPCOMP_LZS	3	/* RFC2395 */
#define IPCOMP_MAX	4

static const value_string cpi2val[] = {
    { IPCOMP_OUI, "OUI" },
    { IPCOMP_DEFLATE, "DEFLATE" },
    { IPCOMP_LZS, "LZS" },
    { 0, NULL },
};

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

static void
dissect_ah(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *next_tree;
    guint8 nxt;
    tvbuff_t *next_tvb;
    int advance;

    advance = dissect_ah_header(tvb, pinfo, tree, &nxt, &next_tree);
    next_tvb = tvb_new_subset(tvb, advance, -1, -1);

    if (g_ah_payload_in_subtree) {
	col_set_writable(pinfo->fd, FALSE);
    }

    /* do lookup with the subdissector table */
    if (!dissector_try_port(ip_dissector_table, nxt, next_tvb, pinfo, next_tree)) {
      dissect_data(next_tvb, 0, pinfo, next_tree);
    }
}

int
dissect_ah_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		  guint8 *nxt_p, proto_tree **next_tree_p)
{
    proto_tree *ah_tree;
    proto_item *ti;
    struct newah ah;
    int advance;

    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_set_str(pinfo->fd, COL_PROTOCOL, "AH");
    if (check_col(pinfo->fd, COL_INFO))
	col_clear(pinfo->fd, COL_INFO);

    tvb_memcpy(tvb, (guint8 *)&ah, 0, sizeof(ah)); 
    advance = sizeof(ah) + ((ah.ah_len - 1) << 2);

    if (check_col(pinfo->fd, COL_INFO)) {
	col_add_fstr(pinfo->fd, COL_INFO, "AH (SPI=0x%08x)",
	    (guint32)ntohl(ah.ah_spi));
    }

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_item(tree, proto_ah, tvb, 0, advance, FALSE);
	ah_tree = proto_item_add_subtree(ti, ett_ah);

	proto_tree_add_text(ah_tree, tvb,
			    offsetof(struct newah, ah_nxt), 1,
			    "Next Header: %s (0x%02x)",
			    ipprotostr(ah.ah_nxt), ah.ah_nxt);
	proto_tree_add_text(ah_tree, tvb,
			    offsetof(struct newah, ah_len), 1,
			    "Length: %u", ah.ah_len << 2);
	proto_tree_add_uint(ah_tree, hf_ah_spi, tvb,
			    offsetof(struct newah, ah_spi), 4,
			    (guint32)ntohl(ah.ah_spi));
	proto_tree_add_uint(ah_tree, hf_ah_sequence, tvb,
			    offsetof(struct newah, ah_seq), 4,
			    (guint32)ntohl(ah.ah_seq));
	proto_tree_add_text(ah_tree, tvb,
			    sizeof(ah), (ah.ah_len - 1) << 2,
			    "ICV");

	if (next_tree_p != NULL) {
	    /* Decide where to place next protocol decode */
	    if (g_ah_payload_in_subtree) {
		*next_tree_p = ah_tree;
	    }
	    else {
		*next_tree_p = tree;
	    }
	}
    } else {
	if (next_tree_p != NULL)
	    *next_tree_p = NULL;
    }

    if (nxt_p != NULL)
	*nxt_p = ah.ah_nxt;

    /* start of the new header (could be a extension header) */
    return advance;
}

static void
dissect_esp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *esp_tree;
    proto_item *ti;
    struct newesp esp;

    /*
     * load the top pane info. This should be overwritten by
     * the next protocol in the stack
     */
    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_set_str(pinfo->fd, COL_PROTOCOL, "ESP");
    if (check_col(pinfo->fd, COL_INFO))
	col_clear(pinfo->fd, COL_INFO);

    tvb_memcpy(tvb, (guint8 *)&esp, 0, sizeof(esp)); 

    if (check_col(pinfo->fd, COL_INFO)) {
	col_add_fstr(pinfo->fd, COL_INFO, "ESP (SPI=0x%08x)",
	    (guint32)ntohl(esp.esp_spi));
    }

    /*
     * populate a tree in the second pane with the status of the link layer
     * (ie none)
     */
    if(tree) {
	ti = proto_tree_add_item(tree, proto_esp, tvb, 0,
				 tvb_length(tvb), FALSE);
	esp_tree = proto_item_add_subtree(ti, ett_esp);
	proto_tree_add_uint(esp_tree, hf_esp_spi, tvb, 
			    offsetof(struct newesp, esp_spi), 4,
			    (guint32)ntohl(esp.esp_spi));
	proto_tree_add_uint(esp_tree, hf_esp_sequence, tvb,
			    offsetof(struct newesp, esp_seq), 4,
			    (guint32)ntohl(esp.esp_seq));
	dissect_data(tvb, sizeof(struct newesp), pinfo, esp_tree);
    }
}

static void
dissect_ipcomp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *ipcomp_tree;
    proto_item *ti;
    struct ipcomp ipcomp;
    char *p;

    /*
     * load the top pane info. This should be overwritten by
     * the next protocol in the stack
     */
    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_set_str(pinfo->fd, COL_PROTOCOL, "IPComp");
    if (check_col(pinfo->fd, COL_INFO))
	col_clear(pinfo->fd, COL_INFO);

    tvb_memcpy(tvb, (guint8 *)&ipcomp, 0, sizeof(ipcomp)); 

    if (check_col(pinfo->fd, COL_INFO)) {
	p = match_strval(ntohs(ipcomp.comp_cpi), cpi2val);
	if (p == NULL) {
	    col_add_fstr(pinfo->fd, COL_INFO, "IPComp (CPI=0x%04x)",
		ntohs(ipcomp.comp_cpi));
	} else
	    col_add_fstr(pinfo->fd, COL_INFO, "IPComp (CPI=%s)", p);
    }

    /*
     * populate a tree in the second pane with the status of the link layer
     * (ie none)
     */
    if (tree) {
	ti = proto_tree_add_item(tree, proto_ipcomp, tvb, 0,
	    tvb_length(tvb), FALSE);
	ipcomp_tree = proto_item_add_subtree(ti, ett_ipcomp);

	proto_tree_add_text(ipcomp_tree, tvb,
	    offsetof(struct ipcomp, comp_nxt), 1,
	    "Next Header: %s (0x%02x)",
	    ipprotostr(ipcomp.comp_nxt), ipcomp.comp_nxt);
	proto_tree_add_uint(ipcomp_tree, hf_ipcomp_flags, tvb,
	    offsetof(struct ipcomp, comp_flags), 1,
	    ipcomp.comp_flags);
	proto_tree_add_uint(ipcomp_tree, hf_ipcomp_cpi, tvb, 
	    offsetof(struct ipcomp, comp_cpi), 2,
	    ntohs(ipcomp.comp_cpi));
	dissect_data(tvb, sizeof(struct ipcomp), pinfo, ipcomp_tree);
    }
}

void
proto_register_ipsec(void)
{

  static hf_register_info hf_ah[] = {
    { &hf_ah_spi,
      { "SPI",		"ah.spi",	FT_UINT32,	BASE_HEX, NULL, 0x0,
      	"" }},
    { &hf_ah_sequence,
      { "Sequence",     "ah.sequence",	FT_UINT32,	BASE_HEX, NULL, 0x0,
      	"" }}
  };

  static hf_register_info hf_esp[] = {
    { &hf_esp_spi,
      { "SPI",		"esp.spi",	FT_UINT32,	BASE_HEX, NULL, 0x0,
      	"" }},
    { &hf_esp_sequence,
      { "Sequence",     "esp.sequence",	FT_UINT32,	BASE_HEX, NULL, 0x0,
      	"" }}
  };

  static hf_register_info hf_ipcomp[] = {
    { &hf_ipcomp_flags,
      { "Flags",	"ipcomp.flags",	FT_UINT8,	BASE_HEX, NULL, 0x0,
      	"" }},
    { &hf_ipcomp_cpi,
      { "CPI",		"ipcomp.cpi",	FT_UINT16,	BASE_HEX, 
        VALS(cpi2val),	0x0,      	"" }},
  };
  static gint *ett[] = {
    &ett_ah,
    &ett_esp,
    &ett_ipcomp,
  };

  module_t *ah_module;

  proto_ah = proto_register_protocol("Authentication Header", "AH", "ah");
  proto_register_field_array(proto_ah, hf_ah, array_length(hf_ah));

  proto_esp = proto_register_protocol("Encapsulating Security Payload",
				      "ESP", "esp");
  proto_register_field_array(proto_esp, hf_esp, array_length(hf_esp));

  proto_ipcomp = proto_register_protocol("IP Payload Compression",
					 "IPComp", "ipcomp");
  proto_register_field_array(proto_ipcomp, hf_ipcomp, array_length(hf_ipcomp));

  proto_register_subtree_array(ett, array_length(ett));

  /* Register a configuration option for placement of AH payload dissection */
  ah_module = prefs_register_protocol(proto_ah, NULL);
  prefs_register_bool_preference(ah_module, "place_ah_payload_in_subtree",
	    "Place AH payload in subtree",
"Whether the AH payload decode should be placed in a subtree",
	    &g_ah_payload_in_subtree);
}

void
proto_reg_handoff_ipsec(void)
{
  dissector_add("ip.proto", IP_PROTO_AH, dissect_ah, proto_ah);
  dissector_add("ip.proto", IP_PROTO_ESP, dissect_esp, proto_esp);
  dissector_add("ip.proto", IP_PROTO_IPCOMP, dissect_ipcomp, proto_ipcomp);
}
