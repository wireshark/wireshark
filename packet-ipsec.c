/* packet-ipsec.c
 * Routines for IPsec/IPComp packet disassembly 
 *
 * $Id: packet-ipsec.c,v 1.7 1999/10/15 05:30:40 itojun Exp $
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

#include <glib.h>
#include "packet.h"
#include "resolv.h"

static int proto_ah = -1;
static int hf_ah_spi = -1;
static int hf_ah_sequence = -1;
static int proto_esp = -1;
static int hf_esp_spi = -1;
static int hf_esp_sequence = -1;
static int proto_ipcomp = -1;
static int hf_ipcomp_cpi = -1;

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

int
dissect_ah(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *ah_tree;
	proto_item *ti;
    struct newah ah;
    int advance;

    memcpy(&ah, (void *) &pd[offset], sizeof(ah)); 
    advance = sizeof(ah) + ((ah.ah_len - 1) << 2);

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "AH");
    if (check_col(fd, COL_INFO)) {
	col_add_fstr(fd, COL_INFO, "AH (SPI=0x%08x)",
	    (guint32)ntohl(ah.ah_spi));
    }

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_item(tree, proto_ah, offset, advance, NULL);
	ah_tree = proto_item_add_subtree(ti, ETT_AH);

	proto_tree_add_text(ah_tree, offset + offsetof(struct newah, ah_nxt), 1,
	    "Next Header: %s (0x%02x)", ipprotostr(ah.ah_nxt), ah.ah_nxt);
	proto_tree_add_text(ah_tree, offset + offsetof(struct newah, ah_len), 1,
	    "Length: %d", ah.ah_len << 2);
	proto_tree_add_item_format(ah_tree, hf_ah_spi,
				   offset + offsetof(struct newah, ah_spi), 4,
				   (guint32)ntohl(ah.ah_spi),
				   "SPI: 0x%08x",
				   (guint32)ntohl(ah.ah_spi));
	proto_tree_add_item_format(ah_tree, hf_ah_sequence,
				   offset + offsetof(struct newah, ah_seq), 4,
				   (guint32)ntohl(ah.ah_seq),
				   "Sequence?: 0x%08x",
				   (guint32)ntohl(ah.ah_seq));
	proto_tree_add_text(ah_tree, offset + sizeof(ah), (ah.ah_len - 1) << 2,
	    "ICV");
    }

    /* start of the new header (could be a extension header) */
    return advance;
}

void
dissect_esp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree *esp_tree;
    proto_item *ti;
    struct newesp esp;

    memcpy(&esp, (void *) &pd[offset], sizeof(esp)); 

    /*
     * load the top pane info. This should be overwritten by
     * the next protocol in the stack
     */
    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "ESP");
    if (check_col(fd, COL_INFO)) {
	col_add_fstr(fd, COL_INFO, "ESP (SPI=0x%08x)",
	    (guint32)ntohl(esp.esp_spi));
    }

    /*
     * populate a tree in the second pane with the status of the link layer
     * (ie none)
     */
    if(tree) {
	ti = proto_tree_add_item(tree, proto_esp, offset, END_OF_FRAME, NULL);
	esp_tree = proto_item_add_subtree(ti, ETT_ESP);
	proto_tree_add_item_format(esp_tree, hf_esp_spi, 
				   offset + offsetof(struct newesp, esp_spi), 4,
				   (guint32)ntohl(esp.esp_spi),
				   "SPI: 0x%08x", 
				   (guint32)ntohl(esp.esp_spi));
	proto_tree_add_item_format(esp_tree, hf_esp_sequence,
				   offset + offsetof(struct newesp, esp_seq), 4,
				   (guint32)ntohl(esp.esp_seq),
				   "Sequence?: 0x%08x", 
				   (guint32)ntohl(esp.esp_seq));
	dissect_data(pd, offset + sizeof(struct newesp), fd, esp_tree);
    }
}

void
dissect_ipcomp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *ipcomp_tree;
    proto_item *ti;
    struct ipcomp ipcomp;
    char *p;

    memcpy(&ipcomp, (void *) &pd[offset], sizeof(ipcomp)); 

    /*
     * load the top pane info. This should be overwritten by
     * the next protocol in the stack
     */
    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "IPComp");
    if (check_col(fd, COL_INFO)) {
	p = val_to_str(ntohs(ipcomp.comp_cpi), cpi2val, "");
	if (p[0] == '\0') {
	    col_add_fstr(fd, COL_INFO, "IPComp (CPI=0x%04x)",
		ntohs(ipcomp.comp_cpi));
	} else
	    col_add_fstr(fd, COL_INFO, "IPComp (CPI=%s)", p);
    }

    /*
     * populate a tree in the second pane with the status of the link layer
     * (ie none)
     */
    if (tree) {
	ti = proto_tree_add_item(tree, proto_ipcomp, offset, END_OF_FRAME,
	    NULL);
	ipcomp_tree = proto_item_add_subtree(ti, ETT_IPCOMP);

	proto_tree_add_text(ipcomp_tree,
	    offset + offsetof(struct ipcomp, comp_nxt), 1,
	    "Next Header: %s (0x%02x)",
	    ipprotostr(ipcomp.comp_nxt), ipcomp.comp_nxt);
	proto_tree_add_text(ipcomp_tree,
	    offset + offsetof(struct ipcomp, comp_flags), 1,
	    "Flags: 0x%02x", ipcomp.comp_flags);
	p = val_to_str(ntohs(ipcomp.comp_cpi), cpi2val, "");
	if (p[0] == '\0') {
	    proto_tree_add_item(ipcomp_tree, hf_ipcomp_cpi, 
		offset + offsetof(struct ipcomp, comp_cpi), 2,
		ntohs(ipcomp.comp_cpi));
	} else {
	    proto_tree_add_item_format(ipcomp_tree, hf_ipcomp_cpi, 
		offset + offsetof(struct ipcomp, comp_cpi), 2,
		ntohs(ipcomp.comp_cpi),
		"CPI: %s (0x%04x)",
		p, ntohs(ipcomp.comp_cpi));
	}
	dissect_data(pd, offset + sizeof(struct ipcomp), fd, ipcomp_tree);
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
    { &hf_ipcomp_cpi,
      { "CPI",		"ipcomp.cpi",	FT_UINT16,	BASE_HEX, NULL, 0x0,
      	"" }},
  };

  proto_ah = proto_register_protocol("Authentication Header", "ah");
  proto_register_field_array(proto_ah, hf_ah, array_length(hf_ah));

  proto_esp = proto_register_protocol("Encapsulated Security Payload", "esp");
  proto_register_field_array(proto_esp, hf_esp, array_length(hf_esp));

  proto_ipcomp = proto_register_protocol("IP Payload Compression", "ipcomp");
  proto_register_field_array(proto_ipcomp, hf_ipcomp, array_length(hf_ipcomp));
}
