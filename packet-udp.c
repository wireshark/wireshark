/* packet-udp.c
 * Routines for UDP packet disassembly
 *
 * $Id: packet-udp.c,v 1.49 2000/02/09 19:09:02 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Richard Sharpe, 13-Feb-1999, added dispatch table support and 
 *                              support for tftp.
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
#include <stdlib.h>

#include <glib.h>
#include "globals.h"
#include "resolv.h"

#include "plugins.h"

static int proto_udp = -1;		
static int hf_udp_srcport = -1;
static int hf_udp_dstport = -1;
static int hf_udp_port = -1;
static int hf_udp_length = -1;
static int hf_udp_checksum = -1;

static gint ett_udp = -1;

/* UDP structs and definitions */

typedef struct _e_udphdr {
  guint16 uh_sport;
  guint16 uh_dport;
  guint16 uh_ulen;
  guint16 uh_sum;
} e_udphdr;

/* UDP Ports -> should go in packet-udp.h */

#define UDP_PORT_TIME    37
#define UDP_PORT_TACACS  49
#define UDP_PORT_DNS     53
#define UDP_PORT_BOOTPS  67
#define UDP_PORT_TFTP    69
#define UDP_PORT_IPX    213
#define UDP_PORT_NTP	123
#define UDP_PORT_NBNS	137
#define UDP_PORT_NBDGM	138
#define UDP_PORT_SNMP   161
#define UDP_PORT_SNMP_TRAP 162
#define UDP_PORT_SRVLOC 427
#define UDP_PORT_PIM_RP_DISC 496
#define UDP_PORT_ISAKMP	500
#define UDP_PORT_WHO    513
#define UDP_PORT_RIP    520
#define UDP_PORT_RIPNG  521
#define UDP_PORT_NCP    524
#define UDP_PORT_VINES	573
#define UDP_PORT_RADIUS 1645
#define UDP_PORT_L2TP   1701
#define UDP_PORT_RADIUS_NEW 1812
#define UDP_PORT_RADACCT 1646
#define UDP_PORT_RADACCT_NEW 1813
#define UDP_PORT_HSRP   1985
#define UDP_PORT_ICP    3130
#define UDP_PORT_ICQ	4000
#define UDP_PORT_SAP	9875
#define UDP_PORT_RX_LOW 7000
#define UDP_PORT_RX_HIGH 7009
#define UDP_PORT_RX_AFS_BACKUPS 7021
#define UDP_PORT_WCCP	2048

struct hash_struct {
  guint16 proto;
  void (*dissect)(const u_char *, int, frame_data *, proto_tree *);
  struct hash_struct *next;
};

static struct hash_struct *hash_table[256];

/*
 * These routines are for UDP, will be generalized soon: RJS
 *
 * XXX - note that they should probably check the IP address as well as
 * the port number, so that we don't mistakenly identify packets as, say,
 * TFTP, merely because they have a source or destination port number
 * equal to the port being used by a TFTP daemon on some machine other
 * than the one they're going to or from.
 */

struct hash_struct *udp_find_hash_ent(guint16 proto) {

  int idx = proto % 256;
  struct hash_struct *hash_ent = hash_table[idx];

  while (hash_ent != NULL) {

    if (hash_ent -> proto == proto)
      return hash_ent;
  
    hash_ent = hash_ent -> next;

  }

  return NULL;

}

void udp_hash_add(guint16 proto,
	void (*dissect)(const u_char *, int, frame_data *, proto_tree *)) {

  int idx = proto % 256;   /* Simply take the remainder, hope for no collisions */
  struct hash_struct *hash_ent = (struct hash_struct *)malloc(sizeof(struct hash_struct));
  struct hash_struct *hash_ent2;
  
  hash_ent -> proto = proto;
  hash_ent -> dissect = dissect;
  hash_ent -> next = NULL;

  if (hash_ent == NULL) {

    fprintf(stderr, "Could not allocate space for hash structure in dissect_udp\n");
    exit(1);
  }

  if (hash_table[idx]) {  /* Something, add on end */

    hash_ent2 = hash_table[idx];

    while (hash_ent2 -> next != NULL)
      hash_ent2 = hash_ent2 -> next;

    hash_ent2 -> next = hash_ent;     /* Bad in pathalogical cases */

  }
  else {

    hash_table[idx] = hash_ent;

  }

}

void init_dissect_udp(void) {

  int i;

  for (i = 0; i < 256; i++) {

    hash_table[i] = NULL;

  }

  /* Now add the protocols we know about */

  udp_hash_add(UDP_PORT_BOOTPS, dissect_bootp);
  udp_hash_add(UDP_PORT_TFTP, dissect_tftp);
  udp_hash_add(UDP_PORT_SAP, dissect_sap);
  udp_hash_add(UDP_PORT_HSRP, dissect_hsrp);
  udp_hash_add(UDP_PORT_PIM_RP_DISC, dissect_auto_rp);
  udp_hash_add(UDP_PORT_TACACS, dissect_tacacs);
}

void
dissect_udp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  e_udphdr  uh;
  guint16    uh_sport, uh_dport, uh_ulen, uh_sum;
  struct hash_struct *dissect_routine = NULL;
  proto_tree *udp_tree;
  proto_item *ti;

  if (!BYTES_ARE_IN_FRAME(offset, sizeof(e_udphdr))) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* Avoids alignment problems on many architectures. */
  memcpy(&uh, &pd[offset], sizeof(e_udphdr));
  uh_sport = ntohs(uh.uh_sport);
  uh_dport = ntohs(uh.uh_dport);
  uh_ulen  = ntohs(uh.uh_ulen);
  uh_sum   = ntohs(uh.uh_sum);
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "UDP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "Source port: %s  Destination port: %s",
	    get_udp_port(uh_sport), get_udp_port(uh_dport));
    
  if (tree) {
    ti = proto_tree_add_item(tree, proto_udp, offset, 8);
    udp_tree = proto_item_add_subtree(ti, ett_udp);

    proto_tree_add_item_format(udp_tree, hf_udp_srcport, offset, 2, uh_sport,
	"Source port: %s (%u)", get_udp_port(uh_sport), uh_sport);
    proto_tree_add_item_format(udp_tree, hf_udp_dstport, offset + 2, 2, uh_dport,
	"Destination port: %s (%u)", get_udp_port(uh_dport), uh_dport);

    proto_tree_add_item_hidden(udp_tree, hf_udp_port, offset, 2, uh_sport);
    proto_tree_add_item_hidden(udp_tree, hf_udp_port, offset+2, 2, uh_dport);

    proto_tree_add_item(udp_tree, hf_udp_length, offset + 4, 2,  uh_ulen);
    proto_tree_add_item_format(udp_tree, hf_udp_checksum, offset + 6, 2, uh_sum,
	"Checksum: 0x%04x", uh_sum);
  }

  /* Skip over header */
  offset += 8;

  pi.ptype = PT_UDP;
  pi.srcport = uh_sport;
  pi.destport = uh_dport;

  /* ONC RPC.  We can't base this on anything in the UDP header; we have
     to look at the payload.  If "dissect_rpc()" returns TRUE, it was
     an RPC packet, otherwise it's some other type of packet. */
  if (dissect_rpc(pd, offset, fd, tree))
    return;

  /* try to apply the plugins */
#ifdef HAVE_PLUGINS
  {
      plugin *pt_plug = plugin_list;

      if (pt_plug) {
	  while (pt_plug) {
	      if (pt_plug->enabled && !strcmp(pt_plug->protocol, "udp") &&
		  tree && dfilter_apply(pt_plug->filter, tree, pd)) {
		  pt_plug->dissector(pd, offset, fd, tree);
		  return;
	      }
	      pt_plug = pt_plug->next;
	  }
      }
  }
#endif

  /* XXX - we should do all of this through the table of ports. */
#define PORT_IS(port)	(uh_sport == port || uh_dport == port)
  if (PORT_IS(UDP_PORT_BOOTPS))
      dissect_bootp(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_DNS))
      dissect_dns(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_SRVLOC))
      dissect_srvloc(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_ISAKMP))
      dissect_isakmp(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_RIP)) {
      /* we should check the source port too (RIP: UDP src and dst port 520) */
      dissect_rip(pd, offset, fd, tree);
  } else if (PORT_IS(UDP_PORT_RIPNG))
      dissect_ripng(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_NCP))
      dissect_ncp(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_NBNS))
      dissect_nbns(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_NBDGM))
      dissect_nbdgm(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_NTP))
      dissect_ntp(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_WHO))
      dissect_who(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_IPX)) /* RFC 1234 */
      dissect_ipx(pd, offset, fd, tree);
  else if ((uh_sport >= UDP_PORT_RX_LOW && uh_sport <= UDP_PORT_RX_HIGH) ||
	(uh_dport >= UDP_PORT_RX_LOW && uh_dport <= UDP_PORT_RX_HIGH) ||
	PORT_IS(UDP_PORT_RX_AFS_BACKUPS)) 
      dissect_rx(pd, offset, fd, tree); /* transarc AFS's RX protocol */
  else if (PORT_IS(UDP_PORT_SNMP) || PORT_IS(UDP_PORT_SNMP_TRAP))
      dissect_snmp(pd, offset, fd, tree);
  else if (PORT_IS(UDP_PORT_VINES)) {
      /* FIXME: AFAIK, src and dst port must be the same */
      dissect_vines_frp(pd, offset, fd, tree);
  } else if (PORT_IS(UDP_PORT_TFTP)) {
      /* This is the first point of call, but it adds a dynamic call */
      udp_hash_add(MAX(uh_sport, uh_dport), dissect_tftp);  /* Add to table */
      dissect_tftp(pd, offset, fd, tree);
  } else if (PORT_IS(UDP_PORT_TIME)) {
      dissect_time(pd, offset, fd, tree);
  } else if (PORT_IS(UDP_PORT_RADIUS) ||
		PORT_IS(UDP_PORT_RADACCT) ||
		PORT_IS(UDP_PORT_RADIUS_NEW) ||
		PORT_IS(UDP_PORT_RADACCT_NEW) ) {
      dissect_radius(pd, offset, fd, tree);
   } else if ( PORT_IS(UDP_PORT_L2TP)) {
      dissect_l2tp(pd,offset,fd,tree);
  } else if ( PORT_IS(UDP_PORT_ICP)) {
	dissect_icp(pd,offset,fd,tree);
 } else if ( PORT_IS(UDP_PORT_ICQ)) {
        dissect_icq(pd,offset,fd,tree);
 } else if (PORT_IS(UDP_PORT_WCCP) ) {
 	dissect_wccp(pd, offset, fd, tree);
 } else {
      /* OK, find a routine in the table, else use the default */

      if ((dissect_routine = udp_find_hash_ent(uh_sport))) {

	struct hash_struct *dr2 = udp_find_hash_ent(uh_dport);

	if (dr2 == NULL) {  /* Not in the table, add */

	  udp_hash_add(uh_dport, dissect_tftp);

	}

	dissect_routine -> dissect(pd, offset, fd, tree);
      }
      else if ((dissect_routine = udp_find_hash_ent(uh_dport))) {

	dissect_routine -> dissect(pd, offset, fd, tree);

      }
      else {

	dissect_data(pd, offset, fd, tree);
      }
  }
}

void
proto_register_udp(void)
{
	static hf_register_info hf[] = {
		{ &hf_udp_srcport,
		{ "Source Port",	"udp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_udp_dstport,
		{ "Destination Port",	"udp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_udp_port,
		{ "Source or Destination Port",	"udp.port", FT_UINT16, BASE_DEC,  NULL, 0x0,
			"" }},

		{ &hf_udp_length,
		{ "Length",		"udp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_udp_checksum,
		{ "Checksum",		"udp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},
	};
	static gint *ett[] = {
		&ett_udp,
	};

	proto_udp = proto_register_protocol("User Datagram Protocol", "udp");
	proto_register_field_array(proto_udp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
