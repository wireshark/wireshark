/* packet-rip.c
 * Routines for RIPv1 and RIPv2 packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-rip.c,v 1.13 1999/11/16 11:42:50 guy Exp $
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
 
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"
#include "packet-rip.h"

static int proto_rip = -1;

static gint ett_rip = -1;
static gint ett_rip_vec = -1;

static void dissect_ip_rip_vektor(guint8 version,
    const e_rip_vektor *rip_vektor, int offset, proto_tree *tree);
static void dissect_rip_authentication(const e_rip_authentication *rip_authentication,
  int offset, proto_tree *tree);

void 
dissect_rip(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    e_riphdr rip_header;
    e_rip_entry rip_entry;
    guint16 family;
    proto_tree *rip_tree = NULL;
	proto_item *ti; 

    /* we do the range checking of the index when checking wether or not this is a RIP packet */
    static char *packet_type[8] = { "never used", "Request", "Response", 
    "Traceon", "Traceoff", "Vendor specific (Sun)" };
    static char *version[3] = { "RIP", "RIPv1", "RIPv2" };

    /* avoid alignment problem */
    memcpy(&rip_header, &pd[offset], sizeof(rip_header));
  
    /* Check if we 've realy got a RIP packet */

    switch(rip_header.version) {
	case RIPv1:
            /* the domain field has to be set to zero for RIPv1 */
            if(!(rip_header.domain == 0)){ 
                dissect_data(pd, offset, fd, tree);
                return;
            }
	    /* the RIPv2 checks are also made for v1 packets */
	case RIPv2:
	    /* check wether or not command nr. is between 1-7 
	     * (range checking for index of char* packet_type is done at the same time) 
	     */
            if( !( (rip_header.command > 0) && (rip_header.command <= 7) )){ 
                dissect_data(pd, offset, fd, tree);
                return;
            }
	    break;
	default:
	    /* we only know RIPv1 and RIPv2 */
            dissect_data(pd, offset, fd, tree);
            return;
    }

    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, version[rip_header.version] );
    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, packet_type[rip_header.command]); 

    if (tree) {
	ti = proto_tree_add_item(tree, proto_rip, offset, END_OF_FRAME, NULL);
	rip_tree = proto_item_add_subtree(ti, ett_rip);

	proto_tree_add_text(rip_tree, offset, 1, "Command: %d (%s)", rip_header.command, packet_type[rip_header.command]); 
	proto_tree_add_text(rip_tree, offset + 1, 1, "Version: %d", rip_header.version);
	if(rip_header.version == RIPv2)
	    proto_tree_add_text(rip_tree, offset + 2 , 2, "Routing Domain: %d", ntohs(rip_header.domain)); 

	/* skip header */
	offset += RIP_HEADER_LENGTH;

        /* zero or more entries */

	while((pi.captured_len - offset) >= RIP_ENTRY_LENGTH){
	    memcpy(&rip_entry, &pd[offset], sizeof(rip_entry)); /* avoid alignment problem */
	    family = ntohs(rip_entry.vektor.family);
	    switch (family) {
	    case 2: /* IP */
		ti = proto_tree_add_text(rip_tree, offset,
				RIP_ENTRY_LENGTH, "IP Address: %s, Metric: %ld",
				ip_to_str((guint8 *) &(rip_entry.vektor.ip)),
				(long)ntohl(rip_entry.vektor.metric));
		dissect_ip_rip_vektor(rip_header.version, &rip_entry.vektor,
				offset, ti);
		break;
	    case 0xFFFF:
	        proto_tree_add_text(rip_tree, offset,
				RIP_ENTRY_LENGTH, "Authentication");
		dissect_rip_authentication(&rip_entry.authentication,
				offset, ti);
		break;
	    default:
	        proto_tree_add_text(rip_tree, offset,
				RIP_ENTRY_LENGTH, "Unknown address family %u",
				family);
		break;
	    }

            offset += RIP_ENTRY_LENGTH;
        }
    }
}

static void
dissect_ip_rip_vektor(guint8 version, const e_rip_vektor *rip_vektor,
  int offset, proto_tree *tree)
{
    proto_tree *rip_vektor_tree;

    rip_vektor_tree = proto_item_add_subtree(tree, ett_rip_vec);
	   
    proto_tree_add_text(rip_vektor_tree, offset, 2, "Address Family ID: IP"); 
    if(version == RIPv2)
	proto_tree_add_text(rip_vektor_tree, offset + 2 , 2, "Route Tag: %d",
				ntohs(rip_vektor->tag)); 
    proto_tree_add_text(rip_vektor_tree, offset + 4, 4, "IP Address: %s",
    				ip_to_str((guint8 *) &(rip_vektor->ip))); 
    if(version == RIPv2) {
	proto_tree_add_text(rip_vektor_tree, offset + 8 , 4, "Netmask: %s", 
				ip_to_str((guint8 *) &(rip_vektor->mask))); 
	proto_tree_add_text(rip_vektor_tree, offset + 12, 4, "Next Hop: %s", 
				ip_to_str((guint8 *) &(rip_vektor->next_hop))); 
    }
    proto_tree_add_text(rip_vektor_tree, offset + 16, 4, "Metric: %ld",
    				(long)ntohl(rip_vektor->metric)); 
}

static void
dissect_rip_authentication(const e_rip_authentication *rip_authentication,
  int offset, proto_tree *tree)
{
    proto_tree *rip_authentication_tree;
    guint16 authtype;

    rip_authentication_tree = proto_item_add_subtree(tree, ett_rip_vec);

    authtype = ntohs(rip_authentication->authtype);
    proto_tree_add_text(rip_authentication_tree, offset + 2, 2,
    				"Authentication type: %u", authtype); 
    if (authtype == 2)
	proto_tree_add_text(rip_authentication_tree, offset + 4 , 16,
				"Password: %.16s",
				rip_authentication->authentication);
}

void
proto_register_rip(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "rip.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_rip,
		&ett_rip_vec,
	};

        proto_rip = proto_register_protocol("Routing Information Protocol", "rip");
 /*       proto_register_field_array(proto_rip, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}
