/* packet-teredo.c  v.1.0
 * Routines for TEREDO packet disassembly
 *   draft-huitema-v6ops-teredo-00.txt
 *   Windows XP Teredo
 *
 * Copyright 2003, Ragi BEJJANI - 6WIND - <ragi.bejjani@6wind.com>
 * Copyright 2003, Vincent JARDIN - 6WIND - <vincent.jardin@6wind.com>
 *
 * $Id: packet-teredo.c,v 1.4 2003/12/29 00:19:00 guy Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/resolv.h>
#include "ipproto.h"
#include "prefs.h"

#include "packet-ip.h"
#include "tap.h"

#define UDP_PORT_TERREDO 3544

static int teredo_tap = -1;

static int proto_teredo = -1;
static int hf_teredo_orgheader = -1;
static int hf_teredo_authheader = -1;
static int hf_teredo_orgport = -1;
static int hf_teredo_orgaddr = -1;

static gint ett_teredo = -1;

typedef struct {
	guint16 th_indtyp;
	guint8 th_cidlen;
	guint8 th_authdlen;
	guint8 th_nonce[8];
	guint8 th_conf; 

	guint8 th_ip_v_hl;  
	guint16 th_header;
	guint16 th_orgport;
	guint32 th_iporgaddr;
} e_teredohdr;

/* Place TEREDO summary in proto tree */
static gboolean teredo_summary_in_tree = TRUE;

static dissector_table_t teredo_dissector_table;
/*static heur_dissector_list_t heur_subdissector_list;*/
static dissector_handle_t data_handle;

/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine to other protocol dissectors */
/* can call to it, ie. socks	*/


static void
decode_teredo_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,proto_tree *tree, int th_header)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, -1, -1);

	if (dissector_try_port(teredo_dissector_table, th_header, next_tvb, pinfo, tree))
		return;

	call_dissector(data_handle,next_tvb, pinfo, tree);  
}

static void
dissect_teredo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *teredo_tree;
	proto_item *ti;
	int        offset = 0;
	static e_teredohdr teredohstruct[4], *teredoh;
	static int teredoh_count = 0;

	proto_item *to;
	proto_tree *teredo_origin_tree;

	teredoh_count++;
	if(teredoh_count>=4){
		teredoh_count=0;
	}
	teredoh = &teredohstruct[teredoh_count];

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TEREDO");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	teredoh->th_header  = tvb_get_ntohs(tvb, offset);
	teredoh->th_ip_v_hl = tvb_get_guint8(tvb, offset);
	teredoh->th_indtyp  = 0;

	if ( (teredoh->th_header)== 1 ) {
		teredoh->th_indtyp   = teredoh->th_header;
		teredoh->th_cidlen   = tvb_get_guint8(tvb,offset+2);     /*Authentication header octet*/
		teredoh->th_authdlen = tvb_get_guint8(tvb,offset+3);
		tvb_memcpy(tvb,teredoh->th_nonce,offset+4,sizeof teredoh->th_nonce);
		teredoh->th_conf     = tvb_get_guint8(tvb,offset+12);

		/*Skip over Authentication Header (fixed length-no authentication)*/
		offset+=13;
		teredoh->th_header  = tvb_get_ntohs(tvb, offset);
		teredoh->th_ip_v_hl = tvb_get_guint8(tvb, offset);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO,
				"Teredo : Tunneling IPv6 over UDP through NATs");

		proto_tree_add_uint_hidden(tree, hf_teredo_authheader, tvb, offset-13, 2, teredoh->th_indtyp);	

		if (teredo_summary_in_tree) {

			if (teredoh->th_header!=0) {
				ti = proto_tree_add_protocol_format(tree, proto_teredo, tvb, offset-13, 13,
					"TEREDO with Authentication encapsulation"); 
			}

        } else {
			ti = proto_tree_add_item(tree, proto_teredo, tvb, offset, 13, FALSE);
		}
	}

	if ( (teredoh->th_header)== 0 ) {
		teredoh->th_orgport=tvb_get_ntohs(tvb, offset+2);
		tvb_memcpy(tvb, (guint8 *)&teredoh->th_iporgaddr, offset + 4, 4);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO,
				"Teredo : Tunneling IPv6 over UDP through NATs");

		if (tree) {
			if (teredo_summary_in_tree) { 
				if (teredoh->th_indtyp==1){
					to = proto_tree_add_protocol_format(tree, proto_teredo, tvb, offset-13, 13+8,
						"TEREDO with Authentication and Origin Indicator encapsulation");  
					teredo_tree = proto_item_add_subtree(to, ett_teredo);
					proto_tree_add_protocol_format(teredo_tree,proto_teredo, tvb,offset-13, 13,
						"Authentication encapsulation");
					ti = proto_tree_add_protocol_format(teredo_tree, proto_teredo, tvb, offset, 8,
						"Origin indicator encapsulation")  ;
				} else { 
					ti = proto_tree_add_protocol_format(tree, proto_teredo, tvb, offset, 8,
						"TEREDO with Origin indicator encapsulation");
				}
			} else {
				ti = proto_tree_add_item(tree, proto_teredo, tvb, offset, 8, FALSE);
			}

			teredo_origin_tree = proto_item_add_subtree(ti, ett_teredo);

			proto_tree_add_uint_format(teredo_origin_tree, hf_teredo_orgheader, tvb, offset, 2,
				teredoh->th_header,
				"Teredo Origin encapsulation header: 0x%04x",
					(teredoh->th_header));
			proto_tree_add_uint_format(teredo_origin_tree, hf_teredo_orgport, tvb, offset + 2, 2,
				teredoh->th_orgport,
				"Origin port:  %u",
					((teredoh->th_orgport)^(0xFFFF)));
			proto_tree_add_ipv4_format(teredo_origin_tree, hf_teredo_orgaddr, tvb, offset + 4, 4,
				teredoh->th_iporgaddr,
				"Origin address: %s",
					get_hostname((teredoh->th_iporgaddr)^(0xFFFFFFFF)));

			proto_tree_add_uint_hidden(teredo_origin_tree, hf_teredo_orgheader, tvb, offset, 2,
				teredoh->th_header);
			proto_tree_add_uint_hidden(teredo_origin_tree, hf_teredo_orgport, tvb, offset+2, 2,
				((teredoh->th_orgport)^(0xFFFF)));
			proto_tree_add_ipv4_hidden(teredo_origin_tree, hf_teredo_orgaddr, tvb, offset + 4, 4,
				((teredoh->th_iporgaddr)^(0xFFFFFFFF)));
		};

		offset+=8; /*Skip over Origin Header*/ 
	};

	if ( (hi_nibble(teredoh->th_ip_v_hl) == 6)
		&& ((teredoh->th_indtyp) != 1) ) { /* checking if the first 4 bits = 6 */

		if (tree) {
			if (teredo_summary_in_tree) {
				ti = proto_tree_add_protocol_format(tree, proto_teredo, tvb, offset, 0,"TEREDO simple encapsulation  ");
			}
		}

		offset+=0;
	}

	decode_teredo_ports(tvb, offset, pinfo, tree, teredoh->th_header /* , teredoh->th_orgport*/);
	tap_queue_packet(teredo_tap, pinfo, teredoh);    
}

void
proto_register_teredo(void)
{
	static hf_register_info hf[] = {

		{ &hf_teredo_authheader,
		{ "Teredo Authentication packet Header","teredo.authheader", FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }},

		{ &hf_teredo_orgheader,
		{ "Teredo Origin encapsulation header","teredo.orgheader", FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }},

		{ &hf_teredo_orgport,
		{ "Origin Port",	"teredo.orgport", FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }},

		{ &hf_teredo_orgaddr,
		{ "Origin IPv4 address","teredo.orgaddr", FT_IPv4, BASE_NONE, NULL, 0x0,"", HFILL }},

	};

	static gint *ett[] = {
		&ett_teredo,
	};

	proto_teredo = proto_register_protocol("TEREDO Tunneling IPv6 over UDP through NATs",
	    "TEREDO", "teredo");
	proto_register_field_array(proto_teredo, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
	teredo_dissector_table = register_dissector_table("teredo","TEREDO ", FT_UINT16, BASE_DEC);
/*	register_heur_dissector_list("teredo.heur", &heur_subdissector_list); */

}

void
proto_reg_handoff_teredo(void)
{
	dissector_handle_t teredo_handle;

	teredo_handle = create_dissector_handle(dissect_teredo, proto_teredo);
	data_handle   = find_dissector("ipv6");
	teredo_tap    = register_tap("teredo");

	dissector_add("udp.port", UDP_PORT_TERREDO, teredo_handle);
}

