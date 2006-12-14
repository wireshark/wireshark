/* packet-k12.c
* Routines for displaying frames from k12 rf5 files
*
* Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
*
* $Id$
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998
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
#include <errno.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <prefs.h>
#include <epan/report_err.h>
#include <epan/emem.h>

static int proto_k12 = -1;

static int hf_k12_port_id = -1;
static int hf_k12_port_name = -1;
static int hf_k12_stack_file = -1;
static int hf_k12_port_type = -1;
static int hf_k12_atm_vp = -1;
static int hf_k12_atm_vc = -1;
static int hf_k12_atm_cid = -1;

static int hf_k12_ts = -1;

static gint ett_k12 = -1;
static gint ett_port = -1;

static dissector_handle_t k12_handle;
static dissector_handle_t data_handle;

static module_t *k12_module;

static const char* k12_config_filename = "";

static GHashTable* k12_cfg = NULL;


static const value_string  k12_port_types[] = {
	{	K12_PORT_DS1, "Ds1" },
	{	K12_PORT_DS0S, "Ds0 Range" },
	{	K12_PORT_ATMPVC, "ATM PVC" },
	{ 0,NULL}
};


static void dissect_k12(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) {
	proto_item* k12_item;
	proto_tree* k12_tree;
	dissector_handle_t sub_handle;

	k12_item = proto_tree_add_protocol_format(tree, proto_k12, tvb, 0, 0, "Packet from: '%s' (0x%.8x)",
											  pinfo->pseudo_header->k12.input_name,
											  pinfo->pseudo_header->k12.input);

	k12_tree = proto_item_add_subtree(k12_item, ett_k12);

	proto_tree_add_uint(k12_tree, hf_k12_port_id, tvb, 0,0,pinfo->pseudo_header->k12.input);
	proto_tree_add_string(k12_tree, hf_k12_port_name, tvb, 0,0,pinfo->pseudo_header->k12.input_name);
	proto_tree_add_string(k12_tree, hf_k12_stack_file, tvb, 0,0,pinfo->pseudo_header->k12.stack_file);

	k12_item = proto_tree_add_uint(k12_tree, hf_k12_port_type, tvb, 0, 0,
								   pinfo->pseudo_header->k12.input_type);

	k12_tree = proto_item_add_subtree(k12_item, ett_port);

	switch ( pinfo->pseudo_header->k12.input_type ) {
		case K12_PORT_DS0S:
			proto_tree_add_uint(k12_tree, hf_k12_ts, tvb, 0,0,pinfo->pseudo_header->k12.input_info.ds0mask);
			break;
		case K12_PORT_ATMPVC:
        {
            gchar* circuit_str = ep_strdup_printf("%u:%u:%u",
                                                  (guint)pinfo->pseudo_header->k12.input_info.atm.vp,
                                                  (guint)pinfo->pseudo_header->k12.input_info.atm.vc,
                                                  (guint)pinfo->pseudo_header->k12.input_info.atm.cid);
            
            pinfo->circuit_id = g_str_hash(circuit_str);
            
			proto_tree_add_uint(k12_tree, hf_k12_atm_vp, tvb, 0,0,pinfo->pseudo_header->k12.input_info.atm.vp);
			proto_tree_add_uint(k12_tree, hf_k12_atm_vc, tvb, 0,0,pinfo->pseudo_header->k12.input_info.atm.vc);
            if (pinfo->pseudo_header->k12.input_info.atm.cid) 
                proto_tree_add_uint(k12_tree, hf_k12_atm_cid, tvb, 0,0,pinfo->pseudo_header->k12.input_info.atm.cid);
			break;
        }
		default:
			break;
	}

	if (! k12_cfg ) {
		sub_handle = data_handle;
	} else {
		sub_handle = g_hash_table_lookup(k12_cfg,pinfo->pseudo_header->k12.stack_file);

		if (! sub_handle )
			sub_handle = data_handle;
	}

	call_dissector(sub_handle, tvb, pinfo, tree);

}

static gboolean free_just_key (gpointer k, gpointer v _U_, gpointer p _U_) {
	g_free(k);
	return TRUE;
}


static GHashTable* k12_load_config(const gchar* filename) {
	FILE* fp;
	gchar buffer[0x10000];
	size_t len;
	GHashTable* hash;
	gchar** curr;
	gchar** lines = NULL;
	guint i;
	dissector_handle_t handle;

	/* XXX: should look for the file in common locations */

	if (( fp = fopen(filename,"r") )) {
		len = fread(buffer,1,0xFFFF,fp);
		fclose(fp);
	} else {
		report_open_failure(filename, errno, FALSE);
		return NULL;
	}

	hash = g_hash_table_new(g_str_hash, g_str_equal);

	if (len > 0) {

		lines = g_strsplit(buffer,"\n",0);

		for (i = 0 ; lines[i]; i++) {
			g_strstrip(lines[i]);
			g_strdown(lines[i]);

			if(*(lines[i]) == '#' || *(lines[i]) == '\0')
				continue;

			curr = g_strsplit(lines[i]," ",0);

			if (! (curr[0] != NULL && *(curr[0]) != '\0' && curr[1] != NULL  && *(curr[1]) != '\0' ) ) {
				report_failure("K12xx: Format error in line %u",i+1);
				g_strfreev(curr);
				g_strfreev(lines);
				g_hash_table_foreach_remove(hash,free_just_key,NULL);
				g_hash_table_destroy(hash);
				return NULL;
			}

			g_strstrip(curr[0]);
			g_strstrip(curr[1]);
			handle = find_dissector(curr[1]);

			if (! handle ) {
				report_failure("k12: proto %s not found",curr[1]);
				handle = data_handle;
			}

			g_hash_table_insert(hash,g_strdup(curr[0]),handle);
			g_strfreev(curr);

		}

		g_strfreev(lines);
		return hash;

	}

	g_hash_table_destroy(hash);

	report_read_failure(filename, errno);

	return NULL;
}


static void k12_load_prefs(void) {
	if (k12_cfg) {
		g_hash_table_foreach_remove(k12_cfg,free_just_key,NULL);
		g_hash_table_destroy(k12_cfg);
		k12_cfg = NULL;
	}

	if (*k12_config_filename != '\0') {
		k12_cfg = k12_load_config(k12_config_filename);
		return;
	}
}

void proto_reg_handoff_k12(void) {
	k12_handle = find_dissector("k12");
	data_handle = find_dissector("data");
	dissector_add("wtap_encap", WTAP_ENCAP_K12, k12_handle);
}

void
proto_register_k12(void)
{
	static hf_register_info hf[] = {
		{ &hf_k12_port_id, { "Port Id", "k12.port_id", FT_UINT32, BASE_HEX,	NULL, 0x0, "", HFILL }},
		{ &hf_k12_port_name, { "Port Name", "k12.port_name", FT_STRING, BASE_NONE, NULL, 0x0,"", HFILL }},
		{ &hf_k12_stack_file, { "Stack file used", "k12.stack_file", FT_STRING, BASE_NONE, NULL, 0x0,"", HFILL }},
		{ &hf_k12_port_type, { "Port type", "k12.input_type", FT_UINT32, BASE_HEX, VALS(k12_port_types), 0x0,"", HFILL }},
		{ &hf_k12_ts, { "Timeslot mask", "k12.ds0.ts", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_k12_atm_vp, { "ATM VPI", "atm.vpi", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_k12_atm_vc, { "ATM VCI", "atm.vci", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_k12_atm_cid, { "AAL2 CID", "aal2.cid", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }}
	};

  static gint *ett[] = {
	  &ett_k12,
	  &ett_port
  };

  proto_k12 = proto_register_protocol("K12xx", "K12xx", "k12");
  proto_register_field_array(proto_k12, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("k12", dissect_k12, proto_k12);

  k12_module = prefs_register_protocol(proto_k12, k12_load_prefs);

  prefs_register_string_preference(k12_module, "config",
								   "Configuration filename",
								   "K12 module configuration filename",
								   &k12_config_filename);

}
