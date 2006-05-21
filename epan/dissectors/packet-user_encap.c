/* packet-user_encap.c
 * Allow users to specify the dissectors for DLTs
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
 *  of the License, or (at your option) any later version.
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/report_err.h>

#include <epan/dissectors/packet-sscop.h>

typedef void (*encap_dissector_t)(tvbuff_t*,packet_info*,proto_tree*,dissector_handle_t);

typedef struct _user_encap_t {
	guint wtap_encap;
	guint last_encap;
	
	const gchar* name;
	const gchar* abbr;
	const gchar* long_name;
	
	const gchar* payload;
	const gchar* header;
	const gchar* trailer;
	guint header_size;
	guint trailer_size;
	
	int hfid;
	
	gint special_encap;
	
	encap_dissector_t encap_dissector;
	dissector_t dissector;
	
	module_t* module;
	
	dissector_handle_t handle;
	dissector_handle_t payload_handle;
	dissector_handle_t header_handle;
	dissector_handle_t trailer_handle;
} user_encap_t;

static const enum_val_t user_dlts[] = {
	{ "Disabled", "Disabled", 0 },
	{ "USER00", "User 0 (DLT=147 WTAP_ENCAP=45)", WTAP_ENCAP_USER0 },
	{ "USER01", "User 1 (DLT=148 WTAP_ENCAP=46)", WTAP_ENCAP_USER1 },
	{ "USER02", "User 2 (DLT=149 WTAP_ENCAP=47)", WTAP_ENCAP_USER2 },
	{ "USER03", "User 3 (DLT=150 WTAP_ENCAP=48)", WTAP_ENCAP_USER3 },
	{ "USER04", "User 4 (DLT=151 WTAP_ENCAP=49)", WTAP_ENCAP_USER4 },
	{ "USER05", "User 5 (DLT=152 WTAP_ENCAP=50)", WTAP_ENCAP_USER5 },
	{ "USER06", "User 6 (DLT=153 WTAP_ENCAP=51)", WTAP_ENCAP_USER6 },
	{ "USER07", "User 7 (DLT=154 WTAP_ENCAP=52)", WTAP_ENCAP_USER7 },
	{ "USER08", "User 8 (DLT=155 WTAP_ENCAP=53)", WTAP_ENCAP_USER8 },
	{ "USER09", "User 9 (DLT=156 WTAP_ENCAP=54)", WTAP_ENCAP_USER9 },
	{ "USER10", "User 10 (DLT=157 WTAP_ENCAP=55)", WTAP_ENCAP_USER10 },
	{ "USER11", "User 11 (DLT=158 WTAP_ENCAP=56)", WTAP_ENCAP_USER11 },
	{ "USER12", "User 12 (DLT=159 WTAP_ENCAP=57)", WTAP_ENCAP_USER12 },
	{ "USER13", "User 13 (DLT=160 WTAP_ENCAP=58)", WTAP_ENCAP_USER13 },
	{ "USER14", "User 14 (DLT=161 WTAP_ENCAP=59)", WTAP_ENCAP_USER14 },
	{ "USER15", "User 15 (DLT=162 WTAP_ENCAP=60)", WTAP_ENCAP_USER15 },
	{ NULL, NULL, 0 }
};

static const enum_val_t encap_types[] = {
	{ "None", "No encpsulation", 0 },
	{ "SSCOP" , "SSCOP", 1 },
	{ NULL, NULL, 0 }
};

static const encap_dissector_t encap_dissectors[] = {
	NULL,
	dissect_sscop_and_payload
};

static void dissect_user(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree,guint id);

static void dissect_user_a(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,0); } 
static void dissect_user_b(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,1); } 
static void dissect_user_c(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,2); } 
static void dissect_user_d(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,3); } 

user_encap_t encaps[] = {
	{0,0,"DLT_USER_A","user_dlt_a","DLT User A","","","",0,0,-1,0,NULL,dissect_user_a,NULL,NULL,NULL,NULL,NULL},
	{0,0,"DLT_USER_B","user_dlt_b","DLT User B","","","",0,0,-1,0,NULL,dissect_user_b,NULL,NULL,NULL,NULL,NULL},
	{0,0,"DLT_USER_C","user_dlt_c","DLT User C","","","",0,0,-1,0,NULL,dissect_user_c,NULL,NULL,NULL,NULL,NULL},
	{0,0,"DLT_USER_D","user_dlt_d","DLT User D","","","",0,0,-1,0,NULL,dissect_user_d,NULL,NULL,NULL,NULL,NULL},
};

static void dissect_user(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree,guint id) {
	user_encap_t* encap = &(encaps[id]);
	tvbuff_t* payload_tvb;
	int offset = 0;
	int len = tvb_reported_length(tvb) - (encap->header_size + encap->trailer_size);
	
	if (encap->encap_dissector) {
		encap->encap_dissector(tvb,pinfo,tree,encap->payload_handle);
		return;
	}
	
	if (encap->header_size) {
		tvbuff_t* hdr_tvb = tvb_new_subset(tvb, 0, encap->header_size, encap->header_size);
		call_dissector(encap->header_handle, hdr_tvb, pinfo, tree);
		offset = encap->header_size;
	}
	
	payload_tvb = tvb_new_subset(tvb, encap->header_size, len, len);
	call_dissector(encap->payload_handle, payload_tvb, pinfo, tree);

	if (encap->trailer_size) {
		tvbuff_t* trailer_tvb = tvb_new_subset(tvb, encap->header_size + len, encap->trailer_size, encap->trailer_size);
		call_dissector(encap->trailer_handle, trailer_tvb, pinfo, tree);
		offset = encap->trailer_size;
	}
}

void proto_reg_handoff_user_encap(void) {
	guint i;
	static dissector_handle_t data_handle;
	
	data_handle = find_dissector("data");

	for (i = 0; i < array_length(encaps); i++) {
		
		if(encaps[i].last_encap)
			dissector_delete("wtap_encap", encaps[i].last_encap, encaps[i].handle);
		
		if (encaps[i].wtap_encap) {
			encaps[i].handle =  find_dissector(encaps[i].abbr);
			dissector_add("wtap_encap", encaps[i].wtap_encap, encaps[i].handle);
			encaps[i].last_encap = encaps[i].wtap_encap;
			
			if(*(encaps[i].payload) != '\0') {
				encaps[i].payload_handle = find_dissector(encaps[i].payload);
				
				if (encaps[i].payload_handle == NULL) {
					encaps[i].payload_handle = data_handle;
					report_failure("%s: No such proto: %s",encaps[i].long_name,encaps[i].payload);
				}
			} else {
				encaps[i].payload_handle = data_handle;			
			}
			
			if(*(encaps[i].header) != '\0') {
				encaps[i].header_handle = find_dissector(encaps[i].header);
				
				if (encaps[i].header_handle == NULL) {
					encaps[i].header_handle = data_handle;
					report_failure("%s: No such proto: %s",encaps[i].long_name,encaps[i].header);
				}
			} else {
				encaps[i].header_handle = data_handle;			
			}
			
			if(*(encaps[i].trailer) != '\0') {
				encaps[i].trailer_handle = find_dissector(encaps[i].trailer);
				
				if (encaps[i].trailer_handle == NULL) {
					encaps[i].trailer_handle = data_handle;
					report_failure("%s: No such proto: %s",encaps[i].long_name,encaps[i].trailer);
				}
			} else {
				encaps[i].trailer_handle = data_handle;			
			}
			
			encaps[i].encap_dissector = encap_dissectors[encaps[i].special_encap];
		}
	}
}

void proto_register_user_encap(void)
{
	size_t i;
	
	for (i = 0; i < array_length(encaps); i++) {
		encaps[i].hfid = proto_register_protocol(encaps[i].name, encaps[i].long_name, encaps[i].abbr);
		encaps[i].module = prefs_register_protocol(encaps[i].hfid, proto_reg_handoff_user_encap);
		
		prefs_register_enum_preference(encaps[i].module, "dlt","DLT", "Data Link Type", &(encaps[i].wtap_encap), user_dlts, FALSE);
		prefs_register_enum_preference(encaps[i].module, "special_encap","Special Encapsulation", "", &(encaps[i].special_encap), encap_types, FALSE);
		prefs_register_string_preference(encaps[i].module, "payload","Payload", "Payload", (const char **) &(encaps[i].payload));
		prefs_register_uint_preference(encaps[i].module, "header_size","Header Size", "The size (in octets) of the Header", 10, &(encaps[i].header_size));
		prefs_register_uint_preference(encaps[i].module, "trailer_size","Trailer Size", "The size (in octets) of the Trailer", 10, &(encaps[i].trailer_size));
		prefs_register_string_preference(encaps[i].module, "header_proto","Header Protocol", "Header Protocol (used only when ecapsulation is not given)", (const char **)&(encaps[i].header));
		prefs_register_string_preference(encaps[i].module, "trailer_proto","Trailer Protocol", "Trailer Protocol (used only when ecapsulation is not given)", (const char **)&(encaps[i].trailer));
		
		register_dissector(encaps[i].abbr, encaps[i].dissector, encaps[i].hfid);
	}
}
