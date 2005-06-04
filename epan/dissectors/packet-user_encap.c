/* packet-user_encap.c
 * Allow users to specify the dissectors for USERn DLTs
 * Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
	gchar* name;
	gchar* abbr;
	gchar* long_name;
	
	gchar* payload;
	gchar* header;
	gchar* trailer;
	guint header_size;
	guint trailer_size;
	
	int hfid;
	
	gint encap;
	
	encap_dissector_t encap_dissector;
	dissector_t dissector;
	
	module_t* module;
	
	dissector_handle_t handle;
	dissector_handle_t payload_handle;
	dissector_handle_t header_handle;
	dissector_handle_t trailer_handle;
} user_encap_t;

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

static void dissect_user0(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,0); } 
static void dissect_user1(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,1); } 
static void dissect_user2(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,2); } 
static void dissect_user3(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,3); } 
static void dissect_user4(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,4); } 
static void dissect_user5(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,5); } 
static void dissect_user6(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,6); } 
static void dissect_user7(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,7); } 
static void dissect_user8(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,8); } 
static void dissect_user9(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,9); } 
static void dissect_user10(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,10); } 
static void dissect_user11(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,11); } 
static void dissect_user12(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,12); } 
static void dissect_user13(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,13); } 
static void dissect_user14(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,14); } 
static void dissect_user15(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree) { dissect_user(tvb,pinfo,tree,15); } 

user_encap_t encaps[] = {
	{"USER0","user0","DLT_USER00","","","",0,0,-1,0,NULL,dissect_user0,NULL,NULL,NULL,NULL,NULL},
	{"USER1","user1","DLT_USER01","","","",0,0,-1,0,NULL,dissect_user1,NULL,NULL,NULL,NULL,NULL},
	{"USER2","user2","DLT_USER02","","","",0,0,-1,0,NULL,dissect_user2,NULL,NULL,NULL,NULL,NULL},
	{"USER3","user3","DLT_USER03","","","",0,0,-1,0,NULL,dissect_user3,NULL,NULL,NULL,NULL,NULL},
	{"USER4","user4","DLT_USER04","","","",0,0,-1,0,NULL,dissect_user4,NULL,NULL,NULL,NULL,NULL},
	{"USER5","user5","DLT_USER05","","","",0,0,-1,0,NULL,dissect_user5,NULL,NULL,NULL,NULL,NULL},
	{"USER6","user6","DLT_USER06","","","",0,0,-1,0,NULL,dissect_user6,NULL,NULL,NULL,NULL,NULL},
	{"USER7","user7","DLT_USER07","","","",0,0,-1,0,NULL,dissect_user7,NULL,NULL,NULL,NULL,NULL},
	{"USER8","user8","DLT_USER08","","","",0,0,-1,0,NULL,dissect_user8,NULL,NULL,NULL,NULL,NULL},
	{"USER9","user9","DLT_USER09","","","",0,0,-1,0,NULL,dissect_user9,NULL,NULL,NULL,NULL,NULL},
	{"USER10","user10","DLT_USER10","","","",0,0,-1,0,NULL,dissect_user10,NULL,NULL,NULL,NULL,NULL},
	{"USER11","user11","DLT_USER11","","","",0,0,-1,0,NULL,dissect_user11,NULL,NULL,NULL,NULL,NULL},
	{"USER12","user12","DLT_USER12","","","",0,0,-1,0,NULL,dissect_user12,NULL,NULL,NULL,NULL,NULL},
	{"USER13","user13","DLT_USER13","","","",0,0,-1,0,NULL,dissect_user13,NULL,NULL,NULL,NULL,NULL},
	{"USER14","user14","DLT_USER14","","","",0,0,-1,0,NULL,dissect_user14,NULL,NULL,NULL,NULL,NULL},
	{"USER15","user15","DLT_USER15","","","",0,0,-1,0,NULL,dissect_user15,NULL,NULL,NULL,NULL,NULL},
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
		tvbuff_t* trailer_tvb = tvb_new_subset(tvb, 0, encap->trailer_size, encap->trailer_size);
		call_dissector(encap->trailer_handle, trailer_tvb, pinfo, tree);
		offset = encap->trailer_size;
	}
}

void proto_reg_handoff_user_encap(void)
{
	int i = 0;
	static dissector_handle_t data_handle;
	
	data_handle = find_dissector("data");

	do {
		encaps[i].handle =  find_dissector(encaps[i].abbr);
		dissector_add("wtap_encap", WTAP_ENCAP_USER0 + i, encaps[i].handle);

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
		
		encaps[i].encap_dissector = encap_dissectors[encaps[i].encap];
		
		i++;
	} while(i<16);
	
}

void proto_register_user_encap(void)
{
	int i;
	
	for (i = 0; i < 16; i++) {
		encaps[i].hfid = proto_register_protocol(encaps[i].name, encaps[i].long_name, encaps[i].abbr);
		encaps[i].module = prefs_register_protocol(encaps[i].hfid, proto_reg_handoff_user_encap);
		
		prefs_register_string_preference(encaps[i].module, "payload","Payload", "Payload", &encaps[i].payload);
		prefs_register_enum_preference(encaps[i].module, "encap","Encapsulation", "The encapsulation used", &encaps[i].encap, encap_types, FALSE);
		prefs_register_uint_preference(encaps[i].module, "header_size","Header Size", "The size (in bytes) of the Header (0 if none)", 10, &encaps[i].header_size);
		prefs_register_uint_preference(encaps[i].module, "trailer_size","Trailer Size", "The size (in bytes) of the Trailer (0 if none)", 10, &encaps[i].trailer_size);
		prefs_register_string_preference(encaps[i].module, "header_proto","Header Protocol", "Header Protocol (used only when ecapsulation is not given)", &encaps[i].header);
		prefs_register_string_preference(encaps[i].module, "trailer_proto","Trailer Protocol", "Trailer Protocol (used only when ecapsulation is not given)", &encaps[i].trailer);
		
		register_dissector(encaps[i].abbr, encaps[i].dissector, encaps[i].hfid);
	}
}
