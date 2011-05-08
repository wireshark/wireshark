/* packet-user_encap.c
 * Allow users to specify the dissectors for DLTs
 * Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/emem.h>

#ifdef _MSC_VER
/* disable: warning C4090: 'XY' : different 'const' qualifiers */
#pragma warning(disable:4090)
#endif

typedef struct _user_encap_t {
	guint encap;
	char* payload_proto_name;
	dissector_handle_t payload_proto;
	char* header_proto_name;
	dissector_handle_t header_proto;
	char* trailer_proto_name;
	dissector_handle_t trailer_proto;
	guint header_size;
	guint trailer_size;
} user_encap_t;

#define ENCAP0_STR "User 0 (DLT=147)"
static const value_string user_dlts[] = {
	{ WTAP_ENCAP_USER0, ENCAP0_STR},
	{ WTAP_ENCAP_USER1, "User 1 (DLT=148)"},
	{ WTAP_ENCAP_USER2, "User 2 (DLT=149)"},
	{ WTAP_ENCAP_USER3, "User 3 (DLT=150)"},
	{ WTAP_ENCAP_USER4, "User 4 (DLT=151)"},
	{ WTAP_ENCAP_USER5, "User 5 (DLT=152)"},
	{ WTAP_ENCAP_USER6, "User 6 (DLT=153)"},
	{ WTAP_ENCAP_USER7, "User 7 (DLT=154)"},
	{ WTAP_ENCAP_USER8, "User 8 (DLT=155)"},
	{ WTAP_ENCAP_USER9, "User 9 (DLT=156)"},
	{ WTAP_ENCAP_USER10, "User 10 (DLT=157)"},
	{ WTAP_ENCAP_USER11, "User 11 (DLT=158)"},
	{ WTAP_ENCAP_USER12, "User 12 (DLT=159)"},
	{ WTAP_ENCAP_USER13, "User 13 (DLT=160)"},
	{ WTAP_ENCAP_USER14, "User 14 (DLT=161)"},
	{ WTAP_ENCAP_USER15, "User 15 (DLT=162)"},
	{ 0, NULL }
};
static int proto_user_encap = -1;

static user_encap_t* encaps = NULL;
static guint num_encaps = 0;
static uat_t* encaps_uat;
static dissector_handle_t data_handle;

static void dissect_user(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {
	user_encap_t* encap = NULL;
	tvbuff_t* payload_tvb;
	proto_item* item;
	int offset = 0;
	int len;
	guint i;
	
	for (i = 0; i < num_encaps; i++) {
		if (encaps[i].encap == pinfo->match_uint) {
			encap = &(encaps[i]);
			break;
		}
	}
	
	item = proto_tree_add_item(tree,proto_user_encap,tvb,0,-1,FALSE);
	if (!encap) {
		char* msg = ep_strdup_printf("User encapsulation not handled: DLT=%d, check your Preferences->Protocols->DLT_USER",
					     pinfo->match_uint + 147 - WTAP_ENCAP_USER0);
		proto_item_set_text(item,"%s",msg);
		expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "%s", msg);
		
		call_dissector(data_handle, tvb, pinfo, tree);
		return;
	}
	if (encap->payload_proto == NULL) {
		char* msg = ep_strdup_printf("User encapsulation's protocol %s not found: DLT=%d, check your Preferences->Protocols->DLT_USER",
					     encap->payload_proto_name,
					     pinfo->match_uint + 147 - WTAP_ENCAP_USER0);
		proto_item_set_text(item,"%s",msg);
		expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "%s", msg);
		
		call_dissector(data_handle, tvb, pinfo, tree);
		return;
	}

	proto_item_set_text(item,"DLT: %d",pinfo->match_uint + 147 - WTAP_ENCAP_USER0);

	len = tvb_reported_length(tvb) - (encap->header_size + encap->trailer_size);
	
	if (encap->header_size) {
		tvbuff_t* hdr_tvb = tvb_new_subset(tvb, 0, encap->header_size, encap->header_size);
		call_dissector(encap->header_proto, hdr_tvb, pinfo, tree);
		offset = encap->header_size;
		if (encap->header_proto_name) {
			const char *proto_name = dissector_handle_get_long_name(find_dissector(encap->header_proto_name));
			if (proto_name) {
				proto_item_append_text(item, ", Header: %s (%s)", encap->header_proto_name, proto_name);
			}
		}
	}
	
	payload_tvb = tvb_new_subset(tvb, encap->header_size, len, len);
	call_dissector(encap->payload_proto, payload_tvb, pinfo, tree);
	if (encap->payload_proto_name) {
		const char *proto_name = dissector_handle_get_long_name(find_dissector(encap->payload_proto_name));
		if (proto_name) {
			proto_item_append_text(item, ", Payload: %s (%s)", encap->payload_proto_name, proto_name);
		}
	}

	if (encap->trailer_size) {
		tvbuff_t* trailer_tvb = tvb_new_subset(tvb, encap->header_size + len, encap->trailer_size, encap->trailer_size);
		call_dissector(encap->trailer_proto, trailer_tvb, pinfo, tree);
		offset = encap->trailer_size;
		if (encap->trailer_proto_name) {
			const char *proto_name = dissector_handle_get_long_name(find_dissector(encap->trailer_proto_name));
			if (proto_name) {
				proto_item_append_text(item, ", Trailer: %s (%s)", encap->trailer_proto_name, proto_name);
			}
		}
	}
}

static void* user_copy_cb(void* dest, const void* orig, size_t len _U_) 
{
  const user_encap_t *o = orig;
  user_encap_t *d = dest;

  d->payload_proto_name = g_strdup(o->payload_proto_name);
  d->header_proto_name  = g_strdup(o->header_proto_name);
  d->trailer_proto_name = g_strdup(o->trailer_proto_name);

  return d;
}

static void user_free_cb(void* record)
{
  user_encap_t *u = record;

  g_free(u->payload_proto_name);
  g_free(u->header_proto_name);
  g_free(u->trailer_proto_name);
}

UAT_VS_DEF(user_encap, encap, user_encap_t, WTAP_ENCAP_USER0, ENCAP0_STR)
UAT_PROTO_DEF(user_encap, payload_proto, payload_proto, payload_proto_name, user_encap_t)
UAT_DEC_CB_DEF(user_encap, header_size, user_encap_t)
UAT_DEC_CB_DEF(user_encap, trailer_size, user_encap_t)
UAT_PROTO_DEF(user_encap, header_proto, header_proto, header_proto_name, user_encap_t)
UAT_PROTO_DEF(user_encap, trailer_proto, trailer_proto, trailer_proto_name, user_encap_t)

void proto_reg_handoff_user_encap(void)
{
	dissector_handle_t user_encap_handle;
	guint i;
	
	user_encap_handle = find_dissector("user_dlt");
	data_handle = find_dissector("data");
	
	for (i = WTAP_ENCAP_USER0 ; i <= WTAP_ENCAP_USER15; i++)
		dissector_add_uint("wtap_encap", i, user_encap_handle);

}


void proto_register_user_encap(void)
{
	module_t *module;

	static uat_field_t user_flds[] = {
		UAT_FLD_VS(user_encap,encap,"DLT",user_dlts,"The DLT"),
		UAT_FLD_PROTO(user_encap,payload_proto,"Payload protocol","Protocol to be used for the payload of this DLT"),
		UAT_FLD_DEC(user_encap,header_size,"Header size","Size of an eventual header that precedes the actual payload, 0 means none"),
		UAT_FLD_PROTO(user_encap,header_proto,"Header protocol","Protocol to be used for the header (empty = data)"),
		UAT_FLD_DEC(user_encap,trailer_size,"Trailer size","Size of an eventual trailer that follows the actual payload, 0 means none"),
		UAT_FLD_PROTO(user_encap,trailer_proto,"Trailer protocol","Protocol to be used for the trailer (empty = data)"),
		UAT_END_FIELDS
	};
	
	
	proto_user_encap = proto_register_protocol("DLT User","DLT_USER","user_dlt");
	
	module = prefs_register_protocol(proto_user_encap, NULL);
	
	encaps_uat = uat_new("User DLTs Table",
						 sizeof(user_encap_t),
						 "user_dlts",
						 TRUE,
						 (void*) &encaps,
						 &num_encaps,
						 UAT_CAT_FFMT,
						 "ChUserDLTsSection",
						 user_copy_cb,
						 NULL,
						 user_free_cb,
                                                 NULL,
						 user_flds );
	
	prefs_register_uat_preference(module,
				      "encaps_table",
				      "Encapsulations Table",
				      "A table that enumerates the various protocols to be used against a certain user DLT",
				      encaps_uat);
	
	
	register_dissector("user_dlt",dissect_user,proto_user_encap);

	/*
	prefs_register_protocol_obsolete(proto_register_protocol("DLT User A","DLT_USER_A","user_dlt_a"));
	prefs_register_protocol_obsolete(proto_register_protocol("DLT User B","DLT_USER_B","user_dlt_b"));
	prefs_register_protocol_obsolete(proto_register_protocol("DLT User C","DLT_USER_C","user_dlt_c"));
	prefs_register_protocol_obsolete(proto_register_protocol("DLT User D","DLT_USER_D","user_dlt_d"));
	*/
}
