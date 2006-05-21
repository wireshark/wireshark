/* packet-tcap-template.c
 * Routines for  TCAP
 * Copyright 2004 - 2005, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * References: ETSI 300 374
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>
#include "packet-ber.h"
#include "packet-tcap.h"

#define PNAME  "Transaction Capabilities Application Part"
#define PSNAME "TCAP"
#define PFNAME "tcap"

/* Initialize the protocol and registered fields */
int proto_tcap = -1;
static int hf_tcap_tag = -1; 
static int hf_tcap_length = -1; 
static int hf_tcap_data = -1;
static int hf_tcap_tid = -1;

#include "packet-tcap-hf.c"

/* Initialize the subtree pointers */
static gint ett_tcap = -1;
static gint ett_param = -1;

static gint ett_otid = -1;
static gint ett_dtid = -1;


#include "packet-tcap-ett.c"

#define MAX_SSN 254
static range_t *global_ssn_range;
static range_t *ssn_range;

dissector_handle_t	tcap_handle = NULL;
static dissector_table_t ber_oid_dissector_table=NULL;
static const char * cur_oid;
static const char * tcapext_oid;
static proto_tree	*tcap_top_tree=NULL;
static dissector_handle_t data_handle;

static dissector_table_t sccp_ssn_table;
static int dissect_tcap_param(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_tcap_UserInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_);


static GHashTable* ansi_sub_dissectors = NULL;
static GHashTable* itu_sub_dissectors = NULL;

static void dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);

extern void add_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
    g_hash_table_insert(ansi_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
    dissector_add("sccp.ssn",ssn,tcap_handle);
}

extern void add_itu_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
    g_hash_table_insert(itu_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
    dissector_add("sccp.ssn",ssn,tcap_handle);
}

extern void delete_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
    g_hash_table_remove(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
    dissector_delete("sccp.ssn",ssn,tcap_handle);
}
extern void delete_itu_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
    g_hash_table_remove(itu_sub_dissectors,GUINT_TO_POINTER(ssn));
	dissector_delete("sccp.ssn", ssn,tcap_handle);
}

static dissector_handle_t get_ansi_tcap_subdissector(guint32 ssn) {
    return g_hash_table_lookup(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
}

dissector_handle_t get_itu_tcap_subdissector(guint32 ssn) {
    return g_hash_table_lookup(itu_sub_dissectors,GUINT_TO_POINTER(ssn));
}



#include "packet-tcap-fn.c"



const value_string tcap_component_type_str[] = {
    { TCAP_COMP_INVOKE,		"Invoke" },
    { TCAP_COMP_RRL,		"Return Result(L)" },
    { TCAP_COMP_RE,			"Return Error" },
    { TCAP_COMP_REJECT,		"Reject" },
    { TCAP_COMP_RRN,		"Return Result(NL)" },
    { 0,			NULL } };


static void
dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;

    tcap_top_tree = parent_tree;
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCAP");
    }

    /* create display subtree for the protocol */
    if(parent_tree){
       item = proto_tree_add_item(parent_tree, proto_tcap, tvb, 0, -1, FALSE);
       tree = proto_item_add_subtree(item, ett_tcap);
    }
    cur_oid = NULL;
    tcapext_oid = NULL;
    pinfo->private_data = NULL;
    dissect_tcap_MessageType(FALSE, tvb, 0, pinfo, tree, -1);


}


void
proto_reg_handoff_tcap(void)
{
    
    static gboolean prefs_initialized = FALSE;
    
    if (! prefs_initialized) {
        sccp_ssn_table = find_dissector_table("sccp.ssn");
        prefs_initialized = TRUE;
    }
    
    register_ber_oid_name("0.0.17.773.1.1.1",
                          "itu-t(0) recommendation(0) q(17) 773 as(1) dialogue-as(1) version1(1)");

    data_handle = find_dissector("data");    
}

static void init_tcap(void);

void
proto_register_tcap(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
	{ &hf_tcap_tag,
		{ "Tag",           "tcap.msgtype",
		FT_UINT8, BASE_HEX, NULL, 0,
		"", HFILL }
	},
	{ &hf_tcap_length,
		{ "Length", "tcap.len",
		FT_UINT8, BASE_HEX, NULL, 0,
		"", HFILL }
	},
	{ &hf_tcap_data,
		{ "Data", "tcap.data",
		FT_BYTES, BASE_HEX, NULL, 0,
		"", HFILL }
	},
		{ &hf_tcap_tid,
		{ "Transaction Id", "tcap.tid",
		FT_BYTES, BASE_HEX, NULL, 0,
		"", HFILL }
	},
#include "packet-tcap-hfarr.c"	
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_tcap,
	&ett_param,
	&ett_otid,
	&ett_dtid,
	#include "packet-tcap-ettarr.c"
    };

    /*static enum_val_t tcap_options[] = {
	{ "itu", "ITU",  ITU_TCAP_STANDARD },
	{ "ansi", "ANSI", ANSI_TCAP_STANDARD },
	{ NULL, NULL, 0 }
    };*/

    module_t *tcap_module;

/* Register the protocol name and description */
    proto_tcap = proto_register_protocol(PNAME, PSNAME, PFNAME);

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_tcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    tcap_module = prefs_register_protocol(proto_tcap, proto_reg_handoff_tcap);

#if 0
    prefs_register_enum_preference(tcap_module, "standard", "ITU TCAP standard",
	"The SS7 standard used in ITU TCAP packets",
	&tcap_standard, tcap_options, FALSE);
#else
    prefs_register_obsolete_preference(tcap_module, "standard");
#endif

#if 0
    prefs_register_bool_preference(tcap_module, "lock_info_col", "Lock Info column",
	"Always show TCAP in Info column",
	&lock_info_col);
#else
    prefs_register_obsolete_preference(tcap_module, "lock_info_col");
#endif

    /* Set default SSNs */
    range_convert_str(&global_ssn_range, "", MAX_SSN);
    ssn_range = range_empty();

    prefs_register_range_preference(tcap_module, "ssn", "SCCP SSNs",
	"SCCP (and SUA) SSNs to decode as TCAP",
	&global_ssn_range, MAX_SSN);
    
    ansi_sub_dissectors = g_hash_table_new(g_direct_hash,g_direct_equal);
    itu_sub_dissectors = g_hash_table_new(g_direct_hash,g_direct_equal);

    /* 'globally' register dissector */
    register_dissector("tcap", dissect_tcap, proto_tcap);

    tcap_handle = create_dissector_handle(dissect_tcap, proto_tcap);

    register_init_routine(&init_tcap);
}


static void range_delete_callback(guint32 ssn)
{
    if ( ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
        dissector_delete("sccp.ssn", ssn, tcap_handle);
    }
}

static void range_add_callback(guint32 ssn)
{
    if (ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
        dissector_add("sccp.ssn", ssn, tcap_handle);
    }
}


static void init_tcap(void) {
    if (ssn_range) {
        range_foreach(ssn_range, range_delete_callback);
        g_free(ssn_range);
    }
    
    ssn_range = range_copy(global_ssn_range);
    range_foreach(ssn_range, range_add_callback);
    
}

static int
dissect_tcap_param(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    gint tag_offset, saved_offset, len_offset;
    tvbuff_t	*next_tvb;
    proto_tree *subtree;
    proto_item *pi;
    gint8 class;
    gboolean pc;
    gint32 tag;
    guint32 len;
    gboolean ind_field;
    
    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
	saved_offset = offset;
    
	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
	tag_offset = offset;
	offset = get_ber_length(tree, tvb, offset, &len, &ind_field);
	len_offset = offset;

	if (pc)
	{
	    pi =
		proto_tree_add_text(tree, tvb, saved_offset, len + (len_offset - saved_offset), "CONSTRUCTOR");
	    subtree = proto_item_add_subtree(pi, ett_param);
	    proto_tree_add_uint_format(subtree, hf_tcap_tag, tvb,
		saved_offset, tag_offset-saved_offset, tag, "CONSTRUCTOR Tag");
	    proto_tree_add_uint(subtree, hf_tcap_tag, tvb,
		saved_offset, tag_offset-saved_offset, class);

	    proto_tree_add_uint(subtree, hf_tcap_length, tvb,
		tag_offset, len_offset-tag_offset, len);
		if (len-(2*ind_field)) /*should always be positive unless we get an empty contructor pointless? */
		{
	    	next_tvb = tvb_new_subset(tvb, offset, len-(2*ind_field), len-(2*ind_field));		
	    		dissect_tcap_param(pinfo, subtree,next_tvb,0);
	    }		
	    	if (ind_field)
	    		proto_tree_add_text(subtree, tvb, offset+len-2, 2, "CONSTRUCTOR EOC");
	    offset += len;
	}
	else
	{
	    pi = proto_tree_add_text(tree, tvb,
		saved_offset, len + (len_offset - saved_offset), "Parameter (0x%.2x)", tag);

	    subtree = proto_item_add_subtree(pi, ett_param);

	    proto_tree_add_uint(subtree, hf_tcap_tag, tvb,
		saved_offset, 1, tag);

	    proto_tree_add_uint(subtree, hf_tcap_length, tvb,
		saved_offset+1, 1, len);
		if (len) /* check for NULLS */
			{
	    	next_tvb = tvb_new_subset(tvb, offset, len, len);		
	    	dissect_ber_octet_string(TRUE, pinfo, tree, next_tvb, 0, hf_tcap_data,
        	                        NULL);
        	}
	    offset += len;
	}
    }
    return offset;
}
