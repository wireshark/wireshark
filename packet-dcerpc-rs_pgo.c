/* packet-dcerpc-rs_pgo.c
 *
 * Routines for dcerpc Afs4Int dissection
 * Copyright 2002, Jaime Fournier <jafour1@yahoo.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz  security/idl/rs_pgo.idl
 *      
 * $Id: packet-dcerpc-rs_pgo.c,v 1.5 2003/08/04 02:49:01 tpot Exp $
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
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"


static int proto_rs_pgo = -1;
static int hf_rs_pgo_opnum = -1;
static int hf_rs_pgo_get_members_rqst_name_domain = -1;
static int hf_rs_pgo_get_members_rqst_sec_rgy_name_max_len = -1;
static int hf_rs_pgo_get_members_rqst_sec_rgy_name_t_size = -1;
static int hf_rs_pgo_get_members_rqst_sec_rgy_name_t = -1;
static int hf_rs_pgo_get_rqst_name_domain = -1;
static int hf_rs_pgo_get_rqst_var = -1;
static int hf_rs_pgo_get_rqst_var2 = -1;
static int hf_rs_pgo_get_rqst_key_size = -1;
static int hf_rs_pgo_get_rqst_key_t = -1;
static int hf_rs_pgo_key_transfer_rqst_var1 = -1;
static int hf_rs_pgo_key_transfer_rqst_var2 = -1;
static int hf_rs_pgo_key_transfer_rqst_var3 = -1;
static int hf_rs_pgo_is_member_rqst_var1 = -1;
static int hf_rs_pgo_is_member_rqst_var2 = -1;
static int hf_rs_pgo_is_member_rqst_var3 = -1;
static int hf_rs_pgo_is_member_rqst_var4 = -1;
static int hf_rs_pgo_is_member_rqst_key1 = -1;
static int hf_rs_pgo_is_member_rqst_key2 = -1;
static int hf_rs_pgo_is_member_rqst_key1_size = -1;
static int hf_rs_pgo_is_member_rqst_key2_size = -1;


static gint ett_rs_pgo = -1;


static e_uuid_t uuid_rs_pgo = { 0x4c878280, 0x3000, 0x0000, { 0x0d, 0x00, 0x02, 0x87, 0x14, 0x00, 0x00, 0x00 } };
static guint16  ver_rs_pgo = 1;

static int
rs_pgo_dissect_get_members_rqst (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
		                 char *drep)
{
     guint32 name_domain,  sec_rgy_name_max_len, sec_rgy_name_t_size;
     const char *sec_rgy_name_t = NULL;

     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
         hf_rs_pgo_get_members_rqst_name_domain, &name_domain);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
         hf_rs_pgo_get_members_rqst_sec_rgy_name_max_len, &sec_rgy_name_max_len);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
         hf_rs_pgo_get_members_rqst_sec_rgy_name_t_size, &sec_rgy_name_t_size);

     proto_tree_add_string (tree, hf_rs_pgo_get_members_rqst_sec_rgy_name_t, tvb, offset, hf_rs_pgo_get_members_rqst_sec_rgy_name_t_size, tvb_get_ptr (tvb, offset, sec_rgy_name_t_size));

     sec_rgy_name_t = (const char *)tvb_get_ptr(tvb,offset,sec_rgy_name_t_size);

     offset += sec_rgy_name_t_size;

     if (check_col(pinfo->cinfo, COL_INFO)){
        col_append_fstr(pinfo->cinfo, COL_INFO, " Request for: %s", sec_rgy_name_t);
     }

     return offset;
}
static int
rs_pgo_dissect_key_transfer_rqst (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
		                 char *drep)
{
    guint32 var1, var2, var3;

     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
        hf_rs_pgo_key_transfer_rqst_var1, &var1);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
        hf_rs_pgo_key_transfer_rqst_var2, &var2);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
        hf_rs_pgo_key_transfer_rqst_var3, &var3);

     if (check_col(pinfo->cinfo, COL_INFO)){
        col_append_fstr(pinfo->cinfo, COL_INFO, " Request for: %u", var3);
     }

     return offset;
}
static int
rs_pgo_dissect_is_member_rqst (tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
		                 char *drep)
{
     guint32 var1, var2, key1_size, key2_size, var3;
     const char *key1, *key2; 
     key1 = NULL; 
     key2 = NULL; 

     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rs_pgo_is_member_rqst_var1, &var1);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rs_pgo_is_member_rqst_var2, &var2);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rs_pgo_is_member_rqst_key1_size, &key1_size);

     proto_tree_add_string (tree, hf_rs_pgo_is_member_rqst_key1, tvb, offset, hf_rs_pgo_is_member_rqst_key1_size, tvb_get_ptr (tvb, offset, key1_size));
     key1 = (const char *)tvb_get_ptr(tvb,offset,key1_size);
     offset += key1_size;

     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rs_pgo_is_member_rqst_var3, &var3);
   /*  offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep, hf_rs_pgo_is_member_rqst_var4, &var4); */
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rs_pgo_is_member_rqst_key2_size, &key2_size);
     proto_tree_add_string (tree, hf_rs_pgo_is_member_rqst_key2, tvb, offset, hf_rs_pgo_is_member_rqst_key2_size, tvb_get_ptr (tvb, offset, key2_size));
     key2 = (const char *)tvb_get_ptr(tvb,offset,key2_size);
     offset += key2_size;

     if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Request: Is %s in %s", key2, key1);
     }

     return offset;

}


static int
rs_pgo_dissect_get_rqst (tvbuff_t *tvb, int offset,
	                         packet_info *pinfo, proto_tree *tree,
	                         char *drep)
{

     guint32 name_domain, key_size, var, var2;
     const char *key_t = NULL;

     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
         hf_rs_pgo_get_rqst_name_domain, &name_domain);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
         hf_rs_pgo_get_rqst_var, &var);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
         hf_rs_pgo_get_rqst_var2, &var2);
     offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, 
         hf_rs_pgo_get_rqst_key_size, &key_size);
	
     if (key_size){ /* Not able to yet decipher the OTHER versions of this call just yet. */

         proto_tree_add_string (tree, hf_rs_pgo_get_rqst_key_t, tvb, offset, hf_rs_pgo_get_rqst_key_size, tvb_get_ptr (tvb, offset, key_size));
         key_t = (const char *)tvb_get_ptr(tvb,offset,key_size);
         offset += (int)key_size;

         if (check_col(pinfo->cinfo, COL_INFO)) {
		 col_append_fstr(pinfo->cinfo, COL_INFO, 
    		 " Request for: %s ", key_t);
         }
     } else {
	 if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_str(pinfo->cinfo, COL_INFO, " Request (other)");
         }
     }


    return offset;
	        
}				 
	 

static dcerpc_sub_dissector rs_pgo_dissectors[] = {
	{ 0, "rs_pgo_add", NULL, NULL},
	{ 1, "rs_pgo_delete", NULL, NULL},
	{ 2, "rs_pgo_replace", NULL, NULL},
	{ 3, "rs_pgo_rename", NULL, NULL},
	{ 4, "rs_pgo_get", rs_pgo_dissect_get_rqst, NULL},
	{ 5, "rs_pgo_key_transfer", rs_pgo_dissect_key_transfer_rqst, NULL},
	{ 6, "rs_pgo_add_member", NULL, NULL},
	{ 7, "rs_pgo_delete_member", NULL, NULL},
	{ 8, "rs_pgo_is_member", rs_pgo_dissect_is_member_rqst, NULL},
	{ 9, "rs_pgo_get_members", rs_pgo_dissect_get_members_rqst, NULL},
        { 0, NULL, NULL, NULL }
};

void
proto_register_rs_pgo (void)
{
	static hf_register_info hf[] = {
       { &hf_rs_pgo_opnum,
         { "Operation", "rs_pgo.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }},
       { &hf_rs_pgo_get_members_rqst_name_domain,
         { "Name Domain", "rs_pgo.get_members_name_domain", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_get_members_rqst_sec_rgy_name_max_len,
         { "Sec_rgy_name_max_len", "rs_pgo.get_members_sec_rgy_name_max_len", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_get_members_rqst_sec_rgy_name_t_size,
         { "Sec_rgy_name_t_size", "rs_pgo.get_members_sec_rgy_name_t_size", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_get_members_rqst_sec_rgy_name_t,
         { "Sec_rgy_name_t", "rs_pgo.get_members_sec_rgy_name_t", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_get_rqst_name_domain,
         { "Name Domain", "rs_pgo.get_rqst_name_domain", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_get_rqst_key_size,
         { "Key Size", "rs_pgo.get_rqst_key_size", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_get_rqst_key_t,
         { "Key", "rs_pgo.get_rqst_key_t", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_get_rqst_var,
         { "Var1", "rs_pgo.get_rqst_var", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_get_rqst_var2,
         { "Var2", "rs_pgo.get_rqst_var2", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_key_transfer_rqst_var1,
         { "Var1", "rs_pgo.key_transfer_rqst_var1", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_key_transfer_rqst_var2,
         { "Var2", "rs_pgo.key_transfer_rqst_var2", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_key_transfer_rqst_var3,
         { "Var3", "rs_pgo.key_transfer_rqst_var3", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_is_member_rqst_var1,
         { "Var1", "rs_pgo.is_member_rqst_var1", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_is_member_rqst_var2,
         { "Var2", "rs_pgo.is_member_rqst_var2", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_is_member_rqst_var3,
         { "Var3", "rs_pgo.is_member_rqst_var3", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_is_member_rqst_var4,
         { "Var4", "rs_pgo.is_member_rqst_var4", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_is_member_rqst_key1_size,
         { "Key1 Size", "rs_pgo.is_member_rqst_key1_size", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_is_member_rqst_key2_size,
         { "Key2 Size", "rs_pgo.is_member_rqst_key2_size", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_is_member_rqst_key2,
         { "Key2", "rs_pgo.is_member_rqst_key2", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
       { &hf_rs_pgo_is_member_rqst_key1,
         { "Key2", "rs_pgo.is_member_rqst_key1", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
	};

	static gint *ett[] = {
		&ett_rs_pgo,
	};
	proto_rs_pgo = proto_register_protocol ("DCE Name Service", "RS_PGO", "rs_pgo");
	proto_register_field_array (proto_rs_pgo, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_pgo (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_pgo, ett_rs_pgo, &uuid_rs_pgo, ver_rs_pgo, rs_pgo_dissectors, hf_rs_pgo_opnum);
}
