/* packet-dcerpc-epm.c
 * Routines for dcerpc endpoint mapper dissection
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc-epm.c,v 1.8 2002/05/26 10:51:06 sahlberg Exp $
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


static int proto_epm = -1;

static int hf_epm_inquiry_type = -1;
static int hf_epm_object_p = -1;
static int hf_epm_object = -1;
static int hf_epm_if_id_p = -1;
static int hf_epm_if_id = -1;
static int hf_epm_ver_maj = -1;
static int hf_epm_ver_min = -1;
static int hf_epm_ver_opt = -1;
static int hf_epm_hnd = -1;
static int hf_epm_max_ents = -1;
static int hf_epm_num_ents = -1;
static int hf_epm_uuid = -1;
static int hf_epm_tower_length = -1;
static int hf_epm_tower_data = -1;
static int hf_epm_max_towers = -1;
static int hf_epm_num_towers = -1;
static int hf_epm_rc = -1;

static gint ett_epm = -1;


static e_uuid_t uuid_epm = { 0xe1af8308, 0x5d1f, 0x11c9, { 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa } };
static guint16  ver_epm = 3;


static int
epm_dissect_ept_lookup_rqst (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
    guint32 dummy;
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_inquiry_type, NULL);
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_object_p, &dummy);
    if (dummy) {
        offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
                                     hf_epm_object, NULL);
    }
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_if_id_p, &dummy);
    if (dummy) {
        offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
                                     hf_epm_if_id, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_epm_ver_maj, NULL);
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_epm_ver_min, NULL);
    }
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_ver_opt, NULL);
    if (tree) {
        proto_tree_add_bytes (tree, hf_epm_hnd, tvb, offset, 20,
                              tvb_get_ptr (tvb, offset, 20));
    }
    offset += 20;

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_max_ents, NULL);
    return offset;
}


static int
epm_dissect_ept_lookup_resp (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_num_ents, NULL);
    /* FIXME: more to do here */
    return offset;
}

#if 0
static int
epm_dissect_uuid (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
    offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
                                  hf_epm_uuid, NULL);
    return offset;
}
#endif

/* typedef struct {
      unsigned int tower_len,
      [size_is(tower_len)] char tower[];
   } twr_t, *twr_p_t;
*/
static int
epm_dissect_tower (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
    guint32 len;
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    /* first one is the header of the conformant array, second one is the
       length field */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_tower_length, &len);
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_tower_length, NULL);
    proto_tree_add_item(tree, hf_epm_tower_data, tvb, offset, len, FALSE);
    offset += len;

    return offset;
}
static int
epm_dissect_tower_pointer (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower, NDR_POINTER_PTR,
                             "Tower pointer:", -1, 1);
    return offset;
}
static int
epm_dissect_tower_array (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
    offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower_pointer);

    return offset;
}

static int
epm_dissect_ept_map_rqst (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
    /* [in] handle_t h */
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

#if 0
    /* according to opengroup we should have an uuid pointer here.
       in my w2k captures i can not see any such thing */
    /* [in, ptr] uuid_p_t object */
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_uuid, NDR_POINTER_PTR,
                             "UUID pointer:", -1, 1);
#endif

    /* [in, ptr] twr_p_t map_tower */
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower, NDR_POINTER_PTR,
                             "Tower pointer:", -1, 1);

    /* [in, out] ept_lookup_handle_t *entry_handle */
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    /* [in] unsigned32 max_towers */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_max_towers, NULL);

    return offset;
}

static int
epm_dissect_ept_map_resp (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
    /* [in, out] ept_lookup_handle_t *entry_handle */
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    /* [out, ptr] unsigned32 *num_towers */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_num_towers, NULL);

    /* [out, length_is(*num_towers), size_is(max_towers), ptr] twr_p_t towers[] */
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower_array, NDR_POINTER_REF,
                             "Tower array:", -1, 1);

    /* [out] error_status_t *status */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_rc, NULL);

    return offset;
}

static dcerpc_sub_dissector epm_dissectors[] = {
    { 0, "ept_insert", NULL, NULL },
    { 1, "ept_delete", NULL, NULL },
    { 2, "ept_lookup", 
	epm_dissect_ept_lookup_rqst, 
	epm_dissect_ept_lookup_resp },
    { 3, "Map", 
	epm_dissect_ept_map_rqst, 
	epm_dissect_ept_map_resp },
    { 4, "ept_lookup_handle_free", NULL, NULL },
    { 5, "ept_inq_object", NULL, NULL },
    { 6, "ept_mgmt_delete", NULL, NULL },
    { 0, NULL, NULL, NULL },
};


void
proto_register_epm (void)
{
	static hf_register_info hf[] = {
        { &hf_epm_inquiry_type,
          { "Inquiry type", "epm.inq_type", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_epm_object_p,
          { "Object pointer", "epm.object_p", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_epm_object,
          { "Object", "epm.object", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_epm_if_id_p,
          { "Interface pointer", "epm.if_id_p", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_epm_if_id,
          { "Interface", "epm.if_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_epm_ver_maj,
          { "Version Major", "epm.ver_maj", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_epm_ver_min,
          { "Version Minor", "epm.ver_min", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_epm_ver_opt,
          { "Version Option", "epm.ver_opt", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},	
        { &hf_epm_hnd,
          { "Handle", "epm.hnd", FT_BYTES, BASE_NONE, NULL, 0x0, "Context handle", HFILL }},	
        { &hf_epm_max_ents,
          { "Max entries", "epm.max_ents", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_epm_num_ents,
          { "Num entries", "epm.num_ents", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_epm_uuid,
          { "UUID", "epm.uuid", FT_STRING, BASE_NONE, NULL, 0x0, "UUID", HFILL }},	
        { &hf_epm_tower_length,
          { "Length", "epm.tower.len", FT_UINT32, BASE_DEC, NULL, 0x0, "Length of tower data", HFILL }},
        { &hf_epm_tower_data,
          { "Tower", "epm.tower", FT_BYTES, BASE_HEX, NULL, 0x0, "Tower data", HFILL }},
        { &hf_epm_max_towers,
          { "Max Towers", "epm.max_towers", FT_UINT32, BASE_DEC, NULL, 0x0, "Maximum number of towers to return", HFILL }},
        { &hf_epm_num_towers,
          { "Num Towers", "epm.num_towers", FT_UINT32, BASE_DEC, NULL, 0x0, "Number number of towers to return", HFILL }},
        { &hf_epm_rc,
          { "Return code", "epm.rc", FT_UINT32, BASE_HEX, NULL, 0x0, "EPM return value", HFILL }},
    };

	static gint *ett[] = {
		&ett_epm,
	};
	proto_epm = proto_register_protocol ("DCE/RPC Endpoint Mapper", "EPM", "epm");
	proto_register_field_array (proto_epm, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_epm (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_epm, ett_epm, &uuid_epm, ver_epm, epm_dissectors);
}
