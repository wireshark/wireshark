/* packet-dcerpc-epm.c
 * Routines for dcerpc endpoint mapper dissection
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc-epm.c,v 1.14 2002/08/28 21:00:09 jmayer Exp $
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


#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"


static int proto_epm = -1;

static int hf_epm_opnum = -1;
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
static int hf_epm_tower_num_floors = -1;
static int hf_epm_tower_rhs_len = -1;
static int hf_epm_tower_lhs_len = -1;
static int hf_epm_tower_proto_id = -1;

static gint ett_epm = -1;
static gint ett_epm_tower_floor = -1;

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



static const value_string proto_id_vals[] = {
	{ 0x00,	"OSI OID"},
	{ 0x0d,	"UUID"},
	{ 0x05,	"OSI TP4"},
	{ 0x06,	"OSI CLNS or DNA Routing"},
	{ 0x07,	"DOD TCP"},
	{ 0x08,	"DOD UDP"},
	{ 0x09,	"DOD IP"},
	{ 0x0a,	"RPC connectionless protocol"},
	{ 0x0b,	"RPC connection-oriented protocol"},
	{ 0x02,	"DNA Session Control"},
	{ 0x03,	"DNA Session Control V3"},
	{ 0x04,	"DNA NSP Transport"},
	{ 0x10,	"Named Pipes"},
	{ 0x11,	"NetBIOS"},
	{ 0x12,	"NetBEUI"},
	{ 0x13,	"Netware SPX"},
	{ 0x14,	"Netware IPX"},
	{ 0x16,	"Appletalk Stream"},
	{ 0x17,	"Appletalk Datagram"},
	{ 0x18,	"Appletalk"},
	{ 0x19,	"NetBIOS"},
	{ 0x1a,	"Vines SPP"},
	{ 0x1b,	"Vines IPC"},
	{ 0x1c,	"StreetTalk"},
	{ 0x20,	"Unix Domain Socket"},
	{ 0x21,	"null"},
	{ 0x22,	"NetBIOS"},
	{ 0, NULL},
};


/* XXX this function assumes LE encoding. can not use the NDR routines
   since they assume padding.
*/
static int
epm_dissect_tower_data (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
    guint16 num_floors, i;
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    num_floors = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_epm_tower_num_floors, tvb, offset, 2, num_floors);
    offset += 2;

    for(i=1;i<=num_floors;i++){
        proto_item *it = NULL;
        proto_tree *tr = NULL;
	int old_offset = offset;
        guint16 len;
	guint8 proto_id;
        e_uuid_t uuid;

        it = proto_tree_add_text(tree, tvb, offset, 0, "Floor %d", i);
        tr = proto_item_add_subtree(it, ett_epm_tower_floor);

        len = tvb_get_letohs(tvb, offset);
        proto_tree_add_uint(tr, hf_epm_tower_lhs_len, tvb, offset, 2, len);
        offset += 2;

        proto_id = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tr, hf_epm_tower_proto_id, tvb, offset, 1, proto_id);

        switch(proto_id){
        case 0x0d: /* UUID */
            dcerpc_tvb_get_uuid (tvb, offset+1, drep, &uuid);
            proto_tree_add_string_format (tr, hf_epm_uuid, tvb, offset+1, 16, "",
                          "UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                          uuid.Data1, uuid.Data2, uuid.Data3,
                          uuid.Data4[0], uuid.Data4[1],
                          uuid.Data4[2], uuid.Data4[3],
                          uuid.Data4[4], uuid.Data4[5],
                          uuid.Data4[6], uuid.Data4[7]);
            proto_tree_add_text(tr, tvb, offset+17, 2, "Version %d.%d", tvb_get_guint8(tvb, offset+18), tvb_get_guint8(tvb, offset+17));
            break;
        }
        offset += len;

        len = tvb_get_letohs(tvb, offset);
        proto_tree_add_uint(tr, hf_epm_tower_rhs_len, tvb, offset, 2, len);
        offset += 2;

        switch(proto_id){
        case 0x07: /* TCP this one is always big endian */
            proto_tree_add_text(tr, tvb, offset, 2, "TCP Port: %d", tvb_get_ntohs(tvb, offset));
            break;
        case 0x08: /* UDP this one is always big endian */
            proto_tree_add_text(tr, tvb, offset, 2, "UDP Port: %d", tvb_get_ntohs(tvb, offset));
            break;
        case 0x09: /* IP this one is always big endian */
            proto_tree_add_text(tr, tvb, offset, 4, "IP address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
            break;
        default:
            if(len){
                proto_tree_add_text(tr, tvb, offset, len, "not decoded yet");
            }
        }
        offset += len;

        proto_item_set_len(it, offset-old_offset);
    }
    return offset;
}

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
    offset = epm_dissect_tower_data(tvb, offset, pinfo, tree, drep);

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
    { 0, NULL, NULL, NULL }
};

static const value_string epm_opnum_vals[] = {
	{ 0, "insert" },
	{ 1, "delete" },
	{ 2, "lookup" },
	{ 3, "map" },
	{ 4, "lookup_handle_free" },
	{ 5, "inq_object" },
	{ 6, "mgmt_delete" },
	{ 0, NULL }
};

void
proto_register_epm (void)
{
	static hf_register_info hf[] = {
        { &hf_epm_opnum,
	  { "Operation", "epm.opnum", FT_UINT16, BASE_DEC,
	    VALS(epm_opnum_vals), 0x0, "Operation", HFILL }},
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
        { &hf_epm_tower_num_floors,
          { "Number of floors", "epm.tower.num_floors", FT_UINT16, BASE_DEC, NULL, 0x0, "Number of floors in tower", HFILL }},
        { &hf_epm_tower_rhs_len,
          { "RHS Length", "epm.tower.rhs.len", FT_UINT16, BASE_DEC, NULL, 0x0, "Length of RHS data", HFILL }},
        { &hf_epm_tower_lhs_len,
          { "LHS Length", "epm.tower.lhs.len", FT_UINT16, BASE_DEC, NULL, 0x0, "Length of LHS data", HFILL }},
        { &hf_epm_tower_proto_id,
          { "Protocol", "epm.tower.proto_id", FT_UINT8, BASE_HEX, VALS(proto_id_vals), 0x0, "Protocol identifier", HFILL }}
    };

	static gint *ett[] = {
		&ett_epm,
		&ett_epm_tower_floor
	};
	proto_epm = proto_register_protocol ("DCE/RPC Endpoint Mapper", "EPM", "epm");
	proto_register_field_array (proto_epm, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_epm (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_epm, ett_epm, &uuid_epm, ver_epm, epm_dissectors, hf_epm_opnum);
}
