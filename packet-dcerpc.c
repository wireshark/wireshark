/* packet-dcerpc.c
 * Routines for DCERPC packet disassembly
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc.c,v 1.40 2002/03/18 07:56:06 guy Exp $
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
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include <epan/conversation.h>
#include "prefs.h"

static const value_string pckt_vals[] = {
    { 0, "Request"},
    { 1, "Ping"},
    { 2, "Response"},
    { 3, "Fault"},
    { 4, "Working"},
    { 5, "Nocall"},
    { 6, "Reject"},
    { 7, "Ack"},
    { 8, "Cl_cancel"},
    { 9, "Fack"},
    { 10, "Cancel_ack"},
    { 11, "Bind"},
    { 12, "Bind_ack"},
    { 13, "Bind_nak"},
    { 14, "Alter_context"},
    { 15, "Alter_context_resp"},
    { 16, "AUTH3?"},
    { 17, "Shutdown"},
    { 18, "Co_cancel"},
    { 19, "Orphaned"},
    { 0,  NULL }
};

static const value_string drep_byteorder_vals[] = {
    { 0, "Big-endian" },
    { 1, "Little-endian" },
    { 0,  NULL }
};

static const value_string drep_character_vals[] = {
    { 0, "ASCII" },
    { 1, "EBCDIC" },
    { 0,  NULL }
};

static const value_string drep_fp_vals[] = {
    { 0, "IEEE" },
    { 1, "VAX" },
    { 2, "Cray" },
    { 3, "IBM" },
    { 0,  NULL }
};

static const true_false_string flags_set_truth = {
  "Set",
  "Not set"
};

static int proto_dcerpc = -1;

/* field defines */
static int hf_dcerpc_request_in = -1;
static int hf_dcerpc_response_in = -1;
static int hf_dcerpc_ver = -1;
static int hf_dcerpc_ver_minor = -1;
static int hf_dcerpc_packet_type = -1;
static int hf_dcerpc_cn_flags = -1;
static int hf_dcerpc_cn_flags_first_frag = -1;
static int hf_dcerpc_cn_flags_last_frag = -1;
static int hf_dcerpc_cn_flags_cancel_pending = -1;
static int hf_dcerpc_cn_flags_reserved = -1;
static int hf_dcerpc_cn_flags_mpx = -1;
static int hf_dcerpc_cn_flags_dne = -1;
static int hf_dcerpc_cn_flags_maybe = -1;
static int hf_dcerpc_cn_flags_object = -1;
static int hf_dcerpc_drep = -1;
static int hf_dcerpc_drep_byteorder = -1;
static int hf_dcerpc_drep_character = -1;
static int hf_dcerpc_drep_fp = -1;
static int hf_dcerpc_cn_frag_len = -1;
static int hf_dcerpc_cn_auth_len = -1;
static int hf_dcerpc_cn_call_id = -1;
static int hf_dcerpc_cn_max_xmit = -1;
static int hf_dcerpc_cn_max_recv = -1;
static int hf_dcerpc_cn_assoc_group = -1;
static int hf_dcerpc_cn_num_ctx_items = -1;
static int hf_dcerpc_cn_ctx_id = -1;
static int hf_dcerpc_cn_num_trans_items = -1;
static int hf_dcerpc_cn_bind_if_id = -1;
static int hf_dcerpc_cn_bind_if_ver = -1;
static int hf_dcerpc_cn_bind_if_ver_minor = -1;
static int hf_dcerpc_cn_bind_trans_id = -1;
static int hf_dcerpc_cn_bind_trans_ver = -1;
static int hf_dcerpc_cn_alloc_hint = -1;
static int hf_dcerpc_cn_sec_addr_len = -1;
static int hf_dcerpc_cn_sec_addr = -1;
static int hf_dcerpc_cn_num_results = -1;
static int hf_dcerpc_cn_ack_result = -1;
static int hf_dcerpc_cn_ack_reason = -1;
static int hf_dcerpc_cn_ack_trans_id = -1;
static int hf_dcerpc_cn_ack_trans_ver = -1;
static int hf_dcerpc_cn_cancel_count = -1;
static int hf_dcerpc_auth_type = -1;
static int hf_dcerpc_auth_level = -1;
static int hf_dcerpc_auth_pad_len = -1;
static int hf_dcerpc_auth_rsrvd = -1;
static int hf_dcerpc_auth_ctx_id = -1;
static int hf_dcerpc_dg_flags1 = -1;
static int hf_dcerpc_dg_flags1_rsrvd_01 = -1;
static int hf_dcerpc_dg_flags1_last_frag = -1;
static int hf_dcerpc_dg_flags1_frag = -1;
static int hf_dcerpc_dg_flags1_nofack = -1;
static int hf_dcerpc_dg_flags1_maybe = -1;
static int hf_dcerpc_dg_flags1_idempotent = -1;
static int hf_dcerpc_dg_flags1_broadcast = -1;
static int hf_dcerpc_dg_flags1_rsrvd_80 = -1;
static int hf_dcerpc_dg_flags2 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_01 = -1;
static int hf_dcerpc_dg_flags2_cancel_pending = -1;
static int hf_dcerpc_dg_flags2_rsrvd_04 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_08 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_10 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_20 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_40 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_80 = -1;
static int hf_dcerpc_dg_serial_hi = -1;
static int hf_dcerpc_obj_id = -1;
static int hf_dcerpc_dg_if_id = -1;
static int hf_dcerpc_dg_act_id = -1;
static int hf_dcerpc_dg_serial_lo = -1;
static int hf_dcerpc_dg_ahint = -1;
static int hf_dcerpc_dg_ihint = -1;
static int hf_dcerpc_dg_frag_len = -1;
static int hf_dcerpc_dg_frag_num = -1;
static int hf_dcerpc_dg_auth_proto = -1;
static int hf_dcerpc_opnum = -1;
static int hf_dcerpc_dg_seqnum = -1;
static int hf_dcerpc_dg_server_boot = -1;
static int hf_dcerpc_dg_if_ver = -1;
static int hf_dcerpc_array_max_count = -1;
static int hf_dcerpc_array_offset = -1;
static int hf_dcerpc_array_actual_count = -1;
static int hf_dcerpc_referent_id = -1;

static gint ett_dcerpc = -1;
static gint ett_dcerpc_cn_flags = -1;
static gint ett_dcerpc_drep = -1;
static gint ett_dcerpc_dg_flags1 = -1;
static gint ett_dcerpc_dg_flags2 = -1;
static gint ett_dcerpc_pointer_data = -1;

/* try to desegment big DCE/RPC packets over TCP? */
static gboolean dcerpc_cn_desegment = TRUE;


/*
 * Subdissectors
 */

/* the registered subdissectors */
static GHashTable *dcerpc_uuids;

typedef struct _dcerpc_uuid_key {
    e_uuid_t uuid;
    guint16 ver;
} dcerpc_uuid_key;

typedef struct _dcerpc_uuid_value {
    int proto;
    int ett;
    gchar *name;
    dcerpc_sub_dissector *procs;
} dcerpc_uuid_value;

static gint
dcerpc_uuid_equal (gconstpointer k1, gconstpointer k2)
{
    dcerpc_uuid_key *key1 = (dcerpc_uuid_key *)k1;
    dcerpc_uuid_key *key2 = (dcerpc_uuid_key *)k2;
    return ((memcmp (&key1->uuid, &key2->uuid, sizeof (e_uuid_t)) == 0)
            && (key1->ver == key2->ver));
}

static guint
dcerpc_uuid_hash (gconstpointer k)
{
    dcerpc_uuid_key *key = (dcerpc_uuid_key *)k;
    /* This isn't perfect, but the Data1 part of these is almost always
       unique. */
    return key->uuid.Data1;
}

void
dcerpc_init_uuid (int proto, int ett, e_uuid_t *uuid, guint16 ver,
                  dcerpc_sub_dissector *procs)
{
    dcerpc_uuid_key *key = g_malloc (sizeof (*key));
    dcerpc_uuid_value *value = g_malloc (sizeof (*value));

    key->uuid = *uuid;
    key->ver = ver;

    value->proto = proto;
    value->ett = ett;
    value->name = proto_get_protocol_short_name (proto);
    value->procs = procs;

    g_hash_table_insert (dcerpc_uuids, key, value);
}


/*
 * To keep track of ctx_id mappings.
 *
 * Everytime we see a bind call we update this table.
 * Note that we always specify a SMB FID. For non-SMB transports this
 * value is 0.
 */
static GHashTable *dcerpc_binds=NULL;

typedef struct _dcerpc_bind_key {
    conversation_t *conv;
    guint16 ctx_id;
    guint16 smb_fid;
} dcerpc_bind_key;

typedef struct _dcerpc_bind_value {
	e_uuid_t uuid;
	guint16 ver;
} dcerpc_bind_value;

static GMemChunk *dcerpc_bind_key_chunk=NULL;
static GMemChunk *dcerpc_bind_value_chunk=NULL;

static gint
dcerpc_bind_equal (gconstpointer k1, gconstpointer k2)
{
    dcerpc_bind_key *key1 = (dcerpc_bind_key *)k1;
    dcerpc_bind_key *key2 = (dcerpc_bind_key *)k2;
    return (key1->conv == key2->conv
            && key1->ctx_id == key2->ctx_id
            && key1->smb_fid == key2->smb_fid);
}

static guint
dcerpc_bind_hash (gconstpointer k)
{
    dcerpc_bind_key *key = (dcerpc_bind_key *)k;
    return ((guint)key->conv) + key->ctx_id + key->smb_fid;
}

/*
 * To keep track of callid mappings.  Should really use some generic
 * conversation support instead.
 */
static GHashTable *dcerpc_calls=NULL;

typedef struct _dcerpc_call_key {
    conversation_t *conv;
    guint32 call_id;
    guint16 smb_fid;
} dcerpc_call_key;

static GMemChunk *dcerpc_call_key_chunk=NULL;

static GMemChunk *dcerpc_call_value_chunk=NULL;

static gint
dcerpc_call_equal (gconstpointer k1, gconstpointer k2)
{
    dcerpc_call_key *key1 = (dcerpc_call_key *)k1;
    dcerpc_call_key *key2 = (dcerpc_call_key *)k2;
    return (key1->conv == key2->conv
            && key1->call_id == key2->call_id
            && key1->smb_fid == key2->smb_fid);
}

static guint
dcerpc_call_hash (gconstpointer k)
{
    dcerpc_call_key *key = (dcerpc_call_key *)k;
    return ((guint32)key->conv) + key->call_id + key->smb_fid;
}


/* to keep track of matched calls/responses
   this one uses the same value struct as calls, but the key is the frame id
*/
static GHashTable *dcerpc_matched=NULL;
static gint
dcerpc_matched_equal (gconstpointer k1, gconstpointer k2)
{
	return (guint32)k1 == (guint32)k2;
}

static guint
dcerpc_matched_hash (gconstpointer k)
{
	return (guint32)k;
}



/*
 * Utility functions.  Modeled after packet-rpc.c
 */

int
dissect_dcerpc_uint8 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                      proto_tree *tree, char *drep, 
                      int hfindex, guint8 *pdata)
{
    guint8 data;

    data = tvb_get_guint8 (tvb, offset);
    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, 1, (drep[0] & 0x10));
    }
    if (pdata)
        *pdata = data;
    return offset + 1;
}

int
dissect_dcerpc_uint16 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, char *drep, 
                       int hfindex, guint16 *pdata)
{
    guint16 data;

    data = ((drep[0] & 0x10)
            ? tvb_get_letohs (tvb, offset)
            : tvb_get_ntohs (tvb, offset));
    
    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, 2, (drep[0] & 0x10));
    }
    if (pdata)
        *pdata = data;
    return offset + 2;
}

int
dissect_dcerpc_uint32 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, char *drep, 
                       int hfindex, guint32 *pdata)
{
    guint32 data;

    data = ((drep[0] & 0x10)
            ? tvb_get_letohl (tvb, offset)
            : tvb_get_ntohl (tvb, offset));
    
    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, 4, (drep[0] & 0x10));
    }
    if (pdata)
        *pdata = data;
    return offset+4;
}

int
dissect_dcerpc_uint64 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, char *drep, 
                       int hfindex, unsigned char *pdata)
{
    if(pdata){
      tvb_memcpy(tvb, pdata, offset, 8);
      if(drep[0] & 0x10){/* XXX this might be the wrong way around */
	unsigned char data;
	data=pdata[0];pdata[0]=pdata[7];pdata[7]=data;
	data=pdata[1];pdata[1]=pdata[6];pdata[6]=data;
	data=pdata[2];pdata[2]=pdata[5];pdata[5]=data;
	data=pdata[3];pdata[3]=pdata[4];pdata[4]=data;
      }
    }

    if (tree) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 8, (drep[0] & 0x10));
    }

    return offset+8;
}

/*
 * a couple simpler things
 */
guint16
dcerpc_tvb_get_ntohs (tvbuff_t *tvb, gint offset, char *drep)
{
    if (drep[0] & 0x10) {
        return tvb_get_letohs (tvb, offset);
    } else {
        return tvb_get_ntohs (tvb, offset);
    }
}

guint32
dcerpc_tvb_get_ntohl (tvbuff_t *tvb, gint offset, char *drep)
{
    if (drep[0] & 0x10) {
        return tvb_get_letohl (tvb, offset);
    } else {
        return tvb_get_ntohl (tvb, offset);
    }
}

void
dcerpc_tvb_get_uuid (tvbuff_t *tvb, gint offset, char *drep, e_uuid_t *uuid)
{
    unsigned int i;
    uuid->Data1 = dcerpc_tvb_get_ntohl (tvb, offset, drep);
    uuid->Data2 = dcerpc_tvb_get_ntohs (tvb, offset+4, drep);
    uuid->Data3 = dcerpc_tvb_get_ntohs (tvb, offset+6, drep);

    for (i=0; i<sizeof (uuid->Data4); i++) {
        uuid->Data4[i] = tvb_get_guint8 (tvb, offset+8+i);
    }
}



/* NDR arrays */
/* function to dissect a unidimensional conformant array */
int 
dissect_ndr_ucarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		proto_tree *tree, char *drep, 
		dcerpc_dissect_fnct_t *fnct)
{
	guint32 i, count;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* conformant run, just dissect the max_count header */
		di->conformant_run=0;
		offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_dcerpc_array_max_count, &di->array_max_count);
		di->array_max_count_offset=offset-4;
		di->conformant_run=1;
	} else {
		/* we dont dont remember where  in the bytestream this fields was */
		proto_tree_add_uint(tree, hf_dcerpc_array_max_count, tvb, di->array_max_count_offset, 4, di->array_max_count);

		/* real run, dissect the elements */
		for(i=0;i<di->array_max_count;i++){
			offset = (*fnct)(tvb, offset, pinfo, tree, drep);
		}
	}

	return offset;
}
/* function to dissect a unidimensional conformant and varying array */
int 
dissect_ndr_ucvarray(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		proto_tree *tree, char *drep, 
		dcerpc_dissect_fnct_t *fnct)
{
	guint32 i, count;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* conformant run, just dissect the max_count header */
		di->conformant_run=0;
		offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_dcerpc_array_max_count, &di->array_max_count);
		di->array_max_count_offset=offset-4;
		offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_dcerpc_array_offset, &di->array_offset);
		di->array_offset_offset=offset-4;
		offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_dcerpc_array_actual_count, &di->array_actual_count);
		di->array_actual_count_offset=offset-4;
		di->conformant_run=1;
	} else {
		/* we dont dont remember where  in the bytestream these fields were */
		proto_tree_add_uint(tree, hf_dcerpc_array_max_count, tvb, di->array_max_count_offset, 4, di->array_max_count);
		proto_tree_add_uint(tree, hf_dcerpc_array_offset, tvb, di->array_offset_offset, 4, di->array_offset);
		proto_tree_add_uint(tree, hf_dcerpc_array_actual_count, tvb, di->array_actual_count_offset, 4, di->array_actual_count);

		/* real run, dissect the elements */
		for(i=0;i<di->array_actual_count;i++){
			offset = (*fnct)(tvb, offset, pinfo, tree, drep);
		}
	}

	return offset;
}


/* ndr pointer handling */
/* list of pointers encountered so far */
static GSList *ndr_pointer_list = NULL;

/* position where in the list to insert newly encountered pointers */
static int ndr_pointer_list_pos=0;

/* boolean controlling whether pointers are top-level or embedded */
static gboolean pointers_are_top_level = TRUE;

/* as a kludge, we represent all embedded reference pointers as id==-1
   hoping that his will not collide with any non-ref pointers */
typedef struct ndr_pointer_data {
	guint32 id;
	proto_tree *tree;
	dcerpc_dissect_fnct_t *fnct; /*if non-NULL, we have not called it yet*/
	int hf_index;
	int levels;
} ndr_pointer_data_t;

static void
init_ndr_pointer_list(packet_info *pinfo)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	di->conformant_run=0;

	while(ndr_pointer_list){
		ndr_pointer_data_t *npd;
	
		npd=g_slist_nth_data(ndr_pointer_list, 0);
		ndr_pointer_list=g_slist_remove(ndr_pointer_list, npd);
		if(npd){
			g_free(npd);
		}
	}

	ndr_pointer_list=NULL;
	ndr_pointer_list_pos=0;
	pointers_are_top_level=TRUE;
}

static int
dissect_deferred_pointers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, char *drep)
{
	int found_new_pointer;
	dcerpc_info *di;

	di=pinfo->private_data;
	do{
		int i, len;

		found_new_pointer=0;
		len=g_slist_length(ndr_pointer_list);
		for(i=0;i<len;i++){
			ndr_pointer_data_t *tnpd;
			tnpd=g_slist_nth_data(ndr_pointer_list, i);
			if(tnpd->fnct){
				dcerpc_dissect_fnct_t *fnct;

				found_new_pointer=1;
				fnct=tnpd->fnct;
				tnpd->fnct=NULL;
				ndr_pointer_list_pos=i+1;
				di->hf_index=tnpd->hf_index;
				di->levels=tnpd->levels;
				/* first a run to handle any conformant
				   array headers */
				di->conformant_run=1;
				offset = (*(fnct))(tvb, offset, pinfo, NULL, drep);
				/* now we dissect the actual pointer */
				di->conformant_run=0;
				offset = (*(fnct))(tvb, offset, pinfo, tnpd->tree, drep);
				break;
			}
		}
	} while(found_new_pointer);

	return offset;
}
						

static void
add_pointer_to_list(packet_info *pinfo, proto_tree *tree, 
		dcerpc_dissect_fnct_t *fnct, guint32 id, int hf_index, int levels)
{
	ndr_pointer_data_t *npd;

	/* check if this pointer is valid */
	if(id!=0xffffffff){
		dcerpc_info *di;
	        dcerpc_call_value *value;

		di=pinfo->private_data;
		value=di->call_data;

		if(di->request){
			if(!(pinfo->fd->flags.visited)){
				if(id>value->max_ptr){
					value->max_ptr=id;
				}
			}
		} else {
			/* if we havent seen the request bail out since we cant
			   know whether this is the first non-NULL instance 
			   or not */
			if(value->req_frame==-1){
				/* XXX THROW EXCEPTION */
			}

			/* We saw this one in the request frame, nothing to
			   dissect later */
			if(id<=value->max_ptr){
				return;
			}
		}
	}

	npd=g_malloc(sizeof(ndr_pointer_data_t));
	npd->id=id;
	npd->tree=tree;
	npd->fnct=fnct;
	npd->hf_index=hf_index;
	npd->levels=levels;
	ndr_pointer_list = g_slist_insert(ndr_pointer_list, npd, 
					ndr_pointer_list_pos);
	ndr_pointer_list_pos++;
}


static int
find_pointer_index(guint32 id)
{
	ndr_pointer_data_t *npd;
	int i,len;
	
	len=g_slist_length(ndr_pointer_list);
	for(i=0;i<len;i++){
		npd=g_slist_nth_data(ndr_pointer_list, i);
		if(npd){
			if(npd->id==id){
				return i;
			}
		}
	}
	
	return -1;
}

/* this function dissects an NDR pointer and stores the callback for later deferred dissection.
 * fnct is the callback function for when we have reached this object in the bytestream.
 * type is what type of pointer this is
 * text is what text we should put in any created tree node
 * hf_index is what hf value we want to pass to the callback function when it is called,
 *    the callback can later pich this one up from di->hf_index.
 * levels is a generic int we want to pass to teh callback function.
 *    the callback can later pick it up from di->levels
 *
 * See packet-dcerpc-samr.c for examples
 */
int 
dissect_ndr_pointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                        proto_tree *tree, char *drep, 
                        dcerpc_dissect_fnct_t *fnct, int type, char *text, int hf_index, int levels)
{
	dcerpc_info *di;
	
	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call was only for dissecting the header for any
		   embedded conformant array. we will not parse any
		   pointers in this mode.
		*/
		return offset;
	}

	/*TOP LEVEL REFERENCE POINTER*/
	if( pointers_are_top_level
	&& (type==NDR_POINTER_REF) ){
		add_pointer_to_list(pinfo, tree, fnct, 0xffffffff, hf_index, levels);
		goto after_ref_id;
	}

	/*TOP LEVEL FULL POINTER*/
	if( pointers_are_top_level
	&& (type==NDR_POINTER_PTR) ){
		int idx;
		guint32 id;
		proto_item *item;
		proto_tree *tr;

		/* get the referent id */
		offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &id);
	
		/* we got a NULL pointer */
		if(id==0){
			proto_tree_add_text(tree, tvb, offset-4, 4,
				"(NULL pointer) %s",text);
			goto after_ref_id;
		}

		/* see if we have seen this pointer before */
		idx=find_pointer_index(id);

		/* we have seen this pointer before */
		if(idx>=0){
			proto_tree_add_text(tree, tvb, offset-4, 4,
				"(duplicate PTR) %s",text);
			goto after_ref_id;
		}

		/* new pointer */
		item=proto_tree_add_text(tree, tvb, offset-4, 4, 
			"%s", text);
		tr=proto_item_add_subtree(item,ett_dcerpc_pointer_data);
		proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb, offset-4, 4, id);
		add_pointer_to_list(pinfo, tr, fnct, id, hf_index, levels);
		goto after_ref_id;
	}
	/*TOP LEVEL UNIQUE POINTER*/
	if( pointers_are_top_level
	&& (type==NDR_POINTER_UNIQUE) ){
		int idx;
		guint32 id;
		proto_item *item;
		proto_tree *tr;

		/* get the referent id */
		offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &id);
	
		/* we got a NULL pointer */
		if(id==0){
			proto_tree_add_text(tree, tvb, offset-4, 4,
				"(NULL pointer) %s",text);
			goto after_ref_id;
		}

		/* new pointer */
		item=proto_tree_add_text(tree, tvb, offset-4, 4, 
			"%s", text);
		tr=proto_item_add_subtree(item,ett_dcerpc_pointer_data);
		proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb, offset-4, 4, id);
		add_pointer_to_list(pinfo, tr, fnct, 0xffffffff, hf_index, levels);
		goto after_ref_id;
	}

	/*EMBEDDED REFERENCE POINTER*/
	if( (!pointers_are_top_level)
	&& (type==NDR_POINTER_REF) ){
		guint32 id;
		proto_item *item;
		proto_tree *tr;

		/* get the referent id */
		offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &id);
	
		/* new pointer */
		item=proto_tree_add_text(tree, tvb, offset-4, 4, 
			"%s",text);
		tr=proto_item_add_subtree(item,ett_dcerpc_pointer_data);
		proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb, offset-4, 4, id);
		add_pointer_to_list(pinfo, tr, fnct, 0xffffffff, hf_index, levels);
		goto after_ref_id;
	}

	/*EMBEDDED UNIQUE POINTER*/
	if( (!pointers_are_top_level)
	&& (type==NDR_POINTER_UNIQUE) ){
		int idx;
		guint32 id;
		proto_item *item;
		proto_tree *tr;

		/* get the referent id */
		offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &id);
	
		/* we got a NULL pointer */
		if(id==0){
			proto_tree_add_text(tree, tvb, offset-4, 4,
				"(NULL pointer) %s", text);
			goto after_ref_id;
		}

		/* new pointer */
		item=proto_tree_add_text(tree, tvb, offset-4, 4, 
			"%s",text);
		tr=proto_item_add_subtree(item,ett_dcerpc_pointer_data);
		proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb, offset-4, 4, id);
		add_pointer_to_list(pinfo, tr, fnct, 0xffffffff, hf_index, levels);
		goto after_ref_id;
	}

	/*EMBEDDED FULL POINTER*/
	if( (!pointers_are_top_level)
	&& (type==NDR_POINTER_PTR) ){
		int idx;
		guint32 id;
		proto_item *item;
		proto_tree *tr;

		/* get the referent id */
		offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &id);
	
		/* we got a NULL pointer */
		if(id==0){
			proto_tree_add_text(tree, tvb, offset-4, 4,
				"(NULL pointer) %s",text);
			goto after_ref_id;
		}

		/* see if we have seen this pointer before */
		idx=find_pointer_index(id);

		/* we have seen this pointer before */
		if(idx>=0){
			proto_tree_add_text(tree, tvb, offset-4, 4,
				"(duplicate PTR) %s",text);
			goto after_ref_id;
		}

		/* new pointer */
		item=proto_tree_add_text(tree, tvb, offset-4, 4, 
			"%s", text);
		tr=proto_item_add_subtree(item,ett_dcerpc_pointer_data);
		proto_tree_add_uint(tr, hf_dcerpc_referent_id, tvb, offset-4, 4, id);
		add_pointer_to_list(pinfo, tr, fnct, id, hf_index, levels);
		goto after_ref_id;
	}


after_ref_id:
	/* After each top level pointer we have dissected we have to
	   dissect all deferrals before we move on to the next top level
	   argument */
	if(pointers_are_top_level==TRUE){
		pointers_are_top_level=FALSE;
		offset = dissect_deferred_pointers(pinfo, tree, tvb, offset, drep);
		pointers_are_top_level=TRUE;
	}

	return offset;
}



static int
dcerpc_try_handoff (packet_info *pinfo, proto_tree *tree,
                    proto_tree *dcerpc_tree,
                    tvbuff_t *tvb, gint offset,
                    guint16 opnum, gboolean is_rqst,
                    char *drep, dcerpc_info *info)
{
    dcerpc_uuid_key key;
    dcerpc_uuid_value *sub_proto;
    int length;
    proto_tree *sub_tree = NULL;
    dcerpc_sub_dissector *proc;
    gchar *name = NULL;
    dcerpc_dissect_fnct_t *sub_dissect;
    const char *saved_proto;
    void *saved_private_data;

    key.uuid = info->call_data->uuid;
    key.ver = info->call_data->ver;

    
    if ((sub_proto = g_hash_table_lookup (dcerpc_uuids, &key)) == NULL
         || !proto_is_protocol_enabled(sub_proto->proto)) {
	/*
	 * We don't have a dissector for this UUID, or the protocol
	 * for that UUID is disabled.
	 */
        length = tvb_length_remaining (tvb, offset);
        if (length > 0) {
            proto_tree_add_text (dcerpc_tree, tvb, offset, length,
                                 "Stub data (%d byte%s)", length,
                                 plurality(length, "", "s"));
        }
        return -1;
    }

    if (tree) {
        proto_item *sub_item;
        sub_item = proto_tree_add_item (tree, sub_proto->proto, tvb, offset, 
                                        -1, FALSE);

        if (sub_item) {
            sub_tree = proto_item_add_subtree (sub_item, sub_proto->ett);
        }
        
    }
    for (proc = sub_proto->procs; proc->name; proc++) {
        if (proc->num == opnum) {
            name = proc->name;
            break;
        }
    }

    if (!name)
        name = "Unknown?!";

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_add_fstr (pinfo->cinfo, COL_INFO, "%s %s(...)",
                      is_rqst ? "rqst" : "rply", name);
    }

    if (check_col (pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str (pinfo->cinfo, COL_PROTOCOL, sub_proto->name);
    }

    sub_dissect = is_rqst ? proc->dissect_rqst : proc->dissect_resp;
    if (sub_dissect) {
        saved_proto = pinfo->current_proto;
	saved_private_data = pinfo->private_data;
        pinfo->current_proto = sub_proto->name;
	pinfo->private_data = (void *)info;

	init_ndr_pointer_list(pinfo);
        offset = sub_dissect (tvb, offset, pinfo, sub_tree, drep);

        pinfo->current_proto = saved_proto;
	pinfo->private_data = saved_private_data;
    } else {
        length = tvb_length_remaining (tvb, offset);
        if (length > 0) {
            proto_tree_add_text (sub_tree, tvb, offset, length,
                                 "Stub data (%d byte%s)", length,
                                 plurality(length, "", "s"));
        }
    }
    return 0;
}

static int
dissect_dcerpc_cn_auth (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        e_dce_cn_common_hdr_t *hdr)
{
    int offset;
    guint8 auth_pad_len;

    /*
     * The authentication information is at the *end* of the PDU; in
     * request and response PDUs, the request and response stub data
     * come before it.
     *
     * If the full packet is here, and we've got an auth len, and it's
     * valid, then dissect the auth info
     */
    if (tvb_length (tvb) >= hdr->frag_len
        && hdr->auth_len
        && (hdr->auth_len + 8 <= hdr->frag_len)) {

        offset = hdr->frag_len - (hdr->auth_len + 8);
        
        offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                       hf_dcerpc_auth_type, NULL);
        offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                       hf_dcerpc_auth_level, NULL);
        offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                       hf_dcerpc_auth_pad_len, &auth_pad_len);
        offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                       hf_dcerpc_auth_rsrvd, NULL);
        offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                        hf_dcerpc_auth_ctx_id, NULL);

        proto_tree_add_text (dcerpc_tree, tvb, offset, hdr->auth_len, "Auth Data");

        /* figure out where the auth padding starts */
        offset = hdr->frag_len - (hdr->auth_len + 8 + auth_pad_len);
        if (offset > 0 && auth_pad_len) {
            proto_tree_add_text (dcerpc_tree, tvb, offset, 
                                 auth_pad_len, "Auth padding");
            return hdr->auth_len + 8 + auth_pad_len;
        } else {
            return hdr->auth_len + 8;
        }
    } else {
        return 0;
    }
}


/* We need to hash in the SMB fid number to generate a unique hash table
   key as DCERPC over SMB allows several pipes over the same TCP/IP
   socket. */

static guint16 get_smb_fid (void *private_data)
{
    dcerpc_private_info *priv = (dcerpc_private_info *)private_data;
	
    if (!priv)
        return 0;	/* Nothing to see here */

    /* DCERPC over smb */

    if (priv->transport_type == DCERPC_TRANSPORT_SMB)
        return priv->data.smb.fid;

    /* Some other transport... */

    return 0;
}

/*
 * Connection oriented packet types
 */

static void
dissect_dcerpc_cn_bind (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        e_dce_cn_common_hdr_t *hdr)
{
    conversation_t *conv = NULL;
    guint8 num_ctx_items;
    guint i;
    gboolean saw_ctx_item = FALSE;
    guint16 ctx_id;
    guint16 num_trans_items;
    guint j;
    e_uuid_t if_id;
    e_uuid_t trans_id;
    guint32 trans_ver;
    guint16 if_ver, if_ver_minor;
    int offset = 16;

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_max_xmit, NULL);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_max_recv, NULL);

    offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_assoc_group, NULL);

    offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_num_ctx_items, &num_ctx_items);

    /* padding */
    offset += 3;

    for (i = 0; i < num_ctx_items; i++) {
      offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                      hf_dcerpc_cn_ctx_id, &ctx_id);

      offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                      hf_dcerpc_cn_num_trans_items, &num_trans_items);

      dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &if_id);
      if (dcerpc_tree) {
          proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_cn_bind_if_id, tvb,
                                        offset, 16, "HMMM",
                                        "Interface UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                        if_id.Data1, if_id.Data2, if_id.Data3,
                                        if_id.Data4[0], if_id.Data4[1],
                                        if_id.Data4[2], if_id.Data4[3],
                                        if_id.Data4[4], if_id.Data4[5],
                                        if_id.Data4[6], if_id.Data4[7]);
      }
      offset += 16;

      if (hdr->drep[0] & 0x10) {
          offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                          hf_dcerpc_cn_bind_if_ver, &if_ver);
          offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                          hf_dcerpc_cn_bind_if_ver_minor, &if_ver_minor);
      } else {
          offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                          hf_dcerpc_cn_bind_if_ver_minor, &if_ver_minor);
          offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                          hf_dcerpc_cn_bind_if_ver, &if_ver);
      }

      if (!saw_ctx_item) {
        conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                                  pinfo->srcport, pinfo->destport, 0);
        if (conv == NULL) {
            conv = conversation_new (&pinfo->src, &pinfo->dst, pinfo->ptype,
                                     pinfo->srcport, pinfo->destport, 0);
        }

	/* if this is the first time we see this packet, we need to
	   update the dcerpc_binds table so that any later calls can
	   match to the interface.
	   XXX We assume that BINDs will NEVER be fragmented.
	*/
	if(!(pinfo->fd->flags.visited)){
		dcerpc_bind_key *key;
		dcerpc_bind_value *value;

	        key = g_mem_chunk_alloc (dcerpc_bind_key_chunk);
        	key->conv = conv;
        	key->ctx_id = ctx_id;
        	key->smb_fid = get_smb_fid(pinfo->private_data);

        	value = g_mem_chunk_alloc (dcerpc_bind_value_chunk);
        	value->uuid = if_id;
        	value->ver = if_ver;

		/* add this entry to the bind table, first removing any
		   previous ones that are identical
		 */
		if(g_hash_table_lookup(dcerpc_binds, key)){
			g_hash_table_remove(dcerpc_binds, key);
		}
        	g_hash_table_insert (dcerpc_binds, key, value);
	}

        if (check_col (pinfo->cinfo, COL_INFO)) {
          col_add_fstr (pinfo->cinfo, COL_INFO, "%s: UUID %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x ver %d.%d",
                        hdr->ptype == PDU_BIND ? "Bind" : "Alter Ctx",
                        if_id.Data1, if_id.Data2, if_id.Data3,
                        if_id.Data4[0], if_id.Data4[1],
                        if_id.Data4[2], if_id.Data4[3],
                        if_id.Data4[4], if_id.Data4[5],
                        if_id.Data4[6], if_id.Data4[7],
                        if_ver, if_ver_minor);
        }
        saw_ctx_item = TRUE;
      }

      for (j = 0; j < num_trans_items; j++) {
        dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &trans_id);
        if (dcerpc_tree) {
            proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_cn_bind_trans_id, tvb,
                                          offset, 16, "HMMM",
                                          "Transfer Syntax: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                          trans_id.Data1, trans_id.Data2, trans_id.Data3,
                                          trans_id.Data4[0], trans_id.Data4[1],
                                          trans_id.Data4[2], trans_id.Data4[3],
                                          trans_id.Data4[4], trans_id.Data4[5],
                                          trans_id.Data4[6], trans_id.Data4[7]);
        }
        offset += 16;

        offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                        hf_dcerpc_cn_bind_trans_ver, &trans_ver);
      }
    }

    dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, hdr);
}

static void
dissect_dcerpc_cn_bind_ack (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                            e_dce_cn_common_hdr_t *hdr)
{
    guint16 max_xmit, max_recv;
    guint16 sec_addr_len;
    guint8 num_results;
    guint i;
    guint16 result;
    guint16 reason;
    e_uuid_t trans_id;
    guint32 trans_ver;

    int offset = 16;

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_max_xmit, &max_xmit);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_max_recv, &max_recv);

    offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_assoc_group, NULL);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_sec_addr_len, &sec_addr_len);
    if (sec_addr_len != 0) {
        proto_tree_add_item (dcerpc_tree, hf_dcerpc_cn_sec_addr, tvb, offset,
                             sec_addr_len, FALSE);
        offset += sec_addr_len;
    }

    if (offset % 4) {
        offset += 4 - offset % 4;
    }

    offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_num_results, &num_results);

    /* padding */
    offset += 3;

    for (i = 0; i < num_results; i++) {
        offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, 
                                        hdr->drep, hf_dcerpc_cn_ack_result,
                                        &result);
        offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, 
                                        hdr->drep, hf_dcerpc_cn_ack_reason,
                                        &reason);

        dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &trans_id);
        if (dcerpc_tree) {
            proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_cn_ack_trans_id, tvb,
                                          offset, 16, "HMMM",
                                          "Transfer Syntax: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                          trans_id.Data1, trans_id.Data2, trans_id.Data3,
                                          trans_id.Data4[0], trans_id.Data4[1],
                                          trans_id.Data4[2], trans_id.Data4[3],
                                          trans_id.Data4[4], trans_id.Data4[5],
                                          trans_id.Data4[6], trans_id.Data4[7]);
        }
        offset += 16;

        offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                        hf_dcerpc_cn_ack_trans_ver, &trans_ver);
    }
    
    dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, hdr);

    if (check_col (pinfo->cinfo, COL_INFO)) {
        if (num_results != 0 && result == 0) {
            col_add_fstr (pinfo->cinfo, COL_INFO, "%s ack: accept  max_xmit: %d  max_recv: %d",
                          hdr->ptype == PDU_BIND_ACK ? "Bind" : "Alter ctx",
                          max_xmit, max_recv);
        } else {
            /* FIXME: should put in reason */
            col_add_fstr (pinfo->cinfo, COL_INFO, "%s ack: %s",
                          hdr->ptype == PDU_BIND_ACK ? "Bind" : "Alter ctx",
                          result == 1 ? "User reject" :
                          result == 2 ? "Provider reject" :
                          "Unknown");
        }
    }
}

static void
dissect_dcerpc_cn_rqst (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        proto_tree *tree, e_dce_cn_common_hdr_t *hdr)
{
    conversation_t *conv;
    guint16 ctx_id;
    guint16 opnum;
    e_uuid_t obj_id;
    int auth_sz = 0;
    int offset = 16;

    offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_alloc_hint, NULL);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_ctx_id, &ctx_id);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_opnum, &opnum);

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_add_fstr (pinfo->cinfo, COL_INFO, "Request: opnum: %d  ctx_id:%d",
                         opnum, ctx_id);
    }

    if (hdr->flags & 0x80) {
        dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &obj_id);
        if (dcerpc_tree) {
            proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                          offset, 16, "HMMM",
                                          "Object UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                          obj_id.Data1, obj_id.Data2, obj_id.Data3,
                                          obj_id.Data4[0],
                                          obj_id.Data4[1],
                                          obj_id.Data4[2],
                                          obj_id.Data4[3],
                                          obj_id.Data4[4],
                                          obj_id.Data4[5],
                                          obj_id.Data4[6],
                                          obj_id.Data4[7]);
        }
        offset += 16;
    }

    auth_sz = dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, hdr);

    conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                              pinfo->srcport, pinfo->destport, 0);
    if (!conv) {

    } else {
        dcerpc_call_value *value;
        int length, reported_length, stub_length;
	dcerpc_info di;

	/* !!! we can NOT check flags.visited here since this will interact
	   badly with when SMB handles (i.e. calls the subdissector)
	   and desegmented pdu's .
	   Instead we check if this pdu is already in the matched table or not
	*/
	if(!g_hash_table_lookup(dcerpc_matched, (void *)pinfo->fd->num)){
		dcerpc_bind_key bind_key;
		dcerpc_bind_value *bind_value;

		bind_key.conv=conv;
		bind_key.ctx_id=ctx_id;
		bind_key.smb_fid=get_smb_fid(pinfo->private_data);

		if((bind_value=g_hash_table_lookup(dcerpc_binds, &bind_key))){
			dcerpc_call_key *call_key;
			dcerpc_call_value *call_value;

			/* We found the binding so just add the call
			   to both the call table and the matched table
			*/
			call_key=g_mem_chunk_alloc (dcerpc_call_key_chunk);
			call_key->conv=conv;
			call_key->call_id=hdr->call_id;
			call_key->smb_fid=get_smb_fid(pinfo->private_data);

			/* if there is already a matching call in the table
			   remove it so it is replaced with the new one */
			if(g_hash_table_lookup(dcerpc_calls, call_key)){
				g_hash_table_remove(dcerpc_calls, call_key);
			}

			call_value=g_mem_chunk_alloc (dcerpc_call_value_chunk);
			call_value->uuid = bind_value->uuid;
			call_value->ver = bind_value->ver;
			call_value->opnum = opnum;
			call_value->req_frame=pinfo->fd->num;
			call_value->rep_frame=-1;
			call_value->max_ptr=0;
			call_value->private_data = NULL;
			g_hash_table_insert (dcerpc_calls, call_key, call_value);

			g_hash_table_insert (dcerpc_matched, (void *)pinfo->fd->num, call_value);	
		}
	}

	value=g_hash_table_lookup (dcerpc_matched, (void *)pinfo->fd->num);


        if (value) {

            /* handoff this call */
            length = tvb_length_remaining(tvb, offset);
            reported_length = tvb_reported_length_remaining(tvb, offset);
            stub_length = hdr->frag_len - offset - auth_sz;
            if (length > stub_length)
              length = stub_length;
            if (reported_length > stub_length)
              reported_length = stub_length;
	    di.conv = conv;
	    di.call_id = hdr->call_id;
	    di.smb_fid = get_smb_fid(pinfo->private_data);
	    di.request = TRUE;
	    di.call_data = value;

	    if(value->rep_frame!=-1){
		proto_tree_add_uint(dcerpc_tree, hf_dcerpc_response_in, 
				    tvb, 0, 0, value->rep_frame);
	    }

            dcerpc_try_handoff (pinfo, tree, dcerpc_tree,
                                tvb_new_subset (tvb, offset, length,
                                                reported_length),
                                0, opnum, TRUE, hdr->drep, &di);
        }
    }
}

static void
dissect_dcerpc_cn_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        proto_tree *tree, e_dce_cn_common_hdr_t *hdr)
{
    dcerpc_call_value *value = NULL;
    conversation_t *conv;
    guint16 ctx_id;
    int auth_sz = 0;
    int offset = 16;

    offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_alloc_hint, NULL);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_ctx_id, &ctx_id);

    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_add_fstr (pinfo->cinfo, COL_INFO, "Response: call_id: %d  ctx_id:%d",
                      hdr->call_id, ctx_id);
    }

    offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_cancel_count, NULL);
    /* padding */
    offset++;

    auth_sz = dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, hdr);

    conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                              pinfo->srcport, pinfo->destport, 0);
    if (!conv) {
        /* no point in creating one here, really */
    } else {

	/* !!! we can NOT check flags.visited here since this will interact
	   badly with when SMB handles (i.e. calls the subdissector)
	   and desegmented pdu's .
	   Instead we check if this pdu is already in the matched table or not
	*/
	if(!g_hash_table_lookup(dcerpc_matched, (void *)pinfo->fd->num)){
		dcerpc_call_key call_key;
		dcerpc_call_value *call_value;

		call_key.conv=conv;
		call_key.call_id=hdr->call_id;
		call_key.smb_fid=get_smb_fid(pinfo->private_data);

		if((call_value=g_hash_table_lookup(dcerpc_calls, &call_key))){
			g_hash_table_insert (dcerpc_matched, (void *)pinfo->fd->num, call_value);
			if(call_value->rep_frame==-1){
				call_value->rep_frame=pinfo->fd->num;
			}

		}
	}

	value=g_hash_table_lookup(dcerpc_matched, (void *)pinfo->fd->num);

        if (value) {
	    int length, reported_length, stub_length;
            dcerpc_info di;

            /* handoff this call */
            length = tvb_length_remaining(tvb, offset);
            reported_length = tvb_reported_length_remaining(tvb, offset);
            stub_length = hdr->frag_len - offset - auth_sz;
            if (length > stub_length)
              length = stub_length;
            if (reported_length > stub_length)
              reported_length = stub_length;
	    di.conv = conv;
	    di.call_id = hdr->call_id;
	    di.smb_fid = get_smb_fid(pinfo->private_data);
	    di.request = FALSE;
	    di.call_data = value;

	    proto_tree_add_uint (dcerpc_tree, hf_dcerpc_opnum, tvb, 0, 0, value->opnum);
	    if(value->req_frame!=-1){
		proto_tree_add_uint(dcerpc_tree, hf_dcerpc_request_in, 
				    tvb, 0, 0, value->req_frame);
	    }

            dcerpc_try_handoff (pinfo, tree, dcerpc_tree,
                                tvb_new_subset (tvb, offset, length,
                                                reported_length),
                                0, value->opnum, FALSE, hdr->drep, &di);
        }
    }
}

/*
 * DCERPC dissector for connection oriented calls
 */
static int
dissect_dcerpc_cn (tvbuff_t *tvb, int offset, packet_info *pinfo,
                   proto_tree *tree, gboolean can_desegment)
{
    static char nulls[4] = { 0 };
    int start_offset;
    int padding = 0;
    proto_item *ti = NULL;
    proto_item *tf = NULL;
    proto_tree *dcerpc_tree = NULL;
    proto_tree *cn_flags_tree = NULL;
    proto_tree *drep_tree = NULL;
    e_dce_cn_common_hdr_t hdr;

    /*
     * when done over nbt, dcerpc requests are padded with 4 bytes of null
     * data for some reason.
     *
     * XXX - if that's always the case, the right way to do this would
     * be to have a "dissect_dcerpc_cn_nb" routine which strips off
     * the 4 bytes of null padding, and make that the dissector
     * used for "netbios".
     */
    if (tvb_bytes_exist (tvb, offset, 4) &&
 	tvb_memeql (tvb, offset, nulls, 4) == 0) {

        /*
         * Skip the padding.
         */
        offset += 4;
        padding += 4;
    }

    /*
     * Check if this looks like a C/O DCERPC call
     */
    if (!tvb_bytes_exist (tvb, offset, sizeof (hdr))) {
        return -1;
    }
    start_offset = offset;
    hdr.rpc_ver = tvb_get_guint8 (tvb, offset++);
    if (hdr.rpc_ver != 5)
        return -1;
    hdr.rpc_ver_minor = tvb_get_guint8 (tvb, offset++);
    if (hdr.rpc_ver_minor != 0 && hdr.rpc_ver_minor != 1)
        return -1;
    hdr.ptype = tvb_get_guint8 (tvb, offset++);
    if (hdr.ptype > 19)
        return -1;

    if (check_col (pinfo->cinfo, COL_PROTOCOL))
        col_set_str (pinfo->cinfo, COL_PROTOCOL, "DCERPC");
    if (check_col (pinfo->cinfo, COL_INFO))
        col_set_str (pinfo->cinfo, COL_INFO, pckt_vals[hdr.ptype].strptr);

    hdr.flags = tvb_get_guint8 (tvb, offset++);
    tvb_memcpy (tvb, (guint8 *)hdr.drep, offset, sizeof (hdr.drep));
    offset += sizeof (hdr.drep);

    hdr.frag_len = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.auth_len = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.call_id = dcerpc_tvb_get_ntohl (tvb, offset, hdr.drep);
    offset += 4;

    offset = start_offset;
    if (can_desegment && pinfo->can_desegment
        && hdr.frag_len > tvb_length_remaining (tvb, offset)) {
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = hdr.frag_len - tvb_length_remaining (tvb, offset);
        return 0;	/* desegmentation required */
    }

    if (tree) {
        ti = proto_tree_add_item (tree, proto_dcerpc, tvb, offset, hdr.frag_len, FALSE);
        if (ti) {
            dcerpc_tree = proto_item_add_subtree (ti, ett_dcerpc);
        }
        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_ver, tvb, offset++, 1, hdr.rpc_ver);
        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_ver_minor, tvb, offset++, 1, hdr.rpc_ver_minor);
        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_packet_type, tvb, offset++, 1, hdr.ptype);
        tf = proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_flags, tvb, offset, 1, hdr.flags);
        cn_flags_tree = proto_item_add_subtree (tf, ett_dcerpc_cn_flags);
        if (cn_flags_tree) {
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_first_frag, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_last_frag, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_cancel_pending, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_reserved, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_mpx, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_dne, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_maybe, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_object, tvb, offset, 1, hdr.flags);
        }
        offset++;

        tf = proto_tree_add_bytes (dcerpc_tree, hf_dcerpc_drep, tvb, offset, 4, hdr.drep);
        drep_tree = proto_item_add_subtree (tf, ett_dcerpc_drep);
        if (drep_tree) {
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_byteorder, tvb, offset, 1, hdr.drep[0] >> 4);
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_character, tvb, offset, 1, hdr.drep[0] & 0x0f);
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_fp, tvb, offset+1, 1, hdr.drep[1]);
        }
        offset += sizeof (hdr.drep);

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_frag_len, tvb, offset, 2, hdr.frag_len);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_auth_len, tvb, offset, 2, hdr.auth_len);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_call_id, tvb, offset, 4, hdr.call_id);
        offset += 4;
    }


    /*
     * Packet type specific stuff is next.
     */
    switch (hdr.ptype) {
    case PDU_BIND:
    case PDU_ALTER:
        dissect_dcerpc_cn_bind (tvb, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_BIND_ACK:
    case PDU_ALTER_ACK:
        dissect_dcerpc_cn_bind_ack (tvb, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_REQ:
        dissect_dcerpc_cn_rqst (tvb, pinfo, dcerpc_tree, tree, &hdr);
        break;

    case PDU_RESP:
        dissect_dcerpc_cn_resp (tvb, pinfo, dcerpc_tree, tree, &hdr);
        break;

    default:
        /* might as well dissect the auth info */
        dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, &hdr);
        break;
    }
    return hdr.frag_len + padding;
}

/*
 * DCERPC dissector for connection oriented calls over packet-oriented
 * transports
 */
static gboolean
dissect_dcerpc_cn_pk (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /*
     * Only one PDU per transport packet, and only one transport
     * packet per PDU.
     */
    if (dissect_dcerpc_cn (tvb, 0, pinfo, tree, FALSE) == -1) {
        /*
         * It wasn't a DCERPC PDU.
         */
        return FALSE;
    } else {
        /*
         * It was.
         */
        return TRUE;
    }
}

/*
 * DCERPC dissector for connection oriented calls over byte-stream
 * transports
 */
static gboolean
dissect_dcerpc_cn_bs (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int pdu_len;
    gboolean ret = FALSE;

    /*
     * There may be multiple PDUs per transport packet; keep
     * processing them.
     */
    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        pdu_len = dissect_dcerpc_cn (tvb, offset, pinfo, tree,
                                     dcerpc_cn_desegment);
        if (pdu_len == -1) {
            /*
             * Not a DCERPC PDU.
             */
            break;
        }

        /*
         * Well, we've seen at least one DCERPC PDU.
         */
        ret = TRUE;

        if (pdu_len == 0) {
            /*
             * Desegmentation required - bail now.
             */
            break;
	}

        /*
         * Step to the next PDU.
         */
        offset += pdu_len;
    }
    return ret;
}

/*
 * DCERPC dissector for connectionless calls
 */
static gboolean
dissect_dcerpc_dg (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *tf = NULL;
    proto_tree *dcerpc_tree = NULL;
    proto_tree *dg_flags1_tree = NULL;
    proto_tree *dg_flags2_tree = NULL;
    proto_tree *drep_tree = NULL;
    e_dce_dg_common_hdr_t hdr;
    int offset = 0;
    conversation_t *conv;

    /*
     * Check if this looks like a CL DCERPC call.  All dg packets
     * have an 80 byte header on them.  Which starts with
     * version (4), pkt_type.
     */
    if (!tvb_bytes_exist (tvb, 0, sizeof (hdr))) {
        return FALSE;
    }
    hdr.rpc_ver = tvb_get_guint8 (tvb, offset++);
    if (hdr.rpc_ver != 4)
        return FALSE;
    hdr.ptype = tvb_get_guint8 (tvb, offset++);
    if (hdr.ptype > 19)
        return FALSE;

    if (check_col (pinfo->cinfo, COL_PROTOCOL))
        col_set_str (pinfo->cinfo, COL_PROTOCOL, "DCERPC");
    if (check_col (pinfo->cinfo, COL_INFO))
        col_set_str (pinfo->cinfo, COL_INFO, pckt_vals[hdr.ptype].strptr);

    hdr.flags1 = tvb_get_guint8 (tvb, offset++);
    hdr.flags2 = tvb_get_guint8 (tvb, offset++);
    tvb_memcpy (tvb, (guint8 *)hdr.drep, offset, sizeof (hdr.drep));
    offset += sizeof (hdr.drep);
    hdr.serial_hi = tvb_get_guint8 (tvb, offset++);
    dcerpc_tvb_get_uuid (tvb, offset, hdr.drep, &hdr.obj_id);
    offset += 16;
    dcerpc_tvb_get_uuid (tvb, offset, hdr.drep, &hdr.if_id);
    offset += 16;
    dcerpc_tvb_get_uuid (tvb, offset, hdr.drep, &hdr.act_id);
    offset += 16;
    hdr.server_boot = dcerpc_tvb_get_ntohl (tvb, offset, hdr.drep);
    offset += 4;
    hdr.if_ver = dcerpc_tvb_get_ntohl (tvb, offset, hdr.drep);
    offset += 4;
    hdr.seqnum = dcerpc_tvb_get_ntohl (tvb, offset, hdr.drep);
    offset += 4;
    hdr.opnum = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.ihint = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.ahint = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.frag_len = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.frag_num = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.auth_proto = tvb_get_guint8 (tvb, offset++);
    hdr.serial_lo = tvb_get_guint8 (tvb, offset++);

    if (tree) {
        ti = proto_tree_add_item (tree, proto_dcerpc, tvb, 0, -1, FALSE);
        if (ti) {
            dcerpc_tree = proto_item_add_subtree(ti, ett_dcerpc);
        }
        offset = 0;
        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_ver, tvb, offset++, 1, hdr.rpc_ver);

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_packet_type, tvb, offset++, 1, hdr.ptype);

        tf = proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_flags1, tvb, offset, 1, hdr.flags1);
        dg_flags1_tree = proto_item_add_subtree (tf, ett_dcerpc_dg_flags1);
        if (dg_flags1_tree) {
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_rsrvd_01, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_last_frag, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_frag, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_nofack, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_maybe, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_idempotent, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_broadcast, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_rsrvd_80, tvb, offset, 1, hdr.flags1);
        }
        offset++;

        tf = proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_flags2, tvb, offset, 1, hdr.flags2);
        dg_flags2_tree = proto_item_add_subtree (tf, ett_dcerpc_dg_flags2);
        if (dg_flags2_tree) {
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_01, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_cancel_pending, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_04, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_08, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_10, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_20, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_40, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_80, tvb, offset, 1, hdr.flags2);
        }
        offset++;

        tf = proto_tree_add_bytes (dcerpc_tree, hf_dcerpc_drep, tvb, offset, sizeof (hdr.drep), hdr.drep);
        drep_tree = proto_item_add_subtree (tf, ett_dcerpc_drep);
        if (drep_tree) {
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_byteorder, tvb, offset, 1, hdr.drep[0] >> 4);
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_character, tvb, offset, 1, hdr.drep[0] & 0x0f);
            proto_tree_add_uint(drep_tree, hf_dcerpc_drep_fp, tvb, offset+1, 1, hdr.drep[1]);
        }
        offset += sizeof (hdr.drep);

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_serial_hi, tvb, offset++, 1, hdr.serial_hi);

        proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                      offset, 16, "HMMM",
                                      "Object: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      hdr.obj_id.Data1, hdr.obj_id.Data2, hdr.obj_id.Data3,
                                      hdr.obj_id.Data4[0],
                                      hdr.obj_id.Data4[1],
                                      hdr.obj_id.Data4[2],
                                      hdr.obj_id.Data4[3],
                                      hdr.obj_id.Data4[4],
                                      hdr.obj_id.Data4[5],
                                      hdr.obj_id.Data4[6],
                                      hdr.obj_id.Data4[7]);
        offset += 16;

        proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_dg_if_id, tvb,
                                      offset, 16, "HMMM",
                                      "Interface: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      hdr.if_id.Data1, hdr.if_id.Data2, hdr.if_id.Data3,
                                      hdr.if_id.Data4[0],
                                      hdr.if_id.Data4[1],
                                      hdr.if_id.Data4[2],
                                      hdr.if_id.Data4[3],
                                      hdr.if_id.Data4[4],
                                      hdr.if_id.Data4[5],
                                      hdr.if_id.Data4[6],
                                      hdr.if_id.Data4[7]);
        offset += 16;

        proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_dg_act_id, tvb,
                                      offset, 16, "HMMM",
                                      "Activity: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      hdr.act_id.Data1, hdr.act_id.Data2, hdr.act_id.Data3,
                                      hdr.act_id.Data4[0],
                                      hdr.act_id.Data4[1],
                                      hdr.act_id.Data4[2],
                                      hdr.act_id.Data4[3],
                                      hdr.act_id.Data4[4],
                                      hdr.act_id.Data4[5],
                                      hdr.act_id.Data4[6],
                                      hdr.act_id.Data4[7]);
        offset += 16;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_server_boot, tvb, offset, 4, hdr.server_boot);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_if_ver, tvb, offset, 4, hdr.if_ver);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_seqnum, tvb, offset, 4, hdr.seqnum);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_opnum, tvb, offset, 2, hdr.opnum);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_ihint, tvb, offset, 2, hdr.ihint);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_ahint, tvb, offset, 2, hdr.ahint);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_frag_len, tvb, offset, 2, hdr.frag_len);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_frag_num, tvb, offset, 2, hdr.frag_num);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_auth_proto, tvb, offset, 1, hdr.auth_proto);
        offset++;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_serial_lo, tvb, offset, 1, hdr.serial_lo);
        offset++;
    }
    /* 
     * keeping track of the conversation shouldn't really be necessary
     * for connectionless packets, because everything we need to know
     * to dissect is in the header for each packet.  Unfortunately,
     * Microsoft's implementation is buggy and often puts the
     * completely wrong if_id in the header.  go figure.  So, keep
     * track of the seqnum and use that if possible.  Note: that's not
     * completely correct.  It should really be done based on both the
     * activity_id and seqnum.  I haven't seen anywhere that it would
     * make a difference, but for future reference...
     */
    conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                              pinfo->srcport, pinfo->destport, 0);
    if (!conv) {
        conv = conversation_new (&pinfo->src, &pinfo->dst, pinfo->ptype,
                                 pinfo->srcport, pinfo->destport, 0);
    }

    /*
     * Packet type specific stuff is next.
     */

    switch (hdr.ptype) {
	dcerpc_info di;
        dcerpc_call_value *value, v;

    case PDU_REQ:

	if(!(pinfo->fd->flags.visited)){
	        dcerpc_call_value *call_value;
		dcerpc_call_key *call_key;

		call_key=g_mem_chunk_alloc (dcerpc_call_key_chunk);
		call_key->conv=conv;
		call_key->call_id=hdr.seqnum;
		call_key->smb_fid=get_smb_fid(pinfo->private_data);

		call_value=g_mem_chunk_alloc (dcerpc_call_value_chunk);
		call_value->uuid = hdr.if_id;
		call_value->ver = hdr.if_ver;
		call_value->opnum = hdr.opnum;
		call_value->req_frame=pinfo->fd->num;
		call_value->rep_frame=-1;
		call_value->max_ptr=0;
		call_value->private_data = NULL;
		g_hash_table_insert (dcerpc_calls, call_key, call_value);

		g_hash_table_insert (dcerpc_matched, (void *)pinfo->fd->num, call_value);	
	}

	value=g_hash_table_lookup(dcerpc_matched, (void *)pinfo->fd->num);
        if (!value) {
            v.uuid = hdr.if_id;
            v.ver = hdr.if_ver;
            v.opnum = hdr.opnum;
            v.req_frame = pinfo->fd->num;
            v.rep_frame = -1;
            v.max_ptr = 0;
            v.private_data=NULL;
            value = &v;
        }

	di.conv = conv;
	di.call_id = hdr.seqnum;
	di.smb_fid = -1;
	di.request = TRUE;
	di.call_data = value;

        dcerpc_try_handoff (pinfo, tree, dcerpc_tree, tvb, offset,
                            hdr.opnum, TRUE, hdr.drep, &di);
        break;
    case PDU_RESP:
	if(!(pinfo->fd->flags.visited)){
	        dcerpc_call_value *call_value;
		dcerpc_call_key call_key;

		call_key.conv=conv;
		call_key.call_id=hdr.seqnum;
		call_key.smb_fid=get_smb_fid(pinfo->private_data);

		if((call_value=g_hash_table_lookup(dcerpc_calls, &call_key))){
			g_hash_table_insert (dcerpc_matched, (void *)pinfo->fd->num, call_value);
			if(call_value->rep_frame==-1){
				call_value->rep_frame=pinfo->fd->num;
			}
		}
	}

	value=g_hash_table_lookup(dcerpc_matched, (void *)pinfo->fd->num);
        if (!value) {
            v.uuid = hdr.if_id;
            v.ver = hdr.if_ver;
            v.opnum = hdr.opnum;
            v.req_frame=-1;
            v.rep_frame=pinfo->fd->num;
            v.private_data=NULL;
            value = &v;
        }

	di.conv = conv;
	di.call_id = 0; 
	di.smb_fid = -1;
	di.request = FALSE;
        di.call_data = value;

	dcerpc_try_handoff (pinfo, tree, dcerpc_tree, tvb, offset,
                            value->opnum, FALSE, hdr.drep, &di);
        break;
    }

    return TRUE;
}

static void
dcerpc_init_protocol (void)
{
	/* structures and data for BIND */
	if (dcerpc_binds){
		g_hash_table_destroy (dcerpc_binds);
	}
	dcerpc_binds = g_hash_table_new (dcerpc_bind_hash, dcerpc_bind_equal);

	if (dcerpc_bind_key_chunk){
		g_mem_chunk_destroy (dcerpc_bind_key_chunk);
	}
	dcerpc_bind_key_chunk = g_mem_chunk_new ("dcerpc_bind_key_chunk",
                                             sizeof (dcerpc_bind_key),
                                             200 * sizeof (dcerpc_bind_key),
                                             G_ALLOC_ONLY);
	if (dcerpc_bind_value_chunk){
		g_mem_chunk_destroy (dcerpc_bind_value_chunk);
	}
	dcerpc_bind_value_chunk = g_mem_chunk_new ("dcerpc_bind_value_chunk",
                                             sizeof (dcerpc_bind_value),
                                             200 * sizeof (dcerpc_bind_value),
                                             G_ALLOC_ONLY);
	/* structures and data for CALL */
	if (dcerpc_calls){
		g_hash_table_destroy (dcerpc_calls);
	}
	dcerpc_calls = g_hash_table_new (dcerpc_call_hash, dcerpc_call_equal);
	if (dcerpc_call_key_chunk){
		g_mem_chunk_destroy (dcerpc_call_key_chunk);
	}
	dcerpc_call_key_chunk = g_mem_chunk_new ("dcerpc_call_key_chunk",
                                             sizeof (dcerpc_call_key),
                                             200 * sizeof (dcerpc_call_key),
                                             G_ALLOC_ONLY);
	if (dcerpc_call_value_chunk){
		g_mem_chunk_destroy (dcerpc_call_value_chunk);
	}
	dcerpc_call_value_chunk = g_mem_chunk_new ("dcerpc_call_value_chunk",
                                             sizeof (dcerpc_call_value),
                                             200 * sizeof (dcerpc_call_value),
                                             G_ALLOC_ONLY);

	/* structure and data for MATCHED */
	if (dcerpc_matched){
		g_hash_table_destroy (dcerpc_matched);
	}
	dcerpc_matched = g_hash_table_new (dcerpc_matched_hash, dcerpc_matched_equal);

}

void
proto_register_dcerpc (void)
{
    static hf_register_info hf[] = {
	{ &hf_dcerpc_request_in,
		{ "Request in", "dcerpc.request_in", FT_UINT32, BASE_DEC,
		NULL, 0, "This packet is a response to the packet in this frame", HFILL }},
	{ &hf_dcerpc_response_in, 
		{ "Response in", "dcerpc.response_in", FT_UINT32, BASE_DEC,
		NULL, 0, "The response to this packet is in this packet", HFILL }},
	{ &hf_dcerpc_referent_id, 
		{ "Referent ID", "dcerpc.referent_id", FT_UINT32, BASE_HEX,
		NULL, 0, "Referent ID for this NDR encoded pointer", HFILL }},
        { &hf_dcerpc_ver,
          { "Version", "dcerpc.ver", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_ver_minor,
          { "Version (minor)", "dcerpc.ver_minor", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_packet_type,
          { "Packet type", "dcerpc.pkt_type", FT_UINT8, BASE_HEX, VALS (pckt_vals), 0x0, "", HFILL }},
        { &hf_dcerpc_cn_flags,
          { "Packet Flags", "dcerpc.cn_flags", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_flags_first_frag,
          { "First Frag", "dcerpc.cn_flags.first_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x1, "", HFILL }},
        { &hf_dcerpc_cn_flags_last_frag,
          { "Last Frag", "dcerpc.cn_flags.last_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x2, "", HFILL }},
        { &hf_dcerpc_cn_flags_cancel_pending,
          { "Cancel Pending", "dcerpc.cn_flags.cancel_pending", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x4, "", HFILL }},
        { &hf_dcerpc_cn_flags_reserved,
          { "Reserved", "dcerpc.cn_flags.reserved", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x8, "", HFILL }},
        { &hf_dcerpc_cn_flags_mpx,
          { "Multiplex", "dcerpc.cn_flags.mpx", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "", HFILL }},
        { &hf_dcerpc_cn_flags_dne,
          { "Did Not Execute", "dcerpc.cn_flags.dne", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "", HFILL }},
        { &hf_dcerpc_cn_flags_maybe,
          { "Maybe", "dcerpc.cn_flags.maybe", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "", HFILL }},
        { &hf_dcerpc_cn_flags_object,
          { "Object", "dcerpc.cn_flags.object", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "", HFILL }},
        { &hf_dcerpc_drep,
          { "Data Representation", "dcerpc.drep", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_drep_byteorder,
          { "Byte order", "dcerpc.drep.byteorder", FT_UINT8, BASE_DEC, VALS (drep_byteorder_vals), 0x0, "", HFILL }},
        { &hf_dcerpc_drep_character,
          { "Character", "dcerpc.drep.character", FT_UINT8, BASE_DEC, VALS (drep_character_vals), 0x0, "", HFILL }},
        { &hf_dcerpc_drep_fp,
          { "Floating-point", "dcerpc.drep.fp", FT_UINT8, BASE_DEC, VALS (drep_fp_vals), 0x0, "", HFILL }},
        { &hf_dcerpc_cn_frag_len,
          { "Frag Length", "dcerpc.cn_frag_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_auth_len,
          { "Auth Length", "dcerpc.cn_auth_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_call_id,
          { "Call ID", "dcerpc.cn_call_id", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_max_xmit,
          { "Max Xmit Frag", "dcerpc.cn_max_xmit", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_max_recv,
          { "Max Recv Frag", "dcerpc.cn_max_recv", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_assoc_group,
          { "Assoc Group", "dcerpc.cn_assoc_group", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_num_ctx_items,
          { "Num Ctx Items", "dcerpc.cn_num_ctx_items", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ctx_id,
          { "Context ID", "dcerpc.cn_ctx_id", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_num_trans_items,
          { "Num Trans Items", "dcerpc.cn_num_trans_items", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_if_id,
          { "Interface UUID", "dcerpc.cn_bind_to_uuid", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_if_ver,
          { "Interface Ver", "dcerpc.cn_bind_if_ver", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_if_ver_minor,
          { "Interface Ver Minor", "dcerpc.cn_bind_if_ver_minor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_trans_id,
          { "Transfer Syntax", "dcerpc.cn_bind_trans_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_trans_ver,
          { "Syntax ver", "dcerpc.cn_bind_trans_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_alloc_hint,
          { "Alloc hint", "dcerpc.cn_alloc_hint", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_sec_addr_len,
          { "Scndry Addr len", "dcerpc.cn_sec_addr_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_sec_addr,
          { "Scndry Addr", "dcerpc.cn_sec_addr", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_num_results,
          { "Num results", "dcerpc.cn_num_results", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ack_result,
          { "Ack result", "dcerpc.cn_ack_result", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ack_reason,
          { "Ack reason", "dcerpc.cn_ack_reason", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ack_trans_id,
          { "Transfer Syntax", "dcerpc.cn_ack_trans_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ack_trans_ver,
          { "Syntax ver", "dcerpc.cn_ack_trans_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_cancel_count,
          { "Cancel count", "dcerpc.cn_cancel_count", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_type,
          { "Auth type", "dcerpc.auth_type", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_level,
          { "Auth level", "dcerpc.auth_level", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_pad_len,
          { "Auth pad len", "dcerpc.auth_pad_len", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_rsrvd,
          { "Auth Rsrvd", "dcerpc.auth_rsrvd", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_ctx_id,
          { "Auth Context ID", "dcerpc.auth_ctx_id", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_flags1,
          { "Flags1", "dcerpc.dg_flags1", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_flags1_rsrvd_01,
          { "Reserved", "dcerpc.dg_flags1_rsrvd_01", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x01, "", HFILL }},
        { &hf_dcerpc_dg_flags1_last_frag,
          { "Last Fragment", "dcerpc.dg_flags1_last_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x02, "", HFILL }},
        { &hf_dcerpc_dg_flags1_frag,
          { "Fragment", "dcerpc.dg_flags1_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x04, "", HFILL }},
        { &hf_dcerpc_dg_flags1_nofack,
          { "No Fack", "dcerpc.dg_flags1_nofack", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x08, "", HFILL }},
        { &hf_dcerpc_dg_flags1_maybe,
          { "Maybe", "dcerpc.dg_flags1_maybe", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "", HFILL }},
        { &hf_dcerpc_dg_flags1_idempotent,
          { "Idempotent", "dcerpc.dg_flags1_idempotent", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "", HFILL }},
        { &hf_dcerpc_dg_flags1_broadcast,
          { "Broadcast", "dcerpc.dg_flags1_broadcast", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "", HFILL }},
        { &hf_dcerpc_dg_flags1_rsrvd_80,
          { "Reserved", "dcerpc.dg_flags1_rsrvd_80", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "", HFILL }},
        { &hf_dcerpc_dg_flags2,
          { "Flags2", "dcerpc.dg_flags2", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_01,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_01", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x01, "", HFILL }},
        { &hf_dcerpc_dg_flags2_cancel_pending,
          { "Cancel Pending", "dcerpc.dg_flags2_cancel_pending", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x02, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_04,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_04", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x04, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_08,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_08", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x08, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_10,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_10", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_20,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_20", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_40,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_40", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_80,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_80", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "", HFILL }},
        { &hf_dcerpc_dg_serial_lo,
          { "Serial Low", "dcerpc.dg_serial_lo", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_serial_hi,
          { "Serial High", "dcerpc.dg_serial_hi", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_ahint,
          { "Activity Hint", "dcerpc.dg_ahint", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_ihint,
          { "Interface Hint", "dcerpc.dg_ihint", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_frag_len,
          { "Fragment len", "dcerpc.dg_frag_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_frag_num,
          { "Fragment num", "dcerpc.dg_frag_num", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_auth_proto,
          { "Auth proto", "dcerpc.dg_auth_proto", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_seqnum,
          { "Sequence num", "dcerpc.dg_seqnum", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_server_boot,
          { "Server boot time", "dcerpc.dg_server_boot", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_if_ver,
          { "Interface Ver", "dcerpc.dg_if_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_obj_id,
          { "Object", "dcerpc.obj_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_if_id,
          { "Interface", "dcerpc.dg_if_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_act_id,
          { "Activitiy", "dcerpc.dg_act_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_opnum,
          { "Opnum", "dcerpc.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_array_max_count,
          { "Max Count", "dcerpc.array.max_count", FT_UINT32, BASE_DEC, NULL, 0x0, "Maximum Count: Number of elements in the array", HFILL }},

        { &hf_dcerpc_array_offset,
          { "Offset", "dcerpc.array.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "Offset for first element in array", HFILL }},

        { &hf_dcerpc_array_actual_count,
          { "Actual Count", "dcerpc.array.actual_count", FT_UINT32, BASE_DEC, NULL, 0x0, "Actual Count: Actual number of elements in the array", HFILL }},


    };
    static gint *ett[] = {
        &ett_dcerpc,
        &ett_dcerpc_cn_flags,
        &ett_dcerpc_drep,
        &ett_dcerpc_dg_flags1,
        &ett_dcerpc_dg_flags2,
        &ett_dcerpc_pointer_data,
    };

    proto_dcerpc = proto_register_protocol ("DCE RPC", "DCERPC", "dcerpc");
    proto_register_field_array (proto_dcerpc, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_init_routine (dcerpc_init_protocol);

    prefs_register_bool_preference (prefs_register_protocol (proto_dcerpc, 
                                                             NULL),
                                    "desegment_dcerpc",
                                    "Desegment all DCE/RPC over TCP",
                                    "Whether the DCE/RPC dissector should desegment all DCE/RPC over TCP",
                                    &dcerpc_cn_desegment);
    dcerpc_uuids = g_hash_table_new (dcerpc_uuid_hash, dcerpc_uuid_equal);
}

void
proto_reg_handoff_dcerpc (void)
{
    heur_dissector_add ("tcp", dissect_dcerpc_cn_bs, proto_dcerpc);
    heur_dissector_add ("netbios", dissect_dcerpc_cn_pk, proto_dcerpc);
    heur_dissector_add ("udp", dissect_dcerpc_dg, proto_dcerpc);
    heur_dissector_add ("smb_transact", dissect_dcerpc_cn_bs, proto_dcerpc);
}
