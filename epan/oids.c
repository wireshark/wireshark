/* oids.c
 * Routines for OBJECT IDENTIFIER operations
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id$
 *
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "emem.h"
#include "uat.h"
#include "packet.h"
#include "report_err.h"

#ifdef HAVE_SMI
#include <smi.h>
#endif

#include "oids.h"

static oid_info_t oid_root = { 0, "", NULL, SMI_BASETYPE_UNKNOWN, -1, NULL, NULL};
static emem_tree_t* oids_by_name = NULL;

static oid_info_t* add_oid(char* name, int type, guint oid_len, guint32 *subids) {
	guint i = 0;
	oid_info_t* c = &oid_root;
	
	oid_len--;
	
	do {
		oid_info_t* n = emem_tree_lookup32(c->children,subids[i]);
		
		if(n) {
			if (i == oid_len) {
				if (!n->name)
					n->name = g_strdup(name);
				
				if (n->value_type == SMI_BASETYPE_UNKNOWN)
					n->value_type = type;
				
				return n;
			} else {
				c = n;
				continue;
			}
		} else {
			oid_info_t* o = g_malloc(sizeof(oid_info_t));
			o->subid = subids[i];
			o->children = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK,"oid_children");
			o->value_hfid = -1;
			o->parent = c;
			o->bits = NULL;

			emem_tree_insert32(c->children,o->subid,o);

			if (i == oid_len) {
				o->name = g_strdup(name);
				o->value_type = type;
				return o;
			} else {
				o->name = NULL;
				o->value_type = SMI_BASETYPE_UNKNOWN;
				c = o;
				continue;
			}
		}
		
	} while(++i);
	
	g_assert_not_reached();
	return NULL;
}

extern void oid_add(char* name, guint oid_len, guint32 *subids) {
	add_oid(name,SMI_BASETYPE_UNKNOWN,oid_len,subids);
}

#ifdef HAVE_SMI
typedef struct smi_module_t {
	char* name;
} smi_module_t;

static smi_module_t* smi_modules = NULL;
static guint num_smi_modules = 0;
static uat_t* smi_modules_uat = NULL;

UAT_CSTRING_CB_DEF(smi_mod,name,smi_module_t)

static void* smi_mod_copy_cb(void* dest, const void* orig, unsigned len _U_) {
	const smi_module_t* m = orig;
	smi_module_t* d = dest;
	
	d->name = g_strdup(m->name);
	
	return d;
}	

static void smi_mod_free_cb(void* p) {
	smi_module_t* m = p;
	if (m->name) g_free(m->name);
}


static char* alnumerize(const char* name) {
	char* s = g_strdup(name);
	char* r = s;
	char* w = r;
	char c;
	
	for (;(c = *r); r++) {
		if (isalnum(c) || c == '_' || c == '-' || c == '.') {
			*(w++) = c;
		} else if (c == ':' && r[1] == ':') {
			*(w++) = '.';
		}
	}
	
	*w = '\0';
	
	return s;
}

#define IS_ENUMABLE(ft) (( (ft == FT_UINT8) || (ft == FT_UINT16) || (ft == FT_UINT24) || (ft == FT_UINT32) \
						   || (ft == FT_INT8) || (ft == FT_INT16) || (ft == FT_INT24) || (ft == FT_INT32) \
						   || (ft == FT_UINT64) || (ft == FT_INT64) ))

void register_mibs(void) {
	SmiModule *smiModule;
    SmiNode *smiNode;
	guint i;
	int proto_smi = -1;
	
	static struct _smi_type_data {
		enum ftenum			type;
		int					display;
	} types[] =  {
	{FT_BYTES,BASE_NONE},
	{FT_INT32,BASE_DEC},
	{FT_BYTES,BASE_NONE},
	{FT_OID,BASE_NONE},
	{FT_UINT32,BASE_DEC},
	{FT_INT64,BASE_DEC},
	{FT_UINT64,BASE_DEC},
	{FT_FLOAT,BASE_DEC},
	{FT_DOUBLE,BASE_DEC},
	{FT_BYTES,BASE_NONE},
	{FT_UINT32,BASE_DEC},
	};
	GArray* hfa = g_array_new(FALSE,TRUE,sizeof(hf_register_info));
	GArray* etta = g_array_new(FALSE,TRUE,sizeof(gint*));
	static uat_field_t smi_fields[] = {
		UAT_FLD_CSTRING(smi_mod,name,"The module's name"),
		UAT_END_FIELDS
	};
	char* smi_load_error = NULL;
	
	smi_modules_uat = uat_new("SMI Modules",
							  sizeof(smi_module_t),
							  "smi_modules",
							  (void**)&smi_modules,
							  &num_smi_modules,
							  UAT_CAT_GENERAL,
							  "ChSNMPSMIModules",
							  smi_mod_copy_cb,
							  NULL,
							  smi_mod_free_cb,
							  smi_fields);
	
	uat_load(smi_modules_uat, &smi_load_error);
	
	if (smi_load_error) {
		report_failure("Error Loading SMI Modules Table: %s",smi_load_error);
	}
	
	smiInit(NULL);
	
	for(i=0;i<num_smi_modules;i++)
		smiLoadModule(smi_modules[i].name);
	
	for (smiModule = smiGetFirstModule();
		 smiModule;
		 smiModule = smiGetNextModule(smiModule)) {
		
		for (smiNode = smiGetFirstNode(smiModule, SMI_NODEKIND_ANY); 
			 smiNode;
			 smiNode = smiGetNextNode(smiNode, SMI_NODEKIND_ANY)) {
			
			SmiType* smiType =  smiGetNodeType(smiNode);
			
			oid_info_t* oid_data = add_oid(smiRenderOID(smiNode->oidlen, smiNode->oid, SMI_RENDER_QUALIFIED),
										   smiType ? smiType->basetype : SMI_BASETYPE_UNKNOWN,
										   smiNode->oidlen,
										   smiNode->oid);
			
			if (smiType) {
				SmiNamedNumber* smiEnum; 
				struct _smi_type_data* typedata;
				hf_register_info hf = { NULL, { NULL, NULL, FT_NONE, BASE_NONE, NULL, 0, "", HFILL }};
				
				typedata = &(types[smiType->basetype <= SMI_BASETYPE_ENUM ? smiType->basetype : SMI_BASETYPE_UNKNOWN]);
				
				hf.hfinfo.name = oid_data->name;
				hf.p_id = &(oid_data->value_hfid);
				hf.hfinfo.type = typedata->type;
				hf.hfinfo.display = typedata->display;
				hf.hfinfo.abbrev = alnumerize(hf.hfinfo.name);
				hf.hfinfo.blurb = g_strdup(smiRenderOID(smiNode->oidlen, smiNode->oid, SMI_RENDER_ALL));
				
				if ( IS_ENUMABLE(hf.hfinfo.type) && (smiEnum = smiGetFirstNamedNumber(smiType))) {
					GArray* vals = g_array_new(TRUE,TRUE,sizeof(value_string));
					
					for(;smiEnum; smiEnum = smiGetNextNamedNumber(smiEnum)) {
						if (smiEnum->name) {
							value_string val = {smiEnum->value.value.integer32,g_strdup(smiEnum->name)};
							g_array_append_val(vals,val);
						}
					}
					
					hf.hfinfo.strings = vals->data;
					g_array_free(vals,FALSE);
				} else if (smiType->basetype == SMI_BASETYPE_BITS && ( smiEnum = smiGetFirstNamedNumber(smiType) )) {
					guint n = 0;
					oid_bits_info_t* bits = g_malloc(sizeof(oid_bits_info_t));
					gint* ettp = &(bits->ett);
					
					bits->num = 0;
					bits->ett = -1;
					
					g_array_append_val(etta,ettp);
					
					for(;smiEnum; smiEnum = smiGetNextNamedNumber(smiEnum), bits->num++);
					
					bits->data = g_malloc(sizeof(struct _oid_bit_t));
					
					for(smiEnum = smiGetFirstNamedNumber(smiType),n=0;
						smiEnum;
						smiEnum = smiGetNextNamedNumber(smiEnum),n++) {
						guint mask = 1 << (smiEnum->value.value.integer32 % 8);
						char* base = alnumerize(oid_data->name);
						char* ext = alnumerize(smiEnum->name);
						hf_register_info hf2 = { &(bits->data[n].hfid), { NULL, NULL, FT_UINT8, BASE_HEX, NULL, mask, "", HFILL }};
						
						bits->data[n].hfid = -1;
						bits->data[n].offset = smiEnum->value.value.integer32 / 8;
						
						hf2.hfinfo.name = g_strdup_printf("%s:%s",oid_data->name,smiEnum->name);
						hf2.hfinfo.abbrev = g_strdup_printf("%s.%s",base,ext);
						
						g_free(base);
						g_free(ext);
						g_array_append_val(hfa,hf2);
					}
				}
				
				g_array_append_val(hfa,hf);
			}
		}
	}
	
	proto_smi = proto_register_protocol("MIBs", "MIBS", "mibs");
	
	proto_register_field_array(proto_smi, (hf_register_info*)hfa->data, hfa->len);
	
	g_array_free(hfa,FALSE);
}
#endif


void oid_init(void) {
	oid_root.children = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK,"oid_root");
	oids_by_name = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK,"oid_names");
	
#ifdef HAVE_SMI
	register_mibs();
#endif
}

const char* oid_subid2string(guint32* subids, guint len) {
	char* s = ep_alloc(len*11);
	char* w = s;	
	
	do {
		w += sprintf(w,"%u.",*subids++);
	} while(--len);
	
	*w = '\0';
	
	return s;
}

guint chech_num_oid(const char* str) {
	const char* r = str;
	char c = '\0';
	guint n = 0;
	
	if (*r == '.') return 0;
	
	do {
		switch(*r) {
			case '.':
				n++;
				if (c == '.') return 0;
				case '1' : case '2' : case '3' : case '4' : case '5' : 
				case '6' : case '7' : case '8' : case '9' : case '0' :
					continue;
				case '\0':
					break;
				default:
					return 0;
		}
		c = *r;
	} while(1);
	
	if (c == '.') return 0;
	
	return n;
}

guint oid_string2subid(const char* str, guint32** subids_p) {
	const char* r = str;
	guint32* subids;
	guint n = chech_num_oid(str);
	
	*subids_p = subids = ep_alloc_array(guint32,n);
	
	do switch(*r) {
		case '.':
			subids++;
			continue;
		case '1' : case '2' : case '3' : case '4' : case '5' : 
		case '6' : case '7' : case '8' : case '9' : case '0' :
			*(subids) *= 10;
			*(subids) += *r - '0';
			continue;
		case '\0':
			break;
		default:
			return 0;
	} while(1);
	
	return n;
}


guint oid_encoded2subid(const guint8 *oid_bytes, gint oid_len, guint32** subids_p) {
	gint i;
	guint n = 1;
	guint32 subid = 0;
	gboolean is_first = TRUE;
	guint32* subids;
	
	for (i=0; i<oid_len; i++){
		guint8 byte = oid_bytes[i];
		if (byte & 0x80) continue;
		n++;
	}
	
	*subids_p = subids = ep_alloc(sizeof(guint32)*n);
	
	for (i=0; i<oid_len; i++){
		guint8 byte = oid_bytes[i];
		
		subid <<= 7;
		subid |= byte & 0x7F;
		
		if (byte & 0x80) {
			continue;
		}
		
		if (is_first) {
			guint32 subid0 = 0;
			
			if (subid >= 40) { (*subids)++; subid-=40; }
			if (subid >= 40) { (*subids)++; subid-=40; }
			
			*subids++ = subid0;
			
			is_first = FALSE;
		}
		
		*subids++ = subid;
		subid = 0;
	}
	
	return n;
}

oid_info_t* oid_get(guint len, guint32* subids, guint* matched, guint* left) {
	oid_info_t* curr_oid = &oid_root;
	guint i;
	
	for( i=0; i < len; i++) {
		oid_info_t* next_oid = emem_tree_lookup32(curr_oid->children,subids[i]);
		if (next_oid) {
			curr_oid = next_oid;
		} else {
			goto done;
		}
	}
done:
	*matched = i;
	*left = len - i;
	return curr_oid;
}


oid_info_t* oid_get_from_encoded(const guint8 *bytes, gint byteslen, guint* matched_p, guint* len_p) {
	gint i;
	guint32 subid = 0;
	oid_info_t* oid = &oid_root;
	guint matched = 0;
	guint left = FALSE;
	
	for (i=0; i<byteslen; i++){
		guint8 byte = bytes[i];
		oid_info_t* next_oid;
		
		subid <<= 7;
		subid |= byte & 0x7F;
		
		if (byte & 0x80) {
			continue;
		}
		
		if (i == 0) {
			guint32 subid0 = 0;
			
			if (subid >= 40) { subid0++; subid-=40; }
			if (subid >= 40) { subid0++; subid-=40; }
			
			if(( next_oid = emem_tree_lookup32(oid->children,subid0) )) {
				matched++;
				oid = next_oid;
			} else {
				left++;
			}
		}
		
		if((next_oid = emem_tree_lookup32(oid->children,subid))) {
			matched++;
			oid = next_oid;
		} else {
			left++;
		}		
		
		subid = 0;
	}
	
	*matched_p = matched;
	*len_p = left;
	return oid;
}

oid_info_t* oid_get_from_string(const gchar *oid_str, guint* matched, guint* left) {
	guint32* subids;
	guint len = oid_string2subid(oid_str, &subids);
	return oid_get(len, subids, matched, left);
}

const gchar *oid_resolved_from_encoded(const guint8 *oid, gint oid_len) {
	guint32 *subid_oid;
	guint subid_oid_length = oid_encoded2subid(oid, oid_len, &subid_oid);
	guint matched;
	guint left;
	oid_info_t* curr_oid = oid_get(subid_oid_length, subid_oid, &matched, &left);
		
		if (matched == subid_oid_length) {
			return curr_oid->name;
		} else {
			return ep_strdup_printf("%s.%s",
									curr_oid->name,
									oid_subid2string(&(subid_oid[matched]),left) );
		}
	
}


guint oid_subid2encoded(guint subids_len, guint32* subids, guint8** bytes_p) {
	guint bytelen = 0;
	guint i;
	guint32 subid;
	guint8* bytes;
	guint8* b;
	
	if (subids_len < 2) return 0;
	
	subid = (subids[1] * 40) + subids[0];
	
	for( i = 2; i < subids_len; i++ ) {
		if (subid & 0xF0000000) {
			bytelen += 5;
		} else if (subid & 0x0FE00000) {
			bytelen += 4;
		} else if (subid & 0x001FC000) {
			bytelen += 3;
		} else if (subid & 0x00003F10) {
			bytelen += 2;
		} else {
			bytelen += 1;
		}
	}
	
	*bytes_p = b = bytes = ep_alloc(bytelen);
	
	subid = (subids[1] * 40) + subids[0];
	
	for (i = 2; i<subids_len; i++) {
		guint32 v;
		
		if (( v = subid & 0xF0000000 )) *(b++) = v << 28;
		if (( v = subid & 0x0FE00000 )) *(b++) = v << 21;
		if (( v = subid & 0x001FC000 )) *(b++) = v << 21;
		if (( v = subid & 0x00003F10 )) *(b++) = v << 21;
		*(b++) =  subid & 0x0000007F;
	}
	
	return bytelen;
}

const gchar* oid_encoded2string(const guint8* encoded, guint len) {
	guint32* subids;
	guint subids_len = oid_encoded2subid(encoded, len, &subids);
	
	if (subids_len) {
		return oid_subid2string(subids,subids_len);
	} else {
		return "";
	}
}



guint oid_string2encoded(const char *oid_str, guint8 **bytes) {
	guint32* subids;
	guint32 subids_len;
	guint byteslen;
		
		if ( ( subids_len = oid_string2subid(oid_str, &subids) )
			 && 
			 ( byteslen = oid_subid2encoded(subids_len, subids, bytes) )  ) {
			return byteslen;
		}
	return 0;
}

char* oid2str(oid_info_t* oid, guint32* subids, guint len, guint left) {
	if (left == 0) {
		return oid->name;
	} else {
		return ep_strdup_printf("%s.%s",oid->name,oid_subid2string(subids+(len-left),left));
	}
}

const gchar *oid_resolved_from_string(const gchar *oid_str) {
	guint32* subids;
	guint num_subids = oid_string2subid(oid_str, &subids);
	
	if (num_subids) {
		guint matched;
		guint left;
		oid_info_t* oid = oid_get(num_subids, subids, &matched, &left);
		return oid2str(oid, subids, num_subids, left);
	} else {
		return emem_tree_lookup_string(oids_by_name, oid_str);
	}
}

const gchar *oid_resolved(guint32 num_subids, guint32* subids) {
	guint matched;
	guint left;
	oid_info_t* oid = oid_get(num_subids, subids, &matched, &left);
	
	return oid2str(oid, subids, num_subids, left);
}



