/* mate_runtime.c
* MATE -- Meta Analysis Tracing Engine
*
* Copyright 2004, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
*
* $Id$
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* TODO:
 + fix debug_print levels
 - timers
    - on gops
    - on gogs?
    - on pdu?
 + transformations
    + maps
*/

#include "mate.h"

typedef struct _mate_range mate_range;

struct _mate_range {
	guint start;
	guint end;
};

typedef struct _tmp_pdu_data {
	GPtrArray* ranges;
	GHashTable* interesting;
	mate_pdu* pdu;
} tmp_pdu_data;


static mate_runtime_data* rd = NULL;
static mate_config* mc = NULL;

static int zero = 0;

static int* dbg = &zero;
static int* dbg_pdu = &zero;
static int* dbg_gop = &zero;
static int* dbg_gog = &zero;
static FILE* dbg_facility = NULL;


static gboolean destroy_mate_items(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_item* mi = (mate_item*) v;
	
	if (mi->gop_key) g_free(mi->gop_key);
	if (mi->gog_keys) g_ptr_array_free (mi->gog_keys,TRUE);
	delete_avpl(mi->avpl,TRUE);
	
	return TRUE;
}

static gboolean destroy_items_in_cfg(gpointer k _U_, gpointer v, gpointer p _U_) {
	g_hash_table_foreach_remove(((mate_cfg_item*)v)->items,destroy_mate_items,NULL);
}

static void delete_mate_runtime_data(mate_runtime_data*  rdat) {	
	g_hash_table_destroy(rdat->gops);
	g_hash_table_destroy(rdat->frames);
	g_hash_table_destroy(rdat->gogs);

	g_hash_table_foreach_remove(mc->pducfgs,destroy_items_in_cfg,NULL);
	g_hash_table_foreach_remove(mc->gopcfgs,destroy_items_in_cfg,NULL);
	g_hash_table_foreach_remove(mc->gogcfgs,destroy_items_in_cfg,NULL);	
	
	g_mem_chunk_destroy (rdat->mate_items);
	
	g_free(rdat);
}


extern void initialize_mate_runtime(void) {
	
	if (( mc = mate_cfg() )) {
		if (rd) {
			delete_mate_runtime_data(rd);
		}

		rd = g_malloc(sizeof(mate_runtime_data));

		mc = mate_cfg();

		rd->current_items = 0;
		rd->now = -1.0;
		rd->frames = g_hash_table_new(g_direct_hash,g_direct_equal);
		rd->gops = g_hash_table_new(g_str_hash,g_str_equal);
		rd->gogs = g_hash_table_new(g_str_hash,g_str_equal);
		rd->mate_items = g_mem_chunk_new("mate_items",sizeof(mate_item),1024,G_ALLOC_AND_FREE);
		rd->highest_analyzed_frame = 0;

		/* this will be called when the mate's dissector is initialized */
		dbg_print (dbg,5,dbg_facility,"initialize_mate: entering");


		dbg_pdu = &(mc->dbg_pdu_lvl);
		dbg_gop = &(mc->dbg_gop_lvl);
		dbg_gog = &(mc->dbg_gog_lvl);

	} else {
		rd = NULL;
	}
}

static mate_item* new_mate_item(mate_cfg_item* cfg) {
	mate_item* it = g_mem_chunk_alloc(rd->mate_items);

	it->cfg = cfg;
	cfg->last_id++;
	
	it->id = cfg->last_id;
	it->avpl  = NULL ;
	it->start  = 0 ;
	it->end  = 0 ;
	it->frame  = 0 ;
	it->next  = NULL ;
	it->released  = FALSE ;
	it->expiration = 0.0;

	rd->current_items++;
	
	
	g_hash_table_insert(cfg->items,GUINT_TO_POINTER(it->id),it);
	return it;
}

static mate_gop* new_gop(mate_cfg_gop* cfg, mate_pdu* pdu, guint8* key) {
	mate_gop* gop = new_mate_item(cfg);

	dbg_print (dbg_gop,1,dbg_facility,"new_gop: %s: ``%s:%d''",gop->cfg->name,gop->id,key);
	
	gop->avpl = new_avpl("attributes");
	
	gop->gog = NULL;
	gop->pdus = pdu;
	gop->last_pdu = pdu;
	gop->gop_key = key;
	gop->next = NULL;
	gop->start_time = pdu->rel_time;
	gop->release_time = 0.0;
	gop->last_time = 0.0;
	
	pdu->gop = gop;
	pdu->next = NULL;
	pdu->is_start = TRUE;
	pdu->rel_time = 0.0;
		
	return gop;
}


static void adopt_gop(mate_gog* gog, mate_gop* gop) {
	dbg_print (dbg_gog,5,dbg_facility,"adopt_gop: gog=%X gop=%X",gog,gop);

	gop->gog = gog;
	gop->next = NULL;
	
	gog->num_of_gops++;
	
	if (gog->last_gop) {		
		gog->last_gop->next = gop;
	}

	gog->last_gop = gop;
	
	if (! gog->gops ) {
		gog->gops = gop;
	}

}

static mate_gog* new_gog(mate_cfg_gog* cfg, mate_gop* gop) {
	mate_gog* gog = new_mate_item(cfg);
	
	dbg_print (dbg_gog,1,dbg_facility,"new_gog: %s:d for %s:%d",gog->cfg->name,gog->id,gog->cfg->name,gop->id);

	gog->cfg = cfg;
	gog->avpl = new_avpl(cfg->name);
	gog->gops = NULL;
	gog->last_n = 0;
	gog->gog_keys = g_ptr_array_new();
	gog->last_gop = NULL;
	
	gog->start_time = gop->rel_time;
	
	adopt_gop(gog,gop);
	
	return gog;
}


static void apply_transforms(mate_item* item) {
	AVPL_Transf* transform = NULL;
	guint i;
		
	for (i = 0; i < item->cfg->transforms->len; i++) {
		transform = g_ptr_array_index(item->cfg->transforms,i);
		avpl_transform(item->avpl, transform);
	}
}


/* applies the extras for which type to what avpl */
static void apply_extras(AVPL* from, AVPL* to,  mate_cfg_item* cfg) {
	AVPL* our_extras = NULL;
	
	if (cfg->extra) {
		dbg_print (dbg,3,dbg_facility,"apply_extras: entering: from='%s' to='%s' for='%s'\n",from->name,to->name,cfg->name);
		
		our_extras = new_avpl_loose_match("",from, cfg->extra, FALSE) ;
				
		if (our_extras) {
			merge_avpl(to,our_extras,TRUE);
			delete_avpl(our_extras,FALSE);
		}
	}
}

static void gog_remove_keys (mate_gog* gog) {
	guint8* k;

	while (gog->gog_keys->len) {
		k = (guint8*) g_ptr_array_remove_index_fast(gog->gog_keys,0);
		g_hash_table_remove(rd->gogs,k);
		g_free(k);
	}
}

static void reanalyze_gop(mate_gop* gop) {
	LoAL* gog_keys = NULL;
	AVPL* curr_gogkey = NULL;
	void* cookie = NULL;
	AVPL* gogkey_match = NULL;
	mate_gog* gog = gop->gog;
	guint8* key;
	
	if ( ! gog ) return;
	
	dbg_print (dbg_gog,1,dbg_facility,"reanalize_gop: gop=%s gog=%s\n",gog->cfg->name,gog->id,gog->cfg->name,gop->id);
	
	apply_extras(gop->avpl,gog->avpl,gog->cfg);
	
	if (gog->last_n != gog->avpl->len) {
		
		dbg_print (dbg_gog,2,dbg_facility,"analize_gop: gog has new attributes let's look for new keys\n");
		
		gog_keys = gog->cfg->keys;
		
		while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
			if (( gogkey_match = new_avpl_exact_match("",gog->avpl,curr_gogkey,FALSE) )) {
				key = avpl_to_str(gogkey_match);
				if ( g_hash_table_lookup(rd->gogs,key) ) {
					g_free(key);
				} else {
					dbg_print (dbg_gog,1,dbg_facility,"analize_gop: new key for gog=%s:%d : %s\n",gog->cfg->name,gog->id,key);
					g_hash_table_insert(rd->gogs,key,gog);
					g_ptr_array_add(gog->gog_keys,key);
				}
				delete_avpl(gogkey_match,FALSE);
			}
		}
		gog->last_n = gog->avpl->len;
	}
	
	if (gog->num_of_released_gops == gog->num_of_gops) {
		gog->released =  TRUE;
		gog->expiration = gog->cfg->expiration + rd->now;
	} else {
		gog->released =  FALSE;
	}
}

static void analize_gop(mate_gop* gop) {
	mate_cfg_gog* cfg = NULL;
	LoAL* gog_keys = NULL;
	AVPL* curr_gogkey = NULL;
	void* cookie = NULL;
	AVPL* gogkey_match = NULL;
	mate_gog* gog = NULL;
	guint8* key = NULL;
	
	if ( ! ( gog = gop->gog ) ) {
		/* no gog, let's either find one or create it if due */
		dbg_print (dbg_gog,1,dbg_facility,"analize_gop: no gog\n");
		
		gog_keys = g_hash_table_lookup(mc->gogs_by_gopname,gop->cfg->name);
		
		if ( ! gog_keys ) {
			dbg_print (dbg_gog,1,dbg_facility,"analize_gop: no gog_keys for this gop\n");
			return;
		}
		
		/* We'll look for any matching gogkeys */
		
		dbg_print (dbg_gog,1,dbg_facility,"analize_gop: got gog_keys\n");
		
		while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
			
			dbg_print (dbg_gog,2,dbg_facility,"analize_gop: about to match\n");
			
			if (( gogkey_match = new_avpl_exact_match(curr_gogkey->name,gop->avpl,curr_gogkey,TRUE) )) {
				
				key = avpl_to_str(gogkey_match);
				
				dbg_print (dbg_gog,1,dbg_facility,"analize_gop: got gogkey_match: %s\n",key);
				
				if (( gog = g_hash_table_lookup(rd->gogs,key) )) {
					dbg_print (dbg_gog,1,dbg_facility,"analize_gop: got already a matching gog\n");
					
					if (gog->num_of_gops == gog->num_of_released_gops && gog->expiration < rd->now) {
						dbg_print (dbg_gog,1,dbg_facility,"analize_gop: this is a new gog, not the old one, let's create it\n");
						
						gog_remove_keys(gog);
						
						gog = new_gog(gog->cfg,gop);
						gog->num_of_gops = 1;
						
						break;
					} else {
						dbg_print (dbg_gog,1,dbg_facility,"analize_gop: this is our gog\n");
						
						g_free(key);
						
						if (! gop->gog ) adopt_gop(gog,gop);
						
						break;
					}
				} else {
					dbg_print (dbg_gog,1,dbg_facility,"analize_gop: no such gog in hash, let's create a new one\n");
					
					cfg = g_hash_table_lookup(mc->gogcfgs,curr_gogkey->name);
					
					gog = new_gog(cfg,gop);
					gog->num_of_gops = 1;
				}
				
				delete_avpl(gogkey_match,TRUE);
				gogkey_match = NULL;
			}
			dbg_print (dbg_gog,1,dbg_facility,"analize_gop: no gogkey_match: %s\n",key);
		}
		
		if (gogkey_match) delete_avpl(gogkey_match,TRUE);
		
		reanalyze_gop(gop);
	} 
}



static void analize_pdu(mate_pdu* pdu) {
	/* TODO: 
    return a g_boolean to tell we've destroyed the pdu when the pdu is unnassigned
	destroy the unassigned pdu
	*/
	mate_cfg_gop* cfg = NULL;
	mate_gop* gop = NULL;
	guint8* gop_key;
	guint8* orig_gop_key = NULL;
	AVPL* candidate_gop_key_match = NULL;
	AVPL* candidate_start = NULL;
	AVPL* candidate_stop = NULL;
	AVPL* is_start = NULL;
	AVPL* is_stop = NULL;
	AVPL* gopkey_match = NULL;
	guint8* avpl_str = NULL;

	dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: %s\n",pdu->cfg->name);

	apply_transforms(pdu);

	cfg = g_hash_table_lookup(mc->gops_by_pduname,pdu->cfg->name);
	
	if (!cfg) return;
	

	
	candidate_gop_key_match = cfg->key;
	
	if (! candidate_gop_key_match) return;
	avpl_str = avpl_to_str(candidate_gop_key_match);
	dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: got candidate key: %s\n",avpl_str);
	g_free(avpl_str);
	
	gopkey_match = new_avpl_exact_match("",pdu->avpl,candidate_gop_key_match, TRUE);
	
	if (gopkey_match) {
		gop_key = avpl_to_str(gopkey_match);
		
		candidate_start = cfg->start;
		
		if (candidate_start) {
			avpl_str = avpl_to_str(candidate_start);
			dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: got candidate start: %s\n",avpl_str);
			g_free(avpl_str);
			is_start = new_avpl_exact_match("",pdu->avpl, candidate_start, FALSE);
		}
		
		if (is_start) {
			avpl_str = avpl_to_str(is_start);
			dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: got start match: %s\n",avpl_str);
			g_free(avpl_str);
			delete_avpl(is_start,FALSE);	
		}
		
		g_hash_table_lookup_extended(rd->gops,gop_key,(gpointer*)&orig_gop_key,(gpointer*)&gop);
		
		if ( gop ) {
			g_free(gop_key);
			
			gop_key = orig_gop_key;
			
			dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: got gop: %s\n",gop_key);
			
			if (is_start) {
				if ( gop->released ) {
					
					dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: new gop on released key before key expiration\n");

					g_hash_table_remove(rd->gops,gop_key);
					gop = new_gop(cfg,pdu,gop_key);
					g_hash_table_insert(rd->gops,gop_key,gop);
				}

				dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: duplicate start on gop\n");

			}
			
			pdu->gop = gop;
			
			if (gop->last_pdu) gop->last_pdu->next = pdu;
			gop->last_pdu = pdu;
			pdu->next = NULL;
			pdu->rel_time -= gop->start_time;
			if (gop->released) pdu->after_release = TRUE;
			
		} else {

			dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: no gop\n");

			if (is_start) {
				gop = new_gop(cfg,pdu,gop_key);
				
				g_hash_table_insert(rd->gops,gop_key,gop);
			} else {
				dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: an unassigned pdu\n");

				pdu->gop = NULL;
				pdu->next = NULL;

				return;
			}
		}
		
		if ( gop ) gop->num_of_pdus++;
		
		dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: merge with key\n");

		merge_avpl(gop->avpl,gopkey_match,TRUE);
		delete_avpl(gopkey_match,TRUE);
		
		dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: apply extras\n");

		apply_extras(pdu->avpl,gop->avpl,gop->cfg);
		
		avpl_str = avpl_to_str(gop->avpl);
		dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: Gop Attributes: %s\n",avpl_str);
		g_free(avpl_str);
		
		gop->last_time = pdu->rel_time;
		
		if ( ! gop->released) {
			candidate_stop = cfg->stop;
			if (candidate_stop) {
				dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: got candidate stop\n");
				is_stop = new_avpl_exact_match("",pdu->avpl, candidate_stop,FALSE);
			}
			
			if(is_stop) {
				avpl_str = avpl_to_str(is_stop);
				dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: is_stop: %s\n",avpl_str);
				g_free(avpl_str);
				delete_avpl(is_stop,FALSE);
				
				if (! gop->released) {
					gop->released = TRUE;
					gop->release_time = pdu->rel_time;
					if (gop->gog) gop->gog->num_of_released_gops++;
				}
				
				pdu->is_stop = TRUE;
			} else {
				dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: is not a stop\n");
			}
		}
			
		if (gop->last_n != gop->avpl->len) apply_transforms(gop);
		
		gop->last_n = gop->avpl->len;
				
		if (gop->gog) {
			reanalyze_gop(gop);
		} else {
			analize_gop(gop);
		}
		
	} else {
		dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: no gop_key\n");
		
		pdu->gop = NULL;
	}
}

static void get_pdu_fields(gpointer k, gpointer v, gpointer p) {
	int hfid = *((int*) k);
	guint8* name = (guint8*) v;
	tmp_pdu_data* data = (tmp_pdu_data*) p;
	GPtrArray* fis;
	field_info* fi;
	guint i,j;
	mate_range* curr_range;
	guint start;
	guint end;
	AVP* avp;
	guint8* s;
	
	/* no warning */
	k = p;
	
	fis = (GPtrArray*) g_hash_table_lookup(data->interesting,(gpointer) hfid);
	
	if (fis) {
		for (i = 0; i < fis->len; i++) {
			fi = (field_info*) g_ptr_array_index(fis,i);
			
			
			start = fi->start;
			end = fi->start + fi->length;
			
			dbg_print(dbg_pdu,6,dbg_facility,"get_pdu_fields: found field %i-%i\n",start,end);
			
			for (j = 0; j < data->ranges->len; j++) {
				
				curr_range = (mate_range*) g_ptr_array_index(data->ranges,j);
				
				dbg_print(dbg_pdu,6,dbg_facility,"get_pdu_fields: check if in range %i-%i\n",curr_range->start,curr_range->end);
				
				if (curr_range->end >= end && curr_range->start <= start) {
					avp = new_avp_from_finfo(name, fi);
					
					s = avp_to_str(avp);
					dbg_print(dbg_pdu,5,dbg_facility,"get_pdu_fields: got %s\n",s);
					g_free(s);
					
					if (! insert_avp(data->pdu->avpl,avp) ) {
						delete_avp(avp);
					}
					
				}
			}
		}
	}
}

static mate_pdu* new_pdu(mate_cfg_pdu* cfg, guint32 framenum, field_info* proto, GHashTable* interesting) {
	mate_pdu* pdu = new_mate_item(cfg);
	field_info* cfi;
	GPtrArray* ptrs;
	mate_range* range;
	mate_range* proto_range;
	tmp_pdu_data data;
	guint i,j;
	gint min_dist;
	field_info* range_fi;
	gint32 last_start;
	int hfid;

	dbg_print (dbg_pdu,2,dbg_facility,"new_pdu: type=%s framenum=%i\n",cfg->name,framenum);
		
	pdu->avpl = new_avpl(cfg->name);
	pdu->cfg = cfg;
	pdu->gop = NULL;
	pdu->next_in_frame = NULL;
	pdu->next = NULL;
	pdu->first = FALSE;
	pdu->is_start = FALSE;
	pdu->is_stop = FALSE;
	pdu->after_release = FALSE;
	pdu->start = proto->start;
	pdu->end = pdu->start + proto->length;
	pdu->frame = framenum;
	pdu->rel_time = rd->now;
	
	data.ranges = g_ptr_array_new();
	data.pdu  = pdu;
	data.interesting = interesting;
	
	/* first we create the proto range */
	proto_range = g_malloc(sizeof(mate_range));
	proto_range->start = pdu->start;
	proto_range->end = pdu->end;
	g_ptr_array_add(data.ranges,proto_range);
	
	dbg_print(dbg_pdu,3,dbg_facility,"new_pdu: proto range %u-%u\n",proto_range->start,proto_range->end);
	
	last_start = proto_range->start;
	
	for (i = 0; i < cfg->hfid_ranges->len; i++) {
		hfid = *((int*)g_ptr_array_index(cfg->hfid_ranges,i));
		ptrs = (GPtrArray*) g_hash_table_lookup(interesting,GINT_TO_POINTER(hfid));
		min_dist = 99999;
		range_fi = NULL;
		
		if (ptrs) {
			for (j=0; j < ptrs->len; j++) {
				cfi = (field_info*) g_ptr_array_index(ptrs,j);
				if (cfi->start < last_start && min_dist >= (last_start - cfi->start) ) {
					range_fi = cfi;
					min_dist = last_start - cfi->start;
				}
			}
			
			if ( range_fi ) {
				range = g_malloc(sizeof(range));
				range->start = range_fi->start;
				range->end = range_fi->start + range_fi->length;
				g_ptr_array_add(data.ranges,range);
				
				last_start = range_fi->start;
				
				dbg_print(dbg_pdu,3,dbg_facility,"new_pdu: transport(%i) range %i-%i\n",hfid,range->start,range->end);
			} else {
				
				/* what do I do if I miss a range? */
			}
			
		}
	}
	
	g_hash_table_foreach(cfg->hfids_attr,get_pdu_fields,&data);
	
	g_ptr_array_free(data.ranges,TRUE);
	
	return pdu;
}	

extern int mate_packet(void *prs _U_, proto_tree* tree _U_, epan_dissect_t *edt _U_, void *dummy _U_) {
	/* nothing to do yet */
}

extern void analyze_frame(packet_info *pinfo, proto_tree* tree) {
	mate_cfg_pdu* cfg;
	GPtrArray* protos;
	field_info* proto;
	guint i,j;
	AVPL* criterium_match;
	
	mate_pdu* pdu = NULL;
	mate_pdu* last = NULL;

	rd->now = (((float)pinfo->fd->rel_secs) + (((float)pinfo->fd->rel_usecs) / 1000000) );

	if ( tree->tree_data && tree->tree_data->interesting_hfids
		 && rd->highest_analyzed_frame < pinfo->fd->num ) {
		for ( i = 0; i < mc->pducfglist->len; i++ ) {
			
			cfg = g_ptr_array_index(mc->pducfglist,i);
			
			dbg_print (dbg_pdu,4,dbg_facility,"mate_packet: tryning to extract: %s\n",cfg->name);
			protos = (GPtrArray*) g_hash_table_lookup(tree->tree_data->interesting_hfids,(gpointer) cfg->hfid_proto);
			
			if (protos)  {
				pdu = NULL;
				
				for (j = 0; j < protos->len; j++) {

					dbg_print (dbg_pdu,3,dbg_facility,"mate_packet: found matching proto, extracting: %s\n",cfg->name);
					
					proto = (field_info*) g_ptr_array_index(protos,j);
					pdu = new_pdu(cfg, pinfo->fd->num, proto, tree->tree_data->interesting_hfids);
					
					if (cfg->criterium) {
						criterium_match = new_avpl_from_match(cfg->criterium_match_mode,"",pdu->avpl,cfg->criterium,FALSE);
						if (criterium_match) {
							delete_avpl(criterium_match,FALSE);
						}
						
						if ( (criterium_match && cfg->criterium->name == mc->reject ) || ( ! criterium_match && cfg->criterium->name == mc->accept )) {
							delete_avpl(pdu->avpl,TRUE);
							g_mem_chunk_free(rd->mate_items,pdu);
							pdu = NULL;
							continue;
						}
					}
										
					analize_pdu(pdu);
					
					if ( ! pdu->gop && cfg->drop_pdu) {
						delete_avpl(pdu->avpl,TRUE);
						g_mem_chunk_free(rd->mate_items,pdu);
						pdu = NULL;
						continue;
					}
					
					if ( cfg->discard_pdu_attributes ) {
						delete_avpl(pdu->avpl,TRUE);
						pdu->avpl = NULL;
					}
					
					if (!last) {
						g_hash_table_insert(rd->frames,GINT_TO_POINTER(pinfo->fd->num),pdu);
						last = pdu;
					} else {
						last->next_in_frame = pdu;
						last = pdu;
					}
					
				}
				
				if ( pdu && cfg->last_to_be_created ) break;
			}
		}
		
		rd->highest_analyzed_frame = pinfo->fd->num;
	}
}

extern mate_pdu* mate_get_pdus(guint32 framenum) {
	
	if (rd) {
		return (mate_pdu*) g_hash_table_lookup(rd->frames,GUINT_TO_POINTER(framenum));
	} else {
		return NULL;
	}
}



