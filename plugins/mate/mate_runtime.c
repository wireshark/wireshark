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


typedef struct _gogkey {
	guint8* key;
	mate_cfg_gop* cfg; 
} gogkey;


static mate_runtime_data* rd = NULL;
static mate_config* mc = NULL;

static int zero = 0;

static int* dbg = &zero;
static int* dbg_pdu = &zero;
static int* dbg_gop = &zero;
static int* dbg_gog = &zero;
static FILE* dbg_facility = NULL;

static void gog_remove_keys (mate_gog* gog);

static gboolean destroy_mate_items(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_item* mi = (mate_item*) v;
	
	if (mi->avpl) delete_avpl(mi->avpl,TRUE);

	if (mi->gop_key) {
		if (g_hash_table_lookup(mi->cfg->gop_index,mi->gop_key) == mi) {
			g_hash_table_remove(mi->cfg->gop_index,mi->gop_key);
		}
		
		g_free(mi->gop_key);
	}


	if (mi->gog_keys) {
		gog_remove_keys(mi);
		g_ptr_array_free(mi->gog_keys,FALSE);
	}
	
	g_mem_chunk_free(rd->mate_items,mi);

	return TRUE;
}

static gboolean return_true(gpointer k _U_, gpointer v _U_, gpointer p _U_) {
	return TRUE;
}

static void destroy_items_in_cfg(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_cfg_item* c =  v;
	
	if (c->gop_index) { 
		g_hash_table_foreach_remove(c->gop_index,return_true,NULL);
		g_hash_table_destroy(c->gop_index);	
		c->gop_index = g_hash_table_new(g_str_hash,g_str_equal);
	}
		
	if (c->gog_index) {
		g_hash_table_foreach_remove(c->gog_index,return_true,NULL);
		g_hash_table_destroy(c->gog_index);	
		c->gog_index = g_hash_table_new(g_str_hash,g_str_equal);
	}
	
	g_hash_table_foreach_remove(c->items,destroy_mate_items,NULL);

	c->last_id = 0;
	
}


extern void initialize_mate_runtime(void) {
	
	dbg_print (dbg,5,dbg_facility,"initialize_mate: entering");

	if (( mc = mate_cfg() )) {
		if (rd == NULL ) {			
			rd = g_malloc(sizeof(mate_runtime_data));
			rd->mate_items = g_mem_chunk_new("mate_items",sizeof(mate_item),1024,G_ALLOC_AND_FREE);
		} else {
			g_hash_table_foreach(mc->pducfgs,destroy_items_in_cfg,NULL);
			g_hash_table_foreach(mc->gopcfgs,destroy_items_in_cfg,NULL);
			g_hash_table_foreach(mc->gogcfgs,destroy_items_in_cfg,NULL);
			
			g_hash_table_destroy(rd->frames);			
		}

		rd->current_items = 0;
		rd->now = -1.0;
		rd->highest_analyzed_frame = 0;
		rd->frames = g_hash_table_new(g_direct_hash,g_direct_equal);
		

		dbg_pdu = &(mc->dbg_pdu_lvl);
		dbg_gop = &(mc->dbg_gop_lvl);
		dbg_gog = &(mc->dbg_gog_lvl);
		
	} else {
		rd = NULL;
	}
}

static mate_item* new_mate_item(mate_cfg_item* cfg) {
	mate_item* it = g_mem_chunk_alloc(rd->mate_items);

	cfg->last_id++;
	
	it->id = cfg->last_id;
	it->cfg = cfg;
	
	it->avpl  = NULL ;
	
	it->next  = NULL ;

	it->expiration = 0.0;
	it->idle_expiration = 0.0;

	it->start_time = 0.0;
	it->release_time = 0.0;
	it->last_time = 0.0;

	it->frame  = 0 ;
	it->gop = NULL;
	it->first = FALSE;
	it->is_start = FALSE;
	it->is_stop = FALSE;
	it->after_release = FALSE;
	it->rel_time = 0.0;
	it->time_in_gop = -1.0;
	it->next_in_frame = NULL;
	
	it->gog = NULL;
	it->pdus = NULL;
	it->released  = FALSE ;
	it->num_of_pdus = 0;
	it->num_of_after_release_pdus = 0;
	it->gop_key = NULL;
	
	it->gops = NULL;
	it->num_of_gops = 0;
	it->num_of_counting_gops = 0;
	it->num_of_released_gops = 0;
	it->last_n = 0;
	it->gog_keys = NULL;
	it->last_gop = NULL;
	
	rd->current_items++;

	g_hash_table_insert(cfg->items,GUINT_TO_POINTER(it->id),it);
	return it;
}

static mate_gop* new_gop(mate_cfg_gop* cfg, mate_pdu* pdu, guint8* key) {
	mate_gop* gop = new_mate_item(cfg);

	dbg_print (dbg_gop,1,dbg_facility,"new_gop: %s: ``%s:%d''",gop->cfg->name,gop->id,key);
	
	gop->avpl = new_avpl(cfg->name);
	
	gop->pdus = pdu;
	gop->last_pdu = pdu;
	gop->gop_key = key;
	gop->start_time = rd->now;
	gop->time_to_die = cfg->lifetime > 0.0 ? cfg->lifetime + rd->now : (float) -1.0 ;
	pdu->gop = gop;
	pdu->next = NULL;
	pdu->is_start = TRUE;
	pdu->time_in_gop = 0.0;
	
	return gop;
}


static void adopt_gop(mate_gog* gog, mate_gop* gop) {
	dbg_print (dbg_gog,5,dbg_facility,"adopt_gop: gog=%X gop=%X",gog,gop);

	gop->gog = gog;
	gop->next = NULL;
	
	if (gop->cfg->start) {
		gog->num_of_counting_gops++;
	}
	
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
	
	dbg_print (dbg_gog,1,dbg_facility,"new_gog: %s:%u for %s:%u",gog->cfg->name,gog->id,gop->cfg->name,gop->id);

	gog->avpl = new_avpl(cfg->name);
	
	gog->gog_keys = g_ptr_array_new();
	gog->start_time = rd->now;
	
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
		dbg_print (dbg,3,dbg_facility,"apply_extras: entering: from='%s' to='%s' for='%s'",from->name,to->name,cfg->name);
		
		our_extras = new_avpl_loose_match("",from, cfg->extra, FALSE) ;
				
		if (our_extras) {
			merge_avpl(to,our_extras,TRUE);
			delete_avpl(our_extras,FALSE);
		}
	}
}

static void gog_remove_keys (mate_gog* gog) {
	gogkey* gog_key;
	
	while (gog->gog_keys->len) {
		gog_key =  g_ptr_array_remove_index_fast(gog->gog_keys,0);
		
		if (g_hash_table_lookup(gog_key->cfg->gog_index,gog_key->key) == gog) {
			g_hash_table_remove(gog_key->cfg->gog_index,gog_key->key);
		}
		
		g_free(gog_key->key);
		g_free(gog_key);
	}
	
}

static void reanalyze_gop(mate_gop* gop) {
	LoAL* gog_keys = NULL;
	AVPL* curr_gogkey = NULL;
	mate_cfg_gop* gop_cfg = NULL;
	void* cookie = NULL;
	AVPL* gogkey_match = NULL;
	mate_gog* gog = gop->gog;
	gogkey* gog_key;
	
	if ( ! gog ) return;
	
	gog->last_time = rd->now;
	
	dbg_print (dbg_gog,1,dbg_facility,"reanalize_gop: %s:%d",gop->cfg->name,gop->id);
	
	apply_extras(gop->avpl,gog->avpl,gog->cfg);
	
	if (gog->last_n != gog->avpl->len) {
		
		dbg_print (dbg_gog,2,dbg_facility,"analize_gop: gog has new attributes let's look for new keys");
		
		gog_keys = gog->cfg->keys;
		
		while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
			gop_cfg = g_hash_table_lookup(mc->gopcfgs,curr_gogkey->name);

			if (( gogkey_match = new_avpl_exact_match(gop_cfg->name,gog->avpl,curr_gogkey,FALSE) )) {			
				
				gog_key = g_malloc(sizeof(gogkey));
				
				gog_key->key = avpl_to_str(gogkey_match);
				delete_avpl(gogkey_match,FALSE);
				
				gog_key->cfg = gop_cfg;
				
				if (g_hash_table_lookup(gop_cfg->gog_index,gog_key->key)) {
					g_free(gog_key->key);
					g_free(gog_key);
					gog_key = NULL;
				} 
				
				if (! gog_key ) {
					/* TODO: try mergeing the gogs */
				} else {
					dbg_print (dbg_gog,1,dbg_facility,"analize_gop: new key for gog=%s:%d : %s",gog->cfg->name,gog->id,gog_key->key);
					g_ptr_array_add(gog->gog_keys,gog_key);
					g_hash_table_insert(gog_key->cfg->gog_index,gog_key->key,gog);
				}
				
			}
		}
		
		gog->last_n = gog->avpl->len;
	}
	
	if (gog->num_of_released_gops == gog->num_of_counting_gops) {
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
		dbg_print (dbg_gog,1,dbg_facility,"analize_gop: no gog");
		
		gog_keys = g_hash_table_lookup(mc->gogs_by_gopname,gop->cfg->name);
		
		if ( ! gog_keys ) {
			dbg_print (dbg_gog,1,dbg_facility,"analize_gop: no gog_keys for this gop");
			return;
		}
		
		/* We'll look for any matching gogkeys */
		
		dbg_print (dbg_gog,1,dbg_facility,"analize_gop: got gog_keys: %s",gog_keys->name) ;
		
		while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
			
			dbg_print (dbg_gog,2,dbg_facility,"analize_gop: about to match");
			
			if (( gogkey_match = new_avpl_exact_match(gop->cfg->name,gop->avpl,curr_gogkey,TRUE) )) {
				
				key = avpl_to_str(gogkey_match);
				
				dbg_print (dbg_gog,1,dbg_facility,"analize_gop: got gogkey_match: %s",key);
				
				if (( gog = g_hash_table_lookup(gop->cfg->gog_index,key) )) {
					dbg_print (dbg_gog,1,dbg_facility,"analize_gop: got already a matching gog");
					
					if (gog->num_of_counting_gops == gog->num_of_released_gops && gog->expiration < rd->now) {
						dbg_print (dbg_gog,1,dbg_facility,"analize_gop: this is a new gog, not the old one, let's create it");
						
						gog_remove_keys(gog);
						
						gog = new_gog(gog->cfg,gop);
						
						break;
					} else {
						dbg_print (dbg_gog,1,dbg_facility,"analize_gop: this is our gog");
						
						g_free(key);
						
						if (! gop->gog ) adopt_gop(gog,gop);
						
						break;
					}
				} else {
					dbg_print (dbg_gog,1,dbg_facility,"analize_gop: no such gog in hash, let's create a new %s",curr_gogkey->name);
					
					cfg = g_hash_table_lookup(mc->gogcfgs,curr_gogkey->name);
					
					if (cfg) {
						gog = new_gog(cfg,gop);
						gog->num_of_gops = 1;
						
						if (gop->cfg->start) {
							gog->num_of_counting_gops = 1;
						}
						
					} else {
						dbg_print (dbg_gog,0,dbg_facility,"analize_gop: no such gog_cfg: %s",curr_gogkey->name);
					}
					
					break;
				}
				
				delete_avpl(gogkey_match,TRUE);
				gogkey_match = NULL;
			}
			
			dbg_print (dbg_gog,1,dbg_facility,"analize_gop: no gogkey_match: %s",key);
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
	LoAL* gog_keys = NULL;
	AVPL* curr_gogkey = NULL;
	void* cookie = NULL;
	AVPL* gogkey_match = NULL;
	guint8* gogkey = NULL;
	
	dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: %s",pdu->cfg->name);

	apply_transforms(pdu);

	/* is there a gop type for this pdu type? */
	cfg = g_hash_table_lookup(mc->gops_by_pduname,pdu->cfg->name);
	
	if (!cfg) return;
	
	candidate_gop_key_match = cfg->key;
	
	if (! candidate_gop_key_match) return;
	
	dbg_print (dbg_gop,3,dbg_facility,"analize_pdu: got candidate key");
	
	/* does the pdu matches the prematch candidate key for the gop type? */
	
	gopkey_match = new_avpl_exact_match("gop_key_match",pdu->avpl,candidate_gop_key_match, TRUE);
	
	if (gopkey_match) {
		gop_key = avpl_to_str(gopkey_match);
		
		candidate_start = cfg->start;
		
		if (candidate_start) {
			dbg_print (dbg_gop,2,dbg_facility,"analize_pdu: got candidate start");
			is_start = new_avpl_exact_match("",pdu->avpl, candidate_start, FALSE);
		}
		
		if (is_start) {
			dbg_print (dbg_gop,2,dbg_facility,"analize_pdu: got start match");
			delete_avpl(is_start,FALSE);	
		}
		
		g_hash_table_lookup_extended(cfg->gop_index,(gconstpointer)gop_key,(gpointer*)&orig_gop_key,(gpointer*)&gop);
		
		if ( gop ) {
			g_free(gop_key);
			
			/* is the gop dead ? */
			if ( ! gop->released &&
				 ( ( gop->cfg->lifetime > 0.0 && gop->time_to_die >= rd->now) || 
				   ( gop->cfg->idle_timeout > 0.0 && gop->time_to_timeout >= rd->now) ) ) {
				gop->released = TRUE;
				
				if (gop->gog && gop->cfg->start) gop->gog->num_of_released_gops++;
			}
			
			/* TODO: is the gop expired? */
			
			gop_key = orig_gop_key;
			
			dbg_print (dbg_gop,2,dbg_facility,"analize_pdu: got gop: %s",gop_key);
			
			if (is_start) {
				if ( gop->released ) {
					dbg_print (dbg_gop,3,dbg_facility,"analize_pdu: start on released gop, a new gop");
					g_hash_table_remove(cfg->gop_index,gop_key);
					gop = new_gop(cfg,pdu,gop_key);
					g_hash_table_insert(cfg->gop_index,gop_key,gop);
				} else {
					dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: duplicate start on gop");
				}
			}
			
			pdu->gop = gop;
			
			if (gop->last_pdu) gop->last_pdu->next = pdu;
			gop->last_pdu = pdu;
			pdu->next = NULL;
			pdu->time_in_gop = rd->now - gop->start_time;
			
			if (gop->released) pdu->after_release = TRUE;
			
		} else {

			dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: no gop already");

			if (is_start) {
				
				gop = new_gop(cfg,pdu,gop_key);
				g_hash_table_insert(cfg->gop_index,gop_key,gop);
				
			} else if (! candidate_start) {
				/* there is no GopStart, we'll check for matching GogKeys
				   if we have one we'll create the Gop */

				apply_extras(pdu->avpl,gopkey_match,cfg);

				gog_keys = g_hash_table_lookup(mc->gogs_by_gopname,cfg->name);

				if (gog_keys) {
					
					while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
						if (( gogkey_match = new_avpl_exact_match(cfg->name,gopkey_match,curr_gogkey,FALSE) )) {
							gogkey = avpl_to_str(gogkey_match);
							if (g_hash_table_lookup(cfg->gog_index,gogkey)) {
								gop = new_gop(cfg,pdu,gop_key);
								g_hash_table_insert(cfg->gop_index,gop_key,gop);
								delete_avpl(gogkey_match,FALSE);
								g_free(gogkey);
								break;
							} else {
								delete_avpl(gogkey_match,FALSE);
								g_free(gogkey);								
							}
						}
					}
					
					if ( ! gop ) {
						g_free(gop_key);
						delete_avpl(gopkey_match,TRUE);
						return;
					}
					
				} else {
					g_free(gop_key);
					delete_avpl(gopkey_match,TRUE);
					return;
				}
				
			} else {
				dbg_print (dbg_gop,6,dbg_facility,"analize_pdu: an unassigned pdu");
				
				pdu->gop = NULL;
				pdu->next = NULL;
				
				g_free(gop_key);
				delete_avpl(gopkey_match,TRUE);
				return;
			}
		}
		
		if ( gop ) {
			gop->num_of_pdus++;
			gop->time_to_timeout = cfg->idle_timeout > 0.0 ? cfg->idle_timeout + rd->now : (float) -1.0 ;
		} else {
			g_error("No GOP at this point is simply wrong!");
		}
		
		dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: merge with key");

		merge_avpl(gop->avpl,gopkey_match,TRUE);
		delete_avpl(gopkey_match,TRUE);
		
		dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: apply extras");

		apply_extras(pdu->avpl,gop->avpl,gop->cfg);
		
		avpl_str = avpl_to_str(gop->avpl);
		dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: Gop Attributes: %s",avpl_str);
		g_free(avpl_str);
		
		gop->last_time = pdu->rel_time;
		
		if ( ! gop->released) {
			candidate_stop = cfg->stop;
			if (candidate_stop) {
				dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: got candidate stop");
				is_stop = new_avpl_exact_match("",pdu->avpl, candidate_stop,FALSE);
			} else {
				is_stop = new_avpl("");
			}
			
			if(is_stop) {
				dbg_print (dbg_gop,1,dbg_facility,"analize_pdu: is a `stop");
				delete_avpl(is_stop,FALSE);
				
				if (! gop->released) {
					gop->released = TRUE;
					gop->release_time = pdu->rel_time;
					if (gop->gog && gop->cfg->start) gop->gog->num_of_released_gops++;
				}
				
				if (candidate_stop) pdu->is_stop = TRUE;
				
			} else {
				dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: is not a stop");
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
		dbg_print (dbg_gop,4,dbg_facility,"analize_pdu: no gop_key");
		
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
			
			dbg_print(dbg_pdu,6,dbg_facility,"get_pdu_fields: found field %i-%i",start,end);
			
			for (j = 0; j < data->ranges->len; j++) {
				
				curr_range = (mate_range*) g_ptr_array_index(data->ranges,j);
				
				dbg_print(dbg_pdu,6,dbg_facility,"get_pdu_fields: check if in range %i-%i",curr_range->start,curr_range->end);
				
				if (curr_range->end >= end && curr_range->start <= start) {
					avp = new_avp_from_finfo(name, fi);
					
					if (*dbg_pdu > 4) {
						s = avp_to_str(avp);
						dbg_print(dbg_pdu,5,dbg_facility,"get_pdu_fields: got %s",s);
						g_free(s);
					}
					
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

	dbg_print (dbg_pdu,2,dbg_facility,"new_pdu: type=%s framenum=%i",cfg->name,framenum);
		
	pdu->avpl = new_avpl(cfg->name);
	pdu->gop = NULL;
	pdu->next_in_frame = NULL;
	pdu->next = NULL;
	pdu->first = FALSE;
	pdu->is_start = FALSE;
	pdu->is_stop = FALSE;
	pdu->after_release = FALSE;
	pdu->frame = framenum;
	pdu->rel_time = rd->now;
	pdu->time_in_gop = -1.0;
	
	data.ranges = g_ptr_array_new();
	data.pdu  = pdu;
	data.interesting = interesting;
	
	/* first we create the proto range */
	proto_range = g_malloc(sizeof(mate_range));
	proto_range->start = proto->start;
	proto_range->end = proto->start + proto->length;
	g_ptr_array_add(data.ranges,proto_range);
	
	dbg_print(dbg_pdu,3,dbg_facility,"new_pdu: proto range %u-%u",proto_range->start,proto_range->end);
	
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
				
				dbg_print(dbg_pdu,3,dbg_facility,"new_pdu: transport(%i) range %i-%i",hfid,range->start,range->end);
			} else {
				/* we missed a range  */
				dbg_print(dbg_pdu,6,dbg_facility,"new_pdu: transport(%i) missed",hfid);
			}
			
		}
	}
	
	g_hash_table_foreach(cfg->hfids_attr,get_pdu_fields,&data);
	
	g_ptr_array_free(data.ranges,TRUE);
	
	return pdu;
}	


static void delete_mate_pdu(mate_pdu* pdu) {
	if (pdu->avpl) delete_avpl(pdu->avpl,TRUE);
	g_mem_chunk_free(rd->mate_items,pdu);	
}

extern void mate_analyze_frame(packet_info *pinfo, proto_tree* tree) {
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
			
			dbg_print (dbg_pdu,4,dbg_facility,"mate_analyze_frame: tryning to extract: %s",cfg->name);
			protos = (GPtrArray*) g_hash_table_lookup(tree->tree_data->interesting_hfids,(gpointer) cfg->hfid_proto);
			
			if (protos)  {
				pdu = NULL;
				
				for (j = 0; j < protos->len; j++) {

					dbg_print (dbg_pdu,3,dbg_facility,"mate_analyze_frame: found matching proto, extracting: %s",cfg->name);
					
					proto = (field_info*) g_ptr_array_index(protos,j);
					pdu = new_pdu(cfg, pinfo->fd->num, proto, tree->tree_data->interesting_hfids);
					
					if (cfg->criterium) {
						criterium_match = new_avpl_from_match(cfg->criterium_match_mode,"",pdu->avpl,cfg->criterium,FALSE);
						if (criterium_match) {
							delete_avpl(criterium_match,FALSE);
						}
						
						if ( (criterium_match && cfg->criterium->name == mc->reject ) 
							 || ( ! criterium_match && cfg->criterium->name == mc->accept )) {
							delete_mate_pdu(pdu);
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



