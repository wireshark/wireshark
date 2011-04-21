/* mate_runtime.c
* MATE -- Meta Analysis Tracing Engine
*
* Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
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
	proto_tree* tree;
	mate_pdu* pdu;
} tmp_pdu_data;


typedef struct _gogkey {
	gchar* key;
	mate_cfg_gop* cfg;
} gogkey;


static mate_runtime_data* rd = NULL;
static mate_config* mc = NULL;

static int zero = 5;

static int* dbg = &zero;
static int* dbg_pdu = &zero;
static int* dbg_gop = &zero;
static int* dbg_gog = &zero;
static FILE* dbg_facility = NULL;

static gboolean destroy_mate_pdus(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_pdu* pdu = (mate_pdu*) v;
	if (pdu->avpl) delete_avpl(pdu->avpl,TRUE);
	g_mem_chunk_free(rd->mate_items,pdu);
	return TRUE;
}

static gboolean destroy_mate_gops(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_gop* gop = (mate_gop*) v;

	if (gop->avpl) delete_avpl(gop->avpl,TRUE);

	if (gop->gop_key) {
		if (g_hash_table_lookup(gop->cfg->gop_index,gop->gop_key) == gop) {
			g_hash_table_remove(gop->cfg->gop_index,gop->gop_key);
		}

		g_free(gop->gop_key);
	}

	g_mem_chunk_free(rd->mate_items,gop);

	return TRUE;
}


static void gog_remove_keys (mate_gog* gog);

static gboolean destroy_mate_gogs(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_gog* gog = (mate_gog*) v;

	if (gog->avpl) delete_avpl(gog->avpl,TRUE);

	if (gog->gog_keys) {
		gog_remove_keys(gog);
		g_ptr_array_free(gog->gog_keys,FALSE);
	}

	g_mem_chunk_free(rd->mate_items,gog);

	return TRUE;
}

static gboolean return_true(gpointer k _U_, gpointer v _U_, gpointer p _U_) {
	return TRUE;
}

static void destroy_pdus_in_cfg(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_cfg_pdu* c =  v;
	g_hash_table_foreach_remove(c->items,destroy_mate_pdus,NULL);
	c->last_id = 0;
}


static void destroy_gops_in_cfg(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_cfg_gop* c =  v;

	g_hash_table_foreach_remove(c->gop_index,return_true,NULL);
	g_hash_table_destroy(c->gop_index);
	c->gop_index = g_hash_table_new(g_str_hash,g_str_equal);

	g_hash_table_foreach_remove(c->gog_index,return_true,NULL);
	g_hash_table_destroy(c->gog_index);
	c->gog_index = g_hash_table_new(g_str_hash,g_str_equal);

	g_hash_table_foreach_remove(c->items,destroy_mate_gops,NULL);
	c->last_id = 0;
}

static void destroy_gogs_in_cfg(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_cfg_gog* c =  v;
	g_hash_table_foreach_remove(c->items,destroy_mate_gogs,NULL);
	c->last_id = 0;
}

extern void initialize_mate_runtime(void) {

	dbg_print (dbg,5,dbg_facility,"initialize_mate: entering");

	if (( mc = mate_cfg() )) {
		if (rd == NULL ) {
			rd = g_malloc(sizeof(mate_runtime_data));
			rd->mate_items = g_mem_chunk_new("mate_items",sizeof(mate_max_size),1024,G_ALLOC_AND_FREE);
		} else {
			g_hash_table_foreach(mc->pducfgs,destroy_pdus_in_cfg,NULL);
			g_hash_table_foreach(mc->gopcfgs,destroy_gops_in_cfg,NULL);
			g_hash_table_foreach(mc->gogcfgs,destroy_gogs_in_cfg,NULL);

			g_hash_table_destroy(rd->frames);
		}

		rd->current_items = 0;
		rd->now = -1.0;
		rd->highest_analyzed_frame = 0;
		rd->frames = g_hash_table_new(g_direct_hash,g_direct_equal);


		/*mc->dbg_gop_lvl = 5;
		mc->dbg_gog_lvl = 5;
		*/
		dbg_pdu = &(mc->dbg_pdu_lvl);
		dbg_gop = &(mc->dbg_gop_lvl);
		dbg_gog = &(mc->dbg_gog_lvl);
		dbg = &(mc->dbg_lvl);
        dbg_facility = mc->dbg_facility;

        dbg_print(dbg, 1, dbg_facility, "starting mate");

	} else {
		rd = NULL;
	}
}


static mate_gop* new_gop(mate_cfg_gop* cfg, mate_pdu* pdu, gchar* key) {
	mate_gop* gop = g_mem_chunk_alloc(rd->mate_items);

	gop->id = ++(cfg->last_id);
	gop->cfg = cfg;

	dbg_print(dbg_gop, 1, dbg_facility, "new_gop: %s: ``%s:%d''", key, gop->cfg->name, gop->id);

	gop->gop_key = key;
	gop->avpl = new_avpl(cfg->name);
	gop->last_n = 0;

	gop->gog = NULL;
	gop->next = NULL;

	gop->expiration = cfg->expiration > 0.0 ? cfg->expiration + rd->now : (float) -1.0 ;
	gop->idle_expiration = cfg->idle_timeout > 0.0 ? cfg->idle_timeout + rd->now : (float) -1.0 ;
	gop->time_to_die = cfg->lifetime > 0.0 ? cfg->lifetime + rd->now : (float) -1.0 ;
	gop->time_to_timeout = 0.0;

	gop->last_time = gop->start_time = rd->now;
	gop->release_time = 0.0;

	gop->num_of_pdus = 0;
	gop->num_of_after_release_pdus = 0;

	gop->pdus = pdu;
	gop->last_pdu = pdu;

	gop->released = FALSE;

	pdu->gop = gop;
	pdu->next = NULL;
	pdu->is_start = TRUE;
	pdu->time_in_gop = 0.0;

	g_hash_table_insert(cfg->gop_index,gop->gop_key,gop);
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
	mate_gog* gog = g_mem_chunk_alloc(rd->mate_items);

	gog->id = ++(cfg->last_id);
	gog->cfg = cfg;

	dbg_print (dbg_gog,1,dbg_facility,"new_gog: %s:%u for %s:%u",gog->cfg->name,gog->id,gop->cfg->name,gop->id);

	gog->avpl = new_avpl(cfg->name);
	gog->last_n = 0;

	gog->expiration = 0.0;
	gog->idle_expiration = 0.0;

	gog->start_time = rd->now;
	gog->release_time = 0.0;
	gog->last_time = 0.0;

	gog->gops = NULL;
	gog->last_gop = NULL;

	gog->num_of_gops = 0;
	gog->num_of_counting_gops = 0;
	gog->num_of_released_gops = 0;

	gog->gog_keys = g_ptr_array_new();

	adopt_gop(gog,gop);

	return gog;
}

static void apply_transforms(GPtrArray* transforms, AVPL* avpl) {
	AVPL_Transf* transform = NULL;
	guint i;

	for (i = 0; i < transforms->len; i++) {
		transform = g_ptr_array_index(transforms,i);
		avpl_transform(avpl, transform);
	}
}


/* applies the extras for which type to what avpl */
static void apply_extras(AVPL* from, AVPL* to,  AVPL* extras) {
	AVPL* our_extras = new_avpl_loose_match("",from, extras, FALSE) ;

	if (our_extras) {
		merge_avpl(to,our_extras,TRUE);
		delete_avpl(our_extras,FALSE);
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

	dbg_print (dbg_gog,1,dbg_facility,"reanalyze_gop: %s:%d",gop->cfg->name,gop->id);

	apply_extras(gop->avpl,gog->avpl,gog->cfg->extra);

	/* XXX: Instead of using the length of the avpl to check if an avpl has changed,
			which is not accurate at all,  we should have apply_extras,
			apply_transformations and other functions that can modify the avpl
		    to flag the avpl if it has changed, then we'll check for the flag
		    and clear it after analysis */

	if (gog->last_n != gog->avpl->len) {

		dbg_print (dbg_gog,2,dbg_facility,"reanalyze_gop: gog has new attributes let's look for new keys");

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
					/* XXX: since these gogs actually share key info
							we should try to merge (non released) gogs
					        that happen to have equal keys */
				} else {
					dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: new key for gog=%s:%d : %s",gog->cfg->name,gog->id,gog_key->key);
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

static void analyze_gop(mate_gop* gop) {
	mate_cfg_gog* cfg = NULL;
	LoAL* gog_keys = NULL;
	AVPL* curr_gogkey = NULL;
	void* cookie = NULL;
	AVPL* gogkey_match = NULL;
	mate_gog* gog = NULL;
	gchar* key = NULL;

	if ( ! gop->gog  ) {
		/* no gog, let's either find one or create it if due */
		dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: no gog");

		gog_keys = g_hash_table_lookup(mc->gogs_by_gopname,gop->cfg->name);

		if ( ! gog_keys ) {
			dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: no gog_keys for this gop");
			return;
		}

		/* We have gog_keys! look for matching gogkeys */

		dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: got gog_keys: %s",gog_keys->name) ;

		while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
			if (( gogkey_match = new_avpl_exact_match(gop->cfg->name,gop->avpl,curr_gogkey,TRUE) )) {

				key = avpl_to_str(gogkey_match);

				dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: got gogkey_match: %s",key);

				if (( gog = g_hash_table_lookup(gop->cfg->gog_index,key) )) {
					dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: got already a matching gog");

					if (gog->num_of_counting_gops == gog->num_of_released_gops && gog->expiration < rd->now) {
						dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: this is a new gog, not the old one, let's create it");

						gog_remove_keys(gog);

						gog = new_gog(gog->cfg,gop);

						break;
					} else {
						dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: this is our gog");

						if (! gop->gog ) adopt_gop(gog,gop);

						break;
					}
				} else {
					dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: no such gog in hash, let's create a new %s",curr_gogkey->name);

					cfg = g_hash_table_lookup(mc->gogcfgs,curr_gogkey->name);

					if (cfg) {
						gog = new_gog(cfg,gop);
						gog->num_of_gops = 1;

						if (gop->cfg->start) {
							gog->num_of_counting_gops = 1;
						}

					} else {
						dbg_print (dbg_gog,0,dbg_facility,"analyze_gop: no such gog_cfg: %s",curr_gogkey->name);
					}

					break;
				}

				/** Can't get here because of "breaks" above */
				g_assert_not_reached();
			}

			dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: no gogkey_match: %s",key);
		} /* while */

		g_free(key);
		key = NULL;

		if (gogkey_match) delete_avpl(gogkey_match,TRUE);

		reanalyze_gop(gop);
	}
}



static void analyze_pdu(mate_pdu* pdu) {
	/* TODO:
    return a g_boolean to tell we've destroyed the pdu when the pdu is unnassigned
	destroy the unassigned pdu
	*/
	mate_cfg_gop* cfg = NULL;
	mate_gop* gop = NULL;
	gchar* gop_key;
	gchar* orig_gop_key = NULL;
	AVPL* candidate_start = NULL;
	AVPL* candidate_stop = NULL;
	AVPL* is_start = NULL;
	AVPL* is_stop = NULL;
	AVPL* gopkey_match = NULL;
	LoAL* gog_keys = NULL;
	AVPL* curr_gogkey = NULL;
	void* cookie = NULL;
	AVPL* gogkey_match = NULL;
	gchar* gogkey_str = NULL;

	dbg_print (dbg_gop,1,dbg_facility,"analyze_pdu: %s",pdu->cfg->name);

	if (! (cfg = g_hash_table_lookup(mc->gops_by_pduname,pdu->cfg->name)) )
		return;

	if ((gopkey_match = new_avpl_exact_match("gop_key_match",pdu->avpl,cfg->key, TRUE))) {
		gop_key = avpl_to_str(gopkey_match);

		g_hash_table_lookup_extended(cfg->gop_index,(gconstpointer)gop_key,(gpointer)&orig_gop_key,(gpointer)&gop);

		if ( gop ) {
			g_free(gop_key);

			/* is the gop dead ? */
			if ( ! gop->released &&
				 ( ( gop->cfg->lifetime > 0.0 && gop->time_to_die >= rd->now) ||
				   ( gop->cfg->idle_timeout > 0.0 && gop->time_to_timeout >= rd->now) ) ) {
				dbg_print (dbg_gop,4,dbg_facility,"analyze_pdu: expiring released gop");
				gop->released = TRUE;

				if (gop->gog && gop->cfg->start) gop->gog->num_of_released_gops++;
			}

			/* TODO: is the gop expired? */

			gop_key = orig_gop_key;

			dbg_print (dbg_gop,2,dbg_facility,"analyze_pdu: got gop: %s",gop_key);

			if (( candidate_start = cfg->start )) {

				dbg_print (dbg_gop,2,dbg_facility,"analyze_pdu: got candidate start");

				if (( is_start = new_avpl_exact_match("",pdu->avpl, candidate_start, FALSE) )) {
					delete_avpl(is_start,FALSE);
					if ( gop->released ) {
						dbg_print (dbg_gop,3,dbg_facility,"analyze_pdu: start on released gop, let's create a new gop");

						g_hash_table_remove(cfg->gop_index,gop_key);
						gop->gop_key = NULL;
						gop = new_gop(cfg,pdu,gop_key);
						g_hash_table_insert(cfg->gop_index,gop_key,gop);
					} else {
						dbg_print (dbg_gop,1,dbg_facility,"analyze_pdu: duplicate start on gop");
					}
				}
			}

			pdu->gop = gop;

			if (gop->last_pdu) gop->last_pdu->next = pdu;
			gop->last_pdu = pdu;
			pdu->next = NULL;
			pdu->time_in_gop = rd->now - gop->start_time;

			if (gop->released) pdu->after_release = TRUE;

		} else {

			dbg_print (dbg_gop,1,dbg_facility,"analyze_pdu: no gop already");

			if ( ! cfg->start ) {
				/* there is no GopStart, we'll check for matching GogKeys
				if we have one we'll create the Gop */

				apply_extras(pdu->avpl,gopkey_match,cfg->extra);

				gog_keys = g_hash_table_lookup(mc->gogs_by_gopname,cfg->name);

				if (gog_keys) {

					while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
						if (( gogkey_match = new_avpl_exact_match(cfg->name,gopkey_match,curr_gogkey,FALSE) )) {
							gogkey_str = avpl_to_str(gogkey_match);

							if (g_hash_table_lookup(cfg->gog_index,gogkey_str)) {
								gop = new_gop(cfg,pdu,gop_key);
								g_hash_table_insert(cfg->gop_index,gop_key,gop);
								delete_avpl(gogkey_match,FALSE);
								g_free(gogkey_str);
								break;
							} else {
								delete_avpl(gogkey_match,FALSE);
								g_free(gogkey_str);
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
				candidate_start = cfg->start;

				if (( is_start = new_avpl_exact_match("",pdu->avpl, candidate_start, FALSE) )) {
					delete_avpl(is_start,FALSE);
					gop = new_gop(cfg,pdu,gop_key);
				} else {
					g_free(gop_key);
					return;
				}

				pdu->gop = gop;
			}
		}

		if (gop->last_pdu) gop->last_pdu->next = pdu;
		gop->last_pdu = pdu;
		pdu->next = NULL;

		pdu->time_in_gop = rd->now - gop->start_time;

		gop->num_of_pdus++;
		gop->time_to_timeout = cfg->idle_timeout > 0.0 ? cfg->idle_timeout + rd->now : (float) -1.0 ;

		dbg_print (dbg_gop,4,dbg_facility,"analyze_pdu: merge with key");

		merge_avpl(gop->avpl,gopkey_match,TRUE);
		delete_avpl(gopkey_match,TRUE);

		dbg_print (dbg_gop,4,dbg_facility,"analyze_pdu: apply extras");

		apply_extras(pdu->avpl,gop->avpl,gop->cfg->extra);

		gop->last_time = pdu->rel_time;

		if ( ! gop->released) {
			candidate_stop = cfg->stop;

			if (candidate_stop) {
				is_stop = new_avpl_exact_match("",pdu->avpl, candidate_stop,FALSE);
			} else {
				is_stop = new_avpl("");
			}

			if(is_stop) {
				dbg_print (dbg_gop,1,dbg_facility,"analyze_pdu: is a `stop");
				delete_avpl(is_stop,FALSE);

				if (! gop->released) {
					gop->released = TRUE;
					gop->release_time = pdu->rel_time;
					if (gop->gog && gop->cfg->start) gop->gog->num_of_released_gops++;
				}

				pdu->is_stop = TRUE;

			}
		}

		if (gop->last_n != gop->avpl->len) apply_transforms(gop->cfg->transforms,gop->avpl);

		gop->last_n = gop->avpl->len;

		if (gop->gog) {
			reanalyze_gop(gop);
		} else {
			analyze_gop(gop);
		}

	} else {
		dbg_print (dbg_gop,4,dbg_facility,"analyze_pdu: no match for this pdu");

		pdu->gop = NULL;
	}
}

static void get_pdu_fields(gpointer k, gpointer v, gpointer p) {
	int hfid = *((int*) k);
	gchar* name = (gchar*) v;
	tmp_pdu_data* data = (tmp_pdu_data*) p;
	GPtrArray* fis;
	field_info* fi;
	guint i,j;
	mate_range* curr_range;
	guint start;
	guint end;
	AVP* avp;
	gchar* s;


	fis = proto_get_finfo_ptr_array(data->tree, hfid);

	if (fis) {
		for (i = 0; i < fis->len; i++) {
			fi = (field_info*) g_ptr_array_index(fis,i);


			start = fi->start;
			end = fi->start + fi->length;

			dbg_print(dbg_pdu,5,dbg_facility,"get_pdu_fields: found field %i-%i",start,end);

			for (j = 0; j < data->ranges->len; j++) {

				curr_range = (mate_range*) g_ptr_array_index(data->ranges,j);

				if (curr_range->end >= end && curr_range->start <= start) {
					avp = new_avp_from_finfo(name, fi);

					if (*dbg_pdu > 4) {
						s = avp_to_str(avp);
						dbg_print(dbg_pdu,0,dbg_facility,"get_pdu_fields: got %s",s);
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

static mate_pdu* new_pdu(mate_cfg_pdu* cfg, guint32 framenum, field_info* proto, proto_tree* tree) {
	mate_pdu* pdu = g_mem_chunk_alloc(rd->mate_items);
	field_info* cfi;
	GPtrArray* ptrs;
	mate_range* range;
	mate_range* proto_range;
	tmp_pdu_data data;
	guint i,j;
	gint min_dist;
	field_info* range_fi;
	gint32 last_start;
	gint32 first_end;
	gint32 curr_end;
	int hfid;

	dbg_print (dbg_pdu,1,dbg_facility,"new_pdu: type=%s framenum=%i",cfg->name,framenum);

	pdu->id = ++(cfg->last_id);
	pdu->cfg = cfg;

	pdu->avpl = new_avpl(cfg->name);

	pdu->frame = framenum;
	pdu->next_in_frame = NULL;
	pdu->rel_time = rd->now;

	pdu->gop = NULL;
	pdu->next = NULL;
	pdu->time_in_gop = -1.0;

	pdu->first = FALSE;
	pdu->is_start = FALSE;
	pdu->is_stop = FALSE;
	pdu->after_release = FALSE;

	data.ranges = g_ptr_array_new();
	data.pdu  = pdu;
	data.tree = tree;

	/* first we create the proto range */
	proto_range = g_malloc(sizeof(mate_range));
	proto_range->start = proto->start;
	proto_range->end = proto->start + proto->length;
	g_ptr_array_add(data.ranges,proto_range);

	dbg_print(dbg_pdu,3,dbg_facility,"new_pdu: proto range %u-%u",proto_range->start,proto_range->end);

	last_start = proto_range->start;

	/* we move forward in the tranport */
	for (i = cfg->transport_ranges->len; i--; ) {
		hfid = *((int*)g_ptr_array_index(cfg->transport_ranges,i));
		ptrs = proto_get_finfo_ptr_array(tree, hfid);
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
				range = g_malloc(sizeof(*range));
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

	if (cfg->payload_ranges) {

		first_end = proto_range->end;

		for (i = 0 ; i < cfg->payload_ranges->len; i++) {
			hfid = *((int*)g_ptr_array_index(cfg->payload_ranges,i));
			ptrs = proto_get_finfo_ptr_array(tree, hfid);
			min_dist = 99999;
			range_fi = NULL;

			if (ptrs) {
				for (j=0; j < ptrs->len; j++) {
					cfi = (field_info*) g_ptr_array_index(ptrs,j);
					curr_end = cfi->start + cfi->length;
					if (curr_end > first_end && min_dist >= (curr_end - first_end) ) {
						range_fi = cfi;
						min_dist = curr_end - first_end;
					}
				}

				if ( range_fi ) {
					range = g_malloc(sizeof(*range));
					range->start = range_fi->start;
					range->end = range_fi->start + range_fi->length;
					g_ptr_array_add(data.ranges,range);

					last_start = range_fi->start;

					dbg_print(dbg_pdu,3,dbg_facility,"new_pdu: payload(%i) range %i-%i",hfid,range->start,range->end);
				} else {
					/* we missed a range  */
					dbg_print(dbg_pdu,5,dbg_facility,"new_pdu: payload(%i) missed",hfid);
				}

			}
		}
	}

	g_hash_table_foreach(cfg->hfids_attr,get_pdu_fields,&data);

	apply_transforms(pdu->cfg->transforms,pdu->avpl);

	g_ptr_array_free(data.ranges,TRUE);

	return pdu;
}


extern void mate_analyze_frame(packet_info *pinfo, proto_tree* tree) {
	mate_cfg_pdu* cfg;
	GPtrArray* protos;
	field_info* proto;
	guint i,j;
	AVPL* criterium_match;

	mate_pdu* pdu = NULL;
	mate_pdu* last = NULL;

	rd->now = (float) nstime_to_sec(&pinfo->fd->rel_ts);

	if ( proto_tracking_interesting_fields(tree)
		 && rd->highest_analyzed_frame < pinfo->fd->num ) {
		for ( i = 0; i < mc->pducfglist->len; i++ ) {

			cfg = g_ptr_array_index(mc->pducfglist,i);

			dbg_print (dbg_pdu,4,dbg_facility,"mate_analyze_frame: trying to extract: %s",cfg->name);
			protos = proto_get_finfo_ptr_array(tree, cfg->hfid_proto);

			if (protos)  {
				pdu = NULL;

				for (j = 0; j < protos->len; j++) {

					dbg_print (dbg_pdu,3,dbg_facility,"mate_analyze_frame: found matching proto, extracting: %s",cfg->name);

					proto = (field_info*) g_ptr_array_index(protos,j);
					pdu = new_pdu(cfg, pinfo->fd->num, proto, tree);

					if (cfg->criterium) {
						criterium_match = new_avpl_from_match(cfg->criterium_match_mode,"",pdu->avpl,cfg->criterium,FALSE);

						if (criterium_match) {
							delete_avpl(criterium_match,FALSE);
						}

						if ( (criterium_match && cfg->criterium_accept_mode == REJECT_MODE )
							 || ( ! criterium_match && cfg->criterium_accept_mode == ACCEPT_MODE )) {

							delete_avpl(pdu->avpl,TRUE);
							g_mem_chunk_free(rd->mate_items,pdu);
							pdu = NULL;

							continue;
						}
					}

					analyze_pdu(pdu);

					if ( ! pdu->gop && cfg->drop_unassigned) {
						delete_avpl(pdu->avpl,TRUE);
						g_mem_chunk_free(rd->mate_items,pdu);
						pdu = NULL;
						continue;
					}

					if ( cfg->discard ) {
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

				if ( pdu && cfg->last_extracted ) break;
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



