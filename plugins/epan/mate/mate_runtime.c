/* mate_runtime.c
 * MATE -- Meta Analysis Tracing Engine
 *
 * Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "mate.h"
#include <wsutil/ws_assert.h>

typedef struct _mate_range mate_range;

struct _mate_range {
	tvbuff_t *ds_tvb;
	unsigned start;
	unsigned end;
};


typedef struct _tmp_pdu_data {
	GPtrArray* ranges;
	proto_tree* tree;
	mate_pdu* pdu;
} tmp_pdu_data;


typedef struct _gogkey {
	char* key;
	mate_cfg_gop* cfg;
} gogkey;


static mate_runtime_data* rd;

static int zero = 5;

static int* dbg = &zero;
static int* dbg_pdu = &zero;
static int* dbg_gop = &zero;
static int* dbg_gog = &zero;
static FILE* dbg_facility;

static gboolean destroy_mate_pdus(void *k _U_, void *v, void *p _U_) {
	mate_pdu* pdu = (mate_pdu*) v;
	if (pdu->avpl) delete_avpl(pdu->avpl,true);
	g_slice_free(mate_max_size, (mate_max_size *)pdu);
	return TRUE;
}

static gboolean destroy_mate_gops(void *k _U_, void *v, void *p _U_) {
	mate_gop* gop = (mate_gop*) v;

	if (gop->avpl) delete_avpl(gop->avpl,true);

	if (gop->gop_key) {
		if (g_hash_table_lookup(gop->cfg->gop_index,gop->gop_key) == gop) {
			g_hash_table_remove(gop->cfg->gop_index,gop->gop_key);
		}

		g_free(gop->gop_key);
	}

	g_slice_free(mate_max_size,(mate_max_size*)gop);

	return TRUE;
}


static void gog_remove_keys (mate_gog* gog);

static gboolean destroy_mate_gogs(void *k _U_, void *v, void *p _U_) {
	mate_gog* gog = (mate_gog*) v;

	if (gog->avpl) delete_avpl(gog->avpl,true);

	if (gog->gog_keys) {
		gog_remove_keys(gog);
		g_ptr_array_free(gog->gog_keys, true);
	}

	g_slice_free(mate_max_size,(mate_max_size*)gog);

	return TRUE;
}

static gboolean return_true(void *k _U_, void *v _U_, void *p _U_) {
	return TRUE;
}

static void destroy_pdus_in_cfg(void *k _U_, void *v, void *p _U_) {
	mate_cfg_pdu* c = (mate_cfg_pdu *)v;
	g_hash_table_foreach_remove(c->items,destroy_mate_pdus,NULL);
	c->last_id = 0;
}


static void destroy_gops_in_cfg(void *k _U_, void *v, void *p _U_) {
	mate_cfg_gop* c = (mate_cfg_gop *)v;

	g_hash_table_foreach_remove(c->gop_index,return_true,NULL);
	g_hash_table_destroy(c->gop_index);
	c->gop_index = g_hash_table_new(g_str_hash,g_str_equal);

	g_hash_table_foreach_remove(c->gog_index,return_true,NULL);
	g_hash_table_destroy(c->gog_index);
	c->gog_index = g_hash_table_new(g_str_hash,g_str_equal);

	g_hash_table_foreach_remove(c->items,destroy_mate_gops,NULL);
	c->last_id = 0;
}

static void destroy_gogs_in_cfg(void *k _U_, void *v, void *p _U_) {
	mate_cfg_gog* c = (mate_cfg_gog *)v;
	g_hash_table_foreach_remove(c->items,destroy_mate_gogs,NULL);
	c->last_id = 0;
}

void initialize_mate_runtime(mate_config* mc) {

	dbg_print (dbg,5,dbg_facility,"initialize_mate: entering");

	if (mc) {
		if (rd == NULL ) {
			rd = g_new(mate_runtime_data, 1);
		} else {
			g_hash_table_foreach(mc->pducfgs,destroy_pdus_in_cfg,NULL);
			g_hash_table_foreach(mc->gopcfgs,destroy_gops_in_cfg,NULL);
			g_hash_table_foreach(mc->gogcfgs,destroy_gogs_in_cfg,NULL);

			g_hash_table_destroy(rd->frames);
		}

		rd->current_items = 0;
		rd->now = -1.0f;
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


static mate_gop* new_gop(mate_cfg_gop* cfg, mate_pdu* pdu, char* key) {
	mate_gop* gop = (mate_gop*)g_slice_new(mate_max_size);

	gop->id = ++(cfg->last_id);
	gop->cfg = cfg;

	dbg_print(dbg_gop, 1, dbg_facility, "new_gop: %s: ``%s:%d''", key, gop->cfg->name, gop->id);

	gop->gop_key = key;
	gop->avpl = new_avpl(cfg->name);
	gop->last_n = 0;

	gop->gog = NULL;
	gop->next = NULL;

	gop->expiration = cfg->expiration > 0.0 ? cfg->expiration + rd->now : -1.0 ;
	gop->idle_expiration = cfg->idle_timeout > 0.0 ? cfg->idle_timeout + rd->now : -1.0 ;
	gop->time_to_die = cfg->lifetime > 0.0 ? cfg->lifetime + rd->now : -1.0 ;
	gop->time_to_timeout = 0.0f;

	gop->last_time = gop->start_time = rd->now;
	gop->release_time = 0.0f;

	gop->num_of_pdus = 0;
	gop->num_of_after_release_pdus = 0;

	gop->pdus = pdu;
	gop->last_pdu = pdu;

	gop->released = false;

	pdu->gop = gop;
	pdu->next = NULL;
	pdu->is_start = true;
	pdu->time_in_gop = 0.0f;

	g_hash_table_insert(cfg->gop_index,gop->gop_key,gop);
	return gop;
}

static void adopt_gop(mate_gog* gog, mate_gop* gop) {
	dbg_print (dbg_gog,5,dbg_facility,"adopt_gop: gog=%p gop=%p",(void*)gog,(void*)gop);

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
	mate_gog* gog = (mate_gog*)g_slice_new(mate_max_size);
	gog->id = ++(cfg->last_id);
	gog->cfg = cfg;

	dbg_print (dbg_gog,1,dbg_facility,"new_gog: %s:%u for %s:%u",gog->cfg->name,gog->id,gop->cfg->name,gop->id);

	gog->avpl = new_avpl(cfg->name);
	gog->last_n = 0;

	gog->expiration = 0.0f;
	gog->idle_expiration = 0.0f;

	gog->start_time = rd->now;
	gog->release_time = 0.0f;
	gog->last_time = 0.0f;

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
	unsigned i;

	for (i = 0; i < transforms->len; i++) {
		transform = (AVPL_Transf *)g_ptr_array_index(transforms,i);
		avpl_transform(avpl, transform);
	}
}


/* applies the extras for which type to what avpl */
static void apply_extras(AVPL* from, AVPL* to,  AVPL* extras) {
	AVPL* our_extras = new_avpl_loose_match("",from, extras, false) ;

	if (our_extras) {
		merge_avpl(to,our_extras,true);
		delete_avpl(our_extras,false);
	}
}

static void gog_remove_keys (mate_gog* gog) {
	gogkey* gog_key;

	while (gog->gog_keys->len) {
		gog_key = (gogkey *)g_ptr_array_remove_index_fast(gog->gog_keys,0);

		if (g_hash_table_lookup(gog_key->cfg->gog_index,gog_key->key) == gog) {
			g_hash_table_remove(gog_key->cfg->gog_index,gog_key->key);
		}

		g_free(gog_key->key);
		g_free(gog_key);
	}

}

static void reanalyze_gop(mate_config* mc, mate_gop* gop) {
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
			gop_cfg = (mate_cfg_gop *)g_hash_table_lookup(mc->gopcfgs,curr_gogkey->name);

			if (( gogkey_match = new_avpl_pairs_match(gop_cfg->name, gog->avpl, curr_gogkey, true, false) )) {

				gog_key = g_new(gogkey, 1);

				gog_key->key = avpl_to_str(gogkey_match);
				delete_avpl(gogkey_match,false);

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
		gog->released =  true;
		gog->expiration = gog->cfg->expiration + rd->now;
	} else {
		gog->released =  false;
	}
}

static void analyze_gop(mate_config* mc, mate_gop* gop) {
	mate_cfg_gog* cfg = NULL;
	LoAL* gog_keys = NULL;
	AVPL* curr_gogkey = NULL;
	void* cookie = NULL;
	AVPL* gogkey_match = NULL;
	mate_gog* gog = NULL;
	char* key = NULL;

	if ( ! gop->gog  ) {
		/* no gog, let's either find one or create it if due */
		dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: no gog");

		gog_keys = (LoAL *)g_hash_table_lookup(mc->gogs_by_gopname,gop->cfg->name);

		if ( ! gog_keys ) {
			dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: no gog_keys for this gop");
			return;
		}

		/* We have gog_keys! look for matching gogkeys */

		dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: got gog_keys: %s",gog_keys->name) ;

		while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
			if (( gogkey_match = new_avpl_pairs_match(gop->cfg->name, gop->avpl, curr_gogkey, true, true) )) {

				key = avpl_to_str(gogkey_match);

				dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: got gogkey_match: %s",key);

				if (( gog = (mate_gog *)g_hash_table_lookup(gop->cfg->gog_index,key) )) {
					dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: got already a matching gog: %s:%d",gog->cfg->name,gog->id);

					if (gog->num_of_counting_gops == gog->num_of_released_gops && gog->expiration < rd->now) {
						dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: this is a new gog, not the old one, let's create it");

						gog_remove_keys(gog);

						new_gog(gog->cfg,gop);

						break;
					} else {
						dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: this is our gog");

						if (! gop->gog ) adopt_gop(gog,gop);

						break;
					}
				} else {
					dbg_print (dbg_gog,1,dbg_facility,"analyze_gop: no such gog in hash, let's create a new %s",curr_gogkey->name);

					cfg = (mate_cfg_gog *)g_hash_table_lookup(mc->gogcfgs,curr_gogkey->name);

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
				ws_assert_not_reached();
			}
		} /* while */

		g_free(key);
		key = NULL;

		if (gogkey_match) delete_avpl(gogkey_match,true);

		reanalyze_gop(mc, gop);
	}
}



static void analyze_pdu(mate_config* mc, mate_pdu* pdu) {
	/* TODO:
	return a g_boolean to tell we've destroyed the pdu when the pdu is unnassigned
	destroy the unassigned pdu
	*/
	mate_cfg_gop* cfg = NULL;
	mate_gop* gop = NULL;
	char* gop_key;
	char* orig_gop_key = NULL;
	AVPL* candidate_start = NULL;
	AVPL* candidate_stop = NULL;
	AVPL* is_start = NULL;
	AVPL* is_stop = NULL;
	AVPL* gopkey_match = NULL;
	LoAL* gog_keys = NULL;
	AVPL* curr_gogkey = NULL;
	void* cookie = NULL;
	AVPL* gogkey_match = NULL;
	char* gogkey_str = NULL;

	dbg_print (dbg_gop,1,dbg_facility,"analyze_pdu: %s",pdu->cfg->name);

	if (! (cfg = (mate_cfg_gop *)g_hash_table_lookup(mc->gops_by_pduname,pdu->cfg->name)) )
		return;

	if ((gopkey_match = new_avpl_pairs_match("gop_key_match", pdu->avpl, cfg->key, true, true))) {
		gop_key = avpl_to_str(gopkey_match);

		g_hash_table_lookup_extended(cfg->gop_index,(const void *)gop_key,(void * *)&orig_gop_key,(void * *)&gop);

		if ( gop ) {
			g_free(gop_key);

			/* is the gop dead ? */
			if ( ! gop->released &&
				 ( ( gop->cfg->lifetime > 0.0 && gop->time_to_die >= rd->now) ||
				   ( gop->cfg->idle_timeout > 0.0 && gop->time_to_timeout >= rd->now) ) ) {
				dbg_print (dbg_gop,4,dbg_facility,"analyze_pdu: expiring released gop");
				gop->released = true;

				if (gop->gog && gop->cfg->start) gop->gog->num_of_released_gops++;
			}

			/* TODO: is the gop expired? */

			gop_key = orig_gop_key;

			dbg_print (dbg_gop,2,dbg_facility,"analyze_pdu: got gop: %s",gop_key);

			if (( candidate_start = cfg->start )) {

				dbg_print (dbg_gop,2,dbg_facility,"analyze_pdu: got candidate start");

				if (( is_start = new_avpl_pairs_match("", pdu->avpl, candidate_start, true, false) )) {
					delete_avpl(is_start,false);
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

			if (gop->released) pdu->after_release = true;

		} else {

			dbg_print (dbg_gop,1,dbg_facility,"analyze_pdu: no gop already");

			if ( ! cfg->start ) {
				/* there is no GopStart, we'll check for matching GogKeys
				if we have one we'll create the Gop */

				apply_extras(pdu->avpl,gopkey_match,cfg->extra);

				gog_keys = (LoAL *)g_hash_table_lookup(mc->gogs_by_gopname,cfg->name);

				if (gog_keys) {

					while (( curr_gogkey = get_next_avpl(gog_keys,&cookie) )) {
						if (( gogkey_match = new_avpl_pairs_match(cfg->name, gopkey_match, curr_gogkey, true, false) )) {
							gogkey_str = avpl_to_str(gogkey_match);

							if (g_hash_table_lookup(cfg->gog_index,gogkey_str)) {
								gop = new_gop(cfg,pdu,gop_key);
								g_hash_table_insert(cfg->gop_index,gop_key,gop);
								delete_avpl(gogkey_match,false);
								g_free(gogkey_str);
								break;
							} else {
								delete_avpl(gogkey_match,false);
								g_free(gogkey_str);
							}
						}
					}

					if ( ! gop ) {
						g_free(gop_key);
						delete_avpl(gopkey_match,true);
						return;
					}

				} else {
					g_free(gop_key);
					delete_avpl(gopkey_match,true);
					return;
				}

			} else {
				candidate_start = cfg->start;

				if (( is_start = new_avpl_pairs_match("", pdu->avpl, candidate_start, true, false) )) {
					delete_avpl(is_start,false);
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
		gop->time_to_timeout = cfg->idle_timeout > 0.0 ? cfg->idle_timeout + rd->now : -1.0 ;

		dbg_print (dbg_gop,4,dbg_facility,"analyze_pdu: merge with key");

		merge_avpl(gop->avpl,gopkey_match,true);
		delete_avpl(gopkey_match,true);

		dbg_print (dbg_gop,4,dbg_facility,"analyze_pdu: apply extras");

		apply_extras(pdu->avpl,gop->avpl,gop->cfg->extra);

		gop->last_time = pdu->rel_time;

		if ( ! gop->released) {
			candidate_stop = cfg->stop;

			if (candidate_stop) {
				is_stop = new_avpl_pairs_match("", pdu->avpl, candidate_stop, true, false);
			} else {
				is_stop = new_avpl("");
			}

			if(is_stop) {
				dbg_print (dbg_gop,1,dbg_facility,"analyze_pdu: is a `stop");
				delete_avpl(is_stop,false);

				if (! gop->released) {
					gop->released = true;
					gop->release_time = pdu->rel_time;
					if (gop->gog && gop->cfg->start) gop->gog->num_of_released_gops++;
				}

				pdu->is_stop = true;

			}
		}

		if (gop->last_n != gop->avpl->len) apply_transforms(gop->cfg->transforms,gop->avpl);

		gop->last_n = gop->avpl->len;

		if (gop->gog) {
			reanalyze_gop(mc, gop);
		} else {
			analyze_gop(mc, gop);
		}

	} else {
		dbg_print (dbg_gop,4,dbg_facility,"analyze_pdu: no match for this pdu");

		pdu->gop = NULL;
	}
}

static proto_node *
// NOLINTNEXTLINE(misc-no-recursion)
proto_tree_find_node_from_finfo(proto_tree *tree, field_info *finfo)
{
        proto_node *pnode = tree;
        proto_node *child;
        proto_node *current;

	if (PNODE_FINFO(pnode) == finfo) {
		return pnode;
	}

        child = pnode->first_child;
        while (child != NULL) {
                current = child;
                child   = current->next;
                // We recurse here, but we're limited by tree depth checks in epan
                if ((pnode = proto_tree_find_node_from_finfo((proto_tree *)current, finfo))) {
                        return pnode;
		}
        }

        return NULL;
}

/* This returns true if there's no point in searching for the avp among the
 * ancestor nodes in the tree. That includes if the field is within one
 * of the ranges, or if the field and all the ranges share the same
 * data source.
 */
static bool
add_avp(const char *name, field_info *fi, const field_info *ancestor_fi, tmp_pdu_data *data)
{
	AVP* avp;
	char* s;
	mate_range* curr_range;
	unsigned start, end;
	tvbuff_t *ds_tvb;
	bool all_same_ds = true;

	start = ancestor_fi->start;
	end = ancestor_fi->start + ancestor_fi->length;
	ds_tvb = ancestor_fi->ds_tvb;

	for (unsigned j = 0; j < data->ranges->len; j++) {

		curr_range = (mate_range*) g_ptr_array_index(data->ranges,j);

		if (curr_range->ds_tvb == ds_tvb) {
			if (curr_range->end >= end && curr_range->start <= start) {
				avp = new_avp_from_finfo(name, fi);
				if (*dbg_pdu > 4) {
					s = avp_to_str(avp);
					dbg_print(dbg_pdu,0,dbg_facility,"add_avp: got %s",s);
					g_free(s);
				}

				if (! insert_avp(data->pdu->avpl, avp) ) {
					delete_avp(avp);
				}
				return true;
			}
		} else {
			all_same_ds = false;
		}
	}

	return all_same_ds;
}

static void get_pdu_fields(void *k, void *v, void *p) {
	int hfid = *((int*) k);
	char* name = (char*) v;
	tmp_pdu_data* data = (tmp_pdu_data*) p;
	GPtrArray* fis;
	field_info* fi;
	unsigned i;
	unsigned start;
	unsigned end;
	tvbuff_t *ds_tvb;

	fis = proto_get_finfo_ptr_array(data->tree, hfid);

	if (fis) {
		for (i = 0; i < fis->len; i++) {
			fi = (field_info*) g_ptr_array_index(fis,i);


			start = fi->start;
			end = fi->start + fi->length;
			ds_tvb = fi->ds_tvb;

			dbg_print(dbg_pdu,5,dbg_facility,"get_pdu_fields: found field %s, %i-%i, length %i", fi->hfinfo->abbrev, start, end, fi->length);

			if (!add_avp(name, fi, fi, data)) {
				/* The field came from a different data source than one of the
				 * ranges (protocol, transport protocol, payload). Search for
				 * the tree node with the field and look to see if one of its
				 * parents is contained within one of the ranges.
				 * (The field, and the hfis for the ranges, were marked as
				 * interesting so this should always work, albeit slower than above.)
				 */
				for (proto_node *pnode = proto_tree_find_node_from_finfo(data->tree, fi);
				     pnode; pnode = pnode->parent) {
					field_info *ancestor_fi = PNODE_FINFO(pnode);
					if (ancestor_fi && ancestor_fi->ds_tvb != ds_tvb) {
						/* Only check anew when the data source changes. */
						ds_tvb = ancestor_fi->ds_tvb;
						if (add_avp(name, fi, ancestor_fi, data)) {
							/* Go to next field in fis */
							break;
						}
					}
				}
			}
		}
	}
}

static mate_pdu* new_pdu(mate_cfg_pdu* cfg, uint32_t framenum, field_info* proto, proto_tree* tree) {
	mate_pdu* pdu = (mate_pdu*)g_slice_new(mate_max_size);
	field_info* cfi;
	GPtrArray* ptrs;
	mate_range* range;
	mate_range* proto_range;
	tmp_pdu_data data;
	unsigned i,j;
	int min_dist;
	field_info* range_fi;
	int32_t last_start;
	int32_t first_end;
	int32_t curr_end;
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
	pdu->time_in_gop = -1.0f;

	pdu->first = false;
	pdu->is_start = false;
	pdu->is_stop = false;
	pdu->after_release = false;

	data.ranges = g_ptr_array_new_with_free_func(g_free);
	data.pdu  = pdu;
	data.tree = tree;

	/* first we create the proto range */
	proto_range = g_new(mate_range, 1);
	proto_range->ds_tvb = proto->ds_tvb;
	proto_range->start = proto->start;
	proto_range->end = proto->start + proto->length;
	g_ptr_array_add(data.ranges,proto_range);

	dbg_print(dbg_pdu,3,dbg_facility,"new_pdu: proto range %u-%u",proto_range->start,proto_range->end);

	last_start = proto_range->start;

	/* we move forward in the transport */
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
				range = (mate_range *)g_malloc(sizeof(*range));
				range->ds_tvb = range_fi->ds_tvb;
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
					range = (mate_range *)g_malloc(sizeof(*range));
					range->ds_tvb = range_fi->ds_tvb;
					range->start = range_fi->start;
					range->end = range_fi->start + range_fi->length;
					g_ptr_array_add(data.ranges,range);

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

	g_ptr_array_free(data.ranges,true);

	return pdu;
}


extern void mate_analyze_frame(mate_config *mc, packet_info *pinfo, proto_tree* tree) {
	mate_cfg_pdu* cfg;
	GPtrArray* protos;
	field_info* proto;
	unsigned i,j;
	AVPL* criterium_match;

	mate_pdu* pdu = NULL;
	mate_pdu* last = NULL;

	rd->now = nstime_to_sec(&pinfo->rel_ts);

	if ( proto_tracking_interesting_fields(tree)
		 && rd->highest_analyzed_frame < pinfo->num ) {
		for ( i = 0; i < mc->pducfglist->len; i++ ) {

			if (i == 0) {
                dbg_print (dbg_pdu,4,dbg_facility,"\nmate_analyze_frame: frame: %i",pinfo->num);
            }
			cfg = (mate_cfg_pdu *)g_ptr_array_index(mc->pducfglist,i);

			dbg_print (dbg_pdu,4,dbg_facility,"mate_analyze_frame: trying to extract: %s",cfg->name);
			protos = proto_get_finfo_ptr_array(tree, cfg->hfid_proto);

			if (protos)  {
				pdu = NULL;

				for (j = 0; j < protos->len; j++) {

					dbg_print (dbg_pdu,3,dbg_facility,"mate_analyze_frame: found matching proto, extracting: %s",cfg->name);

					proto = (field_info*) g_ptr_array_index(protos,j);
					pdu = new_pdu(cfg, pinfo->num, proto, tree);

					if (cfg->criterium) {
						criterium_match = new_avpl_from_match(cfg->criterium_match_mode,"",pdu->avpl,cfg->criterium,false);

						if (criterium_match) {
							delete_avpl(criterium_match,false);
						}

						if ( (criterium_match && cfg->criterium_accept_mode == REJECT_MODE )
							 || ( ! criterium_match && cfg->criterium_accept_mode == ACCEPT_MODE )) {

							delete_avpl(pdu->avpl,true);
							g_slice_free(mate_max_size,(mate_max_size*)pdu);
							pdu = NULL;

							continue;
						}
					}

					analyze_pdu(mc, pdu);

					if ( ! pdu->gop && cfg->drop_unassigned) {
						delete_avpl(pdu->avpl,true);
						g_slice_free(mate_max_size,(mate_max_size*)pdu);
						pdu = NULL;
						continue;
					}

					if ( cfg->discard ) {
						delete_avpl(pdu->avpl,true);
						pdu->avpl = NULL;
					}

					if (!last) {
						g_hash_table_insert(rd->frames,GINT_TO_POINTER(pinfo->num),pdu);
						last = pdu;
					} else {
						last->next_in_frame = pdu;
						last = pdu;
					}

				}

				if ( pdu && cfg->last_extracted ) break;
			}
		}

		rd->highest_analyzed_frame = pinfo->num;
	}
}

extern mate_pdu* mate_get_pdus(uint32_t framenum) {

	if (rd) {
		return (mate_pdu*) g_hash_table_lookup(rd->frames,GUINT_TO_POINTER(framenum));
	} else {
		return NULL;
	}
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
