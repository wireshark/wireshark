/* mate_setup.c
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

static int* dbg;

static int dbg_cfg_lvl = 1;
static int* dbg_cfg = &dbg_cfg_lvl;

FILE* dbg_facility;

typedef gboolean config_action(AVPL* avpl);

/* the current mate_config */
static mate_config* matecfg = NULL;

/* key: the name of the action
value: a pointer to an config_action */
static GHashTable* actions = NULL;

/* aestetics: I like keywords separated from user attributes */
static AVPL* all_keywords = NULL;

/* use as:  setting = extract_named_xxx(avpl,keyword,default_value); */
static int extract_named_int(AVPL* avpl, guint8* keyword, int value) {
	AVP* avp = NULL;

	if(( avp = extract_avp_by_name(avpl,keyword) )) {
		value = strtol(avp->v,NULL,10);
	}

	return value;
}

static float extract_named_float(AVPL* avpl, guint8* keyword, float value) {
	AVP* avp = NULL;

	if(( avp = extract_avp_by_name(avpl,keyword) )) {
		value = (float) strtod(avp->v,NULL);
	}

	return value;
}

static gboolean extract_named_bool(AVPL* avpl, guint8* keyword, gboolean value) {
	AVP* avp = NULL;
	if(( avp = extract_avp_by_name(avpl,keyword) )) {
		value = ((g_strcasecmp(avp->v,"TRUE") == 0) ? TRUE : FALSE);
	}

	return value;
}

static guint8* extract_named_str(AVPL* avpl, guint8* keyword, guint8* value) {
	AVP* avp = NULL;

	if(( avp = extract_avp_by_name(avpl,keyword) )) {
		value = avp->v;
	}

	return value;
}

/* lookups for the string value of the given named attribute from a given hash  */
static gpointer lookup_using_index_avp(AVPL* avpl, guint8* keyword, GHashTable* table, guint8** avp_value) {
	AVP* avp = extract_avp_by_name(avpl,keyword);

	if (avp) {
		*avp_value = avp->v;
		return g_hash_table_lookup(table,avp->v);
	} else {
		*avp_value = NULL;
		return NULL;
	}
}


/* creates and initializes a mate_cfg_item */
static mate_cfg_item* new_mate_cfg_item(guint8* name) {
	mate_cfg_pdu* new = g_malloc(sizeof(mate_cfg_item));

	new->name = g_strdup(name);
	new->type = MATE_UNK_TYPE;
	new->transforms = g_ptr_array_new();
	new->extra = new_avpl(name);
	new->hfid_proto = -1;
	new->discard_pdu_attributes = matecfg->discard_pdu_attributes;
	new->last_to_be_created = matecfg->last_to_be_created;
	new->drop_pdu = matecfg->drop_pdu;
	new->drop_gop = matecfg->drop_gop;
	new->expiration = matecfg->gog_expiration;
	new->show_pdu_tree = matecfg->show_pdu_tree;
	new->show_gop_times = matecfg->show_gop_times;
	new->last_id = 0;
	new->hfid_ranges = NULL;
	new->hfids_attr = NULL;
	new->criterium = NULL;
	new->start = NULL;
	new->stop = NULL;
	new->key = NULL;
	new->keys = NULL;

	new->hfid = -1;
	new->hfid_pdu_rel_time = -1;
	new->my_hfids = g_hash_table_new(g_str_hash,g_str_equal);
	new->items = g_hash_table_new(g_direct_hash,g_direct_equal);

	new->hfid_gop_pdu = -1;
	new->hfid_gop_start_time = -1;
	new->hfid_gop_stop_time = -1;
	new->hfid_gop_last_time = -1;
	new->hfid_gop_num_pdus = -1;

	new->hfid_gog_num_of_gops = -1;
	new->hfid_gog_gop = -1;

	return new;
}

/* for cleaning hashes */
static gboolean free_both(gpointer k, gpointer v, gpointer p) {
	g_free(k);
	if (p) g_free(v);
	return TRUE;
}

static void delete_mate_cfg_item(mate_cfg_item* cfg, gboolean avp_items_too) {

	g_free(cfg->name);

	if (avp_items_too) {
		if (cfg->extra) delete_avpl(cfg->extra,TRUE);
		if (cfg->start) delete_avpl(cfg->start,TRUE);
		if (cfg->stop)  delete_avpl(cfg->stop,TRUE);
		if (cfg->key)  delete_avpl(cfg->key,TRUE);
		if (cfg->criterium)  delete_avpl(cfg->criterium,TRUE);
		if (cfg->keys) delete_loal(cfg->keys,TRUE,TRUE);
	}

	if (cfg->transforms) g_ptr_array_free(cfg->transforms,TRUE);

	if (cfg->hfid_ranges)
		g_ptr_array_free(cfg->hfid_ranges,TRUE);

	if (cfg->hfids_attr)
		g_hash_table_foreach_remove(cfg->hfids_attr,free_both, VALUE_TOO );

}

static mate_cfg_pdu* new_pducfg(guint8* name) {
	mate_cfg_pdu* new = new_mate_cfg_item(name);

	new->type = MATE_PDU_TYPE;
	new->hfid_ranges = g_ptr_array_new();
	new->hfids_attr = g_hash_table_new(g_int_hash,g_int_equal);

	g_ptr_array_add(matecfg->pducfglist,(gpointer) new);

	g_hash_table_insert(matecfg->pducfgs,(gpointer) new->name,(gpointer) new);

	return new;
}

static mate_cfg_gop* new_gopcfg(guint8* name) {
	mate_cfg_gop* new = new_mate_cfg_item(name);
	new->type = MATE_GOP_TYPE;

	g_hash_table_insert(matecfg->gopcfgs,(gpointer) new->name, (gpointer) new);

	return new;
}

static mate_cfg_gog* new_gogcfg(guint8* name) {
	mate_cfg_gog* new = new_mate_cfg_item(name);
	new->type = MATE_GOG_TYPE;

	new->keys = new_loal(name);
	new->expiration = matecfg->gog_expiration;

	g_hash_table_insert(matecfg->gogcfgs,new->name,new);

	return new;
}

static gboolean free_cfgs(gpointer k _U_, gpointer v, gpointer p) {
	delete_mate_cfg_item((mate_cfg_item*)v,(gboolean) p);
	return TRUE;
}

extern void destroy_mate_config(mate_config* mc , gboolean avplib_too) {
	if (mc->dbg_facility) fclose(mc->dbg_facility);
	if (mc->mate_lib_path) g_free(mc->mate_lib_path);
	if (mc->mate_config_file) g_free(mc->mate_config_file);
	if (mc->mate_attrs_filter) g_string_free(mc->mate_attrs_filter,TRUE);
	if (mc->mate_protos_filter) g_string_free(mc->mate_protos_filter,TRUE);
	if (mc->pducfglist) g_ptr_array_free(mc->pducfglist,FALSE);

	if (mc->gogs_by_gopname) {
		g_hash_table_destroy(mc->gogs_by_gopname);
	}

	if (mc->pducfgs) {
		g_hash_table_foreach_remove(mc->pducfgs,free_cfgs,(gpointer) avplib_too);
		g_hash_table_destroy(mc->pducfgs);
	}

	if (mc->gopcfgs) {
		g_hash_table_foreach_remove(mc->gopcfgs,free_cfgs,(gpointer) avplib_too);
		g_hash_table_destroy(mc->gopcfgs);
	}

	if (mc->gogcfgs) {
		g_hash_table_foreach_remove(mc->gogcfgs,free_cfgs,(gpointer) avplib_too);
		g_hash_table_destroy(mc->gogcfgs);
	}

	if (mc->tap_filter)	g_free(mc->tap_filter);

	if (mc->hfrs) g_array_free(mc->hfrs,TRUE);
	g_free(mc);

}


/* a configuration error */
static void mate_config_error(LoAL* loal _U_ ,guint8* line _U_ , guint8* fmt, ...) {
	va_list list;
	guint8* desc;

	va_start( list, fmt );
	desc = g_strdup_vprintf(fmt, list);
	va_end( list );

	dbg_print (dbg,0,dbg_facility,"mate_config_error: %s",desc);

	g_warning(desc);
	g_free(desc);

}


static gboolean mate_load_config(guint8* filename) {
	LoAL* loal = loal_from_file(filename);
	AVPL* avpl;
	guint8* line = NULL;
	config_action* action;
	guint8* name;

	if (loal) {
	while(( avpl = extract_first_avpl(loal) )) {
		line = avpl_to_str(avpl);

		dbg_print (dbg_cfg,3,dbg_facility,"mate_make_config: current line: %s",line);

		action = lookup_using_index_avp(avpl, KEYWORD_ACTION, actions,&name);

		if (action) {
			if ( ! action(avpl) ) {
				mate_config_error(loal,line,"mate: Error on AVPL: '%s'",name);
				return FALSE;
			}
		} else {
			mate_config_error(loal,line,"mate: Error: action '%s' unknown",name);
			return FALSE;
		}

		g_free(line);
	}

	return TRUE;
	} else {
		g_warning("mate: could not load '%s'",filename);
		return FALSE;
	}
}

static gboolean add_hfid(guint8* what, guint8* how, GHashTable* where) {
	header_field_info*  hfi = NULL;
	header_field_info*  first_hfi = NULL;
	gboolean exists = FALSE;
	guint8* as;
	guint8* h;
	int* ip;

	hfi = proto_registrar_get_byname(what);

	while(hfi) {
		first_hfi = hfi;
		hfi = hfi->same_name_prev;
	}

	hfi = first_hfi;

	while (hfi) {
		exists = TRUE;
		ip = g_malloc(sizeof(int));

		*ip = hfi->id;

		if (( as = g_hash_table_lookup(where,ip) )) {
			g_free(ip);
			if (! g_str_equal(as,how)) {
				g_warning("Error: add_hfid: attempt to add %s(%i) as %s"
						  " failed: hfid already added as '%s'",what,hfi->id,how,as);
				return FALSE;
			}
		} else {
			h = g_strdup(how);
			g_hash_table_insert(where,ip,h);


			dbg_print (dbg,5,dbg_facility,"add_hfid: added hfid %s(%i) as %s",what,*ip,how);
		}

		hfi = hfi->same_name_next;

	}

	if (! exists) {
		g_warning("Error: add_hfid(%s): cannot find",what);
	}

	return exists;
}

static gboolean config_pdu(AVPL* avpl) {
	guint8* name = NULL;
	guint8* transport = extract_named_str(avpl,KEYWORD_TRANSPORT,NULL);
	guint8* proto = extract_named_str(avpl,KEYWORD_PROTO,"no_protocol");
	mate_cfg_pdu* cfg = lookup_using_index_avp(avpl,KEYWORD_NAME,matecfg->pducfgs,&name);
	header_field_info* hfi;
	int* hfidp;
	gchar**  transports;
	guint i;
	AVP* attr_avp;

	if (! cfg) {
		cfg = new_pducfg(name);
	} else {
		g_warning("MATE: PDU Config error: No such PDU: %s",cfg->name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	cfg->last_to_be_created = extract_named_bool(avpl,KEYWORD_STOP,matecfg->last_to_be_created);
	cfg->discard_pdu_attributes = extract_named_bool(avpl,KEYWORD_DISCARDPDU,matecfg->discard_pdu_attributes);
	cfg->drop_pdu = extract_named_bool(avpl,KEYWORD_DROPPDU,matecfg->drop_pdu);

	hfi = proto_registrar_get_byname(proto);

	if (hfi) {
		cfg->hfid_proto = hfi->id;
	} else {
		g_warning("mate: PDU Config error: no such proto: %s",proto);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	g_string_sprintfa(matecfg->mate_protos_filter,"||%s",proto);

	if ( transport ) {

		transports = g_strsplit(transport,"/",0);

		if (transports) {
			for (i=0; transports[i]; i++) {
				hfi = proto_registrar_get_byname(transports[i]);
				if (hfi) {
					hfidp = g_malloc(sizeof(int));
					*hfidp = hfi->id;
					g_ptr_array_add(cfg->hfid_ranges,(gpointer)hfidp);
					g_string_sprintfa(matecfg->mate_attrs_filter, "||%s",transports[i]);
				} else {
					g_warning("mate: PDU Config error: no such proto: %s for Transport",proto);
					g_strfreev(transports);
					delete_avpl(avpl,TRUE);
					return FALSE;
				}
			}

			g_strfreev(transports);
		}
	} else {
		g_warning("mate: PDU Config error: no Transport for %s",cfg->name);
		return FALSE;
	}

	while (( attr_avp = extract_first_avp(avpl) )) {
		if ( ! add_hfid(attr_avp->v,attr_avp->n,cfg->hfids_attr) ) {
			g_warning("mate: PDU Config error: failed to set PDU attribute '%s'",attr_avp->n);
			delete_avpl(avpl,TRUE);
			return FALSE;
		}
		g_string_sprintfa(matecfg->mate_attrs_filter, "||%s",attr_avp->v);
	}

	delete_avpl(avpl,TRUE);
	return TRUE;
}

static gboolean config_pduextra(AVPL* avpl) {
	guint8* name;
	AVP* attr_avp;
	mate_cfg_pdu* cfg = lookup_using_index_avp(avpl,KEYWORD_FOR,matecfg->pducfgs,&name);

	if (! cfg) {
		g_warning("mate: PduExtra Config error: no such Pdu %s",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	cfg->last_to_be_created = extract_named_bool(avpl,KEYWORD_STOP,cfg->last_to_be_created);
	cfg->discard_pdu_attributes = extract_named_bool(avpl,KEYWORD_DISCARDPDU,cfg->discard_pdu_attributes);
	cfg->drop_pdu = extract_named_bool(avpl,KEYWORD_DROPPDU,cfg->drop_pdu);

	while (( attr_avp = extract_first_avp(avpl) )) {
		if ( ! add_hfid(attr_avp->v,attr_avp->n,cfg->hfids_attr) ) {
			g_warning("mate: PDU Config error: failed to set attr %s",attr_avp->n);
			delete_avp(attr_avp);
			delete_avpl(avpl,TRUE);
			return FALSE;
		}
		g_string_sprintfa(matecfg->mate_attrs_filter, "||%s",attr_avp->v);
	}

	delete_avpl(avpl,TRUE);
	return TRUE;

}


static gboolean config_pducriteria(AVPL* avpl) {
	guint8* name;
	mate_cfg_gop* cfg = lookup_using_index_avp(avpl, KEYWORD_FOR,matecfg->pducfgs,&name);
	guint8* match = extract_named_str(avpl, KEYWORD_MATCH, NULL);
	avpl_match_mode match_mode = AVPL_STRICT;
	guint8* mode = extract_named_str(avpl, KEYWORD_MODE, NULL);

	if (!cfg) {
		g_warning("mate: PduCriteria Config error: Pdu %s does not exist",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	if ( mode ) {
		if ( g_strcasecmp(mode,KEYWORD_ACCEPT) == 0 ) {
			mode = matecfg->accept;
		} else if ( g_strcasecmp(mode,KEYWORD_REJECT) == 0 ) {
			mode = matecfg->reject;
		} else {
			g_warning("mate: PduCriteria Config error: no such criteria mode: %s",mode);
			delete_avpl(avpl,TRUE);
			return FALSE;
		}
	} else {
		mode = matecfg->accept;
	}

	rename_avpl(avpl,mode);

	if ( match ) {
		if ( g_strcasecmp(match,KEYWORD_LOOSE) == 0 ) {
			match_mode = AVPL_LOOSE;
		} else if ( g_strcasecmp(match,KEYWORD_EVERY) == 0 ) {
			match_mode = AVPL_EVERY;
		} else if ( g_strcasecmp(match,KEYWORD_STRICT) == 0 ) {
			match_mode = AVPL_STRICT;
		} else {
			g_warning("mate: PduCriteria Config error: no such match mode: %s",match);
			delete_avpl(avpl,TRUE);
			return FALSE;
		}
	}

	cfg->criterium_match_mode = match_mode;

	if (cfg->criterium) {
		/* FEATURE: more criteria */
		g_warning("mate: PduCriteria Config error: PduCriteria alredy exists for %s",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}


	cfg->criterium = avpl;

	return TRUE;
}


static gboolean config_include(AVPL* avpl) {
	guint8* filename = extract_named_str(avpl,KEYWORD_FILENAME,NULL);
	guint8* lib = extract_named_str(avpl,KEYWORD_LIB,NULL);

	if ( ! filename && ! lib ) {
		mate_config_error(NULL,NULL,"mate: Include file error: no Filename or Lib given");
		return FALSE;
	}

	if ( filename && lib ) {
		mate_config_error(NULL,NULL,"mate: Include file error: use either Filename or Lib, not both.");
		return FALSE;
	}

	if (lib) {
		filename = g_strdup_printf("%s%s.mate",matecfg->mate_lib_path,lib);
	}

	/* FIXME: stop recursion */
	if ( ! mate_load_config(filename) ) {
		mate_config_error(NULL,NULL,"mate: Error Loading '%s'",filename);
		if (lib) g_free(filename);
		return FALSE;
	}

	if (lib) g_free(filename);

	return TRUE;
}


static gboolean config_settings(AVPL*avpl) {
	AVP* avp;

#ifdef _AVP_DEBUGGING
	int debug_avp = 0;
	int dbg_avp = 0;
	int dbg_avp_op = 0;
	int dbg_avpl = 0;
	int dbg_avpl_op = 0;
#endif


	matecfg->gog_expiration = extract_named_bool(avpl, KEYWORD_GOGEXPIRE,matecfg->gog_expiration);
	matecfg->discard_pdu_attributes = extract_named_bool(avpl, KEYWORD_DISCARDPDU,matecfg->discard_pdu_attributes);
	matecfg->drop_pdu = extract_named_bool(avpl, KEYWORD_DROPPDU,matecfg->drop_pdu);
	matecfg->drop_gop = extract_named_bool(avpl, KEYWORD_DROPGOP,matecfg->drop_gop);
	matecfg->show_pdu_tree = extract_named_bool(avpl, KEYWORD_SHOWPDUTREE,matecfg->show_pdu_tree);
	matecfg->show_gop_times = extract_named_bool(avpl, KEYWORD_SHOWGOPTIMES,matecfg->show_gop_times);

	if(( avp = extract_avp_by_name(avpl,KEYWORD_DEBUGFILENAME) )) {
		matecfg->dbg_facility = dbg_facility = fopen(avp->v,"w");
		delete_avp(avp);
		avp = NULL;
	}

	matecfg->dbg_lvl = extract_named_int(avpl, KEYWORD_DBG_GENERAL,0);
	matecfg->dbg_cfg_lvl = extract_named_int(avpl, KEYWORD_DBG_CFG,0);
	matecfg->dbg_gop_lvl = extract_named_int(avpl, KEYWORD_DBG_PDU,0);
	matecfg->dbg_gop_lvl = extract_named_int(avpl, KEYWORD_DBG_GOP,0);
	matecfg->dbg_gog_lvl = extract_named_int(avpl, KEYWORD_DBG_GOG,0);

#ifdef _AVP_DEBUGGING
	 setup_avp_debug(dbg_facility,
					 extract_named_int(avpl, KEYWORD_DBG_AVPLIB,0),
					 extract_named_int(avpl, KEYWORD_DBG_AVP,0),
					 extract_named_int(avpl, KEYWORD_DBG_AVP_OP,0),
					 extract_named_int(avpl, KEYWORD_DBG_AVPL,0),
					 extract_named_int(avpl, KEYWORD_DBG_AVPL_OP,0));
#endif

	dbg_cfg_lvl = matecfg->dbg_cfg_lvl;

	return TRUE;
}

static gboolean config_transform(AVPL* avpl) {
	guint8* name = extract_named_str(avpl, KEYWORD_NAME, NULL);
	guint8* match = extract_named_str(avpl, KEYWORD_MATCH, NULL);
	guint8* mode = extract_named_str(avpl, KEYWORD_MODE, NULL);
	avpl_match_mode match_mode;
	avpl_replace_mode replace_mode;
	AVPL_Transf* t;
	AVPL_Transf* last;

	if ( match ) {
		if ( g_strcasecmp(match,KEYWORD_LOOSE) == 0 ) {
			match_mode = AVPL_LOOSE;
		} else if ( g_strcasecmp(match,KEYWORD_EVERY) == 0 ) {
			match_mode = AVPL_EVERY;
		} else if ( g_strcasecmp(match,KEYWORD_STRICT) == 0 ) {
			match_mode = AVPL_STRICT;
		} else {
			g_warning("mate: Transform Config error: no such match mode: %s",match);
			return FALSE;
		}
	} else {
		match_mode = matecfg->match_mode;
	}

	if ( mode ) {
		if ( g_strcasecmp(mode,KEYWORD_INSERT) == 0 ) {
			replace_mode = AVPL_INSERT;
		} else if ( g_strcasecmp(mode,KEYWORD_REPLACE) == 0 ) {
			replace_mode = AVPL_REPLACE;
		} else {
			g_warning("mate: Transform Config error: no such replace mode: %s",mode);
			return FALSE;
		}

	} else {
		replace_mode = matecfg->replace_mode;
	}

	if (! name) {
		g_warning("mate: Transform Config error: no Name");
		return FALSE;
	}

	t = new_avpl_transform(name,avpl, match_mode, replace_mode);

	if (( last = g_hash_table_lookup(matecfg->transfs,name) )) {
		while (last->next) last = last->next;
		last->next = t;
	} else {
		g_hash_table_insert(matecfg->transfs,t->name,t);
	}

	return TRUE;
}

static gboolean config_xxx_transform(AVPL* avpl, GHashTable* hash, guint8* keyword) {
	guint8* pdu_name;
	guint8* name;
	AVPL_Transf* transf = lookup_using_index_avp(avpl,KEYWORD_NAME,matecfg->transfs,&name);
	mate_cfg_pdu* cfg = lookup_using_index_avp(avpl,KEYWORD_FOR,hash,&pdu_name);;

	if (! name ) {
		g_warning("mate: %s Config error: No Name",keyword);
		return FALSE;
	}

	if (! pdu_name ) {
		g_warning("mate: %s Config error: No For",keyword);
		return FALSE;
	}

	if (! cfg ) {
		g_warning("mate: %s Config error: %s doesn't exist",keyword,pdu_name);
		return FALSE;
	}

	if (!transf) {
		g_warning("mate: %s Config error: Transform %s doesn't exist",keyword,name);
		return FALSE;
	}

	g_ptr_array_add(cfg->transforms,transf);

	return TRUE;
}

static gboolean config_pdu_transform(AVPL* avpl) {
	return config_xxx_transform(avpl, matecfg->pducfgs, KEYWORD_PDUTRANSFORM);
}

static gboolean config_gop_transform(AVPL* avpl) {
	return config_xxx_transform(avpl, matecfg->gopcfgs, KEYWORD_GOPTRANSFORM);
}

static gboolean config_gog_transform(AVPL* avpl) {
	return config_xxx_transform(avpl, matecfg->gogcfgs, KEYWORD_GOPTRANSFORM);
}

static gboolean config_gop(AVPL* avpl) {
	guint8* name = NULL;
	mate_cfg_gop* cfg = lookup_using_index_avp(avpl, KEYWORD_NAME,matecfg->gopcfgs,&name);
	guint8* on = extract_named_str(avpl,KEYWORD_ON,NULL);

	if (!cfg) {
		cfg = new_gopcfg(name);
	} else {
		g_warning("mate: GopDef Config error: Gop '%s' exists already",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	if (! on ) {
		g_warning("mate: GopDef Config error: No 'On' AVP");
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	if (g_hash_table_lookup(matecfg->gops_by_pduname,on) ) {
		g_warning("mate: GopDef Config error: Gop for Pdu '%s' exists already",on);
		delete_avpl(avpl,TRUE);
		return FALSE;
	} else {
		g_hash_table_insert(matecfg->gops_by_pduname,on,cfg);
	}

	cfg->drop_gop = extract_named_bool(avpl, KEYWORD_DROPGOP,matecfg->drop_gop);
	cfg->show_pdu_tree = extract_named_bool(avpl, KEYWORD_SHOWPDUTREE, matecfg->show_pdu_tree);
	cfg->show_gop_times = extract_named_bool(avpl, KEYWORD_SHOWGOPTIMES,matecfg->show_gop_times);

	cfg->key = avpl;

	return TRUE;
}

static gboolean config_start(AVPL* avpl) {
	guint8* name;
	mate_cfg_gop* cfg = lookup_using_index_avp(avpl, KEYWORD_FOR,matecfg->gopcfgs,&name);;

	if (!cfg) {
		g_warning("mate: GopStart Config error: Gop %s does not exist",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	if (cfg->start) {
		/* FEATURE: more start conditions */
		g_warning("mate: GopStart Config error: GopStart alredy exists for %s",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	cfg->start = avpl;

	return TRUE;
}

static gboolean config_stop(AVPL* avpl) {
	guint8* name;
	mate_cfg_gop* cfg = lookup_using_index_avp(avpl, KEYWORD_FOR,matecfg->gopcfgs,&name);;

	if (!cfg) {
		g_warning("mate: GopStop Config error: Gop %s does not exist",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	if (cfg->stop) {
		/* FEATURE: more GopStop conditions */
		g_warning("mate: GopStart Config error: GopStop alredy exists for %s",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	cfg->stop = avpl;

	return TRUE;
}

static gboolean config_gopextra(AVPL* avpl) {
	guint8* name;
	mate_cfg_gop* cfg = lookup_using_index_avp(avpl, KEYWORD_FOR,matecfg->gopcfgs,&name);;

	if (!cfg) {
		g_warning("mate: GopExtra Config error: Gop %s does not exist",name);
		delete_avpl(avpl,TRUE);
		return FALSE;
	}

	cfg->drop_gop = extract_named_bool(avpl, KEYWORD_DROPGOP,cfg->drop_gop);
	cfg->show_pdu_tree = extract_named_bool(avpl, KEYWORD_SHOWPDUTREE, cfg->show_pdu_tree);
	cfg->show_gop_times = extract_named_bool(avpl, KEYWORD_SHOWGOPTIMES,cfg->show_gop_times);

	merge_avpl(cfg->extra,avpl,TRUE);

	delete_avpl(avpl,TRUE);
	return TRUE;
}

static gboolean config_gog(AVPL* avpl) {
	guint8* name = extract_named_str(avpl, KEYWORD_NAME,NULL);
	mate_cfg_gog* cfg = NULL;

	if (!name) {
		g_warning("mate: GogDef Config error: no Name");
		return FALSE;
	}

	if ( g_hash_table_lookup(matecfg->gogcfgs,name) ) {
		g_warning("mate: GogDef Config error: Gog %s exists already", name);
		return FALSE;
	}

	cfg = new_gogcfg(name);

	cfg->expiration = extract_named_float(avpl, KEYWORD_GOGEXPIRE,matecfg->gog_expiration);

	return TRUE;
}

static gboolean config_gogkey(AVPL* avpl) {
	guint8* name;
	mate_cfg_gog* cfg = lookup_using_index_avp(avpl, KEYWORD_FOR,matecfg->gogcfgs,&name);
	AVPL* reverse_avpl;
	LoAL* gogkeys;
	guint8* on = extract_named_str(avpl,KEYWORD_ON,NULL);

	if ( ! name || ! cfg ) {
		if ( ! name )
			g_warning("mate: GogKey Config error: no Name");
		else
			g_warning("mate: GogKey Config error: no such Gop %s",name);

		return FALSE;
	}

	if (! on ) {
		g_warning("mate: GogKey Config error: no " KEYWORD_ON);
		return FALSE;
	}

	rename_avpl(avpl,name);

	gogkeys = (LoAL*) g_hash_table_lookup(matecfg->gogs_by_gopname,on);

	if (! gogkeys) {
		gogkeys = new_loal("straight");
		g_hash_table_insert(matecfg->gogs_by_gopname,g_strdup(on),gogkeys);
	}

	loal_append(gogkeys,avpl);

	reverse_avpl = new_avpl_from_avpl(on,avpl,TRUE);

	loal_append(cfg->keys,reverse_avpl);

	return TRUE;
}

static gboolean config_gogextra(AVPL* avpl) {
	guint8* name;
	mate_cfg_gop* cfg = lookup_using_index_avp(avpl, KEYWORD_FOR,matecfg->gogcfgs,&name);

	if ( ! name || ! cfg ) {
		if ( ! name )
			g_warning("mate: GogExtra Config error: no Name");
		else
			g_warning("mate: GogExtra Config error: no such Gop %s",name);

		return FALSE;
	}

	cfg->expiration = extract_named_float(avpl, KEYWORD_GOGEXPIRE,cfg->expiration);

	merge_avpl(cfg->extra,avpl,TRUE);

	delete_avpl(avpl,TRUE);
	return TRUE;
}


static void print_xxx_transforms(mate_cfg_item* cfg) {
	guint8* tr_name;
	guint8* cfg_name;
	guint i;

	switch (cfg->type) {
		case MATE_PDU_TYPE:
			cfg_name = "PduTransform";
			break;
		case MATE_GOP_TYPE:
			cfg_name = "GopTransform";
			break;
		case MATE_GOG_TYPE:
			cfg_name = "GogTransform";
			break;
		default:
			cfg_name = "UnknownTransform";
			break;
	}

	for (i=0; i < cfg->transforms->len; i++) {
		tr_name = ((AVPL_Transf*) g_ptr_array_index(cfg->transforms,i))->name;
		dbg_print (dbg_cfg,0,dbg_facility,"Action=%s; For=%s; Name=%s;\n",cfg_name,cfg->name,tr_name);
	}

}

static void print_gog_config(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_cfg_gop* cfg = (mate_cfg_gop*) v;
	guint8* avplstr = NULL;
	void* cookie = NULL;
	AVPL* avpl;

	dbg_print (dbg_cfg,0,dbg_facility,"Action=GogDef; Name=%s; Expiration=%f;\n",cfg->name,cfg->expiration);

	if (cfg->keys) {
		while (( avpl = get_next_avpl(cfg->keys,&cookie) )) {
			avplstr = avpl_to_str(avpl);
			dbg_print (dbg_cfg,0,dbg_facility,"Action=GogKey; For=%s; On=%s; %s\n",cfg->name,avpl->name,avplstr);
			g_free(avplstr);
		}
	}

	if (cfg->extra) {
		avplstr = avpl_to_str(cfg->extra);
		dbg_print (dbg_cfg,0,dbg_facility,"Action=GogExtra; For=%s; %s\n",cfg->name,avplstr);
		g_free(avplstr);
	}

	print_xxx_transforms(cfg);

}



static void print_gop_config(gpointer k _U_ , gpointer v, gpointer p _U_) {
	mate_cfg_gop* cfg = (mate_cfg_gop*) v;
	guint8* avplstr = NULL;
	guint8* show_pdu_tree;
	GString* gopdef;

	gopdef = g_string_new("Action=GopDef; ");

	show_pdu_tree = cfg->show_pdu_tree ? "TRUE" : "FALSE";
	g_string_sprintfa(gopdef,"Name=%s; ShowPduTree=%s;",cfg->name,show_pdu_tree);

	if (cfg->key) {
		avplstr = avpl_to_str(cfg->key);
		g_string_sprintfa(gopdef," %s",avplstr);
		g_free(avplstr);
	}

	dbg_print (dbg_cfg,0,dbg_facility,"%s\n",gopdef->str);


	if (cfg->start) {
		avplstr = avpl_to_str(cfg->start);
		dbg_print (dbg_cfg,0,dbg_facility,"Action=GopStart; For=%s; %s\n",cfg->name,avplstr);
		g_free(avplstr);
	}

	if (cfg->stop) {
		avplstr = avpl_to_str(cfg->stop);
		dbg_print (dbg_cfg,0,dbg_facility,"Action=GopStop; For=%s; %s\n",cfg->name,avplstr);
		g_free(avplstr);
	}

	if (cfg->extra) {
		avplstr = avpl_to_str(cfg->extra);
		dbg_print (dbg_cfg,0,dbg_facility,"Action=GopExtra; For=%s;  %s\n",cfg->name,avplstr);
		g_free(avplstr);
	}

	print_xxx_transforms(cfg);

	g_string_free(gopdef,TRUE);

}

static guint8* my_protoname(int proto_id) {
	if (proto_id) {
		return proto_registrar_get_abbrev(proto_id);
	} else {
		return "*";
	}
}

static void print_hfid_hash(gpointer k, gpointer v, gpointer p _U_) {
	g_string_sprintfa((GString*)p," %s=%s;",(guint8*)v,my_protoname(*(int*)k));
}


static void print_transforms(gpointer k, gpointer v, gpointer p _U_) {
	AVPL_Transf* t = NULL;
	guint8* match;
	guint8* mode;
	guint8* match_s;
	guint8* replace_s;

	for (t = v; t; t = t->next) {
		match_s =  avpl_to_str(t->match);
		replace_s = avpl_to_dotstr(t->replace);

		switch (t->match_mode) {
			case AVPL_STRICT:
				match = "Strict";
				break;
			case AVPL_LOOSE:
				match = "Loose";
				break;
			case AVPL_EVERY:
				match = "Every";
				break;
			default:
				match = "None";
				break;
		}

		switch (t->replace_mode) {
			case AVPL_INSERT:
				mode = "Insert";
				break;
			case AVPL_REPLACE:
				mode = "Replace";
				break;
			default:
				mode = "None";
				break;
		}

		dbg_print (dbg,0,dbg_facility,"\tAction=Transform; Name=%s; Match=%s; Mode=%s; %s %s\n",(guint8*) k,match,mode,match_s,replace_s);

		g_free(match_s);
		g_free(replace_s);
	}
}

static void print_pdu_config(mate_cfg_pdu* cfg) {
	guint i;
	int hfid;
	guint8* discard;
	guint8* stop;
	guint8* criterium_match = NULL;
	guint8* criterium;
	GString* s = g_string_new("Action=PduDef; ");

	discard = cfg->discard_pdu_attributes ? "TRUE": "FALSE";
	stop = cfg->last_to_be_created ? "TRUE" : "FALSE";

	g_string_sprintfa(s, "Name=%s; Proto=%s; DiscartAttribs=%s; Stop=%s;  Transport=",
					  cfg->name,my_protoname(cfg->hfid_proto),discard,stop);

	for (i = 0; i < cfg->hfid_ranges->len; i++) {
		hfid = *((int*) g_ptr_array_index(cfg->hfid_ranges,i));
		g_string_sprintfa(s,"%s/",my_protoname(hfid));
	}

	*(s->str + s->len - 1) = ';';

	g_hash_table_foreach(cfg->hfids_attr,print_hfid_hash,s);

	dbg_print(dbg_cfg,0,dbg_facility,"%s",s->str);

	if (cfg->criterium) {
		switch(cfg->criterium_match_mode) {
			case AVPL_NO_MATCH:
				criterium_match = "None";
				break;
			case AVPL_STRICT:
				criterium_match = "Strict";
				break;
			case AVPL_LOOSE:
				criterium_match = "Loose";
				break;
			case AVPL_EVERY:
				criterium_match = "Every";
				break;
		}

		criterium = avpl_to_str(cfg->criterium);

		dbg_print(dbg_cfg,0,dbg_facility,
				  "Action=PduCriteria; For=%s; Match=%s; Mode=%s;  %s",
				  cfg->name,criterium_match,cfg->criterium->name,criterium);

		g_free(criterium);
	}

	print_xxx_transforms(cfg);

	g_string_free(s,TRUE);
}



static void print_gogs_by_gopname(gpointer k, gpointer v, gpointer p _U_) {
	void* cookie = NULL;
	guint8* str = NULL;
	AVPL* avpl;

	while(( avpl = get_next_avpl((LoAL*)v,&cookie) )) {
		str = avpl_to_str(avpl);
		dbg_print(dbg_cfg,0,dbg_facility,"Gop=%s; Gog=%s; --> %s\n",(guint8*)k,avpl->name,str);
		g_free(str);
	}

}

static void print_gops_by_pduname(gpointer k, gpointer v, gpointer p _U_) {
	dbg_print(dbg_cfg,0,dbg_facility,
			  "PduName=%s; GopName=%s;\n", (guint8*)k,((mate_cfg_gop*)v)->name);
}

static void print_config() {
	guint i;

	/* FIXME: print the settings */

	dbg_print(dbg_cfg,0,dbg_facility,"###########################"
			  " CURRENT CONFIGURATION " "###########################");

	g_hash_table_foreach(matecfg->transfs,print_transforms,NULL);

	for (i=0; i<matecfg->pducfglist->len; i++) {
		print_pdu_config((mate_cfg_pdu*) g_ptr_array_index(matecfg->pducfglist,i));
	}

	g_hash_table_foreach(matecfg->gopcfgs,print_gop_config,NULL);
	g_hash_table_foreach(matecfg->gogcfgs,print_gog_config,NULL);

	dbg_print(dbg_cfg,0,dbg_facility,"###########################"
			  " END OF CURRENT CONFIGURATION " "###########################");

	if (*dbg_cfg > 1) {
		dbg_print(dbg_cfg,0,dbg_facility,"******* Config Hashes");
		dbg_print(dbg_cfg,0,dbg_facility,"*** Gops by PduName");
		g_hash_table_foreach(matecfg->gops_by_pduname,print_gops_by_pduname,NULL);
		dbg_print(dbg_cfg,0,dbg_facility,"*** GogKeys by GopName");
		g_hash_table_foreach(matecfg->gogs_by_gopname,print_gogs_by_gopname,NULL);
	}
}


static void new_attr_hfri(mate_cfg_item* cfg, guint8* name) {
	int* p_id = g_malloc(sizeof(int));

	hf_register_info hfri = {
		p_id,
	{
		g_strdup_printf("%s",name),
		g_strdup_printf("mate.%s.%s",cfg->name,name),
		FT_STRING,BASE_NONE,NULL,0,
		g_strdup_printf("%s attribute of %s",name,cfg->name),HFILL
	}};

	*p_id = -1;
	g_hash_table_insert(cfg->my_hfids,name,p_id);
	g_array_append_val(matecfg->hfrs,hfri);

}

static void analyze_pdu_hfids(gpointer k _U_, gpointer v, gpointer p) {
	new_attr_hfri((mate_cfg_pdu*) p,(guint8*) v);
}

static void analyze_transform_hfrs(mate_cfg_item* cfg) {
	guint i;
	void* cookie = NULL;
	AVPL_Transf* t;
	AVP* avp;

	for (i=0; i < cfg->transforms->len;i++) {
		for (t = g_ptr_array_index(cfg->transforms,i); t; t=t->next ) {
			cookie = NULL;
			while(( avp = get_next_avp(t->replace,&cookie) )) {
				if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
					new_attr_hfri(cfg,avp->n);
				}
			}
		}
	}
}

static void analyze_pdu_config(mate_cfg_pdu* cfg) {
	hf_register_info hfri = { NULL, {NULL, NULL, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}};

	hfri.p_id = &(cfg->hfid);
	hfri.hfinfo.name = g_strdup_printf("%s",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("%s id",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;

	g_array_append_val(matecfg->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_pdu_rel_time);
	hfri.hfinfo.name = g_strdup_printf("%s time",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.RelativeTime",cfg->name);
	hfri.hfinfo.type = FT_FLOAT;
	hfri.hfinfo.display = BASE_DEC;
	hfri.hfinfo.blurb = "Seconds passed since the start of the GOP or capture if the PDU is unnassigned";

	g_array_append_val(matecfg->hfrs,hfri);

	g_hash_table_foreach(cfg->hfids_attr,analyze_pdu_hfids,cfg);

	analyze_transform_hfrs(cfg);
}

static void analyze_gop_config(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_cfg_gop* cfg = v;
	void* cookie = NULL;
	AVP* avp;
	hf_register_info hfri = { NULL, {NULL, NULL, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}};

	hfri.p_id = &(cfg->hfid);
	hfri.hfinfo.name = g_strdup_printf("%s",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("%s id",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;

	g_array_append_val(matecfg->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gop_start_time);
	hfri.hfinfo.name = g_strdup_printf("%s start time",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.StartTime",cfg->name);
	hfri.hfinfo.type = FT_FLOAT;
	hfri.hfinfo.display = BASE_DEC;
	hfri.hfinfo.blurb = g_strdup_printf("Seconds passed since the begining of caputre to the start of this %s",cfg->name);

	g_array_append_val(matecfg->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gop_stop_time);
	hfri.hfinfo.name = g_strdup_printf("%s hold time",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Time",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("Duration in seconds from start to stop of this %s",cfg->name);

	g_array_append_val(matecfg->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gop_last_time);
	hfri.hfinfo.name = g_strdup_printf("%s current time",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Duration",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("Time passed between the start of this %s and the last pdu assigned to it",cfg->name);

	g_array_append_val(matecfg->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gop_num_pdus);
	hfri.hfinfo.name = g_strdup_printf("%s number of PDUs",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.NumOfPdus",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("Number of PDUs assigned to this %s",cfg->name);
	hfri.hfinfo.type = FT_UINT32;

	g_array_append_val(matecfg->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gop_pdu);
	hfri.hfinfo.name = g_strdup_printf("A PDU of %s",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Pdu",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("A PDU assigned to this %s",cfg->name);
	hfri.hfinfo.type = FT_FRAMENUM;

	g_array_append_val(matecfg->hfrs,hfri);

	while(( avp = get_next_avp(cfg->key,&cookie) )) {
		if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
			new_attr_hfri(cfg,avp->n);
		}
	}

	cookie = NULL;
	while(( avp = get_next_avp(cfg->start,&cookie) )) {
		if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
			new_attr_hfri(cfg,avp->n);
		}
	}

	cookie = NULL;
	while(( avp = get_next_avp(cfg->stop,&cookie) )) {
		if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
			new_attr_hfri(cfg,avp->n);
		}
	}

	cookie = NULL;
	while(( avp = get_next_avp(cfg->extra,&cookie) )) {
		if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
			new_attr_hfri(cfg,avp->n);
		}
	}

	analyze_transform_hfrs(cfg);
}


static void analyze_gog_config(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_cfg_gop* cfg = v;
	void* avp_cookie;
	void* avpl_cookie;
	AVP* avp;
	AVPL* avpl;
	hf_register_info hfri = { NULL, {NULL, NULL, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}};

	hfri.p_id = &(cfg->hfid);
	hfri.hfinfo.name = g_strdup_printf("%s",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("%s Id",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;

	g_array_append_val(matecfg->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gog_num_of_gops);
	hfri.hfinfo.name = "number of GOPs";
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.NumOfGops",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;
	hfri.hfinfo.blurb = g_strdup_printf("Number of GOPs assigned to this %s",cfg->name);

	g_array_append_val(matecfg->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gog_gop);
	hfri.hfinfo.name = "a GOP";
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Gop",cfg->name);
	hfri.hfinfo.type = FT_STRING;
	hfri.hfinfo.display = BASE_DEC;
	hfri.hfinfo.blurb = g_strdup_printf("a GOPs assigned to this %s",cfg->name);

	g_array_append_val(matecfg->hfrs,hfri);

	avpl_cookie = NULL;
	while (( avpl = get_next_avpl(cfg->keys,&avpl_cookie) )) {
		avp_cookie = NULL;
		while (( avp = get_next_avp(avpl,&avp_cookie) )) {
			if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
				new_attr_hfri(cfg,avp->n);
			}
		}
	}

	avp_cookie = NULL;
	while (( avp = get_next_avp(cfg->extra,&avp_cookie) )) {
		if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
			new_attr_hfri(cfg,avp->n);
		}
	}

	analyze_transform_hfrs(cfg);
}

static size_t analyze_config() {
	guint i;

	for (i=0; i<matecfg->pducfglist->len; i++) {
		analyze_pdu_config((mate_cfg_pdu*) g_ptr_array_index(matecfg->pducfglist,i));
	}

	g_hash_table_foreach(matecfg->gopcfgs,analyze_gop_config,matecfg);
	g_hash_table_foreach(matecfg->gogcfgs,analyze_gog_config,matecfg);

}

static void new_action(guint8* name, config_action* action) {
	g_hash_table_insert(actions,name,action);

}

static void init_actions() {
	AVP* avp;

	all_keywords = new_avpl("all_keywords");

	insert_avp(all_keywords,new_avp(KEYWORD_ACTION,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_SETTINGS,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_INCLUDE,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_TRANSFORM,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_PDU,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_PDUCRITERIA,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_PDUEXTRA,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_PDUTRANSFORM,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOP,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOPSTART,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOPSTOP,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOPEXTRA,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOPTRANSFORM,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOGDEF,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOGKEY,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOGEXTRA,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOGTRANSFORM,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_NAME,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_ON,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_FOR,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_FROM,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_TO,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_MATCH,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_MODE,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_FILENAME,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_PROTO,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_METHOD,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_TRANSPORT,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_METHOD,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_STRICT,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_LOOSE,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_EVERY,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_REPLACE,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_INSERT,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_MAP,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_GOGEXPIRE,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DISCARDPDU,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_LIBPATH,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_SHOWPDUTREE,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_SHOWGOPTIMES,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_STOP,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DROPPDU,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DROPGOP,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_LIB,"",'='));

	insert_avp(all_keywords,new_avp(KEYWORD_DBG_GENERAL,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_CFG,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_PDU,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_GOP,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_GOG,"",'='));

#ifdef _AVP_DEBUGGING
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_AVPLIB,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_AVP,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_AVP_OP,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_AVPL,"",'='));
	insert_avp(all_keywords,new_avp(KEYWORD_DBG_AVPL_OP,"",'='));
#endif

	avp = new_avp(KEYWORD_ACCEPT,"",'=');
	matecfg->accept = avp->n;
	insert_avp(all_keywords,avp);

	avp = new_avp(KEYWORD_REJECT,"",'=');
	matecfg->reject = avp->n;
	insert_avp(all_keywords,avp);


	if (actions) {
		g_hash_table_destroy(actions);
	}

	actions = g_hash_table_new(g_str_hash,g_str_equal);

	new_action(KEYWORD_SETTINGS,config_settings);
	new_action(KEYWORD_PDU,config_pdu);
	new_action(KEYWORD_PDUEXTRA,config_pduextra);
	new_action(KEYWORD_PDUCRITERIA,config_pducriteria);
	new_action(KEYWORD_GOP,config_gop);
	new_action(KEYWORD_GOGDEF,config_gog);
	new_action(KEYWORD_GOGKEY,config_gogkey);
	new_action(KEYWORD_GOPSTART,config_start);
	new_action(KEYWORD_GOPSTOP,config_stop);
	new_action(KEYWORD_GOPEXTRA,config_gopextra);
	new_action(KEYWORD_GOGEXTRA,config_gogextra);
	new_action(KEYWORD_INCLUDE,config_include);
	new_action(KEYWORD_TRANSFORM,config_transform);
	new_action(KEYWORD_PDUTRANSFORM,config_pdu_transform);
	new_action(KEYWORD_GOPTRANSFORM,config_gop_transform);
	new_action(KEYWORD_GOGTRANSFORM,config_gog_transform);

}

void reset_cfg(gpointer k _U_, gpointer v, gpointer p _U_) {
	mate_cfg_item* c = v;
	c->last_id = 0;
}

extern mate_config* mate_cfg() {

	g_hash_table_foreach(matecfg->pducfgs,reset_cfg,NULL);
	g_hash_table_foreach(matecfg->gopcfgs,reset_cfg,NULL);
	g_hash_table_foreach(matecfg->gogcfgs,reset_cfg,NULL);

	return matecfg;
}

extern mate_config* mate_make_config(guint8* filename) {

	avp_init();

	matecfg = g_malloc(sizeof(mate_config));

	matecfg->gog_expiration = DEFAULT_GOG_EXPIRATION;
	matecfg->discard_pdu_attributes = FALSE;
	matecfg->drop_pdu = FALSE;
	matecfg->drop_gop = FALSE;
	matecfg->show_pdu_tree = TRUE;
	matecfg->show_gop_times = TRUE;
	matecfg->last_to_be_created = FALSE;
	matecfg->match_mode = AVPL_STRICT;
	matecfg->replace_mode = AVPL_INSERT;
	matecfg->mate_lib_path = g_strdup_printf("%s%c%s%c",get_datafile_dir(),DIR_SEP,DEFAULT_MATE_LIB_PATH,DIR_SEP);
	matecfg->mate_config_file = g_strdup(filename);
	matecfg->mate_attrs_filter = g_string_new("");
	matecfg->mate_protos_filter = g_string_new("");
	matecfg->dbg_facility = NULL;
	matecfg->dbg_lvl = 0;
	matecfg->dbg_cfg_lvl = 0;
	matecfg->dbg_pdu_lvl = 0;
	matecfg->dbg_gop_lvl = 0;
	matecfg->dbg_gog_lvl = 0;
	matecfg->pducfglist = g_ptr_array_new();
	matecfg->pducfgs = g_hash_table_new(g_str_hash,g_str_equal);
	matecfg->gopcfgs = g_hash_table_new(g_str_hash,g_str_equal);
	matecfg->gogcfgs = g_hash_table_new(g_str_hash,g_str_equal);
	matecfg->transfs = g_hash_table_new(g_str_hash,g_str_equal);
	matecfg->gops_by_pduname = g_hash_table_new(g_str_hash,g_str_equal);
	matecfg->gogs_by_gopname = g_hash_table_new(g_str_hash,g_str_equal);

	matecfg->hfrs = g_array_new(FALSE,TRUE,sizeof(hf_register_info));

	dbg = &matecfg->dbg_lvl;

	init_actions();

	if ( mate_load_config(filename) ) {
		analyze_config();
		dbg_print (dbg_cfg,3,dbg_facility,"mate_make_config: OK");
		if (dbg_cfg_lvl > 0) print_config();
	} else {
		if (matecfg) destroy_mate_config(matecfg,FALSE);
		matecfg = NULL;
		return NULL;
	}

	if (matecfg->mate_attrs_filter->len > 1) {
		g_string_erase(matecfg->mate_attrs_filter,0,2);
		g_string_erase(matecfg->mate_protos_filter,0,2);
	} else {
		mate_config_error(NULL,NULL,"mate: Failed: nothing left to tap on");
		destroy_mate_config(matecfg,FALSE);
		matecfg = NULL;
		return NULL;
	}

	matecfg->tap_filter = g_strdup_printf("(%s) && (%s)",matecfg->mate_protos_filter->str,matecfg->mate_attrs_filter->str);

	return matecfg;
}

