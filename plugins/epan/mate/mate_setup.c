/* mate_setup.c
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

#include "mate.h"

/* appends the formatted string to the current error log */
static void report_error(mate_config* mc, const gchar* fmt, ...) {
	static gchar error_buffer[DEBUG_BUFFER_SIZE];

	va_list list;

	va_start( list, fmt );
	g_vsnprintf(error_buffer,DEBUG_BUFFER_SIZE,fmt,list);
	va_end( list );

	g_string_append(mc->config_error,error_buffer);
	g_string_append_c(mc->config_error,'\n');

}

/* creates a blank pdu config
     is going to be called only by the grammar
	 which will set all those elements that aren't set here */
extern mate_cfg_pdu* new_pducfg(mate_config* mc, gchar* name) {
	mate_cfg_pdu* cfg = (mate_cfg_pdu *)g_malloc(sizeof(mate_cfg_pdu));

	cfg->name = g_strdup(name);
	cfg->last_id = 0;

	cfg->items = g_hash_table_new(g_direct_hash,g_direct_equal);
	cfg->transforms = NULL;

	cfg->hfid = -1;

	cfg->hfid_pdu_rel_time = -1;
	cfg->hfid_pdu_time_in_gop = -1;

	cfg->my_hfids = g_hash_table_new(g_str_hash,g_str_equal);

	cfg->ett = -1;
	cfg->ett_attr = -1;

	cfg->criterium = NULL;
	cfg->criterium_match_mode = AVPL_NO_MATCH;
	cfg->criterium_accept_mode = ACCEPT_MODE;

	g_ptr_array_add(mc->pducfglist,(gpointer) cfg);
	g_hash_table_insert(mc->pducfgs,(gpointer) cfg->name,(gpointer) cfg);

	cfg->hfids_attr = g_hash_table_new(g_int_hash,g_int_equal);

	return cfg;
}

extern mate_cfg_gop* new_gopcfg(mate_config* mc, gchar* name) {
	mate_cfg_gop* cfg = (mate_cfg_gop *)g_malloc(sizeof(mate_cfg_gop));

	cfg->name = g_strdup(name);
	cfg->last_id = 0;

	cfg->items = g_hash_table_new(g_direct_hash,g_direct_equal);
	cfg->transforms = NULL;

	cfg->extra = new_avpl("extra");

	cfg->hfid = -1;

	cfg->ett = -1;
	cfg->ett_attr = -1;
	cfg->ett_times = -1;
	cfg->ett_children = -1;

	cfg->hfid_start_time = -1;
	cfg->hfid_stop_time = -1;
	cfg->hfid_last_time = -1;

	cfg->hfid_gop_pdu = -1;
	cfg->hfid_gop_num_pdus = -1;

	cfg->my_hfids = g_hash_table_new(g_str_hash,g_str_equal);

	cfg->gop_index = g_hash_table_new(g_str_hash,g_str_equal);
	cfg->gog_index = g_hash_table_new(g_str_hash,g_str_equal);

	g_hash_table_insert(mc->gopcfgs,(gpointer) cfg->name, (gpointer) cfg);

	return cfg;
}

extern mate_cfg_gog* new_gogcfg(mate_config* mc, gchar* name) {
	mate_cfg_gog* cfg = (mate_cfg_gog *)g_malloc(sizeof(mate_cfg_gop));

	cfg->name = g_strdup(name);
	cfg->last_id = 0;

	cfg->items = g_hash_table_new(g_direct_hash,g_direct_equal);
	cfg->transforms = NULL;

	cfg->extra = new_avpl("extra");

	cfg->my_hfids = g_hash_table_new(g_str_hash,g_str_equal);
	cfg->hfid = -1;

	cfg->ett = -1;
	cfg->ett_attr = -1;
	cfg->ett_times = -1;
	cfg->ett_children = -1;
	cfg->ett_gog_gop = -1;

	cfg->hfid_gog_num_of_gops = -1;
	cfg->hfid_gog_gop = -1;
	cfg->hfid_gog_gopstart = -1;
	cfg->hfid_gog_gopstop = -1;

	cfg->hfid_start_time = -1;
	cfg->hfid_stop_time = -1;
	cfg->hfid_last_time = -1;

	g_hash_table_insert(mc->gogcfgs,(gpointer) cfg->name, (gpointer) cfg);

	return cfg;
}

extern gboolean add_hfid(mate_config* mc, header_field_info*  hfi, gchar* how, GHashTable* where) {
	header_field_info*  first_hfi = NULL;
	gboolean exists = FALSE;
	gchar* as;
	gchar* h;
	int* ip;

	while(hfi) {
		first_hfi = hfi;
		hfi = (hfi->same_name_prev_id != -1) ? proto_registrar_get_nth(hfi->same_name_prev_id) : NULL;
	}

	hfi = first_hfi;

	while (hfi) {
		exists = TRUE;
		ip = (int *)g_malloc(sizeof(int));

		*ip = hfi->id;

		if (( as = (gchar *)g_hash_table_lookup(where,ip) )) {
			g_free(ip);
			if (! g_str_equal(as,how)) {
				report_error(mc,
				    "MATE Error: add field to Pdu: attempt to add %s(%i) as %s"
				    " failed: field already added as '%s'",hfi->abbrev,hfi->id,how,as);
				return FALSE;
			}
		} else {
			h = g_strdup(how);
			g_hash_table_insert(where,ip,h);
		}

		hfi = hfi->same_name_next;

	}

	if (! exists) {
		report_error(mc, "MATE Error: cannot find field for attribute %s",how);
	}
	return exists;
}

#if 0
/*
 * XXX - where is this suposed to be used?
 */
extern gchar* add_ranges(mate_config* mc, gchar* range,GPtrArray* range_ptr_arr) {
	gchar**  ranges;
	guint i;
	header_field_info* hfi;
	int* hfidp;

	ranges = g_strsplit(range,"/",0);

	if (ranges) {
		for (i=0; ranges[i]; i++) {
			hfi = proto_registrar_get_byname(ranges[i]);
			if (hfi) {
				hfidp = (int *)g_malloc(sizeof(int));
				*hfidp = hfi->id;
				g_ptr_array_add(range_ptr_arr,(gpointer)hfidp);
			} else {
				g_strfreev(ranges);
				return g_strdup_printf("no such proto: '%s'",ranges[i]);
			}
		}

		g_strfreev(ranges);
	}

	return NULL;
}
#endif

static void new_attr_hfri(mate_config* mc, gchar* item_name, GHashTable* hfids, gchar* name) {
	int* p_id = (int *)g_malloc(sizeof(int));
	hf_register_info hfri;

	memset(&hfri, 0, sizeof hfri);
	*p_id = -1;
	hfri.p_id = p_id;
	hfri.hfinfo.name = g_strdup(name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.%s",item_name,name);
	hfri.hfinfo.type = FT_STRING;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.strings = NULL;
	hfri.hfinfo.bitmask = 0;
	hfri.hfinfo.blurb = g_strdup_printf("%s attribute of %s",name,item_name);

	*p_id = -1;
	g_hash_table_insert(hfids,name,p_id);
	g_array_append_val(mc->hfrs,hfri);

}

typedef struct {
	mate_config* mc;
	mate_cfg_pdu* cfg;
} analyze_pdu_hfids_arg;

static void analyze_pdu_hfids(gpointer k, gpointer v, gpointer p) {
	analyze_pdu_hfids_arg* argp = (analyze_pdu_hfids_arg*)p;
	mate_config* mc = argp->mc;
	mate_cfg_pdu* cfg = argp->cfg;
	new_attr_hfri(mc, cfg->name,cfg->my_hfids,(gchar*) v);

	/*
	 * Add this hfid to our table of wanted hfids.
	 */
	mc->wanted_hfids = g_array_append_val(mc->wanted_hfids, *(int *)k);
	mc->num_fields_wanted++;
}

static void analyze_transform_hfrs(mate_config* mc, gchar* name, GPtrArray* transforms, GHashTable* hfids) {
	guint i;
	void* cookie = NULL;
	AVPL_Transf* t;
	AVP* avp;

	for (i=0; i < transforms->len;i++) {
		for (t = (AVPL_Transf *)g_ptr_array_index(transforms,i); t; t=t->next ) {
			cookie = NULL;
			while(( avp = get_next_avp(t->replace,&cookie) )) {
				if (! g_hash_table_lookup(hfids,avp->n))  {
					new_attr_hfri(mc, name,hfids,avp->n);
				}
			}
		}
	}
}

static void analyze_pdu_config(mate_config* mc, mate_cfg_pdu* cfg) {
	hf_register_info hfri = { NULL, {NULL, NULL, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}};
	gint* ett;
	analyze_pdu_hfids_arg arg;

	hfri.p_id = &(cfg->hfid);
	hfri.hfinfo.name = g_strdup(cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("%s id",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_pdu_rel_time);
	hfri.hfinfo.name = g_strdup_printf("%s time",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.RelativeTime",cfg->name);
	hfri.hfinfo.type = FT_FLOAT;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.blurb = "Seconds passed since the start of capture";

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_pdu_time_in_gop);
	hfri.hfinfo.name = g_strdup_printf("%s time since beginning of Gop",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.TimeInGop",cfg->name);
	hfri.hfinfo.type = FT_FLOAT;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.blurb = "Seconds passed since the start of the GOP";

	g_array_append_val(mc->hfrs,hfri);

	arg.mc = mc;
	arg.cfg = cfg;
	g_hash_table_foreach(cfg->hfids_attr,analyze_pdu_hfids,&arg);

	/* Add the hfids of transport protocols as wanted hfids */
	for (guint i = 0; i < cfg->transport_ranges->len; i++) {
		int hfid = *((int*)g_ptr_array_index(cfg->transport_ranges,i));
		mc->wanted_hfids = g_array_append_val(mc->wanted_hfids, hfid);
		mc->num_fields_wanted++;
	}

	ett = &cfg->ett;
	g_array_append_val(mc->ett,ett);

	ett = &cfg->ett_attr;
	g_array_append_val(mc->ett,ett);

	analyze_transform_hfrs(mc, cfg->name,cfg->transforms,cfg->my_hfids);
}

static void analyze_gop_config(gpointer k _U_, gpointer v, gpointer p) {
	mate_config* mc = (mate_config*)p;
	mate_cfg_gop* cfg = (mate_cfg_gop *)v;
	void* cookie = NULL;
	AVP* avp;
	gint* ett;
	hf_register_info hfri = { NULL, {NULL, NULL, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}};

	hfri.p_id = &(cfg->hfid);
	hfri.hfinfo.name = g_strdup(cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("%s id",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_start_time);
	hfri.hfinfo.name = g_strdup_printf("%s start time",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.StartTime",cfg->name);
	hfri.hfinfo.type = FT_FLOAT;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.blurb = g_strdup_printf("Seconds passed since the beginning of capture to the start of this %s",cfg->name);

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_stop_time);
	hfri.hfinfo.name = g_strdup_printf("%s hold time",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Time",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("Duration in seconds from start to stop of this %s",cfg->name);

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_last_time);
	hfri.hfinfo.name = g_strdup_printf("%s duration",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Duration",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("Time passed between the start of this %s and the last pdu assigned to it",cfg->name);

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gop_num_pdus);
	hfri.hfinfo.name = g_strdup_printf("%s number of PDUs",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.NumOfPdus",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("Number of PDUs assigned to this %s",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gop_pdu);
	hfri.hfinfo.name = g_strdup_printf("A PDU of %s",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Pdu",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("A PDU assigned to this %s",cfg->name);

	if (cfg->pdu_tree_mode == GOP_FRAME_TREE) {
		hfri.hfinfo.type = FT_FRAMENUM;
		hfri.hfinfo.display = BASE_NONE;
		g_array_append_val(mc->hfrs,hfri);
	} else 	if (cfg->pdu_tree_mode == GOP_PDU_TREE) {
		hfri.hfinfo.type = FT_UINT32;
		g_array_append_val(mc->hfrs,hfri);
	} else {
		cfg->pdu_tree_mode = GOP_NO_TREE;
	}

	while(( avp = get_next_avp(cfg->key,&cookie) )) {
		if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
			new_attr_hfri(mc, cfg->name,cfg->my_hfids,avp->n);
		}
	}

	if(cfg->start) {
		cookie = NULL;
		while(( avp = get_next_avp(cfg->start,&cookie) )) {
			if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
				new_attr_hfri(mc, cfg->name,cfg->my_hfids,avp->n);
			}
		}
	}

	if (cfg->stop) {
		cookie = NULL;
		while(( avp = get_next_avp(cfg->stop,&cookie) )) {
			if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
				new_attr_hfri(mc, cfg->name,cfg->my_hfids,avp->n);
			}
		}
	}

	cookie = NULL;
	while(( avp = get_next_avp(cfg->extra,&cookie) )) {
		if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
			new_attr_hfri(mc, cfg->name,cfg->my_hfids,avp->n);
		}
	}

	analyze_transform_hfrs(mc, cfg->name,cfg->transforms,cfg->my_hfids);

	ett = &cfg->ett;
	g_array_append_val(mc->ett,ett);

	ett = &cfg->ett_attr;
	g_array_append_val(mc->ett,ett);

	ett = &cfg->ett_times;
	g_array_append_val(mc->ett,ett);

	ett = &cfg->ett_children;
	g_array_append_val(mc->ett,ett);

	g_hash_table_insert(mc->gops_by_pduname,cfg->name,cfg);
}

static void analyze_gog_config(gpointer k _U_, gpointer v, gpointer p) {
	mate_config* mc = (mate_config*)p;
	mate_cfg_gog* cfg = (mate_cfg_gog *)v;
	void* avp_cookie;
	void* avpl_cookie;
	AVP* avp;
	AVPL* avpl;
	AVPL* gopkey_avpl;
	AVPL* key_avps;
	LoAL* gog_keys = NULL;
	hf_register_info hfri = { NULL, {NULL, NULL, FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}};
	gint* ett;

	/* create the hf array for this gog */
	hfri.p_id = &(cfg->hfid);
	hfri.hfinfo.name = g_strdup(cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("%s Id",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gog_num_of_gops);
	hfri.hfinfo.name = "number of GOPs";
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.NumOfGops",cfg->name);
	hfri.hfinfo.type = FT_UINT32;
	hfri.hfinfo.display = BASE_DEC;
	hfri.hfinfo.blurb = g_strdup_printf("Number of GOPs assigned to this %s",cfg->name);

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gog_gopstart);
	hfri.hfinfo.name = "GopStart frame";
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.GopStart",cfg->name);
	hfri.hfinfo.type = FT_FRAMENUM;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.blurb = g_strdup("The start frame of a GOP");

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_gog_gopstop);
	hfri.hfinfo.name = "GopStop frame";
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.GopStop",cfg->name);
	hfri.hfinfo.type = FT_FRAMENUM;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.blurb = g_strdup("The stop frame of a GOP");

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_start_time);
	hfri.hfinfo.name = g_strdup_printf("%s start time",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.StartTime",cfg->name);
	hfri.hfinfo.type = FT_FLOAT;
	hfri.hfinfo.blurb = g_strdup_printf("Seconds passed since the beginning of capture to the start of this %s",cfg->name);

	g_array_append_val(mc->hfrs,hfri);

	hfri.p_id = &(cfg->hfid_last_time);
	hfri.hfinfo.name = g_strdup_printf("%s duration",cfg->name);
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Duration",cfg->name);
	hfri.hfinfo.blurb = g_strdup_printf("Time passed between the start of this %s and the last pdu assigned to it",cfg->name);

	g_array_append_val(mc->hfrs,hfri);

	/* this might become mate.gogname.gopname */
	hfri.p_id = &(cfg->hfid_gog_gop);
	hfri.hfinfo.name = "a GOP";
	hfri.hfinfo.abbrev = g_strdup_printf("mate.%s.Gop",cfg->name);
	hfri.hfinfo.type = FT_STRING;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.blurb = g_strdup_printf("a GOPs assigned to this %s",cfg->name);

	g_array_append_val(mc->hfrs,hfri);

	/*  index the keys of gog for every gop
		and insert the avps of the keys to the hfarray */
	key_avps = new_avpl("");

	avpl_cookie = NULL;
	while (( avpl = get_next_avpl(cfg->keys,&avpl_cookie) )) {

		if (! ( gog_keys = (LoAL *)g_hash_table_lookup(mc->gogs_by_gopname,avpl->name))) {
			gog_keys = new_loal(avpl->name);
			g_hash_table_insert(mc->gogs_by_gopname,gog_keys->name,gog_keys);
		}

		gopkey_avpl = new_avpl_from_avpl(cfg->name, avpl, TRUE);
		loal_append(gog_keys,gopkey_avpl);

		avp_cookie = NULL;
		while (( avp = get_next_avp(avpl,&avp_cookie) )) {
			if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
				new_attr_hfri(mc, cfg->name,cfg->my_hfids,avp->n);
				insert_avp(key_avps,avp);
			}
		}
	}

	/* insert the extra avps to the hfarray */
	avp_cookie = NULL;
	while (( avp = get_next_avp(cfg->extra,&avp_cookie) )) {
		if (! g_hash_table_lookup(cfg->my_hfids,avp->n))  {
			new_attr_hfri(mc, cfg->name,cfg->my_hfids,avp->n);
		}
	}

	/* every key_avp ios an extra as well.
		one day every Member will have its own extras */
	merge_avpl(cfg->extra,key_avps,TRUE);


	analyze_transform_hfrs(mc, cfg->name,cfg->transforms,cfg->my_hfids);

	ett = &cfg->ett;
	g_array_append_val(mc->ett,ett);

	ett = &cfg->ett_attr;
	g_array_append_val(mc->ett,ett);

	ett = &cfg->ett_children;
	g_array_append_val(mc->ett,ett);

	ett = &cfg->ett_times;
	g_array_append_val(mc->ett,ett);

	ett = &cfg->ett_gog_gop;
	g_array_append_val(mc->ett,ett);

}

static void analyze_config(mate_config* mc) {
	guint i;

	for (i=0; i < mc->pducfglist->len; i++) {
		analyze_pdu_config(mc, (mate_cfg_pdu*) g_ptr_array_index(mc->pducfglist,i));
	}

	g_hash_table_foreach(mc->gopcfgs,analyze_gop_config,mc);
	g_hash_table_foreach(mc->gogcfgs,analyze_gog_config,mc);

}

extern mate_config* mate_make_config(const gchar* filename, int mate_hfid) {
	mate_config* mc;
	gint* ett;
	avp_init();

	mc = (mate_config *)g_malloc(sizeof(mate_config));

	mc->hfid_mate = mate_hfid;

	mc->wanted_hfids = g_array_new(FALSE, FALSE, (guint)sizeof(int));
	mc->num_fields_wanted = 0;

	mc->dbg_facility = NULL;

	mc->mate_lib_path = g_strdup_printf("%s%c%s%c",get_datafile_dir(),DIR_SEP,DEFAULT_MATE_LIB_PATH,DIR_SEP);

	mc->pducfgs = g_hash_table_new(g_str_hash,g_str_equal);
	mc->gopcfgs = g_hash_table_new(g_str_hash,g_str_equal);
	mc->gogcfgs = g_hash_table_new(g_str_hash,g_str_equal);
	mc->transfs = g_hash_table_new(g_str_hash,g_str_equal);

	mc->pducfglist = g_ptr_array_new();
	mc->gops_by_pduname = g_hash_table_new(g_str_hash,g_str_equal);
	mc->gogs_by_gopname = g_hash_table_new(g_str_hash,g_str_equal);

	mc->ett_root = -1;

	mc->hfrs = g_array_new(FALSE,FALSE,sizeof(hf_register_info));
	mc->ett  = g_array_new(FALSE,FALSE,sizeof(gint*));

	mc->defaults.pdu.drop_unassigned = FALSE;
	mc->defaults.pdu.discard = FALSE;
	mc->defaults.pdu.last_extracted = FALSE;
	mc->defaults.pdu.match_mode = AVPL_STRICT;
	mc->defaults.pdu.replace_mode = AVPL_INSERT;

		/* gop prefs */
	mc->defaults.gop.expiration = -1.0f;
	mc->defaults.gop.idle_timeout = -1.0f;
	mc->defaults.gop.lifetime = -1.0f;
	mc->defaults.gop.pdu_tree_mode = GOP_FRAME_TREE;
	mc->defaults.gop.show_times = TRUE;
	mc->defaults.gop.drop_unassigned = FALSE;

		/* gog prefs */
	mc->defaults.gog.expiration = 5.0f;
	mc->defaults.gog.show_times = TRUE;
	mc->defaults.gog.gop_tree_mode = GOP_BASIC_TREE;

	/* what to dbgprint */
	mc->dbg_lvl = 0;
	mc->dbg_pdu_lvl = 0;
	mc->dbg_gop_lvl = 0;
	mc->dbg_gog_lvl = 0;

	mc->config_error = g_string_new("");

	ett = &mc->ett_root;
	g_array_append_val(mc->ett,ett);

	if ( mate_load_config(filename,mc) ) {
		analyze_config(mc);
	} else {
		report_failure("MATE failed to configure!\n"
					   "It is recommended that you fix your config and restart Wireshark.\n"
					   "The reported error is:\n%s\n",mc->config_error->str);

		/* if (mc) destroy_mate_config(mc,FALSE); */
		return NULL;
	}

	if (mc->num_fields_wanted == 0) {
		/* We have no interest in any fields, so we have no
		   work to do. */
		/*destroy_mate_config(mc,FALSE);*/
		return NULL;
	}

	return mc;
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
