/* mate.h
 * MATE -- Meta Analysis and Tracing Engine
 *
 * Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __MATE_H_
#define __MATE_H_

#define WS_LOG_DOMAIN "MATE"
#include <wireshark.h>

#include <gmodule.h>

#include <stdio.h>
#include <string.h>

#include <wsutil/report_message.h>
#include <wsutil/wslog.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <wsutil/filesystem.h>

#include "mate_util.h"

/* defaults */

#define DEFAULT_GOG_EXPIRATION 2.0

#ifdef _WIN32
#define DIR_SEP '\\'
#else
#define DIR_SEP '/'
#endif

#define DEFAULT_MATE_LIB_PATH "matelib"

#define MATE_ITEM_ID_SIZE 24

#define VALUE_TOO ((void*)1)

#define MateConfigError 65535

typedef enum _gop_tree_mode_t {
	GOP_NULL_TREE,
	GOP_BASIC_TREE,
	GOP_FULL_TREE
} gop_tree_mode_t;

typedef enum _gop_pdu_tree {
	GOP_NO_TREE,
	GOP_PDU_TREE,
	GOP_FRAME_TREE,
	GOP_BASIC_PDU_TREE
} gop_pdu_tree_t;

typedef enum _accept_mode_t {
	ACCEPT_MODE,
	REJECT_MODE
} accept_mode_t;


typedef struct _mate_cfg_pdu {
	char* name;
	unsigned last_id; /* keeps the last id given to an item of this kind */

	GHashTable* items; /* all the items of this type */
	GPtrArray* transforms; /* transformations to be applied */

	int hfid;

	int hfid_proto;
	int hfid_pdu_rel_time;
	int hfid_pdu_time_in_gop;

	GHashTable* my_hfids; /* for creating register info */

	int ett;
	int ett_attr;

	GHashTable* hfids_attr; /* k=hfid v=avp_name */

	bool discard;
	bool last_extracted;
	bool drop_unassigned;

	GPtrArray* transport_ranges; /* hfids of candidate transport ranges from which to extract attributes */
	GPtrArray* payload_ranges; /* hfids of candidate payload ranges from which to extract attributes */

	avpl_match_mode criterium_match_mode;
	accept_mode_t criterium_accept_mode;
	AVPL* criterium;
} mate_cfg_pdu;


typedef struct _mate_cfg_gop {
	char* name;
	unsigned last_id; /* keeps the last id given to an item of this kind */
	GHashTable* items; /* all the items of this type */

	GPtrArray* transforms; /* transformations to be applied */
	char* on_pdu;

	AVPL* key; /* key candidate avpl */
	AVPL* start; /* start candidate avpl */
	AVPL* stop;  /* stop candidate avpl */
	AVPL* extra; /* attributes to be added */

	double expiration;
	double idle_timeout;
	double lifetime;

	bool drop_unassigned;
	gop_pdu_tree_t pdu_tree_mode;
	bool show_times;

	GHashTable* my_hfids; /* for creating register info */
	int hfid;
	int hfid_start_time;
	int hfid_stop_time;
	int hfid_last_time;
	int hfid_gop_pdu;
	int hfid_gop_num_pdus;

	int ett;
	int ett_attr;
	int ett_times;
	int ett_children;

	GHashTable* gop_index;
	GHashTable* gog_index;
} mate_cfg_gop;


typedef struct _mate_cfg_gog {
	char* name;

	GHashTable* items; /* all the items of this type */
	unsigned last_id; /* keeps the last id given to an item of this kind */

	GPtrArray* transforms; /* transformations to be applied */

	LoAL* keys;
	AVPL* extra; /* attributes to be added */

	double expiration;
	gop_tree_mode_t gop_tree_mode;
	bool show_times;

	GHashTable* my_hfids; /* for creating register info */
	int hfid;
	int hfid_gog_num_of_gops;
	int hfid_gog_gop;
	int hfid_gog_gopstart;
	int hfid_gog_gopstop;
	int hfid_start_time;
	int hfid_stop_time;
	int hfid_last_time;
	int ett;
	int ett_attr;
	int ett_times;
	int ett_children;
	int ett_gog_gop;
} mate_cfg_gog;

typedef struct _mate_config {
	char* mate_config_file; /* name of the config file */

	int hfid_mate;

	GArray *wanted_hfids;    /* hfids of protocols and fields MATE needs */
	unsigned num_fields_wanted; /* number of fields MATE will look at */

	FILE* dbg_facility; /* where to dump dbgprint output ws_message if null */

	char* mate_lib_path; /* where to look for "Include" files first */

	GHashTable* pducfgs; /* k=pducfg->name v=pducfg */
	GHashTable* gopcfgs; /* k=gopcfg->name v=gopcfg */
	GHashTable* gogcfgs; /* k=gogcfg->name v=gogcfg */
	GHashTable* transfs; /* k=transform->name v=transform */

	GPtrArray* pducfglist; /* pducfgs in order of "execution" */
	GHashTable* gops_by_pduname; /* k=pducfg->name v=gopcfg */
	GHashTable* gogs_by_gopname; /* k=gopname v=loal where avpl->name == matchedgop->name */

	GArray* hfrs;
	int ett_root;
	GArray* ett;

	/* defaults */
	struct _mate_cfg_defaults {
		struct _pdu_defaults {
			avpl_match_mode match_mode;
			avpl_replace_mode replace_mode;
			bool last_extracted;

			bool drop_unassigned;
			bool discard;
		} pdu;

		struct _gop_defaults {
			double expiration;
			double idle_timeout;
			double lifetime;

			gop_pdu_tree_t pdu_tree_mode;
			bool show_times;
			bool drop_unassigned;

		} gop;

		struct _gog_defaults {
			double expiration;
			bool show_times;
			gop_tree_mode_t gop_tree_mode;
		} gog;
	} defaults;

	/* what to dbgprint */
	int dbg_lvl;
	int dbg_pdu_lvl;
	int dbg_gop_lvl;
	int dbg_gog_lvl;

	GPtrArray* config_stack;
	GString* config_error;

} mate_config;


typedef struct _mate_config_frame {
	char* filename;
	unsigned  linenum;
} mate_config_frame;


typedef struct _mate_runtime_data {
	unsigned current_items; /* a count of items */
	double now;
	unsigned highest_analyzed_frame;

	GHashTable* frames; /* k=frame.num v=pdus */

} mate_runtime_data;

typedef struct _mate_pdu mate_pdu;
typedef struct _mate_gop mate_gop;
typedef struct _mate_gog mate_gog;

/* these are used to contain information regarding pdus, gops and gogs */
struct _mate_pdu {
	uint32_t id; /* 1:1 -> saving a g_malloc */
	mate_cfg_pdu* cfg; /* the type of this item */

	AVPL* avpl;

	uint32_t frame; /* which frame I belong to? */
	mate_pdu* next_in_frame; /* points to the next pdu in this frame */
	double rel_time; /* time since start of capture  */

	mate_gop* gop; /* the gop the pdu belongs to (if any) */
	mate_pdu* next; /* next in gop */
	double time_in_gop; /* time since gop start */

	bool first; /* is this the first pdu in this frame? */
	bool is_start; /* this is the start pdu for this gop */
	bool is_stop; /* this is the stop pdu for this gop */
	bool after_release; /* this pdu comes after the stop */

};


struct _mate_gop {
	uint32_t id;
	mate_cfg_gop* cfg;

	char* gop_key;
	AVPL* avpl; /* the attributes of the pdu/gop/gog */
	unsigned last_n;

	mate_gog* gog; /* the gog of a gop */
	mate_gop* next; /* next in gog; */

	double expiration; /* when will it expire after release (all gops releases if gog)? */
	double idle_expiration; /* when will it expire if no new pdus are assigned to it */
	double time_to_die;
	double time_to_timeout;

	double start_time; /* time of start */
	double release_time; /* when this gop/gog was released */
	double last_time; /* the rel_time at which the last pdu has been added (to gop or gog's gop) */


	int num_of_pdus; /* how many gops a gog has? */
	int num_of_after_release_pdus;  /* how many pdus have arrived since it's been released */
	mate_pdu* pdus; /* pdus that belong to a gop (NULL in gog) */
	mate_pdu* last_pdu; /* last pdu in pdu's list */

	bool released; /* has this gop been released? */
};


struct _mate_gog {
	uint32_t id;
	mate_cfg_gog* cfg;

	AVPL* avpl; /* the attributes of the pdu/gop/gog */
	unsigned last_n; /* the number of attributes the avpl had the last time we checked */

	bool released; /* has this gop been released? */

	double expiration; /* when will it expire after release (all gops releases if gog)? */
	double idle_expiration; /* when will it expire if no new pdus are assigned to it */

	/* on gop and gog: */
	double start_time; /* time of start */
	double release_time; /* when this gog was released */
	double last_time; /* the rel_time at which the last pdu has been added */

	mate_gop* gops; /* gops that belong to a gog (NULL in gop) */
	mate_gop* last_gop; /* last gop in gop's list */

	int num_of_gops; /* how many gops a gog has? */
	int num_of_counting_gops;  /* how many of them count for gog release */
	int num_of_released_gops;  /* how many of them have already been released */
	GPtrArray* gog_keys; /* the keys under which this gog is stored in the gogs hash */
};

typedef union _mate_max_size {
	mate_pdu pdu;
	mate_gop gop;
	mate_gog gog;
} mate_max_size;

/* from mate_runtime.c */
extern void initialize_mate_runtime(mate_config* mc);
extern mate_pdu* mate_get_pdus(uint32_t framenum);
extern void mate_analyze_frame(mate_config *mc, packet_info *pinfo, proto_tree* tree);

/* from mate_setup.c */
extern mate_config* mate_make_config(const char* filename, int mate_hfid);

extern mate_cfg_pdu* new_pducfg(mate_config* mc, char* name);
extern mate_cfg_gop* new_gopcfg(mate_config* mc, char* name);
extern mate_cfg_gog* new_gogcfg(mate_config* mc, char* name);

extern bool add_hfid(mate_config* mc, header_field_info*  hfi, char* as, GHashTable* where);
extern char* add_ranges(char* range, GPtrArray* range_ptr_arr);


/* from mate_parser.l */
extern bool mate_load_config(const char* filename, mate_config* mc);

/* Constructor/Destructor prototypes for Lemon Parser */
#define YYMALLOCARGTYPE size_t
void *MateParserAlloc(void* (*)(YYMALLOCARGTYPE));
void MateParserFree(void*, void (*)(void *));
void MateParser(void*, int, char*,  mate_config*);

#endif
