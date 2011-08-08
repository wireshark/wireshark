/* mate.h
* MATE -- Meta Analysis and Tracing Engine
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


#ifndef __MATE_H_
#define __MATE_H_

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* The mate dissector is using deprecated GMemChunk. Do not error out
 * when encountering it.
 */
#undef G_DISABLE_DEPRECATED

#ifndef ENABLE_STATIC
#include "moduleinfo.h"
#include <gmodule.h>
#else
#include <glib.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/filesystem.h>
#include <epan/report_err.h>

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
	gchar* name;
	guint last_id; /* keeps the last id given to an item of this kind */

	GHashTable* items; /* all the items of this type */
	GPtrArray* transforms; /* transformations to be applied */

	int hfid;

	int hfid_proto;
	int hfid_pdu_rel_time;
	int hfid_pdu_time_in_gop;

	GHashTable* my_hfids; /* for creating register info */

	gint ett;
	gint ett_attr;

	GHashTable* hfids_attr; /* k=hfid v=avp_name */

	gboolean discard;
	gboolean last_extracted;
	gboolean drop_unassigned;

	GPtrArray* transport_ranges; /* hfids of candidate transport ranges from which to extract attributes */
	GPtrArray* payload_ranges; /* hfids of candidate payload ranges from which to extract attributes */

	avpl_match_mode criterium_match_mode;
	accept_mode_t criterium_accept_mode;
	AVPL* criterium;
} mate_cfg_pdu;


typedef struct _mate_cfg_gop {
	gchar* name;
	guint last_id; /* keeps the last id given to an item of this kind */
	GHashTable* items; /* all the items of this type */

	GPtrArray* transforms; /* transformations to be applied */
	gchar* on_pdu;

	AVPL* key; /* key candidate avpl */
	AVPL* start; /* start candidate avpl */
	AVPL* stop;  /* stop candidate avpl */
	AVPL* extra; /* attributes to be added */

	float expiration;
	float idle_timeout;
	float lifetime;

	gboolean drop_unassigned;
	gop_pdu_tree_t pdu_tree_mode;
	gboolean show_times;

	GHashTable* my_hfids; /* for creating register info */
	int hfid;
	int hfid_start_time;
	int hfid_stop_time;
	int hfid_last_time;
	int hfid_gop_pdu;
	int hfid_gop_num_pdus;

	gint ett;
	gint ett_attr;
	gint ett_times;
	gint ett_children;

	GHashTable* gop_index;
	GHashTable* gog_index;
} mate_cfg_gop;


typedef struct _mate_cfg_gog {
	gchar* name;

	GHashTable* items; /* all the items of this type */
	guint last_id; /* keeps the last id given to an item of this kind */

	GPtrArray* transforms; /* transformations to be applied */

	LoAL* keys;
	AVPL* extra; /* attributes to be added */

	float expiration;
	gop_tree_mode_t gop_tree_mode;
	gboolean show_times;

	GHashTable* my_hfids; /* for creating register info */
	int hfid;
	int hfid_gog_num_of_gops;
	int hfid_gog_gop;
	int hfid_gog_gopstart;
	int hfid_gog_gopstop;
	int hfid_start_time;
	int hfid_stop_time;
	int hfid_last_time;
	gint ett;
	gint ett_attr;
	gint ett_times;
	gint ett_children;
	gint ett_gog_gop;
} mate_cfg_gog;

typedef struct _mate_config {
	gchar* mate_config_file; /* name of the config file */

	int hfid_mate;

	GString* fields_filter; /* "ip.addr || dns.id || ... " for the tap */
	GString* protos_filter; /* "dns || ftp || ..." for the tap */
	gchar* tap_filter;

	FILE* dbg_facility; /* where to dump dbgprint output g_message if null */

	gchar* mate_lib_path; /* where to look for "Include" files first */

	GHashTable* pducfgs; /* k=pducfg->name v=pducfg */
	GHashTable* gopcfgs; /* k=gopcfg->name v=gopcfg */
	GHashTable* gogcfgs; /* k=gogcfg->name v=gogcfg */
	GHashTable* transfs; /* k=transform->name v=transform */

	GPtrArray* pducfglist; /* pducfgs in order of "execution" */
	GHashTable* gops_by_pduname; /* k=pducfg->name v=gopcfg */
	GHashTable* gogs_by_gopname; /* k=gopname v=loal where avpl->name == matchedgop->name */

	GArray* hfrs;
	gint ett_root;
	GArray* ett;

	/* defaults */
	struct _mate_cfg_defaults {
		struct _pdu_defaults {
			avpl_match_mode match_mode;
			avpl_replace_mode replace_mode;
			gboolean last_extracted;

			gboolean drop_unassigned;
			gboolean discard;
		} pdu;

		struct _gop_defaults {
			float expiration;
			float idle_timeout;
			float lifetime;

			gop_pdu_tree_t pdu_tree_mode;
			gboolean show_times;
			gboolean drop_unassigned;

		} gop;

		struct _gog_defaults {
			float expiration;
			gboolean show_times;
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
	gchar* filename;
	guint  linenum;
} mate_config_frame;


typedef struct _mate_runtime_data {
	guint current_items; /* a count of items */
	GMemChunk* mate_items;
	float now;
	guint highest_analyzed_frame;

	GHashTable* frames; /* k=frame.num v=pdus */

} mate_runtime_data;

typedef struct _mate_pdu mate_pdu;
typedef struct _mate_gop mate_gop;
typedef struct _mate_gog mate_gog;

/* these are used to contain information regarding pdus, gops and gogs */
struct _mate_pdu {
	guint32 id; /* 1:1 -> saving a g_malloc */
	mate_cfg_pdu* cfg; /* the type of this item */

	AVPL* avpl;

	guint32 frame; /* wich frame I belog to? */
	mate_pdu* next_in_frame; /* points to the next pdu in this frame */
	float rel_time; /* time since start of capture  */

	mate_gop* gop; /* the gop the pdu belongs to (if any) */
	mate_pdu* next; /* next in gop */
	float time_in_gop; /* time since gop start */

	gboolean first; /* is this the first pdu in this frame? */
	gboolean is_start; /* this is the start pdu for this gop */
	gboolean is_stop; /* this is the stop pdu for this gop */
	gboolean after_release; /* this pdu comes after the stop */

};


struct _mate_gop {
	guint32 id;
	mate_cfg_gop* cfg;

	gchar* gop_key;
	AVPL* avpl; /* the attributes of the pdu/gop/gog */
	guint last_n;

	mate_gog* gog; /* the gog of a gop */
	mate_gop* next; /* next in gog; */

	float expiration; /* when will it expire after release (all gops releases if gog)? */
	float idle_expiration; /* when will it expire if no new pdus are assigned to it */
	float time_to_die;
	float time_to_timeout;

	float start_time; /* time of start */
	float release_time; /* when this gop/gog was released */
	float last_time; /* the rel_time at which the last pdu has been added (to gop or gog's gop) */


	int num_of_pdus; /* how many gops a gog has? */
	int num_of_after_release_pdus;  /* how many pdus have arrived since it's been released */
	mate_pdu* pdus; /* pdus that belong to a gop (NULL in gog) */
	mate_pdu* last_pdu; /* last pdu in pdu's list */

	gboolean released; /* has this gop been released? */
};


struct _mate_gog {
	guint32 id;
	mate_cfg_gog* cfg;

	AVPL* avpl; /* the attributes of the pdu/gop/gog */
	guint last_n; /* the number of attributes the avpl had the last time we checked */

	gboolean released; /* has this gop been released? */

	float expiration; /* when will it expire after release (all gops releases if gog)? */
	float idle_expiration; /* when will it expire if no new pdus are assigned to it */

	/* on gop and gog: */
	float start_time; /* time of start */
	float release_time; /* when this gog was released */
	float last_time; /* the rel_time at which the last pdu has been added */

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
extern void initialize_mate_runtime(void);
extern mate_pdu* mate_get_pdus(guint32 framenum);
extern void mate_analyze_frame(packet_info *pinfo, proto_tree* tree);

/* from mate_setup.c */
extern mate_config* mate_make_config(const gchar* filename, int mate_hfid);

extern mate_config* mate_cfg(void);
extern mate_cfg_pdu* new_pducfg(gchar* name);
extern mate_cfg_gop* new_gopcfg(gchar* name);
extern mate_cfg_gog* new_gogcfg(gchar* name);

extern gboolean add_hfid(header_field_info*  hfi, gchar* as, GHashTable* where);
extern gchar* add_ranges(gchar* range, GPtrArray* range_ptr_arr);


/* from mate_parser.l */
extern gboolean mate_load_config(const gchar* filename, mate_config* mc);

#endif
