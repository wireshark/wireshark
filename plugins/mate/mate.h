/* mate.h
* MATE -- Meta Analysis and Tracing Engine 
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


#ifndef __MATE_H_
#define __MATE_H_

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef ENABLE_STATIC
#include "plugins/plugin_api.h"
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
#include "plugins/plugin_api_defs.h"


/* defaults */

#define DEFAULT_GOG_EXPIRATION 2.0

#ifdef WIN32
#define DIR_SEP '\\'
#else
#define DIR_SEP '/'
#endif

#define DEFAULT_MATE_LIB_PATH "matelib"

#define MATE_ITEM_ID_SIZE 24

/* Config AVP Names */
#define KEYWORD_ACTION "Action"
#define KEYWORD_SETTINGS "Settings"
#define KEYWORD_INCLUDE "Include"
#define KEYWORD_TRANSFORM "Transform"
#define KEYWORD_PDU "PduDef"
#define KEYWORD_PDUCRITERIA "PduCriteria"
#define KEYWORD_PDUEXTRA "PduExtra"
#define KEYWORD_PDUTRANSFORM "PduTransform"
#define KEYWORD_GOP "GopDef"
#define KEYWORD_GOPSTART "GopStart"
#define KEYWORD_GOPSTOP "GopStop"
#define KEYWORD_GOPEXTRA "GopExtra"
#define KEYWORD_GOPTRANSFORM "GopTransform"
#define KEYWORD_GOGDEF "GogDef"
#define KEYWORD_GOGKEY "GogKey"
#define KEYWORD_GOGEXTRA "GogExtra"
#define KEYWORD_GOGTRANSFORM "GogTransform"
#define KEYWORD_NAME "Name"
#define KEYWORD_ON "On"
#define KEYWORD_FOR "For"
#define KEYWORD_FROM "From"
#define KEYWORD_TO "To"
#define KEYWORD_MATCH "Match"
#define KEYWORD_MODE "Mode"
#define KEYWORD_FILENAME "Filename"
#define KEYWORD_PROTO "Proto"
#define KEYWORD_METHOD "Method"
#define KEYWORD_TRANSPORT "Transport"
#define KEYWORD_STRICT "Strict"
#define KEYWORD_LOOSE "Loose"
#define KEYWORD_EVERY "Every"
#define KEYWORD_REPLACE "Replace"
#define KEYWORD_INSERT "Insert"
#define KEYWORD_MAP "Map"
#define KEYWORD_GOGEXPIRE "GogExpiration"
#define KEYWORD_GOPTREE "GopTree"
#define KEYWORD_DISCARDPDU "DiscardPduData"
#define KEYWORD_LIBPATH "ThingLibPath"
#define KEYWORD_SHOWPDUTREE "ShowPduTree"
#define KEYWORD_SHOWGOPTIMES "ShowGopTimes"
#define KEYWORD_STOP "Stop"
#define KEYWORD_DROPGOP "DiscardUnassignedGop"
#define KEYWORD_DROPPDU "DiscardUnassignedPdu"
#define KEYWORD_LIB "Lib"
#define KEYWORD_ACCEPT "Accept"
#define KEYWORD_REJECT "Reject"
#define KEYWORD_NOTREE "NoTree"
#define KEYWORD_PDUTREE "PduTree"
#define KEYWORD_FRAMETREE "FrameTree"
#define KEYWORD_GOPEXPIRATION "GopExpiration"
#define KEYWORD_GOPIDLETIMEOUT "GopIdleTimeout"
#define KEYWORD_GOPLIFETIME "GopLifetime"

#define KEYWORD_DEBUGFILENAME "Debug_File"
#define KEYWORD_DBG_GENERAL "Debug_General"
#define KEYWORD_DBG_CFG "Debug_Cfg"
#define KEYWORD_DBG_PDU "Debug_PDU"
#define KEYWORD_DBG_GOP "Debug_Gop"
#define KEYWORD_DBG_GOG "Debug_Gog"
#ifdef _AVP_DEBUGGING
#define KEYWORD_DBG_AVPLIB "Debug_AVP_Lib"
#define KEYWORD_DBG_AVP "Debug_AVP"
#define KEYWORD_DBG_AVP_OP "Debug_AVP_Op"
#define KEYWORD_DBG_AVPL "Debug_AVPL"
#define KEYWORD_DBG_AVPL_OP "Debug_AVPL_Op"
#endif

#define VALUE_TOO ((void*)1)

typedef enum _mate_item_type {
	MATE_UNK_TYPE,
	MATE_PDU_TYPE,
	MATE_GOP_TYPE,
	MATE_GOG_TYPE
} mate_item_type;

typedef struct _mate_cfg_item mate_cfg_pdu;
typedef struct _mate_cfg_item mate_cfg_gop;
typedef struct _mate_cfg_item mate_cfg_gog;

typedef struct _mate_item mate_item;
typedef struct _mate_item mate_pdu;
typedef struct _mate_item mate_gop;
typedef struct _mate_item mate_gog;

typedef struct _mate_cfg_item {
	guint8* name;
	mate_item_type type; 
	GPtrArray* transforms; /* transformations to be applied */
	AVPL* extra; /* attributes to be added */
	guint last_id; /* keeps the last id given to an item of this kind */
	int hfid;
	GHashTable* my_hfids; /* for creating register info */
	GHashTable* items; /* all the items of this type */
	gint ett;
	gint ett_attr;
	gint ett_times;
	gint ett_children;
		
	/* pdu */
	gboolean discard_pdu_attributes;
	gboolean last_to_be_created;
	int hfid_proto;
	GPtrArray* hfid_ranges; /* hfids of candidate ranges from which to extract attributes */
	GHashTable* hfids_attr; /* k=hfid v=avp_name */
	gboolean drop_pdu;
	avpl_match_mode criterium_match_mode;
	AVPL* criterium; /* must match to be created */
	int hfid_pdu_rel_time;
	int hfid_pdu_time_in_gop;
	
	
	/* common to gop and gog */
	float expiration;
	int hfid_start_time;
	int hfid_stop_time;
	int hfid_last_time;
	
	/* gop */
	AVPL* start; /* start candidate avpl */
	AVPL* stop;  /* stop candidate avpl */
	AVPL* key; /* key candidate avpl */
	guint8* show_pdu_tree;
	gboolean show_times;
	gboolean drop_gop; 
	float idle_timeout;
	float lifetime;	
	int hfid_gop_pdu;
	int hfid_gop_num_pdus;
	
	GHashTable* gop_index;
	GHashTable* gog_index;
	
	/* gog */
	gboolean gop_as_subtree;
	LoAL* keys;
	int hfid_gog_num_of_gops;
	int hfid_gog_gop;
	
} mate_cfg_item;

typedef struct _mate_config {
	/* current defaults */
	float gog_expiration; /* default expirations for gogs if undefined in gog */
	gboolean discard_pdu_attributes; /* destroy the pdu's avpl once analyzed */
	gboolean drop_pdu; /* destroy the pdu if not assign to a gop */
	gboolean drop_gop; /* destroy the gop if not assign to a gog */
	guint8* mate_lib_path; /* where to look for "Include" files first */
	guint8* show_pdu_tree;
	gboolean show_times;
	gboolean last_to_be_created;
	avpl_match_mode match_mode;
	avpl_replace_mode replace_mode;
	gboolean gop_as_subtree;

	float gop_expiration;
	float gop_idle_timeout;
	float gop_lifetime;
	
	guint8* accept;
	guint8* reject;
	
	guint8* no_tree;
	guint8* frame_tree;
	guint8* pdu_tree;
	
	/* what to dbgprint */
	int dbg_lvl;	
	int dbg_cfg_lvl;
	int dbg_pdu_lvl;
	int dbg_gop_lvl;
	int dbg_gog_lvl;
	
	guint8* mate_config_file; /* name of the config file */
	GString* mate_attrs_filter; /* "ip.addr || dns.id || ... " for the tap */
	GString* mate_protos_filter; /* "dns || ftp || ..." for the tap */
	FILE* dbg_facility; /* where to dump dbgprint output g_message if null */
	guint8* tap_filter;
			
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
} mate_config;

typedef struct _mate_runtime_data {
	guint current_items; /* a count of items */
	GMemChunk* mate_items;
	float now;
	guint highest_analyzed_frame;
	
	GHashTable* frames; /* k=frame.num v=pdus */
	
} mate_runtime_data;

/* these are used to contain information regarding pdus, gops and gogs */
struct _mate_item {
	/* all three of them */
	guint32 id; /* 1:1 -> saving a g_malloc */
	mate_cfg_item* cfg; /* the type of this item */

	AVPL* avpl; /* the attributes of the pdu/gop/gog */
		
	mate_item* next; /* in pdu: next in gop; in gop: next in gog; in gog this doesn't make any sense yet */
	
	float expiration; /* when will it expire after release (all gops releases if gog)? */
	float idle_expiration; /* when will it expire if no new pdus are assigned to it */
	
	/* on gop and gog: */
	float start_time; /* time of start */
	float release_time; /* when this gop/gog was released */
	float last_time; /* the rel_time at which the last pdu has been added (to gop or gog's gop) */
	
	/* union _payload { */
		/* struct _pdu { */
			guint32 frame; /* wich frame I belog to? */
			mate_gop* gop; /* the gop the pdu belongs to (if any) */
			gboolean first; /* is this the first pdu in this frame? */
			gboolean is_start; /* this is the start pdu for this gop */
			gboolean is_stop; /* this is the stop pdu for this gop */
			gboolean after_release; /* this pdu comes after the stop */
			float rel_time; /* time since start of capture  */
			float time_in_gop; /* time since gop start */
			mate_pdu* next_in_frame; /* points to the next pdu in this frame */
		/* } pdu; */
		
		/* struct _gop { */
			mate_gog* gog; /* the gog of a gop */
			mate_pdu* pdus; /* pdus that belong to a gop (NULL in gog) */
			gboolean released; /* has this gop been released? */
			int num_of_pdus; /* how many gops a gog has? */
			int num_of_after_release_pdus;  /* how many pdus have arrived since it's been released */
			guint8* gop_key; /* used by gop */
			mate_pdu* last_pdu; /* last pdu in pdu's list */
			float time_to_die;
			float time_to_timeout;
		/* } gop; */
		
		/* struct _gog { */
			mate_gop* gops; /* gops that belong to a gog (NULL in gop) */
			int num_of_gops; /* how many gops a gog has? */
			int num_of_released_gops;  /* how many of them have already been released */
			guint last_n; /* the number of attributes the avpl had the last time we checked */
			GPtrArray* gog_keys; /* the keys under which this gog is stored in the gogs hash */
			mate_gop* last_gop; /* last gop in gop's list */
		/* } gog; */
	/* } o; */
};

/* from mate_runtime.c */
extern void initialize_mate_runtime(void);
extern mate_pdu* mate_get_pdus(guint32 framenum);
extern void mate_analyze_frame(packet_info *pinfo, proto_tree* tree);
extern int mate_packet(void*, packet_info*, epan_dissect_t*,const void*);

/* from mate_setup.c */
extern mate_config* mate_make_config(guint8* filename);
extern mate_config* mate_cfg(void);

#endif
