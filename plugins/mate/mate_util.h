/* mate_util.h
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


#ifndef __AVP_H_
#define __AVP_H_
#include "epan/proto.h"
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif


/* #define _AVP_DEBUGGING */


/******* dbg_print *********/
#define DEBUG_BUFFER_SIZE 4096
extern void dbg_print(const guint* which, guint how, FILE* where, guint8* fmt, ... );


/******* single copy strings *********/
typedef struct _scs_collection SCS_collection;

#define SCS_SMALL_SIZE 16
#define SCS_MEDIUM_SIZE 256
#define SCS_LARGE_SIZE 4096
#define SCS_HUGE_SIZE 65536

#define SCS_SMALL_CHUNK_SIZE 4096
#define SCS_MEDIUM_CHUNK_SIZE 1024
#define SCS_LARGE_CHUNK_SIZE 256
#define SCS_HUGE_CHUNK_SIZE 128

extern void destroy_scs_collection(SCS_collection* c);
extern SCS_collection* scs_init(void);
extern guint8* scs_subscribe(SCS_collection* collection, guint8* s);
extern void scs_unsubscribe(SCS_collection* collection, guint8* s);
extern guint8* scs_subscribe_printf(SCS_collection* collection, guint8* fmt, ...);

/******* AVPs & Co. *********/
#define AVP_CHUNK_SIZE 4096

/* these are the defined oreators of avps */
#define AVP_OP_EQUAL		'='
#define AVP_OP_NOTEQUAL		'!'
#define AVP_OP_STARTS		'^'
#define AVP_OP_ENDS			'$'
#define AVP_OP_CONTAINS		'~'
#define AVP_OP_LOWER		'<'
#define AVP_OP_HIGHER		'>'
#define AVP_OP_EXISTS		'?'
#define AVP_OP_ONEOFF		'|'
#define AVP_OP_TRANSF		'&'


/* an avp is an object made of a name a value and an operator */
typedef struct _avp {
	guint8* n;
	guint8* v;
	guint8 o;
} AVP;

/* avp nodes are used in avp lists */
typedef struct _avp_node {
	AVP* avp;
	struct _avp_node* next;
	struct _avp_node* prev;
} AVPN;

/* an avp list is a sorted set of avps */
typedef struct _avp_list {
	guint8* name;
	guint32 len;
	AVPN null;
} AVPL;



/* an avpl transformation operation */
typedef enum _avpl_match_mode {
	AVPL_NO_MATCH,
	AVPL_STRICT,
	AVPL_LOOSE,
	AVPL_EVERY
} avpl_match_mode;

typedef enum _avpl_replace_mode {
	AVPL_NO_REPLACE,
	AVPL_INSERT,
	AVPL_REPLACE,
} avpl_replace_mode;

typedef struct _avpl_transf AVPL_Transf;

struct _avpl_transf {
	guint8* name;

	AVPL* match;
	AVPL* replace;

	avpl_match_mode match_mode;
	avpl_replace_mode replace_mode;

	GHashTable* map;
	AVPL_Transf* next;
};

/* loalnodes are used in LoALs */
typedef struct _loal_node {
	AVPL* avpl;
	struct _loal_node *next;
	struct _loal_node *prev;
} LoALnode;


/* a loal is a list of avp lists */
typedef struct _loal {
	guint8* name;
	guint len;
	LoALnode null;
} LoAL;


/* avp library (re)initialization */
extern void avp_init(void);

/* If enabled set's up the debug facilities for the avp library */
#ifdef _AVP_DEBUGGING
extern void setup_avp_debug(FILE* fp, int* general, int* avp, int* avp_op, int* avpl, int* avpl_op);
#endif /* _AVP_DEBUGGING */

/*
 * avp constructors
 */

/* creates a new avp */
extern AVP* new_avp(guint8* name, guint8* value, guint8 op);

/* creates a copy od an avp */
extern AVP* avp_copy(AVP* from);

/* creates an avp from a field_info record */
extern AVP* new_avp_from_finfo(guint8* name, field_info* finfo);

/*
 * avp destructor
 */
extern void delete_avp(AVP* avp);

/*
 * avp methods
 */
/* returns a newly allocated string containing a representation of the avp */
#define avp_to_str(avp) (g_strdup_printf("%s%c%s",avp->n,avp->o,avp->v))

/* returns the src avp if the src avp matches(*) the op avp or NULL if it doesn't */
extern AVP* match_avp(AVP* src, AVP* op);


/*
 * avplist constructors
 */

/* creates an empty avp list */
extern AVPL* new_avpl(guint8* name);


/* creates a copy of an avp list */
extern AVPL* new_avpl_from_avpl(guint8* name, AVPL* avpl, gboolean copy_avps);

/* creates an avp list containing any avps in src matching any avps in op
   it will eventually create an empty list in none match */
extern AVPL* new_avpl_loose_match(guint8* name,AVPL* src, AVPL* op, gboolean copy_avps);

/* creates an avp list containing any avps in src matching every avp in op
  it will not create a list if there is not a match for every attribute in op */
extern AVPL* new_avpl_every_match(guint8* name,AVPL* src, AVPL* op, gboolean copy_avps);

/* creates an avp list containing every avp in src matching every avp in op
   it will not create a list unless every avp in op is matched only once to avery avp in op */
extern AVPL* new_avpl_exact_match(guint8* name,AVPL* src, AVPL* op, gboolean copy_avps);

/* uses mode to call one of the former matches. NO_MATCH = merge(merge(copy(src),op)) */
extern AVPL* new_avpl_from_match(avpl_match_mode mode, guint8* name,AVPL* src, AVPL* op, gboolean copy_avps);



/*
 * avplist destructor
 */
extern void delete_avpl(AVPL* avpl, gboolean avps_too);

/*
 * functions on avpls
 */

/* it will insert an avp to an avpl */
extern gboolean insert_avp(AVPL* avpl, AVP* avp);

/* renames an avpl */
extern void rename_avpl(AVPL* avpl, guint8* name);

/* it will add all the avps in src which don't match(*) any attribute in dest */
extern void merge_avpl(AVPL* dest, AVPL* src, gboolean copy);

/* it will return the first avp in an avpl whose name matches the given name.
  will return NULL if there is not anyone matching */
extern AVP* get_avp_by_name(AVPL* avpl, guint8* name, void** cookie);

/* it will get the next avp from an avpl, using cookie to keep state */
extern AVP* get_next_avp(AVPL* avpl, void** cookie);

/* it will extract the first avp from an avp list */
extern AVP* extract_first_avp(AVPL* avpl);

/* it will extract the last avp from an avp list */
extern AVP* extract_last_avp(AVPL* avpl);

/* it will extract the first avp in an avpl whose name matches the given name.
   it will not extract any and  return NULL if there is not anyone matching */
extern AVP* extract_avp_by_name(AVPL* avpl, guint8* name);

/* returns a newly allocated string containing a representation of the avp list */
extern guint8* avpl_to_str(AVPL* avpl);
extern guint8* avpl_to_dotstr(AVPL*);

/* deletes an avp list  and eventually it's contents */
extern void delete_avpl(AVPL* avpl, gboolean avps_too);

/*
 *  AVPL transformations
 */
extern AVPL_Transf* new_avpl_transform(guint8* name, AVPL* mixed, avpl_match_mode match_mode, avpl_replace_mode replace_mode);
extern void delete_avpl_transform(AVPL_Transf* it);
extern void avpl_transform(AVPL* src, AVPL_Transf* op);


/*
 * Lists of AVP lists
 */

/* creates an empty list of avp lists */
extern LoAL* new_loal(guint8* name);

/* given a file loads all the avpls contained in it
   every line is formatted as it is the output of avplist_to_string */
extern LoAL* loal_from_file(guint8* filename);

/* inserts an avplist into a LoAL */
extern void loal_append(LoAL* loal, AVPL* avpl);

/* extracts the first avp list from the loal */
extern AVPL* extract_first_avpl(LoAL* loal);

/* extracts the last avp list from the loal */
extern AVPL* extract_last_avpl(LoAL* loal);

/* it will get the next avp list from a LoAL, using cookie to keep state */
extern AVPL* get_next_avpl(LoAL* loal,void** cookie);

/* deletes a loal and eventually it's contents */
extern void delete_loal(LoAL* loal, gboolean avpls_too, gboolean avps_too);


#endif
