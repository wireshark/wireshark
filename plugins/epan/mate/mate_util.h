/* mate_util.h
 *
 * Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __AVP_H_
#define __AVP_H_
#include "epan/proto.h"
#include <sys/types.h>

/* #define _AVP_DEBUGGING */


/******* dbg_print *********/
#define DEBUG_BUFFER_SIZE 4096
extern void dbg_print(const int* which, int how, FILE* where,
	const char* fmt, ... ) G_GNUC_PRINTF(4, 5);


/******* single copy strings *********/
typedef struct _scs_collection SCS_collection;

#define SCS_SMALL_SIZE 16
#define SCS_MEDIUM_SIZE 256
#define SCS_LARGE_SIZE 4096
#define SCS_HUGE_SIZE 65536

extern char* scs_subscribe(SCS_collection* collection, const char* s);
extern void scs_unsubscribe(SCS_collection* collection, char* s);
extern char* scs_subscribe_printf(SCS_collection* collection, char* fmt, ...)
	G_GNUC_PRINTF(2, 3);

/******* AVPs & Co. *********/

/* these are the defined oreators of avps */
#define AVP_OP_EQUAL		'='
#define AVP_OP_NOTEQUAL		'!'
#define AVP_OP_STARTS		'^'
#define AVP_OP_ENDS		'$'
#define AVP_OP_CONTAINS		'~'
#define AVP_OP_LOWER		'<'
#define AVP_OP_HIGHER		'>'
#define AVP_OP_EXISTS		'?'
#define AVP_OP_ONEOFF		'|'
#define AVP_OP_TRANSF		'&'


/* an avp is an object made of a name a value and an operator */
typedef struct _avp {
	char* n;
	char* v;
	char o;
} AVP;

/* avp nodes are used in avp lists */
typedef struct _avp_node {
	AVP* avp;
	struct _avp_node* next;
	struct _avp_node* prev;
} AVPN;

/* an avp list is a sorted set of avps */
typedef struct _avp_list {
	char* name;
	uint32_t len;
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
	AVPL_REPLACE
} avpl_replace_mode;

typedef struct _avpl_transf AVPL_Transf;

struct _avpl_transf {
	char* name;

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
	char* name;
	unsigned len;
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
extern AVP* new_avp(const char* name, const char* value, char op);

/* creates a copy od an avp */
extern AVP* avp_copy(AVP* from);

/* creates an avp from a field_info record */
extern AVP* new_avp_from_finfo(const char* name, field_info* finfo);

/*
 * avp destructor
 */
extern void delete_avp(AVP* avp);

/*
 * avp methods
 */
/* returns a newly allocated string containing a representation of the avp */
#define avp_to_str(avp) (ws_strdup_printf("%s%c%s",avp->n,avp->o,avp->v))

/* returns the src avp if the src avp matches(*) the op avp or NULL if it doesn't */
extern AVP* match_avp(AVP* src, AVP* op);


/*
 * avplist constructors
 */

/* creates an empty avp list */
extern AVPL* new_avpl(const char* name);


/* creates a copy of an avp list */
extern AVPL* new_avpl_from_avpl(const char* name, AVPL* avpl, bool copy_avps);

extern AVPL* new_avpl_loose_match(const char* name, AVPL* src, AVPL* op, bool copy_avps);

extern AVPL* new_avpl_pairs_match(const char* name, AVPL* src, AVPL* op, bool strict, bool copy_avps);

/* uses mode to call one of the former matches. NO_MATCH = merge(merge(copy(src),op)) */
extern AVPL* new_avpl_from_match(avpl_match_mode mode, const char* name,AVPL* src, AVPL* op, bool copy_avps);


/*
 * functions on avpls
 */

/* it will insert an avp to an avpl */
extern bool insert_avp(AVPL* avpl, AVP* avp);

/* renames an avpl */
extern void rename_avpl(AVPL* avpl, char* name);

/* it will add all the avps in src which don't match(*) any attribute in dest */
extern void merge_avpl(AVPL* dest, AVPL* src, bool copy);

/* it will return the first avp in an avpl whose name matches the given name.
  will return NULL if there is not anyone matching */
extern AVP* get_avp_by_name(AVPL* avpl, char* name, void** cookie);

/* it will get the next avp from an avpl, using cookie to keep state */
extern AVP* get_next_avp(AVPL* avpl, void** cookie);

/* it will extract the first avp from an avp list */
extern AVP* extract_first_avp(AVPL* avpl);

/* it will extract the last avp from an avp list */
extern AVP* extract_last_avp(AVPL* avpl);

/* it will extract the first avp in an avpl whose name matches the given name.
   it will not extract any and  return NULL if there is not anyone matching */
extern AVP* extract_avp_by_name(AVPL* avpl, char* name);

/* returns a newly allocated string containing a representation of the avp list */
extern char* avpl_to_str(AVPL* avpl);
extern char* avpl_to_dotstr(AVPL*);

/* deletes an avp list  and eventually its contents */
extern void delete_avpl(AVPL* avpl, bool avps_too);

/*
 *  AVPL transformations
 */
extern void delete_avpl_transform(AVPL_Transf* it);
extern void avpl_transform(AVPL* src, AVPL_Transf* op);


/*
 * Lists of AVP lists
 */

/* creates an empty list of avp lists */
extern LoAL* new_loal(const char* name);

/* given a file loads all the avpls contained in it
   every line is formatted as it is the output of avplist_to_string */
extern LoAL* loal_from_file(char* filename);

/* inserts an avplist into a LoAL */
extern void loal_append(LoAL* loal, AVPL* avpl);

/* extracts the first avp list from the loal */
extern AVPL* extract_first_avpl(LoAL* loal);

/* extracts the last avp list from the loal */
extern AVPL* extract_last_avpl(LoAL* loal);

/* it will get the next avp list from a LoAL, using cookie to keep state */
extern AVPL* get_next_avpl(LoAL* loal,void** cookie);

/* deletes a loal and eventually its contents */
extern void delete_loal(LoAL* loal, bool avpls_too, bool avps_too);


#endif
