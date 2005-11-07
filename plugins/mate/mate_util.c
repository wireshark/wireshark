/* mate_util.c
* MATE -- Meta Analysis Tracing Engine
* Utility Library: Single Copy Strings and Attribute Value Pairs
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
#include "mate_util.h"
#include <wiretap/file_util.h>

/***************************************************************************
*  dbg_print
***************************************************************************
* This is the debug facility of the thing.
***************************************************************************/

/* dbg_print:
 * which:  a pointer to the current level of debugging for a feature
 * how: the level over which this message should be printed out
 * where: the file on which to print (g_message if null)
 * fmt, ...: what to print
 */

void dbg_print(const gint* which, gint how, FILE* where, const gchar* fmt, ... ) {
	static gchar debug_buffer[DEBUG_BUFFER_SIZE];
	va_list list;

	if ( ! which || *which < how ) return;

	va_start( list, fmt );
	g_vsnprintf(debug_buffer,DEBUG_BUFFER_SIZE,fmt,list);
	va_end( list );

	if (! where) {
		g_message(debug_buffer);
	} else {
		fputs(debug_buffer,where);
		fputs("\n",where);
	}

}


/***************************************************************************
 *  single copy strings
 ***************************************************************************
 * Strings repeat more often than don't. In order to save memory
 * we'll keep only one copy of each as key to a hash with a count of
 * subscribers as value.
 ***************************************************************************/

/**
 * scs_init:
 * @collection: the scs hash
 *
 *  Initializes the scs hash.
 **/

/* Don't call variables "small" or "huge". They are keywords for the MSVC compiler. Rename them to "mate_small" and "mate_huge"*/
struct _scs_collection {
	GHashTable* hash;	/* key: a string value: guint number of subscribers */
	GMemChunk* ctrs;
	GMemChunk* mate_small;	
	GMemChunk* mate_medium;
	GMemChunk* mate_large;
	GMemChunk* mate_huge;
};

extern void destroy_scs_collection(SCS_collection* c) {
	if ( c->ctrs ) g_mem_chunk_destroy(c->ctrs);
	if ( c->mate_small ) g_mem_chunk_destroy(c->mate_small);
	if ( c->mate_medium ) g_mem_chunk_destroy(c->mate_medium);
	if ( c->mate_large ) g_mem_chunk_destroy(c->mate_large);
	if ( c->mate_huge ) g_mem_chunk_destroy(c->mate_huge);
	
	if (c->hash) g_hash_table_destroy(c->hash);
}

extern SCS_collection* scs_init(void) {
	SCS_collection* c = g_malloc(sizeof(SCS_collection));

	c->hash =  g_hash_table_new(g_str_hash,g_str_equal);
	
	c->ctrs = g_mem_chunk_new("ints_scs_chunk", sizeof(guint),
							   sizeof(guint) * SCS_SMALL_CHUNK_SIZE, G_ALLOC_AND_FREE);
	
	c->mate_small = g_mem_chunk_new("small_scs_chunk", SCS_SMALL_SIZE,
							   SCS_SMALL_SIZE * SCS_SMALL_CHUNK_SIZE, G_ALLOC_AND_FREE);
	
	c->mate_medium = g_mem_chunk_new("medium_scs_chunk", SCS_MEDIUM_SIZE,
							   SCS_MEDIUM_SIZE * SCS_MEDIUM_CHUNK_SIZE, G_ALLOC_AND_FREE);
	
	c->mate_large = g_mem_chunk_new("large_scs_chunk", SCS_LARGE_SIZE,
							   SCS_LARGE_SIZE * SCS_LARGE_CHUNK_SIZE, G_ALLOC_AND_FREE);
	
	c->mate_huge = g_mem_chunk_new("huge_scs_chunk", SCS_HUGE_SIZE,
							   SCS_HUGE_SIZE * SCS_HUGE_CHUNK_SIZE, G_ALLOC_AND_FREE);
	return c;
}


/**
 * subscribe:
 * @collection: the scs hash
 * @s: a string
 *
 * Checks if the given string exists already and if so it increases the count of
 * subsscribers and returns a pointer to the stored string. If not It will copy
 * the given string store it in the hash and return the pointer to the copy.
 * Remember, containment is handled internally, take care of your own strings.
 *
 * Return value: a pointer to the subscribed string.
 **/
gchar* scs_subscribe(SCS_collection* c, const gchar* s) {
	gchar* orig = NULL;
	guint* ip = NULL;
	size_t len = 0;
	GMemChunk* chunk = NULL;
	
	g_hash_table_lookup_extended(c->hash,(gconstpointer)s,(gpointer*)&orig,(gpointer*)&ip);

	if (ip) {
		(*ip)++;
	} else {
		ip = g_mem_chunk_alloc(c->ctrs);
		*ip = 0;
		
		len = strlen(s) + 1;
		
		if (len <= SCS_SMALL_SIZE) {
			chunk = c->mate_small;
			len = SCS_SMALL_SIZE;
		} else if (len <= SCS_MEDIUM_SIZE) {
			chunk = c->mate_medium;
			len = SCS_MEDIUM_SIZE;
		} else if (len <= SCS_LARGE_SIZE) {
			chunk = c->mate_large;
			len = SCS_LARGE_SIZE;
		} else if (len < SCS_HUGE_SIZE) {
			chunk = c->mate_huge;
			len = SCS_HUGE_SIZE;
		} else {
			chunk = c->mate_huge;
			len = SCS_HUGE_SIZE;
			g_warning("mate SCS: string truncated to huge size");
		}
		
		orig = g_mem_chunk_alloc(chunk);
		strncpy(orig,s,len);
		
		g_hash_table_insert(c->hash,orig,ip);
	}

	return orig;
}

/**
 * unsubscribe:
 * @collection: the scs hash
 * @s: a string.
 *
 * decreases the count of subscribers, if zero frees the internal copy of
 * the string.
 **/
void scs_unsubscribe(SCS_collection* c, gchar* s) {
	gchar* orig = NULL;
	guint* ip = NULL;
	size_t len = 0xffff;
	GMemChunk* chunk = NULL;
	
	g_hash_table_lookup_extended(c->hash,(gconstpointer)s,(gpointer*)&orig,(gpointer*)&ip);

	if (ip) {
		if (*ip == 0) {
			g_hash_table_remove(c->hash,orig);
			
			len = strlen(orig);
			
			if (len < SCS_SMALL_SIZE) {
				chunk = c->mate_small;
			} else if (len < SCS_MEDIUM_SIZE) {
				chunk = c->mate_medium;
			} else if (len < SCS_LARGE_SIZE) {
				chunk = c->mate_large;
			} else {
				chunk = c->mate_huge;
			} 
			
			g_mem_chunk_free(chunk,orig);
			g_mem_chunk_free(c->ctrs,ip);
		}
		else {
			(*ip)--;
		}
	} else {
		g_warning("unsusbcribe: not subscribed");
	}
}

/**
 * scs_subscribe_printf:
 * @fmt: a format string ...
 *
 * Formats the input and subscribes it.
 *
 * Return value: the stored copy of the formated string.
 *
 **/
gchar* scs_subscribe_printf(SCS_collection* c, gchar* fmt, ...) {
	va_list list;
	static gchar buf[SCS_HUGE_SIZE];
	
	va_start( list, fmt );
	g_vsnprintf(buf, SCS_HUGE_SIZE-1 ,fmt, list);
	va_end( list );

	return scs_subscribe(c,buf);
}

/***************************************************************************
*  AVPs & Co.
***************************************************************************
* The Thing operates mainly on avps, avpls and loals
* - attribute value pairs (two strings: the name and the value and an opeartor)
* - avp lists a somehow sorted list of avps
* - loal (list of avp lists) an arbitrarily sorted list of avpls
*
*
***************************************************************************/


typedef union _any_avp_type {
	AVP avp;
	AVPN avpn;
	AVPL avpl;
	LoAL loal;
	LoALnode loaln;
} any_avp_type;


static GMemChunk* avp_chunk = NULL;
static SCS_collection* avp_strings = NULL;

#ifdef _AVP_DEBUGGING
static FILE* dbg_fp = NULL;

static int dbg_level = 0;
static int* dbg = &dbg_level;

static int dbg_avp_level = 0;
static int* dbg_avp = &dbg_avp_level;

static int dbg_avp_op_level = 0;
static int* dbg_avp_op = &dbg_avp_op_level;

static int dbg_avpl_level = 0;
static int* dbg_avpl = &dbg_avpl_level;

static int dbg_avpl_op_level = 0;
static int* dbg_avpl_op = &dbg_avpl_op_level;

/**
 * setup_avp_debug:
 * @fp: the file in which to send debugging output.
 * @general: a pointer to the level of debugging of facility "general"
 * @avp: a pointer to the level of debugging of facility "avp"
 * @avp_op: a pointer to the level of debugging of facility "avp_op"
 * @avpl: a pointer to the level of debugging of facility "avpl"
 * @avpl_op: a pointer to the level of debugging of facility "avpl_op"
 *
 * If enabled set's up the debug facilities for the avp library.
 *
 **/
extern void setup_avp_debug(FILE* fp, int* general, int* avp, int* avp_op, int* avpl, int* avpl_op) {
	dbg_fp = fp;
	dbg = general;
	dbg_avp = avp;
	dbg_avp_op = avp_op;
	dbg_avpl = avpl;
	dbg_avpl_op = avpl_op;
}

#endif /* _AVP_DEBUGGING */

/**
 * avp_init:
 * @chunk_size: the initial chunk's size.
 *
 * (Re)Initializes the avp library.
 *
 **/
extern void avp_init(void) {

	if (avp_strings) destroy_scs_collection(avp_strings);
	avp_strings = scs_init();

	if ( avp_chunk ) g_mem_chunk_destroy(avp_chunk);
	avp_chunk = g_mem_chunk_new("avp_chunk", sizeof(any_avp_type),
								AVP_CHUNK_SIZE, G_ALLOC_AND_FREE);

}


/**
 * new_avp_from_finfo:
 * @name: the name the avp will have.
 * @finfo: the field_info from which to fetch the data.
 *
 * Creates an avp from a field_info record.
 *
 * Return value: a pointer to the newly created avp.
 *
 **/
extern AVP* new_avp_from_finfo(const gchar* name, field_info* finfo) {
	AVP* new = g_mem_chunk_alloc(avp_chunk);
	gchar* value;
	
	new->n = scs_subscribe(avp_strings, name);

	if (finfo->value.ftype->val_to_string_repr) {
		value = scs_subscribe(avp_strings, fvalue_to_string_repr(&finfo->value,FTREPR_DISPLAY,NULL));
#ifdef _AVP_DEBUGGING
		dbg_print (dbg_avp,2,dbg_fp,"new_avp_from_finfo: from string: %s",value);
#endif
	} else {
#ifdef _AVP_DEBUGGING
		dbg_print (dbg_avp,2,dbg_fp,"new_avp_from_finfo: a proto: %s",finfo->hfinfo->abbrev);
#endif
		value = scs_subscribe(avp_strings, "");
	}

	new->v = value;

	new->o = '=';

#ifdef _AVP_DEBUGGING
	dbg_print (dbg_avp,1,dbg_fp,"new_avp_from_finfo: %X %s%c%s;",(guint32) new,new->n,new->o,new->v);
#endif

	return new;
}


/**
 * new_avp:
 * @name: the name the avp will have.
 * @value: the value the avp will have.
 * @o: the operator of this avp.
 *
 * Creates an avp given every parameter.
 *
 * Return value: a pointer to the newly created avp.
 *
 **/
extern AVP* new_avp(const gchar* name, const gchar* value, gchar o) {
	AVP* new = g_mem_chunk_alloc(avp_chunk);

	new->n = scs_subscribe(avp_strings, name);
	new->v = scs_subscribe(avp_strings, value);
	new->o = o;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avp,1,dbg_fp,"new_avp: %X %s%c%s;",(guint32) new,new->n,new->o,new->v);
#endif
	return new;
}


/**
* delete_avp:
 * @avp: the avp to delete.
 *
 * Destroys an avp and releases the resources it uses.
 *
 **/
extern void delete_avp(AVP* avp) {
#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avp,1,dbg_fp,"delete_avp: %X %s%c%s;",(guint32) avp,avp->n,avp->o,avp->v);
#endif

	scs_unsubscribe(avp_strings, avp->n);
	scs_unsubscribe(avp_strings, avp->v);
	g_mem_chunk_free(avp_chunk,avp);
}


/**
* avp_copy:
 * @from: the avp to be copied.
 *
 * Creates an avp whose name op and value are copyes of the given one.
 *
 * Return value: a pointer to the newly created avp.
 *
 **/
extern AVP* avp_copy(AVP* from) {
	AVP* new = g_mem_chunk_alloc(avp_chunk);

	new->n = scs_subscribe(avp_strings, from->n);
	new->v = scs_subscribe(avp_strings, from->v);
	new->o = from->o;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avp,1,dbg_fp,"copy_avp: %X %s%c%s;",(guint32) new,new->n,new->o,new->v);
#endif

	return new;
}


static void rename_avp(AVP* avp, gchar* name) {
	gchar* s = avp->n;
	avp->n = scs_subscribe(avp_strings,name);
	scs_unsubscribe(avp_strings,s);
}

/**
 * new_avpl:
 * @name: the name the avpl will have.
 *
 * Creates an empty avpl.
 *
 * Return value: a pointer to the newly created avpl.
 *
 **/
extern AVPL* new_avpl(const gchar* name) {
	AVPL* new_avpl = g_mem_chunk_alloc(avp_chunk);

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,7,dbg_fp,"new_avpl: %X name=%s",new_avpl,name);
#endif

	new_avpl->name = name ? scs_subscribe(avp_strings, name) : scs_subscribe(avp_strings, "");
	new_avpl->len = 0;
	new_avpl->null.avp = NULL;
	new_avpl->null.next = &new_avpl->null;
	new_avpl->null.prev = &new_avpl->null;


	return new_avpl;
}

extern void rename_avpl(AVPL* avpl, gchar* name) {
	scs_unsubscribe(avp_strings,avpl->name);
	avpl->name = scs_subscribe(avp_strings,name);
}

/**
 * insert_avp:
 * @avpl: the avpl in which to insert.
 * @avp: the avp to be inserted.
 *
 * Inserts the given AVP into the given AVPL if an identical one isn't yet there.
 *
 * Return value: whether it was inserted or not.
 *
 * BEWARE: Check the return value, you might need to delete the avp if
 *         it is not inserted.
 **/
extern gboolean insert_avp(AVPL* avpl, AVP* avp) {
	AVPN* new = g_mem_chunk_alloc(avp_chunk);
	AVPN* c;

	new->avp = avp;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,7,dbg_fp,"new_avpn: %X",new);
	dbg_print(dbg_avpl_op,4,dbg_fp,"insert_avp: %X %X %s%c%s;",avpl,avp,avp->n,avp->o,avp->v);
#endif

	/* get to the insertion point */
	for(c=avpl->null.next; c->avp; c = c->next) {

		if ( avp->n == c->avp->n ) {

			if (avp->v > c->avp->v) {
				break;
			}

			if (avp->v == c->avp->v) {
				if (avp->o == AVP_OP_EQUAL) {
#ifdef _AVP_DEBUGGING
					dbg_print(dbg_avpl_op,7,dbg_fp,"delete_avpn: %X",new);
#endif
					g_mem_chunk_free(avp_chunk,new);
					return FALSE;
				}
			}
		}

		if (avp->n > c->avp->n) {
			break;
		}
	}

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl,5,dbg_fp,"insert_avp:  inserting %X in %X before %X;",avp,avpl,c);
#endif

	new->next = c;
	new->prev = c->prev;
	c->prev->next = new;
	c->prev = new;

	avpl->len++;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl,4,dbg_fp,"avpl: %X new len: %i",avpl,avpl->len);
#endif

	return TRUE;
}

/**
 * get_avp_by_name:
 * @avpl: the avpl from which to try to get the avp.
 * @name: the name of the avp we are looking for.
 * @cookie: variable in which to store the state between calls.
 *
 * Gets  pointer to the next avp whose name is given; uses cookie to store its
 * state between calls.
 *
 * Return value: a pointer to the next matching avp if there's one, else NULL.
 *
 **/
extern AVP* get_avp_by_name(AVPL* avpl, gchar* name, void** cookie) {
	AVPN* curr;
	AVPN* start = (AVPN*) *cookie;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,7,dbg_fp,"get_avp_by_name: entering: %X %s %X",avpl,name,*cookie);
#endif

	name = scs_subscribe(avp_strings, name);

	if (!start) start = avpl->null.next;

	for ( curr = start; curr->avp; curr = curr->next ) {
		if ( curr->avp->n == name ) {
			break;
		}
	}

	*cookie = curr;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,5,dbg_fp,"get_avp_by_name: got avp: %X",curr);
#endif

	scs_unsubscribe(avp_strings, name);

	return curr->avp;
}

/**
 * extract_avp_by_name:
 * @avpl: the avpl from which to try to extract the avp.
 * @name: the name of the avp we are looking for.
 *
 * Extracts from the avpl the next avp whose name is given;
 *
 * Return value: a pointer to extracted avp if there's one, else NULL.
 *
 **/
extern AVP* extract_avp_by_name(AVPL* avpl, gchar* name) {
	AVPN* curr;
	AVP* avp = NULL;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,7,dbg_fp,"extract_avp_by_name: entering: %X %s",avpl,name);
#endif

	name = scs_subscribe(avp_strings, name);

	for ( curr = avpl->null.next; curr->avp; curr = curr->next ) {
		if ( curr->avp->n == name ) {
			break;
		}
	}

	scs_unsubscribe(avp_strings, name);

	if( ! curr->avp ) return NULL;

	curr->next->prev = curr->prev;
	curr->prev->next = curr->next;

	avp = curr->avp;

	g_mem_chunk_free(avp_chunk,curr);

	(avpl->len)--;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl,4,dbg_fp,"avpl: %X new len: %i",avpl,avpl->len);
#endif

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,5,dbg_fp,"extract_avp_by_name: got avp: %X",avp);
#endif

	return avp;
}


/**
 * extract_first_avp:
 * @avpl: the avpl from which to try to extract the avp.
 *
 * Extracts the fisrt avp from the avpl.
 *
 * Return value: a pointer to extracted avp if there's one, else NULL.
 *
 **/
extern AVP* extract_first_avp(AVPL* avpl) {
	AVP* avp;
	AVPN* node;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,7,dbg_fp,"extract_first_avp: %X",avpl);
#endif

	node = avpl->null.next;

	avpl->null.next->prev = &avpl->null;
	avpl->null.next = node->next;

	avp = node->avp;

	if (avp) {
		g_mem_chunk_free(avp_chunk,node);
		(avpl->len)--;
#ifdef _AVP_DEBUGGING
		dbg_print(dbg_avpl,4,dbg_fp,"avpl: %X new len: %i",avpl,avpl->len);
#endif
	}

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,5,dbg_fp,"extract_first_avp: got avp: %X",avp);
#endif

	return avp;

}


/**
 * extract_last_avp:
 * @avpl: the avpl from which to try to extract the avp.
 *
 * Extracts the last avp from the avpl.
 *
 * Return value: a pointer to extracted avp if there's one, else NULL.
 *
 **/
extern AVP* extract_last_avp(AVPL* avpl) {
	AVP* avp;
	AVPN* node;

	node = avpl->null.prev;

	avpl->null.prev->next = &avpl->null;
	avpl->null.prev = node->prev;

	avp = node->avp;

	if (avp) {
		g_mem_chunk_free(avp_chunk,node);
		(avpl->len)--;
#ifdef _AVP_DEBUGGING
		dbg_print(dbg_avpl,4,dbg_fp,"avpl: %X new len: %i",avpl,avpl->len);
#endif
	}

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,5,dbg_fp,"extract_last_avp: got avp: %X",avp);
#endif

	return avp;

}


/**
 * delete_avpl:
 * @avpl: the avpl from which to try to extract the avp.
 * @avps_too: whether or not it should delete the avps as well.
 *
 * Destroys an avpl and releases the resources it uses. If told to do
 * so releases the avps as well.
 *
 **/
extern void delete_avpl(AVPL* avpl, gboolean avps_too) {
	AVP* avp;
#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl,3,dbg_fp,"delete_avpl: %X",avpl);
#endif

	while(( avp = extract_last_avp(avpl))) {
		if (avps_too) {
			delete_avp(avp);
		}
	}

	scs_unsubscribe(avp_strings,avpl->name);
	g_mem_chunk_free(avp_chunk,avpl);
}



/**
 * get_next_avp:
 * @avpl: the avpl from which to try to get the avps.
 * @cookie: variable in which to store the state between calls.
 *
 * Iterates on an avpl to get its avps.
 *
 * Return value: a pointer to the next avp if there's one, else NULL.
 *
 **/
extern AVP* get_next_avp(AVPL* avpl, void** cookie) {
	AVPN* node;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,5,dbg_fp,"get_next_avp: avpl: %X avpn: %X",avpl,*cookie);
#endif

	if (*cookie) {
		node = (AVPN*) *cookie;
	} else {
		node = avpl->null.next;
	}

	*cookie = node->next;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,5,dbg_fp,"extract_last_avp: got avp: %X",node->avp);
#endif

	return node->avp;
}

/**
 * avpl_to_str:
 * @avpl: the avpl to represent.
 *
 * Creates a newly allocated string containing a representation of an avpl.
 *
 * Return value: a pointer to the newly allocated string.
 *
 **/
gchar* avpl_to_str(AVPL* avpl) {
	AVPN* c;
	GString* s = g_string_new("");
	gchar* avp_s;
	gchar* r;

	for(c=avpl->null.next; c->avp; c = c->next) {
		avp_s = avp_to_str(c->avp);
		g_string_sprintfa(s," %s;",avp_s);
		g_free(avp_s);
	}

	r = s->str;
	g_string_free(s,FALSE);

	/* g_strchug(r); ? */
	return r;
}

extern gchar* avpl_to_dotstr(AVPL* avpl) {
	AVPN* c;
	GString* s = g_string_new("");
	gchar* avp_s;
	gchar* r;

	for(c=avpl->null.next; c->avp; c = c->next) {
		avp_s = avp_to_str(c->avp);
		g_string_sprintfa(s," .%s;",avp_s);
		g_free(avp_s);
	}

	r = s->str;
	g_string_free(s,FALSE);

	/* g_strchug(r); ? */
	return r;
}

/**
* merge_avpl:
 * @dst: the avpl in which to merge the avps.
 * @src: the avpl from which to get the avps.
 * @copy: whether avps should be copied instead of referenced.
 *
 * Adds the avps of src that are not existent in dst into dst.
 *
 * Return value: a pointer to the newly allocated string.
 *
 **/
extern void merge_avpl(AVPL* dst, AVPL* src, gboolean copy_avps) {
	AVPN* cd = NULL;
	AVPN* cs = NULL;
	gint c;
	AVP* copy;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"merge_avpl: %X %X",dst,src);
#endif

	cs = src->null.next;
	cd = dst->null.next;

	while(cs->avp) {

		if(cd->avp) {
			c = (guint) cd->avp->n - (guint) cs->avp->n;
		} else {
			c = -1;
		}

		if (c > 0) {
			if (cd->avp) cd = cd->next;
		} else if (c < 0) {
			if (copy_avps) {
				copy = avp_copy(cs->avp);
				if ( ! insert_avp(dst,copy) ) {
					delete_avp(copy);
				}
			} else {
				insert_avp(dst,cs->avp);
			}

			cs = cs->next;
		} else {
			if ( ! cd->avp || ! (cd->avp->v == cs->avp->v)  ) {
				if (copy_avps) {
					copy = avp_copy(cs->avp);
					if ( ! insert_avp(dst,copy) ) {
						delete_avp(copy);
					}
				} else {
					insert_avp(dst,cs->avp);
				}
			}
			cs = cs->next;
			if (cd->avp) cd = cd->next;
		}
	}

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,8,dbg_fp,"merge_avpl: done");
#endif

	return;
}


/**
 * merge_avpl:
 * @name: the name of the new avpl.
 * @avpl: the avpl from which to get the avps.
 * @copy_avps: whether avps should be copied instead of referenced.
 *
 * Creates a new avpl containing the same avps as the given avpl
 * It will either reference or copie the avps.
 *
 * Return value: a pointer to the newly allocated string.
 *
 **/
extern AVPL* new_avpl_from_avpl(const gchar* name, AVPL* avpl, gboolean copy_avps) {
	AVPL* newavpl = new_avpl(name);
	void* cookie = NULL;
	AVP* avp;
	AVP* copy;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"new_avpl_from_avpl: %X from=%X name='%s'",newavpl,avpl,name);
#endif

	while(( avp = get_next_avp(avpl,&cookie) )) {
		if (copy_avps) {
			copy = avp_copy(avp);
			if ( ! insert_avp(newavpl,copy) ) {
				delete_avp(copy);
			}
		} else {
			insert_avp(newavpl,avp);
		}
	}

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,8,dbg_fp,"new_avpl_from_avpl: done");
#endif

	return newavpl;
}

/**
* match_avp:
 * @src: an src to be compared agains an "op" avp
 * @op: the "op" avp that will be matched against the src avp
 *
 * Checks whether or not two avp's match.
 *
 * Return value: a pointer to the src avp if there's a match.
 *
 **/
extern AVP* match_avp(AVP* src, AVP* op) {
	gchar** splited;
	int i;
	gchar* p;
	guint ls;
	guint lo;
	float fs = 0.0;
	float fo = 0.0;
	gboolean lower = FALSE;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"match_avp: %s%c%s; vs. %s%c%s;",src->n,src->o,src->v,op->n,op->o,op->v);
#endif

	if ( src->n != op->n ) {
		return NULL;
	}

	switch (op->o) {
		case AVP_OP_EXISTS:
			return src;
		case AVP_OP_EQUAL:
			return src->v == op->v ? src : NULL;
		case AVP_OP_NOTEQUAL:
			return !( src->v == op->v) ? src : NULL;
		case AVP_OP_STARTS:
			return strncmp(src->v,op->v,strlen(op->v)) == 0 ? src : NULL;
		case AVP_OP_ONEOFF:
			splited = g_strsplit(op->v,"|",0);
			if (splited) {
				for (i=0;splited[i];i++) {
					if(g_str_equal(splited[i],src->v)) {
						g_strfreev(splited);
						return src;
					}
				}
				g_strfreev(splited);
			}
			return NULL;

		case AVP_OP_LOWER:
			lower = TRUE;
		case AVP_OP_HIGHER:

			fs = (float) strtod(src->v, NULL);
			fo = (float) strtod(src->v, NULL);

			if (lower) {
				if (fs<fo) return src;
				else return NULL;
			} else {
				if (fs>fo) return src;
				else return NULL;
			}
		case AVP_OP_ENDS:
			/* does this work? */
			ls = strlen(src->v);
			lo = strlen(op->v);

			if ( ls < lo ) {
				return NULL;
			} else {
				p = src->v + ( ls - lo );
				return g_str_equal(p,op->v) ? src : NULL;
			}

		/* case AVP_OP_TRANSF: */
		/*	return do_transform(src,op); */
		case AVP_OP_CONTAINS:
			/* TODO */
			return NULL;
	}
	/* will never get here */
	return NULL;
}



/* TODO: rename me */
/**
 * new_avpl_loose_match:
 * @name: the name of the resulting avpl
 * @src: avpl to be matched agains an "op" avpl
 * @op: the "op" avpl that will be matched against the src avpl
 * @copy_avps: whether the avps in the resulting avpl should be copied
 *
 * creates an avp list containing any avps in src matching any avps in op
 * it will eventually create an empty list in none match
 *
 * Return value: a pointer to the newly created avpl containing the
 *				 matching avps.
 **/
extern AVPL* new_avpl_loose_match(const gchar* name,
								  AVPL* src,
								  AVPL* op,
								  gboolean copy_avps) {

	AVPL* newavpl = new_avpl(scs_subscribe(avp_strings, name));
	AVPN* co = NULL;
	AVPN* cs = NULL;
	gint  c;
	AVP* m;
	AVP* copy;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"new_avpl_loose_match: %X src=%X op=%X name='%s'",newavpl,src,op,name);
#endif


	cs = src->null.next;
	co = op->null.next;
	while(1) {

		if (!co->avp) {
			return newavpl;
		}

		if (!cs->avp) {
			return newavpl;
		}


		c = (guint) co->avp->n - (guint) cs->avp->n;

		if ( c > 0 ) {
			if (co->avp) co = co->next;
		} else if (c < 0) {
			if (cs->avp) cs = cs->next;
		} else {
			m = match_avp(cs->avp,co->avp);
			if(m) {

				if (copy_avps) {
					copy = avp_copy(m);
					if ( ! insert_avp(newavpl,copy) ) {
						delete_avp(copy);
					}
				} else {
					insert_avp(newavpl,m);
				}


			}

			if (cs->avp) cs = cs->next;

		}
	}

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,6,dbg_fp,"new_avpl_loose_match: done!");
#endif

	return NULL;
}

/* TODO: rename me */
/**
* new_avpl_every_match:
 * @name: the name of the resulting avpl
 * @src: avpl to be matched agains an "op" avpl
 * @op: the "op" avpl that will be matched against the src avpl
 * @copy_avps: whether the avps in the resulting avpl should be copied
 *
 * creates an avp list containing any avps in src matching every avp in op
 * it will not create a list if there is not a match for every attribute in op
 *
 * Return value: a pointer to the newly created avpl containing the
 *				 matching avps.
 **/
extern AVPL* new_avpl_every_match(const gchar* name, AVPL* src, AVPL* op, gboolean copy_avps) {
	AVPL* newavpl;
	AVPN* co = NULL;
	AVPN* cs = NULL;
	gint c;
	AVP* m;
	AVP* copy;
	gboolean matches;
	
#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"new_avpl_every_match: %X src=%X op=%X name='%s'",newavpl,src,op,name);
#endif
	if (src->len == 0) return NULL;
	
	newavpl = new_avpl(scs_subscribe(avp_strings, name));
	
	if (op->len == 0)
		return newavpl;
	
	matches = TRUE;

	cs = src->null.next;
	co = op->null.next;
	while(1) {

		if (!co->avp) {
			break;
		}

		if (!cs->avp) {
			break;
		}

		c = (guint) co->avp->n - (guint) cs->avp->n;

		if ( c > 0 ) {
			delete_avpl(newavpl,TRUE);
			return NULL;
		} else if (c < 0) {
			cs = cs->next;
			if (! cs->avp ) {
				break;
			}
		} else {
			m = match_avp(cs->avp,co->avp);

			if(m) {
				matches++;
				cs = cs->next;
				co = co->next;

				if (copy_avps) {
					copy = avp_copy(m);
					if ( ! insert_avp(newavpl,copy) ) {
						delete_avp(copy);
					}
				} else {
					insert_avp(newavpl,m);
				}

			} else {
				cs = cs->next;
			}
		}

	}

	if (matches) {
		return newavpl;
	} else {
		delete_avpl(newavpl,TRUE);
		return NULL;
	}
}


/* TODO: rename me */
/**
 * new_avpl_exact_match:
 * @name: the name of the resulting avpl
 * @src: avpl to be matched agains an "op" avpl
 * @op: the "op" avpl that will be matched against the src avpl
 * @copy_avps: whether the avps in the resulting avpl should be copied
 *
 * creates an avp list containing every avp in src matching every avp in op
 * it will not create a list unless every avp in op is matched only once
 * to every avp in op.
 *
 * Return value: a pointer to the newly created avpl containing the
 *				 matching avps.
 **/
extern AVPL* new_avpl_exact_match(const gchar* name,AVPL* src, AVPL* op, gboolean copy_avps) {
	AVPL* newavpl = new_avpl(name);
	AVPN* co = NULL;
	AVPN* cs = NULL;
	gint c;
	AVP* m;
    AVP* copy;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"new_avpl_every_match: %X src=%X op=%X name='%s'",newavpl,src,op,name);
#endif

	if (op->len == 0)
		return newavpl;
	
	if (src->len == 0) {
		delete_avpl(newavpl,FALSE);
		return NULL;
	}

	cs = src->null.next;
	co = op->null.next;
	while(1) {

		c = (guint) co->avp->n - (guint) cs->avp->n;

		if ( c > 0 ) {
			delete_avpl(newavpl,TRUE);
			return NULL;
		} else if (c < 0) {
			cs = cs->next;
			if (! cs->avp ) {
				delete_avpl(newavpl,TRUE);
				return NULL;
			}
		} else {
			m = match_avp(cs->avp,co->avp);

			if(m) {
				cs = cs->next;
				co = co->next;

				if (copy_avps) {
					copy = avp_copy(m);
					if ( ! insert_avp(newavpl,copy) ) {
						delete_avp(copy);
					}
				} else {
					insert_avp(newavpl,m);
				}


				if (!co->avp) {
					return newavpl;
				}
				if (!cs->avp) {
					delete_avpl(newavpl,TRUE);
					return NULL;
				}
			} else {
				delete_avpl(newavpl,TRUE);
				return NULL;
			}
		}

	}

	/* should never be reached */
	return NULL;
}

extern AVPL* new_avpl_from_match(avpl_match_mode mode, const gchar* name,AVPL* src, AVPL* op, gboolean copy_avps) {
	AVPL* avpl = NULL;
	
	switch (mode) {
		case AVPL_STRICT:
			avpl = new_avpl_exact_match(name,src,op,copy_avps);
			break;
		case AVPL_LOOSE:
			avpl = new_avpl_loose_match(name,src,op,copy_avps);
			break;
		case AVPL_EVERY:
			avpl = new_avpl_every_match(name,src,op,copy_avps);
			break;
		case AVPL_NO_MATCH:
			avpl = new_avpl_from_avpl(name,src,copy_avps);
			merge_avpl(avpl, op, copy_avps);
			break;
	}
	
	return avpl;
}

/**
 * new_avpl_transform:
 *
 * creates an empty avpl transformation
 *
 * Return value: a pointer to the newly created avpl transformation
 **/
static AVPL_Transf* new_avpl_transform(gchar* name, AVPL* mixed, avpl_match_mode match_mode, avpl_replace_mode replace_mode) {
	AVPL_Transf* t = g_malloc(sizeof(AVPL_Transf));
	AVP* avp;

	t->name = g_strdup(name);
	t->match = new_avpl("match");
	t->replace = new_avpl("replace");
	t->match_mode = match_mode;
	t->replace_mode  = replace_mode;
	t->next = NULL;
	t->map = NULL;

	while (( avp = extract_first_avp(mixed) )) {
		if (*(avp->n) == '.') {
			rename_avp(avp,((avp->n)+1));
			insert_avp(t->replace, avp);
		} else {
			insert_avp(t->match, avp);
		}
	}

	return t;
}


/**
 * delete_avpl_transform:
 * @it: a pointer to the avpl transformation object
 *
 * Destroys an avpl transformation object and releases all the resources it
 * uses.
 *
 **/
extern void delete_avpl_transform(AVPL_Transf* op) {
	AVPL_Transf* next;

	for (; op ; op = next) {
		next = op->next;

		g_free(op->name);

		if (op->match) {
			delete_avpl(op->match,TRUE);
		}

		if (op->replace) {
			delete_avpl(op->replace,TRUE);
		}

		g_free(op);
	}

}


/**
 * avpl_transform:
 * @src: the source avpl for the transform operation.
 * @op: a pointer to the avpl transformation object to apply.
 *
 * Applies the "op" transformation to an avpl, matches it and eventually
 * replaces or inserts the transformed avps.
 *
 * Return value: whether the transformation was performed or not.
 **/
extern void avpl_transform(AVPL* src, AVPL_Transf* op) {
	AVPL* avpl = NULL;
	AVPN* cs;
	AVPN* cm;
	AVPN* n;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"avpl_transform: src=%X op=%X",src,op);
#endif

	for ( ; op ; op = op->next) {
		
		avpl = new_avpl_from_match(op->match_mode, src->name,src, op->match, TRUE);

		if (avpl) {
			switch (op->replace_mode) {
				case AVPL_NO_REPLACE:
					delete_avpl(avpl,TRUE);
					return;
				case AVPL_INSERT:
					merge_avpl(src,op->replace,TRUE);
					delete_avpl(avpl,TRUE);
					return;
				case AVPL_REPLACE:
					cs = src->null.next;
					cm = avpl->null.next;
					while(cs->avp) {
						if (cm->avp && cs->avp->n == cm->avp->n && cs->avp->v == cm->avp->v) {
							n = cs->next;

							cs->prev->next = cs->next;
							cs->next->prev = cs->prev;
							g_mem_chunk_free(avp_chunk,cs);

							cs = n;
							cm = cm->next;
						} else {
							cs = cs->next;
						}
					}

					merge_avpl(src,op->replace,TRUE);
					delete_avpl(avpl,TRUE);
					return;
			}
		}
	}
}


/**
 * new_loal:
 * @name: the name the loal will take.
 *
 * Creates an empty list of avp lists.
 *
 * Return value: a pointer to the newly created loal.
 **/
extern LoAL* new_loal(const gchar* name) {
	LoAL* new_loal = g_mem_chunk_alloc(avp_chunk);

	if (! name) {
		name = "anonymous";
	}

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"new_loal: %X name=%s",new_loal,name);
#endif

	new_loal->name = scs_subscribe(avp_strings,name);
	new_loal->null.avpl = NULL;
	new_loal->null.next = &new_loal->null;
	new_loal->null.prev = &new_loal->null;
	new_loal->len = 0;
	return new_loal;
}

/**
 * loal_append:
 * @loal: the loal on which to operate.
 * @avpl: the avpl to append.
 *
 * Appends an avpl to a loal.
 *
 **/
extern void loal_append(LoAL* loal, AVPL* avpl) {
	LoALnode* node = g_mem_chunk_alloc(avp_chunk);

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"new_loal_node: %X",node);
#endif

	node->avpl = avpl;
	node->next = &loal->null;
	node->prev = loal->null.prev;

	loal->null.prev->next = node;
	loal->null.prev = node;
	loal->len++;
}


/**
 * extract_first_avpl:
 * @loal: the loal on which to operate.
 *
 * Extracts the first avpl contained in a loal.
 *
 * Return value: a pointer to the extracted avpl.
 *
 **/
extern AVPL* extract_first_avpl(LoAL* loal) {
	LoALnode* node;
	AVPL* avpl;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"extract_first_avpl: from: %s",loal->name);
#endif

	node = loal->null.next;

	loal->null.next->next->prev = &loal->null;
	loal->null.next = node->next;

	loal->len--;

	avpl = node->avpl;

	if ( avpl ) {
		g_mem_chunk_free(avp_chunk,node);

#ifdef _AVP_DEBUGGING
		dbg_print(dbg_avpl_op,3,dbg_fp,"extract_first_avpl: got %s",avpl->name);
		dbg_print(dbg_avpl_op,3,dbg_fp,"delete_loal_node: %X",node);
#endif
	}

	return avpl;
}

/**
* extract_first_avpl:
 * @loal: the loal on which to operate.
 *
 * Extracts the last avpl contained in a loal.
 *
 * Return value: a pointer to the extracted avpl.
 *
 **/
extern AVPL* extract_last_avpl(LoAL* loal){
	LoALnode* node;
	AVPL* avpl;

	node = loal->null.prev;

	loal->null.prev->prev->next = &loal->null;
	loal->null.prev = node->prev;

	loal->len--;

	avpl = node->avpl;

	if ( avpl ) {
		g_mem_chunk_free(avp_chunk,node);
#ifdef _AVP_DEBUGGING
		dbg_print(dbg_avpl_op,3,dbg_fp,"delete_loal_node: %X",node);
#endif
	}

	return avpl;
}

/**
 * extract_first_avpl:
 * @loal: the loal on which to operate.
 * @cookie pointer to the pointer variable to contain the state between calls
 *
 * At each call will return the following avpl from a loal. The given cookie
 * will be used to manatain the state between calls.
 *
 * Return value: a pointer to the next avpl.
 *
 **/
extern AVPL* get_next_avpl(LoAL* loal,void** cookie) {
	LoALnode* node;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"get_next_avpl: loal=%X node=%X",loal,*cookie);
#endif

	if (*cookie) {
		node = (LoALnode*) *cookie;
	} else {
		node = loal->null.next;
	}

	*cookie = node->next;

	return node->avpl;
}

/**
 * delete_loal:
 * @loal: the loal to be deleted.
 * @avpls_too: whether avpls contained by the loal should be deleted as well
 * @avps_too: whether avps contained by the avpls should be also deleted
 *
 * Destroys a loal and eventually desstroys avpls and avps.
 *
 **/
extern void delete_loal(LoAL* loal, gboolean avpls_too, gboolean avps_too) {
	AVPL* avpl;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"delete_loal: %X",loal);
#endif

	while(( avpl = extract_last_avpl(loal) )) {
		if (avpls_too) {
			delete_avpl(avpl,avps_too);
		}
	}

	scs_unsubscribe(avp_strings,loal->name);
	g_mem_chunk_free(avp_chunk,loal);
}



/****************************************************************************
 ******************* the following are used in load_loal_from_file
 ****************************************************************************/

/**
 * load_loal_error:
 * Used by loal_from_file to handle errors while loading.
 **/
static LoAL* load_loal_error(FILE* fp, LoAL* loal, AVPL* curr, int linenum, const gchar* fmt, ...) {
	va_list list;
	gchar* desc;
	LoAL* ret = NULL;
	gchar* err;
	
	va_start( list, fmt );
	desc = g_strdup_vprintf(fmt, list);
	va_end( list );


	err = g_strdup_printf("Error Loading LoAL from file: in %s at line: %i, %s",loal->name,linenum,desc);
	ret = new_loal(err);

	g_free(desc);
	g_free(err);

	if (fp) fclose(fp);
	if (loal) delete_loal(loal,TRUE,TRUE);
	if (curr) delete_avpl(curr,TRUE);

	return ret;
}


/*  the maximum length allowed for a line */
#define MAX_ITEM_LEN	8192

/* this two ugly things are used for tokenizing */
#define AVP_OP_CHAR '=': case '^': case '$': case '~': case '<': case '>': case '?': case '|': case '&' : case '!'

#define AVP_NAME_CHAR 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I': case 'J':\
case 'K': case 'L': case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T':\
case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z': case 'a': case 'b': case 'c': case 'd':\
case 'e': case 'f': case 'g': case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': case 'n':\
case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u': case 'v': case 'w': case 'x':\
case 'y': case 'z': case '_': case '0': case '1': case '2': case '3': case '4': case '5': case '6':\
case '7': case '8': case '9': case '.'


/**
 * loal_from_file:
 * @filename: the file containing a loals text representation.
 *
 * Given a filename it will attempt to load a loal containing a copy of
 * the avpls represented in the file.
 *
 * Return value: if successful a pointer to the new populated loal, else NULL.
 *
 **/
extern LoAL* loal_from_file(gchar* filename) {
	FILE *fp = NULL;
	gchar c;
	int i = 0;
	guint32 linenum = 1;
	gchar linenum_buf[MAX_ITEM_LEN];
	gchar name[MAX_ITEM_LEN];
	gchar value[MAX_ITEM_LEN];
	gchar op = '?';
	LoAL *loal = new_loal(filename);
	AVPL* curr = NULL;
	AVP* avp;

	enum _load_loal_states {
		START,
		BEFORE_NAME,
		IN_NAME,
		IN_VALUE,
		MY_IGNORE
	} state;

#ifndef _WIN32
	if (! getuid()) {
		return load_loal_error(fp,loal,curr,linenum,"MATE Will not run as root");
	}
#endif

	state = START;

	if (( fp = eth_fopen(filename,"r") )) {
		while(( c = (gchar) fgetc(fp) )){

			if ( feof(fp) ) {
				if ( ferror(fp) ) {
					report_read_failure(filename,errno);
					return load_loal_error(fp,loal,curr,linenum,"Error while reading '%f'",filename);
				}
				break;
			}

			if ( c == '\n' ) {
				linenum++;
			}

			if ( i >= MAX_ITEM_LEN - 1  ) {
				return load_loal_error(fp,loal,curr,linenum,"Maximum item length exceeded");
			}

			switch(state) {
				case MY_IGNORE:
					switch (c) {
						case '\n':
							state = START;
							i = 0;
							continue;
						default:
							continue;
					}
					continue;
				case START:
					switch (c) {
						case ' ': case '\t':
							/* ignore whitespace at line start */
							continue;
						case '\n':
							/* ignore empty lines */
							i = 0;
							continue;
						case AVP_NAME_CHAR:
							state = IN_NAME;
							i = 0;
							name[i++] = c;
							name[i] = '\0';
							g_snprintf(linenum_buf,sizeof(linenum_buf),"%s:%u",filename,linenum);
							curr = new_avpl(linenum_buf);
							continue;
						case '#':
							state = MY_IGNORE;
							continue;
						default:
							return load_loal_error(fp,loal,curr,linenum,"expecting name got: '%c'",c);
					}
				case BEFORE_NAME:
					i = 0;
					name[0] = '\0';
					switch (c) {
						case '\\':
							c = fgetc(fp);
							if (c != '\n') ungetc(c,fp);
							continue;
						case ' ':
						case '\t':
							continue;
						case AVP_NAME_CHAR:
							state = IN_NAME;

							name[i++] = c;
							name[i] = '\0';
							continue;
						case '\n':
							loal_append(loal,curr);
							state = START;
							continue;
						default:
							return load_loal_error(fp,loal,curr,linenum,"expecting name got: '%c'",c);
					}
					case IN_NAME:
						switch (c) {
							case ';':
								state = BEFORE_NAME;

								op = '?';
								name[i] = '\0';
								value[0] = '\0';
								i = 0;

								avp = new_avp(name,value,op);

								if (! insert_avp(curr,avp) ) {
									delete_avp(avp);
								}

								continue;
							case AVP_OP_CHAR:
								name[i] = '\0';
								i = 0;
								op = c;
								state = IN_VALUE;
								continue;
							case AVP_NAME_CHAR:
								name[i++] = c;
								continue;
							case '\n':
								return load_loal_error(fp,loal,curr,linenum,"operator expected found new line");
							default:
								return load_loal_error(fp,loal,curr,linenum,"name or match operator expected found '%c'",c);
						}
					case IN_VALUE:
						switch (c) {
							case '\\':
								value[i++] = fgetc(fp);
								continue;
							case ';':
								state = BEFORE_NAME;

								value[i] = '\0';
								i = 0;

								avp = new_avp(name,value,op);

								if (! insert_avp(curr,avp) ) {
									delete_avp(avp);
								}
								continue;
							case '\n':
								return load_loal_error(fp,loal,curr,linenum,"';' expected found new line");
							default:
								value[i++] = c;
								continue;
						}
			}
		}
		fclose (fp);

		return loal;

	} else {
		report_open_failure(filename,errno,FALSE);
		return load_loal_error(NULL,loal,NULL,0,"Cannot Open file '%s'",filename);
	}
}
