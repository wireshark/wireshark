/* mate_util.c
* MATE -- Meta Analysis Tracing Engine
* Utility Library: Single Copy Strings and Attribute Value Pairs
*
* Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
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
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "mate.h"
#include "mate_util.h"
#include <wsutil/file_util.h>

/***************************************************************************
*  ADDRDIFF
***************************************************************************
* This is a macro that computes the difference between the raw address
* values of two pointers (rather than the difference between the pointers)
* as a ptrdiff_t.
***************************************************************************/
#define ADDRDIFF(p,q)	(((char *)(void *)(p)) - ((char *)(void *)(q)))


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
		g_message("%s", debug_buffer);
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
 *
 *  Initializes the scs hash.
 **/

struct _scs_collection {
	GHashTable* hash;	/* key: a string value: guint number of subscribers */
};

/* ToDo? free any string,ctr entries pointed to by the hash table ??
 *       XXX: AFAIKT destroy_scs_collection() might be called only when reading a
 *         mate config file. Since reading a new config file can apparently currently
 *         only be done once after starting Wireshark, in theory this fcn
 *         currently should never be called since there will never be an existing
 *         scs_collection to be destroyed.
 */
static void destroy_scs_collection(SCS_collection* c) {
	if (c->hash) g_hash_table_destroy(c->hash);
}

static SCS_collection* scs_init(void) {
	SCS_collection* c = (SCS_collection *)g_malloc(sizeof(SCS_collection));

	c->hash =  g_hash_table_new(g_str_hash,g_str_equal);

	return c;
}


/**
 * subscribe:
 * @param c the scs hash
 * @param s a string
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

	g_hash_table_lookup_extended(c->hash,(gconstpointer)s,(gpointer *)&orig,(gpointer *)&ip);

	if (ip) {
		(*ip)++;
	} else {
		ip = g_slice_new(guint);
		*ip = 0;

		len = strlen(s) + 1;

		if (len <= SCS_SMALL_SIZE) {
			len = SCS_SMALL_SIZE;
		} else if (len <= SCS_MEDIUM_SIZE) {
			len = SCS_MEDIUM_SIZE;
		} else if (len <= SCS_LARGE_SIZE) {
			len = SCS_LARGE_SIZE;
		} else if (len < SCS_HUGE_SIZE) {
			len = SCS_HUGE_SIZE;
		} else {
			len = SCS_HUGE_SIZE;
			g_warning("mate SCS: string truncated due to huge size");
		}

		orig = (gchar *)g_slice_alloc(len);
		g_strlcpy(orig,s,len);

		g_hash_table_insert(c->hash,orig,ip);
	}

	return orig;
}

/**
 * unsubscribe:
 * @param c the scs hash
 * @param s a string.
 *
 * decreases the count of subscribers, if zero frees the internal copy of
 * the string.
 **/
void scs_unsubscribe(SCS_collection* c, gchar* s) {
	gchar* orig = NULL;
	guint* ip = NULL;
	size_t len = 0xffff;

	g_hash_table_lookup_extended(c->hash,(gconstpointer)s,(gpointer *)&orig,(gpointer *)&ip);

	if (ip) {
		if (*ip == 0) {
			g_hash_table_remove(c->hash,orig);

			len = strlen(orig);

			if (len < SCS_SMALL_SIZE) {
				len = SCS_SMALL_SIZE;
			} else if (len < SCS_MEDIUM_SIZE) {
				len = SCS_MEDIUM_SIZE;
			} else if (len < SCS_LARGE_SIZE) {
				len = SCS_LARGE_SIZE;
			} else {
				len = SCS_HUGE_SIZE;
			}

			g_slice_free1(len, orig);
			g_slice_free(guint,ip);
		}
		else {
			(*ip)--;
		}
	} else {
		g_warning("unsubscribe: not subscribed");
	}
}

/**
 * scs_subscribe_printf:
 * @param fmt a format string ...
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
	g_vsnprintf(buf, SCS_HUGE_SIZE, fmt, list);
	va_end( list );

	return scs_subscribe(c,buf);
}

/***************************************************************************
*  AVPs & Co.
***************************************************************************
* The Thing operates mainly on avps, avpls and loals
* - attribute value pairs (two strings: the name and the value and an operator)
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
 * @param fp the file in which to send debugging output.
 * @param general a pointer to the level of debugging of facility "general"
 * @param avp a pointer to the level of debugging of facility "avp"
 * @param avp_op a pointer to the level of debugging of facility "avp_op"
 * @param avpl a pointer to the level of debugging of facility "avpl"
 * @param avpl_op a pointer to the level of debugging of facility "avpl_op"
 *
 * If enabled sets up the debug facilities for the avp library.
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
 *
 * (Re)Initializes the avp library.
 *
 **/
extern void avp_init(void) {

	if (avp_strings) destroy_scs_collection(avp_strings);
	avp_strings = scs_init();

}

/**
 * new_avp_from_finfo:
 * @param name the name the avp will have.
 * @param finfo the field_info from which to fetch the data.
 *
 * Creates an avp from a field_info record.
 *
 * Return value: a pointer to the newly created avp.
 *
 **/
extern AVP* new_avp_from_finfo(const gchar* name, field_info* finfo) {
	AVP*   new_avp_val = (AVP*)g_slice_new(any_avp_type);
	gchar* value;
	gchar* repr;

	new_avp_val->n = scs_subscribe(avp_strings, name);

	repr = fvalue_to_string_repr(NULL, &finfo->value,FTREPR_DISPLAY,finfo->hfinfo->display);

	if (repr) {
		value = scs_subscribe(avp_strings, repr);
		wmem_free(NULL, repr);
#ifdef _AVP_DEBUGGING
		dbg_print (dbg_avp,2,dbg_fp,"new_avp_from_finfo: from string: %s",value);
#endif
	} else {
#ifdef _AVP_DEBUGGING
		dbg_print (dbg_avp,2,dbg_fp,"new_avp_from_finfo: a proto: %s",finfo->hfinfo->abbrev);
#endif
		value = scs_subscribe(avp_strings, "");
	}

	new_avp_val->v = value;

	new_avp_val->o = '=';

#ifdef _AVP_DEBUGGING
	dbg_print (dbg_avp,1,dbg_fp,"new_avp_from_finfo: %X %s%c%s;",(guint32) new_avp_val,new_avp_val->n,new_avp_val->o,new_avp_val->v);
#endif

	return new_avp_val;
}


/**
 * new_avp:
 * @param name the name the avp will have.
 * @param value the value the avp will have.
 * @param o the operator of this avp.
 *
 * Creates an avp given every parameter.
 *
 * Return value: a pointer to the newly created avp.
 *
 **/
extern AVP* new_avp(const gchar* name, const gchar* value, gchar o) {
	AVP* new_avp_val = (AVP*)g_slice_new(any_avp_type);

	new_avp_val->n = scs_subscribe(avp_strings, name);
	new_avp_val->v = scs_subscribe(avp_strings, value);
	new_avp_val->o = o;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avp,1,dbg_fp,"new_avp_val: %X %s%c%s;",(guint32) new_avp_val,new_avp_val->n,new_avp_val->o,new_avp_val->v);
#endif
	return new_avp_val;
}


/**
* delete_avp:
 * @param avp the avp to delete.
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
	g_slice_free(any_avp_type,(any_avp_type*)avp);
}


/**
* avp_copy:
 * @param from the avp to be copied.
 *
 * Creates an avp whose name op and value are copies of the given one.
 *
 * Return value: a pointer to the newly created avp.
 *
 **/
extern AVP* avp_copy(AVP* from) {
	AVP* new_avp_val = (AVP*)g_slice_new(any_avp_type);

	new_avp_val->n = scs_subscribe(avp_strings, from->n);
	new_avp_val->v = scs_subscribe(avp_strings, from->v);
	new_avp_val->o = from->o;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avp,1,dbg_fp,"copy_avp: %X %s%c%s;",(guint32) new_avp_val,new_avp_val->n,new_avp_val->o,new_avp_val->v);
#endif

	return new_avp_val;
}

/**
 * new_avpl:
 * @param name the name the avpl will have.
 *
 * Creates an empty avpl.
 *
 * Return value: a pointer to the newly created avpl.
 *
 **/
extern AVPL* new_avpl(const gchar* name) {
	AVPL* new_avpl_p = (AVPL*)g_slice_new(any_avp_type);

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,7,dbg_fp,"new_avpl_p: %X name=%s",new_avpl_p,name);
#endif

	new_avpl_p->name = name ? scs_subscribe(avp_strings, name) : scs_subscribe(avp_strings, "");
	new_avpl_p->len = 0;
	new_avpl_p->null.avp = NULL;
	new_avpl_p->null.next = &new_avpl_p->null;
	new_avpl_p->null.prev = &new_avpl_p->null;


	return new_avpl_p;
}

extern void rename_avpl(AVPL* avpl, gchar* name) {
	scs_unsubscribe(avp_strings,avpl->name);
	avpl->name = scs_subscribe(avp_strings,name);
}

/**
 * insert_avp:
 * @param avpl the avpl in which to insert.
 * @param avp the avp to be inserted.
 *
 * Inserts the given AVP into the given AVPL if an identical one isn't yet there.
 *
 * Return value: whether it was inserted or not.
 *
 * BEWARE: Check the return value, you might need to delete the avp if
 *         it is not inserted.
 **/
extern gboolean insert_avp(AVPL* avpl, AVP* avp) {
	AVPN* new_avp_val = (AVPN*)g_slice_new(any_avp_type);
	AVPN* c;

	new_avp_val->avp = avp;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,7,dbg_fp,"new_avpn: %X",new_avp_val);
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
					dbg_print(dbg_avpl_op,7,dbg_fp,"delete_avpn: %X",new_avp_val);
#endif
					g_slice_free(any_avp_type,(any_avp_type*)new_avp_val);
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

	new_avp_val->next = c;
	new_avp_val->prev = c->prev;
	c->prev->next = new_avp_val;
	c->prev = new_avp_val;

	avpl->len++;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl,4,dbg_fp,"avpl: %X new len: %i",avpl,avpl->len);
#endif

	return TRUE;
}

/**
 * get_avp_by_name:
 * @param avpl the avpl from which to try to get the avp.
 * @param name the name of the avp we are looking for.
 * @param cookie variable in which to store the state between calls.
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
 * @param avpl the avpl from which to try to extract the avp.
 * @param name the name of the avp we are looking for.
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

	g_slice_free(any_avp_type,(any_avp_type*)curr);

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
 * @param avpl the avpl from which to try to extract the avp.
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
		g_slice_free(any_avp_type,(any_avp_type*)node);
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
 * @param avpl the avpl from which to try to extract the avp.
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
		g_slice_free(any_avp_type,(any_avp_type*)node);
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
 * @param avpl the avpl from which to try to extract the avp.
 * @param avps_too whether or not it should delete the avps as well.
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
	g_slice_free(any_avp_type,(any_avp_type*)avpl);
}



/**
 * get_next_avp:
 * @param avpl the avpl from which to try to get the avps.
 * @param cookie variable in which to store the state between calls.
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
 * @param avpl the avpl to represent.
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
		g_string_append_printf(s," %s;",avp_s);
		g_free(avp_s);
	}

	r = g_string_free(s,FALSE);

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
		g_string_append_printf(s," .%s;",avp_s);
		g_free(avp_s);
	}

	r = g_string_free(s,FALSE);

	/* g_strchug(r); ? */
	return r;
}

/**
* merge_avpl:
 * @param dst the avpl in which to merge the avps.
 * @param src the avpl from which to get the avps.
 * @param copy_avps whether avps should be copied instead of referenced.
 *
 * Adds the avps of src that are not existent in dst into dst.
 *
 * Return value: a pointer to the newly allocated string.
 *
 **/
extern void merge_avpl(AVPL* dst, AVPL* src, gboolean copy_avps) {
	AVPN* cd = NULL;
	AVPN* cs = NULL;
	ptrdiff_t c;
	AVP* copy;

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"merge_avpl: %X %X",dst,src);
#endif

	cs = src->null.next;
	cd = dst->null.next;

	while(cs->avp) {

		if(cd->avp) {
			c = ADDRDIFF(cd->avp->n,cs->avp->n);
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
 * @param name the name of the new avpl.
 * @param avpl the avpl from which to get the avps.
 * @param copy_avps whether avps should be copied instead of referenced.
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
 * @param src an src to be compared agains an "op" avp
 * @param op the "op" avp that will be matched against the src avp
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
	float fs = 0.0f;
	float fo = 0.0f;
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
			/* FALLTHRU */
		case AVP_OP_HIGHER:

			fs = (float) g_ascii_strtod(src->v, NULL);
			fo = (float) g_ascii_strtod(op->v, NULL);

			if (lower) {
				if (fs<fo) return src;
				else return NULL;
			} else {
				if (fs>fo) return src;
				else return NULL;
			}
		case AVP_OP_ENDS:
			/* does this work? */
			ls = (guint) strlen(src->v);
			lo = (guint) strlen(op->v);

			if ( ls < lo ) {
				return NULL;
			} else {
				p = src->v + ( ls - lo );
				return g_str_equal(p,op->v) ? src : NULL;
			}

		/* case AVP_OP_TRANSF: */
		/*	return do_transform(src,op); */
		case AVP_OP_CONTAINS:
			return g_strrstr(src->v, op->v) ? src : NULL;;
	}
	/* will never get here */
	return NULL;
}



/* TODO: rename me */
/**
 * new_avpl_loose_match:
 * @param name the name of the resulting avpl
 * @param src avpl to be matched agains an "op" avpl
 * @param op the "op" avpl that will be matched against the src avpl
 * @param copy_avps whether the avps in the resulting avpl should be copied
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
	ptrdiff_t c;
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


		c = ADDRDIFF(co->avp->n, cs->avp->n);

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
 * @param name the name of the resulting avpl
 * @param src avpl to be matched agains an "op" avpl
 * @param op the "op" avpl that will be matched against the src avpl
 * @param copy_avps whether the avps in the resulting avpl should be copied
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
	ptrdiff_t c;
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

		c = ADDRDIFF(co->avp->n,cs->avp->n);

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
 * @param name the name of the resulting avpl
 * @param src avpl to be matched agains an "op" avpl
 * @param op the "op" avpl that will be matched against the src avpl
 * @param copy_avps whether the avps in the resulting avpl should be copied
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
	ptrdiff_t c;
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

		c = ADDRDIFF(co->avp->n,cs->avp->n);

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
 * delete_avpl_transform:
 * @param op a pointer to the avpl transformation object
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
 * @param src the source avpl for the transform operation.
 * @param op a pointer to the avpl transformation object to apply.
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
							g_slice_free(any_avp_type,(any_avp_type*)cs);

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
 * @param name the name the loal will take.
 *
 * Creates an empty list of avp lists.
 *
 * Return value: a pointer to the newly created loal.
 **/
extern LoAL* new_loal(const gchar* name) {
	LoAL* new_loal_p = (LoAL*)g_slice_new(any_avp_type);

	if (! name) {
		name = "anonymous";
	}

#ifdef _AVP_DEBUGGING
	dbg_print(dbg_avpl_op,3,dbg_fp,"new_loal_p: %X name=%s",new_loal_p,name);
#endif

	new_loal_p->name = scs_subscribe(avp_strings,name);
	new_loal_p->null.avpl = NULL;
	new_loal_p->null.next = &new_loal_p->null;
	new_loal_p->null.prev = &new_loal_p->null;
	new_loal_p->len = 0;
	return new_loal_p;
}

/**
 * loal_append:
 * @param loal the loal on which to operate.
 * @param avpl the avpl to append.
 *
 * Appends an avpl to a loal.
 *
 **/
extern void loal_append(LoAL* loal, AVPL* avpl) {
	LoALnode* node = (LoALnode*)g_slice_new(any_avp_type);

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
 * @param loal the loal on which to operate.
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
		g_slice_free(any_avp_type,(any_avp_type*)node);

#ifdef _AVP_DEBUGGING
		dbg_print(dbg_avpl_op,3,dbg_fp,"extract_first_avpl: got %s",avpl->name);
		dbg_print(dbg_avpl_op,3,dbg_fp,"delete_loal_node: %X",node);
#endif
	}

	return avpl;
}

/**
* extract_first_avpl:
 * @param loal the loal on which to operate.
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
		g_slice_free(any_avp_type,(any_avp_type*)node);
#ifdef _AVP_DEBUGGING
		dbg_print(dbg_avpl_op,3,dbg_fp,"delete_loal_node: %X",node);
#endif
	}

	return avpl;
}

/**
 * extract_first_avpl:
 * @param loal the loal on which to operate.
 * @param cookie pointer to the pointer variable to contain the state between calls
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
 * @param loal the loal to be deleted.
 * @param avpls_too whether avpls contained by the loal should be deleted as well
 * @param avps_too whether avps contained by the avpls should be also deleted
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
	g_slice_free(any_avp_type,(any_avp_type*)loal);
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
 * @param filename the file containing a loals text representation.
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

	if (( fp = ws_fopen(filename,"r") )) {
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
							c = (gchar) fgetc(fp);
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
								value[i++] = (gchar) fgetc(fp);
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
