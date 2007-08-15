/* oid.h
 * Definitions for OBJECT IDENTIFIER operations
 *
 * $Id$
 *
 * (c) 2007, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __OIDS_H__
#define __OIDS_H__

#ifndef HAVE_SMI
/* Values from smi.h in case it is not included */
#define SMI_BASETYPE_UNKNOWN 0
#define SMI_BASETYPE_INTEGER32 1
#define SMI_BASETYPE_OCTETSTRING 2
#define SMI_BASETYPE_OBJECTIDENTIFIER 3
#define SMI_BASETYPE_UNSIGNED32 4
#define SMI_BASETYPE_INTEGER64 5
#define SMI_BASETYPE_UNSIGNED64 6
#define SMI_BASETYPE_FLOAT32 7
#define SMI_BASETYPE_FLOAT64 8
#define SMI_BASETYPE_FLOAT128 9
#define SMI_BASETYPE_ENUM 10
#define SMI_BASETYPE_BITS 11
#endif

struct _oid_bit_t {
	guint offset;
	int hfid;
};

typedef struct _oid_bits_info_t {
	guint num;
	gint ett;
	struct _oid_bit_t* data;
} oid_bits_info_t;

typedef struct _oid_info_t {
	guint32 subid;
	char* name;
	void* children; /* an emem_tree_t* */
	int value_type;
	int value_hfid;
	oid_bits_info_t* bits;
	struct _oid_info_t* parent;
} oid_info_t;

/* init funcion called from epan.h */
extern void oid_init(void);

/*
 * The objects returned by all these functions are all allocated with a 
 * packet lifetime and does not have have to be freed. 
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an se_alloc() buffer.
 */

/*
 * These functions convert through the various formats:
 * string: is  like "0.1.3.4.5.30" (not resolved)
 * encoded: is BER encoded (as per X.690 section 8.19)
 * subids: is an array of guint32s
 */

/* return lenght of encoded buffer */
guint oid_subid2encoded(guint len, guint32* subids, guint8** encoded_p);
guint oid_string2encoded(const gchar *oid_str, guint8** encoded_p);

/* return lenght of subid array */
guint oid_encoded2subid(const guint8 *oid, gint len, guint32** subids_p);
guint oid_string2subid(const gchar *oid_str, guint32** subids_p);

extern const gchar* oid_encoded2string(const guint8* encoded, guint len);
extern const gchar* oid_subid2string(guint32 *subids, guint len);

/* these return a formated string as human readable as posible */
extern const gchar *oid_resolved(guint len, guint32 *subids);
extern const gchar *oid_resolved_from_encoded(const guint8 *oid, gint len);
extern const gchar *oid_resolved_from_string(const gchar *oid_str);

/* these yield two formated strings one resolved and one numeric */
 extern void oid_both(guint oid_len, guint32 *subids, char** resolved_p, char** numeric_p);
 extern void oid_both_from_encoded(const guint8 *oid, gint oid_len, char** resolved_p, char** numeric_p);
 extern void oid_both_from_string(const gchar *oid_str, char** resolved_p, char** numeric_p);

/*
 * These return the info for the best match.
 *  *matched_p will be set to the number of nodes used by the returned oid
 *  *left_p will be set to the number of remaining unresolved subids 
 */
extern oid_info_t* oid_get(guint oid_len, guint32 *subids, guint* matched_p, guint* left_p);
extern oid_info_t* oid_get_from_encoded(const guint8 *oid, gint oid_len, guint* matched, guint* left);
extern oid_info_t* oid_get_from_string(const gchar *oid_str, guint* matched, guint* left);

/* these are used to add oids to the collection */
 extern void oid_add(char* name, guint oid_len, guint32 *subids);
 extern void oid_add_from_encoded(char* name, const guint8 *oid, gint oid_len);
 extern void oid_add_from_string(char* name, const gchar *oid_str);


#endif