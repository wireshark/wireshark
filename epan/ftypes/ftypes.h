/* ftypes.h
 * Definitions for field types
 *
 * $Id: ftypes.h,v 1.4 2001/09/14 07:10:13 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
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


#ifndef FTYPES_H
#define FTYPES_H

#include <glib.h>


/* field types */
enum ftenum {
	FT_NONE,	/* used for text labels with no value */
	FT_PROTOCOL,
	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	FT_UINT8,
	FT_UINT16,
	FT_UINT24,	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
	FT_UINT32,
	FT_INT8,
	FT_INT16,
	FT_INT24,
	FT_INT32,
	FT_DOUBLE,
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_STRINGZ,	/* for use with proto_tree_add_item() */
	FT_UINT_STRING,	/* for use with proto_tree_add_item() */
	FT_UCS2_LE,     /* Unicode, 2 byte, Little Endian     */
	FT_ETHER,
	FT_BYTES,
	FT_IPv4,
	FT_IPv6,
	FT_IPXNET,
/*	FT_TEXT_ONLY,*/	/* non-filterable, used when converting ethereal
				from old-style proto_tree to new-style proto_tree */
	FT_NUM_TYPES /* last item number plus one */
};

typedef enum ftenum ftenum_t;
typedef struct _ftype_t ftype_t;

/* Initialize the ftypes subsytem. Called once. */
void
ftypes_initialize(void);

/* Cleanup the ftypes subsystem. Called once. */
void
ftypes_cleanup(void);


/* ---------------- FTYPE ----------------- */

/* Return a string representing the name of the type */
const char*
ftype_name(ftenum_t ftype);

/* Return a string presenting a "pretty" representation of the
 * name of the type. The pretty name means more to the user than
 * that "FT_*" name. */
const char*
ftype_pretty_name(ftenum_t ftype);

/* Returns length of field in packet, or 0 if not determinable/defined. */
int
ftype_length(ftenum_t ftype);

gboolean
ftype_can_slice(enum ftenum ftype);

gboolean
ftype_can_eq(enum ftenum ftype);

gboolean
ftype_can_ne(enum ftenum ftype);

gboolean
ftype_can_gt(enum ftenum ftype);

gboolean
ftype_can_ge(enum ftenum ftype);

gboolean
ftype_can_lt(enum ftenum ftype);

gboolean
ftype_can_le(enum ftenum ftype);

/* ---------------- FVALUE ----------------- */

#include "ipv4.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "tvbuff.h"
#include "nstime.h"
#include "dfilter/drange.h"

typedef struct {
	ftype_t	*ftype;
	union {
		/* Put a few basic types in here */
		gpointer	pointer;
		guint32		integer;
		gdouble		floating;
		gchar		*string;
		GByteArray	*bytes;
		ipv4_addr	ipv4;
		guint8		ipv6[16];
		nstime_t	time;
		tvbuff_t	*tvb;
	} value;
} fvalue_t;

fvalue_t*
fvalue_new(ftenum_t ftype);

void
fvalue_free(fvalue_t *fv);

typedef void (*LogFunc)(char*,...);

fvalue_t*
fvalue_from_string(ftenum_t ftype, char *s, LogFunc log);

const char*
fvalue_type_name(fvalue_t *fv);

void
fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied);

void
fvalue_set_integer(fvalue_t *fv, guint32 value);

void
fvalue_set_floating(fvalue_t *fv, gdouble value);

gpointer
fvalue_get(fvalue_t *fv);

guint32
fvalue_get_integer(fvalue_t *fv);

double
fvalue_get_floating(fvalue_t *fv);

gboolean
fvalue_eq(fvalue_t *a, fvalue_t *b);

gboolean
fvalue_ne(fvalue_t *a, fvalue_t *b);

gboolean
fvalue_gt(fvalue_t *a, fvalue_t *b);

gboolean
fvalue_ge(fvalue_t *a, fvalue_t *b);

gboolean
fvalue_lt(fvalue_t *a, fvalue_t *b);

gboolean
fvalue_le(fvalue_t *a, fvalue_t *b);

guint
fvalue_length(fvalue_t *fv);

fvalue_t*
fvalue_slice(fvalue_t *fv, drange *drange);

#endif /* ftypes.h */
