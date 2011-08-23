/*
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <ftypes-int.h>
#include <string.h>

#define CMP_MATCHES cmp_matches

#include <ctype.h>

static void
string_fvalue_new(fvalue_t *fv)
{
	fv->value.string = NULL;
}

static void
string_fvalue_free(fvalue_t *fv)
{
	g_free(fv->value.string);
}

static void
string_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
    DISSECTOR_ASSERT(value != NULL);
    DISSECTOR_ASSERT(!already_copied);

	/* Free up the old value, if we have one */
	string_fvalue_free(fv);

	fv->value.string = g_strdup(value);
}

static int
string_repr_len(fvalue_t *fv, ftrepr_t rtype)
{
	gchar *p, c;
	int repr_len;

	switch (rtype) {
		case FTREPR_DISPLAY:
			return (int)strlen(fv->value.string);
		case FTREPR_DFILTER:
			repr_len = 0;
			for (p = fv->value.string; (c = *p) != '\0'; p++) {
				/* Backslashes and double-quotes must
				 * be escaped */
				if (c == '\\' || c == '"') {
					repr_len += 2;
				}
				/* Values that can't nicely be represented
				 * in ASCII need to be escaped. */
				else if (!isprint((unsigned char)c)) {
					/* c --> \xNN */
					repr_len += 4;
				}
				/* Other characters are just passed through. */
				else {
					repr_len++;
				}
			}
			return repr_len + 2;	/* string plus leading and trailing quotes */
	}
	g_assert_not_reached();
	return -1;
}

static void
string_to_repr(fvalue_t *fv, ftrepr_t rtype, char *buf)
{
	gchar *p, c;
	char *bufp;
	char hex[3];

	if (rtype == FTREPR_DFILTER) {
		bufp = buf;
		*bufp++ = '"';
		for (p = fv->value.string; (c = *p) != '\0'; p++) {
			/* Backslashes and double-quotes must
			 * be escaped. */
			if (c == '\\' || c == '"') {
				*bufp++ = '\\';
				*bufp++ = c;
			}
			/* Values that can't nicely be represented
			 * in ASCII need to be escaped. */
			else if (!isprint((unsigned char)c)) {
				/* c --> \xNN */
				g_snprintf(hex, sizeof(hex), "%02x", (unsigned char) c);
				*bufp++ = '\\';
				*bufp++ = 'x';
				*bufp++ = hex[0];
				*bufp++ = hex[1];
			}
			/* Other characters are just passed through. */
			else {
				*bufp++ = c;
			}
		}
		*bufp++ = '"';
		*bufp = '\0';
	}
	else {
		strcpy(buf, fv->value.string);
	}
}


static gpointer
value_get(fvalue_t *fv)
{
	return fv->value.string;
}

static gboolean
val_from_string(fvalue_t *fv, char *s, LogFunc logfunc _U_)
{
	/* Free up the old value, if we have one */
	string_fvalue_free(fv);

	fv->value.string = g_strdup(s);
	return TRUE;
}

static gboolean
val_from_unparsed(fvalue_t *fv, char *s, gboolean allow_partial_value _U_, LogFunc logfunc)
{
	fvalue_t *fv_bytes;

	/* Free up the old value, if we have one */
	string_fvalue_free(fv);

	/* Does this look like a byte-string? */
	fv_bytes = fvalue_from_unparsed(FT_BYTES, s, TRUE, NULL);
	if (fv_bytes) {
		/* Copy the bytes over to a string and terminate it
		 * with a NUL. XXX - what if the user embeds a NUL
		 * in the middle of the byte string? */
		int num_bytes = fv_bytes->value.bytes->len;

		fv->value.string = g_malloc(num_bytes + 1);
		memcpy(fv->value.string, fv_bytes->value.bytes->data, num_bytes);
		fv->value.string[num_bytes] = '\0';

		FVALUE_FREE(fv_bytes);
		return TRUE;
	}

	/* Just turn it into a string */
	return val_from_string(fv, s, logfunc);
}

static guint
len(fvalue_t *fv)
{
	return (guint)strlen(fv->value.string);
}

static void
slice(fvalue_t *fv, GByteArray *bytes, guint offset, guint length)
{
	guint8* data;

	data = fv->value.ustring + offset;

	g_byte_array_append(bytes, data, length);
}


static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
	return (strcmp(a->value.string, b->value.string) == 0);
}

static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
	return (strcmp(a->value.string, b->value.string) != 0);
}

static gboolean
cmp_gt(fvalue_t *a, fvalue_t *b)
{
	return (strcmp(a->value.string, b->value.string) > 0);
}

static gboolean
cmp_ge(fvalue_t *a, fvalue_t *b)
{
	return (strcmp(a->value.string, b->value.string) >= 0);
}

static gboolean
cmp_lt(fvalue_t *a, fvalue_t *b)
{
	return (strcmp(a->value.string, b->value.string) < 0);
}

static gboolean
cmp_le(fvalue_t *a, fvalue_t *b)
{
	return (strcmp(a->value.string, b->value.string) <= 0);
}

static gboolean
cmp_contains(fvalue_t *fv_a, fvalue_t *fv_b)
{
	/* According to
	* http://www.introl.com/introl-demo/Libraries/C/ANSI_C/string/strstr.html
	* strstr() returns a non-NULL value if needle is an empty
	* string. We don't that behavior for cmp_contains. */
	if (strlen(fv_b->value.string) == 0) {
		return FALSE;
	}

	if (strstr(fv_a->value.string, fv_b->value.string)) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

static gboolean
cmp_matches(fvalue_t *fv_a, fvalue_t *fv_b)
{
	char *str = fv_a->value.string;
	GRegex *regex = fv_b->value.re;

	/* fv_b is always a FT_PCRE, otherwise the dfilter semcheck() would have
	 * warned us. For the same reason (and because we're using g_malloc()),
	 * fv_b->value.re is not NULL.
	 */
	if (strcmp(fv_b->ftype->name, "FT_PCRE") != 0) {
		return FALSE;
	}
	if (! regex) {
		return FALSE;
	}
	return g_regex_match_full(
			regex,		/* Compiled PCRE */
			str,		/* The data to check for the pattern... */
			(int)strlen(str),	/* ... and its length */
			0,		/* Start offset within data */
			0,		/* GRegexMatchFlags */
			NULL,		/* We are not interested in the match information */
			NULL		/* We don't want error information */
			);
}

void
ftype_register_string(void)
{

	static ftype_t string_type = {
		FT_STRING,			/* ftype */
		"FT_STRING",			/* name */
		"character string",		/* pretty_name */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_free,		/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		val_from_string,		/* val_from_string */
		string_to_repr,			/* val_to_string_repr */
		string_repr_len,		/* len_string_repr */

		string_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,				/* cmp_bitwise_and */
		cmp_contains,
		CMP_MATCHES,

		len,
		slice,
	};
	static ftype_t stringz_type = {
		FT_STRINGZ,			/* ftype */
		"FT_STRINGZ",			/* name */
		"character string",		/* pretty name */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_free,		/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		val_from_string,		/* val_from_string */
		string_to_repr,			/* val_to_string_repr */
		string_repr_len,		/* len_string_repr */

		string_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,				/* cmp_bitwise_and */
		cmp_contains,			/* cmp_contains */
		CMP_MATCHES,

		len,
		slice,
	};
	static ftype_t uint_string_type = {
		FT_UINT_STRING,		/* ftype */
		"FT_UINT_STRING",		/* name */
		"character string",		/* pretty_name */
		0,				/* wire_size */
		string_fvalue_new,		/* new_value */
		string_fvalue_free,		/* free_value */
		val_from_unparsed,		/* val_from_unparsed */
		val_from_string,		/* val_from_string */
		string_to_repr,			/* val_to_string_repr */
		string_repr_len,		/* len_string_repr */

		string_fvalue_set,		/* set_value */
		NULL,				/* set_value_uinteger */
		NULL,				/* set_value_sinteger */
		NULL,				/* set_value_integer64 */
		NULL,				/* set_value_floating */

		value_get,			/* get_value */
		NULL,				/* get_value_uinteger */
		NULL,				/* get_value_sinteger */
		NULL,				/* get_value_integer64 */
		NULL,				/* get_value_floating */

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,				/* cmp_bitwise_and */
		cmp_contains,			/* cmp_contains */
		CMP_MATCHES,

		len,
		slice,
	};

	ftype_register(FT_STRING, &string_type);
	ftype_register(FT_STRINGZ, &stringz_type);
	ftype_register(FT_UINT_STRING, &uint_string_type);
}
