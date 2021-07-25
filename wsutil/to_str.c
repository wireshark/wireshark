/* wsutil/to_str.c
 * Routines for utilities to convert various other types to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <glib.h>

#include "to_str.h"

#include <wsutil/utf8_entities.h>
#include <wsutil/wslog.h>


static inline char
low_nibble_of_octet_to_hex(guint8 oct)
{
	/* At least one version of Apple's C compiler/linker is buggy, causing
	   a complaint from the linker about the "literal C string section"
	   not ending with '\0' if we initialize a 16-element "char" array with
	   a 16-character string, the fact that initializing such an array with
	   such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
	   '\0' byte in the string nonwithstanding. */
	static const gchar hex_digits[16] =
	{ '0', '1', '2', '3', '4', '5', '6', '7',
	  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	return hex_digits[oct & 0xF];
}

static inline char *
byte_to_hex(char *out, guint32 dword)
{
	*out++ = low_nibble_of_octet_to_hex(dword >> 4);
	*out++ = low_nibble_of_octet_to_hex(dword);
	return out;
}

/*
 * This does *not* null-terminate the string.  It returns a pointer
 * to the position in the string following the last character it
 * puts there, so that the caller can either put the null terminator
 * in or can append more stuff to the buffer.
 *
 * There needs to be at least len * 2 bytes left in the buffer.
 */
char *
bytes_to_hexstr(char *out, const guint8 *ad, size_t len)
{
	size_t i;

	if (!ad) {
		ws_warning("Null pointer passed to bytes_to_hexstr()");
		return NULL;
	}

	for (i = 0; i < len; i++)
		out = byte_to_hex(out, ad[i]);
	return out;
}

/*
 * This does *not* null-terminate the string.  It returns a pointer
 * to the position in the string following the last character it
 * puts there, so that the caller can either put the null terminator
 * in or can append more stuff to the buffer.
 *
 * There needs to be at least len * 3 - 1 bytes left in the buffer.
 */
char *
bytes_to_hexstr_punct(char *out, const guint8 *ad, size_t len, char punct)
{
	size_t i;

	if (!ad) {
		ws_warning("Null pointer passed to bytes_to_hexstr_punct()");
		return NULL;
	}

	out = byte_to_hex(out, ad[0]);
	for (i = 1; i < len; i++) {
		*out++ = punct;
		out = byte_to_hex(out, ad[i]);
	}
	return out;
}

/* Max string length for displaying byte string.  */
#define	MAX_BYTE_STR_LEN	72

/* Routine to convert a sequence of bytes to a hex string, one byte/two hex
 * digits at at a time, with a specified punctuation character between
 * the bytes.
 *
 * If punct is '\0', no punctuation is applied (and thus
 * the resulting string is (len-1) bytes shorter)
 */
gchar *
bytestring_to_str(wmem_allocator_t *scope, const guint8 *ad, size_t len, const char punct)
{
	gchar *buf;
	size_t buflen = len;
	gchar *buf_ptr;
	int truncated = 0;

	if (len == 0) {
		ws_warning("Zero length passed to bytestring_to_str()");
		return wmem_strdup(scope, "(zero length)");
	}

	if (!ad) {
		ws_warning("Null pointer passed to bytestring_to_str()");
		return wmem_strdup(scope, "(null pointer)");
	}

	if (!punct)
		return bytes_to_str(scope, ad, len);

	buf=(gchar *)wmem_alloc(scope, MAX_BYTE_STR_LEN+3+1);
	if (buflen > MAX_BYTE_STR_LEN/3) {	/* bd_len > 16 */
		truncated = 1;
		buflen = MAX_BYTE_STR_LEN/3;
	}

	buf_ptr = bytes_to_hexstr_punct(buf, ad, buflen, punct); /* max MAX_BYTE_STR_LEN-1 bytes */

	if (truncated) {
		*buf_ptr++ = punct;			/* 1 byte */
		buf_ptr    = g_stpcpy(buf_ptr, UTF8_HORIZONTAL_ELLIPSIS);	/* 3 bytes */
	}

	*buf_ptr = '\0';
	return buf;
}

char *
bytes_to_str(wmem_allocator_t *scope, const guint8 *bd, size_t bd_len)
{
	gchar *cur;
	gchar *cur_ptr;
	int truncated = 0;

	if (bd_len == 0) {
		ws_warning("Zero length passed to bytes_to_str()");
		return wmem_strdup(scope, "(zero length)");
	}

	if (!bd) {
		ws_warning("Null pointer passed to bytes_to_str()");
		return wmem_strdup(scope, "(null pointer)");
	}

	cur=(gchar *)wmem_alloc(scope, MAX_BYTE_STR_LEN+3+1);
	if (bd_len > MAX_BYTE_STR_LEN/2) {	/* bd_len > 24 */
		truncated = 1;
		bd_len = MAX_BYTE_STR_LEN/2;
	}

	cur_ptr = bytes_to_hexstr(cur, bd, bd_len);	/* max MAX_BYTE_STR_LEN bytes */

	if (truncated)
		cur_ptr = g_stpcpy(cur_ptr, UTF8_HORIZONTAL_ELLIPSIS);	/* 3 bytes */

	*cur_ptr = '\0';				/* 1 byte */
	return cur;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
