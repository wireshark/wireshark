/* strutil.c
 * String utility routines
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include "strutil.h"
#include "emem.h"

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#endif

/*
 * Given a pointer into a data buffer, and to the end of the buffer,
 * find the end of the (putative) line at that position in the data
 * buffer.
 * Return a pointer to the EOL character(s) in "*eol".
 */
const guchar *
find_line_end(const guchar *data, const guchar *dataend, const guchar **eol)
{
  const guchar *lineend;

  lineend = memchr(data, '\n', dataend - data);
  if (lineend == NULL) {
    /*
     * No LF - line is probably continued in next TCP segment.
     */
    lineend = dataend;
    *eol = dataend;
  } else {
    /*
     * Is the LF at the beginning of the line?
     */
    if (lineend > data) {
      /*
       * No - is it preceded by a carriage return?
       * (Perhaps it's supposed to be, but that's not guaranteed....)
       */
      if (*(lineend - 1) == '\r') {
        /*
	 * Yes.  The EOL starts with the CR.
	 */
        *eol = lineend - 1;
      } else {
        /*
         * No.  The EOL starts with the LF.
         */
        *eol = lineend;

        /*
         * I seem to remember that we once saw lines ending with LF-CR
         * in an HTTP request or response, so check if it's *followed*
         * by a carriage return.
         */
        if (lineend < (dataend - 1) && *(lineend + 1) == '\r') {
          /*
           * It's <non-LF><LF><CR>; say it ends with the CR.
           */
          lineend++;
        }
      }
    } else {
      /*
       * Yes - the EOL starts with the LF.
       */
      *eol = lineend;
    }

    /*
     * Point to the character after the last character.
     */
    lineend++;
  }
  return lineend;
}

/*
 * Get the length of the next token in a line, and the beginning of the
 * next token after that (if any).
 * Return 0 if there is no next token.
 */
int
get_token_len(const guchar *linep, const guchar *lineend,
	      const guchar **next_token)
{
  const guchar *tokenp;
  int token_len;

  tokenp = linep;

  /*
   * Search for a blank, a CR or an LF, or the end of the buffer.
   */
  while (linep < lineend && *linep != ' ' && *linep != '\r' && *linep != '\n')
      linep++;
  token_len = linep - tokenp;

  /*
   * Skip trailing blanks.
   */
  while (linep < lineend && *linep == ' ')
    linep++;

  *next_token = linep;

  return token_len;
}


#define	INITIAL_FMTBUF_SIZE	128

#if GLIB_MAJOR_VERSION >= 2
/*
 * XXX - "isprint()" can return "true" for non-ASCII characters, but
 * those don't work with GTK+ 1.3 or later, as they take UTF-8 strings
 * as input.  Until we fix up Ethereal to properly handle non-ASCII
 * characters in all output (both GUI displays and text printouts)
 * in those versions of GTK+, we work around the problem by escaping
 * all characters that aren't printable ASCII.
 *
 * We don't know what version of GTK+ we're using, as epan doesn't
 * use any GTK+ stuff; we use GLib as a proxy for that, with GLib 2.x
 * implying GTK+ 1.3 or later (we don't support GLib 1.3[.x]).
 */
#undef isprint
#define isprint(c) (c >= 0x20 && c < 0x7f)
#endif

/*
 * Given a string, generate a string from it that shows non-printable
 * characters as C-style escapes, and return a pointer to it.
 */
gchar *
format_text(const guchar *string, int len)
{
  static gchar *fmtbuf[3];
  static int fmtbuf_len[3];
  static int idx;
  int column;
  const guchar *stringend = string + len;
  guchar c;
  int i;

  idx = (idx + 1) % 3;

  /*
   * Allocate the buffer if it's not already allocated.
   */
  if (fmtbuf[idx] == NULL) {
    fmtbuf[idx] = g_malloc(INITIAL_FMTBUF_SIZE);
    fmtbuf_len[idx] = INITIAL_FMTBUF_SIZE;
  }
  column = 0;
  while (string < stringend) {
    /*
     * Is there enough room for this character, if it expands to
     * a backslash plus 3 octal digits (which is the most it can
     * expand to), and also enough room for a terminating '\0'?
     */
    if (column+3+1 >= fmtbuf_len[idx]) {
      /*
       * Double the buffer's size if it's not big enough.
       * The size of the buffer starts at 128, so doubling its size
       * adds at least another 128 bytes, which is more than enough
       * for one more character plus a terminating '\0'.
       */
      fmtbuf_len[idx] = fmtbuf_len[idx] * 2;
      fmtbuf[idx] = g_realloc(fmtbuf[idx], fmtbuf_len[idx]);
    }
    c = *string++;

    if (isprint(c)) {
      fmtbuf[idx][column] = c;
      column++;
    } else {
      fmtbuf[idx][column] =  '\\';
      column++;
      switch (c) {

      case '\a':
	fmtbuf[idx][column] = 'a';
	column++;
	break;

      case '\b':
	fmtbuf[idx][column] = 'b';
	column++;
	break;

      case '\f':
	fmtbuf[idx][column] = 'f';
	column++;
	break;

      case '\n':
	fmtbuf[idx][column] = 'n';
	column++;
	break;

      case '\r':
	fmtbuf[idx][column] = 'r';
	column++;
	break;

      case '\t':
	fmtbuf[idx][column] = 't';
	column++;
	break;

      case '\v':
	fmtbuf[idx][column] = 'v';
	column++;
	break;

      default:
	i = (c>>6)&03;
	fmtbuf[idx][column] = i + '0';
	column++;
	i = (c>>3)&07;
	fmtbuf[idx][column] = i + '0';
	column++;
	i = (c>>0)&07;
	fmtbuf[idx][column] = i + '0';
	column++;
	break;
      }
    }
  }
  fmtbuf[idx][column] = '\0';
  return fmtbuf[idx];
}

/* Max string length for displaying byte string.  */
#define	MAX_BYTE_STR_LEN	48

/* Turn an array of bytes into a string showing the bytes in hex. */
#define	N_BYTES_TO_STR_STRINGS	6
gchar *
bytes_to_str(const guint8 *bd, int bd_len) {
  return bytes_to_str_punct(bd,bd_len,'\0');
}

/* Turn an array of bytes into a string showing the bytes in hex with
 * punct as a bytes separator.
 */
gchar *
bytes_to_str_punct(const guint8 *bd, int bd_len, gchar punct) {
  gchar        *cur;
  gchar        *p;
  int           len;
  static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

  cur=ep_alloc(MAX_BYTE_STR_LEN+3+1);
  p = cur;
  len = MAX_BYTE_STR_LEN;
  while (bd_len > 0 && len > 0) {
    *p++ = hex[(*bd) >> 4];
    *p++ = hex[(*bd) & 0xF];
    len -= 2;
    bd++;
    bd_len--;
    if(punct && bd_len > 0){
      *p++ = punct;
      len--;
    }
  }
  if (bd_len != 0) {
    /* Note that we're not showing the full string.  */
    *p++ = '.';
    *p++ = '.';
    *p++ = '.';
  }
  *p = '\0';
  return cur;
}

static gboolean
is_byte_sep(guint8 c)
{
	return (c == '-' || c == ':' || c == '.');
}

/* Turn a string of hex digits with optional separators (defined by
 * is_byte_sep() into a byte array.
 */
gboolean
hex_str_to_bytes(const char *hex_str, GByteArray *bytes, gboolean force_separators) {
	guint8		val;
	const guchar	*p, *q, *punct;
	char		two_digits[3];
	char		one_digit[2];

	g_byte_array_set_size(bytes, 0);
	p = (const guchar *)hex_str;
	while (*p) {
		q = p+1;
		if (*q && isxdigit(*p) && isxdigit(*q)) {
			two_digits[0] = *p;
			two_digits[1] = *q;
			two_digits[2] = '\0';

			/*
			 * Two or more hex digits in a row.
			 * "strtoul()" will succeed, as it'll see at
			 * least one hex digit.
			 */
			val = (guint8) strtoul(two_digits, NULL, 16);
			g_byte_array_append(bytes, &val, 1);
			punct = q + 1;
			if (*punct) {
				/*
				 * Make sure the character after
				 * the second hex digit is a byte
				 * separator, i.e. that we don't have
				 * more than two hex digits, or a
				 * bogus character.
				 */
				if (is_byte_sep(*punct)) {
					p = punct + 1;
					continue;
				}
				else if (force_separators) {
					return FALSE;
					break;
				}
			}
			p = punct;
			continue;
		}
		else if (*q && isxdigit(*p) && is_byte_sep(*q)) {
			one_digit[0] = *p;
			one_digit[1] = '\0';

			/*
			 * Only one hex digit.
			 * "strtoul()" will succeed, as it'll see that
			 * hex digit.
			 */
			val = (guint8) strtoul(one_digit, NULL, 16);
			g_byte_array_append(bytes, &val, 1);
			p = q + 1;
			continue;
		}
		else if (!*q && isxdigit(*p)) {
			one_digit[0] = *p;
			one_digit[1] = '\0';

			/*
			 * Only one hex digit.
			 * "strtoul()" will succeed, as it'll see that
			 * hex digit.
			 */
			val = (guint8) strtoul(one_digit, NULL, 16);
			g_byte_array_append(bytes, &val, 1);
			p = q;
			continue;
		}
		else {
			return FALSE;
		}
	}
	return TRUE;
}

#define SUBID_BUF_LEN 5
gboolean
oid_str_to_bytes(const char *oid_str, GByteArray *bytes) {
  guint32 subid0, subid, sicnt, i;
  const char *p, *dot;
  guint8 buf[SUBID_BUF_LEN];

  g_byte_array_set_size(bytes, 0);

  /* check syntax */
  p = oid_str;
  dot = NULL;
  while (*p) {
    if (!isdigit(*p) && (*p != '.')) return FALSE;
    if (*p == '.') {
      if (p == oid_str) return FALSE;
      if (!*(p+1)) return FALSE;
      if ((p-1) == dot) return FALSE;
      dot = p;
    }
    p++;
  }
  if (!dot) return FALSE;

  p = oid_str;
  sicnt = 0;
  subid0 = 0;	/* squelch GCC complaints */
  while (*p) {
    subid = 0;
    while (isdigit(*p)) {
      subid *= 10;
      subid += *p - '0';
      p++;
    }
    if (sicnt == 0) {
      subid0 = subid;
      if (subid0 > 2) return FALSE;
    } else if (sicnt == 1) {
      if ((subid0 < 2) && (subid > 39)) return FALSE;
      subid += 40 * subid0;
    }
    if (sicnt) {
      i = SUBID_BUF_LEN;
      do {
        i--;
        buf[i] = 0x80 | (subid % 0x80);
        subid >>= 7;
      } while (subid && i);
      buf[SUBID_BUF_LEN-1] &= 0x7F;
      g_byte_array_append(bytes, buf + i, SUBID_BUF_LEN - i);
    }
    sicnt++;
    if (*p) p++;
  }

  return TRUE;
}


/* Return a XML escaped representation of the unescaped string.
 * The returned string must be freed when no longer in use. */
gchar *
xml_escape(const gchar *unescaped)
{
	GString *buffer = g_string_sized_new(128);
	const gchar *p;
	gchar c;
#if GLIB_MAJOR_VERSION < 2
	gchar *ret;
#endif

	p = unescaped;
	while ( (c = *p++) ) {
		switch (c) {
			case '<':
				g_string_append(buffer, "&lt;");
				break;
			case '>':
				g_string_append(buffer, "&gt;");
				break;
			case '&':
				g_string_append(buffer, "&amp;");
				break;
			case '\'':
				g_string_append(buffer, "&apos;");
				break;
			case '"':
				g_string_append(buffer, "&quot;");
				break;
			default:
				g_string_append_c(buffer, c);
				break;
		}
	}
#if GLIB_MAJOR_VERSION >= 2
	/* Return the string value contained within the GString
	 * after getting rid of the GString structure.
	 * This is the way to do this, see the GLib reference. */
	return g_string_free(buffer, FALSE);
#else
	/* But it's not the way to do it in GLib 1.2[.x], as
	 * 1.2[.x]'s "g_string_free()" doesn't return anything.
	 * This is the way to do this in GLib 1.2[.x]. */
	ret = buffer->str;
	g_string_free(buffer, FALSE);
	return ret;
#endif
}


/* Return the first occurrence of needle in haystack.
 * If not found, return NULL.
 * If either haystack or needle has 0 length, return NULL.
 * Algorithm copied from GNU's glibc 2.3.2 memcmp() */
const guint8 *
epan_memmem(const guint8 *haystack, guint haystack_len,
		const guint8 *needle, guint needle_len)
{
	const guint8 *begin;
	const guint8 *const last_possible
		= haystack + haystack_len - needle_len;

	if (needle_len == 0) {
		return NULL;
	}

	if (needle_len > haystack_len) {
		return NULL;
	}

	for (begin = haystack ; begin <= last_possible; ++begin) {
		if (begin[0] == needle[0] &&
			!memcmp(&begin[1], needle + 1,
				needle_len - 1)) {
			return begin;
		}
	}

	return NULL;
}

/*
 * Scan the search string to make sure it's valid hex.  Return the
 * number of bytes in nbytes.
 */
guint8 *
convert_string_to_hex(const char *string, size_t *nbytes)
{
  size_t n_bytes;
  const char *p;
  guchar c;
  guint8 *bytes, *q, byte_val;

  n_bytes = 0;
  p = &string[0];
  for (;;) {
    c = *p++;
    if (c == '\0')
      break;
    if (isspace(c))
      continue;	/* allow white space */
    if (c==':' || c=='.' || c=='-')
      continue; /* skip any ':', '.', or '-' between bytes */
    if (!isxdigit(c)) {
      /* Not a valid hex digit - fail */
      return NULL;
    }

    /*
     * We can only match bytes, not nibbles; we must have a valid
     * hex digit immediately after that hex digit.
     */
    c = *p++;
    if (!isxdigit(c))
      return NULL;

    /* 2 hex digits = 1 byte */
    n_bytes++;
  }

  /*
   * Were we given any hex digits?
   */
  if (n_bytes == 0) {
      /* No. */
      return NULL;
  }

  /*
   * OK, it's valid, and it generates "n_bytes" bytes; generate the
   * raw byte array.
   */
  bytes = g_malloc(n_bytes);
  p = &string[0];
  q = &bytes[0];
  for (;;) {
    c = *p++;
    if (c == '\0')
      break;
    if (isspace(c))
      continue;	/* allow white space */
    if (c==':' || c=='.' || c=='-')
      continue; /* skip any ':', '.', or '-' between bytes */
    /* From the loop above, we know this is a hex digit */
    if (isdigit(c))
      byte_val = c - '0';
    else if (c >= 'a')
      byte_val = (c - 'a') + 10;
    else
      byte_val = (c - 'A') + 10;
    byte_val <<= 4;

    /* We also know this is a hex digit */
    c = *p++;
    if (isdigit(c))
      byte_val |= c - '0';
    else if (c >= 'a')
      byte_val |= (c - 'a') + 10;
    else if (c >= 'A')
      byte_val |= (c - 'A') + 10;

    *q++ = byte_val;
  }
  *nbytes = n_bytes;
  return bytes;
}

/*
 * Copy if if it's a case-sensitive search; uppercase it if it's
 * a case-insensitive search.
 */
char *
convert_string_case(const char *string, gboolean case_insensitive)
{
  char *out_string;
  const char *p;
  char c;
  char *q;

  if (case_insensitive) {
    out_string = g_malloc(strlen(string) + 1);
    for (p = &string[0], q = &out_string[0]; (c = *p) != '\0'; p++, q++)
      *q = toupper((unsigned char)*p);
    *q = '\0';
  } else
    out_string = g_strdup(string);
  return out_string;
}

/* g_strlcat() does not exist in GLib 1.2[.x] */
#if GLIB_MAJOR_VERSION < 2
gsize
g_strlcat(gchar *dst, gchar *src, gsize size)
{
	int strl, strs;
	strl=strlen(dst);
	strs=strlen(src);
	if(strl<size)
		g_snprintf(dst+strl, size-strl, "%s", src);
	dst[size-1]=0;
	return strl+strs;
}
#endif

#ifdef _WIN32

/*
 * XXX - Should we use g_utf8_to_utf16() and g_utf16_to_utf8()
 * instead?  The goal of the functions below was to provide simple
 * wrappers for UTF-8 <-> UTF-16 conversion without making the
 * caller worry about freeing up memory afterward.
 */

/* Convert from UTF-8 to UTF-16. */
wchar_t * utf_8to16(const char *utf8str) {
  static wchar_t *utf16buf[3];
  static int utf16buf_len[3];
  static int idx;

  if (utf8str == NULL)
    return NULL;

  idx = (idx + 1) % 3;

  /*
   * Allocate the buffer if it's not already allocated.
   */
  if (utf16buf[idx] == NULL) {
    utf16buf_len[idx] = INITIAL_FMTBUF_SIZE;
    utf16buf[idx] = g_malloc(utf16buf_len[idx] * sizeof(wchar_t));
  }

  while (MultiByteToWideChar(CP_UTF8, 0, utf8str,
      -1, NULL, 0) >= utf16buf_len[idx]) {
    /*
     * Double the buffer's size if it's not big enough.
     * The size of the buffer starts at 128, so doubling its size
     * adds at least another 128 bytes, which is more than enough
     * for one more character plus a terminating '\0'.
     */
    utf16buf_len[idx] *= 2;
    utf16buf[idx] = g_realloc(utf16buf[idx], utf16buf_len[idx] * sizeof(wchar_t));
  }

  if (MultiByteToWideChar(CP_UTF8, 0, utf8str,
      -1, utf16buf[idx], utf16buf_len[idx]) == 0)
    return NULL;

  return utf16buf[idx];
}

/* Convert from UTF-16 to UTF-8. */
gchar * utf_16to8(const wchar_t *utf16str) {
  static gchar *utf8buf[3];
  static int utf8buf_len[3];
  static int idx;

  if (utf16str == NULL)
    return NULL;

  idx = (idx + 1) % 3;

  /*
   * Allocate the buffer if it's not already allocated.
   */
  if (utf8buf[idx] == NULL) {
    utf8buf_len[idx] = INITIAL_FMTBUF_SIZE;
    utf8buf[idx] = g_malloc(utf8buf_len[idx]);
  }

  while (WideCharToMultiByte(CP_UTF8, 0, utf16str, -1,
      NULL, 0, NULL, NULL) >= utf8buf_len[idx]) {
    /*
     * Double the buffer's size if it's not big enough.
     * The size of the buffer starts at 128, so doubling its size
     * adds at least another 128 bytes, which is more than enough
     * for one more character plus a terminating '\0'.
     */
    utf8buf_len[idx] *= 2;
    utf8buf[idx] = g_realloc(utf8buf[idx], utf8buf_len[idx]);
  }

  if (WideCharToMultiByte(CP_UTF8, 0, utf16str, -1,
      utf8buf[idx], utf8buf_len[idx], NULL, NULL) == 0)
    return NULL;

  return utf8buf[idx];
}

#endif