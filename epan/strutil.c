/* strutil.c
 * String utility routines
 *
 * $Id: strutil.c,v 1.14 2003/12/29 04:06:09 gerald Exp $
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

#if GTK_MAJOR_VERSION >= 2 || GTK_MINOR_VERSION >= 3
/*
 * XXX - "isprint()" can return "true" for non-ASCII characters, but
 * those don't work with GTK+ 1.3 or later, as they take UTF-8 strings
 * as input.  Until we fix up Ethereal to properly handle non-ASCII
 * characters in all output (both GUI displays and text printouts)
 * in those versions of GTK+, we work around the problem by escaping
 * all characters that aren't printable ASCII.
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
  static gchar *fmtbuf;
  static int fmtbuf_len;
  int column;
  const guchar *stringend = string + len;
  guchar c;
  int i;

  /*
   * Allocate the buffer if it's not already allocated.
   */
  if (fmtbuf == NULL) {
    fmtbuf = g_malloc(INITIAL_FMTBUF_SIZE);
    fmtbuf_len = INITIAL_FMTBUF_SIZE;
  }
  column = 0;
  while (string < stringend) {
    /*
     * Is there enough room for this character, if it expands to
     * a backslash plus 3 octal digits (which is the most it can
     * expand to), and also enough room for a terminating '\0'?
     */
    if (column+3+1 >= fmtbuf_len) {
      /*
       * Double the buffer's size if it's not big enough.
       * The size of the buffer starts at 128, so doubling its size
       * adds at least another 128 bytes, which is more than enough
       * for one more character plus a terminating '\0'.
       */
      fmtbuf_len = fmtbuf_len * 2;
      fmtbuf = g_realloc(fmtbuf, fmtbuf_len);
    }
    c = *string++;

    if (isprint(c)) {
      fmtbuf[column] = c;
      column++;
    } else {
      fmtbuf[column] =  '\\';
      column++;
      switch (c) {

      case '\\':
	fmtbuf[column] = '\\';
	column++;
	break;

      case '\a':
	fmtbuf[column] = 'a';
	column++;
	break;

      case '\b':
	fmtbuf[column] = 'b';
	column++;
	break;

      case '\f':
	fmtbuf[column] = 'f';
	column++;
	break;

      case '\n':
	fmtbuf[column] = 'n';
	column++;
	break;

      case '\r':
	fmtbuf[column] = 'r';
	column++;
	break;

      case '\t':
	fmtbuf[column] = 't';
	column++;
	break;

      case '\v':
	fmtbuf[column] = 'v';
	column++;
	break;

      default:
	i = (c>>6)&03;
	fmtbuf[column] = i + '0';
	column++;
	i = (c>>3)&07;
	fmtbuf[column] = i + '0';
	column++;
	i = (c>>0)&07;
	fmtbuf[column] = i + '0';
	column++;
	break;
      }
    }
  }
  fmtbuf[column] = '\0';
  return fmtbuf;
}

/* Max string length for displaying byte string.  */
#define	MAX_BYTE_STR_LEN	32

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
  static gchar  str[N_BYTES_TO_STR_STRINGS][MAX_BYTE_STR_LEN+3+1];
  static int    cur_idx;
  gchar        *cur;
  gchar        *p;
  int           len;
  static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

  cur_idx++;
  if (cur_idx >= N_BYTES_TO_STR_STRINGS)
    cur_idx = 0;
  cur = &str[cur_idx][0];
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
hex_str_to_bytes(const guchar *hex_str, const GByteArray *bytes) {
	guint8		val;
	guchar		*p, *q, *punct;
	char		two_digits[3];
	char		one_digit[2];

	g_byte_array_set_size(bytes, 0);
	p = (guchar *)hex_str;
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
				else {
					return FALSE;
					break;
				}
			}
			else {
				p = punct;
				continue;
			}
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
