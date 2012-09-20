/* strutil.c
 * String utility routines
 *
 * $Id$
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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include "strutil.h"
#include "emem.h"
#include <../isprint.h>


#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#endif

static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
			      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

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
  token_len = (int) (linep - tokenp);

  /*
   * Skip trailing blanks.
   */
  while (linep < lineend && *linep == ' ')
    linep++;

  *next_token = linep;

  return token_len;
}


#define	INITIAL_FMTBUF_SIZE	128

/*
 * Given a string, generate a string from it that shows non-printable
 * characters as C-style escapes, and return a pointer to it.
 */
gchar *
format_text(const guchar *string, size_t len)
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
	fmtbuf[idx][column] = 'b'; /* BS */
	column++;
	break;

      case '\f':
	fmtbuf[idx][column] = 'f'; /* FF */
	column++;
	break;

      case '\n':
	fmtbuf[idx][column] = 'n'; /* NL */
	column++;
	break;

      case '\r':
	fmtbuf[idx][column] = 'r'; /* CR */
	column++;
	break;

      case '\t':
	fmtbuf[idx][column] = 't'; /* tab */
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

/*
 * Given a string, generate a string from it that shows non-printable
 * characters as C-style escapes except a whitespace character
 * (space, tab, carriage return, new line, vertical tab, or formfeed)
 * which will be replaced by a space, and return a pointer to it.
 */
gchar *
format_text_wsp(const guchar *string, size_t len)
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
    } else if  (isspace(c)) {
      fmtbuf[idx][column] = ' ';
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
	fmtbuf[idx][column] = 'b'; /* BS */
	column++;
	break;

      case '\f':
	fmtbuf[idx][column] = 'f'; /* FF */
	column++;
	break;

      case '\n':
	fmtbuf[idx][column] = 'n'; /* NL */
	column++;
	break;

      case '\r':
	fmtbuf[idx][column] = 'r'; /* CR */
	column++;
	break;

      case '\t':
	fmtbuf[idx][column] = 't'; /* tab */
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
	const guchar	*p, *q, *r, *s, *punct;
	char		four_digits_first_half[3];
	char		four_digits_second_half[3];
	char		two_digits[3];
	char		one_digit[2];

	if (! hex_str || ! bytes) {
		return FALSE;
	}
	g_byte_array_set_size(bytes, 0);
	p = (const guchar *)hex_str;
	while (*p) {
		q = p+1;
		r = p+2;
		s = p+3;

		if (*q && *r && *s
		    && isxdigit(*p) && isxdigit(*q) &&
		    isxdigit(*r) && isxdigit(*s)) {
			four_digits_first_half[0] = *p;
			four_digits_first_half[1] = *q;
			four_digits_first_half[2] = '\0';
			four_digits_second_half[0] = *r;
			four_digits_second_half[1] = *s;
			four_digits_second_half[2] = '\0';

			/*
			 * Four or more hex digits in a row.
			 */
			val = (guint8) strtoul(four_digits_first_half, NULL, 16);
			g_byte_array_append(bytes, &val, 1);
			val = (guint8) strtoul(four_digits_second_half, NULL, 16);
			g_byte_array_append(bytes, &val, 1);

			punct = s + 1;
			if (*punct) {
				/*
				 * Make sure the character after
				 * the forth hex digit is a byte
				 * separator, i.e. that we don't have
				 * more than four hex digits, or a
				 * bogus character.
				 */
				if (is_byte_sep(*punct)) {
					p = punct + 1;
					continue;
				}
				else if (force_separators) {
					return FALSE;
				}
			}
			p = punct;
			continue;
		}

		else if (*q && isxdigit(*p) && isxdigit(*q)) {
			two_digits[0] = *p;
			two_digits[1] = *q;
			two_digits[2] = '\0';

			/*
			 * Two hex digits in a row.
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
				}
			}
			p = punct;
			continue;
		}
		else if (*q && isxdigit(*p) && is_byte_sep(*q)) {
			one_digit[0] = *p;
			one_digit[1] = '\0';

			/*
			 * Only one hex digit (not at the end of the string)
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
			 * Only one hex digit (at the end of the string)
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

/*
 * Turn an RFC 3986 percent-encoded string into a byte array.
 * XXX - We don't check for reserved characters.
 */
#define HEX_DIGIT_BUF_LEN 3
gboolean
uri_str_to_bytes(const char *uri_str, GByteArray *bytes) {
	guint8		val;
	const guchar	*p;
	guchar		hex_digit[HEX_DIGIT_BUF_LEN];

	g_byte_array_set_size(bytes, 0);
	if (! uri_str) {
		return FALSE;
	}

	p = (const guchar *)uri_str;

	while (*p) {
		if (! isascii(*p) || ! isprint(*p))
			return FALSE;
		if (*p == '%') {
			p++;
			if (*p == '\0') return FALSE;
			hex_digit[0] = *p;
			p++;
			if (*p == '\0') return FALSE;
			hex_digit[1] = *p;
			hex_digit[2] = '\0';
			if (! isxdigit(hex_digit[0]) || ! isxdigit(hex_digit[1]))
				return FALSE;
			val = (guint8) strtoul((char *)hex_digit, NULL, 16);
			g_byte_array_append(bytes, &val, 1);
		} else {
			g_byte_array_append(bytes, (const guint8 *) p, 1);
		}
		p++;

	}
	return TRUE;
}

/*
 * Given a GByteArray, generate a string from it that shows non-printable
 * characters as percent-style escapes, and return a pointer to it.
 */
gchar *
format_uri(const GByteArray *bytes, const gchar *reserved_chars)
{
  static gchar *fmtbuf[3];
  static guint fmtbuf_len[3];
  static guint idx;
  const guchar *reserved_def = ":/?#[]@!$&'()*+,;= ";
  const guchar *reserved = reserved_def;
  guint8 c;
  guint column, i;
  gboolean is_reserved = FALSE;

  if (! bytes)
    return "";

  idx = (idx + 1) % 3;
  if (reserved_chars)
    reserved = reserved_chars;

  /*
   * Allocate the buffer if it's not already allocated.
   */
  if (fmtbuf[idx] == NULL) {
    fmtbuf[idx] = g_malloc(INITIAL_FMTBUF_SIZE);
    fmtbuf_len[idx] = INITIAL_FMTBUF_SIZE;
  }
  for (column = 0; column < bytes->len; column++) {
    /*
     * Is there enough room for this character, if it expands to
     * a percent plus 2 hex digits (which is the most it can
     * expand to), and also enough room for a terminating '\0'?
     */
    if (column+2+1 >= fmtbuf_len[idx]) {
      /*
       * Double the buffer's size if it's not big enough.
       * The size of the buffer starts at 128, so doubling its size
       * adds at least another 128 bytes, which is more than enough
       * for one more character plus a terminating '\0'.
       */
      fmtbuf_len[idx] = fmtbuf_len[idx] * 2;
      fmtbuf[idx] = g_realloc(fmtbuf[idx], fmtbuf_len[idx]);
    }
    c = bytes->data[column];

    if (!isascii(c) || !isprint(c) || c == '%') {
      is_reserved = TRUE;
    }

    for (i = 0; reserved[i]; i++) {
      if (c == reserved[i])
	is_reserved = TRUE;
    }

    if (!is_reserved) {
      fmtbuf[idx][column] = c;
    } else {
      fmtbuf[idx][column] = '%';
      column++;
      fmtbuf[idx][column] = hex[c >> 4];
      column++;
      fmtbuf[idx][column] = hex[c & 0xF];
    }
  }
  fmtbuf[idx][column] = '\0';
  return fmtbuf[idx];
}

/**
 * Create a copy of a GByteArray
 *
 * @param ba The byte array to be copied.
 * @return If ba exists, a freshly allocated copy.  NULL otherwise.
 *
 */
GByteArray *
byte_array_dup(GByteArray *ba) {
    GByteArray *new_ba;

    if (!ba)
	return NULL;

    new_ba = g_byte_array_new();
    g_byte_array_append(new_ba, ba->data, ba->len);
    return new_ba;
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
    if (!isdigit((guchar)*p) && (*p != '.')) return FALSE;
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
    while (isdigit((guchar)*p)) {
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

/**
 * Compare the contents of two GByteArrays
 *
 * @param ba1 A byte array
 * @param ba2 A byte array
 * @return If both arrays are non-NULL and their lengths are equal and
 *         their contents are equal, returns TRUE.  Otherwise, returns
 *         FALSE.
 *
 * XXX - Should this be in strutil.c?
 */
gboolean
byte_array_equal(GByteArray *ba1, GByteArray *ba2) {
    if (!ba1 || !ba2)
	return FALSE;

    if (ba1->len != ba2->len)
	return FALSE;

    if (memcmp(ba1->data, ba2->data, ba1->len) != 0)
	return FALSE;

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
	/* Return the string value contained within the GString
	 * after getting rid of the GString structure.
	 * This is the way to do this, see the GLib reference. */
	return g_string_free(buffer, FALSE);
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

  if (case_insensitive) {
    return g_utf8_strup(string, -1);
  } else {
    return g_strdup(string);
  }
}

char *
epan_strcasestr(const char *haystack, const char *needle)
{
	gsize hlen = strlen(haystack);
	gsize nlen = strlen(needle);

	while (hlen-- >= nlen) {
		if (!g_ascii_strncasecmp(haystack, needle, nlen))
			return (char*) haystack;
		haystack++;
	}
	return NULL;
}

const char *
string_or_null(const char *string)
{
  if (string)
    return string;
  return "[NULL]";
}

int
escape_string_len(const char *string)
{
	const char *p;
	gchar c;
	int repr_len;

	repr_len = 0;
	for (p = string; (c = *p) != '\0'; p++) {
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

char *
escape_string(char *buf, const char *string)
{
  const gchar *p;
  gchar c;
  char *bufp;
  char hexbuf[3];

  bufp = buf;
  *bufp++ = '"';
  for (p = string; (c = *p) != '\0'; p++) {
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
		g_snprintf(hexbuf,sizeof(hexbuf), "%02x", (unsigned char) c);
		*bufp++ = '\\';
		*bufp++ = 'x';
		*bufp++ = hexbuf[0];
		*bufp++ = hexbuf[1];
	}
	/* Other characters are just passed through. */
	else {
		*bufp++ = c;
	}
  }
  *bufp++ = '"';
  *bufp = '\0';
  return buf;
}

#define GN_CHAR_ALPHABET_SIZE 128

static gunichar IA5_default_alphabet[GN_CHAR_ALPHABET_SIZE] = {

    /*ITU-T recommendation T.50 specifies International Reference Alphabet 5 (IA5) */

    '?', '?', '?', '?', '?', '?', '?', '?',
    '?', '?', '?', '?', '?', '?', '?', '?',
    '?', '?', '?', '?', '?', '?', '?', '?',
    '?', '?', '?', '?', '?', '?', '?', '?',
    ' ', '!', '\"','#', '$', '%', '&', '\'',
    '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
    'X',  'Y',  'Z',  '[',  '\\',  ']',  '^',  '_',
    '`', 'a',  'b',  'c',  'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
    'x',  'y',  'z',  '{',  '|',  '}',  '~',  '?'
};

static gunichar
char_def_ia5_alphabet_decode(unsigned char value)
{
    if (value < GN_CHAR_ALPHABET_SIZE)
    {
		return IA5_default_alphabet[value];
    }
    else
    {
		return '?';
    }
}

void
IA5_7BIT_decode(unsigned char * dest, const unsigned char* src, int len)
{
    int i, j;
    gunichar buf;


    for (i = 0, j = 0; j < len;  j++)
    {
	    buf = char_def_ia5_alphabet_decode(src[j]);
	    i += g_unichar_to_utf8(buf,&(dest[i]));
    }
    dest[i]=0;
    return;
}

/*
 * This function takes a string and copies it, inserting a 'chr' before
 * every 'chr' in it.
 */
gchar*
ws_strdup_escape_char (const gchar *str, const gchar chr)
{
	const gchar *p;
	gchar *q, *new_str;

	if(!str)
		return NULL;

	p = str;
	/* Worst case: A string that is full of 'chr' */
	q = new_str = g_malloc (strlen(str) * 2 + 1);

	while(*p != 0)
	{
		if(*p == chr)
			*q++ = chr;

		*q++ = *p++;
	}
	*q = '\0';

	return new_str;
}

/*
 * This function takes a string and copies it, removing any occurences of double
 * 'chr' with a single 'chr'.
 */
gchar*
ws_strdup_unescape_char (const gchar *str, const char chr)
{
	const gchar *p;
	gchar *q, *new_str;

	if(!str)
		return NULL;

	p = str;
	/* Worst case: A string that contains no 'chr' */
	q = new_str = g_malloc (strlen(str) + 1);

	while(*p != 0)
	{
		*q++ = *p;
		if ((*p == chr) && (*(p+1) == chr))
			p += 2;
		else
			p++;
	}
	*q = '\0';

	return new_str;
}

/* Create a newly-allocated string with replacement values. */
gchar *string_replace(const gchar* str, const gchar *old_val, const gchar *new_val) {
	gchar **str_parts;
	gchar *new_str;

	if (!str || !old_val) {
		return NULL;
	}

	str_parts = g_strsplit(str, old_val, 0);
	new_str = g_strjoinv(new_val, str_parts);
	g_strfreev(str_parts);

	return new_str;
}
