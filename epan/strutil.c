/* strutil.c
 * String utility routines
 *
 * $Id: strutil.c,v 1.6 2000/11/13 07:19:32 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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
const u_char *
find_line_end(const u_char *data, const u_char *dataend, const u_char **eol)
{
  const u_char *lineend;

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
get_token_len(const u_char *linep, const u_char *lineend,
	      const u_char **next_token)
{
  const u_char *tokenp;
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

/*
 * Given a string, generate a string from it that shows non-printable
 * characters as C-style escapes, and return a pointer to it.
 */
gchar *
format_text(const u_char *string, int len)
{
  static gchar *fmtbuf;
  static int fmtbuf_len;
  int column;
  const u_char *stringend = string + len;
  u_char c;
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
