/* packet-smb-common.c
 * Common routines for smb packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include "packet-smb-common.h"

/*
 * Share type values - used in LANMAN and in SRVSVC.
 *
 * XXX - should we dissect share type values, at least in SRVSVC, as
 * a subtree with bitfields, as the 0x80000000 bit appears to be a
 * hidden bit, with some number of bits at the bottom being the share
 * type?
 *
 * Does LANMAN use that bit?
 */
const value_string share_type_vals[] = {
	{0, "Directory tree"},
	{1, "Printer queue"},
	{2, "Communications device"},
	{3, "IPC"},
	{0x80000000, "Hidden Directory tree"},
	{0x80000001, "Hidden Printer queue"},
	{0x80000002, "Hidden Communications device"},
	{0x80000003, "Hidden IPC"},
	{0, NULL}
};

int display_ms_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, char **data)
{
	char *str;
	gint len;

	/* display a string from the tree and return the new offset */

	str = tvb_get_ephemeral_stringz(tvb, offset, &len);
	proto_tree_add_string(tree, hf_index, tvb, offset, len, str);

	/* Return a copy of the string if requested */

	if (data)
		*data = str;

	return 	offset+len;
}


int display_unicode_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, char **data)
{
	char *str, *p;
	int len;
	int charoffset;
	guint16 character;

	/* display a unicode string from the tree and return new offset */

	/*
	 * Get the length of the string.
	 * XXX - is it a bug or a feature that this will throw an exception
	 * if we don't find the '\0'?  I think it's a feature.
	 */
	len = 0;
	while ((character = tvb_get_letohs(tvb, offset + len)) != '\0')
		len += 2;
	len += 2;	/* count the '\0' too */

	/*
	 * Allocate a buffer for the string; "len" is the length in
	 * bytes, not the length in characters.
	 */
	str = ep_alloc(len/2);

	/*
	 * XXX - this assumes the string is just ISO 8859-1; we need
	 * to better handle multiple character sets in Wireshark,
	 * including Unicode/ISO 10646, and multiple encodings of
	 * that character set (UCS-2, UTF-8, etc.).
	 */
	charoffset = offset;
	p = str;
	while ((character = tvb_get_letohs(tvb, charoffset)) != '\0') {
		*p++ = (char) character;
		charoffset += 2;
	}
	*p = '\0';

	proto_tree_add_string(tree, hf_index, tvb, offset, len, str);

	if (data)
		*data = str;

	return 	offset+len;
}

/* Max string length for displaying Unicode strings.  */
#define	MAX_UNICODE_STR_LEN	256

/* Turn a little-endian Unicode '\0'-terminated string into a string we
   can display.
   XXX - for now, we just handle the ISO 8859-1 characters.
   If exactlen==TRUE then us_lenp contains the exact len of the string in
   bytes. It might not be null terminated !
   bc specifies the number of bytes in the byte parameters; Windows 2000,
   at least, appears, in some cases, to put only 1 byte of 0 at the end
   of a Unicode string if the byte count
*/
static gchar *
unicode_to_str(tvbuff_t *tvb, int offset, int *us_lenp, gboolean exactlen,
		   guint16 bc)
{
  gchar *cur;
  gchar        *p;
  guint16       uchar;
  int           len;
  int           us_len;
  gboolean      overflow = FALSE;

  cur=ep_alloc(MAX_UNICODE_STR_LEN+3+1);
  p = cur;
  len = MAX_UNICODE_STR_LEN;
  us_len = 0;
  for (;;) {
    if (bc == 0)
      break;
    if (bc == 1) {
      /* XXX - explain this */
      if (!exactlen)
        us_len += 1;	/* this is a one-byte null terminator */
      break;
    }
    uchar = tvb_get_letohs(tvb, offset);
    if (uchar == 0) {
      us_len += 2;	/* this is a two-byte null terminator */
      break;
    }
    if (len > 0) {
      if ((uchar & 0xFF00) == 0)
        *p++ = (gchar) uchar;	/* ISO 8859-1 */
      else
        *p++ = '?';	/* not 8859-1 */
      len--;
    } else
      overflow = TRUE;
    offset += 2;
    bc -= 2;
    us_len += 2;
    if(exactlen){
      if(us_len>= *us_lenp){
        break;
      }
    }
  }
  if (overflow) {
    /* Note that we're not showing the full string.  */
    *p++ = '.';
    *p++ = '.';
    *p++ = '.';
  }
  *p = '\0';
  *us_lenp = us_len;
  return cur;
}

/* nopad == TRUE : Do not add any padding before this string
 * exactlen == TRUE : len contains the exact len of the string in bytes.
 * bc: pointer to variable with amount of data left in the byte parameters
 *   region
 */
const gchar *
get_unicode_or_ascii_string(tvbuff_t *tvb, int *offsetp,
    gboolean useunicode, int *len, gboolean nopad, gboolean exactlen,
    guint16 *bcp)
{
  gchar *cur;
  const gchar *string;
  int string_len;
  int copylen;
  gboolean overflow = FALSE;

  if (*bcp == 0) {
    /* Not enough data in buffer */
    return NULL;
  }
  if (useunicode) {
    if ((!nopad) && (*offsetp % 2)) {
      (*offsetp)++;   /* Looks like a pad byte there sometimes */
      (*bcp)--;
      if (*bcp == 0) {
        /* Not enough data in buffer */
        return NULL;
      }
    }
    if(exactlen){
      string_len = *len;
      if (string_len < 0) {
        /* This probably means it's a very large unsigned number; just set
           it to the largest signed number, so that we throw the appropriate
           exception. */
        string_len = INT_MAX;
      }
    }
    string = unicode_to_str(tvb, *offsetp, &string_len, exactlen, *bcp);
  } else {
    if(exactlen){
      /*
       * The string we return must be null-terminated.
       */
      cur=ep_alloc(MAX_UNICODE_STR_LEN+3+1);
      copylen = *len;
      if (copylen < 0) {
        /* This probably means it's a very large unsigned number; just set
           it to the largest signed number, so that we throw the appropriate
           exception. */
        copylen = INT_MAX;
      }
      tvb_ensure_bytes_exist(tvb, *offsetp, copylen);
      if (copylen > MAX_UNICODE_STR_LEN) {
        copylen = MAX_UNICODE_STR_LEN;
        overflow = TRUE;
      }
      tvb_memcpy(tvb, (guint8 *)cur, *offsetp, copylen);
      cur[copylen] = '\0';
      if (overflow)
        strcat(cur, "...");
      string_len = *len;
      string = cur;
    } else {
      string_len = tvb_strsize(tvb, *offsetp);
      string = tvb_get_ptr(tvb, *offsetp, string_len);
    }
  }
  *len = string_len;
  return string;
}
