/* column-utils.c
 * Routines for column utilities.
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

#include <string.h>
#include <time.h>

#include "column-utils.h"
#include "timestamp.h"
#include "to_str.h"
#include "packet_info.h"
#include "wsutil/pint.h"
#include "addr_resolv.h"
#include "address_types.h"
#include "ipv6.h"
#include "osi-utils.h"
#include "value_string.h"
#include "column-info.h"
#include "proto.h"

#include <epan/strutil.h>
#include <epan/epan.h>
#include <epan/dfilter/dfilter.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/ws_printf.h>

#ifdef HAVE_LUA
#include <epan/wslua/wslua.h>
#endif

/* Allocate all the data structures for constructing column data, given
   the number of columns. */
void
col_setup(column_info *cinfo, const gint num_cols)
{
  int i;

  cinfo->num_cols              = num_cols;
  cinfo->columns               = g_new(col_item_t, num_cols);
  cinfo->col_first             = g_new(int, NUM_COL_FMTS);
  cinfo->col_last              = g_new(int, NUM_COL_FMTS);
  for (i = 0; i < num_cols; i++) {
    cinfo->columns[i].col_custom_fields_ids = NULL;
  }
  cinfo->col_expr.col_expr     = g_new(const gchar*, num_cols + 1);
  cinfo->col_expr.col_expr_val = g_new(gchar*, num_cols + 1);

  for (i = 0; i < NUM_COL_FMTS; i++) {
    cinfo->col_first[i] = -1;
    cinfo->col_last[i] = -1;
  }
  cinfo->prime_regex = g_regex_new(COL_CUSTOM_PRIME_REGEX,
    G_REGEX_ANCHORED, G_REGEX_MATCH_ANCHORED, NULL);
}

static void
col_custom_ids_free_wrapper(gpointer data, gpointer user_data _U_)
{
  g_free(data);
}

static void
col_custom_fields_ids_free(GSList** custom_fields_id)
{
  if (*custom_fields_id != NULL) {
    g_slist_foreach(*custom_fields_id, col_custom_ids_free_wrapper, NULL);
    g_slist_free(*custom_fields_id);
  }
  *custom_fields_id = NULL;
}

/* Cleanup all the data structures for constructing column data; undoes
   the allocations that col_setup() does. */
void
col_cleanup(column_info *cinfo)
{
  int i;
  col_item_t* col_item;

  for (i = 0; i < cinfo->num_cols; i++) {
    col_item = &cinfo->columns[i];
    g_free(col_item->fmt_matx);
    g_free(col_item->col_title);
    g_free(col_item->col_custom_fields);
    dfilter_free(col_item->col_custom_dfilter);
    /* col_item->col_data points to col_buf or static memory */
    g_free(col_item->col_buf);
    g_free(cinfo->col_expr.col_expr_val[i]);
    col_custom_fields_ids_free(&col_item->col_custom_fields_ids);
  }

  g_free(cinfo->columns);
  g_free(cinfo->col_first);
  g_free(cinfo->col_last);
  /*
   * XXX - MSVC doesn't correctly handle the "const" qualifier; it thinks
   * "const XXX **" means "pointer to const pointer to XXX", i.e. that
   * it's a pointer to something that's "const"ant, not "pointer to
   * pointer to const XXX", i.e. that it's a pointer to a pointer to
   * something that's "const"ant.  Cast its bogus complaints away.
   */
  g_free((gchar **)cinfo->col_expr.col_expr);
  g_free(cinfo->col_expr.col_expr_val);
  g_regex_unref(cinfo->prime_regex);
}

/* Initialize the data structures for constructing column data. */
void
col_init(column_info *cinfo, const struct epan_session *epan)
{
  int i;
  col_item_t* col_item;

  if (!cinfo)
    return;

  for (i = 0; i < cinfo->num_cols; i++) {
    col_item = &cinfo->columns[i];
    col_item->col_buf[0] = '\0';
    col_item->col_data = col_item->col_buf;
    col_item->col_fence = 0;
    col_item->writable = TRUE;
    cinfo->col_expr.col_expr[i] = "";
    cinfo->col_expr.col_expr_val[i][0] = '\0';
  }
  cinfo->writable = TRUE;
  cinfo->epan = epan;
}

gboolean
col_get_writable(column_info *cinfo, const gint col)
{
  int i;
  col_item_t* col_item;

  if (cinfo == NULL)
    return FALSE;

  /* "global" (not) writeability will always override
     an individual column */
  if ((col == -1) || (cinfo->writable == FALSE))
    return cinfo->writable;

  if (cinfo->col_first[col] >= 0) {
    for (i = cinfo->col_first[col]; i <= cinfo->col_last[col]; i++) {
      col_item = &cinfo->columns[i];
      if (col_item->fmt_matx[col]) {
        return col_item->writable;
      }
    }
  }
  return FALSE;
}

void
col_set_writable(column_info *cinfo, const gint col, const gboolean writable)
{
  int i;
  col_item_t* col_item;

  if (cinfo) {
    if (col == -1) {
      cinfo->writable = writable;
    } else if (cinfo->col_first[col] >= 0) {
      for (i = cinfo->col_first[col]; i <= cinfo->col_last[col]; i++) {
        col_item = &cinfo->columns[i];
        if (col_item->fmt_matx[col]) {
          col_item->writable = writable;
        }
      }
    }
  }
}

/* Checks to see if a particular packet information element is needed for the packet list */
#define CHECK_COL(cinfo, el) \
    /* We are constructing columns, and they're writable */ \
    (col_get_writable(cinfo, el) && \
      /* There is at least one column in that format */ \
    ((cinfo)->col_first[el] >= 0))

/* Sets the fence for a column to be at the end of the column. */
void
col_set_fence(column_info *cinfo, const gint el)
{
  int i;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      col_item->col_fence = (int)strlen(col_item->col_data);
    }
  }
}

/* Clear the fence for a column. */
void
col_clear_fence(column_info *cinfo, const gint el)
{
  int i;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
     if (col_item->fmt_matx[el]) {
        col_item->col_fence = 0;
     }
  }
}

/* Gets the text of a column */
const gchar *
col_get_text(column_info *cinfo, const gint el)
{
  int i;
  const gchar* text = NULL;
  col_item_t* col_item;

  if (!(cinfo && (cinfo)->col_first[el] >= 0)) {
    return NULL;
  }

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      text = (col_item->col_data);
    }
  }
  return text;
}


/* Use this to clear out a column, especially if you're going to be
   appending to it later; at least on some platforms, it's more
   efficient than using "col_add_str()" with a null string, and
   more efficient than "col_set_str()" with a null string if you
   later append to it, as the later append will cause a string
   copy to be done. */
void
col_clear(column_info *cinfo, const gint el)
{
  int    i;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      /*
       * At this point, either
       *
       *   1) col_data[i] is equal to col_buf[i], in which case we
       *      don't have to worry about copying col_data[i] to
       *      col_buf[i];
       *
       *   2) col_data[i] isn't equal to col_buf[i], in which case
       *      the only thing that's been done to the column is
       *      "col_set_str()" calls and possibly "col_set_fence()"
       *      calls, in which case the fence is either unset and
       *      at the beginning of the string or set and at the end
       *      of the string - if it's at the beginning, we're just
       *      going to clear the column, and if it's at the end,
       *      we don't do anything.
       */
      if (col_item->col_buf == col_item->col_data || col_item->col_fence == 0) {
        /*
         * The fence isn't at the end of the column, or the column wasn't
         * last set with "col_set_str()", so clear the column out.
         */
        col_item->col_buf[col_item->col_fence] = '\0';
        col_item->col_data = col_item->col_buf;
      }
      cinfo->col_expr.col_expr[i] = "";
      cinfo->col_expr.col_expr_val[i][0] = '\0';
    }
  }
}

#define COL_CHECK_APPEND(col_item, max_len) \
  if (col_item->col_data != col_item->col_buf) {        \
    /* This was set with "col_set_str()"; copy the string they  \
       set it to into the buffer, so we can append to it. */    \
    g_strlcpy(col_item->col_buf, col_item->col_data, max_len);  \
    col_item->col_data = col_item->col_buf;         \
  }

#define COL_CHECK_REF_TIME(fd, buf)         \
  if (fd->flags.ref_time) {                 \
    g_strlcpy(buf, "*REF*", COL_MAX_LEN );  \
    return;                                 \
  }

/* The same as CHECK_COL(), but without the check to see if the column is writable. */
#define HAVE_CUSTOM_COLS(cinfo) ((cinfo) && (cinfo)->col_first[COL_CUSTOM] >= 0)

gboolean
have_custom_cols(column_info *cinfo)
{
  return HAVE_CUSTOM_COLS(cinfo);
}

gboolean
have_field_extractors(void)
{
#ifdef HAVE_LUA
    return wslua_has_field_extractors();
#else
    return FALSE;
#endif
}

/* search in edt tree custom fields */
void col_custom_set_edt(epan_dissect_t *edt, column_info *cinfo)
{
  int i;
  col_item_t* col_item;

  if (!HAVE_CUSTOM_COLS(cinfo))
      return;

  for (i = cinfo->col_first[COL_CUSTOM];
       i <= cinfo->col_last[COL_CUSTOM]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[COL_CUSTOM] &&
        col_item->col_custom_fields &&
        col_item->col_custom_fields_ids) {
        col_item->col_data = col_item->col_buf;
        cinfo->col_expr.col_expr[i] = epan_custom_set(edt, col_item->col_custom_fields_ids,
                                     col_item->col_custom_occurrence,
                                     col_item->col_buf,
                                     cinfo->col_expr.col_expr_val[i],
                                     COL_MAX_LEN);
    }
  }
}

void
col_custom_prime_edt(epan_dissect_t *edt, column_info *cinfo)
{
  int i;
  col_item_t* col_item;

  if (!HAVE_CUSTOM_COLS(cinfo))
    return;

  for (i = cinfo->col_first[COL_CUSTOM];
       i <= cinfo->col_last[COL_CUSTOM]; i++) {
    col_item = &cinfo->columns[i];

    if (col_item->fmt_matx[COL_CUSTOM] &&
        col_item->col_custom_dfilter) {
      epan_dissect_prime_dfilter(edt, col_item->col_custom_dfilter);
    }
  }
}

void
col_append_lstr(column_info *cinfo, const gint el, const gchar *str1, ...)
{
  va_list ap;
  size_t pos, max_len;
  int    i;
  const gchar *str;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      /*
       * First arrange that we can append, if necessary.
       */
      COL_CHECK_APPEND(col_item, max_len);

      pos = strlen(col_item->col_buf);
      if (pos >= max_len)
         return;

      va_start(ap, str1);
      str = str1;
      do {
         if G_UNLIKELY(str == NULL)
             str = "(null)";

         pos += g_strlcpy(&col_item->col_buf[pos], str, max_len - pos);

      } while (pos < max_len && (str = va_arg(ap, const char *)) != COL_ADD_LSTR_TERMINATOR);
      va_end(ap);
    }
  }
}

void
col_append_str_uint(column_info *cinfo, const gint col, const gchar *abbrev, guint32 val, const gchar *sep)
{
  char buf[16];

  guint32_to_str_buf(val, buf, sizeof(buf));
  col_append_lstr(cinfo, col, sep ? sep : "", abbrev, "=", buf, COL_ADD_LSTR_TERMINATOR);
}

static inline void
col_snprint_port(gchar *buf, gulong buf_siz, port_type typ, guint16 val)
{
  const char *str;

  if (gbl_resolv_flags.transport_name &&
        (str = try_serv_name_lookup(typ, val)) != NULL) {
    ws_snprintf(buf, buf_siz, "%s(%"G_GUINT16_FORMAT")", str, val);
  } else {
    ws_snprintf(buf, buf_siz, "%"G_GUINT16_FORMAT, val);
  }
}

void
col_append_ports(column_info *cinfo, const gint col, port_type typ, guint16 src, guint16 dst)
{
  char buf_src[32], buf_dst[32];

  col_snprint_port(buf_src, 32, typ, src);
  col_snprint_port(buf_dst, 32, typ, dst);
  col_append_lstr(cinfo, col, buf_src, UTF8_RIGHTWARDS_ARROW, buf_dst, COL_ADD_LSTR_TERMINATOR);
}

static void
col_do_append_fstr(column_info *cinfo, const int el, const char *separator, const char *format, va_list ap)
{
  size_t len, max_len, sep_len;
  int    i;
  col_item_t* col_item;

  sep_len = (separator) ? strlen(separator) : 0;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      /*
       * First arrange that we can append, if necessary.
       */
      COL_CHECK_APPEND(col_item, max_len);

      len = strlen(col_item->col_buf);

      /*
       * If we have a separator, append it if the column isn't empty.
       */
      if (sep_len != 0 && len != 0) {
        g_strlcat(col_item->col_buf, separator, max_len);
        len += sep_len;
      }

      if (len < max_len) {
        va_list ap2;

        G_VA_COPY(ap2, ap);
        g_vsnprintf(&col_item->col_buf[len], (guint32)(max_len - len), format, ap2);
        va_end(ap2);
      }
    }
  }
}

/*  Appends a vararg list to a packet info string. */
void
col_append_fstr(column_info *cinfo, const gint el, const gchar *format, ...)
{
  va_list ap;

  if (!CHECK_COL(cinfo, el))
    return;

  va_start(ap, format);
  col_do_append_fstr(cinfo, el, NULL, format, ap);
  va_end(ap);
}

/*  Appends a vararg list to a packet info string.
 *  Prefixes it with the given separator if the column is not empty.
 */
void
col_append_sep_fstr(column_info *cinfo, const gint el, const gchar *separator,
                    const gchar *format, ...)
{
  va_list ap;

  if (!CHECK_COL(cinfo, el))
    return;

  if (separator == NULL)
    separator = ", ";    /* default */

  va_start(ap, format);
  col_do_append_fstr(cinfo, el, separator, format, ap);
  va_end(ap);
}

/* Prepends a vararg list to a packet info string. */
#define COL_BUF_MAX_LEN (((COL_MAX_INFO_LEN) > (COL_MAX_LEN)) ? \
    (COL_MAX_INFO_LEN) : (COL_MAX_LEN))
void
col_prepend_fstr(column_info *cinfo, const gint el, const gchar *format, ...)
{
  va_list     ap;
  int         i;
  char        orig_buf[COL_BUF_MAX_LEN];
  const char *orig;
  int         max_len;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      if (col_item->col_data != col_item->col_buf) {
        /* This was set with "col_set_str()"; which is effectively const */
        orig = col_item->col_data;
      } else {
        g_strlcpy(orig_buf, col_item->col_buf, max_len);
        orig = orig_buf;
      }
      va_start(ap, format);
      g_vsnprintf(col_item->col_buf, max_len, format, ap);
      va_end(ap);

      /*
       * Move the fence, unless it's at the beginning of the string.
       */
      if (col_item->col_fence > 0)
        col_item->col_fence += (int) strlen(col_item->col_buf);

      g_strlcat(col_item->col_buf, orig, max_len);
      col_item->col_data = col_item->col_buf;
    }
  }
}
void
col_prepend_fence_fstr(column_info *cinfo, const gint el, const gchar *format, ...)
{
  va_list     ap;
  int         i;
  char        orig_buf[COL_BUF_MAX_LEN];
  const char *orig;
  int         max_len;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      if (col_item->col_data != col_item->col_buf) {
        /* This was set with "col_set_str()"; which is effectively const */
        orig = col_item->col_data;
      } else {
        g_strlcpy(orig_buf, col_item->col_buf, max_len);
        orig = orig_buf;
      }
      va_start(ap, format);
      g_vsnprintf(col_item->col_buf, max_len, format, ap);
      va_end(ap);

      /*
       * Move the fence if it exists, else create a new fence at the
       * end of the prepended data.
       */
      if (col_item->col_fence > 0) {
        col_item->col_fence += (int) strlen(col_item->col_buf);
      } else {
        col_item->col_fence = (int) strlen(col_item->col_buf);
      }
      g_strlcat(col_item->col_buf, orig, max_len);
      col_item->col_data = col_item->col_buf;
    }
  }
}

/* Use this if "str" points to something that won't stay around (and
   must thus be copied). */
void
col_add_str(column_info *cinfo, const gint el, const gchar* str)
{
  int    i;
  size_t max_len;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      if (col_item->col_fence != 0) {
        /*
         * We will append the string after the fence.
         * First arrange that we can append, if necessary.
         */
        COL_CHECK_APPEND(col_item, max_len);
      } else {
        /*
         * There's no fence, so we can just write to the string.
         */
        col_item->col_data = col_item->col_buf;
      }
      g_strlcpy(&col_item->col_buf[col_item->col_fence], str, max_len - col_item->col_fence);
    }
  }
}

/* Use this if "str" points to something that will stay around (and thus
   needn't be copied). */
void
col_set_str(column_info *cinfo, const gint el, const gchar* str)
{
  int i;
  size_t max_len;
  col_item_t* col_item;

  DISSECTOR_ASSERT(str);

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      if (col_item->col_fence != 0) {
        /*
         * We will append the string after the fence.
         * First arrange that we can append, if necessary.
         */
        COL_CHECK_APPEND(col_item, max_len);

        g_strlcpy(&col_item->col_buf[col_item->col_fence], str, max_len - col_item->col_fence);
      } else {
        /*
         * There's no fence, so we can just set the column to point
         * to the string.
         */
        col_item->col_data = str;
      }
    }
  }
}

void
col_add_lstr(column_info *cinfo, const gint el, const gchar *str1, ...)
{
  va_list ap;
  int     i;
  gsize   pos;
  gsize   max_len;
  const gchar *str;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      pos = col_item->col_fence;
      if (pos != 0) {
        /*
         * We will append the string after the fence.
         * First arrange that we can append, if necessary.
         */
        COL_CHECK_APPEND(col_item, max_len);
      } else {
        /*
         * There's no fence, so we can just write to the string.
         */
        col_item->col_data = col_item->col_buf;
      }

      va_start(ap, str1);
      str = str1;
      do {
         if G_UNLIKELY(str == NULL)
             str = "(null)";

         pos += g_strlcpy(&col_item->col_buf[pos], str, max_len - pos);

      } while (pos < max_len && (str = va_arg(ap, const char *)) != COL_ADD_LSTR_TERMINATOR);
      va_end(ap);
    }
  }
}

/* Adds a vararg list to a packet info string. */
void
col_add_fstr(column_info *cinfo, const gint el, const gchar *format, ...)
{
  va_list ap;
  int     i;
  int     max_len;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      if (col_item->col_fence != 0) {
        /*
         * We will append the string after the fence.
         * First arrange that we can append, if necessary.
         */
        COL_CHECK_APPEND(col_item, max_len);
      } else {
        /*
         * There's no fence, so we can just write to the string.
         */
        col_item->col_data = col_item->col_buf;
      }
      va_start(ap, format);
      g_vsnprintf(&col_item->col_buf[col_item->col_fence], max_len - col_item->col_fence, format, ap);
      va_end(ap);
    }
  }
}

static void
col_do_append_str(column_info *cinfo, const gint el, const gchar* separator,
    const gchar* str)
{
  int    i;
  size_t len, max_len;
  col_item_t* col_item;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    col_item = &cinfo->columns[i];
    if (col_item->fmt_matx[el]) {
      /*
       * First arrange that we can append, if necessary.
       */
      COL_CHECK_APPEND(col_item, max_len);

      len = col_item->col_buf[0];

      /*
       * If we have a separator, append it if the column isn't empty.
       */
      if (separator != NULL) {
        if (len != 0) {
          g_strlcat(col_item->col_buf, separator, max_len);
        }
      }
      g_strlcat(col_item->col_buf, str, max_len);
    }
  }
}

void
col_append_str(column_info *cinfo, const gint el, const gchar* str)
{
  if (!CHECK_COL(cinfo, el))
    return;

  col_do_append_str(cinfo, el, NULL, str);
}

void
col_append_sep_str(column_info *cinfo, const gint el, const gchar* separator,
    const gchar* str)
{
  if (!CHECK_COL(cinfo, el))
    return;

  if (separator == NULL)
    separator = ", ";    /* default */

  col_do_append_str(cinfo, el, separator, str);
}

/* --------------------------------- */
gboolean
col_has_time_fmt(column_info *cinfo, const gint col)
{
  col_item_t* col_item = &cinfo->columns[col];
  return ((col_item->fmt_matx[COL_CLS_TIME]) ||
          (col_item->fmt_matx[COL_ABS_TIME]) ||
          (col_item->fmt_matx[COL_ABS_YMD_TIME]) ||
          (col_item->fmt_matx[COL_ABS_YDOY_TIME]) ||
          (col_item->fmt_matx[COL_UTC_TIME]) ||
          (col_item->fmt_matx[COL_UTC_YMD_TIME]) ||
          (col_item->fmt_matx[COL_UTC_YDOY_TIME]) ||
          (col_item->fmt_matx[COL_REL_TIME]) ||
          (col_item->fmt_matx[COL_DELTA_TIME]) ||
          (col_item->fmt_matx[COL_DELTA_TIME_DIS]));
}

static void
set_abs_ymd_time(const frame_data *fd, gchar *buf, gboolean local)
{
  struct tm *tmp;
  time_t then;
  int tsprecision;

  if (fd->flags.has_ts) {
    then = fd->abs_ts.secs;
    if (local)
      tmp = localtime(&then);
    else
      tmp = gmtime(&then);
  } else
    tmp = NULL;
  if (tmp != NULL) {
    switch (timestamp_get_precision()) {
    case TS_PREC_FIXED_SEC:
      tsprecision = WTAP_TSPREC_SEC;
      break;
    case TS_PREC_FIXED_DSEC:
      tsprecision = WTAP_TSPREC_DSEC;
      break;
    case TS_PREC_FIXED_CSEC:
      tsprecision = WTAP_TSPREC_CSEC;
      break;
    case TS_PREC_FIXED_MSEC:
      tsprecision = WTAP_TSPREC_MSEC;
      break;
    case TS_PREC_FIXED_USEC:
      tsprecision = WTAP_TSPREC_USEC;
      break;
    case TS_PREC_FIXED_NSEC:
      tsprecision = WTAP_TSPREC_NSEC;
      break;
    case TS_PREC_AUTO:
      tsprecision = fd->tsprec;
      break;
    default:
      g_assert_not_reached();
    }
    switch (tsprecision) {
    case WTAP_TSPREC_SEC:
      g_snprintf(buf, COL_MAX_LEN,"%04d-%02d-%02d %02d:%02d:%02d",
        tmp->tm_year + 1900,
        tmp->tm_mon + 1,
        tmp->tm_mday,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec);
      break;
    case WTAP_TSPREC_DSEC:
      g_snprintf(buf, COL_MAX_LEN,"%04d-%02d-%02d %02d:%02d:%02d.%01d",
        tmp->tm_year + 1900,
        tmp->tm_mon + 1,
        tmp->tm_mday,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 100000000);
      break;
    case WTAP_TSPREC_CSEC:
      g_snprintf(buf, COL_MAX_LEN,"%04d-%02d-%02d %02d:%02d:%02d.%02d",
        tmp->tm_year + 1900,
        tmp->tm_mon + 1,
        tmp->tm_mday,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 10000000);
      break;
    case WTAP_TSPREC_MSEC:
      g_snprintf(buf, COL_MAX_LEN, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        tmp->tm_year + 1900,
        tmp->tm_mon + 1,
        tmp->tm_mday,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 1000000);
      break;
    case WTAP_TSPREC_USEC:
      g_snprintf(buf, COL_MAX_LEN, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
        tmp->tm_year + 1900,
        tmp->tm_mon + 1,
        tmp->tm_mday,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 1000);
      break;
    case WTAP_TSPREC_NSEC:
      g_snprintf(buf, COL_MAX_LEN, "%04d-%02d-%02d %02d:%02d:%02d.%09d",
        tmp->tm_year + 1900,
        tmp->tm_mon + 1,
        tmp->tm_mday,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs);
      break;
    default:
      g_assert_not_reached();
    }
  } else {
    buf[0] = '\0';
  }
}

static void
col_set_abs_ymd_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_ymd_time(fd, cinfo->columns[col].col_buf, TRUE);
  cinfo->col_expr.col_expr[col] = "frame.time";
  g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_utc_ymd_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_ymd_time(fd, cinfo->columns[col].col_buf, FALSE);
  cinfo->col_expr.col_expr[col] = "frame.time";
  g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
set_abs_ydoy_time(const frame_data *fd, gchar *buf, gboolean local)
{
  struct tm *tmp;
  time_t then;
  int tsprecision;

  if (fd->flags.has_ts) {
    then = fd->abs_ts.secs;
    if (local)
      tmp = localtime(&then);
    else
      tmp = gmtime(&then);
  } else
    tmp = NULL;
  if (tmp != NULL) {
    switch (timestamp_get_precision()) {
    case TS_PREC_FIXED_SEC:
      tsprecision = WTAP_TSPREC_SEC;
      break;
    case TS_PREC_FIXED_DSEC:
      tsprecision = WTAP_TSPREC_DSEC;
      break;
    case TS_PREC_FIXED_CSEC:
      tsprecision = WTAP_TSPREC_CSEC;
      break;
    case TS_PREC_FIXED_MSEC:
      tsprecision = WTAP_TSPREC_MSEC;
      break;
    case TS_PREC_FIXED_USEC:
      tsprecision = WTAP_TSPREC_USEC;
      break;
    case TS_PREC_FIXED_NSEC:
      tsprecision = WTAP_TSPREC_NSEC;
      break;
    case TS_PREC_AUTO:
      tsprecision = fd->tsprec;
      break;
    default:
      g_assert_not_reached();
    }
    switch (tsprecision) {
    case WTAP_TSPREC_SEC:
      g_snprintf(buf, COL_MAX_LEN,"%04d/%03d %02d:%02d:%02d",
        tmp->tm_year + 1900,
        tmp->tm_yday + 1,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec);
      break;
    case WTAP_TSPREC_DSEC:
      g_snprintf(buf, COL_MAX_LEN,"%04d/%03d %02d:%02d:%02d.%01d",
        tmp->tm_year + 1900,
        tmp->tm_yday + 1,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 100000000);
      break;
    case WTAP_TSPREC_CSEC:
      g_snprintf(buf, COL_MAX_LEN,"%04d/%03d %02d:%02d:%02d.%02d",
        tmp->tm_year + 1900,
        tmp->tm_yday + 1,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 10000000);
      break;
    case WTAP_TSPREC_MSEC:
      g_snprintf(buf, COL_MAX_LEN, "%04d/%03d %02d:%02d:%02d.%03d",
        tmp->tm_year + 1900,
        tmp->tm_yday + 1,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 1000000);
      break;
    case WTAP_TSPREC_USEC:
      g_snprintf(buf, COL_MAX_LEN, "%04d/%03d %02d:%02d:%02d.%06d",
        tmp->tm_year + 1900,
        tmp->tm_yday + 1,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 1000);
      break;
    case WTAP_TSPREC_NSEC:
      g_snprintf(buf, COL_MAX_LEN, "%04d/%03d %02d:%02d:%02d.%09d",
        tmp->tm_year + 1900,
        tmp->tm_yday + 1,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs);
      break;
    default:
      g_assert_not_reached();
    }
  } else {
    buf[0] = '\0';
  }
}

static void
col_set_abs_ydoy_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_ydoy_time(fd, cinfo->columns[col].col_buf, TRUE);
  cinfo->col_expr.col_expr[col] = "frame.time";
  g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_utc_ydoy_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_ydoy_time(fd, cinfo->columns[col].col_buf, FALSE);
  cinfo->col_expr.col_expr[col] = "frame.time";
  g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
set_time_seconds(const frame_data *fd, const nstime_t *ts, gchar *buf)
{
  int tsprecision;

  switch (timestamp_get_precision()) {
  case TS_PREC_FIXED_SEC:
    tsprecision = WTAP_TSPREC_SEC;
    break;
  case TS_PREC_FIXED_DSEC:
    tsprecision = WTAP_TSPREC_DSEC;
    break;
  case TS_PREC_FIXED_CSEC:
    tsprecision = WTAP_TSPREC_CSEC;
    break;
  case TS_PREC_FIXED_MSEC:
    tsprecision = WTAP_TSPREC_MSEC;
    break;
  case TS_PREC_FIXED_USEC:
    tsprecision = WTAP_TSPREC_USEC;
    break;
  case TS_PREC_FIXED_NSEC:
    tsprecision = WTAP_TSPREC_NSEC;
    break;
  case TS_PREC_AUTO:
    tsprecision = fd->tsprec;
    break;
  default:
    g_assert_not_reached();
  }
  switch (tsprecision) {
  case WTAP_TSPREC_SEC:
    display_signed_time(buf, COL_MAX_LEN,
      (gint32) ts->secs, ts->nsecs / 1000000000, TO_STR_TIME_RES_T_SECS);
    break;
  case WTAP_TSPREC_DSEC:
    display_signed_time(buf, COL_MAX_LEN,
      (gint32) ts->secs, ts->nsecs / 100000000, TO_STR_TIME_RES_T_DSECS);
    break;
  case WTAP_TSPREC_CSEC:
    display_signed_time(buf, COL_MAX_LEN,
      (gint32) ts->secs, ts->nsecs / 10000000, TO_STR_TIME_RES_T_CSECS);
    break;
  case WTAP_TSPREC_MSEC:
    display_signed_time(buf, COL_MAX_LEN,
      (gint32) ts->secs, ts->nsecs / 1000000, TO_STR_TIME_RES_T_MSECS);
    break;
  case WTAP_TSPREC_USEC:
    display_signed_time(buf, COL_MAX_LEN,
      (gint32) ts->secs, ts->nsecs / 1000, TO_STR_TIME_RES_T_USECS);
    break;
  case WTAP_TSPREC_NSEC:
    display_signed_time(buf, COL_MAX_LEN,
      (gint32) ts->secs, ts->nsecs, TO_STR_TIME_RES_T_NSECS);
    break;
  default:
    g_assert_not_reached();
  }
}

static void
set_time_hour_min_sec(const frame_data *fd, const nstime_t *ts, gchar *buf)
{
  time_t secs = ts->secs;
  long nsecs = (long) ts->nsecs;
  gboolean negative = FALSE;
  int tsprecision;

  if (secs < 0) {
    secs = -secs;
    negative = TRUE;
  }
  if (nsecs < 0) {
    nsecs = -nsecs;
    negative = TRUE;
  }

  switch (timestamp_get_precision()) {
  case TS_PREC_FIXED_SEC:
    tsprecision = WTAP_TSPREC_SEC;
    break;
  case TS_PREC_FIXED_DSEC:
    tsprecision = WTAP_TSPREC_DSEC;
    break;
  case TS_PREC_FIXED_CSEC:
    tsprecision = WTAP_TSPREC_CSEC;
    break;
  case TS_PREC_FIXED_MSEC:
    tsprecision = WTAP_TSPREC_MSEC;
    break;
  case TS_PREC_FIXED_USEC:
    tsprecision = WTAP_TSPREC_USEC;
    break;
  case TS_PREC_FIXED_NSEC:
    tsprecision = WTAP_TSPREC_NSEC;
    break;
  case TS_PREC_AUTO:
    tsprecision = fd->tsprec;
    break;
  default:
    g_assert_not_reached();
  }
  switch (tsprecision) {
  case WTAP_TSPREC_SEC:
    if (secs >= (60*60)) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dh %2dm %2ds",
                 negative ? "- " : "",
                 (gint32) secs / (60 * 60),
                 (gint32) (secs / 60) % 60,
                 (gint32) secs % 60);
    } else if (secs >= 60) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dm %2ds",
                 negative ? "- " : "",
                 (gint32) secs / 60,
                 (gint32) secs % 60);
    } else {
      g_snprintf(buf, COL_MAX_LEN, "%s%ds",
                 negative ? "- " : "",
                 (gint32) secs);
    }
    break;
  case WTAP_TSPREC_DSEC:
    if (secs >= (60*60)) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dh %2dm %2d.%01lds",
                 negative ? "- " : "",
                 (gint32) secs / (60 * 60),
                 (gint32) (secs / 60) % 60,
                 (gint32) secs % 60,
                 nsecs / 100000000);
    } else if (secs >= 60) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dm %2d.%01lds",
                 negative ? "- " : "",
                 (gint32) secs / 60,
                 (gint32) secs % 60,
                 nsecs / 100000000);
    } else {
      g_snprintf(buf, COL_MAX_LEN, "%s%d.%01lds",
                 negative ? "- " : "",
                 (gint32) secs,
                 nsecs / 100000000);
    }
    break;
  case WTAP_TSPREC_CSEC:
    if (secs >= (60*60)) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dh %2dm %2d.%02lds",
                 negative ? "- " : "",
                 (gint32) secs / (60 * 60),
                 (gint32) (secs / 60) % 60,
                 (gint32) secs % 60,
                 nsecs / 10000000);
    } else if (secs >= 60) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dm %2d.%02lds",
                 negative ? "- " : "",
                 (gint32) secs / 60,
                 (gint32) secs % 60,
                 nsecs / 10000000);
    } else {
      g_snprintf(buf, COL_MAX_LEN, "%s%d.%02lds",
                 negative ? "- " : "",
                 (gint32) secs,
                 nsecs / 10000000);
    }
    break;
  case WTAP_TSPREC_MSEC:
    if (secs >= (60*60)) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dh %2dm %2d.%03lds",
                 negative ? "- " : "",
                 (gint32) secs / (60 * 60),
                 (gint32) (secs / 60) % 60,
                 (gint32) secs % 60,
                 nsecs / 1000000);
    } else if (secs >= 60) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dm %2d.%03lds",
                 negative ? "- " : "",
                 (gint32) secs / 60,
                 (gint32) secs % 60,
                 nsecs / 1000000);
    } else {
      g_snprintf(buf, COL_MAX_LEN, "%s%d.%03lds",
                 negative ? "- " : "",
                 (gint32) secs,
                 nsecs / 1000000);
    }
    break;
  case WTAP_TSPREC_USEC:
    if (secs >= (60*60)) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dh %2dm %2d.%06lds",
                 negative ? "- " : "",
                 (gint32) secs / (60 * 60),
                 (gint32) (secs / 60) % 60,
                 (gint32) secs % 60,
                 nsecs / 1000);
    } else if (secs >= 60) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dm %2d.%06lds",
                 negative ? "- " : "",
                 (gint32) secs / 60,
                 (gint32) secs % 60,
                 nsecs / 1000);
    } else {
      g_snprintf(buf, COL_MAX_LEN, "%s%d.%06lds",
                 negative ? "- " : "",
                 (gint32) secs,
                 nsecs / 1000);
    }
    break;
  case WTAP_TSPREC_NSEC:
    if (secs >= (60*60)) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dh %2dm %2d.%09lds",
                 negative ? "- " : "",
                 (gint32) secs / (60 * 60),
                 (gint32) (secs / 60) % 60,
                 (gint32) secs % 60,
                 nsecs);
    } else if (secs >= 60) {
      g_snprintf(buf, COL_MAX_LEN, "%s%dm %2d.%09lds",
                 negative ? "- " : "",
                 (gint32) secs / 60,
                 (gint32) secs % 60,
                 nsecs);
    } else {
      g_snprintf(buf, COL_MAX_LEN, "%s%d.%09lds",
                 negative ? "- " : "",
                 (gint32) secs,
                 nsecs);
    }
    break;
  default:
    g_assert_not_reached();
  }
}

static void
col_set_rel_time(const frame_data *fd, column_info *cinfo, const int col)
{
  nstime_t del_rel_ts;

  if (!fd->flags.has_ts) {
    cinfo->columns[col].col_buf[0] = '\0';
    return;
  }

  frame_delta_abs_time(cinfo->epan, fd, fd->frame_ref_num, &del_rel_ts);

  switch (timestamp_get_seconds_type()) {
  case TS_SECONDS_DEFAULT:
    set_time_seconds(fd, &del_rel_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_relative";
    g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);
    break;
  case TS_SECONDS_HOUR_MIN_SEC:
    set_time_hour_min_sec(fd, &del_rel_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_relative";
    set_time_seconds(fd, &del_rel_ts, cinfo->col_expr.col_expr_val[col]);
    break;
  default:
    g_assert_not_reached();
  }
  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_delta_time(const frame_data *fd, column_info *cinfo, const int col)
{
  nstime_t del_cap_ts;

  frame_delta_abs_time(cinfo->epan, fd, fd->num - 1, &del_cap_ts);

  switch (timestamp_get_seconds_type()) {
  case TS_SECONDS_DEFAULT:
    set_time_seconds(fd, &del_cap_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_delta";
    g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);
    break;
  case TS_SECONDS_HOUR_MIN_SEC:
    set_time_hour_min_sec(fd, &del_cap_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_delta";
    set_time_seconds(fd, &del_cap_ts, cinfo->col_expr.col_expr_val[col]);
    break;
  default:
    g_assert_not_reached();
  }

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_delta_time_dis(const frame_data *fd, column_info *cinfo, const int col)
{
  nstime_t del_dis_ts;

  if (!fd->flags.has_ts) {
    cinfo->columns[col].col_buf[0] = '\0';
    return;
  }

  frame_delta_abs_time(cinfo->epan, fd, fd->prev_dis_num, &del_dis_ts);

  switch (timestamp_get_seconds_type()) {
  case TS_SECONDS_DEFAULT:
    set_time_seconds(fd, &del_dis_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_delta_displayed";
    g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);
    break;
  case TS_SECONDS_HOUR_MIN_SEC:
    set_time_hour_min_sec(fd, &del_dis_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_delta_displayed";
    set_time_seconds(fd, &del_dis_ts, cinfo->col_expr.col_expr_val[col]);
    break;
  default:
    g_assert_not_reached();
  }

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
set_abs_time(const frame_data *fd, gchar *buf, gboolean local)
{
  struct tm *tmp;
  time_t then;
  int tsprecision;

  if (fd->flags.has_ts) {
    then = fd->abs_ts.secs;
    if (local)
      tmp = localtime(&then);
    else
      tmp = gmtime(&then);
  } else
    tmp = NULL;
  if (tmp != NULL) {
    switch (timestamp_get_precision()) {
    case TS_PREC_FIXED_SEC:
      tsprecision = WTAP_TSPREC_SEC;
      break;
    case TS_PREC_FIXED_DSEC:
      tsprecision = WTAP_TSPREC_DSEC;
      break;
    case TS_PREC_FIXED_CSEC:
      tsprecision = WTAP_TSPREC_CSEC;
      break;
    case TS_PREC_FIXED_MSEC:
      tsprecision = WTAP_TSPREC_MSEC;
      break;
    case TS_PREC_FIXED_USEC:
      tsprecision = WTAP_TSPREC_USEC;
      break;
    case TS_PREC_FIXED_NSEC:
      tsprecision = WTAP_TSPREC_NSEC;
      break;
    case TS_PREC_AUTO:
      tsprecision = fd->tsprec;
      break;
    default:
      g_assert_not_reached();
    }
    switch (tsprecision) {
    case WTAP_TSPREC_SEC:
      g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d",
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec);
      break;
    case WTAP_TSPREC_DSEC:
      g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d.%01d",
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 100000000);
      break;
    case WTAP_TSPREC_CSEC:
      g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d.%02d",
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 10000000);
      break;
    case WTAP_TSPREC_MSEC:
      g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d.%03d",
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 1000000);
      break;
    case WTAP_TSPREC_USEC:
      g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d.%06d",
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs / 1000);
      break;
    case WTAP_TSPREC_NSEC:
      g_snprintf(buf, COL_MAX_LEN, "%02d:%02d:%02d.%09d",
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        fd->abs_ts.nsecs);
      break;
    default:
      g_assert_not_reached();
    }

  } else {
    *buf = '\0';
  }
}

static void
col_set_abs_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_time(fd, cinfo->columns[col].col_buf, TRUE);
  cinfo->col_expr.col_expr[col] = "frame.time";
  g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_utc_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_time(fd, cinfo->columns[col].col_buf, FALSE);
  cinfo->col_expr.col_expr[col] = "frame.time";
  g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static gboolean
set_epoch_time(const frame_data *fd, gchar *buf)
{
  int tsprecision;

  if (!fd->flags.has_ts) {
    buf[0] = '\0';
    return FALSE;
  }
  switch (timestamp_get_precision()) {
  case TS_PREC_FIXED_SEC:
    tsprecision = WTAP_TSPREC_SEC;
    break;
  case TS_PREC_FIXED_DSEC:
    tsprecision = WTAP_TSPREC_DSEC;
    break;
  case TS_PREC_FIXED_CSEC:
    tsprecision = WTAP_TSPREC_CSEC;
    break;
  case TS_PREC_FIXED_MSEC:
    tsprecision = WTAP_TSPREC_MSEC;
    break;
  case TS_PREC_FIXED_USEC:
    tsprecision = WTAP_TSPREC_USEC;
    break;
  case TS_PREC_FIXED_NSEC:
    tsprecision = WTAP_TSPREC_NSEC;
    break;
  case TS_PREC_AUTO:
    tsprecision = fd->tsprec;
    break;
  default:
    g_assert_not_reached();
  }
  switch (tsprecision) {
  case WTAP_TSPREC_SEC:
    display_epoch_time(buf, COL_MAX_LEN,
      fd->abs_ts.secs, fd->abs_ts.nsecs / 1000000000, TO_STR_TIME_RES_T_SECS);
    break;
  case WTAP_TSPREC_DSEC:
    display_epoch_time(buf, COL_MAX_LEN,
       fd->abs_ts.secs, fd->abs_ts.nsecs / 100000000, TO_STR_TIME_RES_T_DSECS);
    break;
  case WTAP_TSPREC_CSEC:
    display_epoch_time(buf, COL_MAX_LEN,
       fd->abs_ts.secs, fd->abs_ts.nsecs / 10000000, TO_STR_TIME_RES_T_CSECS);
    break;
  case WTAP_TSPREC_MSEC:
    display_epoch_time(buf, COL_MAX_LEN,
       fd->abs_ts.secs, fd->abs_ts.nsecs / 1000000, TO_STR_TIME_RES_T_MSECS);
    break;
  case WTAP_TSPREC_USEC:
    display_epoch_time(buf, COL_MAX_LEN,
       fd->abs_ts.secs, fd->abs_ts.nsecs / 1000, TO_STR_TIME_RES_T_USECS);
    break;
  case WTAP_TSPREC_NSEC:
    display_epoch_time(buf, COL_MAX_LEN,
       fd->abs_ts.secs, fd->abs_ts.nsecs, TO_STR_TIME_RES_T_NSECS);
    break;
  default:
    g_assert_not_reached();
  }
  return TRUE;
}

static void
col_set_epoch_time(const frame_data *fd, column_info *cinfo, const int col)
{
  if (set_epoch_time(fd, cinfo->columns[col].col_buf)) {
    cinfo->col_expr.col_expr[col] = "frame.time_delta";
    g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);
  }
  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

void
set_fd_time(const epan_t *epan, frame_data *fd, gchar *buf)
{

  switch (timestamp_get_type()) {
  case TS_ABSOLUTE:
    set_abs_time(fd, buf, TRUE);
    break;

  case TS_ABSOLUTE_WITH_YMD:
    set_abs_ymd_time(fd, buf, TRUE);
    break;

  case TS_ABSOLUTE_WITH_YDOY:
    set_abs_ydoy_time(fd, buf, TRUE);
    break;

  case TS_RELATIVE:
    if (fd->flags.has_ts) {
      nstime_t del_rel_ts;

      frame_delta_abs_time(epan, fd, fd->frame_ref_num, &del_rel_ts);

      switch (timestamp_get_seconds_type()) {
      case TS_SECONDS_DEFAULT:
        set_time_seconds(fd, &del_rel_ts, buf);
        break;
      case TS_SECONDS_HOUR_MIN_SEC:
        set_time_seconds(fd, &del_rel_ts, buf);
        break;
      default:
        g_assert_not_reached();
      }
    } else {
      buf[0] = '\0';
    }
    break;

  case TS_DELTA:
    if (fd->flags.has_ts) {
      nstime_t del_cap_ts;

      frame_delta_abs_time(epan, fd, fd->num - 1, &del_cap_ts);

      switch (timestamp_get_seconds_type()) {
      case TS_SECONDS_DEFAULT:
        set_time_seconds(fd, &del_cap_ts, buf);
        break;
      case TS_SECONDS_HOUR_MIN_SEC:
        set_time_hour_min_sec(fd, &del_cap_ts, buf);
        break;
      default:
        g_assert_not_reached();
      }
    } else {
      buf[0] = '\0';
    }
    break;

  case TS_DELTA_DIS:
    if (fd->flags.has_ts) {
      nstime_t del_dis_ts;

      frame_delta_abs_time(epan, fd, fd->prev_dis_num, &del_dis_ts);

      switch (timestamp_get_seconds_type()) {
      case TS_SECONDS_DEFAULT:
        set_time_seconds(fd, &del_dis_ts, buf);
        break;
      case TS_SECONDS_HOUR_MIN_SEC:
        set_time_hour_min_sec(fd, &del_dis_ts, buf);
        break;
      default:
        g_assert_not_reached();
      }
    } else {
      buf[0] = '\0';
    }
    break;

  case TS_EPOCH:
    set_epoch_time(fd, buf);
    break;

  case TS_UTC:
    set_abs_time(fd, buf, FALSE);
    break;

  case TS_UTC_WITH_YMD:
    set_abs_ymd_time(fd, buf, FALSE);
    break;

  case TS_UTC_WITH_YDOY:
    set_abs_ydoy_time(fd, buf, FALSE);
    break;

  case TS_NOT_SET:
    /* code is missing for this case, but I don't know which [jmayer20051219] */
    g_assert(FALSE);
    break;
  }
}

static void
col_set_cls_time(const frame_data *fd, column_info *cinfo, const gint col)
{
  switch (timestamp_get_type()) {
  case TS_ABSOLUTE:
    col_set_abs_time(fd, cinfo, col);
    break;

  case TS_ABSOLUTE_WITH_YMD:
    col_set_abs_ymd_time(fd, cinfo, col);
    break;

  case TS_ABSOLUTE_WITH_YDOY:
    col_set_abs_ydoy_time(fd, cinfo, col);
    break;

  case TS_RELATIVE:
    col_set_rel_time(fd, cinfo, col);
    break;

  case TS_DELTA:
    col_set_delta_time(fd, cinfo, col);
    break;

  case TS_DELTA_DIS:
    col_set_delta_time_dis(fd, cinfo, col);
    break;

  case TS_EPOCH:
    col_set_epoch_time(fd, cinfo, col);
    break;

  case TS_UTC:
    col_set_utc_time(fd, cinfo, col);
    break;

  case TS_UTC_WITH_YMD:
    col_set_utc_ymd_time(fd, cinfo, col);
    break;

  case TS_UTC_WITH_YDOY:
    col_set_utc_ydoy_time(fd, cinfo, col);
    break;

  case TS_NOT_SET:
    /* code is missing for this case, but I don't know which [jmayer20051219] */
    g_assert_not_reached();
    break;
  }
}

/* Set the format of the variable time format. */
static void
col_set_fmt_time(const frame_data *fd, column_info *cinfo, const gint fmt, const gint col)
{
  COL_CHECK_REF_TIME(fd, cinfo->columns[col].col_buf);

  switch (fmt) {
  case COL_CLS_TIME:
    col_set_cls_time(fd, cinfo, col);
    break;

  case COL_ABS_TIME:
    col_set_abs_time(fd, cinfo, col);
    break;

  case COL_ABS_YMD_TIME:
    col_set_abs_ymd_time(fd, cinfo, col);
    break;

  case COL_ABS_YDOY_TIME:
    col_set_abs_ydoy_time(fd, cinfo, col);
    break;

  case COL_REL_TIME:
    col_set_rel_time(fd, cinfo, col);
    break;

  case COL_DELTA_TIME:
    col_set_delta_time(fd, cinfo, col);
    break;

  case COL_DELTA_TIME_DIS:
    col_set_delta_time_dis(fd, cinfo, col);
    break;

  case COL_UTC_TIME:
    col_set_utc_time(fd, cinfo, col);
    break;

  case COL_UTC_YMD_TIME:
    col_set_utc_ymd_time(fd, cinfo, col);
    break;

  case COL_UTC_YDOY_TIME:
    col_set_utc_ydoy_time(fd, cinfo, col);
    break;

  default:
    g_assert_not_reached();
    break;
  }
}

/* --------------------------- */
/* Set the given (relative) time to a column element.
 *
 * Used by dissectors to set the time in a column
 *
 * @param cinfo         the current packet row
 * @param el            the column to use, e.g. COL_INFO
 * @param ts            the time to set in the column
 * @param fieldname     the fieldname to use for creating a filter (when
 *                        applying/preparing/copying as filter)
 */
void
col_set_time(column_info *cinfo, const gint el, const nstime_t *ts, const char *fieldname)
{
  int col;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  /** @todo TODO: We don't respect fd->flags.ref_time (no way to access 'fd')
  COL_CHECK_REF_TIME(fd, buf);
  */

  for (col = cinfo->col_first[el]; col <= cinfo->col_last[el]; col++) {
    col_item = &cinfo->columns[col];
    if (col_item->fmt_matx[el]) {
      switch (timestamp_get_precision()) {
      case TS_PREC_FIXED_SEC:
        display_signed_time(col_item->col_buf, COL_MAX_LEN,
          (gint32) ts->secs, ts->nsecs / 1000000000, TO_STR_TIME_RES_T_SECS);
        break;
      case TS_PREC_FIXED_DSEC:
        display_signed_time(col_item->col_buf, COL_MAX_LEN,
          (gint32) ts->secs, ts->nsecs / 100000000, TO_STR_TIME_RES_T_DSECS);
        break;
      case TS_PREC_FIXED_CSEC:
        display_signed_time(col_item->col_buf, COL_MAX_LEN,
          (gint32) ts->secs, ts->nsecs / 10000000, TO_STR_TIME_RES_T_CSECS);
        break;
      case TS_PREC_FIXED_MSEC:
        display_signed_time(col_item->col_buf, COL_MAX_LEN,
          (gint32) ts->secs, ts->nsecs / 1000000, TO_STR_TIME_RES_T_MSECS);
        break;
      case TS_PREC_FIXED_USEC:
        display_signed_time(col_item->col_buf, COL_MAX_LEN,
          (gint32) ts->secs, ts->nsecs / 1000, TO_STR_TIME_RES_T_USECS);
        break;
      case TS_PREC_FIXED_NSEC:
      case TS_PREC_AUTO:    /* default to maximum */
        display_signed_time(col_item->col_buf, COL_MAX_LEN,
          (gint32) ts->secs, ts->nsecs, TO_STR_TIME_RES_T_NSECS);
        break;
      default:
        g_assert_not_reached();
      }
      col_item->col_data = col_item->col_buf;
      cinfo->col_expr.col_expr[col] = fieldname;
      g_strlcpy(cinfo->col_expr.col_expr_val[col],col_item->col_buf,COL_MAX_LEN);
    }
  }
}

static void
col_set_addr(packet_info *pinfo, const int col, const address *addr, const gboolean is_src,
             const gboolean fill_col_exprs, const gboolean res)
{
  const char *name;
  col_item_t* col_item = &pinfo->cinfo->columns[col];

  if (addr->type == AT_NONE) {
    /* No address, nothing to do */
    return;
  }

  if (res && (name = address_to_name(addr)) != NULL)
    col_item->col_data = name;
  else {
    col_item->col_data = col_item->col_buf;
    address_to_str_buf(addr, col_item->col_buf, COL_MAX_LEN);
  }

  if (!fill_col_exprs)
    return;

  pinfo->cinfo->col_expr.col_expr[col] = address_type_column_filter_string(addr, is_src);
  /* For address types that have a filter, create a string */
  if (strlen(pinfo->cinfo->col_expr.col_expr[col]) > 0)
    address_to_str_buf(addr, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
}

/* ------------------------ */
static void
col_set_port(packet_info *pinfo, const int col, const gboolean is_res, const gboolean is_src, const gboolean fill_col_exprs _U_)
{
  guint32 port;
  col_item_t* col_item = &pinfo->cinfo->columns[col];

  if (is_src)
    port = pinfo->srcport;
  else
    port = pinfo->destport;

  /* TODO: Use fill_col_exprs */

  switch (pinfo->ptype) {
  case PT_SCTP:
    if (is_res)
      g_strlcpy(col_item->col_buf, sctp_port_to_display(pinfo->pool, port), COL_MAX_LEN);
    else
      guint32_to_str_buf(port, col_item->col_buf, COL_MAX_LEN);
    break;

  case PT_TCP:
    guint32_to_str_buf(port, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    if (is_res)
      g_strlcpy(col_item->col_buf, tcp_port_to_display(pinfo->pool, port), COL_MAX_LEN);
    else
      g_strlcpy(col_item->col_buf, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "tcp.srcport";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "tcp.dstport";
    break;

  case PT_UDP:
    guint32_to_str_buf(port, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    if (is_res)
      g_strlcpy(col_item->col_buf, udp_port_to_display(pinfo->pool, port), COL_MAX_LEN);
    else
      g_strlcpy(col_item->col_buf, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "udp.srcport";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "udp.dstport";
    break;

  case PT_DDP:
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "ddp.src_socket";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "ddp.dst_socket";
    guint32_to_str_buf(port, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    g_strlcpy(col_item->col_buf, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    break;

  case PT_IPX:
    /* XXX - resolve IPX socket numbers */
    g_snprintf(col_item->col_buf, COL_MAX_LEN, "0x%04x", port);
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], col_item->col_buf,COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "ipx.src.socket";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "ipx.dst.socket";
    break;

  case PT_IDP:
    /* XXX - resolve IDP socket numbers */
    g_snprintf(col_item->col_buf, COL_MAX_LEN, "0x%04x", port);
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], col_item->col_buf,COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "idp.src.socket";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "idp.dst.socket";
    break;

  case PT_USB:
    /* XXX - resolve USB endpoint numbers */
    g_snprintf(col_item->col_buf, COL_MAX_LEN, "0x%08x", port);
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], col_item->col_buf,COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "usb.src.endpoint";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "usb.dst.endpoint";
    break;

  default:
    break;
  }
  col_item->col_data = col_item->col_buf;
}

gboolean
col_based_on_frame_data(column_info *cinfo, const gint col)
{
  g_assert(cinfo);
  g_assert(col < cinfo->num_cols);

  switch (cinfo->columns[col].col_fmt) {
  case COL_NUMBER:
  case COL_CLS_TIME:
  case COL_ABS_TIME:
  case COL_ABS_YMD_TIME:
  case COL_ABS_YDOY_TIME:
  case COL_UTC_TIME:
  case COL_UTC_YMD_TIME:
  case COL_UTC_YDOY_TIME:
  case COL_REL_TIME:
  case COL_DELTA_TIME:
  case COL_DELTA_TIME_DIS:
  case COL_PACKET_LENGTH:
  case COL_CUMULATIVE_BYTES:
    return TRUE;

  default:
    return FALSE;
  }
}

void
col_fill_in_frame_data(const frame_data *fd, column_info *cinfo, const gint col, const gboolean fill_col_exprs)
{
  col_item_t* col_item = &cinfo->columns[col];

  switch (col_item->col_fmt) {
  case COL_NUMBER:
    guint32_to_str_buf(fd->num, col_item->col_buf, COL_MAX_LEN);
    col_item->col_data = col_item->col_buf;
    break;

  case COL_CLS_TIME:
  case COL_ABS_TIME:
  case COL_ABS_YMD_TIME:
  case COL_ABS_YDOY_TIME:
  case COL_UTC_TIME:
  case COL_UTC_YMD_TIME:
  case COL_UTC_YDOY_TIME:
  case COL_REL_TIME:
  case COL_DELTA_TIME:
  case COL_DELTA_TIME_DIS:
    /* TODO: Pass on fill_col_exprs */
    col_set_fmt_time(fd, cinfo, col_item->col_fmt, col);
    break;

  case COL_PACKET_LENGTH:
    guint32_to_str_buf(fd->pkt_len, col_item->col_buf, COL_MAX_LEN);
    col_item->col_data = col_item->col_buf;
    break;

  case COL_CUMULATIVE_BYTES:
    guint32_to_str_buf(fd->cum_bytes, col_item->col_buf, COL_MAX_LEN);
    col_item->col_data = col_item->col_buf;
    break;

  default:
    break;
  }

  if (!fill_col_exprs)
    return;

  switch (col_item->col_fmt) {
  case COL_NUMBER:
    cinfo->col_expr.col_expr[col] = "frame.number";
    g_strlcpy(cinfo->col_expr.col_expr_val[col], col_item->col_buf, COL_MAX_LEN);
    break;

  case COL_CLS_TIME:
  case COL_ABS_TIME:
  case COL_ABS_YMD_TIME:
  case COL_ABS_YDOY_TIME:
  case COL_UTC_TIME:
  case COL_UTC_YMD_TIME:
  case COL_UTC_YDOY_TIME:
  case COL_REL_TIME:
  case COL_DELTA_TIME:
  case COL_DELTA_TIME_DIS:
    /* Already handled above */
    break;

  case COL_PACKET_LENGTH:
    cinfo->col_expr.col_expr[col] = "frame.len";
    g_strlcpy(cinfo->col_expr.col_expr_val[col], col_item->col_buf, COL_MAX_LEN);
    break;

  case COL_CUMULATIVE_BYTES:
    break;

  default:
    break;
  }
}

void
col_fill_in(packet_info *pinfo, const gboolean fill_col_exprs, const gboolean fill_fd_colums)
{
  int i;
  col_item_t* col_item;

  if (!pinfo->cinfo)
    return;

  for (i = 0; i < pinfo->cinfo->num_cols; i++) {
    col_item = &pinfo->cinfo->columns[i];
    if (col_based_on_frame_data(pinfo->cinfo, i)) {
      if (fill_fd_colums)
        col_fill_in_frame_data(pinfo->fd, pinfo->cinfo, i, fill_col_exprs);
    } else {
      switch (col_item->col_fmt) {
      case COL_DEF_SRC:
      case COL_RES_SRC:   /* COL_DEF_SRC is currently just like COL_RES_SRC */
        col_set_addr(pinfo, i, &pinfo->src, TRUE, fill_col_exprs, TRUE);
        break;

      case COL_UNRES_SRC:
        col_set_addr(pinfo, i, &pinfo->src, TRUE, fill_col_exprs, FALSE);
        break;

      case COL_DEF_DL_SRC:
      case COL_RES_DL_SRC:
        col_set_addr(pinfo, i, &pinfo->dl_src, TRUE, fill_col_exprs, TRUE);
        break;

      case COL_UNRES_DL_SRC:
        col_set_addr(pinfo, i, &pinfo->dl_src, TRUE, fill_col_exprs, FALSE);
        break;

      case COL_DEF_NET_SRC:
      case COL_RES_NET_SRC:
        col_set_addr(pinfo, i, &pinfo->net_src, TRUE, fill_col_exprs, TRUE);
        break;

      case COL_UNRES_NET_SRC:
        col_set_addr(pinfo, i, &pinfo->net_src, TRUE, fill_col_exprs, FALSE);
        break;

      case COL_DEF_DST:
      case COL_RES_DST:   /* COL_DEF_DST is currently just like COL_RES_DST */
        col_set_addr(pinfo, i, &pinfo->dst, FALSE, fill_col_exprs, TRUE);
        break;

      case COL_UNRES_DST:
        col_set_addr(pinfo, i, &pinfo->dst, FALSE, fill_col_exprs, FALSE);
        break;

      case COL_DEF_DL_DST:
      case COL_RES_DL_DST:
        col_set_addr(pinfo, i, &pinfo->dl_dst, FALSE, fill_col_exprs, TRUE);
        break;

      case COL_UNRES_DL_DST:
        col_set_addr(pinfo, i, &pinfo->dl_dst, FALSE, fill_col_exprs, FALSE);
        break;

      case COL_DEF_NET_DST:
      case COL_RES_NET_DST:
        col_set_addr(pinfo, i, &pinfo->net_dst, FALSE, fill_col_exprs, TRUE);
        break;

      case COL_UNRES_NET_DST:
        col_set_addr(pinfo, i, &pinfo->net_dst, FALSE, fill_col_exprs, FALSE);
        break;

      case COL_DEF_SRC_PORT:
      case COL_RES_SRC_PORT:  /* COL_DEF_SRC_PORT is currently just like COL_RES_SRC_PORT */
        col_set_port(pinfo, i, TRUE, TRUE, fill_col_exprs);
        break;

      case COL_UNRES_SRC_PORT:
        col_set_port(pinfo, i, FALSE, TRUE, fill_col_exprs);
        break;

      case COL_DEF_DST_PORT:
      case COL_RES_DST_PORT:  /* COL_DEF_DST_PORT is currently just like COL_RES_DST_PORT */
        col_set_port(pinfo, i, TRUE, FALSE, fill_col_exprs);
        break;

      case COL_UNRES_DST_PORT:
        col_set_port(pinfo, i, FALSE, FALSE, fill_col_exprs);
        break;

      case NUM_COL_FMTS:  /* keep compiler happy - shouldn't get here */
        g_assert_not_reached();
        break;
      default:
        if (col_item->col_fmt >= NUM_COL_FMTS) {
          g_assert_not_reached();
        }
        /*
         * Formatting handled by col_custom_set_edt() (COL_CUSTOM), expert.c
         * (COL_EXPERT), or individual dissectors.
         */
        break;
      }
    }
  }
}

/*
 * Fill in columns if we got an error reading the packet.
 * We set most columns to "???", fill in columns that don't need data read
 * from the file, and set the Info column to an error message.
 */
void
col_fill_in_error(column_info *cinfo, frame_data *fdata, const gboolean fill_col_exprs, const gboolean fill_fd_colums)
{
  int i;
  col_item_t* col_item;

  if (!cinfo)
    return;

  for (i = 0; i < cinfo->num_cols; i++) {
    col_item = &cinfo->columns[i];
    if (col_based_on_frame_data(cinfo, i)) {
      if (fill_fd_colums)
        col_fill_in_frame_data(fdata, cinfo, i, fill_col_exprs);
    } else if (col_item->col_fmt == COL_INFO) {
      /* XXX - say more than this */
      col_item->col_data = "Read error";
    } else {
      if (col_item->col_fmt >= NUM_COL_FMTS) {
        g_assert_not_reached();
      }
      /*
       * No dissection was done, and these columns are set as the
       * result of the dissection, so....
       */
      col_item->col_data = "???";
      break;
    }
  }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
