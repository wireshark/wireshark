/* column-utils.c
 * Routines for column utilities.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <time.h>

#include "column-utils.h"
#include "timestamp.h"
#include "sna-utils.h"
#include "atalk-utils.h"
#include "to_str.h"
#include "packet_info.h"
#include "pint.h"
#include "addr_resolv.h"
#include "ipv6-utils.h"
#include "osi-utils.h"
#include "value_string.h"
#include "column_info.h"

#include <epan/strutil.h>
#include <epan/epan.h>

/* Allocate all the data structures for constructing column data, given
   the number of columns. */
void
col_setup(column_info *cinfo, gint num_cols)
{
  int i;

  cinfo->num_cols   = num_cols;
  cinfo->col_fmt    = g_new(gint, num_cols);
  cinfo->fmt_matx   = g_new(gboolean*, num_cols);
  cinfo->col_first  = g_new(int, NUM_COL_FMTS);
  cinfo->col_last   = g_new(int, NUM_COL_FMTS);
  cinfo->col_title  = g_new(gchar*, num_cols);
  cinfo->col_custom_field = g_new(gchar*, num_cols);
  cinfo->col_custom_field_id = g_new(int, num_cols);
  cinfo->col_custom_dfilter = g_new(dfilter_t*, num_cols);
  cinfo->col_data   = (const gchar **)g_new(gchar*, num_cols);
  cinfo->col_buf    = g_new(gchar*, num_cols);
  cinfo->col_fence  = g_new(int, num_cols);
  cinfo->col_expr.col_expr = (const gchar **) g_new(gchar*, num_cols + 1);
  cinfo->col_expr.col_expr_val = g_new(gchar*, num_cols + 1);

  for (i = 0; i < NUM_COL_FMTS; i++) {
    cinfo->col_first[i] = -1;
    cinfo->col_last[i] = -1;
  }
}

/* Initialize the data structures for constructing column data. */
void
col_init(column_info *cinfo)
{
  int i;

  if (!cinfo)
    return;

  for (i = 0; i < cinfo->num_cols; i++) {
    cinfo->col_buf[i][0] = '\0';
    cinfo->col_data[i] = cinfo->col_buf[i];
    cinfo->col_fence[i] = 0;
    cinfo->col_expr.col_expr[i] = "";
    cinfo->col_expr.col_expr_val[i][0] = '\0';
  }
  cinfo->writable = TRUE;
}

#define COL_GET_WRITABLE(cinfo) (cinfo ? cinfo->writable : FALSE)

gboolean
col_get_writable(column_info *cinfo)
{
    return COL_GET_WRITABLE(cinfo);
}

void
col_set_writable(column_info *cinfo, gboolean writable)
{
    if (cinfo)
        cinfo->writable = writable;
}

/* Checks to see if a particular packet information element is needed for the packet list */
#define CHECK_COL(cinfo, el) \
    /* We are constructing columns, and they're writable */ \
    (COL_GET_WRITABLE(cinfo) && \
      /* There is at least one column in that format */ \
    ((cinfo)->col_first[el] >= 0))

gint
check_col(column_info *cinfo, gint el)
{
  return CHECK_COL(cinfo, el);
}

/* Sets the fence for a column to be at the end of the column. */
void
col_set_fence(column_info *cinfo, gint el)
{
  int i;

  if (!CHECK_COL(cinfo, el))
    return;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
      cinfo->col_fence[i] = (int)strlen(cinfo->col_data[i]);
    }
  }
}

/* Use this to clear out a column, especially if you're going to be
   appending to it later; at least on some platforms, it's more
   efficient than using "col_add_str()" with a null string, and
   more efficient than "col_set_str()" with a null string if you
   later append to it, as the later append will cause a string
   copy to be done. */
void
col_clear(column_info *cinfo, gint el)
{
  int    i;
  int    fence;

  if (!CHECK_COL(cinfo, el))
    return;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
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
      fence = cinfo->col_fence[i];
      if (fence == 0 || cinfo->col_buf[i] == cinfo->col_data[i]) {
        /*
         * The fence isn't at the end of the column, or the column wasn't
         * last set with "col_set_str()", so clear the column out.
         */
        cinfo->col_buf[i][fence] = '\0';
        cinfo->col_data[i] = cinfo->col_buf[i];
      }
      cinfo->col_expr.col_expr[i] = "";
      cinfo->col_expr.col_expr_val[i][0] = '\0';
    }
  }
}

#define COL_CHECK_APPEND(cinfo, i, max_len) \
  if (cinfo->col_data[i] != cinfo->col_buf[i]) {        \
    /* This was set with "col_set_str()"; copy the string they  \
       set it to into the buffer, so we can append to it. */    \
    g_strlcpy(cinfo->col_buf[i], cinfo->col_data[i], max_len);  \
    cinfo->col_data[i] = cinfo->col_buf[i];         \
  }

#define COL_CHECK_REF_TIME(fd, buf) \
  if(fd->flags.ref_time){                   \
    g_strlcpy(buf, "*REF*", COL_MAX_LEN );  \
    return 0;                           \
  }

/* Use this if "str" points to something that will stay around (and thus
   needn't be copied). */
void
col_set_str(column_info *cinfo, gint el, const gchar* str)
{
  int i;
  int fence;
  size_t max_len;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
      fence = cinfo->col_fence[i];
      if (fence != 0) {
        /*
         * We will append the string after the fence.
         * First arrange that we can append, if necessary.
         */
        COL_CHECK_APPEND(cinfo, i, max_len);

        g_strlcpy(&cinfo->col_buf[i][fence], str, max_len - fence);
      } else {
        /*
         * There's no fence, so we can just set the column to point
         * to the string.
         */
        cinfo->col_data[i] = str;
      }
    }
  }
}

/* Adds a vararg list to a packet info string. */
void
col_add_fstr(column_info *cinfo, gint el, const gchar *format, ...) {
  va_list ap;
  int     i;
  int     fence;
  int     max_len;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  va_start(ap, format);
  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
      fence = cinfo->col_fence[i];
      if (fence != 0) {
        /*
         * We will append the string after the fence.
         * First arrange that we can append, if necessary.
         */
        COL_CHECK_APPEND(cinfo, i, max_len);
      } else {
        /*
         * There's no fence, so we can just write to the string.
         */
        cinfo->col_data[i] = cinfo->col_buf[i];
      }
      g_vsnprintf(&cinfo->col_buf[i][fence], max_len - fence, format, ap);
    }
  }
  va_end(ap);
}

/* The same as CHECK_COL(), but without the check to see if the column is writable. */
#define HAVE_CUSTOM_COLS(cinfo) ((cinfo) && (cinfo)->col_first[COL_CUSTOM] >= 0)

gboolean
have_custom_cols(column_info *cinfo)
{
  return HAVE_CUSTOM_COLS(cinfo);
}

/* search in edt tree custom fields */
void col_custom_set_edt(epan_dissect_t *edt, column_info *cinfo)
{
  int i;

  if(!HAVE_CUSTOM_COLS(cinfo))
      return;

  for (i = cinfo->col_first[COL_CUSTOM];
       i <= cinfo->col_last[COL_CUSTOM]; i++) {
    if (cinfo->fmt_matx[i][COL_CUSTOM] && cinfo->col_custom_field[i]) {
      cinfo->col_data[i] = cinfo->col_buf[i];

       cinfo->col_expr.col_expr[i] = epan_custom_set(edt, cinfo->col_custom_field_id[i],
                                     cinfo->col_buf[i],
                                     cinfo->col_expr.col_expr_val[i],
                                     COL_MAX_LEN);
    }
  }
}

void
col_custom_prime_edt(epan_dissect_t *edt, column_info *cinfo)
{
  int i;

  if(!HAVE_CUSTOM_COLS(cinfo))
      return;

  for (i = cinfo->col_first[COL_CUSTOM];
       i <= cinfo->col_last[COL_CUSTOM]; i++) {

    cinfo->col_custom_field_id[i] = -1;
    if (cinfo->fmt_matx[i][COL_CUSTOM] &&
		cinfo->col_custom_dfilter[i]){
        epan_dissect_prime_dfilter(edt, cinfo->col_custom_dfilter[i]);
        if (cinfo->col_custom_field) {
            header_field_info* hfinfo = proto_registrar_get_byname(cinfo->col_custom_field[i]);
            /* ASSERT if none ? */
			g_assert(hfinfo);
            cinfo->col_custom_field_id[i] = hfinfo->id;
        }
	}
  }
}

gboolean
col_has_time_fmt(column_info *cinfo, gint col)
{
  return ((cinfo->fmt_matx[col][COL_CLS_TIME]) ||
          (cinfo->fmt_matx[col][COL_ABS_TIME]) ||
          (cinfo->fmt_matx[col][COL_ABS_DATE_TIME]) ||
          (cinfo->fmt_matx[col][COL_REL_TIME]) ||
          (cinfo->fmt_matx[col][COL_DELTA_TIME]) ||
          (cinfo->fmt_matx[col][COL_DELTA_TIME_DIS]));
}

static void
col_do_append_sep_va_fstr(column_info *cinfo, gint el, const gchar *separator,
              const gchar *format, va_list ap)
{
  int  i;
  int  len, max_len, sep_len;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  if (separator == NULL)
    sep_len = 0;
  else
    sep_len = (int) strlen(separator);
  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
      /*
       * First arrange that we can append, if necessary.
       */
      COL_CHECK_APPEND(cinfo, i, max_len);

      len = (int) strlen(cinfo->col_buf[i]);

      /*
       * If we have a separator, append it if the column isn't empty.
       */
      if (separator != NULL) {
        if (len != 0) {
          g_strlcat(cinfo->col_buf[i], separator, max_len);
          len += sep_len;
        }
      }
      g_vsnprintf(&cinfo->col_buf[i][len], max_len - len, format, ap);
      cinfo->col_buf[i][max_len-1] = 0;
    }
  }
}

/* Appends a vararg list to a packet info string. */
void
col_append_fstr(column_info *cinfo, gint el, const gchar *format, ...)
{
  va_list ap;

  if (!CHECK_COL(cinfo, el))
    return;

  va_start(ap, format);
  col_do_append_sep_va_fstr(cinfo, el, NULL, format, ap);
  va_end(ap);
}

/* Appends a vararg list to a packet info string.
 * Prefixes it with the given separator if the column is not empty. */
void
col_append_sep_fstr(column_info *cinfo, gint el, const gchar *separator,
        const gchar *format, ...)
{
  va_list ap;

  if (!CHECK_COL(cinfo, el))
    return;

  if (separator == NULL)
    separator = ", ";    /* default */
  va_start(ap, format);
  col_do_append_sep_va_fstr(cinfo, el, separator, format, ap);
  va_end(ap);
}



/* Prepends a vararg list to a packet info string. */
#define COL_BUF_MAX_LEN (((COL_MAX_INFO_LEN) > (COL_MAX_LEN)) ? \
    (COL_MAX_INFO_LEN) : (COL_MAX_LEN))
void
col_prepend_fstr(column_info *cinfo, gint el, const gchar *format, ...)
{
  va_list     ap;
  int         i;
  char        orig_buf[COL_BUF_MAX_LEN];
  const char *orig;
  int         max_len;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  va_start(ap, format);
  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
      if (cinfo->col_data[i] != cinfo->col_buf[i]) {
        /* This was set with "col_set_str()"; which is effectively const */
        orig = cinfo->col_data[i];
      } else {
        g_strlcpy(orig_buf, cinfo->col_buf[i], max_len);
        orig = orig_buf;
      }
      g_vsnprintf(cinfo->col_buf[i], max_len, format, ap);
      cinfo->col_buf[i][max_len - 1] = '\0';

      /*
       * Move the fence, unless it's at the beginning of the string.
       */
      if (cinfo->col_fence[i] > 0)
        cinfo->col_fence[i] += (int) strlen(cinfo->col_buf[i]);

      g_strlcat(cinfo->col_buf[i], orig, max_len);
      cinfo->col_data[i] = cinfo->col_buf[i];
    }
  }
  va_end(ap);
}
void
col_prepend_fence_fstr(column_info *cinfo, gint el, const gchar *format, ...)
{
  va_list     ap;
  int         i;
  char        orig_buf[COL_BUF_MAX_LEN];
  const char *orig;
  int         max_len;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  va_start(ap, format);
  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
      if (cinfo->col_data[i] != cinfo->col_buf[i]) {
        /* This was set with "col_set_str()"; which is effectively const */
        orig = cinfo->col_data[i];
      } else {
        g_strlcpy(orig_buf, cinfo->col_buf[i], max_len);
        orig = orig_buf;
      }
      g_vsnprintf(cinfo->col_buf[i], max_len, format, ap);
      cinfo->col_buf[i][max_len - 1] = '\0';

      /*
       * Move the fence if it exists, else create a new fence at the
       * end of the prepended data.
       */
      if (cinfo->col_fence[i] > 0) {
        cinfo->col_fence[i] += (int) strlen(cinfo->col_buf[i]);
      } else {
        cinfo->col_fence[i]  = (int) strlen(cinfo->col_buf[i]);
      }
      g_strlcat(cinfo->col_buf[i], orig, max_len);
      cinfo->col_data[i] = cinfo->col_buf[i];
    }
  }
  va_end(ap);
}

/* Use this if "str" points to something that won't stay around (and
   must thus be copied). */
void
col_add_str(column_info *cinfo, gint el, const gchar* str)
{
  int    i;
  int    fence;
  size_t max_len;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
      fence = cinfo->col_fence[i];
      if (fence != 0) {
        /*
         * We will append the string after the fence.
         * First arrange that we can append, if necessary.
         */
        COL_CHECK_APPEND(cinfo, i, max_len);
      } else {
        /*
         * There's no fence, so we can just write to the string.
         */
        cinfo->col_data[i] = cinfo->col_buf[i];
      }
      g_strlcpy(&cinfo->col_buf[i][fence], str, max_len - fence);
    }
  }
}

static void
col_do_append_str(column_info *cinfo, gint el, const gchar* separator,
    const gchar* str)
{
  int    i;
  size_t len, max_len, sep_len;

  if (!CHECK_COL(cinfo, el))
    return;

  if (el == COL_INFO)
    max_len = COL_MAX_INFO_LEN;
  else
    max_len = COL_MAX_LEN;

  if (separator == NULL)
    sep_len = 0;
  else
    sep_len = strlen(separator);

  for (i = cinfo->col_first[el]; i <= cinfo->col_last[el]; i++) {
    if (cinfo->fmt_matx[i][el]) {
      /*
       * First arrange that we can append, if necessary.
       */
      COL_CHECK_APPEND(cinfo, i, max_len);

      len = cinfo->col_buf[i][0];

      /*
       * If we have a separator, append it if the column isn't empty.
       */
      if (separator != NULL) {
        if (len != 0) {
          g_strlcat(cinfo->col_buf[i], separator, max_len);
        }
      }
      g_strlcat(cinfo->col_buf[i], str, max_len);
    }
  }
}

void
col_append_str(column_info *cinfo, gint el, const gchar* str)
{
  col_do_append_str(cinfo, el, NULL, str);
}

void
col_append_sep_str(column_info *cinfo, gint el, const gchar* separator,
    const gchar* str)
{
  if (separator == NULL)
    separator = ", ";    /* default */
  col_do_append_str(cinfo, el, separator, str);
}

/* --------------------------------- */
static gint
set_abs_date_time(frame_data *fd, gchar *buf)
{
  struct tm *tmp;
  time_t then;

  COL_CHECK_REF_TIME(fd, buf);

  then = fd->abs_ts.secs;
  tmp = localtime(&then);
  if (tmp != NULL) {
      switch(timestamp_get_precision()) {
      case(TS_PREC_FIXED_SEC):
      case(TS_PREC_AUTO_SEC):
          g_snprintf(buf, COL_MAX_LEN,"%04d-%02d-%02d %02d:%02d:%02d",
             tmp->tm_year + 1900,
             tmp->tm_mon + 1,
             tmp->tm_mday,
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec);
          break;
      case(TS_PREC_FIXED_DSEC):
      case(TS_PREC_AUTO_DSEC):
          g_snprintf(buf, COL_MAX_LEN,"%04d-%02d-%02d %02d:%02d:%02d.%01ld",
             tmp->tm_year + 1900,
             tmp->tm_mon + 1,
             tmp->tm_mday,
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs / 100000000);
          break;
      case(TS_PREC_FIXED_CSEC):
      case(TS_PREC_AUTO_CSEC):
          g_snprintf(buf, COL_MAX_LEN,"%04d-%02d-%02d %02d:%02d:%02d.%02ld",
             tmp->tm_year + 1900,
             tmp->tm_mon + 1,
             tmp->tm_mday,
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs / 10000000);
          break;
      case(TS_PREC_FIXED_MSEC):
      case(TS_PREC_AUTO_MSEC):
          g_snprintf(buf, COL_MAX_LEN, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tmp->tm_year + 1900,
             tmp->tm_mon + 1,
             tmp->tm_mday,
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs / 1000000);
          break;
      case(TS_PREC_FIXED_USEC):
      case(TS_PREC_AUTO_USEC):
          g_snprintf(buf, COL_MAX_LEN, "%04d-%02d-%02d %02d:%02d:%02d.%06ld",
             tmp->tm_year + 1900,
             tmp->tm_mon + 1,
             tmp->tm_mday,
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs / 1000);
          break;
      case(TS_PREC_FIXED_NSEC):
      case(TS_PREC_AUTO_NSEC):
          g_snprintf(buf, COL_MAX_LEN, "%04d-%02d-%02d %02d:%02d:%02d.%09ld",
             tmp->tm_year + 1900,
             tmp->tm_mon + 1,
             tmp->tm_mday,
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs);
          break;
      default:
          g_assert_not_reached();
      }
  } else {
    buf[0] = '\0';
  }
  return 1;
}

static void
col_set_abs_date_time(frame_data *fd, column_info *cinfo, int col)
{
  if (set_abs_date_time(fd, cinfo->col_buf[col])) {
      cinfo->col_expr.col_expr[col] = "frame.time";
      g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->col_buf[col],COL_MAX_LEN);
  }
  cinfo->col_data[col] = cinfo->col_buf[col];
}

/* --------------------------------- */
static gint
set_rel_time(frame_data *fd, gchar *buf)
{
  COL_CHECK_REF_TIME(fd, buf);

  switch(timestamp_get_precision()) {
      case(TS_PREC_FIXED_SEC):
      case(TS_PREC_AUTO_SEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->rel_ts.secs, fd->rel_ts.nsecs / 1000000000, SECS);
          break;
      case(TS_PREC_FIXED_DSEC):
      case(TS_PREC_AUTO_DSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->rel_ts.secs, fd->rel_ts.nsecs / 100000000, DSECS);
          break;
      case(TS_PREC_FIXED_CSEC):
      case(TS_PREC_AUTO_CSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->rel_ts.secs, fd->rel_ts.nsecs / 10000000, CSECS);
          break;
      case(TS_PREC_FIXED_MSEC):
      case(TS_PREC_AUTO_MSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->rel_ts.secs, fd->rel_ts.nsecs / 1000000, MSECS);
          break;
      case(TS_PREC_FIXED_USEC):
      case(TS_PREC_AUTO_USEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->rel_ts.secs, fd->rel_ts.nsecs / 1000, USECS);
          break;
      case(TS_PREC_FIXED_NSEC):
      case(TS_PREC_AUTO_NSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->rel_ts.secs, fd->rel_ts.nsecs, NSECS);
          break;
      default:
          g_assert_not_reached();
  }
  return 1;
}

static void
col_set_rel_time(frame_data *fd, column_info *cinfo, int col)
{
  if (set_rel_time(fd, cinfo->col_buf[col])) {
      cinfo->col_expr.col_expr[col] = "frame.time_relative";
      g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->col_buf[col],COL_MAX_LEN);
  }
  cinfo->col_data[col] = cinfo->col_buf[col];
}

/* ------------------------------------------ */
static gint
set_delta_time(frame_data *fd, gchar *buf)
{
  COL_CHECK_REF_TIME(fd, buf);

  switch(timestamp_get_precision()) {
      case(TS_PREC_FIXED_SEC):
      case(TS_PREC_AUTO_SEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_cap_ts.secs, fd->del_cap_ts.nsecs / 1000000000, SECS);
          break;
      case(TS_PREC_FIXED_DSEC):
      case(TS_PREC_AUTO_DSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_cap_ts.secs, fd->del_cap_ts.nsecs / 100000000, DSECS);
          break;
      case(TS_PREC_FIXED_CSEC):
      case(TS_PREC_AUTO_CSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_cap_ts.secs, fd->del_cap_ts.nsecs / 10000000, CSECS);
          break;
      case(TS_PREC_FIXED_MSEC):
      case(TS_PREC_AUTO_MSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_cap_ts.secs, fd->del_cap_ts.nsecs / 1000000, MSECS);
          break;
      case(TS_PREC_FIXED_USEC):
      case(TS_PREC_AUTO_USEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_cap_ts.secs, fd->del_cap_ts.nsecs / 1000, USECS);
          break;
      case(TS_PREC_FIXED_NSEC):
      case(TS_PREC_AUTO_NSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_cap_ts.secs, fd->del_cap_ts.nsecs, NSECS);
          break;
      default:
          g_assert_not_reached();
  }
  return 1;
}

static void
col_set_delta_time(frame_data *fd, column_info *cinfo, int col)
{
  if (set_delta_time(fd, cinfo->col_buf[col])) {
      cinfo->col_expr.col_expr[col] = "frame.time_delta";
      g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->col_buf[col],COL_MAX_LEN);
  }
  cinfo->col_data[col] = cinfo->col_buf[col];
}

/* ------------------------------------------
 To do: Add CHECK_COL checks to the col_add* routines
*/
static gint
set_delta_time_dis(frame_data *fd, gchar *buf)
{
  COL_CHECK_REF_TIME(fd, buf);

  switch(timestamp_get_precision()) {
      case(TS_PREC_FIXED_SEC):
      case(TS_PREC_AUTO_SEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_dis_ts.secs, fd->del_dis_ts.nsecs / 1000000000, SECS);
          break;
      case(TS_PREC_FIXED_DSEC):
      case(TS_PREC_AUTO_DSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_dis_ts.secs, fd->del_dis_ts.nsecs / 100000000, DSECS);
          break;
      case(TS_PREC_FIXED_CSEC):
      case(TS_PREC_AUTO_CSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_dis_ts.secs, fd->del_dis_ts.nsecs / 10000000, CSECS);
          break;
      case(TS_PREC_FIXED_MSEC):
      case(TS_PREC_AUTO_MSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_dis_ts.secs, fd->del_dis_ts.nsecs / 1000000, MSECS);
          break;
      case(TS_PREC_FIXED_USEC):
      case(TS_PREC_AUTO_USEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_dis_ts.secs, fd->del_dis_ts.nsecs / 1000, USECS);
          break;
      case(TS_PREC_FIXED_NSEC):
      case(TS_PREC_AUTO_NSEC):
          display_signed_time(buf, COL_MAX_LEN,
            (gint32) fd->del_dis_ts.secs, fd->del_dis_ts.nsecs, NSECS);
          break;
      default:
          g_assert_not_reached();
  }
  return 1;
}

static void
col_set_delta_time_dis(frame_data *fd, column_info *cinfo, int col)
{
  if (set_delta_time_dis(fd, cinfo->col_buf[col])) {
    cinfo->col_expr.col_expr[col] = "frame.time_delta_displayed";
    g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->col_buf[col],COL_MAX_LEN);
  }
  cinfo->col_data[col] = cinfo->col_buf[col];
}

/* ------------------------ */
/* To do: Add CHECK_COL checks to the col_add* routines */

static gint
set_abs_time(frame_data *fd, gchar *buf)
{
  struct tm *tmp;
  time_t then;

  COL_CHECK_REF_TIME(fd, buf);

  then = fd->abs_ts.secs;
  tmp = localtime(&then);
  if (tmp != NULL) {
      switch(timestamp_get_precision()) {
      case(TS_PREC_FIXED_SEC):
      case(TS_PREC_AUTO_SEC):
          g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d",
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec);
          break;
      case(TS_PREC_FIXED_DSEC):
      case(TS_PREC_AUTO_DSEC):
          g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d.%01ld",
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs / 100000000);
          break;
      case(TS_PREC_FIXED_CSEC):
      case(TS_PREC_AUTO_CSEC):
          g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d.%02ld",
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs / 10000000);
          break;
      case(TS_PREC_FIXED_MSEC):
      case(TS_PREC_AUTO_MSEC):
          g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d.%03ld",
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs / 1000000);
          break;
      case(TS_PREC_FIXED_USEC):
      case(TS_PREC_AUTO_USEC):
          g_snprintf(buf, COL_MAX_LEN,"%02d:%02d:%02d.%06ld",
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs / 1000);
          break;
      case(TS_PREC_FIXED_NSEC):
      case(TS_PREC_AUTO_NSEC):
          g_snprintf(buf, COL_MAX_LEN, "%02d:%02d:%02d.%09ld",
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_ts.nsecs);
          break;
      default:
          g_assert_not_reached();
      }

  } else {
    *buf = '\0';
  }
  return 1;
}

static void
col_set_abs_time(frame_data *fd, column_info *cinfo, int col)
{
  if (set_abs_time(fd, cinfo->col_buf[col])) {
      cinfo->col_expr.col_expr[col] = "frame.time";
      g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->col_buf[col],COL_MAX_LEN);
  }
  cinfo->col_data[col] = cinfo->col_buf[col];
}

/* ------------------------ */
static gint
set_epoch_time(frame_data *fd, gchar *buf)
{

  COL_CHECK_REF_TIME(fd, buf);

  switch(timestamp_get_precision()) {
      case(TS_PREC_FIXED_SEC):
      case(TS_PREC_AUTO_SEC):
          display_epoch_time(buf, COL_MAX_LEN,
            fd->abs_ts.secs, fd->abs_ts.nsecs / 1000000000, SECS);
          break;
      case(TS_PREC_FIXED_DSEC):
      case(TS_PREC_AUTO_DSEC):
          display_epoch_time(buf, COL_MAX_LEN,
            fd->abs_ts.secs, fd->abs_ts.nsecs / 100000000, DSECS);
          break;
      case(TS_PREC_FIXED_CSEC):
      case(TS_PREC_AUTO_CSEC):
          display_epoch_time(buf, COL_MAX_LEN,
            fd->abs_ts.secs, fd->abs_ts.nsecs / 10000000, CSECS);
          break;
      case(TS_PREC_FIXED_MSEC):
      case(TS_PREC_AUTO_MSEC):
          display_epoch_time(buf, COL_MAX_LEN,
            fd->abs_ts.secs, fd->abs_ts.nsecs / 1000000, MSECS);
          break;
      case(TS_PREC_FIXED_USEC):
      case(TS_PREC_AUTO_USEC):
          display_epoch_time(buf, COL_MAX_LEN,
            fd->abs_ts.secs, fd->abs_ts.nsecs / 1000, USECS);
          break;
      case(TS_PREC_FIXED_NSEC):
      case(TS_PREC_AUTO_NSEC):
          display_epoch_time(buf, COL_MAX_LEN,
            fd->abs_ts.secs, fd->abs_ts.nsecs, NSECS);
          break;
      default:
          g_assert_not_reached();
  }
  return 1;
}

static void
col_set_epoch_time(frame_data *fd, column_info *cinfo, int col)
{

  if (set_epoch_time(fd, cinfo->col_buf[col])) {
    cinfo->col_expr.col_expr[col] = "frame.time_delta";
    g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->col_buf[col],COL_MAX_LEN);
  }
  cinfo->col_data[col] = cinfo->col_buf[col];
}

/* Set the format of the variable time format.
   XXX - this is called from "file.c" when the user changes the time
   format they want for "command-line-specified" time; it's a bit ugly
   that we have to export it, but if we go to a CList-like widget that
   invokes callbacks to get the text for the columns rather than
   requiring us to stuff the text into the widget from outside, we
   might be able to clean this up. */
void
set_cls_time(frame_data *fd, gchar *buf)
{
  switch (timestamp_get_type()) {
    case TS_ABSOLUTE:
      set_abs_time(fd, buf);
      break;

    case TS_ABSOLUTE_WITH_DATE:
      set_abs_date_time(fd, buf);
      break;

    case TS_RELATIVE:
      set_rel_time(fd, buf);
      break;

    case TS_DELTA:
      set_delta_time(fd, buf);
      break;

    case TS_DELTA_DIS:
      set_delta_time_dis(fd, buf);
      break;

    case TS_EPOCH:
      set_epoch_time(fd, buf);
      break;

    case TS_NOT_SET:
    /* code is missing for this case, but I don't know which [jmayer20051219] */
    g_assert(FALSE);
        break;
  }
}


static void
col_set_cls_time(frame_data *fd, column_info *cinfo, gint col)
{
  switch (timestamp_get_type()) {
    case TS_ABSOLUTE:
      col_set_abs_time(fd, cinfo, col);
      break;

    case TS_ABSOLUTE_WITH_DATE:
      col_set_abs_date_time(fd, cinfo, col);
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

    case TS_NOT_SET:
      /* code is missing for this case, but I don't know which [jmayer20051219] */
      g_assert_not_reached();
      break;
  }
}

/* Set the format of the variable time format.
   XXX - this is called from "file.c" when the user changes the time
   format they want for "command-line-specified" time; it's a bit ugly
   that we have to export it, but if we go to a CList-like widget that
   invokes callbacks to get the text for the columns rather than
   requiring us to stuff the text into the widget from outside, we
   might be able to clean this up. */
void
col_set_fmt_time(frame_data *fd, column_info *cinfo, gint fmt, gint col)
{
  switch (fmt) {
    case COL_CLS_TIME:
       col_set_cls_time(fd, cinfo, col);
      break;

    case COL_ABS_TIME:
      col_set_abs_time(fd, cinfo, col);
      break;

    case COL_ABS_DATE_TIME:
      col_set_abs_date_time(fd, cinfo, col);
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

    default:
      g_assert_not_reached();
      break;
  }
}

/* --------------------------- */
void
col_set_time(column_info *cinfo, gint el, nstime_t *ts, char *fieldname)
{
  int   col;

  if (!CHECK_COL(cinfo, el))
    return;

  for (col = cinfo->col_first[el]; col <= cinfo->col_last[el]; col++) {
    if (cinfo->fmt_matx[col][el]) {
      switch(timestamp_get_precision()) {
    case(TS_PREC_FIXED_SEC):
    case(TS_PREC_AUTO_SEC):
      display_signed_time(cinfo->col_buf[col], COL_MAX_LEN,
        (gint32) ts->secs, ts->nsecs / 1000000000, SECS);
      break;
    case(TS_PREC_FIXED_DSEC):
    case(TS_PREC_AUTO_DSEC):
      display_signed_time(cinfo->col_buf[col], COL_MAX_LEN,
        (gint32) ts->secs, ts->nsecs / 100000000, DSECS);
      break;
    case(TS_PREC_FIXED_CSEC):
    case(TS_PREC_AUTO_CSEC):
      display_signed_time(cinfo->col_buf[col], COL_MAX_LEN,
        (gint32) ts->secs, ts->nsecs / 10000000, CSECS);
      break;
    case(TS_PREC_FIXED_MSEC):
    case(TS_PREC_AUTO_MSEC):
      display_signed_time(cinfo->col_buf[col], COL_MAX_LEN,
        (gint32) ts->secs, ts->nsecs / 1000000, MSECS);
      break;
    case(TS_PREC_FIXED_USEC):
    case(TS_PREC_AUTO_USEC):
      display_signed_time(cinfo->col_buf[col], COL_MAX_LEN,
        (gint32) ts->secs, ts->nsecs / 1000, USECS);
      break;
    case(TS_PREC_FIXED_NSEC):
    case(TS_PREC_AUTO_NSEC):
      display_signed_time(cinfo->col_buf[col], COL_MAX_LEN,
        (gint32) ts->secs, ts->nsecs, NSECS);
      break;
    default:
      g_assert_not_reached();
      }
      cinfo->col_data[col] = cinfo->col_buf[col];
      cinfo->col_expr.col_expr[col] = fieldname;
      g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->col_buf[col],COL_MAX_LEN);
    }
  }
}

static void
col_set_addr(packet_info *pinfo, int col, address *addr, gboolean is_src)
{
  struct e_in6_addr ipv6_addr;

  if (addr->type == AT_NONE)
    /* No address, nothing to do */
    return;

#ifdef NEW_PACKET_LIST
  pinfo->cinfo->col_data[col] = se_get_addr_name(addr);
#else
  get_addr_name_buf(addr, pinfo->cinfo->col_buf[col], COL_MAX_LEN);
  pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
#endif

  switch (addr->type) {

  case AT_ETHER:
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "eth.src";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "eth.dst";
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], ether_to_str(addr->data), COL_MAX_LEN);
    break;

  case AT_IPv4:
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "ip.src";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "ip.dst";
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], ip_to_str(addr->data), COL_MAX_LEN);
    break;

  case AT_IPv6:
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "ipv6.src";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "ipv6.dst";
    memcpy(&ipv6_addr.bytes, addr->data, sizeof ipv6_addr.bytes);
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], ip6_to_str(&ipv6_addr), COL_MAX_LEN);
    break;

  case AT_ATALK:
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "ddp.src";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "ddp.dst";
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], pinfo->cinfo->col_buf[col], COL_MAX_LEN);
    break;

  case AT_ARCNET:
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "arcnet.src";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "arcnet.dst";
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], pinfo->cinfo->col_buf[col], COL_MAX_LEN);
    break;

  case AT_URI:
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "uri.src";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "uri.dst";
    address_to_str_buf(addr, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    break;

  default:
    break;
  }
}

/* ------------------------ */
static void
col_set_port(packet_info *pinfo, int col, gboolean is_res, gboolean is_src)
{
  guint32 port;

  if (is_src)
    port = pinfo->srcport;
  else
    port = pinfo->destport;

  switch (pinfo->ptype) {
  case PT_SCTP:
    if (is_res)
      g_strlcpy(pinfo->cinfo->col_buf[col], get_sctp_port(port), COL_MAX_LEN);
    else
      g_snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;

  case PT_TCP:
    g_snprintf(pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN, "%u", port);
    if (is_res)
      g_strlcpy(pinfo->cinfo->col_buf[col], get_tcp_port(port), COL_MAX_LEN);
    else
      g_strlcpy(pinfo->cinfo->col_buf[col], pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "tcp.srcport";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "tcp.dstport";
    break;

  case PT_UDP:
    g_snprintf(pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN, "%u", port);
    if (is_res)
      g_strlcpy(pinfo->cinfo->col_buf[col], get_udp_port(port), COL_MAX_LEN);
    else
      g_strlcpy(pinfo->cinfo->col_buf[col], pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
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
    g_snprintf(pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN, "%u", port);
    g_strlcpy(pinfo->cinfo->col_buf[col], pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    break;

  case PT_IPX:
    /* XXX - resolve IPX socket numbers */
    g_snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "0x%04x", port);
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], pinfo->cinfo->col_buf[col],COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "ipx.src.socket";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "ipx.dst.socket";
    break;

  case PT_IDP:
    /* XXX - resolve IDP socket numbers */
    g_snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "0x%04x", port);
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], pinfo->cinfo->col_buf[col],COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "idp.src.socket";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "idp.dst.socket";
    break;

  case PT_USB:
    /* XXX - resolve USB endpoint numbers */
    g_snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "0x%08x", port);
    g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], pinfo->cinfo->col_buf[col],COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "usb.src.endpoint";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "usb.dst.endpoint";
    break;

  default:
    break;
  }
  pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
}

gboolean
col_based_on_frame_data(column_info *cinfo, gint col)
{
    switch (cinfo->col_fmt[col]) {

    case COL_NUMBER:
    case COL_CLS_TIME:
    case COL_ABS_TIME:
    case COL_ABS_DATE_TIME:
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
col_fill_in_frame_data(frame_data *fd, column_info *cinfo, gint col)
{
    switch (cinfo->col_fmt[col]) {

    case COL_NUMBER:
      g_snprintf(cinfo->col_buf[col], COL_MAX_LEN, "%u", fd->num);
      cinfo->col_data[col] = cinfo->col_buf[col];
      cinfo->col_expr.col_expr[col] = "frame.number";
      g_strlcpy(cinfo->col_expr.col_expr_val[col], cinfo->col_buf[col], COL_MAX_LEN);
      break;

    case COL_CLS_TIME:
    case COL_ABS_TIME:
    case COL_ABS_DATE_TIME:
    case COL_REL_TIME:
    case COL_DELTA_TIME:
    case COL_DELTA_TIME_DIS:
      col_set_fmt_time(fd, cinfo, cinfo->col_fmt[col], col);
      break;

    case COL_PACKET_LENGTH:
      g_snprintf(cinfo->col_buf[col], COL_MAX_LEN, "%u", fd->pkt_len);
      cinfo->col_data[col] = cinfo->col_buf[col];
      cinfo->col_expr.col_expr[col] = "frame.len";
      g_strlcpy(cinfo->col_expr.col_expr_val[col], cinfo->col_buf[col], COL_MAX_LEN);
      break;

    case COL_CUMULATIVE_BYTES:
      g_snprintf(cinfo->col_buf[col], COL_MAX_LEN, "%u", fd->cum_bytes);
      cinfo->col_data[col] = cinfo->col_buf[col];
      break;

    default:
      break;
    }
}

void
col_fill_in(packet_info *pinfo, gboolean fill_fd_colums)
{
  int i;

  if (!pinfo->cinfo)
    return;

  for (i = 0; i < pinfo->cinfo->num_cols; i++) {
    switch (pinfo->cinfo->col_fmt[i]) {

    case COL_NUMBER:
    case COL_CLS_TIME:
    case COL_ABS_TIME:
    case COL_ABS_DATE_TIME:
    case COL_REL_TIME:
    case COL_DELTA_TIME:
    case COL_DELTA_TIME_DIS:
    case COL_PACKET_LENGTH:
    case COL_CUMULATIVE_BYTES:
      if (fill_fd_colums)
        col_fill_in_frame_data(pinfo->fd, pinfo->cinfo, i);
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:   /* COL_DEF_SRC is currently just like COL_RES_SRC */
      col_set_addr(pinfo, i, &pinfo->src, TRUE);
      break;

    case COL_UNRES_SRC:
      col_set_addr(pinfo, i, &pinfo->src, TRUE);
      break;

    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
      col_set_addr(pinfo, i, &pinfo->dl_src, TRUE);
      break;

    case COL_UNRES_DL_SRC:
      col_set_addr(pinfo, i, &pinfo->dl_src, TRUE);
      break;

    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
      col_set_addr(pinfo, i, &pinfo->net_src, TRUE);
      break;

    case COL_UNRES_NET_SRC:
      col_set_addr(pinfo, i, &pinfo->net_src, TRUE);
      break;

    case COL_DEF_DST:
    case COL_RES_DST:   /* COL_DEF_DST is currently just like COL_RES_DST */
      col_set_addr(pinfo, i, &pinfo->dst, FALSE);
      break;

    case COL_UNRES_DST:
      col_set_addr(pinfo, i, &pinfo->dst, FALSE);
      break;

    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
      col_set_addr(pinfo, i, &pinfo->dl_dst, FALSE);
      break;

    case COL_UNRES_DL_DST:
      col_set_addr(pinfo, i, &pinfo->dl_dst, FALSE);
      break;

    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
      col_set_addr(pinfo, i, &pinfo->net_dst, FALSE);
      break;

    case COL_UNRES_NET_DST:
      col_set_addr(pinfo, i, &pinfo->net_dst, FALSE);
      break;

    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:  /* COL_DEF_SRC_PORT is currently just like COL_RES_SRC_PORT */
      col_set_port(pinfo, i, TRUE, TRUE);
      break;

    case COL_UNRES_SRC_PORT:
      col_set_port(pinfo, i, FALSE, TRUE);
      break;

    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:  /* COL_DEF_DST_PORT is currently just like COL_RES_DST_PORT */
      col_set_port(pinfo, i, TRUE, FALSE);
      break;

    case COL_UNRES_DST_PORT:
      col_set_port(pinfo, i, FALSE, FALSE);
      break;

    case COL_DSTIDX:
      g_snprintf(pinfo->cinfo->col_buf[i], COL_MAX_LEN, "0x%x", pinfo->dst_idx);
      pinfo->cinfo->col_data[i] = pinfo->cinfo->col_buf[i];
      break;

    case COL_VSAN:
      g_snprintf(pinfo->cinfo->col_buf[i], COL_MAX_LEN, "%u", pinfo->vsan);
      pinfo->cinfo->col_data[i] = pinfo->cinfo->col_buf[i];
      break;

    case COL_CUSTOM:    /* done by col_custom_set_edt() */
      break;

    case COL_PROTOCOL:  /* currently done by dissectors */
    case COL_INFO:      /* currently done by dissectors */
      break;

    case COL_IF_DIR:    /* currently done by dissectors */
      break;

    case COL_DCE_CALL:  /* done by dcerpc */
      break;

    case COL_DCE_CTX:   /* done by dcerpc */
      break;

    case COL_8021Q_VLAN_ID: /* done by packet-nstrace.c and packet-vlan.c */
      break;

    case COL_EXPERT:    /* done by expert.c */
      break;

    case COL_FREQ_CHAN: /* done by radio dissectors */
      break;

    case NUM_COL_FMTS:  /* keep compiler happy - shouldn't get here */
    default:
      g_assert_not_reached();
      break;
    }
  }
}

#if 0
XXX this needs more rework?
/* --------------------------- */

static  gchar *
set_addr(address *addr, gboolean is_res)
{
  if (addr->type == AT_NONE)
    return "";  /* no address, nothing to do */

  if (is_res) {
    return se_get_addr_name(addr /*, COL_MAX_LEN*/);
  }
  return se_address_to_str(addr);
}

/* Fills col_text in the frame data structure */
void
col_fill_fdata(packet_info *pinfo)
{
  int i;
  frame_data *fdata;
  gboolean res;

  if (!pinfo->cinfo)
    return;

  fdata = pinfo->fd;

  res =FALSE;

  for (i = 0; i < pinfo->cinfo->num_cols; i++) {

    switch (pinfo->cinfo->col_fmt[i]) {
    case COL_NUMBER:           /* frame number */
    case COL_PACKET_LENGTH:    /* fd->pkt_len */
    case COL_CUMULATIVE_BYTES: /* fd->cum_bytes */
    case COL_CLS_TIME:
    case COL_ABS_TIME:
    case COL_ABS_DATE_TIME:    /* from fd structures */
    case COL_REL_TIME:
    case COL_DELTA_TIME:
    case COL_DELTA_TIME_DIS:
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:   /* COL_DEF_SRC is currently just like COL_RES_SRC */
      res = TRUE;
    case COL_UNRES_SRC:
      fdata->col_text[i] = set_addr(&pinfo->src, res);
      break;

    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
      res = TRUE;
    case COL_UNRES_DL_SRC:
      fdata->col_text[i] = set_addr (&pinfo->dl_src, res);
      break;

    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
      res = TRUE;
    case COL_UNRES_NET_SRC:
      fdata->col_text[i] = set_addr (&pinfo->net_src, res);
      break;

    case COL_DEF_DST:
    case COL_RES_DST:   /* COL_DEF_DST is currently just like COL_RES_DST */
      res = TRUE;
    case COL_UNRES_DST:
      fdata->col_text[i] = set_addr (&pinfo->dst, res);
      break;

    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
      res = TRUE;
    case COL_UNRES_DL_DST:
      fdata->col_text[i] = set_addr (&pinfo->dl_dst, res);
      break;

    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
      res = TRUE;
    case COL_UNRES_NET_DST:
      fdata->col_text[i] = set_addr (&pinfo->net_dst, res);
      break;

    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:  /* COL_DEF_SRC_PORT is currently just like COL_RES_SRC_PORT */
      fdata->col_text[i] = set_port(pinfo, TRUE, pinfo->srcport);
      break;
    case COL_UNRES_SRC_PORT:
      fdata->col_text[i] = set_port(pinfo, FALSE, pinfo->srcport);
      break;

    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:  /* COL_DEF_DST_PORT is currently just like COL_RES_DST_PORT */
      fdata->col_text[i] = set_port(pinfo, TRUE, pinfo->destport);
      break;

    case COL_UNRES_DST_PORT:
      fdata->col_text[i] = set_port(pinfo, FALSE, pinfo->destport);
      break;

    case COL_IF_DIR:    /* currently done by dissectors */
    case COL_PROTOCOL:
    case COL_INFO:
    case COL_HPUX_SUBSYS:
    case COL_HPUX_DEVID:
    case COL_DCE_CALL:
    case COL_8021Q_VLAN_ID:
    case COL_DSCP_VALUE:
    case COL_COS_VALUE:
    case COL_FR_DLCI:
    case COL_BSSGP_TLLI:
    case COL_EXPERT:
    case COL_CUSTOM:
    case COL_FREQ_CHAN:
      if (pinfo->cinfo->col_data[i] != pinfo->cinfo->col_buf[i]) {
         /* XXX assume it's a constant */
         fdata->col_text[i] = (gchar *)pinfo->cinfo->col_data[i];
      }
      else {
         /* copy */
         fdata->col_text[i] = se_strdup(pinfo->cinfo->col_data[i]);
      }
      break;
    case COL_OXID:
      fdata->col_text[i] = (gchar *)(GUINT_TO_POINTER((guint)pinfo->oxid));
      break;
    case COL_RXID:
      fdata->col_text[i] = (gchar *)(GUINT_TO_POINTER((guint)pinfo->rxid));
      break;
    case COL_CIRCUIT_ID:
      set_circuit_id(pinfo);
      break;
    case COL_SRCIDX:
      fdata->col_text[i] = (gchar *)(GUINT_TO_POINTER((guint)pinfo->src_idx));
      break;
    case COL_DSTIDX:
      fdata->col_text[i] = (gchar *)(GUINT_TO_POINTER((guint)pinfo->dst_idx));
      break;
    case COL_VSAN:
      fdata->col_text[i] = (gchar *)(GUINT_TO_POINTER((guint)pinfo->vsan));
      break;

    case NUM_COL_FMTS:  /* keep compiler happy - shouldn't get here */
      g_assert_not_reached();
      break;
    }
  }
}

/* XXX Gets/creates the text fro col_text in frame data */
/* --------------------- */
gchar *
col_get_text(frame_data *fd, column_info *cinfo, gint col)
{
static gchar fmtbuf[3][COL_MAX_LEN];
static int idx;
gchar  *buf;
gchar  *ptr;

    idx = (idx + 1) % 3;
    buf = fmtbuf[idx];
    *buf = 0;
    ptr = buf;

    switch (cinfo->col_fmt[col]) {
    case COL_NUMBER: /* frame number */
      g_snprintf(buf, COL_MAX_LEN, "%u", fd->num);
      break;

    case COL_CLS_TIME:
      set_cls_time(fd, buf);
      break;
    case COL_ABS_TIME:
      set_abs_time(fd, buf);
      break;
    case COL_ABS_DATE_TIME:
      set_abs_date_time(fd, buf);
      break;
    case COL_REL_TIME:
      set_rel_time(fd, buf);
      break;
    case COL_DELTA_TIME:
      set_delta_time(fd, buf);
      break;
    case COL_DELTA_TIME_DIS:
      set_delta_time_dis(fd, buf);
      break;

    case COL_PACKET_LENGTH: /* fd->pkt_len */
      g_snprintf(buf, COL_MAX_LEN, "%u", fd->pkt_len);
      break;

    case COL_CUMULATIVE_BYTES: /* fd->cum_bytes */
      g_snprintf(buf, COL_MAX_LEN, "%u", fd->cum_bytes);
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:   /* network address */
    case COL_UNRES_SRC:
    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
    case COL_UNRES_DL_SRC:
    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
    case COL_UNRES_NET_SRC:
    case COL_DEF_DST:
    case COL_RES_DST:
    case COL_UNRES_DST:
    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
    case COL_UNRES_DL_DST:
    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
    case COL_UNRES_NET_DST:

    case COL_IF_DIR:
    case COL_CIRCUIT_ID:
    case COL_PROTOCOL:
    case COL_INFO:
    case COL_HPUX_SUBSYS:
    case COL_HPUX_DEVID:
    case COL_DCE_CALL:
    case COL_8021Q_VLAN_ID:
    case COL_DSCP_VALUE:
    case COL_COS_VALUE:
    case COL_FR_DLCI:
    case COL_BSSGP_TLLI:
    case COL_EXPERT:
    case COL_CUSTOM:
    case COL_FREQ_CHAN:
      ptr = fd->col_text[col];
      break;

    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:
    case COL_UNRES_SRC_PORT:
    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:
    case COL_UNRES_DST_PORT:
      /* hack */
      if (GPOINTER_TO_UINT(fd->col_text[col]) <= 65536)
          g_snprintf(buf, COL_MAX_LEN, "%u", GPOINTER_TO_UINT(fd->col_text[col]));
      else
          ptr = fd->col_text[col];
      break;

    case COL_OXID:
    case COL_RXID:
    case COL_SRCIDX:
    case COL_DSTIDX:
      g_snprintf(buf, COL_MAX_LEN, "0x%x", GPOINTER_TO_UINT(fd->col_text[col]));
      break;

    case COL_VSAN:
      g_snprintf(buf, COL_MAX_LEN, "%u", GPOINTER_TO_UINT(fd->col_text[col]));
      break;

    case NUM_COL_FMTS:  /* keep compiler happy - shouldn't get here */
      g_assert_not_reached();
      break;
    }
    return ptr;
}
#endif
