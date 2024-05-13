/* column-utils.c
 * Routines for column utilities.
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
#include <locale.h>
#include <limits.h>

#include "column-utils.h"
#include "timestamp.h"
#include "to_str.h"
#include "packet_info.h"
#include "wsutil/pint.h"
#include "addr_resolv.h"
#include "address_types.h"
#include "osi-utils.h"
#include "value_string.h"
#include "column-info.h"
#include "column.h"
#include "proto.h"

#include <epan/strutil.h>
#include <epan/epan.h>
#include <epan/dfilter/dfilter.h>

#include <wsutil/inet_cidr.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/ws_assert.h>
#include <wsutil/unicode-utils.h>
#include <wsutil/time_util.h>

#ifdef HAVE_LUA
#include <epan/wslua/wslua.h>
#endif

#define COL_BUF_MAX_LEN (((COL_MAX_INFO_LEN) > (COL_MAX_LEN)) ? \
    (COL_MAX_INFO_LEN) : (COL_MAX_LEN))

/* Used for locale decimal point */
static char *col_decimal_point;

/* Used to indicate updated column information, e.g. a new request/response. */
static bool col_data_changed_;

static int proto_cols;
static int ett_cols;

/* Allocate all the data structures for constructing column data, given
   the number of columns. */
void
col_setup(column_info *cinfo, const int num_cols)
{
  int i;

  col_decimal_point            = localeconv()->decimal_point;
  cinfo->num_cols              = num_cols;
  cinfo->columns               = g_new(col_item_t, num_cols);
  cinfo->col_first             = g_new(int, NUM_COL_FMTS);
  cinfo->col_last              = g_new(int, NUM_COL_FMTS);
  for (i = 0; i < num_cols; i++) {
    cinfo->columns[i].col_custom_fields_ids = NULL;
  }
  cinfo->col_expr.col_expr     = g_new(const char*, num_cols + 1);
  cinfo->col_expr.col_expr_val = g_new(char*, num_cols + 1);

  for (i = 0; i < NUM_COL_FMTS; i++) {
    cinfo->col_first[i] = -1;
    cinfo->col_last[i] = -1;
  }
  cinfo->prime_regex = g_regex_new(COL_CUSTOM_PRIME_REGEX,
    (GRegexCompileFlags) (G_REGEX_RAW),
    0, NULL);
}

static void
col_custom_free_cb(void *data)
{
  col_custom_t *col_custom = (col_custom_t*)data;
  dfilter_free(col_custom->dfilter);
  g_free(col_custom->dftext);
  g_free(col_custom);
}

static void
col_custom_fields_ids_free(GSList** custom_fields_id)
{
  if (*custom_fields_id != NULL) {
    g_slist_free_full(*custom_fields_id, col_custom_free_cb);
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

  if (!cinfo)
    return;

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
  g_free((char **)cinfo->col_expr.col_expr);
  g_free(cinfo->col_expr.col_expr_val);
  if (cinfo->prime_regex)
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
    col_item->writable = true;
    cinfo->col_expr.col_expr[i] = "";
    cinfo->col_expr.col_expr_val[i][0] = '\0';
  }
  cinfo->writable = true;
  cinfo->epan = epan;
}

bool
col_get_writable(column_info *cinfo, const int col)
{
  int i;
  col_item_t* col_item;

  if (cinfo == NULL)
    return false;

  /* "global" (not) writeability will always override
     an individual column */
  if ((col == -1) || (cinfo->writable == false))
    return cinfo->writable;

  if (cinfo->col_first[col] >= 0) {
    for (i = cinfo->col_first[col]; i <= cinfo->col_last[col]; i++) {
      col_item = &cinfo->columns[i];
      if (col_item->fmt_matx[col]) {
        return col_item->writable;
      }
    }
  }
  return false;
}

void
col_set_writable(column_info *cinfo, const int col, const bool writable)
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
col_set_fence(column_info *cinfo, const int el)
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
col_clear_fence(column_info *cinfo, const int el)
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
const char *
col_get_text(column_info *cinfo, const int el)
{
  int i;
  const char* text = NULL;
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
col_clear(column_info *cinfo, const int el)
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
    (void) g_strlcpy(col_item->col_buf, col_item->col_data, max_len);  \
    col_item->col_data = col_item->col_buf;         \
  }

#define COL_CHECK_REF_TIME(fd, buf)         \
  if (fd->ref_time) {                 \
    (void) g_strlcpy(buf, "*REF*", COL_MAX_LEN );  \
    return;                                 \
  }

/* The same as CHECK_COL(), but without the check to see if the column is writable. */
#define HAVE_CUSTOM_COLS(cinfo) ((cinfo) && (cinfo)->col_first[COL_CUSTOM] >= 0)

bool
have_custom_cols(column_info *cinfo)
{
  return HAVE_CUSTOM_COLS(cinfo);
}

bool
have_field_extractors(void)
{
#ifdef HAVE_LUA
    return wslua_has_field_extractors();
#else
    return false;
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

#if 0
// Needed if we create _ws.col.custom
static void
col_custom_set(proto_tree *tree, column_info *cinfo)
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
        cinfo->col_expr.col_expr[i] = proto_custom_set(tree, col_item->col_custom_fields_ids,
                                     col_item->col_custom_occurrence,
                                     col_item->col_buf,
                                     cinfo->col_expr.col_expr_val[i],
                                     COL_MAX_LEN);
    }
  }
}
#endif

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
      epan_dissect_prime_with_dfilter(edt, col_item->col_custom_dfilter);
    }
  }
}

char*
col_custom_get_filter(epan_dissect_t *edt, column_info *cinfo, const int col)
{
  col_item_t* col_item;

  ws_assert(cinfo);
  ws_assert(col < cinfo->num_cols);

  col_item = &cinfo->columns[col];
  if (col_item->fmt_matx[COL_CUSTOM] &&
      col_item->col_custom_fields &&
      col_item->col_custom_fields_ids) {

      return proto_custom_get_filter(edt, col_item->col_custom_fields_ids,
                                     col_item->col_custom_occurrence);
  }
  return NULL;
}

void
col_append_lstr(column_info *cinfo, const int el, const char *str1, ...)
{
  va_list ap;
  size_t pos, max_len;
  int    i;
  const char *str;
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
        if (G_UNLIKELY(str == NULL)) {
          str = "(null)";
        }
        WS_UTF_8_CHECK(str, -1);
        pos = ws_label_strcpy(col_item->col_buf, max_len, pos, str, 0);

      } while (pos < max_len && (str = va_arg(ap, const char *)) != COL_ADD_LSTR_TERMINATOR);
      va_end(ap);
    }
  }
}

void
col_append_str_uint(column_info *cinfo, const int col, const char *abbrev, uint32_t val, const char *sep)
{
  char buf[16];

  guint32_to_str_buf(val, buf, sizeof(buf));
  col_append_lstr(cinfo, col, sep ? sep : "", abbrev, "=", buf, COL_ADD_LSTR_TERMINATOR);
}

static inline void
col_snprint_port(char *buf, size_t buf_siz, port_type typ, uint16_t val)
{
  const char *str;

  if (gbl_resolv_flags.transport_name &&
        (str = try_serv_name_lookup(typ, val)) != NULL) {
    snprintf(buf, buf_siz, "%s(%"PRIu16")", str, val);
  } else {
    snprintf(buf, buf_siz, "%"PRIu16, val);
  }
}

void
col_append_ports(column_info *cinfo, const int col, port_type typ, uint16_t src, uint16_t dst)
{
  char buf_src[32], buf_dst[32];

  col_snprint_port(buf_src, 32, typ, src);
  col_snprint_port(buf_dst, 32, typ, dst);
  col_append_lstr(cinfo, col, buf_src, " " UTF8_RIGHTWARDS_ARROW " ", buf_dst, COL_ADD_LSTR_TERMINATOR);
}

void
col_append_frame_number(packet_info *pinfo, const int col, const char *fmt_str, unsigned frame_num)
{
  col_append_fstr(pinfo->cinfo, col, fmt_str, frame_num);
  if (!pinfo->fd->visited) {
    col_data_changed_ = true;
  }
}

static void
col_do_append_fstr(column_info *cinfo, const int el, const char *separator, const char *format, va_list ap)
{
  size_t len, max_len, sep_len, pos;
  int    i;
  col_item_t* col_item;
  char tmp[COL_BUF_MAX_LEN];

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
        (void) ws_label_strcat(col_item->col_buf, max_len, separator, 0);
        len += sep_len;
      }

      if (len < max_len) {
        va_list ap2;

        va_copy(ap2, ap);
        pos = vsnprintf(tmp, sizeof(tmp), format, ap2);
        va_end(ap2);
        if (pos >= max_len) {
          ws_utf8_truncate(tmp, max_len - 1);
        }
        WS_UTF_8_CHECK(tmp, -1);
        ws_label_strcpy(col_item->col_buf, max_len, len, tmp, 0);
      }
    }
  }
}

/*  Appends a vararg list to a packet info string. */
void
col_append_fstr(column_info *cinfo, const int el, const char *format, ...)
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
col_append_sep_fstr(column_info *cinfo, const int el, const char *separator,
                    const char *format, ...)
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
void
col_prepend_fstr(column_info *cinfo, const int el, const char *format, ...)
{
  va_list     ap;
  int         i;
  char        orig_buf[COL_BUF_MAX_LEN];
  const char *orig;
  size_t      max_len, pos;
  col_item_t* col_item;
  char tmp[COL_BUF_MAX_LEN];

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
        (void) g_strlcpy(orig_buf, col_item->col_buf, max_len);
        orig = orig_buf;
      }
      va_start(ap, format);
      pos = vsnprintf(tmp, sizeof(tmp), format, ap);
      va_end(ap);
      if (pos >= max_len) {
        ws_utf8_truncate(tmp, max_len - 1);
      }
      WS_UTF_8_CHECK(tmp, -1);
      pos = ws_label_strcpy(col_item->col_buf, max_len, 0, tmp, 0);

      /*
       * Move the fence, unless it's at the beginning of the string.
       */
      if (col_item->col_fence > 0)
        col_item->col_fence += (int) strlen(col_item->col_buf);

      /*
       * Append the original data.
       */
      ws_label_strcpy(col_item->col_buf, max_len, pos, orig, 0);
      col_item->col_data = col_item->col_buf;
    }
  }
}
void
col_prepend_fence_fstr(column_info *cinfo, const int el, const char *format, ...)
{
  va_list     ap;
  int         i;
  char        orig_buf[COL_BUF_MAX_LEN];
  const char *orig;
  size_t      max_len, pos;
  col_item_t* col_item;
  char tmp[COL_BUF_MAX_LEN];

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
        (void) g_strlcpy(orig_buf, col_item->col_buf, max_len);
        orig = orig_buf;
      }
      va_start(ap, format);
      pos = vsnprintf(tmp, sizeof(tmp), format, ap);
      va_end(ap);
      if (pos >= max_len) {
        ws_utf8_truncate(tmp, max_len - 1);
      }
      WS_UTF_8_CHECK(tmp, -1);
      pos = ws_label_strcpy(col_item->col_buf, max_len, 0, tmp, 0);

      /*
       * Move the fence if it exists, else create a new fence at the
       * end of the prepended data.
       */
      if (col_item->col_fence > 0) {
        col_item->col_fence += (int) strlen(col_item->col_buf);
      } else {
        col_item->col_fence = (int) strlen(col_item->col_buf);
      }
      /*
       * Append the original data.
       */
      ws_label_strcpy(col_item->col_buf, max_len, pos, orig, 0);
      col_item->col_data = col_item->col_buf;
    }
  }
}

/* Use this if "str" points to something that won't stay around (and
   must thus be copied). */
void
col_add_str(column_info *cinfo, const int el, const char* str)
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
      WS_UTF_8_CHECK(str, -1);
      (void) ws_label_strcpy(col_item->col_buf, max_len, col_item->col_fence, str, 0);
    }
  }
}

/* Use this if "str" points to something that will stay around (and thus
   needn't be copied). */
void
col_set_str(column_info *cinfo, const int el, const char* str)
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

        (void) g_strlcpy(&col_item->col_buf[col_item->col_fence], str, max_len - col_item->col_fence);
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
col_add_lstr(column_info *cinfo, const int el, const char *str1, ...)
{
  va_list ap;
  int     i;
  size_t  pos;
  size_t  max_len;
  const char *str;
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
        if (G_UNLIKELY(str == NULL)) {
          str = "(null)";
        }
        WS_UTF_8_CHECK(str, -1);
        pos = ws_label_strcpy(col_item->col_buf, max_len, pos, str, 0);

      } while (pos < max_len && (str = va_arg(ap, const char *)) != COL_ADD_LSTR_TERMINATOR);
      va_end(ap);
    }
  }
}

/* Adds a vararg list to a packet info string. */
void
col_add_fstr(column_info *cinfo, const int el, const char *format, ...)
{
  va_list ap;
  int     i, pos;
  int     max_len;
  col_item_t* col_item;
  char tmp[COL_BUF_MAX_LEN];

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
      pos = vsnprintf(tmp, sizeof(tmp), format, ap);
      va_end(ap);
      if (pos >= max_len) {
        ws_utf8_truncate(tmp, max_len - 1);
      }
      WS_UTF_8_CHECK(tmp, -1);
      ws_label_strcpy(col_item->col_buf, max_len, col_item->col_fence, tmp, 0);
    }
  }
}

static void
col_do_append_str(column_info *cinfo, const int el, const char* separator,
    const char* str)
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
          (void) ws_label_strcat(col_item->col_buf, max_len, separator, 0);
        }
      }
      WS_UTF_8_CHECK(str, -1);
      (void) ws_label_strcat(col_item->col_buf, max_len, str, 0);
    }
  }
}

void
col_append_str(column_info *cinfo, const int el, const char* str)
{
  if (!CHECK_COL(cinfo, el))
    return;

  col_do_append_str(cinfo, el, NULL, str);
}

void
col_append_sep_str(column_info *cinfo, const int el, const char* separator,
    const char* str)
{
  if (!CHECK_COL(cinfo, el))
    return;

  if (separator == NULL)
    separator = ", ";    /* default */

  col_do_append_str(cinfo, el, separator, str);
}

/* --------------------------------- */
bool
col_has_time_fmt(column_info *cinfo, const int col)
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

static int
get_frame_timestamp_precision(const frame_data *fd)
{
  int tsprecision;

  tsprecision = timestamp_get_precision();
  if (tsprecision == TS_PREC_AUTO)
    tsprecision = fd->tsprec;
  else if (tsprecision < 0)
    ws_assert_not_reached();

  /*
   * Time stamp precision values higher than the maximum
   * precision we support can't be handled.  Just display
   * those times with the maximum precision we support.
   */
  if (tsprecision > WS_TSPREC_MAX)
    tsprecision = WS_TSPREC_MAX;

  return tsprecision;
}

static int
get_default_timestamp_precision(void)
{
  int tsprecision;

  tsprecision = timestamp_get_precision();
  if (tsprecision == TS_PREC_AUTO)
    tsprecision = WS_TSPREC_MAX; /* default to the maximum precision we support */
  else if (tsprecision < 0)
    ws_assert_not_reached();

  /*
   * Time stamp precision values higher than the maximum
   * precision we support can't be handled.  Just display
   * those times with the maximum precision we support.
   */
  if (tsprecision > WS_TSPREC_MAX)
    tsprecision = WS_TSPREC_MAX;

  return tsprecision;
}

static void
set_abs_ymd_time(const frame_data *fd, char *buf, char *decimal_point, bool local)
{
  if (!fd->has_ts) {
    buf[0] = '\0';
    return;
  }
  format_nstime_as_iso8601(buf, COL_MAX_LEN, &fd->abs_ts, decimal_point, local, get_frame_timestamp_precision(fd));
}

static void
col_set_abs_ymd_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_ymd_time(fd, cinfo->columns[col].col_buf, col_decimal_point, true);
  cinfo->col_expr.col_expr[col] = "frame.time";
  (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_utc_ymd_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_ymd_time(fd, cinfo->columns[col].col_buf, col_decimal_point, false);
  cinfo->col_expr.col_expr[col] = "frame.time";
  (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
set_abs_ydoy_time(const frame_data *fd, char *buf, char *decimal_point, bool local)
{
  struct tm tm, *tmp;
  char *ptr;
  size_t remaining;
  int num_bytes;
  int tsprecision;

  if (!fd->has_ts) {
    buf[0] = '\0';
    return;
  }

  if (local)
    tmp = ws_localtime_r(&fd->abs_ts.secs, &tm);
  else
    tmp = ws_gmtime_r(&fd->abs_ts.secs, &tm);
  if (tmp == NULL) {
    snprintf(buf, COL_MAX_LEN, "Not representable");
    return;
  }
  ptr = buf;
  remaining = COL_MAX_LEN;
  num_bytes = snprintf(ptr, remaining,"%04d/%03d %02d:%02d:%02d",
    tmp->tm_year + 1900,
    tmp->tm_yday + 1,
    tmp->tm_hour,
    tmp->tm_min,
    tmp->tm_sec);
  if (num_bytes < 0) {
    /*
     * That got an error.
     * Not much else we can do.
     */
    snprintf(ptr, remaining, "snprintf() failed");
    return;
  }
  if ((unsigned int)num_bytes >= remaining) {
    /*
     * That filled up or would have overflowed the buffer.
     * Nothing more we can do.
     */
    return;
  }
  ptr += num_bytes;
  remaining -= num_bytes;

  tsprecision = get_frame_timestamp_precision(fd);
  if (tsprecision != 0) {
    /*
     * Append the fractional part.
     * Get the nsecs as a 32-bit unsigned value, as it should never
     * be negative, so we treat it as unsigned.
     */
    format_fractional_part_nsecs(ptr, remaining, (uint32_t)fd->abs_ts.nsecs, decimal_point, tsprecision);
  }
}

static void
col_set_abs_ydoy_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_ydoy_time(fd, cinfo->columns[col].col_buf, col_decimal_point, true);
  cinfo->col_expr.col_expr[col] = "frame.time";
  (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_utc_ydoy_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_ydoy_time(fd, cinfo->columns[col].col_buf, col_decimal_point, false);
  cinfo->col_expr.col_expr[col] = "frame.time";
  (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
set_time_seconds(const frame_data *fd, const nstime_t *ts, char *buf)
{
  ws_assert(fd->has_ts);

  display_signed_time(buf, COL_MAX_LEN, ts, get_frame_timestamp_precision(fd));
}

static void
set_time_hour_min_sec(const frame_data *fd, const nstime_t *ts, char *buf, char *decimal_point)
{
  time_t secs = ts->secs;
  uint32_t nsecs;
  bool negative = false;
  char *ptr;
  size_t remaining;
  int num_bytes;
  int tsprecision;

  ws_assert(fd->has_ts);

  if (secs < 0) {
    secs = -secs;
    negative = true;
  }
  if (ts->nsecs >= 0) {
    nsecs = ts->nsecs;
  } else if (G_LIKELY(ts->nsecs != INT_MIN)) {
    /*
     * This isn't the smallest negative number that fits in 32
     * bits, so we can compute its negative and store it in a
     * 32-bit unsigned int variable.
     */
    nsecs = -ts->nsecs;
    negative = true;
  } else {
    /*
     * -2147483648 is the smallest number that fits in a signed
     * 2's complement 32-bit variable, and its negative doesn't
     * fit in 32 bits.
     *
     * Just cast it to a 32-bit unsigned int value to set the
     * 32-bit unsigned int variable to 2147483648.
     *
     * Note that, on platforms where both integers and long
     * integers are 32-bit, such as 32-bit UN*Xes and both
     * 32-bit *and* 64-bit Windows, making the variable in
     * question a long will not avoid undefined behavior.
     */
    nsecs = (uint32_t)ts->nsecs;
    negative = true;
  }
  ptr = buf;
  remaining = COL_MAX_LEN;
  if (secs >= (60*60)) {
    num_bytes = snprintf(ptr, remaining, "%s%dh %2dm %2d",
               negative ? "- " : "",
               (int32_t) secs / (60 * 60),
               (int32_t) (secs / 60) % 60,
               (int32_t) secs % 60);
  } else if (secs >= 60) {
    num_bytes = snprintf(ptr, remaining, "%s%dm %2d",
               negative ? "- " : "",
               (int32_t) secs / 60,
               (int32_t) secs % 60);
  } else {
    num_bytes = snprintf(ptr, remaining, "%s%d",
               negative ? "- " : "",
               (int32_t) secs);
  }
  if (num_bytes < 0) {
    /*
     * That got an error.
     * Not much else we can do.
     */
    snprintf(ptr, remaining, "snprintf() failed");
    return;
  }
  if ((unsigned int)num_bytes >= remaining) {
    /*
     * That filled up or would have overflowed the buffer.
     * Nothing more we can do.
     */
    return;
  }
  ptr += num_bytes;
  remaining -= num_bytes;

  tsprecision = get_frame_timestamp_precision(fd);
  if (tsprecision != 0) {
    /*
     * Append the fractional part.
     */
    num_bytes = format_fractional_part_nsecs(ptr, remaining, nsecs, decimal_point, tsprecision);
    if ((unsigned int)num_bytes >= remaining) {
      /*
       * That filled up or would have overflowed the buffer.
       * Nothing more we can do.
       */
      return;
    }
    ptr += num_bytes;
    remaining -= num_bytes;
  }

  /* Append the "s" for seconds. */
  snprintf(ptr, remaining, "s");
}

static void
col_set_rel_time(const frame_data *fd, column_info *cinfo, const int col)
{
  nstime_t del_rel_ts;

  if (!fd->has_ts) {
    cinfo->columns[col].col_buf[0] = '\0';
    return;
  }

  frame_delta_abs_time(cinfo->epan, fd, fd->frame_ref_num, &del_rel_ts);

  switch (timestamp_get_seconds_type()) {
  case TS_SECONDS_DEFAULT:
    set_time_seconds(fd, &del_rel_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_relative";
    (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);
    break;
  case TS_SECONDS_HOUR_MIN_SEC:
    set_time_hour_min_sec(fd, &del_rel_ts, cinfo->columns[col].col_buf, col_decimal_point);
    cinfo->col_expr.col_expr[col] = "frame.time_relative";
    set_time_seconds(fd, &del_rel_ts, cinfo->col_expr.col_expr_val[col]);
    break;
  default:
    ws_assert_not_reached();
  }
  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_delta_time(const frame_data *fd, column_info *cinfo, const int col)
{
  nstime_t del_cap_ts;

  if (!fd->has_ts) {
    cinfo->columns[col].col_buf[0] = '\0';
    return;
  }

  frame_delta_abs_time(cinfo->epan, fd, fd->num - 1, &del_cap_ts);

  switch (timestamp_get_seconds_type()) {
  case TS_SECONDS_DEFAULT:
    set_time_seconds(fd, &del_cap_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_delta";
    (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);
    break;
  case TS_SECONDS_HOUR_MIN_SEC:
    set_time_hour_min_sec(fd, &del_cap_ts, cinfo->columns[col].col_buf, col_decimal_point);
    cinfo->col_expr.col_expr[col] = "frame.time_delta";
    set_time_seconds(fd, &del_cap_ts, cinfo->col_expr.col_expr_val[col]);
    break;
  default:
    ws_assert_not_reached();
  }

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_delta_time_dis(const frame_data *fd, column_info *cinfo, const int col)
{
  nstime_t del_dis_ts;

  if (!fd->has_ts) {
    cinfo->columns[col].col_buf[0] = '\0';
    return;
  }

  frame_delta_abs_time(cinfo->epan, fd, fd->prev_dis_num, &del_dis_ts);

  switch (timestamp_get_seconds_type()) {
  case TS_SECONDS_DEFAULT:
    set_time_seconds(fd, &del_dis_ts, cinfo->columns[col].col_buf);
    cinfo->col_expr.col_expr[col] = "frame.time_delta_displayed";
    (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);
    break;
  case TS_SECONDS_HOUR_MIN_SEC:
    set_time_hour_min_sec(fd, &del_dis_ts, cinfo->columns[col].col_buf, col_decimal_point);
    cinfo->col_expr.col_expr[col] = "frame.time_delta_displayed";
    set_time_seconds(fd, &del_dis_ts, cinfo->col_expr.col_expr_val[col]);
    break;
  default:
    ws_assert_not_reached();
  }

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

/*
 * Time, without date.
 */
static void
set_abs_time(const frame_data *fd, char *buf, char *decimal_point, bool local)
{
  struct tm tm, *tmp;
  char *ptr;
  size_t remaining;
  int num_bytes;
  int tsprecision;

  if (!fd->has_ts) {
    *buf = '\0';
    return;
  }

  ptr = buf;
  remaining = COL_MAX_LEN;

  if (local)
    tmp = ws_localtime_r(&fd->abs_ts.secs, &tm);
  else
    tmp = ws_gmtime_r(&fd->abs_ts.secs, &tm);
  if (tmp == NULL) {
    snprintf(ptr, remaining, "Not representable");
    return;
  }

  /* Integral part. */
  num_bytes = snprintf(ptr, remaining, "%02d:%02d:%02d",
    tmp->tm_hour,
    tmp->tm_min,
    tmp->tm_sec);
  if (num_bytes < 0) {
    /*
     * That got an error.
     * Not much else we can do.
     */
    snprintf(ptr, remaining, "snprintf() failed");
    return;
  }
  if ((unsigned int)num_bytes >= remaining) {
    /*
     * That filled up or would have overflowed the buffer.
     * Nothing more we can do.
     */
    return;
  }
  ptr += num_bytes;
  remaining -= num_bytes;

  tsprecision = get_frame_timestamp_precision(fd);
  if (tsprecision != 0) {
    /*
     * Append the fractional part.
     * Get the nsecs as a 32-bit unsigned value, as it should never
     * be negative, so we treat it as unsigned.
     */
    format_fractional_part_nsecs(ptr, remaining, (uint32_t)fd->abs_ts.nsecs, decimal_point, tsprecision);
  }
}

static void
col_set_abs_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_time(fd, cinfo->columns[col].col_buf, col_decimal_point, true);
  cinfo->col_expr.col_expr[col] = "frame.time";
  (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static void
col_set_utc_time(const frame_data *fd, column_info *cinfo, const int col)
{
  set_abs_time(fd, cinfo->columns[col].col_buf, col_decimal_point, false);
  cinfo->col_expr.col_expr[col] = "frame.time";
  (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);

  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

static bool
set_epoch_time(const frame_data *fd, char *buf)
{
  if (!fd->has_ts) {
    buf[0] = '\0';
    return false;
  }
  display_epoch_time(buf, COL_MAX_LEN, &fd->abs_ts, get_frame_timestamp_precision(fd));
  return true;
}

static void
col_set_epoch_time(const frame_data *fd, column_info *cinfo, const int col)
{
  if (set_epoch_time(fd, cinfo->columns[col].col_buf)) {
    cinfo->col_expr.col_expr[col] = "frame.time_delta";
    (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],cinfo->columns[col].col_buf,COL_MAX_LEN);
  }
  cinfo->columns[col].col_data = cinfo->columns[col].col_buf;
}

void
set_fd_time(const epan_t *epan, frame_data *fd, char *buf)
{

  switch (timestamp_get_type()) {
  case TS_ABSOLUTE:
    set_abs_time(fd, buf, col_decimal_point, true);
    break;

  case TS_ABSOLUTE_WITH_YMD:
    set_abs_ymd_time(fd, buf, col_decimal_point, true);
    break;

  case TS_ABSOLUTE_WITH_YDOY:
    set_abs_ydoy_time(fd, buf, col_decimal_point, true);
    break;

  case TS_RELATIVE:
    if (fd->has_ts) {
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
        ws_assert_not_reached();
      }
    } else {
      buf[0] = '\0';
    }
    break;

  case TS_DELTA:
    if (fd->has_ts) {
      nstime_t del_cap_ts;

      frame_delta_abs_time(epan, fd, fd->num - 1, &del_cap_ts);

      switch (timestamp_get_seconds_type()) {
      case TS_SECONDS_DEFAULT:
        set_time_seconds(fd, &del_cap_ts, buf);
        break;
      case TS_SECONDS_HOUR_MIN_SEC:
        set_time_hour_min_sec(fd, &del_cap_ts, buf, col_decimal_point);
        break;
      default:
        ws_assert_not_reached();
      }
    } else {
      buf[0] = '\0';
    }
    break;

  case TS_DELTA_DIS:
    if (fd->has_ts) {
      nstime_t del_dis_ts;

      frame_delta_abs_time(epan, fd, fd->prev_dis_num, &del_dis_ts);

      switch (timestamp_get_seconds_type()) {
      case TS_SECONDS_DEFAULT:
        set_time_seconds(fd, &del_dis_ts, buf);
        break;
      case TS_SECONDS_HOUR_MIN_SEC:
        set_time_hour_min_sec(fd, &del_dis_ts, buf, col_decimal_point);
        break;
      default:
        ws_assert_not_reached();
      }
    } else {
      buf[0] = '\0';
    }
    break;

  case TS_EPOCH:
    set_epoch_time(fd, buf);
    break;

  case TS_UTC:
    set_abs_time(fd, buf, col_decimal_point, false);
    break;

  case TS_UTC_WITH_YMD:
    set_abs_ymd_time(fd, buf, col_decimal_point, false);
    break;

  case TS_UTC_WITH_YDOY:
    set_abs_ydoy_time(fd, buf, col_decimal_point, false);
    break;

  case TS_NOT_SET:
    /* code is missing for this case, but I don't know which [jmayer20051219] */
    ws_assert_not_reached();
    break;
  }
}

static void
col_set_cls_time(const frame_data *fd, column_info *cinfo, const int col)
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
    ws_assert_not_reached();
    break;
  }
}

/* Set the format of the variable time format. */
static void
col_set_fmt_time(const frame_data *fd, column_info *cinfo, const int fmt, const int col)
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
    ws_assert_not_reached();
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
col_set_time(column_info *cinfo, const int el, const nstime_t *ts, const char *fieldname)
{
  int col;
  col_item_t* col_item;

  if (!CHECK_COL(cinfo, el))
    return;

  /** @todo TODO: We don't respect fd->ref_time (no way to access 'fd')
  COL_CHECK_REF_TIME(fd, buf);
  */

  for (col = cinfo->col_first[el]; col <= cinfo->col_last[el]; col++) {
    col_item = &cinfo->columns[col];
    if (col_item->fmt_matx[el]) {
      display_signed_time(col_item->col_buf, COL_MAX_LEN, ts, get_default_timestamp_precision());
      col_item->col_data = col_item->col_buf;
      cinfo->col_expr.col_expr[col] = fieldname;
      (void) g_strlcpy(cinfo->col_expr.col_expr_val[col],col_item->col_buf,COL_MAX_LEN);
    }
  }
}

static void
col_set_addr(packet_info *pinfo, const int col, const address *addr, const bool is_src,
             const bool fill_col_exprs, const bool res)
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
  if (strlen(pinfo->cinfo->col_expr.col_expr[col]) > 0) {
    address_to_str_buf(addr, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
  } else {
    /* For address types that don't, use the internal column FT_STRING hfi */
    pinfo->cinfo->col_expr.col_expr[col] = proto_registrar_get_nth(col_item->hf_id)->abbrev;
    (void) g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], pinfo->cinfo->columns[col].col_data, COL_MAX_LEN);
  }
}

/* ------------------------ */
static void
col_set_port(packet_info *pinfo, const int col, const bool is_res, const bool is_src, const bool fill_col_exprs _U_)
{
  uint32_t port;
  col_item_t* col_item = &pinfo->cinfo->columns[col];

  if (is_src)
    port = pinfo->srcport;
  else
    port = pinfo->destport;

  /* TODO: Use fill_col_exprs */

  switch (pinfo->ptype) {
  case PT_SCTP:
    if (is_res)
      (void) g_strlcpy(col_item->col_buf, sctp_port_to_display(pinfo->pool, port), COL_MAX_LEN);
    else
      guint32_to_str_buf(port, col_item->col_buf, COL_MAX_LEN);
    break;

  case PT_TCP:
    guint32_to_str_buf(port, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    if (is_res)
      (void) g_strlcpy(col_item->col_buf, tcp_port_to_display(pinfo->pool, port), COL_MAX_LEN);
    else
      (void) g_strlcpy(col_item->col_buf, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "tcp.srcport";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "tcp.dstport";
    break;

  case PT_UDP:
    guint32_to_str_buf(port, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    if (is_res)
      (void) g_strlcpy(col_item->col_buf, udp_port_to_display(pinfo->pool, port), COL_MAX_LEN);
    else
      (void) g_strlcpy(col_item->col_buf, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
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
    (void) g_strlcpy(col_item->col_buf, pinfo->cinfo->col_expr.col_expr_val[col], COL_MAX_LEN);
    break;

  case PT_IPX:
    /* XXX - resolve IPX socket numbers */
    snprintf(col_item->col_buf, COL_MAX_LEN, "0x%04x", port);
    (void) g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], col_item->col_buf,COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "ipx.src.socket";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "ipx.dst.socket";
    break;

  case PT_IDP:
    /* XXX - resolve IDP socket numbers */
    snprintf(col_item->col_buf, COL_MAX_LEN, "0x%04x", port);
    (void) g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], col_item->col_buf,COL_MAX_LEN);
    if (is_src)
      pinfo->cinfo->col_expr.col_expr[col] = "idp.src.socket";
    else
      pinfo->cinfo->col_expr.col_expr[col] = "idp.dst.socket";
    break;

  case PT_USB:
    /* XXX - resolve USB endpoint numbers */
    snprintf(col_item->col_buf, COL_MAX_LEN, "0x%08x", port);
    (void) g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[col], col_item->col_buf,COL_MAX_LEN);
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

bool
col_based_on_frame_data(column_info *cinfo, const int col)
{
  ws_assert(cinfo);
  ws_assert(col < cinfo->num_cols);

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
    return true;

  default:
    return false;
  }
}

void
col_fill_in_frame_data(const frame_data *fd, column_info *cinfo, const int col, const bool fill_col_exprs)
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
    (void) g_strlcpy(cinfo->col_expr.col_expr_val[col], col_item->col_buf, COL_MAX_LEN);
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
    (void) g_strlcpy(cinfo->col_expr.col_expr_val[col], col_item->col_buf, COL_MAX_LEN);
    break;

  case COL_CUMULATIVE_BYTES:
    break;

  default:
    break;
  }
}

void
col_fill_in(packet_info *pinfo, const bool fill_col_exprs, const bool fill_fd_colums)
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
        col_set_addr(pinfo, i, &pinfo->src, true, fill_col_exprs, true);
        break;

      case COL_UNRES_SRC:
        col_set_addr(pinfo, i, &pinfo->src, true, fill_col_exprs, false);
        break;

      case COL_DEF_DL_SRC:
      case COL_RES_DL_SRC:
        col_set_addr(pinfo, i, &pinfo->dl_src, true, fill_col_exprs, true);
        break;

      case COL_UNRES_DL_SRC:
        col_set_addr(pinfo, i, &pinfo->dl_src, true, fill_col_exprs, false);
        break;

      case COL_DEF_NET_SRC:
      case COL_RES_NET_SRC:
        col_set_addr(pinfo, i, &pinfo->net_src, true, fill_col_exprs, true);
        break;

      case COL_UNRES_NET_SRC:
        col_set_addr(pinfo, i, &pinfo->net_src, true, fill_col_exprs, false);
        break;

      case COL_DEF_DST:
      case COL_RES_DST:   /* COL_DEF_DST is currently just like COL_RES_DST */
        col_set_addr(pinfo, i, &pinfo->dst, false, fill_col_exprs, true);
        break;

      case COL_UNRES_DST:
        col_set_addr(pinfo, i, &pinfo->dst, false, fill_col_exprs, false);
        break;

      case COL_DEF_DL_DST:
      case COL_RES_DL_DST:
        col_set_addr(pinfo, i, &pinfo->dl_dst, false, fill_col_exprs, true);
        break;

      case COL_UNRES_DL_DST:
        col_set_addr(pinfo, i, &pinfo->dl_dst, false, fill_col_exprs, false);
        break;

      case COL_DEF_NET_DST:
      case COL_RES_NET_DST:
        col_set_addr(pinfo, i, &pinfo->net_dst, false, fill_col_exprs, true);
        break;

      case COL_UNRES_NET_DST:
        col_set_addr(pinfo, i, &pinfo->net_dst, false, fill_col_exprs, false);
        break;

      case COL_DEF_SRC_PORT:
      case COL_RES_SRC_PORT:  /* COL_DEF_SRC_PORT is currently just like COL_RES_SRC_PORT */
        col_set_port(pinfo, i, true, true, fill_col_exprs);
        break;

      case COL_UNRES_SRC_PORT:
        col_set_port(pinfo, i, false, true, fill_col_exprs);
        break;

      case COL_DEF_DST_PORT:
      case COL_RES_DST_PORT:  /* COL_DEF_DST_PORT is currently just like COL_RES_DST_PORT */
        col_set_port(pinfo, i, true, false, fill_col_exprs);
        break;

      case COL_UNRES_DST_PORT:
        col_set_port(pinfo, i, false, false, fill_col_exprs);
        break;

      case COL_CUSTOM:
        /* Formatting handled by col_custom_set_edt() / col_custom_get_filter() */
        break;

      case NUM_COL_FMTS:  /* keep compiler happy - shouldn't get here */
        ws_assert_not_reached();
        break;
      default:
        if (col_item->col_fmt >= NUM_COL_FMTS) {
          ws_assert_not_reached();
        }
        /*
         * Formatting handled by expert.c (COL_EXPERT), or individual
         * dissectors. Fill in from the text using the internal hfid.
         */
        if (fill_col_exprs) {
          pinfo->cinfo->col_expr.col_expr[i] = proto_registrar_get_nth(col_item->hf_id)->abbrev;
          (void) g_strlcpy(pinfo->cinfo->col_expr.col_expr_val[i], pinfo->cinfo->columns[i].col_data, (col_item->col_fmt == COL_INFO) ? COL_MAX_INFO_LEN : COL_MAX_LEN);
        }
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
col_fill_in_error(column_info *cinfo, frame_data *fdata, const bool fill_col_exprs, const bool fill_fd_colums)
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
        ws_assert_not_reached();
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

bool col_data_changed(void) {
  bool cur_cdc = col_data_changed_;
  col_data_changed_ = false;
  return cur_cdc;
}

void
col_register_protocol(void)
{
  /* This gets called by proto_init() before column_register_fields()
   * gets called by the preference modules actually getting registered.
   */
  if (proto_cols <= 0) {
    proto_cols = proto_get_id_by_filter_name("_ws.col");
  }
  if (proto_cols <= 0) {
    proto_cols = proto_register_protocol("Wireshark Columns", "Columns", "_ws.col");
  }
  static int *ett[] = {
    &ett_cols
  };
  proto_register_subtree_array(ett, G_N_ELEMENTS(ett));
}

void
col_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *col_tree;

  column_info *cinfo = pinfo->cinfo;

  if (!cinfo) {
    return;
  }

  if (proto_field_is_referenced(tree, proto_cols)) {
    // XXX: Needed if we also create _ws.col.custom
    //col_custom_set(tree, cinfo);
    col_fill_in(pinfo, false, true);
    ti = proto_tree_add_item(tree, proto_cols, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(ti);
    col_tree = proto_item_add_subtree(ti, ett_cols);
    for (int i = 0; i < cinfo->num_cols; ++i) {
      if (cinfo->columns[i].hf_id != -1) {
        if (cinfo->columns[i].col_fmt == COL_CUSTOM) {
          ti = proto_tree_add_string_format(col_tree, cinfo->columns[i].hf_id, tvb, 0, 0, get_column_text(cinfo, i), "%s: %s", get_column_title(i), get_column_text(cinfo, i));
        } else {
          ti = proto_tree_add_string(col_tree, cinfo->columns[i].hf_id, tvb, 0, 0, get_column_text(cinfo, i));
        }
        proto_item_set_hidden(ti);
      }
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
