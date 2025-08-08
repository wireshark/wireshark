/** @file
*
* Definitions to provide some functions that are not present in older
* GLIB versions we support (currently down to 2.50)
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/
#ifndef GLIB_COMPAT_H
#define GLIB_COMPAT_H

#include "ws_symbol_export.h"
#include "ws_attributes.h"

#include <glib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if !GLIB_CHECK_VERSION(2, 60, 0)

#define g_queue_clear_full queue_clear_full
static inline void
queue_clear_full (GQueue * queue, GDestroyNotify free_func)
{
  gpointer data;

  while ((data = g_queue_pop_head (queue)) != NULL)
    free_func (data);
}

#endif

#if !GLIB_CHECK_VERSION(2, 61, 2)

typedef volatile gint   gatomicrefcount;

typedef struct _GRealArray  GRealArray;
struct _GRealArray
{
  guint8 *data;
  guint   len;
  guint   alloc;
  guint   elt_size;
  guint   zero_terminated ;
  guint   clear;
  gatomicrefcount ref_count;
  GDestroyNotify clear_func;
};

static inline gboolean
g_array_binary_search (GArray        *array,
                       const void *   target,
                       GCompareFunc   compare_func,
                       guint         *out_match_index)
{
  gboolean result = FALSE;
  GRealArray *_array = (GRealArray *) array;
  guint left, middle, right;
  gint val;

  g_return_val_if_fail (_array != NULL, FALSE);
  g_return_val_if_fail (compare_func != NULL, FALSE);

  if (G_LIKELY(_array->len))
    {
      left = 0;
      right = _array->len - 1;

      while (left <= right)
        {
          middle = left + (right - left) / 2;

          val = compare_func (_array->data + (_array->elt_size * middle), target);
          if (val == 0)
            {
              result = TRUE;
              break;
            }
          else if (val < 0)
            left = middle + 1;
          else if (/* val > 0 && */ middle > 0)
            right = middle - 1;
          else
            break;  /* element not found */
        }
    }

  if (result && out_match_index != NULL)
    *out_match_index = middle;

  return result;
}
#endif

#if !GLIB_CHECK_VERSION(2, 64, 0)
typedef struct _GRealPtrArray  GRealPtrArray;

struct _GRealPtrArray
{
  gpointer       *pdata;
  guint           len;
  guint           alloc;
  gatomicrefcount ref_count;
  guint8          null_terminated : 1; /* always either 0 or 1, so it can be added to array lengths */
  GDestroyNotify  element_free_func;
};

static inline gpointer
g_array_steal (GArray *array,
               gsize *len)
{
  GRealArray *rarray;
  gpointer segment;

  g_return_val_if_fail (array != NULL, NULL);

  rarray = (GRealArray *) array;
  segment = (gpointer) rarray->data;

  if (len != NULL)
    *len = rarray->len;

  rarray->data  = NULL;
  rarray->len   = 0;
  rarray->alloc = 0;
  return segment;
}

static inline gpointer *
g_ptr_array_steal (GPtrArray *array,
                   gsize *len)
{
  GRealPtrArray *rarray;
  gpointer *segment;

  g_return_val_if_fail (array != NULL, NULL);

  rarray = (GRealPtrArray *) array;
  segment = (gpointer *) rarray->pdata;

  if (len != NULL)
    *len = rarray->len;

  rarray->pdata = NULL;
  rarray->len   = 0;
  rarray->alloc = 0;
  return segment;
}

static inline guint8 *
g_byte_array_steal (GByteArray *array,
                    gsize *len)
{
  return (guint8 *) g_array_steal ((GArray *) array, len);
}
#endif

#if !GLIB_CHECK_VERSION(2, 68, 0)
static inline void *
g_memdup2(const void *mem, size_t byte_size)
{
  void * new_mem;

  if (mem && byte_size != 0) {
      new_mem = g_malloc(byte_size);
      memcpy(new_mem, mem, byte_size);
  }
  else
    new_mem = NULL;

  return new_mem;
}
#endif

#if !GLIB_CHECK_VERSION(2, 74, 0)
#ifndef G_REGEX_DEFAULT
#define G_REGEX_DEFAULT ((GRegexCompileFlags)0)
#endif
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* GLIB_COMPAT_H */
