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

#if !GLIB_CHECK_VERSION(2, 57, 1)

/**
 * @brief Steals a key-value pair from the hash table if it exists.
 *
 * @param hash_table The hash table to search in.
 * @param lookup_key The key to look up and steal.
 * @param stolen_key Pointer to store the stolen key, or NULL if not needed.
 * @param stolen_value Pointer to store the stolen value, or NULL if not needed.
 * @return TRUE if the key was found and stolen, FALSE otherwise.
 */
static inline gboolean
g_hash_table_steal_extended (GHashTable    *hash_table,
                             gconstpointer  lookup_key,
                             gpointer      *stolen_key,
                             gpointer      *stolen_value)
{
  gpointer key, value;
  if (g_hash_table_lookup_extended (hash_table, lookup_key, &key, &value))
  {
    stolen_key = &key;
    stolen_value = &value;

    g_hash_table_steal (hash_table, key);

    return TRUE;
  } else {
    if (stolen_key != NULL)
        *stolen_key = NULL;
    if (stolen_value != NULL)
      *stolen_value = NULL;
  }

  return FALSE;
}

#endif

#if !GLIB_CHECK_VERSION(2, 60, 0)

#define g_queue_clear_full queue_clear_full

/**
 * @brief Clears a GQueue and frees all elements using a provided function.
 *
 * This function iterates over each element in the given GQueue, pops it from the queue,
 * and then calls the specified GDestroyNotify function to free the memory of each element.
 *
 * @param queue The GQueue to be cleared.
 * @param free_func A pointer to the function used to free each element's memory.
 */
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

typedef struct _GRealArray GRealArray;
/**
 * @brief Internal implementation of GArray, holding the backing buffer and allocation metadata.
 */
struct _GRealArray {
    guint8         *data;             /**< Pointer to the raw backing buffer storing array elements. */
    guint           len;              /**< Current number of elements stored in the array. */
    guint           alloc;            /**< Total number of elements the current backing buffer can hold before reallocation. */
    guint           elt_size;         /**< Size in bytes of a single array element. */
    guint           zero_terminated;  /**< Non-zero if a null element is maintained past the last valid element. */
    guint           clear;            /**< Non-zero if newly allocated elements are zero-initialised before use. */
    gatomicrefcount ref_count;        /**< Atomic reference count controlling the lifetime of this array. */
    GDestroyNotify  clear_func;       /**< Optional callback invoked on each element before it is removed or the array is freed; NULL if not set. */
};

/**
 * @brief Searches for a target value in a sorted array using binary search.
 *
 * This function performs a binary search on a sorted GArray to find the index of the target value.
 * If the target is found, it returns TRUE and sets out_match_index to the index of the target.
 * If the target is not found, it returns FALSE and leaves out_match_index unchanged.
 *
 * @param array The sorted GArray to search.
 * @param target The value to search for in the array.
 * @param compare_func A comparison function that defines the order of elements in the array.
 * @param out_match_index Pointer to store the index of the found target, or unchanged if not found.
 * @return TRUE if the target is found, FALSE otherwise.
 */
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
typedef struct _GRealPtrArray GRealPtrArray;


/**
 * @brief Internal implementation of GPtrArray, holding the backing pointer buffer and allocation metadata.
 */
struct _GRealPtrArray {
    gpointer       *pdata;              /**< Pointer to the raw backing buffer storing the array's element pointers. */
    guint           len;                /**< Current number of pointers stored in the array. */
    guint           alloc;              /**< Total number of pointer slots the current backing buffer can hold before reallocation. */
    gatomicrefcount ref_count;          /**< Atomic reference count controlling the lifetime of this array. */
    guint8          null_terminated:1;  /**< 1 if a NULL sentinel is maintained past the last valid pointer, allowing the buffer to be used as a NULL-terminated array; 0 otherwise. */
    GDestroyNotify  element_free_func;  /**< Optional callback invoked on each element pointer before it is removed or the array is freed; NULL if not set. */
};

/**
 * @brief Steal the data from a GArray and reset its length to zero.
 *
 * This function transfers ownership of the memory allocated for the elements in the GArray
 * to the caller, setting the array's length to zero. The caller is responsible for freeing
 * the returned segment when done.
 *
 * @param array The GArray whose data is to be stolen.
 * @param len Pointer to a gsize where the length of the stolen data will be stored, or NULL if not needed.
 * @return gpointer A pointer to the stolen data, or NULL if the input array was NULL.
 */
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

/**
 * @brief Steals the data from a GPtrArray and returns it.
 *
 * This function removes all elements from the given GPtrArray, sets its length to 0,
 * and returns a pointer to the stolen data segment. The caller is responsible for freeing
 * the returned data when done.
 *
 * @param array Pointer to the GPtrArray whose data is to be stolen.
 * @param len Optional pointer to store the number of elements in the array before stealing.
 * @return gpointer Pointer to the stolen data segment, or NULL if the array was empty.
 */
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

/**
 * @brief Steals ownership of the data from a GByteArray.
 *
 * This function transfers ownership of the data contained in the GByteArray to the caller.
 * The caller is responsible for freeing the memory when done.
 *
 * @param array The GByteArray whose data is to be stolen.
 * @param len A pointer to a gsize where the length of the stolen data will be stored.
 * @return A pointer to the stolen data as a guint8*.
 */
static inline guint8 *g_byte_array_steal (GByteArray *array,
                    gsize *len)
{
  return (guint8 *) g_array_steal ((GArray *) array, len);
}
#endif

#if !GLIB_CHECK_VERSION(2, 68, 0)

/**
 * @brief Duplicates a memory block with error checking.
 *
 * Allocates memory and copies the contents of the given memory block to the new location.
 * If the input pointer is NULL or the byte size is zero, returns NULL without allocating memory.
 *
 * @param mem Pointer to the memory block to be duplicated.
 * @param byte_size Size of the memory block in bytes.
 * @return Pointer to the newly allocated and copied memory block, or NULL if allocation fails.
 */
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

#if !GLIB_CHECK_VERSION(2, 74, 0)
#ifndef G_REGEX_MATCH_DEFAULT
#define G_REGEX_MATCH_DEFAULT ((GRegexMatchFlags)0)
#endif
#endif

#if !GLIB_CHECK_VERSION(2, 88, 0)
#ifndef G_NSEC_PER_SEC
#define G_NSEC_PER_SEC 1000000000
#endif
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* GLIB_COMPAT_H */
