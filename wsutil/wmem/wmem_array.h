/** @file
 * Definitions for the Wireshark Memory Manager Array
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_ARRAY_H__
#define __WMEM_ARRAY_H__

#include <string.h>
#include <glib.h>

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-array Array
 *
 *    A resizable array implementation on top of wmem.
 *
 *    @{
 */

struct _wmem_array_t;

/**
 * @brief Opaque type representing a dynamically resizable array in the wmem system.
 *
 * `wmem_array_t` is a flexible container for storing elements of fixed size,
 * managed by a `wmem_allocator_t`. It supports efficient appending, resizing,
 * and memory-safe access patterns.
 */
typedef struct _wmem_array_t wmem_array_t;

/**
 * @brief Create a new dynamically sized array with a specified element size and initial capacity.
 *
 * Allocates and initializes a new `wmem_array_t` structure using the given memory allocator.
 * The array is configured to hold elements of size `elem_size`, with space initially allocated
 * for `alloc_count` elements.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param elem_size Size in bytes of each element to be stored in the array.
 * @param alloc_count Initial number of elements to allocate space for.
 * @return Pointer to the newly created array, or NULL on failure.
 */
WS_DLL_PUBLIC
wmem_array_t *
wmem_array_sized_new(wmem_allocator_t *allocator, size_t elem_size,
                     unsigned alloc_count);

/**
 * @brief Create a new dynamically sized array with default initial capacity.
 *
 * Allocates and initializes a new `wmem_array_t` structure using the given memory allocator.
 * The array is configured to hold elements of size `elem_size`, with a default initial allocation.
 *
 * @param allocator Pointer to the memory allocator to use.
 * @param elem_size Size in bytes of each element to be stored in the array.
 * @return Pointer to the newly created array, or NULL on failure.
 */
WS_DLL_PUBLIC
wmem_array_t *
wmem_array_new(wmem_allocator_t *allocator, const size_t elem_size);

/**
 * @brief Increase the capacity of a dynamic array by a specified number of elements.
 *
 * Expands the internal storage of the given `wmem_array_t` to accommodate at least
 * `to_add` additional elements. This does not modify the current contents of the array.
 *
 * @param array Pointer to the dynamic array to grow.
 * @param to_add Number of additional elements to allocate space for.
 */
WS_DLL_PUBLIC
void
wmem_array_grow(wmem_array_t *array, const unsigned to_add);

/**
 * @brief Set a null terminator at the end of a dynamic array.
 *
 * Ensures that the `wmem_array_t` contains a null terminator at the end of its data.
 * This operation does not affect the logical length of the array but guarantees safe
 * null-terminated access.
 *
 * @param array Pointer to the dynamic array to modify.
 */
WS_DLL_PUBLIC
void
wmem_array_set_null_terminator(wmem_array_t *array);

/**
 * @brief Zero out the contents of a dynamic array.
 *
 * Sets all bytes in the internal data buffer of the given `wmem_array_t` to zero.
 *
 * @param array Pointer to the dynamic array to zero out.
 */
WS_DLL_PUBLIC
void
wmem_array_bzero(wmem_array_t *array);

/**
 * @brief Append elements to a dynamic array.
 *
 * Copies `count` elements from the input buffer `in` into the end of the given
 * `wmem_array_t` array. The array is resized if necessary to accommodate the new elements.
 *
 * @param array Pointer to the dynamic array to append to.
 * @param in Pointer to the input buffer containing elements to append.
 * @param count Number of elements to append from the input buffer.
 */
WS_DLL_PUBLIC
void
wmem_array_append(wmem_array_t *array, const void *in, unsigned count);

/**
 * @brief Append a single element to a wmem array.
 *
 * This macro wraps `wmem_array_append()` to simplify appending one item.
 * It automatically takes the address of the value and sets the count to 1.
 *
 * @param ARRAY Pointer to the `wmem_array_t` to append to.
 * @param VAL   Value to append; its address will be passed to the underlying function.
 */
#define wmem_array_append_one(ARRAY, VAL) \
    wmem_array_append((ARRAY), &(VAL), 1)

/**
 * @brief Retrieve a pointer to an element in a dynamic array by index.
 *
 * Returns a pointer to the element at the specified `array_index` within the given
 * `wmem_array_t` array. No bounds checking is performed, so the caller must ensure
 * the index is valid.
 *
 * @param array Pointer to the dynamic array to access.
 * @param array_index Index of the element to retrieve.
 * @return Pointer to the element at the specified index.
 */
WS_DLL_PUBLIC
void *
wmem_array_index(const wmem_array_t *array, unsigned array_index);

/**
 * @brief Safely retrieve an element from a dynamic array by index.
 *
 * Attempts to access the element at the specified `array_index` in the given `wmem_array_t`.
 * If the index is valid, the element is copied into the memory pointed to by `val` and the
 * function returns 0. If the index is out of bounds, no data is copied and the function returns -1.
 *
 * @param array Pointer to the dynamic array to access.
 * @param array_index Index of the element to retrieve.
 * @param val Pointer to memory where the retrieved element will be copied.
 * @return 0 if the index is valid and the element was copied, -1 otherwise.
 */
WS_DLL_PUBLIC
int
wmem_array_try_index(const wmem_array_t *array, unsigned array_index, void *val);

/**
 * @brief Sort the elements of a dynamic array.
 *
 * Sorts the contents of the given `wmem_array_t`.
 * The comparison function `compar` should return a value less than, equal to, or greater than zero
 * depending on the relative ordering of the two elements.
 *
 * @param array Pointer to the dynamic array to sort.
 * @param compar Comparison function used to determine the order of elements.
 *               It must follow the signature: int compar(const void *a, const void *b).
 */
WS_DLL_PUBLIC
void
wmem_array_sort(wmem_array_t *array, int (*compar)(const void*,const void*));

/**
 * @brief Retrieve a raw pointer to the internal buffer of a dynamic array.
 *
 * Returns a pointer to the internal data buffer of the given `wmem_array_t`.
 * This allows direct access to the array contents.
 *
 * @param array Pointer to the dynamic array.
 * @return Raw pointer to the internal buffer.
 */
WS_DLL_PUBLIC
void *
wmem_array_get_raw(const wmem_array_t *array);

/**
 * @brief Get the number of elements currently stored in a dynamic array.
 *
 * Returns the count of elements that have been appended to the given `wmem_array_t`.
 * If the array pointer is NULL, the function returns 0.
 *
 * @param array Pointer to the dynamic array.
 * @return Number of elements currently stored in the array, or 0 if the array is NULL.
 */
WS_DLL_PUBLIC
unsigned
wmem_array_get_count(const wmem_array_t *array);

/**
 * @brief Retrieve the memory allocator associated with a dynamic array.
 *
 * Returns the `wmem_allocator_t` used to allocate and manage memory for the given `wmem_array_t`.
 * If the array pointer is NULL, the function safely returns NULL.
 *
 * @param array Pointer to the dynamic array.
 * @return Pointer to the associated memory allocator, or NULL if the array is NULL.
 */
WS_DLL_PUBLIC
wmem_allocator_t*
wmem_array_get_allocator(const wmem_array_t* array);

/**
 * @brief Finalize a dynamic array and retrieve its underlying buffer.
 *
 * Truncates the internal buffer of the given `wmem_array_t` to match the number of elements
 * currently stored, including an extra element if the array is null-terminated. Frees the
 * `wmem_array_t` structure itself and returns a pointer to the resized buffer.
 *
 * After this call, the original array structure becomes invalid and
 * must not be used.
 *
 * @param array Pointer to the dynamic array to finalize.
 * @return Pointer to the resized internal buffer, or NULL if the array is NULL.
 *
 * @note The caller is responsible for freeing the returned buffer if necessary.
 */
WS_DLL_PUBLIC
void *
wmem_array_finalize(wmem_array_t *array);

/**
 * @brief Destroy a dynamic array and free its associated memory.
 *
 * Frees both the internal buffer and the `wmem_array_t` structure itself using the array's
 * associated memory allocator. After this call, the array pointer becomes invalid and must
 * not be used.
 *
 * @param array Pointer to the dynamic array to destroy.
 */
WS_DLL_PUBLIC
void
wmem_destroy_array(wmem_array_t *array);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_ARRAY_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
