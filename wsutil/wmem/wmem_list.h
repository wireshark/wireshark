/** @file
 * Definitions for the Wireshark Memory Manager Doubly-Linked List
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_LIST_H__
#define __WMEM_LIST_H__

#include <string.h>
#include <glib.h>

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-list Doubly-Linked List
 *
 *    A doubly-linked list implementation on top of wmem.
 *
 *    @{
 */

struct _wmem_list_t;
struct _wmem_list_frame_t;

typedef struct _wmem_list_t       wmem_list_t;
typedef struct _wmem_list_frame_t wmem_list_frame_t;

/**
 * @brief Count the number of elements in a wmem list.
 *
 * Returns the total number of elements currently stored in the given `wmem_list_t`.
 * This function operates in constant time.
 *
 * @param list Pointer to the list whose elements are to be counted.
 * @return The number of elements in the list.
 */
WS_DLL_PUBLIC
unsigned
wmem_list_count(const wmem_list_t *list);

/**
 * @brief Retrieve the head (first frame) of a wmem list.
 *
 * Returns a pointer to the first frame in the given `wmem_list_t`, or `NULL` if the list is empty.
 *
 * @note The returned frame can be used with `wmem_list_frame_next()` to traverse the list.
 *
 * @param list Pointer to the list whose head frame is to be retrieved.
 * @return Pointer to the first `wmem_list_frame_t` in the list, or `NULL` if the list is empty.
 */
WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_head(const wmem_list_t *list);

/**
 * @brief Retrieve the tail (last frame) of a wmem list.
 *
 * Returns a pointer to the last frame in the given `wmem_list_t`, or `NULL` if the list is empty.
 * This is useful for appending elements or reverse traversal.
 *
 * @note The returned frame can be used with `wmem_list_frame_prev()` to traverse backward.
 *
 * @param list Pointer to the list whose tail frame is to be retrieved.
 * @return Pointer to the last `wmem_list_frame_t` in the list, or `NULL` if the list is empty.
 */
WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_tail(const wmem_list_t *list);

/**
 * @brief Retrieve the next frame in a wmem list.
 *
 * Returns a pointer to the frame that follows the given `wmem_list_frame_t` in the list.
 * If the input frame is the last one or `NULL`, the function returns `NULL`.
 *
 * @param frame Pointer to the current list frame.
 * @return Pointer to the next `wmem_list_frame_t`, or `NULL` if there is none.
 *
 * @note This function is typically used for forward traversal of a `wmem_list_t`.
 */
WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_frame_next(const wmem_list_frame_t *frame);

/**
 * @brief Retrieve the previous frame in a wmem list.
 *
 * Returns a pointer to the frame that precedes the given `wmem_list_frame_t` in the list.
 * If the input frame is the first one or `NULL`, the function returns `NULL`.
 *
 * @note This function is typically used for reverse traversal of a `wmem_list_t`.
 *
 * @param frame Pointer to the current list frame.
 * @return Pointer to the previous `wmem_list_frame_t`, or `NULL` if there is none.
 */
WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_frame_prev(const wmem_list_frame_t *frame);

/**
 * @brief Retrieve the data stored in a list frame.
 *
 * Returns the user-defined data pointer associated with the given `wmem_list_frame_t`.
 * This allows access to the contents of a list element during traversal or inspection.
 *
 * @param frame Pointer to the list frame whose data is to be retrieved.
 * @return Pointer to the data stored in the frame, or `NULL` if the frame is `NULL` or empty.
 *
 * @note The returned pointer is not copied; it refers directly to the stored data.
 */
WS_DLL_PUBLIC
void *
wmem_list_frame_data(const wmem_list_frame_t *frame);

/**
 * @brief Remove the first occurrence of a data element from a wmem list.
 *
 * Searches the given `wmem_list_t` for the first frame containing the specified `data`
 * pointer and removes it from the list. If the data is not found, the list remains unchanged.
 *
 * @note Only the first matching frame is removed. Comparison is done by pointer equality.
 *
 * @param list Pointer to the list from which the data should be removed.
 * @param data Pointer to the data to remove.
 */
WS_DLL_PUBLIC
void
wmem_list_remove(wmem_list_t *list, void *data);

/**
 * @brief Remove a specific frame from a wmem list.
 *
 * Removes the given `wmem_list_frame_t` from the specified `wmem_list_t`, updating
 * internal links to maintain list integrity. If the frame is not part of the list,
 * the function has no effect.
 *
 * @note This operation does not free the data stored in the frame.
 *
 * @param list Pointer to the list from which the frame should be removed.
 * @param frame Pointer to the frame to remove.
 */
WS_DLL_PUBLIC
void
wmem_list_remove_frame(wmem_list_t *list, wmem_list_frame_t *frame);

/**
 * @brief Find the first frame containing the specified data in a wmem list.
 *
 * Performs a linear search with O(n) complexity through the given `wmem_list_t` to locate the first frame
 * whose stored data matches the specified `data` pointer. Comparison is done using
 * pointer equality (`==`).
 *
 * @param list Pointer to the list to search.
 * @param data Pointer to the data to find.
 * @return Pointer to the matching `wmem_list_frame_t`, or `NULL` if not found.
 */
WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_find(const wmem_list_t *list, const void *data);

/**
 * @brief Find a frame in a wmem list using a custom comparison function.
 *
 * Performs a linear search through the given `wmem_list_t`, using the provided
 * `GCompareFunc` to compare each frame's data against the specified `data` pointer.
 * Returns the first matching frame, or `NULL` if no match is found.
 *
 * @param list Pointer to the list to search.
 * @param data Pointer to the data to match against.
 * @param func Custom comparison function of type `GCompareFunc`.
 *             Should return 0 for a match, non-zero otherwise.
 * @return Pointer to the matching `wmem_list_frame_t`, or `NULL` if not found.
 */
WS_DLL_PUBLIC
wmem_list_frame_t *
wmem_list_find_custom(const wmem_list_t *list, const void *data, GCompareFunc func);

/**
 * @brief Prepend a data element to the beginning of a wmem list.
 *
 * Inserts the specified `data` pointer at the head of the given `wmem_list_t`.
 * The new element becomes the first frame in the list, shifting existing elements
 * toward the tail.
 *
 * @note This operation runs in constant time.
 *
 * @param list Pointer to the list to modify.
 * @param data Pointer to the data to prepend.
 */
WS_DLL_PUBLIC
void
wmem_list_prepend(wmem_list_t *list, void *data);

/**
 * @brief Appends a data element to the end of a wmem list.
 *
 * Appends the specified `data` pointer at the end of the given `wmem_list_t`.
 * The new element becomes the last frame in the list.
 *
 * @note This operation runs in constant time.
 *
 * @param list Pointer to the list to modify.
 * @param data Pointer to the data to append.
 */
WS_DLL_PUBLIC
void
wmem_list_append(wmem_list_t *list, void *data);

/**
 * @brief Insert a data element into a wmem list in sorted order.
 *
 * Inserts the specified `data` pointer into the given `wmem_list_t` such that the list
 * remains sorted according to the provided comparison function. The insertion point is
 * determined by applying `func` to each existing element until the correct position is found.
 *
 * @note This function performs a linear search with O(n) complexity to find the insertion point.
 *
 * @param list Pointer to the list to modify.
 * @param data Pointer to the data to insert.
 * @param func Comparison function of type `GCompareFunc` used to maintain sort order.
 *             Should return a negative value if the first argument is less than the second,
 *             zero if equal, and positive if greater.
 */
WS_DLL_PUBLIC
void
wmem_list_insert_sorted(wmem_list_t *list, void* data, GCompareFunc func);

/**
 * @brief Insert a data element into a wmem list in sorted order, starting from the tail.
 *
 * Similar to `wmem_list_insert_sorted`, this function inserts the specified `data` pointer
 * into the given `wmem_list_t` while maintaining sort order. However, it begins the search
 * for the insertion point from the tail of the list, which can be more efficient for
 * appending-like patterns or when newer elements tend to be larger.
 *
 * @note This function performs a linear search with O(n) complexity, starting from the tail.
 *
 * @param list Pointer to the list to modify.
 * @param data Pointer to the data to insert.
 * @param func Comparison function of type `GCompareFunc` used to maintain sort order.
 *             Should return a negative value if the first argument is less than the second,
 *             zero if equal, and positive if greater.
 */
WS_DLL_PUBLIC
void
wmem_list_append_sorted(wmem_list_t *list, void* data, GCompareFunc func);

/**
 * @brief Create a new wmem list using the specified memory allocator.
 *
 * Allocates and initializes a new `wmem_list_t` structure using the given `wmem_allocator_t`.
 * The list is initially empty and ready for use with other wmem list operations.
 *
 * @param allocator Pointer to the memory allocator to use for list management.
 * @return Pointer to the newly created `wmem_list_t`, or `NULL` on allocation failure.
 */
WS_DLL_PUBLIC
wmem_list_t *
wmem_list_new(wmem_allocator_t *allocator)
G_GNUC_MALLOC;

/**
 * @brief Apply a function to each data element in a wmem list.
 *
 * Iterates over all frames in the given `wmem_list_t`, invoking the specified `foreach_func`
 * on each data element. The `user_data` pointer is passed to each invocation of the function.
 *
 * @param list Pointer to the list to iterate over.
 * @param foreach_func Function of type `GFunc` to apply to each data element.
 *                     The function receives the element's data and `user_data` as arguments.
 * @param user_data Pointer to user-defined data passed to each call of `foreach_func`.
 */
WS_DLL_PUBLIC
void
wmem_list_foreach(const wmem_list_t *list, GFunc foreach_func, void * user_data);

/**
 * @brief Destroy a wmem list and release its internal resources.
 *
 * Frees all internal memory associated with the given `wmem_list_t`, including its frames.
 * This function does not free the data stored in the list frames-only the list structure itself.
 *
 * @param list Pointer to the list to destroy.
 */
WS_DLL_PUBLIC
void
wmem_destroy_list(wmem_list_t *list);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_LIST_H__ */

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
