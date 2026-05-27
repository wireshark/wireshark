/** @file
 *
 * Routines for providing general range support to the dfilter library
 *
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs
 * Copyright 1999 Gerald Combs
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __DRANGE_H__
#define __DRANGE_H__

#include <wireshark.h>

/* Please don't directly manipulate these structs.  Please use
 * the methods provided.  If you REALLY can't do what you need to
 * do with the methods provided please write new methods that do
 * what you need, put them into the drange object here, and limit
 * your direct manipulation of the drange and drange_node structs to
 * here.
 */

/**
 * @brief Discriminator tag describing how the end boundary of a drange_node is expressed.
 */
typedef enum {
    DRANGE_NODE_END_T_UNINITIALIZED, /**< End boundary has not been set */
    DRANGE_NODE_END_T_LENGTH,        /**< End boundary is expressed as a length relative to start_offset */
    DRANGE_NODE_END_T_OFFSET,        /**< End boundary is expressed as an absolute end offset */
    DRANGE_NODE_END_T_TO_THE_END     /**< Range extends to the end of the field/buffer */
} drange_node_end_t;


/**
 * @brief A single contiguous slice within a display filter range expression.
 */
typedef struct _drange_node {
    int start_offset; /**< Byte offset at which the slice begins (inclusive) */
    int length;       /**< Length of the slice in bytes; valid when ending == DRANGE_NODE_END_T_LENGTH */
    int end_offset;   /**< Absolute end offset of the slice; valid when ending == DRANGE_NODE_END_T_OFFSET */
    drange_node_end_t ending; /**< Indicates how the end boundary of this node is interpreted */
} drange_node;


/**
 * @brief A display filter range composed of one or more drange_node slices.
 */
typedef struct _drange {
    GSList *range_list;    /**< Linked list of drange_node entries making up the range */
    bool has_total_length; /**< True if total_length has been computed and is valid */
    int total_length;      /**< Sum of all slice lengths; valid only when has_total_length is true */
    int min_start_offset;  /**< Smallest start_offset across all nodes in range_list */
    int max_start_offset;  /**< Largest start_offset across all nodes in range_list */
} drange_t;

/* drange_node constructor */

/**
 * @brief Creates a new empty drange_node.
 *
 * @return A pointer to the newly created drange_node.
 */
drange_node* drange_node_new(void);

/* drange_node constructor */

/**
 * @brief Creates a new drange_node from a string representation.
 *
 * @param range_str The string representation of the range.
 * @param err_ptr Pointer to store error message if any.
 * @return A newly created drange_node or NULL on failure.
 */
drange_node* drange_node_from_str(const char *range_str, char **err_ptr);

/* drange_node destructor */

/**
 * @brief Frees a drange_node structure.
 *
 * @param drnode Pointer to the drange_node to be freed.
 */
void drange_node_free(drange_node* drnode);

/* Call drange_node destructor on all list items */
/**
 * @brief Frees all elements in the provided GSList.
 *
 * @param list The GSList containing drange_node structures to be freed.
 */
void drange_node_free_list(GSList* list);

/* drange_node accessors */

/**
 * @brief Get the start offset of a drange_node.
 *
 * @param drnode Pointer to the drange_node.
 * @return The start offset of the node.
 */
int drange_node_get_start_offset(drange_node* drnode);
/**
 * @brief Get the length of a drange_node.
 *
 * @param drnode Pointer to the drange_node.
 * @return The length of the node.
 */
int drange_node_get_length(drange_node* drnode);

/**
 * @brief Get the end offset of a drange_node.
 *
 * @param drnode Pointer to the drange_node.
 * @return The end offset.
 */
int drange_node_get_end_offset(drange_node* drnode);

/**
 * @brief Get the ending type of a drange_node.
 *
 * @param drnode Pointer to the drange_node.
 * @return The ending type of the node.
 */
drange_node_end_t drange_node_get_ending(drange_node* drnode);

/* drange_node mutators */

/**
 * @brief Set the start offset of a drange_node.
 *
 * @param drnode Pointer to the drange_node structure.
 * @param offset The new start offset value.
 */
void drange_node_set_start_offset(drange_node* drnode, int offset);

/**
 * @brief Set the length of a drange node.
 *
 * @param drnode Pointer to the drange node.
 * @param length The new length for the node.
 */
void drange_node_set_length(drange_node* drnode, int length);

/**
 * @brief Set the end offset of a drange_node.
 *
 * @param drnode Pointer to the drange_node to modify.
 * @param offset The new end offset value.
 */
void drange_node_set_end_offset(drange_node* drnode, int offset);

/**
 * @brief Sets the drange_node to the end.
 *
 * @param drnode Pointer to the drange_node to be set to the end.
 */
void drange_node_set_to_the_end(drange_node* drnode);

/**
 * @brief Creates a new drange_t object.
 *
 * @param drnode A pointer to a drange_node, or NULL if not needed.
 * @return A pointer to the newly created drange_t object.
 */
drange_t * drange_new(drange_node* drnode);

/**
 * @brief Create a new drange_t from a GSList of ranges.
 *
 * @param list The GSList containing the ranges to be added to the new drange_t.
 * @return A pointer to the newly created drange_t, or NULL if an error occurred.
 */
drange_t * drange_new_from_list(GSList *list);

/**
 * @brief Creates a duplicate of the given drange_t.
 *
 * @param org The drange_t to be duplicated.
 * @return A pointer to the newly created duplicate drange_t, or NULL if an error occurred.
 */
drange_t * drange_dup(drange_t *org);

/**
 * @brief Frees a drange_t structure and all its associated resources.
 * @param dr Pointer to the drange_t to be freed.
 * @note only use this if you used drange_new() to create the drange
 */
void drange_free(drange_t* dr);

/* drange accessors */

/**
 * @brief Check if the drange has a total length.
 *
 * @param dr The drange to check.
 * @return true If the drange has a total length, false otherwise.
 */
bool drange_has_total_length(drange_t* dr);

/**
 * @brief Get the total length of a drange.
 *
 * @param dr Pointer to the drange structure.
 * @return The total length of the drange, or -1 if it does not have a total length.
 */
int drange_get_total_length(drange_t* dr);

/**
 * @brief Get the minimum start offset of a drange.
 *
 * @param dr Pointer to the drange structure.
 * @return int The minimum start offset.
 */
int drange_get_min_start_offset(drange_t* dr);

/**
 * @brief Get the maximum start offset of a drange.
 *
 * @param dr Pointer to the drange structure.
 * @return int The maximum start offset.
 */
int drange_get_max_start_offset(drange_t* dr);

/* drange mutators */

/**
 * @brief Appends a drange_node to the end of a drange_t.
 *
 * @param dr The drange_t to which the node will be appended.
 * @param drnode The drange_node to append.
 */
void drange_append_drange_node(drange_t* dr, drange_node* drnode);

/**
 * @brief Prepends a drange_node to the beginning of a drange_t.
 *
 * @param dr The drange_t to which the node will be prepended.
 * @param drnode The drange_node to prepend.
 */
void drange_prepend_drange_node(drange_t* dr, drange_node* drnode);

/**
 * @brief Iterates over each node in a drange_t structure and applies a function to it.
 *
 * @param dr Pointer to the drange_t structure.
 * @param func Function pointer to be applied to each node.
 * @param funcdata Data to be passed to the function.
 */
void drange_foreach_drange_node(drange_t* dr, GFunc func, void *funcdata);

 /**
  * @brief Convert a drange_node to its string representation.
  *
  * @param rn Pointer to the drange_node to convert.
  * @return A dynamically allocated string representing the drange_node.
  */

char *drange_node_tostr(const drange_node *rn);

 /**
  * @brief Convert a drange_t structure to its string representation.
  *
  * @param dr Pointer to the drange_t structure to convert.
  * @return A dynamically allocated string representing the range, or NULL on failure.
  */

char *drange_tostr(const drange_t *dr);

#endif /* ! __DRANGE_H__ */
