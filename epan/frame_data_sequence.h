/** @file
 * Implements a sequence of frame_data structures
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <epan/frame_data.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _frame_data_sequence frame_data_sequence;

/**
 * @brief Create a new frame_data_sequence.
 *
 * @return A pointer to the newly created frame_data_sequence.
 */
WS_DLL_PUBLIC frame_data_sequence *new_frame_data_sequence(void);

/**
 * @brief Add a frame_data entry to the sequence.
 *
 * Adds the given frame_data entry to the specified frame_data_sequence.
 *
 * @param fds Pointer to the frame data sequence to which the entry will be added.
 * @param fdata Pointer to the frame data entry to be added.
 * @return Pointer to the added frame data entry, or NULL on failure.
 */
WS_DLL_PUBLIC frame_data *frame_data_sequence_add(frame_data_sequence *fds,
    frame_data *fdata);

/**
 * @brief Finds a frame data entry in the sequence.
 *
 * Searches for a frame data entry with the specified number in the given frame data sequence.
 *
 * @param fds Pointer to the frame data sequence.
 * @param num The frame number to find.
 * @return Pointer to the found frame data entry, or NULL if not found.
 */
WS_DLL_PUBLIC frame_data *frame_data_sequence_find(frame_data_sequence *fds,
    uint32_t num);

/**
 * @brief Free a frame_data_sequence and all the frame_data structures in it.
 *
 * @param fds Pointer to the frame data sequence to be freed.
 */
WS_DLL_PUBLIC void free_frame_data_sequence(frame_data_sequence *fds);

/**
 * @brief Finds and marks frame data entries that depend on a given key.
 *
 * Searches for frame data entries in the sequence that depend on the specified key and marks them accordingly.
 *
 * @param key The key to search for dependencies.
 * @param value Additional information related to the key.
 * @param user_data User-defined data passed to the callback function.
 */
WS_DLL_PUBLIC void find_and_mark_frame_depended_upon(void *key, void *value, void *user_data);


#ifdef __cplusplus
}
#endif /* __cplusplus */
