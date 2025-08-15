/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_BUFFER_H__
#define __W_BUFFER_H__

#include <inttypes.h>
#include <stddef.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SOME_FUNCTIONS_ARE_INLINE

#define DEFAULT_INIT_BUFFER_SIZE_2048 (2 * 1024) /* Everyone still uses 1500 byte frames, right? */

/**
 * @brief A dynamic byte buffer with adjustable start and end positions.
 *
 * This structure supports efficient appending and trimming of data,
 * making it suitable for streaming or incremental parsing scenarios.
 */
typedef struct Buffer {
    uint8_t *data;       /**< Pointer to the allocated memory block. */
    size_t allocated;    /**< Total size of the allocated buffer. */
    size_t start;        /**< Offset to the first valid byte. */
    size_t first_free;   /**< Offset to the first unused byte (end of valid data). */
} Buffer;

/**
 * @brief Initializes a Buffer with the specified initial capacity.
 *
 * Allocates memory for the buffer and sets internal pointers.
 *
 * @param buffer Pointer to the Buffer structure to initialize.
 * @param space Initial size of the buffer in bytes.
 */
WS_DLL_PUBLIC
void ws_buffer_init(Buffer* buffer, size_t space);

/**
 * @brief Frees the memory associated with a Buffer.
 *
 * Releases any allocated memory and resets internal fields.
 *
 * @param buffer Pointer to the Buffer structure to free.
 */
WS_DLL_PUBLIC
void ws_buffer_free(Buffer* buffer);

/**
 * @brief Ensures the buffer has enough space for additional data.
 *
 * Expands the buffer if necessary to accommodate `space` bytes beyond `first_free`.
 *
 * @param buffer Pointer to the Buffer structure.
 * @param space Number of additional bytes required.
 */
WS_DLL_PUBLIC
void ws_buffer_assure_space(Buffer* buffer, size_t space);

/**
 * @brief Appends data to the end of the buffer.
 *
 * Copies `bytes` from `from` into the buffer starting at `first_free`,
 * expanding the buffer if needed.
 *
 * @param buffer Pointer to the Buffer structure.
 * @param from Pointer to the source data.
 * @param bytes Number of bytes to append.
 */
WS_DLL_PUBLIC
void ws_buffer_append(Buffer* buffer, const uint8_t *from, size_t bytes);

/**
 * @brief Removes bytes from the beginning of the buffer.
 *
 * Advances the `start` pointer by `bytes`, effectively discarding that portion.
 * Does not shrink the allocated memory.
 *
 * @param buffer Pointer to the Buffer structure.
 * @param bytes Number of bytes to remove from the start.
 */
WS_DLL_PUBLIC
void ws_buffer_remove_start(Buffer* buffer, size_t bytes);

/**
 * @brief Cleans up internal buffer state across all active buffers.
 *
 * Performs global cleanup tasks, such as releasing shared resources or
 * resetting internal buffer tracking. Typically called during shutdown.
 */
WS_DLL_PUBLIC
void ws_buffer_cleanup(void);

#ifdef SOME_FUNCTIONS_ARE_INLINE
/* Or inlines */
static inline void
ws_buffer_clean(Buffer *buffer)
{
	buffer->start = 0;
	buffer->first_free = 0;
}

static inline void
ws_buffer_increase_length(Buffer* buffer, size_t bytes)
{
	buffer->first_free += bytes;
}

static inline size_t
ws_buffer_length(const Buffer* buffer)
{
	return buffer->first_free - buffer->start;
}

static inline uint8_t *
ws_buffer_start_ptr(const Buffer* buffer)
{
	return buffer->data + buffer->start;
}

static inline uint8_t *
ws_buffer_end_ptr(const Buffer* buffer)
{
	return buffer->data + buffer->first_free;
}

static inline void
ws_buffer_append_buffer(Buffer* buffer, const Buffer* src_buffer)
{
	ws_buffer_append(buffer, ws_buffer_start_ptr(src_buffer), ws_buffer_length(src_buffer));
}
#else

/**
 * @brief Resets the buffer to an empty state without freeing memory.
 *
 * Clears the buffer contents by resetting `start` and `first_free` to zero.
 * The allocated memory remains available for reuse.
 *
 * @param buffer Pointer to the Buffer to clean.
 */
WS_DLL_PUBLIC
void ws_buffer_clean(Buffer* buffer);

/**
 * @brief Increases the logical length of the buffer.
 *
 * Advances the `first_free` pointer by `bytes`, effectively reserving space
 * for future writes. The caller must ensure that enough space is available.
 *
 * @param buffer Pointer to the Buffer.
 * @param bytes Number of bytes to add to the current length.
 */
WS_DLL_PUBLIC
void ws_buffer_increase_length(Buffer* buffer, size_t bytes);

/**
 * @brief Returns the number of valid bytes currently in the buffer.
 *
 * Calculates the length of data between `start` and `first_free`.
 *
 * @param buffer Pointer to the Buffer.
 * @return Number of bytes of valid data in the buffer.
 */
WS_DLL_PUBLIC
size_t ws_buffer_length(const Buffer* buffer);

/**
 * @brief Returns a pointer to the start of valid data in the buffer.
 *
 * @param buffer Pointer to the Buffer.
 * @return Pointer to the first valid byte.
 */
WS_DLL_PUBLIC
uint8_t* ws_buffer_start_ptr(const Buffer* buffer);

/**
 * @brief Returns a pointer to the end of valid data in the buffer.
 *
 * @param buffer Pointer to the Buffer.
 * @return Pointer to the first byte after the valid data.
 */
WS_DLL_PUBLIC
uint8_t* ws_buffer_end_ptr(const Buffer* buffer);

/**
 * @brief Appends the contents of one buffer to another.
 *
 * Copies the valid data from `src_buffer` into `buffer`, expanding it if necessary.
 *
 * @param buffer Destination buffer to append to.
 * @param src_buffer Source buffer whose contents will be appended.
 */
WS_DLL_PUBLIC
void ws_buffer_append_buffer(Buffer* buffer, const Buffer* src_buffer);

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
