/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WTAP_FILE_WRAPPERS_H__
#define __WTAP_FILE_WRAPPERS_H__

#include <wireshark.h>
#include "wtap.h"
#include <wsutil/file_util.h>

extern FILE_T file_open(const char *path);
extern FILE_T file_fdopen(int fildes);
extern void file_set_random_access(FILE_T stream, bool random_flag, GPtrArray *seek);

/**
 * @brief Seek to a position in the file.
 *
 * Supports large offsets and returns error codes.
 *
 * @param stream File handle.
 * @param offset Byte offset.
 * @param whence SEEK_SET, SEEK_CUR, or SEEK_END.
 * @param err Optional error code output.
 * @return New position or -1 on failure.
 */
WS_DLL_PUBLIC int64_t file_seek(FILE_T stream, int64_t offset, int whence, int *err);

/**
 * @brief Get current position in the file.
 *
 * Returns logical position, accounting for buffering.
 *
 * @param stream File handle.
 * @return Current offset or -1 on failure.
 */
WS_DLL_PUBLIC int64_t file_tell(FILE_T stream);

extern int64_t file_tell_raw(FILE_T stream);
extern int file_fstat(FILE_T stream, ws_statb64 *statb, int *err);

/**
 * @brief Check if file is compressed.
 *
 * Returns true for compressed formats.
 *
 * @param stream File handle.
 * @return true if compressed; false otherwise.
 */
WS_DLL_PUBLIC bool file_iscompressed(FILE_T stream);

/**
 * @brief Read bytes from a file.
 *
 * Reads up to @p count bytes into @p buf from the given file stream.
 *
 * @param buf Destination buffer.
 * @param count Number of bytes to read.
 * @param file File handle.
 * @return Number of bytes read, or -1 on error.
 */
WS_DLL_PUBLIC int file_read(void *buf, unsigned int count, FILE_T file);

/**
 * @brief Peek the next byte from the file without advancing the position.
 *
 * Returns the next byte in the stream or EOF.
 *
 * @param stream File handle.
 * @return Byte value or EOF.
 */
WS_DLL_PUBLIC int file_peekc(FILE_T stream);

/**
 * @brief Read the next byte from the file.
 *
 * Advances the file position by one.
 *
 * @param stream File handle.
 * @return Byte value or EOF.
 */
WS_DLL_PUBLIC int file_getc(FILE_T stream);

/**
 * @brief Read a line from the file.
 *
 * Reads up to @p len - 1 characters into @p buf, stopping at newline or EOF.
 *
 * @param buf Destination buffer.
 * @param len Buffer size.
 * @param stream File handle.
 * @return @p buf on success, or NULL on error or EOF.
 */
WS_DLL_PUBLIC char *file_gets(char *buf, int len, FILE_T stream);

/**
 * @brief Read a line from the file, skipping leading whitespace.
 *
 * Similar to file_gets(), but trims leading spaces before reading.
 *
 * @param buf Destination buffer.
 * @param len Buffer size.
 * @param stream File handle.
 * @return @p buf on success, or NULL on error or EOF.
 */
WS_DLL_PUBLIC char *file_getsp(char *buf, int len, FILE_T stream);

/**
 * @brief Check for end-of-file.
 *
 * Returns true if EOF has been reached on the stream.
 *
 * @param stream File handle.
 * @return true if EOF, false otherwise.
 */
WS_DLL_PUBLIC bool file_eof(FILE_T stream);

/**
 * @brief Check for file error.
 *
 * Returns the error status and optionally sets an error message.
 *
 * @param fh File handle.
 * @param err_info Optional pointer to error message string.
 * @return Error code, or 0 if no error.
 */
WS_DLL_PUBLIC int file_error(FILE_T fh, char **err_info);

extern void file_clearerr(FILE_T stream);
extern void file_fdclose(FILE_T file);
extern bool file_fdreopen(FILE_T file, const char *path);
extern void file_close(FILE_T file);

#endif /* __FILE_H__ */
