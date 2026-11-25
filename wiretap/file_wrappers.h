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

/**
 * @brief Open a file for reading or writing.
 *
 * @param path The path to the file to open.
 * @return FILE_T A file handle for the opened file, or NULL on failure.
 */
extern FILE_T file_open(const char *path);

/**
 * @brief Open a file descriptor for reading or writing.
 *
 * @param fildes The file descriptor to be opened.
 * @return FILE* A pointer to the opened file stream if successful, otherwise NULL.
 */
extern FILE_T file_fdopen(int fildes);

/**
 * @brief Set random access flag for a file stream.
 *
 * @param stream The file stream to modify.
 * @param random_flag Flag indicating whether to enable random access.
 * @param seek Array of seek positions (not used).
 */
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
WS_WARN_UNUSED WS_DLL_PUBLIC int64_t file_seek(FILE_T stream, int64_t offset, int whence, int *err);

/**
 * @brief Get current position in the file.
 *
 * Returns logical position, accounting for buffering.
 *
 * @param stream File handle.
 * @return Current offset or -1 on failure.
 */
WS_DLL_PUBLIC int64_t file_tell(FILE_T stream);

/**
 * @brief Get current raw position in the file.
 *
 * Returns actual byte offset in the underlying file, ignoring buffering.
 *
 * @param stream File handle.
 * @return Current raw offset or -1 on failure.
 */
extern int64_t file_tell_raw(FILE_T stream);

/**
 * @brief Get file input buffer size.
 *
 * Returns the size, in bytes, of the input buffer.
 *
 * @note When reading from a @ref wtap->ispipe "pipe", a heuristic open routine
 * should read no farther than this into a stream before deciding whether to
 * accept, so that the stream can seek back to the beginning for the next
 * routine to try.
 *
 * @param stream File handle
 * @return Current input buffer size
 */
WS_DLL_PUBLIC unsigned file_bufsize(FILE_T stream);

/**
 * @brief Mark the current position as one we'll seek back to.
 *
 * Until this is called again, the stream can seek back to the marked
 * position, even when reading from a @ref wtap->ispipe "pipe", as long as
 * nothing has read more than file_bufsize() bytes past it.
 *
 * Initially, the mark is at the beginning of the file; that's how a
 * heuristic open routine, which shouldn't read more than file_bufsize()
 * bytes on a pipe, can seek back to the beginning for the next routine.
 *
 * wtap_read() sets the mark before calling the read routine, so a
 * sequential read routine can read past the end of its record and seek
 * back. It needs to call this itself only to keep data from an earlier
 * position, or to start the file_bufsize() bytes from a later one.
 *
 * A seek to a position before the mark isn't guaranteed to work on a pipe.
 * Setting the mark is cheap: it only records the position. Data before
 * it is discarded, and data after it moved, only when the I/O routines'
 * buffer is next refilled, so a routine can still seek back to wherever
 * it could before it set the mark, until it reads more.
 *
 * @param stream File handle
 */
WS_DLL_PUBLIC void file_set_seek_mark(FILE_T stream);

/**
 * @brief Get file status information.
 *
 * @param stream File handle.
 * @param statb Pointer to ws_statb64 structure to receive file status.
 * @param err Optional pointer to receive error code on failure.
 * @return 0 on success, -1 on failure.
 */
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
 * @brief Read a line from the file, returning a pointer to the end.
 *
 * Similar to file_gets(), but returns a pointer to the terminating '\0'
 * in buf on success.
 *
 * @param buf Destination buffer.
 * @param len Buffer size.
 * @param stream File handle.
 * @return @p to the terminating '\0' on success, or NULL on error or EOF.
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

/**
 * @brief Clear error and end-of-file indicators for a file stream.
 *
 * @param stream The file stream to clear.
 */
extern void file_clearerr(FILE_T stream);

/**
 * @brief Close a file stream.
 *
 * @param file The file stream to close.
 */
extern void file_fdclose(FILE_T file);

/**
 * @brief Reopens a file descriptor for reading.
 *
 * @param file The file descriptor to be reopened.
 * @param path The new path to open.
 * @return true if the file was successfully reopened, false otherwise.
 */
extern bool file_fdreopen(FILE_T file, const char *path);

/**
 * @brief Close a file stream.
 *
 * @param file The file stream to close.
 */
extern void file_close(FILE_T file);

#endif /* __FILE_H__ */
