/* file_compressed.h
 * Declarations for writing compressed files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Derived from code in the Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_FILE_COMPRESSED_H__
#define __WSUTIL_FILE_COMPRESSED_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Types of compression for a file, including "none".
 */
typedef enum {
    WS_FILE_UNCOMPRESSED,
    WS_FILE_GZIP_COMPRESSED,
    WS_FILE_ZSTD_COMPRESSED,
    WS_FILE_LZ4_COMPRESSED,
    WS_FILE_UNKNOWN_COMPRESSION,
} ws_compression_type;

/**
 * @brief Converts a compression type name to its corresponding enum value.
 *
 * @param name The name of the compression type.
 * @return ws_compression_type The corresponding enum value, or WS_FILE_UNKNOWN_COMPRESSION if not found.
 */
WS_DLL_PUBLIC ws_compression_type
ws_name_to_compression_type(const char *name);

WS_DLL_PUBLIC ws_compression_type

/**
 * @brief Converts a file extension to its corresponding compression type.
 *
 * @param ext The file extension to convert.
 * @return The compression type associated with the given extension, or WS_FILE_UNKNOWN_COMPRESSION if no match is found.
 */
ws_extension_to_compression_type(const char *ext);

/**
 * @brief Checks if a given compression type can be written.
 *
 * @param compression_type The compression type to check.
 * @return true If the compression type can be written, false otherwise.
 */
WS_DLL_PUBLIC bool
ws_can_write_compression_type(ws_compression_type compression_type);

/**
 * @brief Get a description for a given compression type.
 *
 * @param compression_type The compression type to get the description for.
 * @return const char* A string describing the compression type, or NULL if unknown.
 */
WS_DLL_PUBLIC const char *
ws_compression_type_description(ws_compression_type compression_type);

/**
 * @brief Get the extension for a given compression type.
 *
 * @param compression_type The compression type to get the extension for.
 * @return const char* The file extension, or NULL if not found.
 */
WS_DLL_PUBLIC const char *
ws_compression_type_extension(ws_compression_type compression_type);

/**
 * @brief Get the name of a compression type.
 *
 * @param compression_type The compression type to get the name for.
 * @return const char* The name of the compression type, or NULL if not found.
 */
WS_DLL_PUBLIC const char *
ws_compression_type_name(ws_compression_type compression_type);

/**
 * @brief Retrieves a list of all supported compression type extensions.
 *
 * This function returns a GSList containing strings representing the file extension
 * for each supported compression type.
 *
 * @return A GSList of compression type extensions, or NULL if no extensions are available.
 */
WS_DLL_PUBLIC GSList *
ws_get_all_compression_type_extensions_list(void);

/**
 * @brief Retrieves a list of all output compression type names.
 *
 * This function returns a GSList containing the names of all available output
 * compression types that support writing.
 *
 * @return A GSList of compression type names, or NULL if an error occurs.
 */
WS_DLL_PUBLIC GSList *
ws_get_all_output_compression_type_names_list(void);

/*
 * (Possibly) compressed writable stream.
 * Data is written to the stream using one of the above compression
 * types, if the type supports writing.
 *
 * One of those types is WS_FILE_UNCOMPRESSED, which is why it's
 * *possibly* compressed.
 */
typedef struct ws_cwstream ws_cwstream;

/**
 * @brief Opens a compressed file stream.
 *
 * @param filename The name of the file to open.
 * @param ctype The compression type to use.
 * @param err Pointer to an integer where error information will be stored.
 * @return A pointer to the newly created ws_cwstream, or NULL if an error occurred.
 */
WS_DLL_PUBLIC ws_cwstream*
ws_cwstream_open(const char *filename, ws_compression_type ctype, int *err);

/**
 * @brief Opens a compressed file stream from an existing file descriptor.
 *
 * @param fd The file descriptor of the file to open.
 * @param ctype The compression type to use for the file.
 * @param err Pointer to an integer where any error code will be stored.
 * @return ws_cwstream* A pointer to the newly created compressed file stream, or NULL on failure.
 */
WS_DLL_PUBLIC ws_cwstream*
ws_cwstream_fdopen(int fd, ws_compression_type ctype, int *err);

/**
 * @brief Opens a compressed stream for writing to stdout.
 *
 * @param ctype The compression type to use.
 * @param err Pointer to an integer where error codes will be stored.
 * @return A pointer to the newly created ws_cwstream, or NULL on failure.
 */
WS_DLL_PUBLIC ws_cwstream*
ws_cwstream_open_stdout(ws_compression_type ctype, int *err);

/* Write to file */
/**
 * @brief Writes data to a compressed writable stream.
 *
 * @param pfile Pointer to the compressed writable stream.
 * @param data Pointer to the data to be written.
 * @param data_length Length of the data to be written.
 * @param bytes_written Optional pointer to store the number of bytes actually written.
 * @param err Optional pointer to store an error code if an error occurs.
 * @return true on success, false and sets err (if provided) on failure.
 */
WS_DLL_PUBLIC bool
ws_cwstream_write(ws_cwstream* pfile, const uint8_t* data, size_t data_length,
                  uint64_t *bytes_written, int *err);

/**
 * @brief Flushes the compressed writable stream.
 *
 * @param pfile Pointer to the ws_cwstream structure.
 * @param err Optional pointer to an integer where the error code will be stored if an error occurs.
 * @return true on success, false and sets err (if not NULL) on failure.
 */
WS_DLL_PUBLIC bool
ws_cwstream_flush(ws_cwstream* pfile, int *err);

/**
 * Close open file handles and frees memory associated with pfile.
 *
 * @brief Closes a file stream and frees associated resources.
 *
 * Return true on success, returns false and sets err (optional) on failure.
 * err can be NULL, e.g. if closing after some other failure that is more
 * relevant to report, or when exiting a program
 *
 * @param pfile Pointer to the ws_cwstream structure representing the file stream.
 * @param err Pointer to an integer where an error code will be stored if an error occurs.
 */
WS_DLL_PUBLIC bool
ws_cwstream_close(ws_cwstream* pfile, int *err);

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)

typedef struct gzip_writer *GZWFILE_T;

WS_DLL_PUBLIC GZWFILE_T gzwfile_open(const char *path);
WS_DLL_PUBLIC GZWFILE_T gzwfile_fdopen(int fd);
WS_DLL_PUBLIC unsigned gzwfile_write(GZWFILE_T state, const void *buf, unsigned len);
WS_DLL_PUBLIC int gzwfile_flush(GZWFILE_T state);
WS_DLL_PUBLIC int gzwfile_close(GZWFILE_T state);
WS_DLL_PUBLIC int gzwfile_geterr(GZWFILE_T state);
#endif /* HAVE_ZLIB */

#ifdef HAVE_LZ4
typedef struct lz4_writer *LZ4WFILE_T;

WS_DLL_PUBLIC LZ4WFILE_T lz4wfile_open(const char *path);
WS_DLL_PUBLIC LZ4WFILE_T lz4wfile_fdopen(int fd);
WS_DLL_PUBLIC size_t lz4wfile_write(LZ4WFILE_T state, const void *buf, size_t len);
WS_DLL_PUBLIC int lz4wfile_flush(LZ4WFILE_T state);
WS_DLL_PUBLIC int lz4wfile_close(LZ4WFILE_T state);
WS_DLL_PUBLIC int lz4wfile_geterr(LZ4WFILE_T state);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_FILE_COMPRESSED_H__ */
