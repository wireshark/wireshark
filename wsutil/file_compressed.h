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

WS_DLL_PUBLIC ws_compression_type
ws_name_to_compression_type(const char *name);

WS_DLL_PUBLIC ws_compression_type
ws_extension_to_compression_type(const char *ext);

WS_DLL_PUBLIC bool
ws_can_write_compression_type(ws_compression_type compression_type);

WS_DLL_PUBLIC const char *
ws_compression_type_description(ws_compression_type compression_type);

WS_DLL_PUBLIC const char *
ws_compression_type_extension(ws_compression_type compression_type);

WS_DLL_PUBLIC const char *
ws_compression_type_name(ws_compression_type compression_type);

WS_DLL_PUBLIC GSList *
ws_get_all_compression_type_extensions_list(void);

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

WS_DLL_PUBLIC ws_cwstream*
ws_cwstream_open(const char *filename, ws_compression_type ctype, int *err);

WS_DLL_PUBLIC ws_cwstream*
ws_cwstream_fdopen(int fd, ws_compression_type ctype, int *err);

WS_DLL_PUBLIC ws_cwstream*
ws_cwstream_open_stdout(ws_compression_type ctype, int *err);

/* Write to file */
WS_DLL_PUBLIC bool
ws_cwstream_write(ws_cwstream* pfile, const uint8_t* data, size_t data_length,
                  uint64_t *bytes_written, int *err);

WS_DLL_PUBLIC bool
ws_cwstream_flush(ws_cwstream* pfile, int *err);

/* Close open file handles and frees memory associated with pfile.
 *
 * Return true on success, returns false and sets err (optional) on failure.
 * err can be NULL, e.g. if closing after some other failure that is more
 * relevant to report, or when exiting a program. */
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
