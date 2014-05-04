/* ftap.h
 *
 * Filetap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __FTAP_H__
#define __FTAP_H__

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <glib.h>
#include <time.h>
#include <filetap/buffer.h>
#include <wsutil/nstime.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Encapsulation types. Choose names that truly reflect
 * what is contained in the packet trace file.
 *
 * FTAP_ENCAP_PER_RECORD is a value passed to "ftap_dump_open()" or
 * "ftap_dump_fd_open()" to indicate that there is no single encapsulation
 * type for all records in the file; this may cause those routines to
 * fail if the file format being written can't support that.
 * It's also returned by "ftap_file_encap()" for capture files that
 * don't have a single encapsulation type for all packets in the file.
 *
 * FTAP_ENCAP_UNKNOWN is returned by "ftap_pcap_encap_to_ftap_encap()"
 * if it's handed an unknown encapsulation.
 *
 */
#define FTAP_ENCAP_PER_RECORD                   -1
#define FTAP_ENCAP_UNKNOWN                       0

    /* After adding new item here, please also add new item to encap_table_base array */

#define FTAP_NUM_ENCAP_TYPES                    ftap_get_num_encap_types()

/* File types/subtypes that can be read by filetap. */
#define FTAP_FILE_TYPE_SUBTYPE_UNKNOWN                        0

#define FTAP_NUM_FILE_TYPES_SUBTYPES  ftap_get_num_file_types_subtypes()

/*
 * Maximum record size we'll support.
 * 65535 is the largest snapshot length that libpcap supports, so we
 * use that.
 */
#define FTAP_MAX_RECORD_SIZE    65535

typedef struct ftap ftap;
typedef struct ftap_dumper ftap_dumper;

typedef struct ftap_reader *FILE_F;

/*
 * For registering extensions used for capture file formats.
 *
 * These items are used in dialogs for opening files, so that
 * the user can ask to see all capture files (as identified
 * by file extension) or particular types of capture files.
 *
 * Each file type has a description and a list of extensions the file
 * might have.  Some file types aren't real file types, they're
 * just generic types, such as "text file" or "XML file", that can
 * be used for, among other things, captures we can read, or for
 * extensions such as ".cap" that were unimaginatively chosen by
 * several different sniffers for their file formats.
 */
struct filetap_extension_info {
    /* the file type name */
    const char *name;

    /* a semicolon-separated list of file extensions used for this type */
    const char *extensions;
};

/*
 * For registering file types that we can open.
 *
 * Each file type has an open routine and an optional list of extensions
 * the file might have.
 *
 * The open routine should return:
 *
 *	-1 on an I/O error;
 *
 *	1 if the file it's reading is one of the types it handles;
 *
 *	0 if the file it's reading isn't the type it handles.
 *
 * If the routine handles this type of file, it should set the "file_type"
 * field in the "struct ftap" to the type of the file.
 *
 * Note that the routine does not have to free the private data pointer on
 * error. The caller takes care of that by calling ftap_close on error.
 * (See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8518)
 *
 * However, the caller does have to free the private data pointer when
 * returning 0, since the next file type will be called and will likely
 * just overwrite the pointer.
 */

/*
 * Some file formats have defined magic numbers at fixed offsets from
 * the beginning of the file; those routines should return 1 if and
 * only if the file has the magic number at that offset.  (pcap-ng
 * is a bit of a special case, as it has both the Section Header Block
 * type field and its byte-order magic field; it checks for both.)
 * Those file formats do not require a file name extension in order
 * to recognize them or to avoid recognizing other file types as that
 * type, and have no extensions specified for them.
 */
typedef int (*ftap_open_routine_t)(struct ftap*, int *, char **);

/*
 * Some file formats don't have defined magic numbers at fixed offsets,
 * so a heuristic is required.  If that file format has any file name
 * extensions used for it, a list of those extensions should be
 * specified, so that, if the name of the file being opened has an
 * extension, the file formats that use that extension are tried before
 * the ones that don't, to handle the case where a file of one type
 * might be recognized by the heuristics for a different file type.
 */
struct ftap_heuristic_open_info {
	ftap_open_routine_t open_routine;
	const char *extensions;
	gchar **extensions_set; /* populated using extensions member during initialization */
};

struct ftap_file_type_subtype_info {
    /* the file type name */
    /* should be NULL for all "pseudo" types that are only internally used and not read/writeable */
    const char *name;

    /* the file type short name, used as a shortcut for the command line tools */
    /* should be NULL for all "pseudo" types that are only internally used and not read/writeable */
    const char *short_name;

    /* the default file extension, used to save this type */
    /* should be NULL if no default extension is known */
    const char *default_file_extension;

    /* a semicolon-separated list of additional file extensions */
    /* used for this type */
    /* should be NULL if no extensions, or no extensions other */
    /* than the default extension, are known */
    const char *additional_file_extensions;
};


/** On failure, "ftap_open_offline()" returns NULL, and puts into the
 * "int" pointed to by its second argument:
 *
 * @param filename Name of the file to open
 * @param err a positive "errno" value if the capture file can't be opened;
 * a negative number, indicating the type of error, on other failures.
 * @param err_info for some errors, a string giving more details of
 * the error
 * @param do_random TRUE if random access to the file will be done,
 * FALSE if not
 */
WS_DLL_PUBLIC
struct ftap* ftap_open_offline(const char *filename, int *err,
    gchar **err_info, gboolean do_random);

/**
 * If we were compiled with zlib and we're at EOF, unset EOF so that
 * ftap_read/gzread has a chance to succeed. This is necessary if
 * we're tailing a file.
 */
WS_DLL_PUBLIC
void ftap_cleareof(ftap *fth);

/** Returns TRUE if read was successful. FALSE if failure. data_offset is
 * set to the offset in the file where the data for the read packet is
 * located. */
WS_DLL_PUBLIC
gboolean ftap_read(ftap *fth, int *err, gchar **err_info,
    gint64 *data_offset);

WS_DLL_PUBLIC
gboolean ftap_seek_read (ftap *fth, gint64 seek_off,
	Buffer *buf, int len,
	int *err, gchar **err_info);

/*** get various information snippets about the current file ***/

/** Return an approximation of the amount of data we've read sequentially
 * from the file so far. */
WS_DLL_PUBLIC
gint64 ftap_read_so_far(ftap *fth);
WS_DLL_PUBLIC
gint64 ftap_file_size(ftap *fth, int *err);
WS_DLL_PUBLIC
gboolean ftap_iscompressed(ftap *fth);
WS_DLL_PUBLIC
guint ftap_snapshot_length(ftap *fth); /* per file */
WS_DLL_PUBLIC
int ftap_file_type_subtype(ftap *fth);
WS_DLL_PUBLIC
int ftap_file_encap(ftap *fth);

/*** close the file descriptors for the current file ***/
WS_DLL_PUBLIC
void ftap_fdclose(ftap *fth);

/*** reopen the random file descriptor for the current file ***/
WS_DLL_PUBLIC
gboolean ftap_fdreopen(ftap *fth, const char *filename, int *err);

/*** close the current file ***/
WS_DLL_PUBLIC
void ftap_sequential_close(ftap *fth);
WS_DLL_PUBLIC
void ftap_close(ftap *fth);

/*** various string converter functions ***/
WS_DLL_PUBLIC
const char *ftap_file_type_subtype_string(int file_type_subtype);
WS_DLL_PUBLIC
const char *ftap_file_type_subtype_short_string(int file_type_subtype);
WS_DLL_PUBLIC
int ftap_short_string_to_file_type_subtype(const char *short_name);

/*** various file extension functions ***/
WS_DLL_PUBLIC
GSList *ftap_get_all_file_extensions_list(void);
WS_DLL_PUBLIC
const char *ftap_default_file_extension(int filetype);
WS_DLL_PUBLIC
GSList *ftap_get_file_extensions_list(int filetype, gboolean include_compressed);
WS_DLL_PUBLIC
void ftap_free_extensions_list(GSList *extensions);

WS_DLL_PUBLIC
const char *ftap_encap_string(int encap);
WS_DLL_PUBLIC
const char *ftap_encap_short_string(int encap);
WS_DLL_PUBLIC
int ftap_short_string_to_encap(const char *short_name);

WS_DLL_PUBLIC
const char *ftap_strerror(int err);

/*** get available number of file types and encapsulations ***/
WS_DLL_PUBLIC
int ftap_get_num_file_type_extensions(void);
WS_DLL_PUBLIC
int ftap_get_num_encap_types(void);
WS_DLL_PUBLIC
int ftap_get_num_file_types_subtypes(void);

/*** get information for file type extension ***/
WS_DLL_PUBLIC
const char *ftap_get_file_extension_type_name(int extension_type);
WS_DLL_PUBLIC
GSList *ftap_get_file_extension_type_extensions(guint extension_type);

/*** dynamically register new file types and encapsulations ***/
WS_DLL_PUBLIC
void ftap_register_plugin_types(void);
WS_DLL_PUBLIC
void register_all_filetap_modules(void);
WS_DLL_PUBLIC
void ftap_register_file_type_extension(const struct filetap_extension_info *ei);
WS_DLL_PUBLIC
void ftap_register_magic_number_open_routine(ftap_open_routine_t open_routine);
WS_DLL_PUBLIC
void ftap_register_heuristic_open_info(struct ftap_heuristic_open_info *oi);
WS_DLL_PUBLIC
int ftap_register_file_type_subtypes(const struct ftap_file_type_subtype_info* fi);
WS_DLL_PUBLIC
int ftap_register_encap_type(const char* name, const char* short_name);


/**
 * Filetap error codes.
 */
#define FTAP_ERR_NOT_REGULAR_FILE              -1
    /** The file being opened for reading isn't a plain file (or pipe) */

#define FTAP_ERR_RANDOM_OPEN_PIPE              -2
    /** The file is being opened for random access and it's a pipe */

#define FTAP_ERR_FILE_UNKNOWN_FORMAT           -3
    /** The file being opened is not a capture file in a known format */

#define FTAP_ERR_UNSUPPORTED                   -4
    /** Supported file type, but there's something in the file we
       can't support */

#define FTAP_ERR_CANT_WRITE_TO_PIPE            -5
    /** Filetap can't save to a pipe in the specified format */

#define FTAP_ERR_CANT_OPEN                     -6
    /** The file couldn't be opened, reason unknown */

#define FTAP_ERR_UNSUPPORTED_FILE_TYPE         -7
    /** Filetap can't save files in the specified format */

#define FTAP_ERR_UNSUPPORTED_ENCAP             -8
    /** Filetap can't read or save files in the specified format with the
       specified encapsulation */

#define FTAP_ERR_ENCAP_PER_RECORD_UNSUPPORTED  -9
    /** The specified format doesn't support per-packet encapsulations */

#define FTAP_ERR_CANT_CLOSE                   -10
    /** The file couldn't be closed, reason unknown */

#define FTAP_ERR_CANT_READ                    -11
    /** An attempt to read failed, reason unknown */

#define FTAP_ERR_SHORT_READ                   -12
    /** An attempt to read read less data than it should have */

#define FTAP_ERR_BAD_FILE                     -13
    /** The file appears to be damaged or corrupted or otherwise bogus */

#define FTAP_ERR_SHORT_WRITE                  -14
    /** An attempt to write wrote less data than it should have */

#define FTAP_ERR_UNC_TRUNCATED                -15
    /** Compressed data was oddly truncated */

#define FTAP_ERR_UNC_OVERFLOW                 -16
    /** Uncompressing data would overflow buffer */

#define FTAP_ERR_UNC_BAD_OFFSET               -17
    /** LZ77 compressed data has bad offset to string */

#define FTAP_ERR_RANDOM_OPEN_STDIN            -18
    /** We're trying to open the standard input for random access */

#define FTAP_ERR_COMPRESSION_NOT_SUPPORTED    -19
    /* The filetype doesn't support output compression */

#define FTAP_ERR_CANT_SEEK                    -20
    /** An attempt to seek failed, reason unknown */

#define FTAP_ERR_CANT_SEEK_COMPRESSED         -21
    /** An attempt to seek on a compressed stream */

#define FTAP_ERR_DECOMPRESS                   -22
    /** Error decompressing */

#define FTAP_ERR_INTERNAL                     -23
    /** "Shouldn't happen" internal errors */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FTAP_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
