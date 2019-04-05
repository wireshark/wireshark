/* merge.h
 * Definitions for routines for merging files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MERGE_H__
#define __MERGE_H__

#include "wiretap/wtap.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    RECORD_PRESENT,
    RECORD_NOT_PRESENT,
    AT_EOF,
    GOT_ERROR
} in_file_state_e;

/**
 * Structures to manage our input files.
 */
typedef struct merge_in_file_s {
    const char     *filename;
    wtap           *wth;
    wtap_rec        rec;
    Buffer          frame_buffer;
    in_file_state_e state;
    guint32         packet_num;     /* current packet number */
    gint64          size;           /* file size */
    GArray         *idb_index_map;  /* used for mapping the old phdr interface_id values to new during merge */
    guint           dsbs_seen;      /* number of elements processed so far from wth->dsbs */
} merge_in_file_t;

/** Return values from merge_files(). */
typedef enum {
    MERGE_OK,
    MERGE_USER_ABORTED,
    /* below here are true errors */
    MERGE_ERR_CANT_OPEN_INFILE,
    MERGE_ERR_CANT_OPEN_OUTFILE,
    MERGE_ERR_CANT_READ_INFILE,
    MERGE_ERR_BAD_PHDR_INTERFACE_ID,
    MERGE_ERR_CANT_WRITE_OUTFILE,
    MERGE_ERR_CANT_CLOSE_OUTFILE,
    MERGE_ERR_INVALID_OPTION
} merge_result;


/** Merge events, used as an arg in the callback function - indicates when the callback was invoked. */
typedef enum {
    MERGE_EVENT_INPUT_FILES_OPENED,
    MERGE_EVENT_FRAME_TYPE_SELECTED,
    MERGE_EVENT_READY_TO_MERGE,
    MERGE_EVENT_RECORD_WAS_READ,
    MERGE_EVENT_DONE
} merge_event;


/** Merge mode for IDB info. */
typedef enum {
    IDB_MERGE_MODE_NONE = 0,    /**< no merging of IDBs is done, all IDBs are copied into merged file */
    IDB_MERGE_MODE_ALL_SAME,/**< duplicate IDBs merged only if all the files have the same set of IDBs */
    IDB_MERGE_MODE_ANY_SAME, /**< any and all duplicate IDBs are merged into one IDB, even within a file */
    IDB_MERGE_MODE_MAX
} idb_merge_mode;


/** Returns the idb_merge_mode for the given string name.
 *
 * @param name The name of the mode.
 * @return The idb_merge_mode, or IDB_MERGE_MODE_MAX on failure.
 */
WS_DLL_PUBLIC idb_merge_mode
merge_string_to_idb_merge_mode(const char *name);


/** Returns the string name for the given number.
 *
 * @param mode The number of the mode, representing the idb_merge_mode enum value.
 * @return The string name, or "UNKNOWN" on failure.
 */
WS_DLL_PUBLIC const char*
merge_idb_merge_mode_to_string(const int mode);


/** @struct merge_progress_callback_t
 *
 * @brief Callback information for merging.
 *
 * @details The merge_files() routine can invoke a callback during its execution,
 * to enable verbose printing or progress bar updating, for example. This struct
 * provides merge_files() with the callback routine to invoke, and optionally
 * private data to pass through to the callback each time it is invoked.
 * For the callback_func routine's arguments: the event is when the callback
 * was invoked, the num is an int specific to the event, in_files is an array
 * of the created merge info, in_file_count is the size of the array, data is
 * whatever was passed in the data member of this struct. The callback_func
 * routine's return value should be TRUE if merging should be aborted.
 */
typedef struct {
    gboolean (*callback_func)(merge_event event, int num,
                              const merge_in_file_t in_files[], const guint in_file_count,
                              void *data);
    void *data; /**< private data to use for passing through to the callback function */
} merge_progress_callback_t;


/** Merge the given input files to a file with the given filename
 *
 * @param out_filename The output filename
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @param[out] err Set to the internal WTAP_ERR_XXX error code if it failed
 *   with MERGE_ERR_CANT_OPEN_INFILE, MERGE_ERR_CANT_OPEN_OUTFILE,
 *   MERGE_ERR_CANT_READ_INFILE, MERGE_ERR_CANT_WRITE_OUTFILE, or
 *   MERGE_ERR_CANT_CLOSE_OUTFILE
 * @param[out] err_info Additional information for some WTAP_ERR_XXX codes
 * @param[out] err_fileno Set to the input file number which failed, if it
 *   failed
 * @param[out] err_framenum Set to the input frame number if it failed
 * @return the frame type
 */
WS_DLL_PUBLIC merge_result
merge_files(const gchar* out_filename, const int file_type,
            const char *const *in_filenames, const guint in_file_count,
            const gboolean do_append, const idb_merge_mode mode,
            guint snaplen, const gchar *app_name, merge_progress_callback_t* cb,
            int *err, gchar **err_info, guint *err_fileno,
            guint32 *err_framenum);

/** Merge the given input files to a temporary file
 *
 * @param out_filenamep Points to a pointer that's set to point to the
 *        pathname of the temporary file; it's allocated with g_malloc()
 * @param pfx A string to be used as the prefix for the temporary file name
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @param[out] err Set to the internal WTAP_ERR_XXX error code if it failed
 *   with MERGE_ERR_CANT_OPEN_INFILE, MERGE_ERR_CANT_OPEN_OUTFILE,
 *   MERGE_ERR_CANT_READ_INFILE, MERGE_ERR_CANT_WRITE_OUTFILE, or
 *   MERGE_ERR_CANT_CLOSE_OUTFILE
 * @param[out] err_info Additional information for some WTAP_ERR_XXX codes
 * @param[out] err_fileno Set to the input file number which failed, if it
 *   failed
 * @param[out] err_framenum Set to the input frame number if it failed
 * @return the frame type
 */
WS_DLL_PUBLIC merge_result
merge_files_to_tempfile(gchar **out_filenamep, const char *pfx,
                        const int file_type, const char *const *in_filenames,
                        const guint in_file_count, const gboolean do_append,
                        const idb_merge_mode mode, guint snaplen,
                        const gchar *app_name, merge_progress_callback_t* cb,
                        int *err, gchar **err_info, guint *err_fileno,
                        guint32 *err_framenum);

/** Merge the given input files to the standard output
 *
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @param[out] err Set to the internal WTAP_ERR_XXX error code if it failed
 *   with MERGE_ERR_CANT_OPEN_INFILE, MERGE_ERR_CANT_OPEN_OUTFILE,
 *   MERGE_ERR_CANT_READ_INFILE, MERGE_ERR_CANT_WRITE_OUTFILE, or
 *   MERGE_ERR_CANT_CLOSE_OUTFILE
 * @param[out] err_info Additional information for some WTAP_ERR_XXX codes
 * @param[out] err_fileno Set to the input file number which failed, if it
 *   failed
 * @param[out] err_framenum Set to the input frame number if it failed
 * @return the frame type
 */
WS_DLL_PUBLIC merge_result
merge_files_to_stdout(const int file_type, const char *const *in_filenames,
                      const guint in_file_count, const gboolean do_append,
                      const idb_merge_mode mode, guint snaplen,
                      const gchar *app_name, merge_progress_callback_t* cb,
                      int *err, gchar **err_info, guint *err_fileno,
                      guint32 *err_framenum);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MERGE_H__ */

