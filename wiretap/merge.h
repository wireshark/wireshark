/* merge.h
 * Definitions for routines for merging files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __MERGE_H__
#define __MERGE_H__

#include "wiretap/wtap.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    PACKET_PRESENT,
    PACKET_NOT_PRESENT,
    AT_EOF,
    GOT_ERROR
} in_file_state_e;

/**
 * Structures to manage our input files.
 */
typedef struct merge_in_file_s {
    const char     *filename;
    wtap           *wth;
    gint64          data_offset;
    in_file_state_e state;
    guint32         packet_num;     /* current packet number */
    gint64          size;           /* file size */
    GArray         *idb_index_map;  /* used for mapping the old phdr interface_id values to new during merge */
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
    MERGE_ERR_CANT_CLOSE_OUTFILE
} merge_result;


/** Merge events, used as an arg in the callback function - indicates when the callback was invoked. */
typedef enum {
    MERGE_EVENT_INPUT_FILES_OPENED,
    MERGE_EVENT_FRAME_TYPE_SELECTED,
    MERGE_EVENT_READY_TO_MERGE,
    MERGE_EVENT_PACKET_WAS_READ,
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


/** Merge the given input files to the output file descriptor.
 *
 * @param out_fd The already opened output file decriptor
 * @param out_filename The output filename, used in error messages
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @param[out] err Set to the internal WTAP_ERR_XXX error code if it failed
 * @param[out] err_info Set to a descriptive error string, which must be g_free'd
 * @param[out] err_fileno Set to the input file number which failed, if it failed
 * @return the frame type
 */
WS_DLL_PUBLIC merge_result
merge_files(int out_fd, const gchar* out_filename, const int file_type,
            const char *const *in_filenames, const guint in_file_count,
            const gboolean do_append, const idb_merge_mode mode,
            guint snaplen, const gchar *app_name, merge_progress_callback_t* cb,
            int *err, gchar **err_info, guint *err_fileno);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MERGE_H__ */

